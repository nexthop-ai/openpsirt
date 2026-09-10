package access

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// Credential prefixes.
//
// Every credential this deployment issues says which kind it is in its first
// few characters. Two things follow. Resolution reads the prefix rather than
// trying each store in turn, so a pipeline's key can never be looked up as
// somebody's personal token or the other way round. And a credential that ends
// up somewhere public is recognizable as one: secret scanners match on fixed
// prefixes, and a bare 43 characters of base64 matches nothing.
const (
	// KeyPrefix marks a pipeline's credential.
	KeyPrefix = "opk_"
	// TokenPrefix marks a person's own credential.
	TokenPrefix = "opt_"
)

// Token is somebody's own credential for scripting.
type Token struct {
	bun.BaseModel `bun:"table:personal_token,alias:pt"`

	ID         int64  `bun:"id,pk,autoincrement"`
	Name       string `bun:"name,notnull"`
	SecretHash string `bun:"secret_hash,notnull"`
	PersonID   int64  `bun:"person_id,notnull"`
	// ProductID narrows the token below its owner. Absent means it reaches
	// whatever they do.
	ProductID  *int64     `bun:"product_id"`
	CreatedAt  time.Time  `bun:"created_at,notnull"`
	ExpiresAt  time.Time  `bun:"expires_at,notnull"`
	LastUsedAt *time.Time `bun:"last_used_at"`
	RevokedAt  *time.Time `bun:"revoked_at"`
}

// DefaultTokenLifetime is how long a personal token lasts when nobody says.
const DefaultTokenLifetime = 90 * 24 * time.Hour

// MaxTokenLifetime is the ceiling when an administrator has not set one.
const MaxTokenLifetime = 365 * 24 * time.Hour

// NewToken mints somebody a credential of their own, returning the secret once.
//
// Expiry is not optional. A credential that never runs out is one nobody ever
// revokes, and the ones that matter are discovered when somebody leaves and
// nobody knows what breaks if it is turned off.
func (s *Store) NewToken(ctx context.Context, personID int64, name string, productID *int64, lifetime, ceiling time.Duration) (*Token, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", fmt.Errorf("a token needs a name, so its owner can tell it from the others")
	}
	if ceiling <= 0 {
		ceiling = MaxTokenLifetime
	}
	if lifetime <= 0 {
		// The default is what somebody gets for not saying, so it is clamped
		// to what is allowed rather than compared against it. Refusing a mint
		// that asked for nothing, naming a limit nobody tried to exceed, would
		// make every deployment with a short ceiling reject its own default.
		lifetime = min(DefaultTokenLifetime, ceiling)
	}
	if lifetime > ceiling {
		return nil, "", fmt.Errorf("a token may last at most %s here", ceiling)
	}

	raw, err := secret()
	if err != nil {
		return nil, "", err
	}
	presented := TokenPrefix + raw

	now := s.now().Truncate(time.Microsecond)
	token := &Token{
		Name: name, SecretHash: hashSecret(presented), PersonID: personID, ProductID: productID,
		CreatedAt: now, ExpiresAt: now.Add(lifetime).Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(token).Exec(ctx); err != nil {
		return nil, "", fmt.Errorf("record a token: %w", err)
	}
	return token, presented, nil
}

// ResolveToken turns somebody's own credential into the subject it stands for.
//
// Resolved through its owner every time rather than from anything stored with
// the token. That is what makes it a live reference: a role withdrawn from
// them — by an administrator, or by a group membership that went away — cuts
// the token at the same instant, with nothing extra to remember.
func (s *Store) ResolveToken(ctx context.Context, presented string) (Subject, error) {
	token := new(Token)
	if err := s.db.NewSelect().Model(token).
		Where("secret_hash = ?", hashSecret(presented)).Scan(ctx); err != nil {
		return Subject{}, ErrDenied
	}
	if token.RevokedAt != nil {
		return Subject{}, ErrDenied
	}
	if !s.now().Before(token.ExpiresAt) {
		return Subject{}, ErrDenied
	}

	person := new(Account)
	if err := s.db.NewSelect().Model(person).Where("id = ?", token.PersonID).Scan(ctx); err != nil {
		// The account is gone, so the token is too.
		return Subject{}, ErrDenied
	}
	subject, err := s.Resolve(ctx, person.Identity)
	if err != nil {
		return Subject{}, err
	}

	// Coarse, like the others: a script driving this token makes as many
	// requests as it likes, and each one would otherwise rewrite the same row.
	if used := s.now().Truncate(time.Microsecond); staleEnough(token.LastUsedAt, used) {
		if _, err := s.db.NewUpdate().Model((*Token)(nil)).
			Set("last_used_at = ?", used).Where("id = ?", token.ID).Exec(ctx); err != nil {
			return Subject{}, fmt.Errorf("record that a token was used: %w", err)
		}
	}

	// Marked before any narrowing, because it is true of every token: what
	// arrives on one may not mint another, narrowed or not. A token that can
	// mint is a token whose limits are one request deep — the holder asks for
	// a wider one and gets it, because minting resolves through the owner.
	subject = subject.delegate()
	if token.ProductID != nil {
		subject = subject.narrowedTo(*token.ProductID)
	}
	return subject, nil
}

// delegate marks a subject as arriving on a minted credential.
func (s Subject) delegate() Subject {
	s.delegated = true
	return s
}

// narrowedTo keeps only what this subject holds on one product.
//
// Narrowing intersects rather than replaces, so a token pinned to something
// its owner cannot read reaches nothing rather than being granted it. Admin is
// dropped entirely: administration is global, and a token narrowed to one
// product carrying it would not be narrowed at all.
func (s Subject) narrowedTo(productID int64) Subject {
	narrowed := Subject{
		ID: s.ID, Identity: s.Identity, Kind: s.Kind, delegated: s.delegated,
		grants: map[int64][]Role{},
	}
	if held, ok := s.grants[productID]; ok {
		narrowed.grants[productID] = held
	}
	return narrowed
}

// Tokens lists somebody's own credentials.
func (s *Store) Tokens(ctx context.Context, personID int64) ([]Token, error) {
	var tokens []Token
	if err := s.db.NewSelect().Model(&tokens).
		Where("person_id = ?", personID).Order("name ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the tokens: %w", err)
	}
	return tokens, nil
}

// AllTokens lists everybody's, for an administrator.
func (s *Store) AllTokens(ctx context.Context) ([]Token, error) {
	var tokens []Token
	if err := s.db.NewSelect().Model(&tokens).
		Order("person_id ASC", "name ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the tokens: %w", err)
	}
	return tokens, nil
}

// RevokeToken withdraws one.
//
// Marked rather than deleted, so that what used a token remains answerable
// after it stops working.
func (s *Store) RevokeToken(ctx context.Context, id int64) error {
	revoked := s.now().Truncate(time.Microsecond)
	if _, err := s.db.NewUpdate().Model((*Token)(nil)).
		Set("revoked_at = ?", revoked).
		Where("id = ?", id).Where("revoked_at IS NULL").Exec(ctx); err != nil {
		return fmt.Errorf("revoke a token: %w", err)
	}
	return nil
}

// TokenByName finds one of somebody's tokens.
func (s *Store) TokenByName(ctx context.Context, personID int64, name string) (*Token, error) {
	token := new(Token)
	if err := s.db.NewSelect().Model(token).
		Where("person_id = ?", personID).Where("name = ?", name).Scan(ctx); err != nil {
		return nil, fmt.Errorf("no token of yours is called %q", name)
	}
	return token, nil
}
