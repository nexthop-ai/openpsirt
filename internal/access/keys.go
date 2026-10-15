// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/uptrace/bun"
)

// Key is a pipeline's credential.
type Key struct {
	bun.BaseModel `bun:"table:api_key,alias:ak"`

	ID         int64      `bun:"id,pk,autoincrement"`
	Name       string     `bun:"name,notnull"`
	SecretHash string     `bun:"secret_hash,notnull"`
	ProductID  int64      `bun:"product_id,notnull"`
	StreamID   *int64     `bun:"stream_id"`
	VariantID  *int64     `bun:"variant_id"`
	CreatedAt  time.Time  `bun:"created_at,notnull"`
	LastUsedAt *time.Time `bun:"last_used_at"`
	RevokedAt  *time.Time `bun:"revoked_at"`
}

// secretBytes is how much randomness a key carries.
//
// A key is not a password: it is generated here, never chosen, and never
// typed from memory. What it needs is enough entropy that guessing is not a
// strategy, which is also why the stored form is a plain digest rather than a
// slow hash — there is nothing to slow down when there is nothing to guess.
const secretBytes = 32

// KeyName is how a key's name is stored and how it is matched.
//
// An administrator types it to make a key and again to withdraw one, so it
// follows the rule for a name people type: stored folded, compared exactly,
// the same way a username is.
func KeyName(typed string) string { return credentialNamed(typed) }

// credentialNamed is a key's or a token's name as stored: folded, and cut to
// the width of the column that holds it, on a character.
func credentialNamed(typed string) string {
	return bound.HeadRunes(Folded(typed), database.NameWidth)
}

// ErrNoKeyName refuses a key whose name is only spaces.
var ErrNoKeyName = refusal.New("a key needs a name, so it can be told from the others")

// NewKey creates a pipeline credential, returning the secret once.
//
// Once is the whole point. A credential store that can hand back what it holds
// is a credential store that hands over every pipeline's key along with a copy
// of the database.
func (s *Store) NewKey(ctx context.Context, name string, scope Scope) (*Key, string, error) {
	name = KeyName(name)
	if name == "" {
		return nil, "", ErrNoKeyName
	}
	raw := make([]byte, secretBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("generate a key: %w", err)
	}
	secret := KeyPrefix + base64.RawURLEncoding.EncodeToString(raw)

	key := &Key{
		Name: name, SecretHash: hashSecret(secret),
		ProductID: scope.ProductID, StreamID: scope.StreamID, VariantID: scope.VariantID,
		CreatedAt: s.now().Truncate(time.Microsecond),
	}
	// The name in force is written beside the name and cleared when the key
	// is withdrawn, so a withdrawn name may be given to a new key. What a key
	// sent is recorded against its row rather than its name.
	if _, err := s.db.NewInsert().Model(key).Value("live_name", "?", name).Exec(ctx); err != nil {
		return nil, "", fmt.Errorf("record a key: %w", err)
	}
	return key, secret, nil
}

// ResolveKey turns a presented secret into the subject it stands for.
func (s *Store) ResolveKey(ctx context.Context, secret string) (Subject, error) {
	if strings.TrimSpace(secret) == "" {
		return Subject{}, ErrDenied
	}

	// Matched on the whole digest, which is the comparison. A constant-time
	// compare afterwards, over the row the equality has just selected, cannot
	// fail — and calling the lookup "not by itself a statement that the
	// secrets match" is wrong, because a SQL equality on the whole digest is
	// exactly that.
	//
	// The presented secret is never compared byte by byte: only its digest
	// reaches the database. The timing of this is decided by the index lookup,
	// which is not constant time and which nothing here controls —
	// making that a property rather than decoration means replacing the lookup
	// with a fetch by a non-secret key and a comparison in Go, which is a
	// different design and would be stated as one.
	key := new(Key)
	err := s.db.NewSelect().Model(key).Where(`"secret_hash" = ?`, hashSecret(secret)).Scan(ctx)
	if err != nil {
		return Subject{}, database.FromRead(err, ErrDenied, "look up a key")
	}
	if key.RevokedAt != nil {
		return Subject{}, ErrDenied
	}

	if _, err := s.touch(ctx, (*Key)(nil), key.ID, "last_used_at", key.LastUsedAt); err != nil {
		return Subject{}, fmt.Errorf("record that a key was used: %w", err)
	}
	return NewPipeline(key.ID, key.Name, Scope{
		ProductID: key.ProductID, StreamID: key.StreamID, VariantID: key.VariantID,
	}), nil
}

// Revoke stops a key working, without removing what it did.
func (s *Store) Revoke(ctx context.Context, keyID int64) error {
	result, err := s.db.NewUpdate().Model((*Key)(nil)).
		Set(`"revoked_at" = ?`, s.now().Truncate(time.Microsecond)).
		Set(`"live_name" = NULL`).
		Where(`"id" = ?`, keyID).Where(`"revoked_at" IS NULL`).Exec(ctx)
	if err != nil {
		return fmt.Errorf("revoke key %d: %w", keyID, err)
	}
	return matched(result, fmt.Sprintf("revoke key %d", keyID), "that key is already revoked")
}

// hashSecret is what gets stored.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Keys lists the pipeline credentials, without their secrets.
//
// There is nothing to list them with: what is stored is a digest, and that is
// the point. An operator needs which keys exist, what each reaches, when it
// was last used, and whether it still works.
func (s *Store) Keys(ctx context.Context) ([]Key, error) {
	var keys []Key
	if err := s.db.NewSelect().Model(&keys).Order("name").Scan(ctx); err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}
	return keys, nil
}
