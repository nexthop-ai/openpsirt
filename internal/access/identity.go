package access

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// ProxyProvider names the trusted-header path.
//
// It has no stable identifier of its own: a proxy asserts a username on every
// request and there is nothing else to match on. That is a property of the
// arrangement rather than a shortcut — the proxy is the authority there, and a
// deployment trusting it has already accepted that what it says is who
// somebody is.
const ProxyProvider = "proxy"

// Identity is one way a person signs in.
type Identity struct {
	bun.BaseModel `bun:"table:person_identity,alias:pi"`

	ID       int64  `bun:"id,pk,autoincrement"`
	PersonID int64  `bun:"person_id,notnull"`
	Provider string `bun:"provider,notnull"`
	// Subject is the provider's own stable identifier, absent until the first
	// successful sign-in binds it.
	Subject   *string    `bun:"subject"`
	Username  string     `bun:"username,notnull"`
	CreatedAt time.Time  `bun:"created_at,notnull"`
	BoundAt   *time.Time `bun:"bound_at"`
}

// Claim authorizes somebody to sign in through a provider, before that
// provider has ever been asked about them.
//
// The username is what an administrator can type. The stable identifier is not
// knowable until the person actually arrives, which is why authorizing in
// advance has to be expressed in the moving name and then pinned to the fixed
// one at first use.
func (s *Store) Claim(ctx context.Context, personID int64, provider, username string) error {
	provider, username = strings.TrimSpace(provider), strings.TrimSpace(username)
	if provider == "" || username == "" {
		return fmt.Errorf("a way to sign in needs both a provider and a username")
	}

	existing := new(Identity)
	err := s.db.NewSelect().Model(existing).
		Where("provider = ?", provider).Where("username = ?", username).Scan(ctx)
	if err == nil {
		if existing.PersonID != personID {
			return fmt.Errorf("%q at %q is already somebody else here", username, provider)
		}
		return nil
	}

	claim := &Identity{
		PersonID: personID, Provider: provider, Username: username,
		CreatedAt: s.now().Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(claim).Exec(ctx); err != nil {
		return fmt.Errorf("authorize %q at %q: %w", username, provider, err)
	}
	return nil
}

// MatchProvider finds who a provider is describing, binding its identifier on
// the first successful sign-in.
//
// The order is what makes this safe. A bound identifier wins outright, so
// somebody who renamed themselves is still themselves and somebody who took
// the name they left behind is not them. Only a name nobody has bound yet is
// matched by name, which is the pre-authorization being redeemed.
//
// Nothing here creates a person. It returns who was already authorized, or
// nothing at all.
func (s *Store) MatchProvider(ctx context.Context, provider, subject, username string) (*Account, error) {
	provider = strings.TrimSpace(provider)
	subject, username = strings.TrimSpace(subject), strings.TrimSpace(username)
	if provider == "" || username == "" {
		return nil, ErrDenied
	}

	if subject != "" {
		bound := new(Identity)
		if err := s.db.NewSelect().Model(bound).
			Where("provider = ?", provider).Where("subject = ?", subject).Scan(ctx); err == nil {
			// Their name may have moved since they were last here. Following
			// it keeps what an administrator reads current; it never decides
			// anything, because the identifier already did.
			if bound.Username != username {
				if err := s.rename(ctx, bound, username); err != nil {
					return nil, err
				}
			}
			return s.byID(ctx, bound.PersonID)
		}
	}

	claimed := new(Identity)
	if err := s.db.NewSelect().Model(claimed).
		Where("provider = ?", provider).Where("username = ?", username).Scan(ctx); err != nil {
		return nil, ErrDenied
	}
	if claimed.Subject != nil && *claimed.Subject != subject {
		// The name was pinned to somebody else's identifier. Whoever holds it
		// now is not who was authorized, which is the case this whole shape
		// exists to catch.
		return nil, ErrDenied
	}

	if claimed.Subject == nil {
		if subject == "" {
			// Nothing to pin to. A provider that names somebody without a
			// stable identifier leaves this authorization redeemable by name
			// forever, which is the matching this whole shape exists to
			// replace — so it is refused rather than admitted unpinned.
			// The proxy path is the exception and states a subject of its own.
			return nil, ErrDenied
		}

		bound := s.now().Truncate(time.Microsecond)
		result, err := s.db.NewUpdate().Model((*Identity)(nil)).
			Set("subject = ?", subject).Set("bound_at = ?", bound).
			Where("id = ?", claimed.ID).Where("subject IS NULL").Exec(ctx)
		if err != nil {
			return nil, fmt.Errorf("pin %q at %q: %w", username, provider, err)
		}
		// Whether this pinned it is the whole question. Two arrivals can reach
		// here at once holding different identifiers, and exactly one may
		// redeem the authorization — so the one whose update matched nothing
		// is somebody else, and is refused rather than admitted on the
		// strength of a row the other just claimed.
		pinned, err := result.RowsAffected()
		if err != nil || pinned != 1 {
			return nil, ErrDenied
		}
	}
	return s.byID(ctx, claimed.PersonID)
}

// rename follows a username that moved, refusing where the new one is already
// somebody else's.
//
// A collision here means two people at one provider now report the same name,
// which cannot happen while both are real. Keeping the old name is the safe
// answer: it is only a label, and the identifier still resolves them.
func (s *Store) rename(ctx context.Context, identity *Identity, username string) error {
	taken, err := s.db.NewSelect().Model((*Identity)(nil)).
		Where("provider = ?", identity.Provider).Where("username = ?", username).
		Where("id <> ?", identity.ID).Count(ctx)
	if err != nil {
		return fmt.Errorf("check whether %q is taken: %w", username, err)
	}
	if taken > 0 {
		return nil
	}
	if _, err := s.db.NewUpdate().Model((*Identity)(nil)).
		Set("username = ?", username).Where("id = ?", identity.ID).Exec(ctx); err != nil {
		return fmt.Errorf("follow a username that moved: %w", err)
	}
	identity.Username = username
	return nil
}

// Identities lists the ways somebody may sign in.
func (s *Store) Identities(ctx context.Context, personID int64) ([]Identity, error) {
	var identities []Identity
	if err := s.db.NewSelect().Model(&identities).
		Where("person_id = ?", personID).Order("provider ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how they sign in: %w", err)
	}
	return identities, nil
}

// byID reads a person by row.
func (s *Store) byID(ctx context.Context, id int64) (*Account, error) {
	person := new(Account)
	if err := s.db.NewSelect().Model(person).Where("id = ?", id).Scan(ctx); err != nil {
		return nil, ErrDenied
	}
	return person, nil
}

// Arrival is who a provider says has just signed in.
type Arrival struct {
	// Provider names which one, because a username is only unique within the
	// provider that issued it.
	Provider string
	// Subject is that provider's own stable identifier. Empty where the
	// provider has none, which is the trusted-header case.
	Subject     string
	Username    string
	DisplayName string
}

// handle is what to call somebody in a record of what they did.
//
// Qualified by provider, because two providers can each have an "alice" and
// the two are not the same person. A deployment with one provider still gets
// the qualifier: leaving it off where it happens to be unambiguous would mean
// the handle changed shape the day a second provider was configured, and
// everything that recorded the old one would be describing somebody who no
// longer appears to exist.
func (a Arrival) handle() string {
	return a.Provider + ":" + a.Username
}
