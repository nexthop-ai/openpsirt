package access

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// Identity is how a person signs in.
//
// One per person: a deployment configures one provider at a time, and a
// username a trusted proxy asserts is the same identity as the same username
// from that provider (REQ-41).
type Identity struct {
	bun.BaseModel `bun:"table:person_identity,alias:pi"`

	ID       int64 `bun:"id,pk,autoincrement"`
	PersonID int64 `bun:"person_id,notnull"`
	// Subject is the provider's own stable identifier, absent until a sign-in
	// through the provider binds it. A proxy binds nothing, so an identity
	// reached only that way keeps waiting to be bound — which is what lets the
	// provider still bind it afterwards.
	Subject   *string    `bun:"subject"`
	Username  string     `bun:"username,notnull"`
	CreatedAt time.Time  `bun:"created_at,notnull"`
	BoundAt   *time.Time `bun:"bound_at"`
}

// folded is how a username is stored and how it is matched.
//
// An identity is a username now, and a username is both halves of the rule at
// once: an administrator types it to authorize somebody in advance, and a
// provider hands it over at every sign-in. The rule for a name people type
// wins, because the failure runs that way — an administrator writing "Alice"
// where the provider reports "alice" leaves an authorization nobody can redeem
// and, under group-bound admission, a second account beside the first.
//
// Normalized on the way in rather than compared loosely. The stored value
// compares the same under any engine, which is what keeps this from depending
// on a collation (REQ-08).
func folded(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// Claim authorizes somebody to sign in, before any provider has been asked
// about them.
//
// The username is what an administrator can type. The stable identifier is not
// knowable until the person actually arrives, which is why authorizing in
// advance has to be expressed in the moving name and then pinned to the fixed
// one at first use.
func (s *Store) Claim(ctx context.Context, personID int64, username string) error {
	username = folded(username)
	if username == "" {
		return fmt.Errorf("a way to sign in needs a username")
	}

	existing := new(Identity)
	err := s.db.NewSelect().Model(existing).Where("username = ?", username).Scan(ctx)
	if err == nil {
		if existing.PersonID != personID {
			return fmt.Errorf("%q is already somebody else here", username)
		}
		return nil
	}

	claim := &Identity{
		PersonID: personID, Username: username,
		CreatedAt: s.now().Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(claim).Exec(ctx); err != nil {
		return fmt.Errorf("authorize %q: %w", username, err)
	}
	return nil
}

// MatchProvider finds who the provider is describing, binding its identifier
// on the first successful sign-in.
//
// The order is what makes this safe. A bound identifier wins outright, so
// somebody who renamed themselves is still themselves and somebody who took
// the name they left behind is not them. Only a name nobody has bound yet is
// matched by name, which is the pre-authorization being redeemed.
//
// Nothing here creates a person. It returns who was already authorized, or
// nothing at all.
func (s *Store) MatchProvider(ctx context.Context, subject, username string) (*Account, error) {
	// The identifier is the provider's own and is compared exactly. Only the
	// name is folded.
	subject, username = strings.TrimSpace(subject), folded(username)
	if subject == "" || username == "" {
		// A provider that names somebody without a stable identifier leaves
		// the authorization redeemable by name forever, which is the matching
		// this whole shape exists to replace. The adapters refuse it before it
		// reaches here; this is the same refusal stated where it is relied on.
		return nil, ErrDenied
	}

	bound := new(Identity)
	if err := s.db.NewSelect().Model(bound).
		Where("subject = ?", subject).Scan(ctx); err == nil {
		// Their name may have moved since they were last here. Following it
		// keeps what an administrator reads current; it never decides
		// anything, because the identifier already did.
		if bound.Username != username {
			if err := s.rename(ctx, bound, username); err != nil {
				return nil, err
			}
		}
		return s.byID(ctx, bound.PersonID)
	}

	claimed, err := s.claimedBy(ctx, username)
	if err != nil {
		return nil, err
	}
	if claimed.Subject != nil && *claimed.Subject != subject {
		// The name was pinned to somebody else's identifier. Whoever holds it
		// now is not who was authorized, which is the case this whole shape
		// exists to catch.
		return nil, ErrDenied
	}

	if claimed.Subject == nil {
		at := s.now().Truncate(time.Microsecond)
		result, err := s.db.NewUpdate().Model((*Identity)(nil)).
			Set("subject = ?", subject).Set("bound_at = ?", at).
			Where("id = ?", claimed.ID).Where("subject IS NULL").Exec(ctx)
		if err != nil {
			return nil, fmt.Errorf("pin %q: %w", username, err)
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

// MatchProxy finds who a trusted proxy is asserting.
//
// A proxy has no stable identifier to offer: it asserts a username on every
// request and there is nothing else to match on. So the username decides, and
// **nothing is bound** — which is what lets the provider bind its own
// identifier to the same identity at a later sign-in, whichever way round
// somebody arrives first.
//
// It is also why a bound identifier does not refuse this path. The mismatch
// refusal in MatchProvider protects a name that moved between people at the
// provider; a proxy asserting that name is the deployment's own front door
// saying who is there, and a deployment trusting the header has already
// granted whatever sets it the power to claim to be anybody.
func (s *Store) MatchProxy(ctx context.Context, username string) (*Account, error) {
	username = folded(username)
	if username == "" {
		return nil, ErrDenied
	}
	claimed, err := s.claimedBy(ctx, username)
	if err != nil {
		return nil, err
	}
	return s.byID(ctx, claimed.PersonID)
}

// claimedBy reads the authorization waiting under a username.
func (s *Store) claimedBy(ctx context.Context, username string) (*Identity, error) {
	claimed := new(Identity)
	if err := s.db.NewSelect().Model(claimed).
		Where("username = ?", username).Scan(ctx); err != nil {
		return nil, ErrDenied
	}
	return claimed, nil
}

// rename follows a username that moved, refusing where the new one is already
// somebody else's.
//
// A collision here means two people now report the same name, which cannot
// happen while both are real. Keeping the old name is the safe answer: it is
// only a label, and the identifier still resolves them.
func (s *Store) rename(ctx context.Context, identity *Identity, username string) error {
	username = folded(username)
	taken, err := s.db.NewSelect().Model((*Identity)(nil)).
		Where("username = ?", username).Where("id <> ?", identity.ID).Count(ctx)
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

// UnbindIdentifier clears the provider identifier pinned to somebody.
//
// The authorization stays: the username row remains, waiting to be redeemed
// again by whoever next arrives under that name. Only the pin goes.
//
// It exists because a deployment may change provider, and an identifier is the
// old provider's. After a swap every pinned row refuses its holder — the name
// matches, the identifier does not, and nothing on a sign-in path can clear it
// — so without this the way back in is editing the database by hand.
//
// An administrative act rather than something a sign-in does for itself. A
// mismatched identifier is exactly what protects a name that moved between
// people, so clearing it automatically would undo the protection at the moment
// it was working.
func (s *Store) UnbindIdentifier(ctx context.Context, personID int64) error {
	if _, err := s.db.NewUpdate().Model((*Identity)(nil)).
		Set("subject = NULL").Set("bound_at = NULL").
		Where("person_id = ?", personID).Exec(ctx); err != nil {
		return fmt.Errorf("unbind how they sign in: %w", err)
	}
	return nil
}

// Identities lists the ways somebody may sign in.
func (s *Store) Identities(ctx context.Context, personID int64) ([]Identity, error) {
	var identities []Identity
	if err := s.db.NewSelect().Model(&identities).
		Where("person_id = ?", personID).Order("username ASC").Scan(ctx); err != nil {
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

// Arrival is who has just signed in.
type Arrival struct {
	// Subject is the provider's own stable identifier. Empty where the arrival
	// came through a trusted proxy, which has none.
	Subject string
	// ViaProxy says a trusted proxy asserted this rather than a provider.
	// Stated rather than inferred from an empty Subject: which of the two
	// paths an arrival took decides whether an identifier is bound and whether
	// a mismatch refuses, and an authorization boundary should not turn on a
	// field somebody could leave empty by accident.
	ViaProxy    bool
	Username    string
	DisplayName string
}

// match resolves an arrival down whichever path it came by.
func (s *Store) match(ctx context.Context, who Arrival) (*Account, error) {
	if who.ViaProxy {
		return s.MatchProxy(ctx, who.Username)
	}
	return s.MatchProvider(ctx, who.Subject, who.Username)
}

// handle is what to call somebody in a record of what they did.
//
// The username, unqualified. One provider is configured at a time and a
// username a proxy asserts is the same person as that username at the
// provider, so there is nothing to qualify it with — and qualifying it made
// one human two accounts, which is the defect that settled this (REQ-41).
func (a Arrival) handle() string {
	return folded(a.Username)
}
