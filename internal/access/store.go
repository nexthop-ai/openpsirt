// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Account is somebody who has been granted access.
type Account struct {
	bun.BaseModel `bun:"table:person,alias:pe"`

	ID int64 `bun:"id,pk,autoincrement"`
	// PartyID is what work is assigned to. A person and a team share one
	// name space so that "who holds this" is one question, and this is
	// this person's name in it.
	PartyID     int64  `bun:"party_id,notnull"`
	Identity    string `bun:"identity,notnull"`
	DisplayName string `bun:"display_name"`
	// IsAdmin is administration granted here: by an administrator, or
	// derived from a group. Configuration's half is IsBootstrap, and
	// Administers is the two together.
	IsAdmin bool `bun:"is_admin,notnull"`
	// IsBootstrap is set from configuration at every startup. It is
	// administration of its own, held while the name stays in configuration,
	// and it keeps a re-derivation from group membership out of the way back
	// in.
	IsBootstrap bool `bun:"is_bootstrap,notnull"`
	// AdminDerived says a group granted this rather than a person. Only what
	// a group gave is taken back when groups stop deciding, so somebody
	// promoted inside the application survives a change of mode.
	AdminDerived bool `bun:"admin_derived,notnull"`
	// AdminDerivedAt is when a group last said so, refreshed at every sign-in
	// that derives it. It is what bounds the flag for a credential that never
	// signs in. Null where a person granted it.
	AdminDerivedAt *time.Time `bun:"admin_derived_at"`
	// Audits is the other thing held over the deployment rather than over a
	// product: reading what it is set to, who holds what, and what has been
	// changed administratively. It grants no product's findings or decisions.
	//
	// The two columns beside it are administration's two, and carry the same
	// bound for the same reason.
	Audits          bool       `bun:"audits,notnull"`
	AuditsDerived   bool       `bun:"audits_derived,notnull"`
	AuditsDerivedAt *time.Time `bun:"audits_derived_at"`
	// Email is where to reach this person outside the application, and
	// EmailDerived says a sign-in provider supplied it rather than
	// somebody here. The pair works like the two above: a provider may
	// refresh what a provider gave and may never overwrite what an
	// administrator set.
	//
	// Empty is ordinary. An address is optional, and somebody without one
	// is told nothing outside the application and keeps the area inside
	// it.
	Email string `bun:"email"`
	// EmailSource says who last decided the address. Three states, because
	// two cannot tell "nobody has said" from "somebody said none".
	EmailSource EmailSource `bun:"email_source,notnull"`
	// Digest says they asked for one, and DigestUnassigned that it lists what
	// nobody owns as well as what is theirs. Both off by
	// default: a digest nobody asked for is mail somebody filters.
	Digest           bool       `bun:"digest,notnull"`
	DigestUnassigned bool       `bun:"digest_unassigned,notnull"`
	DigestSentAt     *time.Time `bun:"digest_sent_at"`
	CreatedAt        time.Time  `bun:"created_at,notnull"`
	LastSeenAt       *time.Time `bun:"last_seen_at"`
	// DeactivatedAt is when they stopped being somebody who may sign in.
	// Null is the ordinary state. Never a deletion: the record names them
	// as the proposer of judgments and the approver of others.
	DeactivatedAt *time.Time `bun:"deactivated_at"`
}

// Administers reports whether they administer this deployment, from either
// half: granted here, or named in configuration.
//
// What is stored, unbounded by the stamp a group's grant carries. Resolve is
// what applies that bound to a request.
func (a Account) Administers() bool { return a.IsAdmin || a.IsBootstrap }

// Party is a name that work can be assigned to: a person or a team.
//
// One table for both, so that assignment points at either through the column
// it already has. Two columns are right in nine places and forgotten in the
// tenth, and the tenth is a list that quietly omits work.
type Party struct {
	bun.BaseModel `bun:"table:party,alias:pa"`

	ID   int64     `bun:"id,pk,autoincrement"`
	Kind PartyKind `bun:"kind,notnull"`
}

// PartyKind says which table holds the rest of a party.
type PartyKind string

const (
	// APerson is somebody who has been granted access.
	APerson PartyKind = "person"
	// ATeam is a named set of people that holds work and grants nothing.
	ATeam PartyKind = "team"
)

// PartyKinds is both sorts of party.
func PartyKinds() []PartyKind { return []PartyKind{APerson, ATeam} }

// Store reads and writes who may do what.
type Store struct {
	db  bun.IDB
	now func() time.Time
	// claimWindow is how long an authorization this store writes stays
	// redeemable by name. Carried on the store rather than read at the write,
	// because the store is what a handler already holds and the setting is
	// read where settings are read.
	claimWindow time.Duration
	// derivedFor is how long a grant a group derived stays in force without
	// being derived again.
	//
	// A function rather than a value, and read per request rather than held,
	// because what bounds it is a setting an administrator changes without a
	// restart — the same reason the resolver holds the role mode that way. A
	// held copy would go on using the window that was configured at startup,
	// so an administrator shortening it to cut off somebody who has left would
	// get no effect until the process was restarted.
	//
	// Nil, or a window of zero, leaves a derived grant in force indefinitely.
	derivedFor func(context.Context) time.Duration
}

// DerivingWithin returns a store where a grant a group derived stays in force
// for the window the given function reports, asked each time it is needed.
//
// It bounds staleness, not authentication. Membership is read
// when somebody signs in, and every sign-in replaces their derived grants
// whole, so a browser's are never older than its session. A personal token
// never signs in — it resolves through its owner and reads whatever their last
// sign-in wrote — so without this a group somebody left keeps granting them
// roles through that token until they next sign in, which for somebody who has
// gone is never.
//
// No mode is consulted because none is needed: a deployment that assigns roles
// directly derives nothing, so it has no row this can reach.
func (s *Store) DerivingWithin(window func(context.Context) time.Duration) *Store {
	narrowed := *s
	narrowed.derivedFor = window
	return &narrowed
}

// stale reports that a derived grant has not been derived recently enough to
// still be in force.
//
// Only a derived one: what an administrator assigned is a standing decision
// and does not go off.
func (s *Store) stale(ctx context.Context, source Source, at time.Time) bool {
	if s.derivedFor == nil || source != Derived {
		return false
	}
	window := s.derivedFor(ctx)
	if window <= 0 {
		return false
	}
	return s.now().Sub(at) > window
}

// over is this store reading and writing through another connection.
//
// A copy with one field replaced, rather than a literal built field by field.
// The literals drifted: each new field on the store is an edit in four places
// and the three that are not in front of you are the ones that get missed,
// which is how `claimWindow` came to be dropped by some of them.
func (s *Store) over(db bun.IDB) *Store {
	moved := *s
	moved.db = db
	return &moved
}

// handle returns the connection this store was built over, or reports that it
// is already inside a transaction.
//
// A store built over a transaction cannot start another, and a retry that
// re-ran the inner half alone would repeat part of a transaction whose other
// part had been rolled back. Saying so is better than silently doing it.
func (s *Store) handle() (*bun.DB, error) {
	db, ok := database.Handle(s.db)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}
	return db, nil
}

// seenResolution is how coarse a last-used record is.
//
// It answers "is this still in use", which is a question about days. Recording
// it to the second would make every read a write on the row a person touches
// most, for a precision nothing asks for.
const seenResolution = time.Hour

// staleEnough reports whether a last-used stamp is old enough to rewrite.
func staleEnough(recorded *time.Time, now time.Time) bool {
	return recorded == nil || now.Sub(*recorded) >= seenResolution
}

// touch records that a credential or a person was used, where what was
// recorded has gone stale, and reports the moment it wrote or nil.
//
// Every credential's last use goes through here, so none is written on every
// request. Every authenticated request passes through a resolver, so writing
// each time makes the row the hottest in the database and every read a write,
// which a replica cannot serve from a follower and which, on a cluster, turns
// two concurrent requests on one credential into a certification conflict at
// commit. The date is what anybody reads it for, so an hour's resolution loses
// nothing.
func (s *Store) touch(ctx context.Context, model any, id int64, column string,
	recorded *time.Time) (*time.Time, error) {

	now := s.now().Truncate(time.Microsecond)
	if !staleEnough(recorded, now) {
		return nil, nil
	}
	if _, err := s.db.NewUpdate().Model(model).
		Set("? = ?", bun.Ident(column), now).Where(`"id" = ?`, id).Exec(ctx); err != nil {
		return nil, err
	}
	return &now, nil
}

// NewStore returns a store over db.
func NewStore(db bun.IDB) *Store {
	return &Store{
		db:          db,
		now:         func() time.Time { return time.Now().UTC() },
		claimWindow: DefaultClaimWindow,
	}
}

// Within runs do inside one transaction, with this store rebuilt over it.
//
// For an act that is more than one statement: a handler declaring a team and
// then adding its members left the team and whoever it reached standing when
// a later name turned out not to be anybody. A caller already inside a
// transaction joins it rather than opening a second.
// The handle is passed alongside the store because an act that spans packages
// needs it: recording somebody and granting them roles resolves product names,
// which is a different store over the same transaction.
func (s *Store) Within(ctx context.Context,
	do func(context.Context, *Store, bun.IDB) error) error {

	return database.Within(ctx, s.db, func(ctx context.Context, db bun.IDB) error {
		return do(ctx, s.over(db), db)
	})
}

// move writes what is held over the deployment where it differs from what was
// read, and records the new values on the account.
//
// Conditional on what was read, so the value being replaced is read by the
// statement that replaces it. A write that matched nothing lost a race with
// another writer who moved the same flag since, and is ErrGoAgain: the caller
// records the move from the value it read, and a fresh transaction is what
// reads the value that is there now.
func (s *Store) move(ctx context.Context, existing *Account, admin, audits *bool) error {
	for _, flag := range []struct {
		column, what string
		held         *bool
		asked        *bool
	}{
		{"is_admin", "is an administrator", &existing.IsAdmin, admin},
		{"audits", "audits this deployment", &existing.Audits, audits},
	} {
		if flag.asked == nil || *flag.held == *flag.asked {
			continue
		}
		result, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("? = ?", bun.Ident(flag.column), *flag.asked).Where(`"id" = ?`, existing.ID).
			Where("? = ?", bun.Ident(flag.column), *flag.held).Exec(ctx)
		if err != nil {
			return fmt.Errorf("record that %q %s: %w", existing.Identity, flag.what, err)
		}
		n, err := database.Affected(result)
		if err != nil {
			return fmt.Errorf("record that %q %s: %w", existing.Identity, flag.what, err)
		}
		if n == 0 {
			return fmt.Errorf("record that %q %s: %w", existing.Identity, flag.what, database.ErrGoAgain)
		}
		*flag.held = *flag.asked
	}
	return nil
}

// Ensure records somebody who has been granted access, or confirms one already
// recorded.
//
// This is the only path that creates a person, and nothing on a sign-in path
// calls it. Access is granted in advance or not at all.
// admin is a pointer so that three things stay distinguishable: making
// somebody an administrator, taking it away, and saying nothing about it.
//
// Nothing about it means nothing is written, which is what a caller that must
// leave administration alone needs. Reading what is stored and passing it back
// was what the endpoint did, and it is a read the write does not see: two
// requests at once, one granting administration and one saying nothing, and
// the second writes back the value it read before the first (REQ-71). A
// dropped connection read the same way — it answered "nobody is recorded as
// this", so administration was withdrawn from somebody who had it and no row
// said anybody had done it.
// audits is the same shape as admin and says the same three things about the
// other capability held over the deployment.
func (s *Store) Ensure(ctx context.Context, identity, displayName string,
	admin, audits *bool) (*Account, error) {

	_, person, err := s.Restate(ctx, identity, displayName, admin, audits)
	return person, err
}

// ErrNoIdentity is a person asked for with no name to record them under.
var ErrNoIdentity = refusal.New("a person needs an identity to be granted anything")

// Restate is Ensure, answering what was stored before the write beside what
// is stored after it. Before is nil where they were not recorded.
//
// Before is the value the conditional write was made against, read by the
// statement that decides whether anything moved. A caller recording the move
// from a read of its own can read a value another writer has since replaced,
// and record a move this write did not make.
func (s *Store) Restate(ctx context.Context, identity, displayName string,
	admin, audits *bool) (before, after *Account, err error) {

	// Folded, so that what is recorded here and what a sign-in matches are the
	// same string. An identity is a username, and a username is a name people
	// type.
	identity = Folded(identity)
	if identity == "" {
		return nil, nil, ErrNoIdentity
	}
	// The read and the write are one act, taken again whole where another
	// writer recorded the same person first: the second pass finds the row
	// the first could not see. A caller already inside a transaction has its
	// act taken again instead.
	err = database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		before, after, err = s.over(tx).restate(ctx, identity, displayName, admin, audits)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return before, after, nil
}

// restate is Restate's act, over one transaction.
func (s *Store) restate(ctx context.Context, identity, displayName string,
	admin, audits *bool) (before, after *Account, err error) {

	existing, err := s.ByIdentity(ctx, identity)
	if err == nil {
		was := *existing
		if err := s.move(ctx, existing, admin, audits); err != nil {
			return nil, nil, err
		}
		return &was, existing, nil
	}
	if !errors.Is(err, ErrNoSuchPerson) {
		// A read that failed is not somebody who is not there. Answered as
		// "not there", this went on to record them again — and with them a
		// fresh party row, for a person who already had one.
		return nil, nil, err
	}

	person := &Account{
		Identity: identity, DisplayName: displayName,
		IsAdmin: admin != nil && *admin,
		Audits:  audits != nil && *audits,
		// Said rather than left to the zero value. "Nobody has said" and
		// "somebody said none" are different states — read as the same, the
		// next sign-in puts back the address an administrator had just
		// removed — so the state a new row is in is named where it is made.
		EmailSource: NobodySaid,
		CreatedAt:   s.now().Truncate(time.Microsecond),
	}
	if err := s.record(ctx, person); err != nil {
		return nil, nil, fmt.Errorf("record %q: %w", identity, err)
	}
	return nil, person, nil
}

// record writes a new person, and the party they are assignable as.
//
// The only way a person is made. Both statements or neither: somebody without
// a party could be granted work that nothing could point at, and a second
// place doing this by hand is how one of them would come to be — the sign-in
// path already was one.
func (s *Store) record(ctx context.Context, person *Account) error {
	write := func(ctx context.Context, db bun.IDB) error {
		party := &Party{Kind: APerson}
		if _, err := db.NewInsert().Model(party).Exec(ctx); err != nil {
			return err
		}
		person.PartyID = party.ID
		_, err := db.NewInsert().Model(person).Exec(ctx)
		if database.IsDuplicate(err) {
			// Another writer recorded them between the caller's look and
			// this write, which is two requests of one first sign-in, or two
			// replicas naming one administrator at start. The act is taken
			// again whole, and its look then finds them.
			return fmt.Errorf("record %q: %w", person.Identity, database.ErrGoAgain)
		}
		return err
	}
	// Through the one helper, so the whole of it is retried: a cluster
	// certifies at COMMIT, and a write whose statements all succeeded can
	// still be rolled back under it. A caller already inside a transaction —
	// an administrator recording somebody, which is trailed in the same
	// transaction — joins that one instead.
	return database.Within(ctx, s.db, write)
}

// EmailSource says who last decided somebody's address.
type EmailSource string

const (
	// NobodySaid is the state of a person nobody has given an address to. A
	// provider may fill it in.
	NobodySaid EmailSource = ""
	// FromProvider is an address a sign-in provider stated and said it had
	// verified. A later sign-in may refresh it.
	FromProvider EmailSource = "provider"
	// Recorded is an address somebody here set, including setting it to none.
	// A provider may never write over one of these.
	Recorded EmailSource = "recorded"
)

// EmailSources is every source that has decided an address. NobodySaid is the
// absence of one, and is not offered.
func EmailSources() []EmailSource { return []EmailSource{FromProvider, Recorded} }

// SetEmail records where to reach somebody outside the application.
//
// `derived` says a sign-in provider supplied it rather than somebody here, and
// it decides precedence: a provider's address is written only over one nobody
// here recorded, so a provider may refresh what a provider gave and may never
// overwrite what an administrator set. Written the other way round, the next
// sign-in would quietly undo a correction somebody made on purpose.
//
// An empty address from an administrator clears it, which is how somebody is
// taken off mail without being taken off the tool. An empty one from a
// provider changes nothing: a provider that has stopped stating an address is
// silent about it rather than asking for the stored one to go.
//
// The comparison is on what is stored rather than on what was read earlier, so
// two sign-ins racing cannot both decide they are the first.
func (s *Store) SetEmail(ctx context.Context, personID int64, address string, from EmailSource) error {
	address = strings.TrimSpace(address)
	if personID == 0 {
		return refusal.New("an address needs somebody to belong to")
	}
	if from == FromProvider && address == "" {
		return nil
	}

	update := s.db.NewUpdate().Model((*Account)(nil)).
		Set(`"email" = ?`, address).
		Set(`"email_source" = ?`, from).
		Where(`"id" = ?`, personID)
	if from == FromProvider {
		// Only where nobody here has decided. "Nobody has said" and "somebody
		// said none" are different states and this is why they have to be:
		// read as the same, the next sign-in puts back exactly the address an
		// administrator had just removed.
		update = update.Where(`"email_source" <> ?`, Recorded)
	}
	if _, err := update.Exec(ctx); err != nil {
		return fmt.Errorf("record where to reach person %d: %w", personID, err)
	}
	return nil
}

// SetDisplayName records the label shown instead of somebody's identity. An
// empty name clears it, which leaves the identity showing.
//
// Conditional on from, the name the caller read inside the same transaction,
// so the trail's record of the move is a move this write made. One that
// matched nothing answers database.ErrGoAgain and is taken again whole.
func (s *Store) SetDisplayName(ctx context.Context, personID int64, from, to string) error {
	if personID == 0 {
		return refusal.New("a name needs somebody to belong to")
	}
	result, err := s.db.NewUpdate().Model((*Account)(nil)).
		Set(`"display_name" = ?`, strings.TrimSpace(to)).
		Where(`"id" = ?`, personID).
		Where(`COALESCE("display_name", '') = ?`, from).Exec(ctx)
	if err != nil {
		return fmt.Errorf("record the name of person %d: %w", personID, err)
	}
	n, err := database.Affected(result)
	if err != nil {
		return fmt.Errorf("record the name of person %d: %w", personID, err)
	}
	if n == 0 {
		return fmt.Errorf("record the name of person %d: %w", personID, database.ErrGoAgain)
	}
	return nil
}

// SetDigest records what somebody asked to be sent.
//
// Both switches are theirs rather than an administrator's: what somebody wants
// to read is not something to be decided for them, and a channel they cannot
// turn off is one they route to a folder.
func (s *Store) SetDigest(ctx context.Context, personID int64, wanted, unowned bool) error {
	if personID == 0 {
		return refusal.New("a preference needs somebody to belong to")
	}
	// A request for what nobody owns, without a digest at all, is a
	// setting that changes nothing, which is worse than not offering it.
	if unowned && !wanted {
		return refusal.New("a digest listing what nobody owns is still a digest: ask for one")
	}
	if _, err := s.db.NewUpdate().Model((*Account)(nil)).
		Set(`"digest" = ?`, wanted).
		Set(`"digest_unassigned" = ?`, unowned).
		Where(`"id" = ?`, personID).Exec(ctx); err != nil {
		return fmt.Errorf("record what person %d asked to be sent: %w", personID, err)
	}
	return nil
}
