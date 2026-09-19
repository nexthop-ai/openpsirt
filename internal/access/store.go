package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
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
	IsAdmin     bool   `bun:"is_admin,notnull"`
	// IsBootstrap is set from configuration at every startup, and is what
	// keeps a re-derivation from group membership out of the way back in.
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

// Grant is one role held against one product.
type Grant struct {
	bun.BaseModel `bun:"table:role_grant,alias:rg"`

	ID        int64 `bun:"id,pk,autoincrement"`
	PersonID  int64 `bun:"person_id,notnull"`
	ProductID int64 `bun:"product_id,notnull"`
	Role      Role  `bun:"role,notnull"`
	// Source says whether an administrator assigned this or a group derived
	// it, and Active whether it grants anything at all right now. A grant made
	// inactive by a change of mode is kept so the change can be undone, and it
	// is never counted as access while it sits there.
	Source    Source    `bun:"source,notnull"`
	Active    bool      `bun:"active,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
}

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
// What this bounds is staleness, not authentication. Membership is read
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

	// Folded, so that what is recorded here and what a sign-in matches are the
	// same string. An identity is a username, and a username is a name people
	// type.
	identity = folded(identity)
	if identity == "" {
		return nil, fmt.Errorf("a person needs an identity to be granted anything")
	}

	existing, err := s.ByIdentity(ctx, identity)
	if err == nil {
		// Conditional on what is stored, so the value being replaced is read
		// by the statement that replaces it. The affected-row count then says
		// whether it moved, which is what the trail records.
		if admin != nil && existing.IsAdmin != *admin {
			if _, err := s.db.NewUpdate().Model((*Account)(nil)).
				Set("is_admin = ?", *admin).Where("id = ?", existing.ID).
				Where("is_admin = ?", existing.IsAdmin).Exec(ctx); err != nil {
				return nil, fmt.Errorf("record that %q is an administrator: %w", identity, err)
			}
			existing.IsAdmin = *admin
		}
		if audits != nil && existing.Audits != *audits {
			if _, err := s.db.NewUpdate().Model((*Account)(nil)).
				Set("audits = ?", *audits).Where("id = ?", existing.ID).
				Where("audits = ?", existing.Audits).Exec(ctx); err != nil {
				return nil, fmt.Errorf("record that %q audits this deployment: %w", identity, err)
			}
			existing.Audits = *audits
		}
		return existing, nil
	}
	if !errors.Is(err, ErrNoSuchPerson) {
		// A read that failed is not somebody who is not there. Answered as
		// "not there", this went on to record them again — and with them a
		// fresh party row, for a person who already had one.
		return nil, err
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
		return nil, fmt.Errorf("record %q: %w", identity, err)
	}
	return person, nil
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
		return errors.New("an address needs somebody to belong to")
	}
	if from == FromProvider && address == "" {
		return nil
	}

	update := s.db.NewUpdate().Model((*Account)(nil)).
		Set("email = ?", address).
		Set("email_source = ?", from).
		Where("id = ?", personID)
	if from == FromProvider {
		// Only where nobody here has decided. "Nobody has said" and "somebody
		// said none" are different states and this is why they have to be:
		// read as the same, the next sign-in puts back exactly the address an
		// administrator had just removed.
		update = update.Where("email_source <> ?", Recorded)
	}
	if _, err := update.Exec(ctx); err != nil {
		return fmt.Errorf("record where to reach person %d: %w", personID, err)
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
		return errors.New("a preference needs somebody to belong to")
	}
	// Asking for what nobody owns without asking for a digest at all is a
	// setting that changes nothing, which is worse than not offering it.
	if unowned && !wanted {
		return errors.New("a digest listing what nobody owns is still a digest: ask for one")
	}
	if _, err := s.db.NewUpdate().Model((*Account)(nil)).
		Set("digest = ?", wanted).
		Set("digest_unassigned = ?", unowned).
		Where("id = ?", personID).Exec(ctx); err != nil {
		return fmt.Errorf("record what person %d asked to be sent: %w", personID, err)
	}
	return nil
}

// ByIdentity finds somebody by what a sign-in path calls them.
func (s *Store) ByIdentity(ctx context.Context, identity string) (*Account, error) {
	person := new(Account)
	// Folded to match how it was stored. An identity typed with different
	// capitals is the same person, and looking it up exactly would answer
	// "nobody" for somebody who is plainly there.
	err := s.db.NewSelect().Model(person).Where("identity = ?", folded(identity)).Scan(ctx)
	if err != nil {
		return nil, database.FromRead(err,
			fmt.Errorf("nobody is recorded as %q: %w", identity, ErrNoSuchPerson),
			fmt.Sprintf("look up %q", identity))
	}
	return person, nil
}

// Stated is what Ensure is told about administration, where nothing at all
// leaves it as it is.
func Stated(admin bool) *bool { return &admin }

// ErrNoSuchPerson is what an identity nobody here holds comes back as.
//
// A sentinel rather than a sentence, because whoever asked has to tell it from
// a read that could not be made: the first is a 404 and the second is a fault.
var ErrNoSuchPerson = errors.New("nobody here is called that")

// Resolve turns an identity into the subject it stands for.
//
// Somebody unknown, and somebody known but granted nothing, are both refused —
// with the same answer, deliberately.
func (s *Store) Resolve(ctx context.Context, identity string) (Subject, error) {
	return s.resolve(ctx, identity, false)
}

// resolve is Resolve, and says whether a grant a group derived has to be fresh.
//
// It does for a personal token and does not for a browser. A session's derived
// grants were written by the sign-in that issued it, so bounding them here
// would take roles away from somebody mid-session for being exactly as old as
// the session itself. A token has no sign-in behind it at all, which is the
// whole of what this is for.
func (s *Store) resolve(ctx context.Context, identity string, boundDerived bool) (Subject, error) {
	person, err := s.ByIdentity(ctx, identity)
	if err != nil {
		return Subject{}, ErrDenied
	}
	// Somebody who has left holds whatever they held, and reaches none of
	// it. Checked here because every way a person gets in comes through
	// this — a session, a personal token and a group-bound sign-in all
	// resolve by identity — so a second spelling of it would be a second
	// rule to keep in step (REQ-45).
	//
	// Their roles are deliberately not withdrawn. What they held is part of
	// why the record reads as it does, and restoring somebody who came back
	// should not mean reconstructing it from memory.
	if person.DeactivatedAt != nil {
		return Subject{}, ErrDenied
	}

	var held []Grant
	// Inactive grants are read past entirely. A row that grants nothing
	// must never be counted as access — not here, and not in any report or
	// review that asks what somebody holds.
	if err := s.db.NewSelect().Model(&held).
		Where("person_id = ?", person.ID).Where("active = ?", true).Scan(ctx); err != nil {
		return Subject{}, fmt.Errorf("read what %q may do: %w", identity, err)
	}
	grants := map[int64][]Role{}
	for _, grant := range held {
		// A row naming something that is not a role grants nothing. It can
		// only get there by hand or by a downgrade, and reading it as "some
		// role" would make it a grant of whatever the reader assumes.
		if !grant.Role.Valid() {
			continue
		}
		if boundDerived && s.stale(ctx, grant.Source, grant.CreatedAt) {
			continue
		}
		grants[grant.ProductID] = append(grants[grant.ProductID], grant.Role)
	}
	// A role held across every product is spread over the catalog as it stands
	// now, which is what makes a product declared after the grant covered
	// without anybody being re-granted anything (REQ-42). Read only where one
	// is held, so the ordinary subject costs nothing.
	var estate []EstateGrant
	if err := s.db.NewSelect().Model(&estate).
		Where("person_id = ?", person.ID).Where("active = ?", true).Scan(ctx); err != nil {
		return Subject{}, fmt.Errorf("read what %q may do everywhere: %w", identity, err)
	}
	if len(estate) > 0 {
		everywhere := make([]Role, 0, len(estate))
		for _, grant := range estate {
			if boundDerived && s.stale(ctx, grant.Source, grant.CreatedAt) {
				continue
			}
			if grant.Role.Valid() {
				everywhere = append(everywhere, grant.Role)
			}
		}
		products, err := s.everyProduct(ctx)
		if err != nil {
			return Subject{}, err
		}
		spreadEstate(grants, everywhere, products)
	}
	// Every case they were brought into, one issue at a time. Read beside
	// the roles because it is the same question — what may they reach —
	// asked at a smaller unit, and because being on a case is a grant:
	// somebody holding nothing but a case is somebody with access, not
	// somebody who slipped in.
	cases, err := s.CasesOf(ctx, person.ID)
	if err != nil {
		return Subject{}, err
	}
	// Administration a group conferred is bounded the same way the roles it
	// conferred are, and for the same reason: a group is what says so, and a
	// credential that never signs in never asks a group again. Without this a
	// person a group made an administrator, who minted a year-long token and
	// then left, went on administering through it — and administration is what
	// decides who may read anybody's notification feed.
	//
	// A stamp that is missing on a derived flag is treated as stale rather
	// than as fresh. It means nothing has confirmed it since the column
	// existed, which is the same thing the bound is for.
	administers := person.IsAdmin
	if boundDerived && person.AdminDerived {
		if person.AdminDerivedAt == nil || s.stale(ctx, Derived, *person.AdminDerivedAt) {
			administers = false
		}
	}
	// Auditing is bounded exactly as administration is, and for the same
	// reason: a group is what says so, and a credential that never signs in
	// never asks a group again.
	audits := person.Audits
	if boundDerived && person.AuditsDerived {
		if person.AuditsDerivedAt == nil || s.stale(ctx, Derived, *person.AuditsDerivedAt) {
			audits = false
		}
	}
	// Somebody holding the audit permission alone holds access: they reach no
	// product and read the deployment's own records, which is the whole of
	// what it is for.
	if !administers && !audits && len(grants) == 0 && len(cases) == 0 {
		return Subject{}, ErrDenied
	}

	// Written only when it has gone stale, not on every request. Every
	// authenticated request passes through here, so writing each time makes a
	// person's own row the hottest in the database and makes every read a
	// write — which a replica cannot serve from a follower and which, on a
	// cluster, turns two concurrent requests from one person into a
	// certification conflict at commit. The date is what anybody reads it for,
	// so an hour's resolution loses nothing.
	if seen := s.now().Truncate(time.Microsecond); staleEnough(person.LastSeenAt, seen) {
		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("last_seen_at = ?", seen).Where("id = ?", person.ID).Exec(ctx); err != nil {
			return Subject{}, fmt.Errorf("record that %q was seen: %w", identity, err)
		}
	}
	// Theirs is their own name in the assignable space, and
	// the name of every team they are on. Read here because this is the
	// one place a person becomes a subject, and "assigned to me" has to
	// mean the same thing on the list, the counts, the digest and the
	// reminders.
	teams, err := s.TeamsOf(ctx, person.ID)
	if err != nil {
		return Subject{}, err
	}
	on := make([]int64, 0, len(teams))
	for _, team := range teams {
		on = append(on, team.PartyID)
	}
	subject := NewPerson(person.ID, person.Identity, administers, grants,
		person.PartyID, on...).OnCases(cases)
	if audits {
		subject = subject.Auditing()
	}
	return subject, nil
}

// alreadyThere turns a refused insert into success where the state the caller
// asked for already holds.
//
// Every grant path wrote this out, and none of them asked what the failure was
// — so any insert error at all became success as long as a row was there,
// including one caused by a concurrent insert that was then rolled back. The
// question is only ever asked of a uniqueness violation, which is the one
// failure that means "somebody got there first".
//
// The predicate stays the caller's, because what "already holds" means is the
// one part that genuinely differs: a grant asks whether it is in force, a
// binding asks whether the row exists, and each says why beside itself.
//
// Where the row is there and the predicate says no, the caller hears what
// happened rather than the driver's constraint message — which is what an
// administrator was shown for an operation the endpoint documents as
// idempotent.
//
// The other way round is also in this package: AddToTeam reads and writes
// inside one transaction instead. Either is defensible; this is the one for a
// write whose refusal is a unique index rather than a row it has to see first.
func (s *Store) alreadyThere(ctx context.Context, insertErr error, what string,
	present func(context.Context) (bool, error)) error {

	if !database.IsDuplicate(insertErr) {
		return fmt.Errorf("%s: %w", what, insertErr)
	}
	there, err := present(ctx)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if there {
		return nil
	}
	return fmt.Errorf("%s: it is already recorded and is not in force, so it "+
		"cannot be granted again from here", what)
}

// GrantRole gives somebody a role on a product.
func (s *Store) GrantRole(ctx context.Context, personID, productID int64, role Role) error {
	if !role.Valid() {
		return fmt.Errorf("%q is not a role", role)
	}
	grant := &Grant{
		PersonID: personID, ProductID: productID, Role: role,
		Source: Assigned, Active: true,
		CreatedAt: s.now().Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(grant).Exec(ctx); err != nil {
		// Granting what somebody already holds is not a failure. In force,
		// like every other question about what somebody holds: a row set aside
		// by a change of mode grants nothing, so reporting success on one
		// would tell an administrator they had granted something that does not
		// exist.
		return s.alreadyThere(ctx, err, fmt.Sprintf("grant %q", role),
			func(ctx context.Context) (bool, error) {
				return s.holds(ctx, personID, productID, role)
			})
	}
	return nil
}

func (s *Store) holds(ctx context.Context, personID, productID int64, role Role) (bool, error) {
	n, err := s.db.NewSelect().Model((*Grant)(nil)).
		Where("person_id = ?", personID).Where("product_id = ?", productID).
		Where("role = ?", role).Where("active = ?", true).Count(ctx)
	return n > 0, err
}

// secretBytes is how much randomness a key carries.
//
// A key is not a password: it is generated here, never chosen, and never
// typed from memory. What it needs is enough entropy that guessing is not a
// strategy, which is also why the stored form is a plain digest rather than a
// slow hash — there is nothing to slow down when there is nothing to guess.
const secretBytes = 32

// NewKey creates a pipeline credential, returning the secret once.
//
// Once is the whole point. A credential store that can hand back what it holds
// is a credential store that hands over every pipeline's key along with a copy
// of the database.
func (s *Store) NewKey(ctx context.Context, name string, scope Scope) (*Key, string, error) {
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
	if _, err := s.db.NewInsert().Model(key).Exec(ctx); err != nil {
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
	err := s.db.NewSelect().Model(key).Where("secret_hash = ?", hashSecret(secret)).Scan(ctx)
	if err != nil {
		return Subject{}, ErrDenied
	}
	if key.RevokedAt != nil {
		return Subject{}, ErrDenied
	}

	used := s.now().Truncate(time.Microsecond)
	if _, err := s.db.NewUpdate().Model((*Key)(nil)).
		Set("last_used_at = ?", used).Where("id = ?", key.ID).Exec(ctx); err != nil {
		return Subject{}, fmt.Errorf("record that a key was used: %w", err)
	}
	return NewPipeline(key.ID, key.Name, Scope{
		ProductID: key.ProductID, StreamID: key.StreamID, VariantID: key.VariantID,
	}), nil
}

// Revoke stops a key working, without removing what it did.
func (s *Store) Revoke(ctx context.Context, keyID int64) error {
	_, err := s.db.NewUpdate().Model((*Key)(nil)).
		Set("revoked_at = ?", s.now().Truncate(time.Microsecond)).
		Where("id = ?", keyID).Where("revoked_at IS NULL").Exec(ctx)
	if err != nil {
		return fmt.Errorf("revoke key %d: %w", keyID, err)
	}
	return nil
}

// hashSecret is what gets stored.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// People lists everybody and what they hold, inactive grants included and
// marked as such.
//
// The rows are returned whole rather than filtered, because this is the view
// an access review reads: a grant that has been set aside has to be visible as
// set aside, not hidden and not counted. An inactive row must never read like
// a live one, which is what the caller renders.
func (s *Store) People(ctx context.Context) ([]Account, map[int64][]Grant, error) {
	var people []Account
	if err := s.db.NewSelect().Model(&people).Order("identity").Scan(ctx); err != nil {
		return nil, nil, fmt.Errorf("list people: %w", err)
	}
	var grants []Grant
	if err := s.db.NewSelect().Model(&grants).Order("person_id", "product_id").Scan(ctx); err != nil {
		return nil, nil, fmt.Errorf("list what people hold: %w", err)
	}
	held := map[int64][]Grant{}
	for _, grant := range grants {
		held[grant.PersonID] = append(held[grant.PersonID], grant)
	}
	return people, held, nil
}

// Grants lists what one person holds, inactive grants included and marked as
// such, the same way People reports them.
//
// Asked when a person has just been changed and the answer has to describe
// them: what is in force, and where each role came from, are the store's to
// say. Reading them back is the difference between reporting the record and
// repeating the request that changed it.
func (s *Store) Grants(ctx context.Context, personID int64) ([]Grant, error) {
	var grants []Grant
	if err := s.db.NewSelect().Model(&grants).
		Where("person_id = ?", personID).Order("product_id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what they hold: %w", err)
	}
	return grants, nil
}

// Withdraw takes a role away.
//
// The row is removed rather than marked. A grant is a statement about now, and
// what somebody used to hold is answered by the record of what they did, not
// by keeping a permission that no longer applies.
func (s *Store) Withdraw(ctx context.Context, personID, productID int64, role Role) error {
	res, err := s.db.NewDelete().Model((*Grant)(nil)).
		Where("person_id = ?", personID).
		Where("product_id = ?", productID).
		Where("role = ?", role).Exec(ctx)
	if err != nil {
		return fmt.Errorf("withdraw %q: %w", role, err)
	}
	// A withdrawal that matched nothing is not a withdrawal. Answered as
	// success, the caller wrote a trail row recording an act that did not
	// happen, and then asked whether the person still held anything here —
	// which, for a role they never had, came back no, and handed back every
	// finding they were dealing with in that product.
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("withdraw %q: %w", role, err)
	}
	if n == 0 {
		return fmt.Errorf("they do not hold %q here: %w", role, ErrNothingMatched)
	}
	return nil
}

// HoldsAnythingIn reports whether somebody still has any role on a product.
//
// Asked after a role is withdrawn, because the last one going is what turns
// their assigned work into work nobody can reach: assigned, so not in the
// shared queue, and assigned to somebody who can no longer open it.
func (s *Store) HoldsAnythingIn(ctx context.Context, personID, productID int64) (bool, error) {
	// And they are still here. A departed person's grant rows are left in
	// place deliberately, so counting them left their work with somebody who
	// is refused at sign-in and the answer said nothing was released.
	here, err := s.here(ctx, personID)
	if err != nil || !here {
		return false, err
	}
	// Any role at all, asked of the same union every other question uses. In
	// force, like every question about what somebody holds: a row that grants
	// nothing must never be counted as access — a grant left inactive by a
	// switch to group-bound roles answers "they still hold something here", so
	// their assigned findings stay with somebody who can no longer open them
	// and the response says nothing was released. And a role held across
	// every product is a role held here, so withdrawing their last per-product
	// grant does not leave their work unreachable.
	held, err := holdingAny(s.db.NewSelect().
		TableExpr(`"person" AS "p"`).ColumnExpr("p.id").
		Where("p.id = ?", personID), "p.id", Roles(), productID).Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read what they still hold: %w", err)
	}
	return held, nil
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

// Names resolves people to what to call them, for showing who did something.
//
// A display name where one is known, and the identity they signed in with
// otherwise. Batched because the alternative is a query per row, and the
// places this is needed — a review queue, a list of what was dismissed — are
// exactly the ones that are long.
//
// What this answers is never sent back to a lookup. A display name is a
// label somebody chose and resolves to nobody; Handles is what a route naming
// a person in its path matches.
func (s *Store) Names(ctx context.Context, ids []int64) (map[int64]string, error) {
	names := map[int64]string{}
	if len(ids) == 0 {
		return names, nil
	}
	var people []Account
	if err := s.db.NewSelect().Model(&people).
		Column("id", "identity", "display_name").
		Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who these people are: %w", err)
	}
	for _, person := range people {
		if person.DisplayName != "" {
			names[person.ID] = person.DisplayName
			continue
		}
		names[person.ID] = person.Identity
	}
	return names, nil
}

// Handles resolves people to the identity they sign in under.
//
// Beside Names, and the other half of it: Names is for showing and this is for
// resolving, and wherever somebody has a display name the two are different
// strings. ByIdentity matches the folded identity column alone, so a list that
// published a display name in a field a route resolves could not be acted on —
// which is how a collaborator on an embargoed case became somebody the API
// could list and not remove.
//
// The package offered no batch identity lookup at all, so a handler that had
// to round-trip a name had nothing else to reach for.
func (s *Store) Handles(ctx context.Context, ids []int64) (map[int64]string, error) {
	handles := map[int64]string{}
	if len(ids) == 0 {
		return handles, nil
	}
	var people []Account
	if err := s.db.NewSelect().Model(&people).
		Column("id", "identity").
		Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these people sign in as: %w", err)
	}
	for _, person := range people {
		handles[person.ID] = person.Identity
	}
	return handles, nil
}

// Mentionable is somebody who could be named in text about a product.
type Mentionable struct {
	// ID is who they are, for telling them. It is not offered to a caller —
	// the editor needs the name to write and nothing else — and it is here so
	// that whoever may be *offered* and whoever may be *told* come from one
	// query rather than two that could come to disagree.
	ID       int64  `bun:"id"`
	Identity string `bun:"identity"`
	Name     string `bun:"name"`
}

// WhoCanRead lists the people who may read findings of this visibility in this
// product, for offering as mentions.
//
// Offering only people who can already see the thing is the whole point.
// An autocomplete that lists everybody teaches somebody to mention a colleague
// who then cannot open what they were called to, and on an undisclosed finding
// the mention itself says that a finding exists — which is the disclosure the
// visibility rule is there to prevent.
//
// An administrator is not included for being one. Administering the
// catalog is not reading its findings, which is the split the roles were
// separated to make possible — so an administrator holding nothing on the
// product was offered as a mention target on an undisclosed finding there,
// and the mention itself told them a finding exists that they may not open.
// One who wants to be mentionable grants themselves a read role, which is how
// everything else here works.
//
// Inactive grants are read past entirely, the same way every other question
// about what somebody holds reads past them, and so is somebody who has left:
// they are refused at sign-in, so offering their name mentions somebody who
// will never see it.
func (s *Store) WhoCanRead(ctx context.Context, subject Subject, productID int64,
	visibility Visibility, term string, limit int) ([]Mentionable, error) {

	// Asking who may read something undisclosed is itself a question about
	// undisclosed work, and the answer is the one every other read gives:
	// nothing. Asked here rather than only at the two handlers that call it,
	// because a third endpoint over this query would answer for everybody —
	// which is the rule this project does not bend, and the gate was written
	// out at each caller instead of being carried on the query.
	if !subject.Reads(visibility, productID) {
		return nil, nil
	}
	limit = database.APicker.Of(limit)

	query := s.readersIn(productID, visibility)
	if query == nil {
		return nil, nil
	}
	query = narrowToTerm(query.OrderExpr("p.identity").Limit(limit), term)
	// Narrowed here rather than in the caller, because a picker at a
	// hundred people cannot fetch them all and filter in a browser — and
	// the limit would cut the list before the term did, so the name
	// somebody typed would be missing from a list that says it matched
	// nothing.
	//
	// Lowered on both sides rather than asked to compare loosely: the
	// engines do not agree on what a case-insensitive comparison is, and
	// one spelled the same way everywhere behaves the same way everywhere.
	//
	// Folded here and again by the engine, and this is the caller where that
	// still costs something. Folding in Go is Unicode-aware and LOWER() on
	// SQLite is ASCII-only, so a display name carrying a non-ASCII capital is
	// found on three engines and missed on the fourth. An identity is an
	// address and ASCII; a display name is free human text and has no folded
	// column to compare against, unlike the component names that do.
	//
	// Escaped, because a search box is not a pattern language: a term of "%"
	// matched every person the deployment could offer, in one request, from
	// the picker that decides who may be named on an embargoed case.
	var found []Mentionable
	if err := query.Scan(ctx, &found); err != nil {
		return nil, fmt.Errorf("read who may be mentioned: %w", err)
	}
	return found, nil
}

// narrowToTerm is the picker's own matching, spelled once so the page and the
// count of it cannot come to narrow differently.
func narrowToTerm(query *bun.SelectQuery, term string) *bun.SelectQuery {
	wanted := strings.TrimSpace(term)
	if wanted == "" {
		return query
	}
	like := database.LikeContains(wanted)
	return query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.WhereOr("LOWER(p.identity) LIKE ?"+database.LikeClause, like).
			WhereOr("LOWER(COALESCE(NULLIF(p.display_name, ''), p.identity)) LIKE ?"+
				database.LikeClause, like)
	})
}

// CountWhoCanRead is how many the picker has to choose from in all.
//
// The same narrowing as the page above, so a listing that says "25 of 140" is
// counting the thing it is showing part of. Asked as its own statement rather
// than read off the page, for the reason every capped listing here states: a
// figure taken from a page answers a different question from the one it looks
// like.
func (s *Store) CountWhoCanRead(ctx context.Context, subject Subject, productID int64,
	visibility Visibility, term string) (int, error) {

	if !subject.Reads(visibility, productID) {
		return 0, nil
	}
	query := s.readersIn(productID, visibility)
	if query == nil {
		return 0, nil
	}
	total, err := narrowToTerm(query, term).Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count who may be mentioned: %w", err)
	}
	return total, nil
}

// ReadersNamed resolves these sign-in identities to the people among them who
// may read findings of this visibility in this product.
//
// The resolver behind a mention, and the reason it is not the picker's query
// with a different argument: the picker narrows by what somebody typed and
// then takes a page, and a mention has a name in hand and needs the answer
// for that name. Paging the picker instead answered from the
// alphabetically-first hundred readers, so mentioning anybody sorting past
// position one hundred reached nobody, deterministically, and the author was
// told the name matched nobody — a failure that grows with the deployment.
//
// A name nobody holds and a name held by somebody who may not read this both
// come back absent, and are not told apart.
func (s *Store) ReadersNamed(ctx context.Context, subject Subject, productID int64,
	visibility Visibility, names []string) ([]Mentionable, error) {

	// The same gate the picker carries, for the same reason: what this answers
	// is who may read something, which is a fact about the thing being read.
	if !subject.Reads(visibility, productID) {
		return nil, nil
	}
	query := s.readersIn(productID, visibility)
	if query == nil || len(names) == 0 {
		return nil, nil
	}
	wanted := make([]string, 0, len(names))
	for _, name := range names {
		wanted = append(wanted, strings.ToLower(strings.TrimSpace(name)))
	}
	// Lowered on both sides rather than asked to compare loosely, for the
	// reason the picker does it: the engines do not agree on what a
	// case-insensitive comparison is.
	var found []Mentionable
	if err := query.Where("LOWER(p.identity) IN (?)", bun.List(wanted)).
		Scan(ctx, &found); err != nil {
		return nil, fmt.Errorf("read who may be told: %w", err)
	}
	return found, nil
}

// readersIn is the half the picker and the mention resolver share: the people
// who may read findings of this visibility in this product.
//
// Nil where no role reaches that visibility at all, which is an answer rather
// than an empty condition to be filled in.
func (s *Store) readersIn(productID int64, visibility Visibility) *bun.SelectQuery {
	// The roles enough to read at this visibility, asked of the rule
	// rather than of a list. It was the same four lines as rolesReading, in
	// the same package, one of them named and one not — which is how "may
	// read" comes to mean two things.
	enough := rolesReading(productID, visibility)
	if len(enough) == 0 {
		return nil
	}
	return holdingAny(s.db.NewSelect().
		TableExpr(`"person" AS "p"`).
		ColumnExpr(`p.id AS "id"`).
		ColumnExpr(`p.identity AS "identity"`).
		ColumnExpr(`COALESCE(NULLIF(p.display_name, ''), p.identity) AS "name"`).
		Where("p.deactivated_at IS NULL"), "p.id", enough, productID)
}

// Deactivate records that somebody has left, and Reactivate that they are
// back.
//
// Never a deletion. The record names them as the proposer of judgments and the
// approver of others, and an assignment may point at them; deleting the row
// would either break those or rewrite what happened. So leaving is a date, and
// every path in reads it (REQ-45).
//
// Their roles are left where they are. What somebody held is part of why
// the record reads as it does, and restoring an account should not mean
// reconstructing its grants from memory. What stops them is the date, which is
// read before anything else about them.
//
// Reports whether it changed anything, so a caller can tell "done" from
// "already". Deactivating somebody twice is not an error — an administrator
// clicking again, or two of them acting at once, is the ordinary case — but
// the second one does not move the date, because the date is when they left.
func (s *Store) Deactivate(ctx context.Context, personID int64) (bool, error) {
	res, err := s.db.NewUpdate().Model((*Account)(nil)).
		Set("deactivated_at = ?", s.now().Truncate(time.Microsecond)).
		Where("id = ?", personID).
		Where("deactivated_at IS NULL").
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("record that they left: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return false, fmt.Errorf("record that they left: %w", err)
	}
	return n > 0, nil
}

// Reactivate clears the date, so they may sign in again with whatever they
// still hold.
func (s *Store) Reactivate(ctx context.Context, personID int64) (bool, error) {
	res, err := s.db.NewUpdate().Model((*Account)(nil)).
		Set("deactivated_at = ?", nil).
		Where("id = ?", personID).
		Where("deactivated_at IS NOT NULL").
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("record that they are back: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return false, fmt.Errorf("record that they are back: %w", err)
	}
	return n > 0, nil
}
