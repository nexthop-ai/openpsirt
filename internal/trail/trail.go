// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package trail records what somebody changed about how this deployment works.
//
// Not what was triaged — that is the decision history, and it is kept beside
// the decisions. This is the layer above: the settings, grants and dates that
// decide what the triage record *says*.
package trail

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Kind is what sort of thing was changed. A reader filters by it, so the set
// is small and named for what somebody would look for rather than for which
// table was written.
type Kind string

const (
	// Setting is a value in the settings, including the three that rewrite
	// what the tool reports: the deadline windows, the triage floor, and how
	// roles are assigned.
	Setting Kind = "setting"
	// Role is a grant or a withdrawal against one product.
	Role Kind = "role"
	// Support is an end-of-life date on a product or a release, which takes
	// the deadline off everything in it.
	Support Kind = "support"
	// Credential is a key or a token: made, or revoked.
	Credential Kind = "credential"
	// Account is somebody recorded, which is the act that lets them in at all.
	Account Kind = "account"
	// Team is a team declared or retired, or somebody put on one or taken off.
	Team Kind = "team"
	// Routing is a standing rule that hands unheld work to a team, added or
	// retired. Not a Role: a role is granted to a person against one product,
	// and a routing rule grants nobody anything — it decides who is asked.
	Routing Kind = "routing"
	// Alias is another identifier an issue answers to. Deployment-wide and
	// permanent: from the moment it is recorded, a scan of any product
	// reporting that name resolves to this issue and inherits its decisions.
	// Neither a setting nor a grant, and the one act here that changes what a
	// later scan means.
	Alias Kind = "alias"
	// Release is when a tag went out and what it was cut from. Both are
	// recorded after the fact and both change what a chart and a set of
	// release notes say, so who moved them is the same question as who moved
	// an end-of-life date.
	Release Kind = "release"
	// Catalog is a product, a release or a variant renamed or retired, and
	// what a variant reaches corrected. What the catalog holds decides what a
	// scan may name, what every picker offers and how a finding ranks, so
	// moving one moves what the tool reports. Not a Release: that is a tag's
	// ship date and what it was cut from, which are facts about one release
	// rather than about what the catalog holds.
	Catalog Kind = "catalog"
	// ExploitedHere is somebody recording that a product was exploited
	// through an issue, or clearing that record. Not a triage decision: it is a fact
	// about an incident rather than a judgment about a finding, and what it
	// does is decide what the triage record may say — a claim that the issue
	// does not apply is refused while it stands, and one already agreed to
	// has its agreement taken back. That is the same kind of act as an alias,
	// and it belongs beside one.
	ExploitedHere Kind = "exploited-here"
	// Case is somebody brought into one undisclosed case, or taken off it
	// . An access change like the rest of these: it is the one way
	// somebody reaches an embargoed finding without holding private
	// reading on the product, so who was let in and when is exactly what
	// is asked afterwards.
	Case Kind = "case"
	// Merge is a judgment a report's merge of two issues took out of force
	// because another stood in its place in the same product: a rating claim
	// withdrawn, or a record of being attacked cleared. Nobody chose which of
	// the two stands, so what the product lost is asked about afterwards.
	Merge Kind = "merge"
)

// Kinds is every kind there is, in the order the API offers them.
//
// Named here rather than written out wherever one is offered. The set is
// small and grows one at a time, and a kind added to the constants above and
// missed in a list somewhere else is a kind nothing can be filtered by —
// which shows up as an empty screen rather than as a failure.
func Kinds() []Kind {
	return []Kind{
		Setting, Role, Routing, Support, Release,
		Credential, Account, Team, Case, Alias, Catalog, ExploitedHere, Merge,
	}
}

// Actor is what made a change: a person, the deployment's startup
// configuration, a merge of two issues, or an upgrade. An upgrade's rows are
// written by the migration that makes them, which holds its own copy of the
// word "upgrade" as it holds its own copy of every rule it applies.
type Actor string

const (
	// ByPerson is a change somebody made in the application. The person is
	// named beside it.
	ByPerson Actor = "person"
	// ByConfiguration is a change the deployment's startup configuration
	// made, which names no person. Only the administrators configuration
	// names are changed this way.
	ByConfiguration Actor = "configuration"
	// ByMerge is a change a scan made by merging two issues its report named
	// together, which names no person.
	ByMerge Actor = "merge"
)

// Change is one administrative act.
type Change struct {
	bun.BaseModel `bun:"table:admin_change,alias:ac"`

	ID int64     `bun:"id,pk,autoincrement"`
	At time.Time `bun:"at,notnull"`
	// Actor is what made it, and never absent: a change nobody made is a
	// change nothing records, which is the state this exists to end.
	Actor Actor `bun:"actor,notnull"`
	// By is the person who made it. Absent where no person did.
	By   *int64 `bun:"by"`
	Kind Kind   `bun:"kind,notnull"`
	Name string `bun:"about,notnull"`
	// Was is what it held before and Became what it holds now. Absent before
	// means nobody had set it; absent after means it was cleared. The two are
	// different acts and a blank cannot tell them apart.
	Was    *string `bun:"was"`
	Became *string `bun:"became"`
}

// Person is who made the change, or zero where configuration did.
func (c Change) Person() int64 {
	if c.By == nil {
		return 0
	}
	return *c.By
}

// NameLimit is how much of what a change is about the column holds.
//
// A store must not be able to overflow its own column. What is written
// here is composed by the caller from names — a collaborator is a product, an
// issue and a person — and the column is sized for three of them with their
// separators. Every caller composes from stored values, each of which is a
// name's own width, so this never fires; it is here because "every caller
// does the right thing" is not a property anything checks, and the failure it
// would otherwise take is the act refused rather than the record shortened.
//
// Bounded by runes rather than bytes: the column counts characters, and
// cutting a multi-byte name mid-rune would store something that is not text.
//
// The column's own width, taken from where the column is declared rather than
// written out again: a bound and the column it protects that are two copies of
// one number are two numbers eventually.
const NameLimit = database.ComposedWidth

// Store reads and writes the trail.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Record writes one administrative act.
//
// Called where the actor is known, which is the request that made the change:
// the stores underneath take no subject, and threading one through every
// setting write to reach this would make a signature about auditing rather
// than about the thing being written.
//
// Written in the transaction that makes the change, so a failure here
// fails the change. Both are one act, and a change recorded nowhere is the
// state this table exists to prevent; nothing was committed, so the retry a
// caller makes changes nothing twice.
func (s *Store) Record(ctx context.Context, by access.Subject, kind Kind, name string,
	was, became *string) error {

	if by.Kind != access.Person || by.ID == 0 {
		return refusal.Errorf("an administrative change is recorded against whoever made it")
	}
	person := by.ID
	return s.write(ctx, &Change{Actor: ByPerson, By: &person,
		Kind: kind, Name: name, Was: was, Became: became})
}

// RecordByConfiguration writes one change the deployment's startup
// configuration made, in the transaction that makes it.
func (s *Store) RecordByConfiguration(ctx context.Context, kind Kind, name string,
	was, became *string) error {

	return s.write(ctx, &Change{Actor: ByConfiguration,
		Kind: kind, Name: name, Was: was, Became: became})
}

// RecordByMerge writes one change a merge of two issues made, in the
// transaction that makes it.
func (s *Store) RecordByMerge(ctx context.Context, kind Kind, name string,
	was, became *string) error {

	return s.write(ctx, &Change{Actor: ByMerge,
		Kind: kind, Name: name, Was: was, Became: became})
}

// NamedInConfiguration and UnnamedByConfiguration are what the trail says
// about an account when configuration names an administrator and when it
// stops naming them.
const (
	NamedInConfiguration   = "administrator: named in OPENPSIRT_BOOTSTRAP_ADMINS"
	UnnamedByConfiguration = "administration removed: OPENPSIRT_BOOTSTRAP_ADMINS no longer names them"
)

// NameAdministrators applies the administrators configuration names, and
// records each one it names or stops naming, against configuration, in one
// transaction. It answers who stopped being named.
//
// Applied at every start rather than only the first, which makes it the
// documented way back in: an operator who has locked themselves out adds
// themselves and restarts. It is a pre-authorization rather than a bypass.
// Being named grants the role; it does not admit anybody who has not
// authenticated.
//
// A start that names the same people as the last one records nothing.
func NameAdministrators(ctx context.Context, db bun.IDB, identities []string) ([]string, error) {
	var naming access.Naming
	err := database.Within(ctx, db, func(ctx context.Context, db bun.IDB) error {
		var err error
		if naming, err = access.NewStore(db).NameBootstrapAdmins(ctx, identities); err != nil {
			return err
		}
		store := NewStore(db)
		for _, identity := range naming.Named {
			if err := store.RecordByConfiguration(ctx, Account, identity,
				nil, Said(NamedInConfiguration, true)); err != nil {
				return err
			}
		}
		for _, identity := range naming.Unnamed {
			if err := store.RecordByConfiguration(ctx, Account, identity,
				Said(NamedInConfiguration, true), Said(UnnamedByConfiguration, true)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return naming.Unnamed, nil
}

func (s *Store) write(ctx context.Context, change *Change) error {
	change.At = s.now().Truncate(time.Microsecond)
	change.Name = bound.HeadRunes(change.Name, NameLimit)
	if _, err := s.db.NewInsert().Model(change).Exec(ctx); err != nil {
		return fmt.Errorf("record that %q changed: %w", change.Name, err)
	}
	return nil
}

// Over is the stretch of time a read of the trail covers.
//
// A zero start is the beginning and a zero end is now, which is what an
// unbounded side means. The end is not itself in it, like every other period
// this tool answers about.
type Over struct {
	Since time.Time
	Until time.Time
}

// Changes reads the trail, newest first, optionally of one kind and over a
// period.
//
// Paged, because it only grows: a deployment a year old has every setting
// anybody ever moved in it, and a screen that asks for all of them is one that
// stops answering. A period is what makes it usable at that size: an audit
// asks what changed in the year the certificate covers, and paging back
// through everything since is not that question.
func (s *Store) Changes(ctx context.Context, by access.Subject, kind Kind, over Over,
	limit, offset int) ([]Change, int, error) {

	if err := readable(by); err != nil {
		return nil, 0, err
	}
	limit = database.AList.Of(limit)
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		if kind != "" {
			q = q.Where("kind = ?", kind)
		}
		if !over.Since.IsZero() {
			q = q.Where("at >= ?", over.Since)
		}
		if !over.Until.IsZero() {
			q = q.Where("at < ?", over.Until)
		}
		return q
	}
	return s.page(ctx, narrow, limit, offset, "what has been changed")
}

// About reads the trail for one subject of a change, newest first.
//
// The trail names what changed rather than pointing at it — a role change is
// recorded as "somebody on some product" — so this asks for the name and for
// every name beginning with it followed by " on ". That covers a role, which is
// per product, and a change recorded against the bare name.
//
// Everything LIKE treats as special is escaped. An identity is an email address
// and "_" is a wildcard, so `a_b@example.com` would otherwise match
// `axb@example.com` and report somebody else's history as this person's. The
// escape character is "#" rather than a backslash, because a backslash inside a
// string literal is itself an escape on two of the four engines and `ESCAPE
// '\'` does not parse there at all — the same reason the routing rules use it.
func (s *Store) About(ctx context.Context, by access.Subject, kind Kind, name string,
	limit, offset int) ([]Change, int, error) {

	if err := readable(by); err != nil {
		return nil, 0, err
	}
	limit = database.AList.Of(limit)
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		if kind != "" {
			q = q.Where("kind = ?", kind)
		}
		return q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("about = ?", name).
				WhereOr(`about LIKE ?`+database.LikeClause, database.LikeEscaped(name)+" on %")
		})
	}
	return s.page(ctx, narrow, limit, offset, fmt.Sprintf("what changed about %q", name))
}

// page is one page of the trail under a narrowing, newest first, with how many
// the narrowing holds in all. what names the reading, for its errors.
func (s *Store) page(ctx context.Context, narrow func(*bun.SelectQuery) *bun.SelectQuery,
	limit, offset int, what string) ([]Change, int, error) {

	total, err := narrow(s.db.NewSelect().Model((*Change)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count %s: %w", what, err)
	}
	var changes []Change
	err = narrow(s.db.NewSelect().Model(&changes)).
		Order("at DESC", "id DESC").
		Limit(limit).Offset(offset).
		Scan(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", what, err)
	}
	return changes, total, nil
}

// readable refuses a subject that holds nothing over this deployment.
//
// Here rather than in the handler that asks, because a row names who was
// brought into which case and an undisclosed one is among them — so this is a
// query about who may read something rather than a shape a handler happens to
// guard, and a check in a handler is the one somebody forgets (REQ-42 and
// REQ-43). A refusal rather than an empty page: a reader who may not ask is
// told so, instead of being shown a deployment where nobody has ever changed
// anything.
//
// The record is shown whole, not narrowed by which products the reader
// reaches. It names them — a role granted on one, a release whose support date
// moved — so holding this means knowing which products exist and what their
// releases are called. That is a property of the grant rather than a leak:
// granting it is a deliberate administrative act, and the alternative is an
// audit record with holes in it that nothing marks.
func readable(by access.Subject) error {
	if by.ReadsTheDeployment() {
		return nil
	}
	// The deployment itself rather than anybody in it — a background pass
	// reporting on the tool, which answers nobody.
	if by.Unnarrowed() {
		return nil
	}
	return access.Denied("read the administrative trail")
}

// Said turns a value into what the trail stores, where absent means unset.
func Said(value string, set bool) *string {
	if !set {
		return nil
	}
	return &value
}
