package finding

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// ErrSamePerson says work was handed from somebody to themselves.
//
// A sentinel because it is the one refusal here that is about what was asked
// rather than about what went wrong. Everything else this returns is a
// database that could not answer, and reporting those to a caller as though
// they were its fault is how a driver's error text ends up on a screen.
var ErrSamePerson = errors.New("that would hand their work to themselves")

// moveWork is the write itself, apart from the answering: which rows move, and
// what they move to.
//
// Taken out of Assign so that an act which hands over several pieces of work at
// once — planning an upgrade, which promises the whole component — can do it
// inside the transaction that records the promise, under the same rule and
// with the same narrowing. A second copy of this update would be a second
// place for the dispatch rule to be forgotten.
func (s *Store) moveWork(ctx context.Context, db bun.IDB, subject access.Subject,
	productID, vulnerabilityID, componentID int64, to *int64, dispatches bool,
	visible []access.Visibility) (int64, error) {

	now := s.now().UTC().Truncate(time.Microsecond)
	update := db.NewUpdate().Model((*Finding)(nil)).
		// Across the product's builds, not one of them. The same code
		// built as several variants is one piece of work — a judgment
		// carries no variant, so somebody taking this on has taken on
		// every build of the product holding the same component.
		// Assigning one build left the identical work unassigned
		// beside it, which is how a person ends up holding half of
		// what they think they hold.
		Where(`target_id IN (SELECT tg.id FROM "target" AS "tg"
			JOIN "stream" AS "st" ON st.id = tg.stream_id
			WHERE st.product_id = ?)`, productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("component_id = ?", componentID).
		Where("closed_at IS NULL").
		// Narrowed by what this person may see, like every other query here. A
		// finding nobody has disclosed is not one somebody may hand around.
		Where("visibility IN (?)", bun.List(visible))

	// Without the right to dispatch, this only ever moves what nobody owns or
	// what is already theirs. Asked here rather than beforehand so that the
	// engine answers it at the moment of the write: there is no window for a
	// colleague's assignment to land in, and a row that stopped qualifying is
	// simply not matched.
	if !dispatches {
		// What nobody holds, what is already theirs, and what is
		// sitting in a queue of a team they are on. That last is not
		// taking work off a colleague, which is the act the dispatch
		// right names: work routed to a team is unheld until somebody
		// takes it, so anybody on the team picks it up under triage
		// alone.
		update = update.Where("assigned_to IS NULL OR assigned_to IN (?)",
			bun.List(subject.Mine()))
	}

	if to == nil {
		update = update.Set("assigned_to = ?", nil).Set("assigned_at = ?", nil)
	} else {
		update = update.Set("assigned_to = ?", *to).Set("assigned_at = ?", now)
	}

	result, err := update.Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("record who is dealing with this: %w", err)
	}
	moved, err := database.Affected(result)
	if err != nil {
		return 0, fmt.Errorf("record who is dealing with this: %w", err)
	}
	return moved, nil
}

// HandOverWithin gives several pieces of work to one party inside a
// transaction somebody else opened, under the rule Assign holds.
//
// What it exists for: planning an upgrade is one act that answers a whole
// component, and saying who is carrying it is part of that act rather than a
// second one somebody might forget. Recorded in the same transaction, so a
// promise nobody is carrying and a holder with no promise are both impossible.
//
// Product-wide, like every other assignment: the promise is per build, and who
// is carrying the work is not — somebody moving the package on one release is
// who moves it on the next.
func (s *Store) HandOverWithin(ctx context.Context, tx bun.IDB, subject access.Subject,
	productID int64, work [][2]int64, to *int64) (int64, error) {

	if !subject.Triages(access.Public, productID) {
		return 0, access.Denied(fmt.Sprintf(
			"decide who deals with findings in product %d", productID))
	}
	dispatches := subject.Holds(access.Assigner, productID)
	if !dispatches && to != nil && *to != subject.Party() {
		return 0, access.Denied(fmt.Sprintf(
			"give work to somebody else in product %d — you may take what nobody owns, "+
				"and hand back your own", productID))
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return 0, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	var moved int64
	for _, each := range work {
		n, err := s.moveWork(ctx, tx, subject, productID, each[0], each[1], to,
			dispatches, visible)
		if err != nil {
			return 0, err
		}
		moved += n
	}
	return moved, nil
}

// Assign records who is dealing with an issue in a component, across every
// build of one product that holds it.
//
// Set for the whole group at once rather than per place: assigning one place
// of an issue and not another is not something anybody means to do, and the
// places of a group are the same problem seen from several parents. **Across
// builds for the same reason** — the same code built as several variants is
// one piece of work, and it is answered by one judgment.
//
// Assigning to nobody is how something is handed back, and is deliberately the
// same operation — taking work back is not a different kind of act from giving
// it out, and making it one produces two paths that drift. The build is named
// rather than the product, and the product is resolved from it here. Both are
// int64, so a caller passing the wrong one is invisible to the compiler — and
// it is invisible on SQLite too, where a fresh database makes the first
// product and the first build both 1. Taking the build keeps every call site
// saying what it is looking at and leaves one place that knows the grain.
//
// **The party work lands on is a person or a team**, in the column that already
// holds one. Nothing here asks which it is: the whole point of one
// column is that every filter, count and handover asks "who holds this" once.
func (s *Store) Assign(ctx context.Context, subject access.Subject, targetID, vulnerabilityID,
	componentID int64, to *int64) (moved int64, undisclosed bool, err error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return 0, false, err
	}
	// Deciding who deals with something is a write, so it asks for a
	// right. Being able to *see* a finding is not being able to hand it
	// around, and narrowing by visibility is not an authorization check —
	// it stops somebody assigning what they cannot see, not somebody
	// assigning.
	//
	// Which right depends on who it lands on. Taking work nobody owns, and
	// handing back your own, are part of triaging: the constant stream of
	// unowned findings assigning what is there now produces would
	// otherwise need somebody's attention before anybody could start.
	// Putting work on somebody else, or taking what they are holding, is a
	// different act and asks for the right that names it.
	triages := subject.Triages(access.Public, productID)
	if !triages {
		return 0, false, access.Denied(fmt.Sprintf("decide who deals with findings in product %d", productID))
	}
	// Whether this caller may put work on somebody else, or take what
	// somebody else holds. Where they may not, the rule is carried into the
	// write below rather than checked before it: a check and a write that are
	// two statements are two moments, and a colleague's assignment landing
	// between them is all it takes to reassign what the rule just refused.
	dispatches := subject.Holds(access.Assigner, productID)
	if !dispatches && to != nil && *to != subject.Party() {
		return 0, false, access.Denied(fmt.Sprintf(
			"give work to somebody else in product %d — you may take what nobody owns, "+
				"and hand back your own", productID))
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return 0, false, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	moved, err = s.moveWork(ctx, s.db, subject, productID, vulnerabilityID, componentID,
		to, dispatches, visible)
	if err != nil {
		return 0, false, err
	}
	if moved == 0 {
		// Nothing moved. For a caller who may not dispatch, that is either
		// "there is nothing there" or "somebody else is holding it", and the
		// two deserve different answers — so the question is asked once, on
		// the failing path only, and narrowed by what this person may see so
		// that the answer cannot describe a row they may not read.
		if !dispatches {
			held, err := s.db.NewSelect().Model((*Finding)(nil)).
				Column("id").
				Where(`target_id IN (SELECT tg.id FROM "target" AS "tg"
					JOIN "stream" AS "st" ON st.id = tg.stream_id
					WHERE st.product_id = ?)`, productID).
				Where("vulnerability_id = ?", vulnerabilityID).
				Where("component_id = ?", componentID).
				Where("closed_at IS NULL").
				Where("visibility IN (?)", bun.List(visible)).
				Where("assigned_to IS NOT NULL").
				Where("assigned_to NOT IN (?)", bun.List(subject.Mine())).
				Exists(ctx)
			if err != nil {
				return 0, false, fmt.Errorf("read who is dealing with this: %w", err)
			}
			if held {
				return 0, false, access.Denied(fmt.Sprintf(
					"take work somebody else is dealing with in product %d — you may take "+
						"what nobody owns, and hand back your own", productID))
			}
		}
		return 0, false, nil
	}

	// Whether what was just handed over is a finding nobody has announced.
	//
	// Answered here because the caller has to know it to decide what may
	// be said about it outside the application and cannot see the rows
	// from where it stands. Asked after the write and narrowed the same
	// way, so it describes what actually moved. Any one row answers: they
	// are one issue at one component in one build, and visibility belongs
	// to the finding rather than to the place.
	private, err := s.db.NewSelect().Model((*Finding)(nil)).
		Column("id").
		Where(`target_id IN (SELECT tg.id FROM "target" AS "tg"
			WHERE tg.stream_id IN (SELECT st.id FROM "stream" AS "st"
				WHERE st.product_id = ?))`, productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("component_id = ?", componentID).
		Where("closed_at IS NULL").
		Where("visibility = ?", access.Private).
		Exists(ctx)
	if err != nil {
		return moved, false, fmt.Errorf("read whether that finding is disclosed: %w", err)
	}
	return moved, private, nil
}

// StrictestOf is the tightest visibility any open place of this finding
// carries, across the product's builds.
//
// The question routing asks: work goes to a party that can read all of what is
// routed there, and one undisclosed place among fifty public ones makes the
// whole of it undisclosed for that purpose. Reading what is undisclosed
// implies reading what is not, so the strictest is the only one worth asking
// about.
//
// Narrowed by what the caller may see, like every other read here. A place
// they cannot see is not one they can route.
func (s *Store) StrictestOf(ctx context.Context, subject access.Subject, targetID,
	vulnerabilityID, componentID int64) (access.Visibility, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return access.Public, err
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return access.Public, access.Denied(
			fmt.Sprintf("read findings in product %d", productID))
	}
	private, err := s.db.NewSelect().Model((*Finding)(nil)).
		Column("id").
		Where(`target_id IN (SELECT tg.id FROM "target" AS "tg"
			JOIN "stream" AS "st" ON st.id = tg.stream_id
			WHERE st.product_id = ?)`, productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("component_id = ?", componentID).
		Where("closed_at IS NULL").
		Where("visibility IN (?)", bun.List(visible)).
		Where("visibility = ?", access.Private).
		Exists(ctx)
	if err != nil {
		return access.Public, fmt.Errorf("read how far this is disclosed: %w", err)
	}
	if private {
		return access.Private, nil
	}
	return access.Public, nil
}

// StrictestOnComponent is how far the least disclosed thing open against a
// component in these builds has been announced.
//
// The same question StrictestOf asks about one finding, asked about everything
// an upgrade covers. Handing a promise to somebody is handing them what it
// covers, and one embargoed finding among fifty is enough to make the handover
// the disclosure — so the level that matters is the strictest in the set
// rather than that of whichever row somebody happened to be looking at.
func (s *Store) StrictestOnComponent(ctx context.Context, subject access.Subject,
	productID int64, targets []int64, component string) (access.Visibility, error) {

	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return access.Public, access.Denied(
			fmt.Sprintf("read findings in product %d", productID))
	}
	if len(targets) == 0 {
		return access.Public, nil
	}
	// Matched on the fold, the way the upgrade itself resolves what it covers:
	// naming any binary of a source package reaches all of them, so asking
	// about the binary alone would miss the embargo sitting on its sibling.
	private, err := s.db.NewSelect().Model((*Finding)(nil)).
		Column("id").
		Where("target_id IN (?)", bun.List(targets)).
		Where("closed_at IS NULL").
		Where("visibility IN (?)", bun.List(visible)).
		Where("visibility = ?", access.Private).
		Where(`component_id IN (SELECT c.id FROM "component" AS "c"
			WHERE `+FoldedOn+` = (SELECT c2."fold_key" FROM "component" AS "c2"
				WHERE c2."name_folded" = ? LIMIT 1))`, graph.Folded(component)).
		Exists(ctx)
	if err != nil {
		return access.Public, fmt.Errorf("read how far this is disclosed: %w", err)
	}
	if private {
		return access.Private, nil
	}
	return access.Public, nil
}

// Release hands everything one person holds back to nobody.
//
// The case this exists for is somebody leaving. Their work is then invisible
// twice over — not in the shared list because it is assigned, and not in
// anybody's own list because they are not here — so it is in no view at all
// rather than visibly orphaned.
//
// Nothing tells us somebody has left. Membership is read at sign-in, and
// somebody who has gone never signs in again, so this is an action an
// administrator takes rather than something the software discovers.
func (s *Store) Release(ctx context.Context, subject access.Subject, party int64) (int64, error) {
	return s.handOver(ctx, subject, party, nil)
}

// HandOver moves everything one person holds to somebody else.
//
// Kept apart from Release because they answer different questions. Handing
// over says who is dealing with it now; releasing says nobody is, and puts it
// back where it can be picked up — which is the honest answer when whoever
// takes it on has not been decided.
func (s *Store) HandOver(ctx context.Context, subject access.Subject, from, to int64) (int64, error) {
	if from == to {
		return 0, ErrSamePerson
	}
	return s.handOver(ctx, subject, from, &to)
}

// ReleaseIn hands back what one person holds in one product.
//
// The narrow form of Release, for when somebody's last role on a product is
// withdrawn. What they hold elsewhere is untouched, because nothing about that
// product changed.
//
// Administrative like Release: this moves work somebody else was given.
func (s *Store) ReleaseIn(ctx context.Context, subject access.Subject, party, productID int64) (int64, error) {
	if !subject.Admin {
		return 0, access.Denied("move work assigned to somebody else")
	}
	var moved int64
	err := database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		result, err := tx.NewUpdate().Model((*Finding)(nil)).
			Set("assigned_to = ?", nil).Set("assigned_at = ?", nil).
			Where("assigned_to = ?", party).
			Where("closed_at IS NULL").
			Where(`target_id IN (SELECT tg.id FROM "target" AS "tg"
				JOIN "stream" AS "st" ON st.id = tg.stream_id
				WHERE st.product_id = ?)`, productID).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("hand back what they were dealing with: %w", err)
		}
		moved, err = database.Affected(result)
		if err != nil {
			return fmt.Errorf("hand back what they were dealing with: %w", err)
		}
		return nil
	})
	return moved, err
}

func (s *Store) handOver(ctx context.Context, subject access.Subject, from int64, to *int64) (int64, error) {
	if !subject.Admin {
		// Moving work somebody else was given is an administrative act. A
		// person hands back their own by assigning it to nobody.
		return 0, access.Denied("move work assigned to somebody else")
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	var moved int64
	err := database.InTransaction(ctx, s.db, func(ctx context.Context, tx bun.Tx) error {
		update := tx.NewUpdate().Model((*Finding)(nil)).
			Where("assigned_to = ?", from).
			Where("closed_at IS NULL")
		if to == nil {
			update = update.Set("assigned_to = ?", nil).Set("assigned_at = ?", nil)
		} else {
			update = update.Set("assigned_to = ?", *to).Set("assigned_at = ?", now)
		}
		result, err := update.Exec(ctx)
		if err != nil {
			return fmt.Errorf("move what they were dealing with: %w", err)
		}
		moved, err = database.Affected(result)
		if err != nil {
			return fmt.Errorf("move what they were dealing with: %w", err)
		}
		return nil
	})
	return moved, err
}

// Holding is how much work one party has, and how much of it is late.
type Holding struct {
	// PartyID is who holds it — a person, or a team the work is queued with.
	PartyID int64 `bun:"person_id"`
	// Open is how many pieces of work they hold — an issue in a component
	// in a product, which is the unit everything else here counts in.
	Open int `bun:"open"`
	// Places is how many findings those cover. The fan-out, kept alongside
	// rather than instead: one kernel flaw at forty-eight places is one thing
	// to answer and forty-eight rows to write, and both are worth saying.
	Places int `bun:"places"`
	// Overdue is how much of it is past its deadline. The number that says
	// whether somebody is holding work or sitting on it — a large open count
	// on somebody who is keeping up is not the same signal at all.
	Overdue int `bun:"overdue"`
}

// HeldBy reports what each person is dealing with, for the people this subject
// may see findings about.
//
// The number that matters is not how many findings exist but how many are
// stuck behind somebody: an idle account holding nothing is harmless, and work
// waiting on a person who is not here is the thing worth surfacing.
//
// **Counted in pieces of work, not in rows** — an issue in a component in a
// product, the same unit Unassigned and AssignedTo list in. Counting
// rows made this screen disagree with every screen it links to: measured
// against a real image, one kernel flaw assigned to one person read as 48 held
// against her here and as the single item it is in her own list. The larger
// number is not even a worse version of the smaller one, because it moves with
// how far a component fans out rather than with how much anybody has to do.
func (s *Store) HeldBy(ctx context.Context, subject access.Subject,
	productID int64) ([]Holding, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, access.Denied("read who is holding work")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, nil
	}

	mine := func() *bun.SelectQuery {
		query := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			Where("f.closed_at IS NULL").
			Where("f.assigned_to IS NOT NULL")
		// One product where the caller named one, for a screen that is about
		// one. Zero is every product, which is what the people screen asks
		// for.
		if productID != 0 {
			query = query.Where("st.product_id = ?", productID)
		}
		if !all {
			query = query.Where("st.product_id IN (?)", bun.List(products))
		}
		// The same narrowing every other query here carries. A count is as
		// much a disclosure as a row: "somebody holds six" tells a reader
		// there are six.
		return onlyVisible(query, subject, products, all)
	}

	// One row per person per piece of work, counted by grouping and
	// counting the groups. The derived table is named and quoted, because
	// GROUPS is a reserved word in MySQL 8 and the obvious alias is a
	// syntax error on one engine and fine on the other three.
	pieces := mine().
		ColumnExpr(`f.assigned_to AS "person_id"`).
		GroupExpr("f.assigned_to, f.vulnerability_id, f.component_id, st.product_id")

	// Bounded like every other list. It is a name-yielding projection —
	// one row per person holding open work the caller can see — and it was
	// the only one with no ceiling at all: no limit parameter, no default,
	// and a response that grows with the deployment. Ordered by who is
	// holding most, so the bound cuts the tail rather than an arbitrary
	// slice.
	var held []Holding
	if err := s.db.NewSelect().
		TableExpr(`(?) AS "work"`, pieces).
		ColumnExpr(`"work".person_id AS "person_id"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		ColumnExpr(`0 AS "places"`).
		ColumnExpr(`0 AS "overdue"`).
		GroupExpr(`"work".person_id`).
		OrderExpr("open DESC, person_id").
		Limit(database.InBulk.Most).
		Scan(ctx, &held); err != nil {
		return nil, fmt.Errorf("read who is holding what: %w", err)
	}

	// The fan-out, as its own pass rather than summed out of the grouping.
	// Summing a count across a derived table comes back as a decimal on two of
	// the four engines, and a cast to make it an integer is exactly the kind
	// of engine-specific spelling that has already been wrong here once.
	var spread []struct {
		PersonID int64 `bun:"person_id"`
		Places   int   `bun:"places"`
	}
	if err := mine().
		ColumnExpr(`f.assigned_to AS "person_id"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		GroupExpr("f.assigned_to").
		Scan(ctx, &spread); err != nil {
		return nil, fmt.Errorf("read how far what they hold reaches: %w", err)
	}
	places := map[int64]int{}
	for _, row := range spread {
		places[row.PersonID] = row.Places
	}
	for i := range held {
		held[i].Places = places[held[i].PartyID]
	}

	// How much of it is late. One pass, against the deadline stored on the
	// finding — it used to be a pass per urgency band, each with its own
	// cutoff, because the deadline was derived. Overdue has to mean the
	// same thing here as on the screen that lists what is running out, and
	// the surest way to keep two answers equal is for there to be one of
	// them: the deadline is the stored one, and what takes a finding off
	// the clock is the one condition both read — a decision that applies,
	// and nothing the build argued away. Counting every late finding
	// regardless made a dismissed finding overdue against whoever held it
	// while the list of what is running out, rightly, left it off.
	var counted []struct {
		PersonID int64 `bun:"person_id"`
		Overdue  int   `bun:"overdue"`
	}
	//
	// Counted in the same units as the rest of this: a piece of work is late
	// when any of its places is. The alternative reads worse in both
	// directions — a group with one late place among forty is late, and
	// calling it a fortieth of one is a number nobody acts on.
	standing, args := OffTheClock("st.product_id", s.now())
	late := mine().
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`f.assigned_to AS "person_id"`).
		Where("f.due_at IS NOT NULL").
		Where("f.due_at < ?", s.now().UTC()).
		Where("f.suppressed_by IS NULL").
		Where("NOT "+standing, args...).
		GroupExpr("f.assigned_to, f.vulnerability_id, f.component_id, st.product_id")
	err := s.db.NewSelect().
		TableExpr(`(?) AS "work"`, late).
		ColumnExpr(`"work".person_id AS "person_id"`).
		ColumnExpr(`COUNT(*) AS "overdue"`).
		GroupExpr(`"work".person_id`).
		Scan(ctx, &counted)
	if err != nil {
		return nil, fmt.Errorf("read how much of it is late: %w", err)
	}
	overdue := map[int64]int{}
	for _, row := range counted {
		overdue[row.PersonID] += row.Overdue
	}
	for i := range held {
		held[i].Overdue = overdue[held[i].PartyID]
	}
	return held, nil
}

// Owned is one finding nobody is dealing with, named rather than numbered.
type Owned struct {
	VulnerabilityID int64 `bun:"vulnerability_id"`
	ComponentID     int64 `bun:"component_id"`
	// ProductID is what a caller keys on where a name will not do: a product
	// is spelled one way in a path and another on a screen, and an identifier
	// is the same everywhere and cannot be renamed out from under a key.
	ProductID     int64  `bun:"product_id"`
	Vulnerability string `bun:"vulnerability"`
	Component     string `bun:"component"`
	Version       string `bun:"version"`
	Severity      string `bun:"severity"`
	Exploited     bool   `bun:"exploited"`
	Product       string `bun:"product"`
	// Stream and Variant name **a** build holding this, not the only one. A
	// screen needs somewhere to link to and an action needs a finding to name,
	// and where several builds hold the same code any of them will do. What
	// says there are several is Builds, so a screen can show that instead of
	// naming one of them as though it were the answer.
	Stream  string `bun:"stream"`
	Variant string `bun:"variant"`
	Urgency int64  `bun:"urgency"`
	// Undisclosed says at least one of the findings behind this row is one
	// nobody has announced. Any is enough: what may be said about a group
	// outside this deployment is decided by the most careful row in it .
	Undisclosed bool `bun:"undisclosed"`
	// OpenedAt is when the newest of them opened, which is what "since the
	// last digest" is measured against.
	OpenedAt time.Time `bun:"opened_at"`
	// Places is how many findings this covers, across every build it is in.
	// It is what a judgment here would be recorded against.
	Places int `bun:"places"`
	// Builds is how many builds hold it. One is the ordinary answer and reads
	// as it always did; more than one is the whole point of collapsing them.
	Builds int `bun:"builds"`
}

// Unassigned reports the work nobody is dealing with, across every product the
// subject may see, most urgent first.
//
// Across products deliberately. Work falling between people is not a
// per-product problem — it is exactly the thing that hides when every screen
// is scoped to one product and nobody looks at the others.
//
// **One item per issue in a component in a product, not one per build**
// . Variants are mostly the same thing built twice: a decision is keyed
// on the product, the place and the upstream versions and carries no variant,
// so answering this on one build answers it on every build of that product
// holding the same code. Listed per build, a second variant doubled this
// screen while doubling none of the work — which is how a queue stops being
// read.
//
// **Genuine differences still break out, and they break out by themselves.** A
// component row is one name at one version, shared by every build that ships
// it, so two variants at the same version group together and two at different
// versions do not. Nothing here has to decide which case it is looking at.
//
// The product stays in the key. A decision is a claim about one product's code
// , so two products shipping the identical component at the identical version
// are two judgments, and merging them would offer one answer for work that is
// answered separately.
func (s *Store) Unassigned(ctx context.Context, subject access.Subject, scope Scope,
	limit, offset int) ([]Owned, int, error) {
	return s.work(ctx, subject, scope, nil, limit, offset)
}

// AssignedTo reports what one party is dealing with — a person, or a team the
// work is queued with — in the same units as what nobody is.
//
// The same shape deliberately. "What is waiting for me" and "what is waiting
// for nobody" are the same question asked of a different holder, and answering
// them in two shapes is how a screen ends up saying somebody holds ninety
// things because it counted places where the other counted judgments.
func (s *Store) AssignedTo(ctx context.Context, subject access.Subject, parties []int64,
	scope Scope, limit, offset int) ([]Owned, int, error) {

	return s.work(ctx, subject, scope, parties, limit, offset)
}

// UnassignedSince is what nobody owns that arrived after a moment.
//
// The digest's half of Unassigned: what a person is told about daily is what
// has appeared since they were last told, rather than everything open, which
// after a month is a list nobody reads.
func (s *Store) UnassignedSince(ctx context.Context, subject access.Subject, scope Scope,
	since time.Time, limit int) ([]Owned, int, error) {

	return s.workSince(ctx, subject, scope, nil, &since, limit, 0)
}

// work is what some set of parties holds, or what nobody does.
//
// A set rather than one, because "assigned to me" means mine or my team's
// everywhere the phrase appears, and a screen that asked twice and merged
// would page and count two half-lists.
func (s *Store) work(ctx context.Context, subject access.Subject, scope Scope,
	holders []int64, limit, offset int) ([]Owned, int, error) {

	return s.workSince(ctx, subject, scope, holders, nil, limit, offset)
}

// workSince is the same, bounded to what opened after a moment.
//
// Only the digest passes one, and it passes the moment the last digest went:
// what it carries is what has arrived since, rather than everything that is
// open, which after a month is a list nobody reads.
func (s *Store) workSince(ctx context.Context, subject access.Subject, scope Scope,
	holders []int64, since *time.Time, limit, offset int) ([]Owned, int, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are different
	// statements, and this is the second.
	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read what is assigned")
	}
	products, all := subject.Products()
	mine := subject.Mine()
	// A capability held without a read role reaches no product, and what
	// gives it content is what it has been assigned: an assignment is
	// itself a grant of visibility of what was assigned. So this answers
	// for somebody who reads nothing, where they hold something.
	if subject.Kind != access.Person || (!all && len(products) == 0 && len(mine) == 0) {
		return nil, 0, nil
	}
	limit = database.AList.Of(limit)

	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			Where("f.closed_at IS NULL")
		if since != nil {
			q = q.Where("f.opened_at > ?", *since)
		}
		if len(holders) == 0 {
			q = q.Where("f.assigned_to IS NULL")
		} else {
			q = q.Where("f.assigned_to IN (?)", bun.List(holders))
		}
		if !all {
			// A product they read, or a row that is theirs. The visibility
			// clause below still applies to both, so an assignment carries a
			// row at the visibility they may read it at and no further.
			q = q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
				if len(products) > 0 {
					q = q.WhereOr("st.product_id IN (?)", bun.List(products))
				}
				if len(mine) > 0 {
					q = q.WhereOr("f.assigned_to IN (?)", bun.List(mine))
				}
				return q
			})
		}
		return scope.Narrow(onlyVisible(q, subject, products, all))
	}

	// Counted by grouping and counting the groups, not by a COUNT DISTINCT
	// expression. Two reasons, and both were live at once.
	//
	// With no GROUP BY, bun's Count() emits its own count(*) and never
	// appends the columns — so the expression was dead text and the total
	// was a count of finding *rows* while the list is grouped. On a real
	// image the fan-out is the whole point of this model, so the total was
	// not slightly wrong.
	//
	// And the expression concatenated with ||, which on two of the four
	// engines is logical OR: the operands coerce to numbers, the whole thing
	// collapses to 1, and the count comes back as 1 for any non-empty result.
	// Measured: 3 on SQLite and PostgreSQL, 1 on MySQL and MariaDB.
	//
	// The derived table is named "grouped" and quoted. GROUPS is a
	// reserved word in MySQL 8 — it names a window frame type — so the
	// obvious alias is a syntax error on one engine and fine on the other
	// three. The page in two statements: which groups, then their names.
	// The first groups and orders over finding and the two joins the
	// scoping needs; the names of the issue, the component and the build
	// come from a second statement over the page rather than from four
	// more joins under the aggregate, which is what the first version did
	// — a text column reduced with MIN once per row of the grouping to
	// read fifty names.
	var heads []struct {
		VulnerabilityID int64     `bun:"vulnerability_id"`
		ComponentID     int64     `bun:"component_id"`
		ProductID       int64     `bun:"product_id"`
		TargetID        int64     `bun:"target_id"`
		Builds          int       `bun:"builds"`
		Urgency         int64     `bun:"urgency"`
		Places          int       `bun:"places"`
		Total           int       `bun:"total"`
		Undisclosed     bool      `bun:"undisclosed"`
		OpenedAt        time.Time `bun:"opened_at"`
	}
	err := narrow(s.db.NewSelect()).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`st.product_id AS "product_id"`).
		// One of the builds, and how many there are. The one is what a link
		// and an action need somewhere to point; the count is what stops a
		// screen presenting it as the only one. MIN rather than any other
		// choice because it is stable: a row that named a different build
		// between two reads would move under somebody.
		ColumnExpr(`MIN(f.target_id) AS "target_id"`).
		ColumnExpr(`COUNT(DISTINCT f.target_id) AS "builds"`).
		ColumnExpr(`MAX(f.urgency) AS "urgency"`).
		// The oldest place decides, as it does everywhere else here: a group
		// open for a month with one place added yesterday has been somebody's
		// problem for a month, and a maximum made it read as a day old — so
		// the unassigned queue and the digest built on it sorted a six-week
		// backlog item as new work.
		ColumnExpr(`MIN(f.opened_at) AS "opened_at"`).
		// Any undisclosed row makes the group undisclosed. Written as a sum
		// rather than a boolean aggregate: the four engines do not agree on
		// one, and counting is the same question asked portably.
		ColumnExpr(`SUM(CASE WHEN f.visibility = ? THEN 1 ELSE 0 END) > 0 AS "undisclosed"`,
			access.Private).
		ColumnExpr(`COUNT(*) AS "places"`).
		// The total rides on the page, as the findings list's does: the
		// groups the narrowing admits, counted after the grouping and before
		// the limit, in the statement that groups them.
		ColumnExpr(`COUNT(*) OVER () AS "total"`).
		GroupExpr("f.vulnerability_id, f.component_id, st.product_id").
		OrderExpr("urgency DESC, f.vulnerability_id, f.component_id, st.product_id").
		Limit(limit).Offset(offset).
		Scan(ctx, &heads)
	if err != nil {
		return nil, 0, fmt.Errorf("read what nobody is dealing with: %w", err)
	}
	total := 0
	if len(heads) > 0 {
		total = heads[0].Total
	} else {
		if total, err = s.db.NewSelect().
			TableExpr(`(?) AS "grouped"`, narrow(s.db.NewSelect()).
				ColumnExpr("f.vulnerability_id").
				GroupExpr("f.vulnerability_id, f.component_id, st.product_id")).
			Count(ctx); err != nil {
			return nil, 0, fmt.Errorf("count what nobody is dealing with: %w", err)
		}
	}

	issues := make([]int64, 0, len(heads))
	components := make([]int64, 0, len(heads))
	targets := make([]int64, 0, len(heads))
	for _, head := range heads {
		issues = append(issues, head.VulnerabilityID)
		components = append(components, head.ComponentID)
		targets = append(targets, head.TargetID)
	}
	named, err := issuesNamed(ctx, s.db, issues)
	if err != nil {
		return nil, 0, err
	}
	shipped, err := componentsNamed(ctx, s.db, components)
	if err != nil {
		return nil, 0, err
	}
	builds, err := targetsNamed(ctx, s.db, targets)
	if err != nil {
		return nil, 0, err
	}

	rows := make([]Owned, 0, len(heads))
	for _, head := range heads {
		row := Owned{
			VulnerabilityID: head.VulnerabilityID, ComponentID: head.ComponentID,
			ProductID: head.ProductID,
			Urgency:   head.Urgency, Places: head.Places, Builds: head.Builds,
			Undisclosed: head.Undisclosed, OpenedAt: head.OpenedAt,
			Exploited: Rank(head.Urgency).Exploited(),
		}
		if issue, held := named[head.VulnerabilityID]; held {
			row.Vulnerability, row.Severity = issue.Identifier, issue.Severity
		}
		if component, held := shipped[head.ComponentID]; held {
			row.Component, row.Version = component.Name, component.Version
		}
		if build, held := builds[head.TargetID]; held {
			row.Product, row.Stream, row.Variant = build.Product, build.Stream, build.Variant
		}
		rows = append(rows, row)
	}
	return rows, total, nil
}

// buildName is what a build is called on a screen: its product, stream and
// variant, as people know them.
type buildName struct {
	TargetID int64  `bun:"target_id"`
	Product  string `bun:"product"`
	Stream   string `bun:"stream"`
	Variant  string `bun:"variant"`
}

// targetsNamed reads the names of the builds these targets are, by target.
func targetsNamed(ctx context.Context, db *bun.DB, ids []int64) (map[int64]buildName, error) {
	held := map[int64]buildName{}
	if len(ids) == 0 {
		return held, nil
	}
	var builds []buildName
	err := db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		Join(`JOIN "product" AS "p" ON p.id = st.product_id`).
		ColumnExpr(`tg.id AS "target_id"`).
		ColumnExpr(`p.display_name AS "product"`).
		ColumnExpr(`st.display_name AS "stream"`).
		ColumnExpr(`va.display_name AS "variant"`).
		Where("tg.id IN (?)", bun.List(ids)).
		Scan(ctx, &builds)
	if err != nil {
		return nil, fmt.Errorf("name the builds on the page: %w", err)
	}
	for _, build := range builds {
		held[build.TargetID] = build
	}
	return held, nil
}

// onlyReadable narrows a query to what this subject may read, per product.
//
// Holding private read on one product does not make undisclosed findings on
// another visible, so the clause is per product rather than a single flag.
//
// **An administrator is not narrowed at all**, and the first version of this
// got that exactly backwards: Products() reports "everything" as an empty list
// with a flag, the empty list rendered as IN (NULL) — which is never true —
// and the clause collapsed to public-only for the one subject who is supposed
// to see everything. Their dashboard, deadline list and trend all
// under-reported, with nothing saying so.
// onlyReadable narrows a query to what one person may read: the products they
// hold anything on, and within those, what has been disclosed to them.
//
// **Both halves, together, because forgetting the first one is silent.** The
// visibility half alone admits every disclosed finding in the deployment,
// including in products the asker holds nothing on — which reads as working,
// because the numbers are plausible and nothing refuses.
//
// **The product half is not always this one, which is why the visibility half
// is callable on its own.** A query that has already pinned a single product —
// a build's readiness, one product's releases — has narrowed further than this
// would, and applying a set membership over it would be a second clause saying
// less. Those call inOneProduct, which is the same pairing stated for the case
// where the query brought its own first half. Nothing calls the visibility
// half bare: that is the thing to check when reading one of these, and it is
// the reason the two names exist rather than one function and a comment.
func onlyReadable(q *bun.SelectQuery, subject access.Subject, products []int64, all bool) *bun.SelectQuery {
	if !all {
		q = q.Where("st.product_id IN (?)", bun.List(products))
	}
	return onlyVisible(q, subject, products, all)
}

// inOneProduct narrows to what may be read inside a product the query has
// already pinned itself to.
//
// The pairing onlyReadable makes, for a query whose first half is an equality
// rather than a set: it says out loud that the product half has been done,
// which a bare call to the visibility half does not.
func inOneProduct(q *bun.SelectQuery, subject access.Subject, productID int64,
	all bool) *bun.SelectQuery {

	return onlyVisible(q, subject, []int64{productID}, all)
}

func onlyVisible(q *bun.SelectQuery, subject access.Subject, products []int64, all bool) *bun.SelectQuery {
	if all {
		return q
	}
	held := make([]int64, 0, len(products))
	for _, id := range products {
		if subject.Reads(access.Private, id) {
			held = append(held, id)
		}
	}
	if len(held) == 0 {
		// Nothing undisclosed anywhere, which is a real answer rather than an
		// empty condition to be filled in.
		return q.Where("f.visibility = ?", access.Public)
	}
	return q.Where("(f.visibility = ? OR st.product_id IN (?))",
		access.Public, bun.List(held))
}
