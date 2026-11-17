// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// Holding is how much work one party has, and how much of it is late.
type Holding struct {
	// PartyID is who holds it — a person, or a team the work is queued with.
	PartyID int64 `bun:"person_id"`
	// Open is how many pieces of work they hold — an issue in a component
	// in a product, which is the unit everything else here counts in.
	Open int `bun:"open"`
	// Occurrences is how many findings those cover. The fan-out, kept alongside
	// rather than instead: one kernel flaw at forty-eight occurrences is one
	// thing to answer and forty-eight rows to write, and both are worth saying.
	Occurrences int `bun:"places"`
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
// Counted in pieces of work, not in rows — an issue in a component in a
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

	kinds, kindArgs := kind.Assignment.Where(`"f"."kind"`)
	mine := func() *bun.SelectQuery {
		query := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "build" AS "b" ON "b"."id" = "f"."build_id"`).
			Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
			Where(kinds, kindArgs...).
			Where(`"f"."closed_at" IS NULL`).
			Where(notRecordedAsFlaw).
			Where(`"f"."assigned_to" IS NOT NULL`)
		// One product where the caller named one, for a screen that is about
		// one. Zero is every product, which is what the people tab of the
		// assignments screen asks for.
		if productID != 0 {
			query = query.Where(`"st"."product_id" = ?`, productID)
		}
		if !all {
			query = query.Where(`"st"."product_id" IN (?)`, bun.List(products))
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
		ColumnExpr(`"f"."assigned_to" AS "person_id"`).
		GroupExpr(`"f"."assigned_to", ` + pieceOfWork)

	// Bounded like every other list. It is a name-yielding projection —
	// one row per person holding open work the caller can see — and it was
	// the only one with no ceiling at all: no limit parameter, no default,
	// and a response that grows with the deployment. Ordered by who is
	// holding most, so the bound cuts the tail rather than an arbitrary
	// slice.
	var held []Holding
	if err := s.db.NewSelect().
		TableExpr(`(?) AS "work"`, pieces).
		ColumnExpr(`"work"."person_id" AS "person_id"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		ColumnExpr(`0 AS "places"`).
		ColumnExpr(`0 AS "overdue"`).
		GroupExpr(`"work"."person_id"`).
		OrderExpr(`"open" DESC, "person_id"`).
		Limit(int64(database.InBulk.Most)).
		Scan(ctx, &held); err != nil {
		return nil, fmt.Errorf("read who is holding what: %w", err)
	}

	// The fan-out, as its own pass rather than summed out of the grouping.
	// Summing a count across a derived table comes back as a decimal on two of
	// the four engines, and a cast to make it an integer is exactly the kind
	// of engine-specific spelling that has already been wrong here once.
	var spread []struct {
		PersonID    int64 `bun:"person_id"`
		Occurrences int   `bun:"places"`
	}
	if err := mine().
		ColumnExpr(`"f"."assigned_to" AS "person_id"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		GroupExpr(`"f"."assigned_to"`).
		Scan(ctx, &spread); err != nil {
		return nil, fmt.Errorf("read how far what they hold reaches: %w", err)
	}
	occurrences := map[int64]int{}
	for _, row := range spread {
		occurrences[row.PersonID] = row.Occurrences
	}
	for i := range held {
		held[i].Occurrences = occurrences[held[i].PartyID]
	}

	// counted is how much of it is late. One pass, against the deadline stored
	// on the finding. Derived instead it is a pass per urgency band, each with
	// its own cutoff. Overdue has to mean the same thing here as on the screen
	// that lists what is running out, and the surest way to keep two answers
	// equal is for there to be one of them: the deadline is the stored one,
	// and what takes a finding off the clock is the one condition both read —
	// a decision that applies, and nothing the build argued away. Counting
	// every late finding regardless made a dismissed finding overdue against
	// whoever held it while the list of what is running out, rightly, left it
	// off.
	var counted []struct {
		PersonID int64 `bun:"person_id"`
		Overdue  int   `bun:"overdue"`
	}
	//
	// Counted in the same units as the rest of this: a piece of work is late
	// when any of its occurrences is. The alternative reads worse in both
	// directions — a group with one late occurrence among forty is late, and
	// calling it a fortieth of one is a number nobody acts on.
	standing, args := OffTheClock(`"st"."product_id"`, s.now())
	late := mine().
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		ColumnExpr(`"f"."assigned_to" AS "person_id"`).
		Where(`"f"."due_at" IS NOT NULL`).
		Where(`"f"."due_at" < ?`, s.now().UTC()).
		Where(NotArguedAway).
		Where("NOT "+standing, args...).
		GroupExpr(`"f"."assigned_to", ` + pieceOfWork)
	err := s.db.NewSelect().
		TableExpr(`(?) AS "work"`, late).
		ColumnExpr(`"work"."person_id" AS "person_id"`).
		ColumnExpr(`COUNT(*) AS "overdue"`).
		GroupExpr(`"work"."person_id"`).
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
	// Purl is the component's package identifier, which what tells it from
	// another component of the same name and version is read out of.
	Purl      string `bun:"-"`
	Severity  string `bun:"severity"`
	Exploited bool   `bun:"exploited"`
	Incident  bool   `bun:"incident"`
	// Product is the name that addresses it, and ProductName the one shown.
	Product     string `bun:"product"`
	ProductName string `bun:"-"`
	// Branch or tag and Variant name a build holding this, not the only one. A
	// screen needs somewhere to link to and an action needs a finding to name,
	// and where several builds hold the same code any of them will do. What
	// says there are several is Builds, so a screen can show that instead of
	// naming one of them as though it were the answer.
	BranchOrTag     string `bun:"branch_or_tag"`
	BranchOrTagName string `bun:"-"`
	Variant         string `bun:"variant"`
	VariantName     string `bun:"-"`
	Urgency         int64  `bun:"urgency"`
	// Undisclosed says at least one of the findings behind this row is one
	// nobody has announced. Any is enough: what may be said about a group
	// outside this deployment is decided by the most careful row in it .
	Undisclosed bool `bun:"undisclosed"`
	// OpenedAt is when the newest of them opened, which is what "since the
	// last digest" is measured against.
	OpenedAt time.Time `bun:"opened_at"`
	// Occurrences is how many findings this covers, across every build it is in.
	// It is what a decision here would be recorded against.
	Occurrences int `bun:"places"`
	// Builds is how many builds hold it. One is the ordinary answer and reads
	// as it always did; more than one is the whole point of collapsing them.
	Builds int `bun:"builds"`
	// Occurrence is the code finding's occurrence where this is a code finding, and empty for any
	// other finding. A code finding is one piece of work at one occurrence, whatever
	// component its builds name.
	Occurrence string `bun:"place"`
}

// Unassigned reports the work nobody is dealing with, across every product the
// subject may see, most urgent first.
//
// Across products deliberately. Work falling between people is not a
// per-product problem — it is exactly the thing that hides when every screen
// is scoped to one product and nobody looks at the others.
//
// One item per issue in a component in a product, not one per build . Variants
// are mostly the same thing built twice: a decision occurrence is keyed on the
// product, the occurrence and the upstream versions and carries no variant, so
// answering this on one build answers it on every build of that product holding
// the same code. Listed per build, a second variant doubled this screen while
// doubling none of the work — which is how a queue stops being read.
//
// Genuine differences still break out, and they break out by themselves. A
// component row is one name at one version, shared by every build that ships
// it, so two variants at the same version group together and two at different
// versions do not. Nothing here has to decide which case it is looking at.
//
// The product stays in the key. A decision is about one product's code
// , so two products shipping the identical component at the identical version
// are two decisions, and merging them would offer one answer for work that is
// answered separately.
//
// A family keeps one of the two, which a screen counts apart; the empty family
// is both.
func (s *Store) Unassigned(ctx context.Context, subject access.Subject, scope Scope, family kind.Family,
	limit, offset int) ([]Owned, int, error) {
	return s.workSince(ctx, kind.Assignment, family, subject, scope, nil, nil, limit, offset)
}

// AssignedTo reports what one party is dealing with — a person, or a team the
// work is queued with — in the same units as what nobody is, of the kinds the
// consumer asking names: the lists of held work name code findings, and the digest
// does not.
//
// The same shape deliberately. "What is waiting for me" and "what is waiting
// for nobody" are the same question asked of a different holder, and answering
// them in two shapes is how a screen ends up saying somebody holds ninety
// things because it counted occurrences where the other counted decisions.
//
// A family keeps one of the two families, as Unassigned does.
func (s *Store) AssignedTo(ctx context.Context, c kind.Consumer, family kind.Family, subject access.Subject,
	parties []int64, scope Scope, limit, offset int) ([]Owned, int, error) {

	return s.workSince(ctx, c, family, subject, scope, parties, nil, limit, offset)
}

// UnassignedSince is what nobody owns that arrived after a moment.
//
// The digest's half of Unassigned: what a person is told about daily is what
// has appeared since they were last told, rather than everything open, which
// after a month is a list nobody reads.
func (s *Store) UnassignedSince(ctx context.Context, subject access.Subject, scope Scope,
	since time.Time, limit int) ([]Owned, int, error) {

	return s.workSince(ctx, kind.Notifications, "", subject, scope, nil, &since, limit, 0)
}

// workSince is what some set of parties holds, or what nobody does, of the
// consumer's kinds in one family or both, bounded to what opened after a
// moment where one is given.
//
// A set of parties rather than one, because "assigned to me" means mine or my
// team's everywhere the phrase appears, and a screen that asked twice and
// merged would page and count two half-lists.
//
// Only the digest passes a moment, and it passes the moment the last digest
// went: what it carries is what has arrived since, rather than everything
// that is open, which after a month is a list nobody reads.
func (s *Store) workSince(ctx context.Context, c kind.Consumer, family kind.Family, subject access.Subject,
	scope Scope, holders []int64, since *time.Time, limit, offset int) ([]Owned, int, error) {

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
	if !all && len(products) == 0 && len(mine) == 0 {
		return nil, 0, nil
	}
	limit = database.AList.Of(limit)

	kinds, kindArgs := c.WhereIn(`"f"."kind"`, family)
	// Nobody holds a code finding seen only in releases past their end of life, and
	// nobody may take one, so the work nobody holds leaves out each sighting
	// of a code finding in such a release, as the code finding queue does.
	var ended []int64
	if len(holders) == 0 {
		var err error
		if ended, err = catalog.NewStore(s.db).BranchesAndTagsPastEndOfLife(ctx, s.now().UTC()); err != nil {
			return nil, 0, err
		}
	}
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.TableExpr(`"finding" AS "f"`).
			Join(`JOIN "build" AS "b" ON "b"."id" = "f"."build_id"`).
			Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
			Where(kinds, kindArgs...).
			Where(`"f"."closed_at" IS NULL`)
		if since != nil {
			q = q.Where(`"f"."opened_at" > ?`, *since)
		}
		if len(holders) == 0 {
			q = q.Where(`"f"."assigned_to" IS NULL`)
			if len(ended) > 0 {
				q = q.Where(`("f"."kind" <> ? OR "b"."branch_or_tag_id" NOT IN (?))`, kind.Analysis, bun.List(ended))
			}
		} else {
			q = q.Where(`"f"."assigned_to" IN (?)`, bun.List(holders))
		}
		// A product they read at the row's visibility, or a disclosed row
		// that is theirs. The product half is inside both.
		return scope.Narrow(orCarried(q, subject, products, all))
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
	// more joins under the aggregate — which reduces a text column with MIN
	// once per row of the grouping to read fifty names.
	var heads []struct {
		VulnerabilityID int64     `bun:"vulnerability_id"`
		ComponentID     int64     `bun:"component_id"`
		ProductID       int64     `bun:"product_id"`
		BuildID         int64     `bun:"build_id"`
		Builds          int       `bun:"builds"`
		Urgency         int64     `bun:"urgency"`
		Exploited       int       `bun:"exploited"`
		Incident        int       `bun:"incident"`
		Occurrences     int       `bun:"places"`
		Occurrence      string    `bun:"place"`
		Total           int       `bun:"total"`
		Undisclosed     bool      `bun:"undisclosed"`
		OpenedAt        time.Time `bun:"opened_at"`
	}
	// Each build grouped on its own first, then the partial groups grouped
	// across builds: one grouping over every build's occurrences sorts them
	// all, and on 15 builds of one image that spilled 573 MB to disk
	// (perBuild). Every column folds exactly: a count is a sum of counts, a
	// least or most the least or most of the partial ones, and the builds a
	// piece of work is in are its partial groups, one per build.
	inScope, err := s.Builds(ctx, scope)
	if err != nil {
		return nil, 0, err
	}
	privateCount, privateArg := access.PrivateCountAs(access.FindingVisibility(), "private_places")
	// Each build in two branches. A dependency finding is its component's
	// piece of work and is never a flaw, since a flaw records a code finding's
	// occurrence, so its branch reads only what the group index holds and
	// reads no table. A code finding is its occurrence's piece of work, and
	// its branch reads the occurrence and asks after the flaw.
	part := func(build int64, code bool) *bun.SelectQuery {
		q := narrow(s.db.NewSelect()).
			Where(`"f"."build_id" = ?`, build).
			ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
			ColumnExpr(`"st"."product_id" AS "product_id"`)
		if code {
			q = q.Where(`"f"."kind" = ?`, kind.Analysis).
				Where(notRecordedAsFlaw).
				ColumnExpr(`0 AS "piece_component"`).
				ColumnExpr(`"f"."occurrence_identity" AS "place"`).
				GroupExpr(`"f"."vulnerability_id", "st"."product_id", "f"."occurrence_identity"`)
		} else {
			q = q.Where(`"f"."kind" <> ?`, kind.Analysis).
				ColumnExpr(`"f"."component_id" AS "piece_component"`).
				ColumnExpr(`'' AS "place"`).
				GroupExpr(`"f"."vulnerability_id", "st"."product_id", "f"."component_id"`)
		}
		return q.
			ColumnExpr(`MIN("f"."component_id") AS "component_least"`).
			ColumnExpr(`MIN("f"."build_id") AS "build_id"`).
			ColumnExpr(`MAX("f"."urgency") AS "urgency"`).
			ColumnExpr(exploitedAcross+` AS "exploited"`).
			ColumnExpr(incidentAcross+` AS "incident"`).
			ColumnExpr(`MIN("f"."opened_at") AS "opened_at"`).
			ColumnExpr(privateCount, privateArg).
			ColumnExpr(`COUNT(*) AS "places"`)
	}
	parts := perBuild(s.db, inScope,
		func(build int64) *bun.SelectQuery { return part(build, false) },
		func(build int64) *bun.SelectQuery { return part(build, true) })
	if parts == nil {
		return nil, 0, nil
	}
	pieces := func() *bun.SelectQuery {
		return s.db.NewSelect().
			TableExpr(`(?) AS "p"`, parts).
			GroupExpr(`"p"."vulnerability_id", "p"."product_id", "p"."piece_component", "p"."place"`)
	}
	err = pieces().
		ColumnExpr(`"p"."vulnerability_id" AS "vulnerability_id"`).
		// The lowest of a code finding's components, as one of its builds names it.
		// Every other piece of work is one component.
		ColumnExpr(`MIN("p"."component_least") AS "component_id"`).
		ColumnExpr(`"p"."place" AS "place"`).
		ColumnExpr(`"p"."product_id" AS "product_id"`).
		// One of the builds, and how many there are. The one is what a link
		// and an action need somewhere to point; the count is what stops a
		// screen presenting it as the only one. MIN rather than any other
		// choice because it is stable: a row that named a different build
		// between two reads would move under somebody.
		ColumnExpr(`MIN("p"."build_id") AS "build_id"`).
		ColumnExpr(`COUNT(*) AS "builds"`).
		ColumnExpr(`MAX("p"."urgency") AS "urgency"`).
		ColumnExpr(`MAX("p"."exploited") AS "exploited"`).
		ColumnExpr(`MAX("p"."incident") AS "incident"`).
		// The oldest occurrence decides, as it does everywhere else here: a
		// group open for a month with one occurrence added yesterday has been
		// somebody's problem for a month, and a maximum made it read as a day
		// old — so the unassigned queue and the digest built on it sorted a
		// six-week backlog item as new work.
		ColumnExpr(`MIN("p"."opened_at") AS "opened_at"`).
		// Any undisclosed row makes the group undisclosed. Counted rather
		// than a boolean aggregate: the four engines do not agree on one.
		ColumnExpr(`(SUM("p"."private_places") > 0) AS "undisclosed"`).
		ColumnExpr(`SUM("p"."places") AS "places"`).
		// The total rides on the page, as the findings list's does: the
		// groups the narrowing admits, counted after the grouping and before
		// the limit, in the statement that groups them.
		ColumnExpr(`COUNT(*) OVER () AS "total"`).
		OrderExpr(`"urgency" DESC, "p"."vulnerability_id", MIN("p"."component_least"), "p"."product_id", "p"."place"`).
		Limit(int64(limit)).Offset(int64(offset)).
		Scan(ctx, &heads)
	if err != nil {
		return nil, 0, fmt.Errorf("read what nobody is dealing with: %w", err)
	}
	total := 0
	if len(heads) > 0 {
		total = heads[0].Total
	} else {
		counted, err := s.db.NewSelect().
			TableExpr(`(?) AS "grouped"`, pieces().ColumnExpr(`"p"."vulnerability_id"`)).
			Count(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("count what nobody is dealing with: %w", err)
		}
		total = int(counted)
	}

	issues := make([]int64, 0, len(heads))
	components := make([]int64, 0, len(heads))
	buildIDs := make([]int64, 0, len(heads))
	for _, head := range heads {
		issues = append(issues, head.VulnerabilityID)
		components = append(components, head.ComponentID)
		buildIDs = append(buildIDs, head.BuildID)
	}
	named, err := issuesNamed(ctx, s.db, subject, issues)
	if err != nil {
		return nil, 0, err
	}
	// And what each product rates them, which is what the row shows. The
	// names come back with the published word only, by design — one issue is
	// read once for a page that can span products, and each of them may rate
	// it differently — so the rating is read alongside and put on the copy.
	// Without it the assignment lists and the nightly digest reported the
	// world's severity for a finding whose own product had said otherwise,
	// and the findings list beside them said the other thing.
	within := make([]int64, 0, len(heads))
	for _, head := range heads {
		within = append(within, head.ProductID)
	}
	rated, err := RatingsIn(ctx, s.db, within, issues)
	if err != nil {
		return nil, 0, err
	}
	shipped, err := componentsNamed(ctx, s.db, components, buildIDs)
	if err != nil {
		return nil, 0, err
	}
	builds, err := namedBuilds(ctx, s.db, buildIDs)
	if err != nil {
		return nil, 0, err
	}

	rows := make([]Owned, 0, len(heads))
	for _, head := range heads {
		row := Owned{
			VulnerabilityID: head.VulnerabilityID, ComponentID: head.ComponentID,
			ProductID: head.ProductID,
			Urgency:   head.Urgency, Occurrences: head.Occurrences, Builds: head.Builds,
			Undisclosed: head.Undisclosed, OpenedAt: head.OpenedAt, Occurrence: head.Occurrence,
			Exploited: head.Exploited == 1, Incident: head.Incident == 1,
		}
		if issue, held := named[head.VulnerabilityID]; held {
			issue = issue.RatedIn(rated[RatedKey{
				ProductID: head.ProductID, VulnerabilityID: head.VulnerabilityID}])
			row.Vulnerability, row.Severity = issue.Identifier, issue.InForce()
		}
		if component, held := shipped.at(head.ComponentID, head.BuildID); held {
			row.Component, row.Version, row.Purl = component.Name, component.Version, component.Purl
		}
		if build, held := builds[head.BuildID]; held {
			row.Product, row.BranchOrTag, row.Variant = build.Product, build.BranchOrTag, build.Variant
			row.ProductName = build.ProductName
			row.BranchOrTagName, row.VariantName = build.BranchOrTagName, build.VariantName
		}
		rows = append(rows, row)
	}
	return rows, total, nil
}

// buildName is what a build is called on a screen: its product, branch or tag and
// variant, as people know them.
type buildName struct {
	BuildID         int64  `bun:"build_id"`
	Product         string `bun:"product"`
	ProductName     string `bun:"product_name"`
	BranchOrTag     string `bun:"branch_or_tag"`
	BranchOrTagName string `bun:"branch_or_tag_name"`
	Variant         string `bun:"variant"`
	VariantName     string `bun:"variant_name"`
}

// namedBuilds reads the names of these builds, by build.
func namedBuilds(ctx context.Context, db bun.IDB, ids []int64) (map[int64]buildName, error) {
	held := map[int64]buildName{}
	if len(ids) == 0 {
		return held, nil
	}
	var builds []buildName
	err := db.NewSelect().
		TableExpr(`"build" AS "b"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "b"."branch_or_tag_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "b"."variant_id"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "st"."product_id"`).
		ColumnExpr(`"b"."id" AS "build_id"`).
		Apply(catalog.BuildNames("p", "st", "va")).
		Where(`"b"."id" IN (?)`, bun.List(ids)).
		Scan(ctx, &builds)
	if err != nil {
		return nil, fmt.Errorf("name the builds on the page: %w", err)
	}
	for _, build := range builds {
		held[build.BuildID] = build
	}
	return held, nil
}
