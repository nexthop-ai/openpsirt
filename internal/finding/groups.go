package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The page a person reads.
//
// One row per issue and component, however many places it sits at, with the
// numbers a reader is shown and the one word for how far it has been decided.
// The page and its decorations are two statements — the first reads the
// covering index and nothing else, the second asks only about the rows that
// came back — because a page that joins everything it wants to show cannot use
// that index.
//
// Its own test file is page_test.go.

// Group is one issue in one component, with the places it occupies.
//
// This is the unit somebody decides about. The places are what the decision is
// recorded against — one real image produced 335,021 findings and 305,487 of
// them were a single kernel across the modules built against it, so a list of
// places is six thousand screens of rows differing in a column nobody reads.
type Group struct {
	// Product and ProductName are filled only where the list spans
	// products . Inside one product every row would repeat it, and a
	// column every row agrees about is width the parts that differ need.
	Product     string
	ProductName string

	Vulnerability string
	Severity      string
	// Summary is the first line of what the issue says about itself, for a
	// list where fifty rows otherwise read "CVE-2026-74280 · linux-image"
	// fifty times. Somebody scanning for the one they care about is reading
	// the words, and without them telling two rows apart cost a click each.
	Summary   string
	Component string
	Version   string
	// Upstream is what a fork was made from, where it is one. A version nobody
	// recognizes needs it to be explainable.
	Upstream string
	// Source is the package this binary was built from, where the two differ.
	// The same issue at two binaries of one source is two rows here and one
	// piece of work everywhere else — it is decided once, upgraded once and
	// routed by one rule — and a reader with no way to see that is reading a
	// list a third of which is the same work said again.
	Source string
	// Ecosystem is the kind of package this is, as its identifier spells it.
	// Part of what tells one row from another: a name at a version is not
	// unique within a build, which can hold a source repository and the
	// package built from it under one name at one version.
	Ecosystem string
	FixState  FixState
	FixedIn   string
	// Fold is what the row is about: the source package at the version it was
	// built at, in the ecosystem and distribution it came from. It is what a
	// judgment, an assignment and an upgrade all name.
	Fold string
	// Packages is how many binaries of the fold sit here, and Consumers how
	// many things pull them in. These are the numbers a reader is shown,
	// counted in the units they act in: deciding on this row decides about
	// every package and every consumer under it, and a row that hid its size
	// would invite a judgment made about one being applied to sixty unseen.
	Packages  int
	Consumers int
	// Places is how many findings sit under it. What the bulk cap is measured
	// against and what the disposition register expands to, rather than a
	// number a reader is asked to reconcile with the two above.
	Places int
	// Answered counts the places the build has already argued about.
	Answered int
	// State is how far we have decided this group, in the same four words
	// the state filter takes and by the same definition: undecided when no
	// place has a decision of any kind, waiting when a claim stands proposed
	// and nobody has agreed, agreed when every place is answered by a
	// standing decision, lapsed when a decision here stopped applying and
	// nothing replaced it. Empty where none of the four holds — some places
	// approved and the rest never decided, with nothing waiting or lapsed.
	State string
	// SentBack says a live claim at one of the places is currently with its
	// author, which is the row the proposer is looking for in the list.
	SentBack bool
	// Undisclosed says nothing here has been announced, and DiscloseAt
	// when the embargo ends. Everything about disclosure existed in the
	// API and appeared nowhere a person could see it: an undisclosed
	// recorded flaw rendered identically to any other row.
	Undisclosed bool
	DiscloseAt  *time.Time
	// Tags are the words somebody put on this, as they were typed.
	Tags []string
	// OpenedAt is when the earliest of these places opened here, which is
	// the age a deadline relates to. Not the year in the identifier: an
	// issue assigned in 2019 that first appeared in this product last week
	// has been somebody's problem for a week.
	OpenedAt time.Time
	// DueAt is the earliest deadline across these places, and NoDeadline
	// says why there is none where there is none. Exactly two reasons,
	// both deliberate, and a blank cell would mean either.
	DueAt      *time.Time
	NoDeadline NoDeadline
	// Urgency is how far up the list this belongs, and Exploited says whether
	// it is there because somebody is using it. The flag is carried rather
	// than left to be inferred from the number: a position nobody can explain
	// is one people stop trusting and then work around.
	Urgency   int64
	Exploited bool
	// LikelihoodPPM is the published estimate that this will be exploited, in
	// parts per million. Carried because it ranks *above* severity: without it
	// on the row, a medium sitting above a high looks like the list is
	// unsorted, when it is sorted by something the list never showed.
	LikelihoodPPM int
	// ScoreCenti is what the ordering actually compares. The severity word
	// beside it comes from whichever scoring generation the source used — a
	// 2003 issue scored 10.0 reads "high" under CVSS v2 and "critical" under
	// v3 — so a row showing only the word looks mis-sorted when two tie.
	//
	// Scored says whether there is one at all, because the column is nullable
	// and zero is a real score. Published as a zero, an unscored finding sorted
	// with the genuinely 0.0-rated ones at the bottom of a spreadsheet and was
	// included by every filter asking for a score below anything.
	ScoreCenti int
	Scored     bool
	// Owner and Parent are the two ends of the way down to this component:
	// the part of the product it belongs to, and what directly pulls it in
	// . Those two are what differ between sibling rows — the top says
	// which part of the product this is, the bottom is what a decision is
	// about — and the steps between them rarely distinguish anything, so
	// Middle counts them rather than naming them.
	//
	// A group covers every place the component sits at, and those places
	// can come down different ways. Chains says how many distinct ways
	// there are, so a row can say "one of 4" rather than presenting one
	// route as though it were the only one.
	//
	// All four are empty where the selection spans more than one build . A
	// chain belongs to one build's graph, and a group that sits in three
	// builds is reached three ways, so filling these from whichever build
	// the row happened to name would present one route as the answer — the
	// thing the paragraph above says not to do, one level up.
	Owner  string
	Parent string
	Middle int
	Chains int
	// Builds is how many builds in the selection hold this group, and Stream
	// and Variant name **one** of them — not the only one. A screen needs
	// somewhere to link to and an action needs a build to name; what says
	// there are others is the count, so a screen can show that instead of
	// reading the named one as the whole answer. Both are empty where the
	// selection is a single build, since the row would only be repeating it.
	Builds  int
	Stream  string
	Variant string
	// Matched says how the scanner reached this. One answer for the whole
	// group: every place of it comes from the same line of a report. Empty
	// where the scanner said nothing.
	Matched Matched `bun:"matched"`
}

// stateWord says how far a group has been decided, from the same counts the
// state filter uses. The order is the filter's: a group every place of which
// is answered is agreed whatever else its history holds; one with a claim
// waiting is waiting; one where a decision lapsed and nothing stands is
// lapsed; one nobody ever decided about is undecided. Some places approved
// and the rest never decided, with nothing waiting or lapsed, is none of the
// four, and says so by saying nothing.
func stateWord(places, waiting, approved, lapsed int) string {
	switch {
	case places > 0 && approved == places:
		return "agreed"
	case waiting > 0:
		return "waiting"
	case lapsed > 0 && approved == 0:
		return "lapsed"
	case waiting == 0 && approved == 0 && lapsed == 0:
		// Nothing stands, rather than nothing was ever said — the same
		// predicate the filter's own "undecided" uses. Asked as "no claim
		// row exists", a place whose only claim was withdrawn fell through
		// every case and drew a blank word, while the filter put it in the
		// undecided bucket. The row and the filter now answer from one rule,
		// which is why no count of claims-of-any-kind is read here or taken
		// from the statement.
		return "undecided"
	}
	return ""
}

// worstBand is the highest severity among a set of counts, or empty where
// nothing was rated.
//
// Named rather than derived on the screen because two screens deriving it is
// two places for "worst" to come to mean different things — and because the
// order of these words is a fact about the domain, not a display choice.
func worstBand(counts map[string]int) string {
	for _, band := range []string{"critical", "high", "medium", "low"} {
		if counts[band] > 0 {
			return band
		}
	}
	return ""
}

// inScope authorizes a selection and resolves it to the builds it covers.
//
// The three things every list over findings needs before it can read one:
// which product it is narrowing inside, what the reader may see there, and
// which builds the selection holds. Done once because two lists resolving them
// slightly differently would answer slightly different questions side by side.
func (s *Store) inScope(ctx context.Context, subject access.Subject, scope Scope,
	filter *Filter) (int64, []access.Visibility, []int64, error) {

	if scope.ProductID == nil {
		// Every list here correlates a decision by product and a place
		// identity carries none, so a selection without one would reach
		// decisions made in every product in the deployment.
		return 0, nil, nil, fmt.Errorf("read findings: the selection names no product")
	}
	productID := *scope.ProductID
	if !subject.Sees(productID) {
		return 0, nil, nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return 0, nil, nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}
	targets, err := s.buildsWorking(ctx, scope, filter.Workable)
	if err != nil {
		return 0, nil, nil, err
	}
	// Set here rather than trusted from the caller, for the reason above.
	filter.ProductID = productID
	// And the line's, which is the same identifier for the same reason: the
	// word a line states and the rating it compares against are both this
	// product's decisions, and a caller free to state either would be choosing
	// whose rating its findings are judged by.
	filter.Floor.ProductID = productID
	// Who "mine" means, from the subject rather than from the request, and
	// their teams with them: the column holds a party.
	filter.HeldBy = subject.Mine()
	// The store's clock, so the deadline filters compare against the same
	// moment everything else here does — and so a frozen clock reaches them,
	// which is what left the overdue filter with no test.
	filter.now = s.now
	// How many builds the selection holds, which is what "differs between
	// builds" is measured against. The filter cannot see it.
	filter.Builds = len(targets)
	// A subtree is a walk over one build's edges, so it is answerable only
	// where the selection is one build. Asked across several it is refused
	// rather than answered from whichever build sorted first — which is what
	// leaving the identifier at zero would have done, silently and emptily.
	switch {
	case len(targets) == 1:
		filter.TargetID = targets[0]
	case filter.Beneath != nil:
		return 0, nil, nil, fmt.Errorf("read findings beneath a component: a subtree is a walk"+
			" over one build's edges, and %d builds are in scope", len(targets))
	}
	return productID, visible, targets, nil
}

// Groups returns what is open in a selection, as the things somebody decides
// about rather than as one row per place.
//
// The selection is not always one build. With the branch or the variant left
// at "all" the page answers for every build under the product: a row is one
// issue at one component still, and its places are counted across every build
// the group is in. What a row cannot carry there is the way down, because a
// chain belongs to one build's graph — so those columns are filled only where
// the selection is a single build, and across several the row names one of
// them and says how many hold it instead. Naming one as though it were the
// answer is the thing being avoided.
func (s *Store) Groups(ctx context.Context, subject access.Subject, scope Scope, limit, offset int,
	filter Filter) ([]Group, int, error) {
	productID, visible, targets, err := s.inScope(ctx, subject, scope, &filter)
	if err != nil {
		return nil, 0, err
	}
	if len(targets) == 0 {
		return nil, 0, nil
	}

	limit = database.AList.Of(limit)

	// The page in two statements: which groups, then what is known about
	// them.
	//
	// The first groups every open finding in the build by issue and component
	// and keeps the fifty most urgent. It reads four columns, all of them in
	// finding's covering index, so however large the build is this is one
	// walk of one index with nothing looked up. Everything else the row shows
	// — likelihood and score, how far it has been decided, how many ways
	// down there are, the fix — is read in a second statement over the fifty
	// groups on the page. The first version asked all of it in one statement,
	// and the five correlated decision lookups per row ran against every one
	// of a build's 240,945 open rows to produce fifty answers.
	heads, total, err := s.heads(ctx, targets, visible, limit, offset, filter)
	if err != nil {
		return nil, 0, err
	}

	known, err := s.decorate(ctx, targets, productID, visible, heads, filter)
	if err != nil {
		return nil, 0, err
	}
	rows := make([]decorated, 0, len(heads))
	for _, head := range heads {
		row := known[groupKey{head.VulnerabilityID, head.Fold}]
		row.groupHead = head
		rows = append(rows, row)
	}

	// Named in two more queries rather than two per row. A page of fifty was
	// a hundred and one round trips, every one of them a primary-key lookup —
	// and this is the screen somebody opens first, against the largest product
	// they have.
	//
	// The failures are reported rather than skipped. Each lookup used to be
	// ignored when it failed, so a database in trouble produced a findings
	// list with blank component names in it: a page that looks like data and
	// is not.
	issues := make([]int64, 0, len(rows))
	components := make([]int64, 0, len(rows))
	for _, row := range rows {
		issues = append(issues, row.VulnerabilityID)
		components = append(components, row.ComponentID)
		// The consumer too, so a row whose way down could not be walked can
		// still name what pulls it in.
		if row.ConsumerID != nil {
			components = append(components, *row.ConsumerID)
		}
	}
	named, err := issuesNamed(ctx, s.db, issues)
	if err != nil {
		return nil, 0, err
	}
	// What this product rates them, where it rates them anything. One
	// statement for the page, like the two lookups above: the rating belongs
	// to the product and the page is inside one, so the pair is known here.
	rated, err := RatingsIn(ctx, s.db, []int64{productID}, issues)
	if err != nil {
		return nil, 0, err
	}
	shipped, err := componentsNamed(ctx, s.db, components)
	if err != nil {
		return nil, 0, err
	}

	// Both ends of the way down to each row, in one pass over the page rather
	// than a walk per row. A row whose places are pulled in directly by the
	// build is asked about by the component itself, which lands on the same
	// answer with one step in it.
	oneBuild := len(targets) == 1
	var chains map[int64][]graph.Step
	var where map[int64]build
	if oneBuild {
		wanted := make([]int64, 0, len(rows))
		for _, row := range rows {
			if row.ConsumerID != nil {
				wanted = append(wanted, *row.ConsumerID)
			} else {
				wanted = append(wanted, row.ComponentID)
			}
		}
		if chains, err = graph.NewStore(s.db).Chains(ctx, subject, targets[0], wanted); err != nil {
			return nil, 0, err
		}
	} else {
		// Across builds a row names one of them, so that a screen has
		// somewhere to link to and an action has a build to name. Read for the
		// page's builds in one statement rather than per row.
		at := make([]int64, 0, len(rows))
		for _, row := range rows {
			at = append(at, row.TargetID)
		}
		if where, err = buildsNamed(ctx, s.db, at); err != nil {
			return nil, 0, err
		}
	}

	// The words somebody put on the page's rows, read in one statement
	// rather than per row: a tag is worth showing where the filter that
	// finds it lives, and a query per row is fifty queries for a page.
	marks, err := s.tagsFor(ctx, filter.ProductID, rows)
	if err != nil {
		return nil, 0, err
	}

	groups := make([]Group, 0, len(rows))
	for _, row := range rows {
		group := groupFrom(row, named, rated, shipped, filter.Floor)
		group.Tags = marks[markKey{row.VulnerabilityID, row.ComponentID}]
		if oneBuild {
			// How many distinct ways down there are: the consumers this
			// component has here, plus one for the build pulling it in
			// directly.
			group.Chains = row.Consumers
			if row.Direct > 0 {
				group.Chains++
			}
			down := chains[row.ComponentID]
			if row.ConsumerID != nil {
				down = chains[*row.ConsumerID]
			}
			group.Owner, group.Parent, group.Middle = Ends(down)
			// A way down that could not be walked is not the same as nothing
			// pulling this in, and the row said the second when it meant the
			// first. The finding records its consumer whatever the graph did,
			// so name it: what is unknown is the route up to the build, not
			// what sits directly above.
			//
			// It happens where the inventory places a component under
			// something that is itself not reachable from the root — a
			// fragment the producer described and never attached — and the
			// honest answer is the half we hold rather than none of it.
			if group.Owner == "" && group.Parent == "" && row.ConsumerID != nil {
				if consumer, held := shipped[*row.ConsumerID]; held {
					group.Parent = consumer.Name
				}
			}
		} else if at, held := where[row.TargetID]; held {
			group.Builds = row.Builds
			// The way down is left empty rather than filled from this one
			// build: the group sits in every build the count names, and each
			// of them reaches it its own way.
			group.Stream, group.Variant = at.Stream, at.Variant
		}
		groups = append(groups, group)
	}
	return groups, total, nil
}

// groupFrom is the row a person reads, from what the page read about it.
//
// The part both lists share. It was written twice, once in each, and the
// copies had drifted where it matters most: the cross-product list named the
// severity a report published where the per-product list named the rating in
// force, so an issue reassessed here read one way on one list and another way
// on the other — which is the whole point of reassessing it.
//
// What each list adds afterwards is what differs between them: the way down,
// for a list of one build; the product and the build to link to, for a list
// that spans them.
// Which product's rating a row reads is the line's, because the two are one
// product's: the word the line states and the word it is compared against are
// both decisions that team made.
func groupFrom(row decorated, named map[int64]Vulnerability, rated map[RatedKey]string,
	shipped map[int64]graph.Component, floor Floor) Group {

	group := Group{
		Fold: row.Fold, Packages: row.Packages, Consumers: row.pullers(),
		Places: row.Places, Answered: row.Answered,
		Urgency: row.Urgency, Exploited: Rank(row.Urgency).Exploited(),
		LikelihoodPPM: row.LikelihoodPPM, ScoreCenti: row.ScoreCenti,
		Scored:   row.Scored == 1,
		FixState: FixState(row.FixState), FixedIn: row.FixedIn,
		Matched:  Matched(row.Matched),
		State:    stateWord(row.Places, row.Waiting, row.Approved, row.Lapsed),
		SentBack: row.SentBack > 0,
		OpenedAt: row.OpenedAt, DueAt: row.DueAt,
		Undisclosed: row.Undisclosed,
		DiscloseAt:  row.DiscloseAt,
	}
	if issue, held := named[row.VulnerabilityID]; held {
		issue = issue.RatedIn(rated[RatedKey{floor.ProductID, row.VulnerabilityID}])
		group.Vulnerability, group.Severity = issue.Identifier, issue.InForce()
		// The one line of the issue's own words the row shows. Two lists of
		// the same rows, one of which says what the issue is: fifty rows
		// otherwise read "CVE-2026-74280 · linux-image" fifty times.
		group.Summary = firstLineOf(issue.Description)
	}
	if component, held := shipped[row.ComponentID]; held {
		group.Component, group.Version = component.Name, component.Version
		group.Ecosystem = graph.EcosystemOf(component.Purl)
		if component.UpstreamVersion != "" {
			group.Upstream = component.UpstreamName + " " + component.UpstreamVersion
		}
		// Which source package it was built from, where that is not the name
		// itself. Two rows that are one bump say so on both lists.
		if component.UpstreamName != "" && component.UpstreamName != component.Name {
			group.Source = component.UpstreamName
		}
	}
	// Why there is no deadline, said rather than left as a blank cell. The two
	// reasons are exhaustive, so whatever the line does not account for is the
	// other one: the line is a statement about the rating, which is on the
	// row, and everything else without a deadline is in a release nothing is
	// going to be fixed in.
	//
	// Which line that is belongs to the caller: per product it is the
	// product's own, and across products it is the deployment's, because one
	// word chosen for a page that spans them would answer for none of them.
	if group.DueAt == nil {
		group.NoDeadline = OutOfSupport
		if !floor.Admits(group.Exploited, group.Severity) {
			group.NoDeadline = BelowTheLine
		}
	}
	return group
}

// build names one of the places a group sits, for a row that spans several.
type build struct {
	ID      int64  `bun:"id"`
	Stream  string `bun:"stream"`
	Variant string `bun:"variant"`
}

// buildsNamed names the builds a page's rows point at.
//
// One statement for the page rather than one per row, and the names are the
// ones somebody declared: a path resolves a name without regard to capitals ,
// so what was typed is both what reads correctly and what routes.
func buildsNamed(ctx context.Context, db bun.IDB, ids []int64) (map[int64]build, error) {
	named := make(map[int64]build, len(ids))
	if len(ids) == 0 {
		return named, nil
	}
	var rows []build
	if err := db.NewSelect().
		TableExpr(`target AS "tg"`).
		Join(`JOIN stream AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN variant AS "va" ON va.id = tg.variant_id`).
		ColumnExpr(`tg.id AS "id"`).
		ColumnExpr(`st.display_name AS "stream"`).
		ColumnExpr(`va.display_name AS "variant"`).
		Where("tg.id IN (?)", bun.List(ids)).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("name the builds a page sits in: %w", err)
	}
	for _, row := range rows {
		named[row.ID] = row
	}
	return named, nil
}

// groupHead is one group of the findings list as the covering index knows it:
// which issue in which component, at how many places, and the worst urgency
// among them. Everything the list is filtered, ordered and paged by.
type groupHead struct {
	VulnerabilityID int64 `bun:"vulnerability_id"`
	// Fold is what the row is about: the source package at the version it was
	// built at. Two binaries of one source are one row, because they are one
	// thing to decide about, one thing to upgrade and one rule to route.
	Fold string `bun:"fold"`
	// ComponentID is a representative of the fold — the lowest identifier —
	// so that everything read per row has a component to hang off. Which one
	// it is decides nothing a reader sees.
	ComponentID int64 `bun:"component_id"`
	// Places is how many findings sit under the row. What the cap is measured
	// against and what the disposition register expands to.
	//
	// How many packages and how many consumers — the numbers a reader is
	// shown — are counted in the second statement rather than here. They are
	// COUNT(DISTINCT), and **MariaDB answers a query with no rows at all when
	// a COUNT(DISTINCT) sits beside a window function**, silently: no error,
	// an empty page, and a total from the other statement that says there was
	// something. This one carries the window function that counts the whole
	// filtered set, so the distinct counts go where there is none.
	Places  int   `bun:"places"`
	Urgency int64 `bun:"urgency"`
	// Total is how many groups the filter admits, the same on every row.
	Total int `bun:"total"`
}

// NoDeadline is why a finding carries no deadline.
//
// There are exactly two reasons and both are deliberate — a deadline stored at
// ingest works out a deadline at ingest for everything else — so an empty cell
// would mean two intended things at once, on the one screen whose purpose is
// noticing what is running out.
type NoDeadline string

const (
	// BelowTheLine is a finding its product does not consider worth
	// triaging . Still recorded, still counted, and off the clock.
	BelowTheLine NoDeadline = "below-the-line"
	// OutOfSupport is a finding in a release that is past its end of life
	// . Nothing is going to be fixed there, so nothing is late.
	OutOfSupport NoDeadline = "out-of-support"
)

// groupKey names one group of the list.
type groupKey struct {
	vulnerabilityID int64
	fold            string
}

// pullers is how many things pull this fold's packages in here.
//
// The distinct consumers, plus the build itself where anything is pulled in
// directly: a null consumer is the product, which is one thing however many
// packages hang off it, and COUNT(DISTINCT) passes over nulls.
func (d decorated) pullers() int {
	return pullersOf(d.Consumers, d.Direct)
}

// decorated is a group of the list with what the page shows about it read in.
type decorated struct {
	groupHead
	Answered      int        `bun:"answered"`
	OpenedAt      time.Time  `bun:"opened_at"`
	DueAt         *time.Time `bun:"due_at"`
	Undisclosed   bool       `bun:"undisclosed"`
	DiscloseAt    *time.Time `bun:"disclose_at"`
	LikelihoodPPM int        `bun:"likelihood_ppm"`
	ScoreCenti    int        `bun:"score_centi"`
	Scored        int        `bun:"scored"`
	FixState      string     `bun:"fix_state"`
	FixedIn       string     `bun:"fixed_in"`
	Matched       string     `bun:"matched"`
	ConsumerID    *int64     `bun:"consumer_id"`
	Consumers     int        `bun:"consumers"`
	Direct        int        `bun:"direct"`
	// Packages is how many binaries of the fold sit here and ConsumerPlaces
	// how many things pull them in — the two numbers a reader is shown.
	Packages       int   `bun:"packages"`
	ConsumerPlaces int   `bun:"consumer_places"`
	Builds         int   `bun:"builds"`
	TargetID       int64 `bun:"target_id"`
	Waiting        int   `bun:"waiting_here"`
	Approved       int   `bun:"approved_here"`
	Lapsed         int   `bun:"lapsed_here"`
	SentBack       int   `bun:"sent_back_here"`
}

// heads reads one page of the findings list's groups, most urgent first, from
// finding's covering index and nothing else, and how many groups there are.
//
// The total rides on the page. It is counted through the same filter as the
// page — a total that ignores the narrowing is worse than no total: it
// reports how much there is to decide about, which is the figure people
// quote, while the list beside it shows something else — and it used to be
// a second statement making the same grouping over the same rows to count
// what the first had just grouped. `COUNT(*) OVER ()` is the number of rows
// the grouping produced after the HAVING clauses and before the limit,
// which is exactly that, on all four engines (window functions are in each
// of them), for the cost of nothing. Where the page comes back empty — an
// offset past the end — there is no row to carry it and it is counted
// separately.
func (s *Store) heads(ctx context.Context, targets []int64, visible []access.Visibility,
	limit, offset int, filter Filter) ([]groupHead, int, error) {

	var heads []groupHead
	page := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		// The fold, which is the unit a person acts in: two binaries of one
		// source package are one row, because upgrading them is one act,
		// deciding about them is one judgment and routing them is one rule.
		// A reader with no way to see that was reading a list a third of
		// which was the same work said again.
		Join(`JOIN component AS "c" ON c.id = f.component_id`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(FoldedOn+` AS "fold"`).
		ColumnExpr(`MIN(f.component_id) AS "component_id"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		// The most urgent place this issue sits at. A group is one decision
		// about one issue at one fold, so what should decide where that
		// decision appears is the worst of what it covers.
		ColumnExpr(`MAX(f.urgency) AS "urgency"`).
		ColumnExpr(`COUNT(*) OVER () AS "total"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr(GroupedOn)
	// The issue is joined only where the order needs it. The default page
	// reads finding's covering index and nothing else, which is what makes it
	// a page rather than a scan, and a join added for everybody would pay for
	// a sort almost nobody asks for.
	if by, known := order[filter.SortBy]; known && by.issue {
		page = page.Join(`JOIN vulnerability AS "v" ON v.id = f.vulnerability_id`)
	}
	page = page.
		// Ordered by urgency unless somebody asked otherwise. Urgency
		// rather than how widespread something is: sorting by place
		// count puts whatever ships in the most places at the top,
		// which on a real image is the kernel — everywhere, and not
		// therefore the thing to look at first. What somebody with an
		// hour needs at the top is what is being exploited.
		//
		// The expression comes from the allowlist and never from the
		// request , and the tie-break is always the same pair so that
		// paging is stable: two rows equal on the sorted column must
		// not swap between pages, or a page boundary drops one and
		// repeats another.
		OrderExpr(sortedBy(filter)).
		Limit(limit).Offset(offset)
	if err := filter.narrow(page).Scan(ctx, &heads); err != nil {
		return nil, 0, fmt.Errorf("read what is open: %w", err)
	}
	if len(heads) > 0 {
		return heads, heads[0].Total, nil
	}
	// Grouped the way the page groups, which is by the fold rather than by
	// the component. Two binaries of one source are one row on a page and
	// were two here, so the figure above the list changed depending on which
	// page was being looked at — and this is the one somebody quotes, because
	// it is what a deep link or the last page shows.
	counted := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		Join(`JOIN component AS "c" ON c.id = f.component_id`).
		ColumnExpr("f.vulnerability_id").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr(GroupedOn)
	total, err := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, filter.narrow(counted)).
		Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count what is open: %w", err)
	}
	return heads, total, nil
}

// decorate reads what the page shows about each of its groups, in one
// statement over the groups named and no other.
//
// Narrowed through the same filter as the groups were chosen by, so every
// number here is over exactly the places the group was counted over: a list
// narrowed to what sits inside one container reports how many of *those*
// places are answered, not how many places there are anywhere.
func (s *Store) decorate(ctx context.Context, targets []int64, productID int64,
	visible []access.Visibility, heads []groupHead, filter Filter) (map[groupKey]decorated, error) {

	known := make(map[groupKey]decorated, len(heads))
	if len(heads) == 0 {
		return known, nil
	}
	issues := make([]int64, 0, len(heads))
	folds := make([]string, 0, len(heads))
	for _, head := range heads {
		issues = append(issues, head.VulnerabilityID)
		folds = append(folds, head.Fold)
	}

	// How far each group has been decided, counted the way the state filter
	// counts it, so the row and the filter cannot disagree. Four correlated
	// counts over our decisions in this product at each place and at the
	// versions the place holds, plus whether any live claim is with its
	// author.
	var rows []decorated
	q := s.db.NewSelect().
		TableExpr(`finding AS "f"`).
		// Joined for the likelihood and the score. Likelihood ranks above
		// severity, so a list that orders by it and does not show it looks
		// unsorted.
		Join(`JOIN vulnerability AS "v" ON v.id = f.vulnerability_id`).
		// And for the versions a decision is keyed on. Two primary-key
		// lookups per place on the page, so the correlated counts can ask
		// whether a claim is about the versions shipping here rather than
		// about the place at whatever versions it once held.
		Join(`JOIN component AS "c" ON c.id = f.component_id`).
		Join(`LEFT JOIN component AS "uc" ON uc.id = f.consumer_id`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(FoldedOn+` AS "fold"`).
		ColumnExpr(`MIN(f.component_id) AS "component_id"`).
		ColumnExpr(`MAX(COALESCE(v.likelihood_ppm, 0)) AS "likelihood_ppm"`).
		ColumnExpr(`MAX(COALESCE(v.score_centi, 0)) AS "score_centi"`).
		// Whether any of the issues folded here carries a score at all.
		// Written as a sum rather than as a boolean, because the four engines
		// do not agree about what a boolean out of an aggregate is.
		ColumnExpr(`MAX(CASE WHEN v.score_centi IS NULL THEN 0 ELSE 1 END) AS "scored"`).
		ColumnExpr(`SUM(CASE WHEN f.suppressed_by IS NULL THEN 0 ELSE 1 END) AS "answered"`).
		// When the earliest of these places opened, and the earliest deadline
		// any of them carries. The age a deadline relates to is this one, not
		// the year in the identifier.
		ColumnExpr(`MIN(f.opened_at) AS "opened_at"`).
		ColumnExpr(`MIN(f.due_at) AS "due_at"`).
		// Whether anything here is undisclosed, and when the earliest embargo
		// ends. One undisclosed place among fifty makes the group
		// undisclosed, which is what it is for anybody deciding what may be
		// said about it.
		//
		// Counted rather than aggregated over the word. A maximum of the word
		// was written on the belief that "private" sorts after "public", and
		// it does not — so the expression returned "public" for exactly the
		// mixed group it was written to catch, and a list showed no embargo
		// marker on a row holding an undisclosed place. The four engines do
		// not agree on a boolean aggregate either, and counting is the same
		// question asked portably.
		ColumnExpr(`SUM(CASE WHEN f.visibility = ? THEN 1 ELSE 0 END) > 0 AS "undisclosed"`,
			access.Private).
		ColumnExpr(`MIN(f.disclose_at) AS "disclose_at"`).
		ColumnExpr(`MIN(f.fix_state) AS "fix_state"`).
		ColumnExpr(`MIN(f.fixed_in) AS "fixed_in"`).
		// Any of them: a group is an issue at a component, every place of it
		// comes from one line of a scanner's report, and the applier writes
		// that line to all of them.
		ColumnExpr(`MIN(COALESCE(f.matched, '')) AS "matched"`).
		// One of the ways down, and how many there are. MIN passes over the
		// places the build pulls in directly, whose consumer is null, so those
		// are counted separately rather than being read as "no route at all".
		ColumnExpr(`MIN(f.consumer_id) AS "consumer_id"`).
		ColumnExpr(`COUNT(DISTINCT f.consumer_id) AS "consumers"`).
		// The other number a reader is shown, counted here rather than beside
		// the window function that pages the list — see groupHead. The
		// consumers are already counted just above, and a distinct count of
		// place identities would not do: a place is a package under a
		// consumer, so across a fold of three packages that is the place count
		// with a different word on it.
		ColumnExpr(`COUNT(DISTINCT f.component_id) AS "packages"`).
		ColumnExpr(`SUM(CASE WHEN f.consumer_id IS NULL THEN 1 ELSE 0 END) AS "direct"`).
		// How many builds in the selection hold this group, and one of them to
		// name. Both are one where the selection is a single build, which is
		// why the row says nothing about either there.
		ColumnExpr(`COUNT(DISTINCT f.target_id) AS "builds"`).
		ColumnExpr(`MIN(f.target_id) AS "target_id"`)
	// How far each group has been decided, counted the way the state filter
	// counts it, so the row and the filter cannot disagree. One spelling of
	// each state, in decided.go.
	q = decisionCounts(q, "?", []any{productID},
		claimWaiting, claimApproved, claimLapsed, claimSentBack).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		// The page's issues and the page's folds, as two lists. That admits an
		// issue from one row at the fold of another, and those groups are read
		// and dropped; what it buys is the index. As fifty
		// `(issue = ? AND fold = ?)` pairs joined by OR, SQLite walked every
		// open row in the build against the fifty — 150 ms, half the page —
		// where two lists are fifty index seeks, 2 ms. A page is mostly one
		// package's issues, so the extra groups are few, and each is one seek
		// too.
		Where("f.vulnerability_id IN (?)", bun.List(issues)).
		Where(FoldedOn+" IN (?)", bun.List(folds)).
		GroupExpr(GroupedOn)
	if err := filter.narrow(q).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read about what is open: %w", err)
	}
	for _, row := range rows {
		known[groupKey{row.VulnerabilityID, row.Fold}] = row
	}
	return known, nil
}

// ends reduces a way down to the two steps worth showing and a count of what
// was left out.
//
// The chain arrives build-first. The build itself is not one of the two: every
// row in a list scoped to one build shares it, so naming it in every row says
// nothing and costs the width that the parts which differ need.
// Ends returns the two ends of a way down and how many steps sit between
// them: the part of the product a component belongs to, and what directly
// pulls it in. Exported because a decision is described the same way
// wherever it is listed, and a second spelling of which step is which is how
// two screens disagree about where a component sits.
func Ends(down []graph.Step) (owner, parent string, middle int) {
	switch len(down) {
	case 0:
		// The inventory placed the component nowhere. Saying so is the honest
		// answer; claiming the product itself pulls it in is a comfortable
		// sentence and not a true one.
		return "", "", 0
	case 1:
		// The build pulls it in directly, so both ends are the build.
		return down[0].Name, down[0].Name, 0
	}
	owner = down[1].Name
	parent = down[len(down)-1].Name
	// Everything between the two named steps.
	if middle = len(down) - 3; middle < 0 {
		middle = 0
	}
	return owner, parent, middle
}

// firstLineOf is as much of a description as a row can carry: the first line
// or the first sentence, whichever ends sooner, and nothing where there is
// none.
//
// Cut here rather than on the screen, so that every reader of the list gets
// the same summary — an export and a row disagreeing about what an issue says
// would be two answers to one question — and so that a page of fifty does not
// carry fifty paragraphs in order to render one line each.
func firstLineOf(description string) string {
	said := strings.TrimSpace(description)
	if said == "" {
		return ""
	}
	if cut := strings.IndexAny(said, "\n\r"); cut > 0 {
		said = said[:cut]
	}
	// The stop and the space after it, rather than the stop alone: a version
	// number in the middle of a sentence is not the end of one.
	if stop := strings.Index(said, ". "); stop > 0 {
		said = said[:stop+1]
	}
	const most = 160
	if len(said) > most {
		if space := strings.LastIndex(said[:most], " "); space > 0 {
			return strings.TrimSpace(said[:space]) + "…"
		}
		return said[:most] + "…"
	}
	return strings.TrimSpace(said)
}
