package finding

// Grouping what is open by the thing that would answer it, rather than by the
// issue.
//
// Two reads that are the same shape and a different question from the findings
// list: one row per upstream bump with everything it would close, and one row
// per component with everything open against it. They lived in read.go beside
// the list itself, which is how a file gets to two and a half thousand lines —
// each addition is small and beside something related, and nothing is ever the
// one that made it too long.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// Bundle is one upstream bump and everything it would close.
//
// The unit a remediation is actually done in, which nothing here had: the same
// bump answers thousands of rows. On a real image 5,047 fixable rows are 271
// distinct bumps and one kernel bump closes 917 of them.
type Bundle struct {
	// Fold is what a bump is *of*, and what everything under it is grouped by:
	// the source package at the version it was built at, in the ecosystem and
	// distribution it came from. Siblings collapse — curl, libcurl4t64 and
	// libcurl3t64 are one source package bumping once — and one source shipped
	// at two versions in one build stays two, which keying on the name alone
	// could not do.
	Fold string
	// Upstream is what to call it: the source package where one is recorded,
	// and the component's own name otherwise.
	Upstream string
	// From is the version in hand and To the version that fixes it, as
	// whoever packages the component wrote them. Never compared, only
	// grouped: comparing them needs an ordering per ecosystem this does not
	// have.
	From string
	To   string
	// Components are the names this bundle covers, which is what makes a
	// bundle keyed on an upstream readable — somebody declaring a curl bump
	// should see which packages it moves.
	Components []string
	// Issues is how many distinct vulnerabilities the bump closes, Places how
	// many findings those sit at, and Builds how many builds of the selection
	// hold any of it.
	Issues int
	Places int
	Builds int
	// In names those builds, which is what a declaration is offered against:
	// a bump is declared for releases, and the ones worth offering are the
	// ones that have it.
	In []Build
	// Urgency is the worst of what it closes, Severity that as a word, and
	// Exploited whether any of it is being used. A bundle is worth doing for
	// its worst member.
	Urgency   int64
	Severity  string
	Exploited bool
}

// Bundles groups what is fixable by the bump that would fix it.
//
// **Presentation, like every other grouping here.** One act still writes one
// decision per component and per place; this only says which rows a
// person is answering at once.
//
// Only what has a fix: a bundle is a version to move to, so a finding with no
// fixed version is not in one. That is the same population the fixable filter
// selects, and it is applied here rather than left to a caller, because a
// bundle keyed on an empty version is one bundle holding everything unfixable.
func (s *Store) Bundles(ctx context.Context, subject access.Subject, scope Scope,
	limit, offset int, filter Filter) ([]Bundle, int, error) {

	productID, visible, targets, err := s.inScope(ctx, subject, scope, &filter)
	if err != nil {
		return nil, 0, err
	}
	if len(targets) == 0 {
		return nil, 0, nil
	}
	limit = database.AList.Of(limit)

	var rows []struct {
		Fold     string `bun:"fold"`
		Upstream string `bun:"upstream"`
		From     string `bun:"shipped"`
		To       string `bun:"fixed_in"`
		Issues   int    `bun:"issues"`
		Places   int    `bun:"places"`
		Builds   int    `bun:"builds"`
		Urgency  int64  `bun:"urgency"`
		Worst    int    `bun:"worst"`
		Total    int    `bun:"total"`
	}
	// The worst thing in the bundle, as a rank rather than as a word, because
	// the four engines do not agree on how words order. Folded exactly the way
	// the line and the deadline fold them, so an unrated issue is a medium
	// here as it is everywhere else.
	const worst = `MAX(CASE
		WHEN ` + EffectiveSeverityExpr + ` = 'critical' THEN 4
		WHEN ` + EffectiveSeverityExpr + ` = 'high' THEN 3
		WHEN ` + EffectiveSeverityExpr + ` IN ('low', 'negligible', 'none') THEN 1
		ELSE 2 END)`

	bundled := func(q *bun.SelectQuery) *bun.SelectQuery {
		return filter.narrow(q.
			TableExpr("finding AS f").
			Join("JOIN component AS c ON c.id = f.component_id").
			Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
			Join(RatedHere, productID).
			Where("f.target_id IN (?)", bun.List(targets)).
			Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible)).
			// A bundle is a version to move to.
			Where("f.fixed_in IS NOT NULL").
			Where("f.fixed_in <> ?", "").
			GroupExpr(FoldedOn + ", f.fixed_in"))
	}

	page := bundled(s.db.NewSelect()).
		ColumnExpr(FoldedOn + " AS fold").
		ColumnExpr(PerFold(SourceName) + " AS upstream").
		ColumnExpr(PerFold(SourceVersion) + " AS shipped").
		ColumnExpr("f.fixed_in AS fixed_in").
		ColumnExpr("COUNT(DISTINCT f.vulnerability_id) AS issues").
		ColumnExpr("COUNT(*) AS places").
		ColumnExpr("COUNT(DISTINCT f.target_id) AS builds").
		ColumnExpr("MAX(f.urgency) AS urgency").
		ColumnExpr(worst + " AS worst").
		ColumnExpr("COUNT(*) OVER () AS total").
		// Worst first. A bundle is worth doing for its worst member, and one
		// closing nine hundred low findings is not the one to do before a
		// bundle closing one that is being exploited.
		OrderExpr("urgency DESC, issues DESC, upstream, fixed_in").
		Limit(limit).Offset(offset)
	if err := page.Scan(ctx, &rows); err != nil {
		return nil, 0, fmt.Errorf("read what one bump would close: %w", err)
	}

	total := 0
	if len(rows) > 0 {
		total = rows[0].Total
	} else {
		// Counted the same way the findings list counts its groups:
		// over a derived table, named and quoted, because GROUPS is
		// reserved on MySQL 8.
		counted := bundled(s.db.NewSelect()).ColumnExpr("COUNT(*) AS n")
		if total, err = s.db.NewSelect().
			TableExpr(`(?) AS "bundled"`, counted).Count(ctx); err != nil {
			return nil, 0, fmt.Errorf("count what the bumps are: %w", err)
		}
	}

	bundles := make([]Bundle, 0, len(rows))
	for _, row := range rows {
		bundles = append(bundles, Bundle{
			Fold:     row.Fold,
			Upstream: row.Upstream, From: row.From, To: row.To,
			Issues: row.Issues, Places: row.Places, Builds: row.Builds,
			Urgency: row.Urgency, Severity: worstWord(row.Worst),
			Exploited: Rank(row.Urgency).Exploited(),
		})
	}
	if err := s.namesIn(ctx, targets, visible, filter, bundles); err != nil {
		return nil, 0, err
	}
	return bundles, total, nil
}

// pullersOf is how many things pull a component in, given the distinct
// consumers counted and how many rows had none.
//
// A component nothing pulls in has no consumer to count distinctly, so the
// build itself is the one thing pulling it in.
func pullersOf(consumers, direct int) int {
	if direct > 0 {
		return consumers + 1
	}
	return consumers
}

// Build is one release and variant, by name.
type Build struct {
	Stream  string
	Variant string
}

// worstWord turns the rank the bundle query folds severities to back into the
// word, in the same four the rest of this speaks.
func worstWord(rank int) string {
	switch rank {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 1:
		return "low"
	case 2:
		return "medium"
	}
	return ""
}

// namesIn fills in which component names each bundle on the page covers.
//
// A second statement over the page's bundles rather than a string aggregate in
// the first: the four engines spell that three ways, and the one thing this
// needs is a list of names.
func (s *Store) namesIn(ctx context.Context, targets []int64, visible []access.Visibility,
	filter Filter, bundles []Bundle) error {

	if len(bundles) == 0 {
		return nil
	}
	var rows []struct {
		Fold    string `bun:"fold"`
		To      string `bun:"fixed_in"`
		Name    string `bun:"name"`
		Stream  string `bun:"stream"`
		Variant string `bun:"variant"`
	}
	q := filter.narrow(s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN variant AS va ON va.id = tg.variant_id").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("f.fixed_in IS NOT NULL").
		Where("f.fixed_in <> ?", "").
		GroupExpr(FoldedOn + ", f.fixed_in, c.name, st.name, va.name")).
		ColumnExpr(FoldedOn + " AS fold").
		ColumnExpr("f.fixed_in AS fixed_in").
		ColumnExpr("c.name AS name").
		ColumnExpr("st.name AS stream").
		ColumnExpr("va.name AS variant")
	if err := q.Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read which packages a bump moves: %w", err)
	}
	named := map[string][]string{}
	seen := map[string]bool{}
	in := map[string][]Build{}
	for _, row := range rows {
		at := row.Fold + "\x00" + row.To
		if !seen[at+"\x00c\x00"+row.Name] {
			seen[at+"\x00c\x00"+row.Name] = true
			named[at] = append(named[at], row.Name)
		}
		if !seen[at+"\x00b\x00"+row.Stream+"\x00"+row.Variant] {
			seen[at+"\x00b\x00"+row.Stream+"\x00"+row.Variant] = true
			in[at] = append(in[at], Build{Stream: row.Stream, Variant: row.Variant})
		}
	}
	for i := range bundles {
		at := bundles[i].Fold + "\x00" + bundles[i].To
		bundles[i].Components = named[at]
		bundles[i].In = in[at]
	}
	return nil
}

// ComponentGroups returns what is open against a target, gathered by the
// component it is open against rather than by the issue.
func (s *Store) ComponentGroups(ctx context.Context, subject access.Subject, scope Scope,
	limit, offset int, filter Filter) ([]ComponentGroup, int, error) {

	_, visible, targets, err := s.inScope(ctx, subject, scope, &filter)
	if err != nil {
		return nil, 0, err
	}
	if len(targets) == 0 {
		return nil, 0, nil
	}
	limit = database.AList.Of(limit)

	var rows []struct {
		ComponentID int64 `bun:"component_id"`
		Issues      int   `bun:"issues"`
		Places      int   `bun:"places"`
		Urgency     int64 `bun:"urgency"`
		Total       int   `bun:"total"`
	}
	// Everything read here is in finding's covering index, so this is one
	// walk of it however large the build is; whether anything is exploited
	// is read off the urgency, which ranks it in a band of its own.
	page := s.db.NewSelect().
		TableExpr("finding AS f").
		ColumnExpr("f.component_id AS component_id").
		// Distinct issues rather than rows, because that is what the findings
		// list shows and therefore what hiding this component would remove
		// from it.
		ColumnExpr("COUNT(DISTINCT f.vulnerability_id) AS issues").
		ColumnExpr("COUNT(*) AS places").
		ColumnExpr("MAX(f.urgency) AS urgency").
		// The total rides on the page, as the findings list's does.
		ColumnExpr("COUNT(*) OVER () AS total").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.component_id").
		// By weight, not by urgency, unless asked. The question this view
		// answers is where the volume is, and making urgency the default
		// would reproduce the findings list at worse resolution — but "which
		// of these is worst" is the other question somebody reads this to
		// answer, and refusing to answer it sends them back to a list of six
		// thousand rows to find out.
		OrderExpr(componentOrder(filter.SortBy)).
		Limit(limit).Offset(offset)
	if err = filter.narrow(page).Scan(ctx, &rows); err != nil {
		return nil, 0, fmt.Errorf("read what is open by component: %w", err)
	}

	total := 0
	if len(rows) > 0 {
		total = rows[0].Total
	} else {
		counted := s.db.NewSelect().
			TableExpr("finding AS f").
			ColumnExpr("f.component_id").
			Where("f.target_id IN (?)", bun.List(targets)).
			Where("f.closed_at IS NULL").
			Where("f.visibility IN (?)", bun.List(visible)).
			GroupExpr("f.component_id")
		if total, err = s.db.NewSelect().
			TableExpr(`(?) AS "grouped"`, filter.narrow(counted)).
			Count(ctx); err != nil {
			return nil, 0, fmt.Errorf("count what is open by component: %w", err)
		}
	}

	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ComponentID)
	}
	shipped, err := componentsNamed(ctx, s.db, ids)
	if err != nil {
		return nil, 0, err
	}

	upgrades, err := s.upgradesFor(ctx, ids, targets, visible, filter)
	if err != nil {
		return nil, 0, err
	}
	bands, err := s.bandsFor(ctx, ids, targets, visible, filter)
	if err != nil {
		return nil, 0, err
	}

	groups := make([]ComponentGroup, 0, len(rows))
	for _, row := range rows {
		group := ComponentGroup{
			Issues: row.Issues, Places: row.Places,
			Exploited: Rank(row.Urgency).Exploited(), Urgency: row.Urgency,
			Upgrades:   upgrades[row.ComponentID],
			BySeverity: bands[row.ComponentID],
		}
		group.Worst = worstBand(group.BySeverity)
		if named, ok := shipped[row.ComponentID]; ok {
			group.Component = named.Name
			group.Version = named.Version
			group.Upstream = named.UpstreamVersion
			group.UpstreamName = named.UpstreamName
			group.Ecosystem = graph.EcosystemOf(named.Purl)
		}
		groups = append(groups, group)
	}
	return groups, total, nil
}

// componentOrder is how the by-component view is ordered.
//
// Weight by default and urgency on request, both with the same tie-breaks so
// that a page boundary is a boundary rather than a place rows move across.
//
// The urgency is what is already read for the exploited flag, so asking for it
// costs nothing: exploited ranks in a band of its own above every severity,
// which is what "worst" means everywhere else here.
func componentOrder(by SortKey) string {
	if by == BySeverity || by == ByUrgency {
		return "urgency DESC, issues DESC, places DESC, f.component_id"
	}
	return "issues DESC, places DESC, f.component_id"
}

// bandsFor is how the issues open against each component were rated.
//
// **Ranking by count alone is the wrong answer to the question this view
// asks.** A package with forty-four issues outranks one with three criticals,
// and somebody reading it to decide what to look at next is told the opposite
// of what they need. The count is still the order — where the weight is is the
// question — but the row says what the weight is made of.
//
// Distinct issues, like the count beside it, so the parts sum to the whole
// rather than to the number of places.
func (s *Store) bandsFor(ctx context.Context, ids []int64, targets []int64,
	visible []access.Visibility, filter Filter) (map[int64]map[string]int, error) {

	if len(ids) == 0 {
		return nil, nil
	}
	var rows []struct {
		ComponentID int64  `bun:"component_id"`
		Band        string `bun:"band"`
		Issues      int    `bun:"issues"`
	}
	query := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		ColumnExpr("f.component_id AS component_id").
		ColumnExpr("COALESCE(v.severity, '') AS band").
		ColumnExpr("COUNT(DISTINCT f.vulnerability_id) AS issues").
		Where("f.component_id IN (?)", bun.List(ids)).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.component_id, COALESCE(v.severity, '')")
	if err := filter.narrow(query).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read how what is open here was rated: %w", err)
	}
	out := make(map[int64]map[string]int, len(ids))
	for _, row := range rows {
		// Folded through the one place that says which words are real: a
		// scanner's "unknown" and no rating at all are the same state, and
		// two rows for it is two names for one nothing.
		band := BandOf(row.Band)
		if out[row.ComponentID] == nil {
			out[row.ComponentID] = map[string]int{}
		}
		out[row.ComponentID][band] += row.Issues
	}
	return out, nil
}

// upgradesFor is where each component on a page could go, and how much each
// move would close.
//
// One read for the page rather than one per row: a page of fifty components on
// a real image is fifty round trips otherwise, for a column.
//
// **Ordered by how much it closes, never by version.** Comparing two versions
// needs an ordering per ecosystem this does not have, so the question
// "which of these is nearest" is one this cannot answer and does not pretend
// to. What it answers is which one closes the most, which is the question
// somebody choosing between them is actually asking.
func (s *Store) upgradesFor(ctx context.Context, ids []int64, targets []int64,
	visible []access.Visibility, filter Filter) (map[int64][]Candidate, error) {

	if len(ids) == 0 {
		return nil, nil
	}
	var rows []struct {
		ComponentID int64  `bun:"component_id"`
		Issue       int64  `bun:"vulnerability_id"`
		FixedIn     string `bun:"fixed_in"`
		Purl        string `bun:"purl"`
	}
	query := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN component AS c ON c.id = f.component_id").
		ColumnExpr("f.component_id AS component_id").
		ColumnExpr("f.vulnerability_id AS vulnerability_id").
		ColumnExpr("f.fixed_in AS fixed_in").
		ColumnExpr("c.purl AS purl").
		Where("f.component_id IN (?)", bun.List(ids)).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		// A finding with nothing to move to contributes no upgrade. It is not
		// absent from the view — it is a row with an empty column, which is
		// the population that needs a judgment rather than a bump.
		Where("f.fixed_in IS NOT NULL").
		Where("f.fixed_in <> ?", "").
		// Grouped to one row per issue rather than per version string, because
		// a version has to be read out of that string before it can be counted
		// — and grouped rather than plain because the narrowing asks questions
		// of the places under an issue, which are aggregates.
		GroupExpr("f.component_id, f.vulnerability_id, f.fixed_in, c.purl")
	if err := filter.narrow(query).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read where each component could go: %w", err)
	}
	per := map[int64][]namedFix{}
	scheme := map[int64]vercmp.Scheme{}
	for _, row := range rows {
		versions := versionsIn(row.FixedIn)
		if len(versions) == 0 {
			continue
		}
		per[row.ComponentID] = append(per[row.ComponentID],
			namedFix{issue: row.Issue, versions: versions})
		scheme[row.ComponentID] = vercmp.SchemeOf(graph.EcosystemOf(row.Purl))
	}
	out := make(map[int64][]Candidate, len(per))
	for component, found := range per {
		out[component] = candidatesFrom(found, scheme[component])
	}
	return out, nil
}

// PerBuild is one build's answer about a component: the version it ships and
// where that could go.
type PerBuild struct {
	TargetID int64
	Stream   string
	Variant  string
	// Version is what this build ships, and Upgrades where it could go, each
	// with how many issues that move would close here.
	Version string
	// Purl is the package identifier, which is where the ecosystem is read
	// from and what an upstream address is built out of.
	Purl string
	// Summary is one line saying what the package is, and ProjectURL where it
	// is developed, both as an ecosystem's index stated them. Absent for
	// plenty of components: one index serves no summary and none is asked
	// about a distribution package.
	Summary    string
	ProjectURL string
	// Supplier is who the scan said supplied it, from the inventory rather
	// than from an index.
	Supplier string
	// BySeverity is what is open here by how it was rated, so a count has a
	// shape: forty issues and three criticals are different work.
	BySeverity map[string]int
	// Exploited says whether any of them is known to be exploited, which
	// outranks everything else about a row.
	Exploited bool
	// Fixable is how many of them any version fixes, counted once per issue.
	// Summed from the per-version counts instead, an issue whose record names
	// three versions is counted three times and the total exceeds what is open.
	Fixable int
	// Newest is what the ecosystem's index says is current and when it
	// shipped, and FirstSeen when this deployment first saw the component.
	Newest    string
	NewestAt  *time.Time
	FirstSeen time.Time
	Upgrades  []Candidate
	// Issues is how many distinct vulnerabilities are open against it in this
	// build, Consumers how many things pull it in there, and Places how many
	// times those sit somewhere in it.
	//
	// Consumers is the unit somebody acts in: a judgment covers the whole
	// fold, and what varies underneath is what pulls the package in. Places
	// is kept as the figure the bulk cap is measured against.
	Issues    int
	Consumers int
	Places    int
	// DueAt is the earliest deadline among them, which is what a commitment
	// about this build is gated against.
	DueAt *time.Time
	// Committed is what somebody has already promised for this build: the
	// version and the date. Read from the decisions rather than a record
	// beside them.
	CommittedTo *time.Time
	UpgradeTo   string
}

// AcrossBuilds is one component seen in every build of a product that carries
// it.
//
// **The screen that was missing.** The by-component view answers where the
// weight is, and clicking a component took somebody to a filtered list of its
// findings — so a component could be read and never acted on, and the act of
// upgrading it ended up on a screen of its own keyed on version pairs. This is
// the component as the thing it is: what each stream ships, where each could
// go, and what has been promised for each.
//
// **Per build rather than per product**, because the answer differs by build
// and that is the whole difficulty: a stream staying on 3.0.x and a stream on
// 3.5.x are different work with different testing, and one target across both
// would be wrong for one of them.
//
// **A build is listed because it ships the component, not because something is
// open against it.** The presence comes from the graph and the counts are
// joined onto it, so a package carrying nothing of its own still answers with
// the version it ships and where it sits. Driven off the findings instead, a
// vendored binary whose whole risk sits underneath it — nothing on the package,
// everything in what it pulls in — answered with no builds at all, which reads
// as a name the product does not ship.
//
// **One row per version, not per build.** A build shipping a name at two
// versions holds two components, and they are two different pieces of code to
// decide about; collapsing them to the lowest version reported one of them and
// silently hid the other.
func (s *Store) AcrossBuilds(ctx context.Context, subject access.Subject, scope Scope,
	component string) ([]PerBuild, error) {

	_, visible, targets, err := s.inScope(ctx, subject, scope, &Filter{})
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(component)
	if len(targets) == 0 || name == "" {
		return nil, nil
	}

	var rows []struct {
		TargetID    int64      `bun:"target_id"`
		Stream      string     `bun:"stream"`
		Variant     string     `bun:"variant"`
		Version     string     `bun:"version"`
		Purl        string     `bun:"purl"`
		Summary     string     `bun:"summary"`
		ProjectURL  string     `bun:"project_url"`
		Supplier    string     `bun:"supplier"`
		Newest      string     `bun:"latest_version"`
		NewestAt    *time.Time `bun:"latest_released_at"`
		FirstSeen   time.Time  `bun:"first_seen_at"`
		Exploited   int        `bun:"exploited"`
		Fixable     int        `bun:"fixable"`
		Issues      int        `bun:"issues"`
		Consumers   int        `bun:"consumers"`
		Places      int        `bun:"places"`
		DueAt       *time.Time `bun:"due_at"`
		ComponentID int64      `bun:"component_id"`
	}
	// What is open against it, per build and component. A left join rather
	// than the driving table: no findings is an answer, and it is the answer
	// for every package that carries its risk underneath it rather than on
	// itself. Narrowed by visibility here, where the counts are, because the
	// presence of a component is readable to anybody who may read the build
	// while what is open against it is not.
	open := s.db.NewSelect().
		TableExpr("finding AS f").
		ColumnExpr("f.target_id AS target_id").
		ColumnExpr("f.component_id AS component_id").
		ColumnExpr("COUNT(DISTINCT f.vulnerability_id) AS issues").
		ColumnExpr("COUNT(*) AS places").
		ColumnExpr("MIN(f.due_at) AS due_at").
		ColumnExpr("MAX(CASE WHEN f.urgency_exploited THEN 1 ELSE 0 END) AS exploited").
		ColumnExpr("COUNT(DISTINCT CASE WHEN f.fixed_in IS NOT NULL AND f.fixed_in <> ''"+
			" THEN f.vulnerability_id END) AS fixable").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.target_id, f.component_id")

	// How many things pull it in, from the graph rather than from the
	// findings: it is a fact about the build, true whether or not anything is
	// open. A component nothing pulls in is contained by the build itself,
	// which counts as the one thing pulling it in.
	pullers := s.db.NewSelect().
		TableExpr("graph_edge AS e").
		Join("JOIN graph_node AS ch ON ch.id = e.child_id").
		ColumnExpr("ch.target_id AS target_id").
		ColumnExpr("ch.component_id AS component_id").
		ColumnExpr("COUNT(DISTINCT e.parent_id) AS consumers").
		Where("e.target_id IN (?)", bun.List(targets)).
		Where("e.closed_scan_id IS NULL").
		Where("e.parent_id <> e.child_id").
		GroupExpr("ch.target_id, ch.component_id")

	err = s.db.NewSelect().
		TableExpr("graph_node AS n").
		Join("JOIN component AS c ON c.id = n.component_id").
		Join("JOIN target AS tg ON tg.id = n.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN variant AS va ON va.id = tg.variant_id").
		Join(`LEFT JOIN (?) AS "op" ON "op".target_id = n.target_id AND "op".component_id = n.component_id`, open).
		Join(`LEFT JOIN (?) AS "pl" ON "pl".target_id = n.target_id AND "pl".component_id = n.component_id`, pullers).
		ColumnExpr("n.target_id AS target_id").
		ColumnExpr("n.component_id AS component_id").
		ColumnExpr("st.name AS stream").
		ColumnExpr("va.name AS variant").
		ColumnExpr("c.version AS version").
		ColumnExpr("c.purl AS purl").
		ColumnExpr("COALESCE(c.summary, '') AS summary").
		ColumnExpr("COALESCE(c.project_url, '') AS project_url").
		ColumnExpr("COALESCE(c.supplier, '') AS supplier").
		ColumnExpr("COALESCE(c.latest_version, '') AS latest_version").
		ColumnExpr("c.latest_released_at AS latest_released_at").
		ColumnExpr("c.first_seen_at AS first_seen_at").
		ColumnExpr(`COALESCE("op".exploited, 0) AS exploited`).
		ColumnExpr(`COALESCE("op".fixable, 0) AS fixable`).
		ColumnExpr(`COALESCE("op".issues, 0) AS issues`).
		ColumnExpr(`COALESCE("op".places, 0) AS places`).
		ColumnExpr(`"op".due_at AS due_at`).
		ColumnExpr(`COALESCE("pl".consumers, 1) AS consumers`).
		Where("n.target_id IN (?)", bun.List(targets)).
		Where("n.closed_scan_id IS NULL").
		Where("n.is_root = ?", false).
		Where("c.name = ?", name).
		OrderExpr("st.name, va.name, c.version").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read a component across its builds: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}

	ids := make([]int64, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ComponentID)
	}
	// Where each could go, per build: the same read the by-component view
	// takes, narrowed to these builds so a stream's answer is its own.
	upgrades, err := s.upgradesPerBuild(ctx, ids, targets, visible, name)
	if err != nil {
		return nil, err
	}
	promised, err := s.promisedPerBuild(ctx, targets, visible, name)
	if err != nil {
		return nil, err
	}
	bands, err := s.bandsPerBuild(ctx, targets, visible, name)
	if err != nil {
		return nil, err
	}

	out := make([]PerBuild, 0, len(rows))
	for _, row := range rows {
		build := PerBuild{
			TargetID: row.TargetID, Stream: row.Stream, Variant: row.Variant,
			Version: row.Version, Purl: row.Purl,
			Summary: row.Summary, ProjectURL: row.ProjectURL,
			Supplier: row.Supplier,
			Newest:   row.Newest, NewestAt: row.NewestAt, FirstSeen: row.FirstSeen,
			Exploited: row.Exploited > 0, Fixable: row.Fixable, Issues: row.Issues,
			BySeverity: bands[[2]int64{row.TargetID, row.ComponentID}],
			Consumers:  row.Consumers, Places: row.Places,
			DueAt:    row.DueAt,
			Upgrades: upgrades[[2]int64{row.TargetID, row.ComponentID}],
		}
		if said, ok := promised[[2]int64{row.TargetID, row.ComponentID}]; ok {
			build.CommittedTo, build.UpgradeTo = said.at, said.to
		}
		out = append(out, build)
	}
	return out, nil
}

// upgradesPerBuild is where a component could go, answered per build.
//
// **Grouped per version, not per string.** What a scanner records as the fix is
// one field, and some ecosystems put several versions in it — "1.25.13, 1.26.6,
// 1.27.0-rc.3" is one string naming three releases, any of which closes the
// issue. Grouped on the string, one version lands in several groups and its own
// coverage is reported nowhere.
//
// **And counted twice.** What a release fixed is what names it; what an upgrade
// to it closes is that plus everything fixed before it. The second needs the
// ecosystem's ordering and is the question somebody choosing a version asks, so
// where the ordering is unavailable the candidates carry equal counts and say
// they are unranked rather than being ranked by the first.
func (s *Store) upgradesPerBuild(ctx context.Context, ids, targets []int64,
	visible []access.Visibility, name string) (map[[2]int64][]Candidate, error) {

	var rows []struct {
		TargetID    int64  `bun:"target_id"`
		ComponentID int64  `bun:"component_id"`
		Issue       int64  `bun:"vulnerability_id"`
		FixedIn     string `bun:"fixed_in"`
		Ecosystem   string `bun:"purl"`
	}
	// One row per finding rather than a grouped count, because the grouping is
	// per version and a version has to be read out of the string first.
	err := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN component AS c ON c.id = f.component_id").
		ColumnExpr("f.target_id AS target_id").
		ColumnExpr("f.component_id AS component_id").
		ColumnExpr("f.vulnerability_id AS vulnerability_id").
		ColumnExpr("f.fixed_in AS fixed_in").
		ColumnExpr("c.purl AS purl").
		Where("f.target_id IN (?)", bun.List(targets)).
		// Narrowed to the components the rows are about, because a row is one
		// version: pooled per build, a build shipping one name at two versions
		// offers each version the other's candidates and counts.
		Where("f.component_id IN (?)", bun.List(ids)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.name = ?", name).
		Where("f.fixed_in IS NOT NULL").
		Where("f.fixed_in <> ?", "").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where a component could go in each build: %w", err)
	}

	// What each build's findings name, one entry per issue so an issue counts
	// once however many versions its fix names.
	per := map[[2]int64][]namedFix{}
	scheme := map[[2]int64]vercmp.Scheme{}
	for _, row := range rows {
		versions := versionsIn(row.FixedIn)
		if len(versions) == 0 {
			continue
		}
		at := [2]int64{row.TargetID, row.ComponentID}
		per[at] = append(per[at], namedFix{issue: row.Issue, versions: versions})
		scheme[at] = vercmp.SchemeOf(graph.EcosystemOf(row.Ecosystem))
	}

	out := make(map[[2]int64][]Candidate, len(per))
	for at, found := range per {
		out[at] = candidatesFrom(found, scheme[at])
	}
	return out, nil
}

// namedFix is one issue and every version its fix names.
type namedFix struct {
	issue    int64
	versions []string
}

// versionsIn reads the versions out of what a scanner recorded as the fix.
//
// Separated by commas, which is how the producers that name several spell it.
// Anything empty is dropped rather than becoming a candidate nobody can move to.
func versionsIn(fixedIn string) []string {
	parts := strings.Split(fixedIn, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// candidatesFrom turns what the findings name into the versions a build could
// move to, with what each release fixed and what reaching it would close.
func candidatesFrom(found []namedFix, scheme vercmp.Scheme) []Candidate {
	// Every version anybody named, in the order first seen so that an
	// unorderable set still comes back the same way twice.
	var versions []string
	seen := map[string]bool{}
	for _, one := range found {
		for _, v := range one.versions {
			if !seen[v] {
				seen[v] = true
				versions = append(versions, v)
			}
		}
	}

	// Ordered where these versions could actually be ordered, not merely where
	// the ecosystem has an ordering. A runtime published through a language
	// index and naming itself after its own toolchain has the scheme and not
	// the spelling, and one version the comparison refuses makes the whole set
	// unrankable — a list ordered except for the entry nobody could place is
	// not ordered.
	ordered := scheme != vercmp.Unordered
	for _, v := range versions {
		if _, ok := vercmp.Order(scheme, v, v); !ok {
			ordered = false
			break
		}
	}
	if !ordered {
		scheme = vercmp.Unordered
	}
	out := make([]Candidate, 0, len(versions))
	for _, candidate := range versions {
		here, reached := map[int64]bool{}, map[int64]bool{}
		for _, one := range found {
			for _, v := range one.versions {
				if v == candidate {
					here[one.issue] = true
				}
				if vercmp.Reaches(scheme, candidate, v) {
					reached[one.issue] = true
				}
			}
		}
		out = append(out, Candidate{
			To: candidate, FixedHere: len(here), Reached: len(reached), Ordered: ordered,
		})
	}

	// Furthest along first where that can be said, so the version worth taking
	// leads. Ranked on what a release fixed instead, the newest lands wherever
	// its own count happens to put it, which on a maintained line is near the
	// bottom.
	sort.SliceStable(out, func(i, j int) bool {
		if ordered {
			if cmp, ok := vercmp.Order(scheme, out[i].To, out[j].To); ok && cmp != 0 {
				return cmp > 0
			}
		}
		if out[i].Reached != out[j].Reached {
			return out[i].Reached > out[j].Reached
		}
		return out[i].To < out[j].To
	})
	return out
}

type promise struct {
	at *time.Time
	to string
}

// promisedPerBuild is what has already been committed for this component in
// each build, read off the decisions rather than a record beside them.
//
// Per version as well as per build, because a commitment is one fold moving and
// a fold is keyed on the version in hand: a build shipping one name at two
// versions has two of them, and keyed on the build alone each version reported
// the other's promise.
func (s *Store) promisedPerBuild(ctx context.Context, targets []int64,
	visible []access.Visibility, name string) (map[[2]int64]promise, error) {

	var rows []struct {
		TargetID    int64      `bun:"target_id"`
		ComponentID int64      `bun:"component_id"`
		CommittedTo *time.Time `bun:"committed_to"`
		UpgradeTo   string     `bun:"upgrade_to"`
	}
	// Through the finding, because a decision is keyed on a place and a build
	// is what a place sits in. The latest promise wins where there are
	// several: a replanned date is the one that stands.
	// A product is reached through the build rather than carried on the
	// finding, which is where the correlation everywhere else starts from.
	err := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("JOIN decision AS de ON de.product_id = st.product_id"+
			" AND de.vulnerability_id = f.vulnerability_id"+
			" AND de.place_identity = f.place_identity").
		// The argument, which is where the outcome and the promise live: one
		// act is one argument, and the rows underneath say where it lands.
		Join("JOIN claim AS cl ON cl.id = de.claim_id").
		ColumnExpr("f.target_id AS target_id").
		ColumnExpr("f.component_id AS component_id").
		ColumnExpr("MAX(cl.committed_to) AS committed_to").
		ColumnExpr("MIN(COALESCE(cl.upgrade_to, '')) AS upgrade_to").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.name = ?", name).
		Where("cl.outcome = ?", "upgrade-needed").
		Where("de.live_key IS NOT NULL").
		GroupExpr("f.target_id, f.component_id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is already promised: %w", err)
	}
	out := make(map[[2]int64]promise, len(rows))
	for _, row := range rows {
		out[[2]int64{row.TargetID, row.ComponentID}] = promise{
			at: row.CommittedTo, to: row.UpgradeTo,
		}
	}
	return out, nil
}

// bandsPerBuild is how what is open against a component was rated, per build.
//
// A count has a shape: forty issues and three criticals are different work, and
// a number with no shape beside it tells somebody deciding what to read next
// the opposite of what they need.
//
// Distinct issues, like the count beside it, so the parts sum to the whole
// rather than to the number of places.
func (s *Store) bandsPerBuild(ctx context.Context, targets []int64,
	visible []access.Visibility, name string) (map[[2]int64]map[string]int, error) {

	var rows []struct {
		TargetID    int64  `bun:"target_id"`
		ComponentID int64  `bun:"component_id"`
		Band        string `bun:"band"`
		Issues      int    `bun:"issues"`
	}
	err := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		ColumnExpr("f.target_id AS target_id").
		ColumnExpr("f.component_id AS component_id").
		ColumnExpr("COALESCE(v.severity, '') AS band").
		ColumnExpr("COUNT(DISTINCT f.vulnerability_id) AS issues").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.name = ?", name).
		GroupExpr("f.target_id, f.component_id, COALESCE(v.severity, '')").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read how what is open here was rated: %w", err)
	}
	out := map[[2]int64]map[string]int{}
	for _, row := range rows {
		// A scanner's "unknown" and no rating at all are the same state, and
		// two entries for it is two names for one nothing.
		at := [2]int64{row.TargetID, row.ComponentID}
		if out[at] == nil {
			out[at] = map[string]int{}
		}
		out[at][BandOf(row.Band)] += row.Issues
	}
	return out, nil
}
