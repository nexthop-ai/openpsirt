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
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
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

	_, visible, targets, err := s.inScope(ctx, subject, scope, &filter)
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
		WHEN COALESCE(v.assessed_severity, v.severity, '') = 'critical' THEN 4
		WHEN COALESCE(v.assessed_severity, v.severity, '') = 'high' THEN 3
		WHEN COALESCE(v.assessed_severity, v.severity, '') IN ('low', 'negligible', 'none') THEN 1
		ELSE 2 END)`

	bundled := func(q *bun.SelectQuery) *bun.SelectQuery {
		return filter.narrow(q.
			TableExpr("finding AS f").
			Join("JOIN component AS c ON c.id = f.component_id").
			Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
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
		To          string `bun:"fixed_in"`
		Issues      int    `bun:"issues"`
	}
	query := s.db.NewSelect().
		TableExpr("finding AS f").
		ColumnExpr("f.component_id AS component_id").
		ColumnExpr("f.fixed_in AS fixed_in").
		ColumnExpr("COUNT(DISTINCT f.vulnerability_id) AS issues").
		Where("f.component_id IN (?)", bun.List(ids)).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		// A finding with nothing to move to contributes no upgrade. It is not
		// absent from the view — it is a row with an empty column, which is
		// the population that needs a judgment rather than a bump.
		Where("f.fixed_in IS NOT NULL").
		Where("f.fixed_in <> ?", "").
		GroupExpr("f.component_id, f.fixed_in").
		OrderExpr("f.component_id, issues DESC, f.fixed_in")
	if err := filter.narrow(query).Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read where each component could go: %w", err)
	}
	out := make(map[int64][]Candidate, len(ids))
	for _, row := range rows {
		out[row.ComponentID] = append(out[row.ComponentID], Candidate{To: row.To, Issues: row.Issues})
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
	Version  string
	Upgrades []Candidate
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
		Issues      int        `bun:"issues"`
		Consumers   int        `bun:"consumers"`
		Direct      int        `bun:"direct"`
		Places      int        `bun:"places"`
		DueAt       *time.Time `bun:"due_at"`
		ComponentID int64      `bun:"component_id"`
	}
	err = s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN component AS c ON c.id = f.component_id").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN variant AS va ON va.id = tg.variant_id").
		ColumnExpr("f.target_id AS target_id").
		ColumnExpr("st.name AS stream").
		ColumnExpr("va.name AS variant").
		ColumnExpr("MIN(c.version) AS version").
		ColumnExpr("MIN(f.component_id) AS component_id").
		ColumnExpr("COUNT(DISTINCT f.vulnerability_id) AS issues").
		ColumnExpr("COUNT(DISTINCT f.consumer_id) AS consumers").
		// A component nothing pulls in has no consumer to count distinctly,
		// so the build itself is the one thing pulling it in.
		ColumnExpr("COALESCE(SUM(CASE WHEN f.consumer_id IS NULL THEN 1 ELSE 0 END), 0) AS direct").
		ColumnExpr("COUNT(*) AS places").
		ColumnExpr("MIN(f.due_at) AS due_at").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.name = ?", name).
		GroupExpr("f.target_id, st.name, va.name").
		OrderExpr("st.name, va.name").
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

	out := make([]PerBuild, 0, len(rows))
	for _, row := range rows {
		build := PerBuild{
			TargetID: row.TargetID, Stream: row.Stream, Variant: row.Variant,
			Version: row.Version, Issues: row.Issues,
			Consumers: pullersOf(row.Consumers, row.Direct), Places: row.Places,
			DueAt: row.DueAt, Upgrades: upgrades[row.TargetID],
		}
		if said, ok := promised[row.TargetID]; ok {
			build.CommittedTo, build.UpgradeTo = said.at, said.to
		}
		out = append(out, build)
	}
	return out, nil
}

// upgradesPerBuild is where a component could go, answered per build.
func (s *Store) upgradesPerBuild(ctx context.Context, ids, targets []int64,
	visible []access.Visibility, name string) (map[int64][]Candidate, error) {

	var rows []struct {
		TargetID int64  `bun:"target_id"`
		To       string `bun:"fixed_in"`
		Issues   int    `bun:"issues"`
	}
	err := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN component AS c ON c.id = f.component_id").
		ColumnExpr("f.target_id AS target_id").
		ColumnExpr("f.fixed_in AS fixed_in").
		ColumnExpr("COUNT(DISTINCT f.vulnerability_id) AS issues").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.name = ?", name).
		Where("f.fixed_in IS NOT NULL").
		Where("f.fixed_in <> ?", "").
		GroupExpr("f.target_id, f.fixed_in").
		OrderExpr("f.target_id, issues DESC, f.fixed_in").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where a component could go in each build: %w", err)
	}
	out := make(map[int64][]Candidate, len(targets))
	for _, row := range rows {
		out[row.TargetID] = append(out[row.TargetID], Candidate{To: row.To, Issues: row.Issues})
	}
	return out, nil
}

type promise struct {
	at *time.Time
	to string
}

// promisedPerBuild is what has already been committed for this component in
// each build, read off the decisions rather than a record beside them.
func (s *Store) promisedPerBuild(ctx context.Context, targets []int64,
	visible []access.Visibility, name string) (map[int64]promise, error) {

	var rows []struct {
		TargetID    int64      `bun:"target_id"`
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
		ColumnExpr("MAX(cl.committed_to) AS committed_to").
		ColumnExpr("MIN(COALESCE(cl.upgrade_to, '')) AS upgrade_to").
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.name = ?", name).
		Where("cl.outcome = ?", "upgrade-needed").
		Where("de.live_key IS NOT NULL").
		GroupExpr("f.target_id").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is already promised: %w", err)
	}
	out := make(map[int64]promise, len(rows))
	for _, row := range rows {
		out[row.TargetID] = promise{at: row.CommittedTo, to: row.UpgradeTo}
	}
	return out, nil
}
