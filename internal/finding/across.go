// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/vercmp"
)

// PerBuild is one build's answer about one fold: a source package at the
// version it was built at, the binary packages this build ships from it, and
// where the whole could go.
//
// A fold rather than a binary, because an upgrade is planned per source
// package: curl, libcurl4t64 and libcurl3t64 are one bump, and the page they
// are decided on is one page.
type PerBuild struct {
	TargetID int64
	Stream   string
	Variant  string
	// Source is the source package and SourceVersion the version it was built
	// at: what a producer stated, or the binary's own where it stated nothing.
	Source        string
	SourceVersion string
	// Packages are the binary packages this build ships from it, by name.
	Packages []FoldPackage
	// BySeverity is what is open across the fold by how it was rated, so a
	// count has a shape: forty issues and three criticals are different work.
	BySeverity map[string]int
	// Exploited says whether a feed reports any of them being used in the
	// world, and ExploitedHere whether this product was recorded as attacked
	// through one. The second outranks everything else about a row.
	Exploited     bool
	ExploitedHere bool
	// Fixable is how many of them any version fixes, counted once per issue.
	Fixable  int
	Upgrades []Candidate
	// Issues is how many distinct vulnerabilities are open across the fold in
	// this build, Consumers how many things outside it pull it in there, and
	// Places how many times those sit somewhere in it.
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
	// CommittedTo is what somebody has already promised for this build: the
	// version and the date. Read from the decisions rather than a record
	// beside them.
	CommittedTo *time.Time
	UpgradeTo   string
}

// FoldPackage is one binary package of a fold, as one build ships it.
type FoldPackage struct {
	Name    string
	Version string
	// Purl is the package identifier, which is where the ecosystem is read
	// from and what an upstream address is built out of.
	Purl string
	// Summary is one line saying what the package is, and ProjectURL where it
	// is developed, both as an ecosystem's index stated them.
	Summary    string
	ProjectURL string
	// Supplier and License are what the inventory said, rather than an index.
	Supplier string
	License  string
	// Newest is what the ecosystem's index says is current and when it
	// shipped, and FirstSeen when this deployment first saw the component.
	Newest    string
	NewestAt  *time.Time
	FirstSeen time.Time
	// Issues is how many distinct vulnerabilities are open against this
	// package alone, and Consumers how many things pull it in.
	Issues    int
	Consumers int
	// Stated is every version this build stated for the package, newest
	// first, where it is a container image held by its name. A package
	// carries its version in its identity, and has none.
	Stated []graph.Stated
}

// foldIn is one fold in one build.
type foldIn struct {
	target int64
	fold   string
}

// AcrossBuilds is one source package seen in every build of a product that
// ships any binary built from it.
//
// The name is matched against binary names and source names alike, without
// regard to capitals: a link from the tree names the binary somebody was
// looking at, and a person asking about a kernel names the source. Every fold
// the name reaches is answered, so a source shipped at two versions is two
// rows per build — two pieces of code, decided about separately.
//
// Per build rather than per product, because the answer differs by build: a
// stream staying on 3.0.x and a stream on 3.5.x are different work with
// different testing, and one target across both would be wrong for one of them.
//
// A build is listed because it ships the fold, not because something is open
// against it. The presence comes from the graph and the counts are joined onto
// it, so a package carrying nothing of its own still answers with the version
// it ships and where it sits.
func (s *Store) AcrossBuilds(ctx context.Context, subject access.Subject, scope Scope,
	component string) ([]PerBuild, error) {

	productID, visible, targets, err := s.inScope(ctx, subject, scope, &Filter{})
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(component)
	if len(targets) == 0 || name == "" {
		return nil, nil
	}
	folds, err := FoldsNamed(ctx, s.db, targets, name, "")
	if err != nil {
		return nil, err
	}
	if len(folds) == 0 {
		return nil, nil
	}

	held, err := s.componentsOf(ctx, folds)
	if err != nil || len(held) == 0 {
		return nil, err
	}
	packages, err := s.packagesAcross(ctx, targets, held)
	if err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, nil
	}
	open, err := s.openAcross(ctx, productID, targets, visible, held)
	if err != nil {
		return nil, err
	}
	pullers, err := s.pullersAcross(ctx, targets, folds)
	if err != nil {
		return nil, err
	}
	stated, err := graph.StatedVersions(ctx, s.db, targets, held.ids())
	if err != nil {
		return nil, err
	}

	var order []foldIn
	rows := map[foldIn]*PerBuild{}
	for _, one := range packages {
		key := foldIn{one.TargetID, one.FoldKey}
		row, held := rows[key]
		if !held {
			row = &PerBuild{
				TargetID: one.TargetID, Stream: one.Stream, Variant: one.Variant,
				Source: one.Source, SourceVersion: one.SourceVersion,
				BySeverity: open.bands[key], Upgrades: open.upgrades[key],
				// Contained by the build itself where nothing outside the fold
				// pulls it in, which counts as the one thing pulling it in.
				Consumers: max(pullers[key], 1),
			}
			if counted, ok := open.counted[key]; ok {
				row.Issues, row.Places, row.DueAt = counted.Issues, counted.Places, counted.DueAt
				row.Exploited, row.ExploitedHere = counted.Exploited > 0, counted.ExploitedHere > 0
				row.Fixable = counted.Fixable
			}
			if said, ok := open.promised[key]; ok {
				row.CommittedTo, row.UpgradeTo = said.at, said.to
			}
			rows[key] = row
			order = append(order, key)
		}
		row.Packages = append(row.Packages, FoldPackage{
			Name: one.Name, Version: one.Version, Purl: one.Purl,
			Summary: one.Summary, ProjectURL: one.ProjectURL,
			Supplier: one.Supplier, License: one.License,
			Newest: one.Newest, NewestAt: one.NewestAt, FirstSeen: one.FirstSeen,
			Issues: open.onEach[binaryIn{one.TargetID, one.ComponentID}], Consumers: one.Consumers,
			Stated: stated[graph.TargetComponent{TargetID: one.TargetID, ComponentID: one.ComponentID}],
		})
	}

	// Two versions of one source in one build are ordered by the ecosystem's
	// own ordering where the fold has one, so 9.2 lists before 10.1, and by
	// their text where it has none.
	schemes := map[string]vercmp.Scheme{}
	for _, key := range order {
		if _, ok := schemes[key.fold]; !ok {
			schemes[key.fold] = held.scheme(key.fold)
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := rows[order[i]], rows[order[j]]
		if a.Stream != b.Stream {
			return a.Stream < b.Stream
		}
		if a.Variant != b.Variant {
			return a.Variant < b.Variant
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if scheme := schemes[order[i].fold]; scheme == schemes[order[j].fold] {
			if n, ok := vercmp.Order(scheme, a.SourceVersion, b.SourceVersion); ok && n != 0 {
				return n < 0
			}
		}
		return a.SourceVersion < b.SourceVersion
	})
	out := make([]PerBuild, 0, len(order))
	for _, key := range order {
		out = append(out, *rows[key])
	}
	return out, nil
}

// FoldsNamed is the folds a name reaches in these builds, as their keys.
//
// A name reaches a fold where a live binary in one of the builds carries it
// or was built from a source carrying it, compared without regard to capitals.
// Restricted to the builds asked about, so a name shipped at one version here
// and another elsewhere answers for what these builds ship, and never for a
// component row nothing here carries. A version narrows to the folds built at
// it; empty is every version.
//
// A blank name reaches nothing. An empty string is what the source column
// holds on every component that names no source, so compared, a blank name
// would reach all of them.
//
// Read on its own, and what it names reaches each statement over the findings
// as a list of values. As a subquery, how many findings it matches is the planner's
// estimate, and on statistics that lag the table PostgreSQL estimates one and
// runs the subquery once per finding, reading every graph node of the build
// each time: the kernel's 204,000 findings in a build of 737 graph nodes take
// 22 s that way and 1.9 s as values. Statistics lag after every large scan,
// until the server's own refresh reaches the table.
func FoldsNamed(ctx context.Context, db bun.IDB, targets []int64, name, version string) ([]string, error) {
	q := foldsNamed(db, targets, name).ColumnExpr(`"cn"."fold_key"`).Distinct()
	if version = strings.TrimSpace(version); version != "" {
		q = q.Where(sourceVersionOf+" = ?", version)
	}
	var folds []string
	if err := q.OrderExpr(`"cn"."fold_key"`).Scan(ctx, &folds); err != nil {
		return nil, fmt.Errorf("read what %q names in these builds: %w", strings.TrimSpace(name), err)
	}
	return folds, nil
}

// sourceVersionOf is SourceVersion over the component joined as "cn".
var sourceVersionOf = upstreamVersionOf("cn")

func foldsNamed(db bun.IDB, targets []int64, name string) *bun.SelectQuery {
	q := db.NewSelect().
		TableExpr(`"component" AS "cn"`).
		Join(`JOIN "graph_node" AS "nn" ON "nn"."component_id" = "cn"."id"`).
		Where(`"nn"."target_id" IN (?)`, bun.List(targets)).
		Where(`"nn"."closed_scan_id" IS NULL`)
	folded := graph.Folded(strings.TrimSpace(name))
	if folded == "" {
		return q.Where("1 = 0")
	}
	return q.Where(`("cn"."name_folded" = ? OR "cn"."upstream_folded" = ?)`, folded, folded)
}

// OneFoldNamed is FoldsNamed for an act that writes: where no version was
// given and one build ships the name at two source versions, it refuses,
// naming the versions. Two versions in one build are two pieces of code,
// decided about separately, so a promise made from one is not one about both.
func OneFoldNamed(ctx context.Context, db bun.IDB, targets []int64,
	name, version string) ([]string, error) {

	if strings.TrimSpace(version) != "" {
		return FoldsNamed(ctx, db, targets, name, version)
	}
	var rows []struct {
		TargetID int64  `bun:"target_id"`
		FoldKey  string `bun:"fold_key"`
		Version  string `bun:"source_version"`
		Purl     string `bun:"purl"`
	}
	err := foldsNamed(db, targets, name).
		ColumnExpr(`"nn"."target_id" AS "target_id"`).
		ColumnExpr(`"cn"."fold_key" AS "fold_key"`).
		ColumnExpr(sourceVersionOf+` AS "source_version"`).
		ColumnExpr(`COALESCE("cn"."purl", '') AS "purl"`).
		OrderExpr(`"source_version"`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which versions of %q these builds ship: %w", name, err)
	}
	perBuild := map[int64]map[string]bool{}
	several := false
	for _, row := range rows {
		if perBuild[row.TargetID] == nil {
			perBuild[row.TargetID] = map[string]bool{}
		}
		perBuild[row.TargetID][row.FoldKey] = true
		several = several || len(perBuild[row.TargetID]) > 1
	}
	if several {
		var choices []graph.Choice
		seen := map[string]bool{}
		for _, row := range rows {
			if !seen[row.FoldKey] {
				seen[row.FoldKey] = true
				choices = append(choices, graph.ChoiceOf(row.Version, row.Purl))
			}
		}
		return nil, &graph.Ambiguous{Name: strings.TrimSpace(name), Choices: choices}
	}
	folds := make([]string, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		if !seen[row.FoldKey] {
			seen[row.FoldKey] = true
			folds = append(folds, row.FoldKey)
		}
	}
	return folds, nil
}

// heldBy is the component rows the folds hold: the fold each belongs to and
// its package identifier, by component.
type heldBy map[int64]heldRow

type heldRow struct {
	fold string
	purl string
}

// ids is the component identifiers, in order, for a statement to name as a
// list of values.
func (h heldBy) ids() []int64 {
	out := make([]int64, 0, len(h))
	for id := range h {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// folds is the folds the components belong to, in order, and an expression
// over a column holding a component's identifier that answers the fold's
// position among them, with the values it binds.
//
// A position rather than the fold key, so the places are grouped on an integer
// worked out from the row: joined to the component table for its key, the
// grouping sorts 17,866 rows of 64-character keys for the bench kernel, 204 ms
// against 175 ms.
func (h heldBy) folds(column string) ([]string, string, []any) {
	ids := h.ids()
	var folds []string
	at := map[string]int{}
	for _, id := range ids {
		if _, ok := at[h[id].fold]; !ok {
			at[h[id].fold] = len(folds)
			folds = append(folds, h[id].fold)
		}
	}
	expr := "CASE " + column + strings.Repeat(" WHEN ? THEN ?", len(ids)) + " END"
	args := make([]any, 0, 2*len(ids))
	for _, id := range ids {
		args = append(args, id, at[h[id].fold])
	}
	return folds, expr, args
}

// scheme is how the versions of a fold are ordered, read from the package
// identifier of its first component. The fold key carries the package type and
// the distribution, so every component of one fold is of one ecosystem.
func (h heldBy) scheme(fold string) vercmp.Scheme {
	for _, id := range h.ids() {
		if h[id].fold == fold {
			return vercmp.SchemeOf(graph.EcosystemOf(h[id].purl))
		}
	}
	return vercmp.Unordered
}

// componentsOf is every component row the folds hold.
//
// Read on its own and handed to each statement over the findings as a list of
// values, for the reason FoldsNamed is. Restricted through a join on the fold
// key, the findings a fold holds are the planner's estimate for an average
// component: PostgreSQL estimates the bench kernel's 322,616 open places at
// 106, sorts them on disk, and probes an index once per place. Named as
// values, the estimate comes from the statistics on those components, and the
// same places are grouped in memory.
func (s *Store) componentsOf(ctx context.Context, folds []string) (heldBy, error) {
	var rows []struct {
		ID      int64  `bun:"id"`
		FoldKey string `bun:"fold_key"`
		Purl    string `bun:"purl"`
	}
	err := s.db.NewSelect().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`"c"."id" AS "id"`).
		ColumnExpr(`"c"."fold_key" AS "fold_key"`).
		ColumnExpr(`COALESCE("c"."purl", '') AS "purl"`).
		Where(FoldedOn+" IN (?)", bun.List(folds)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read the components of a source package: %w", err)
	}
	out := make(heldBy, len(rows))
	for _, row := range rows {
		out[row.ID] = heldRow{fold: row.FoldKey, purl: row.Purl}
	}
	return out, nil
}

// packageRow is one binary package in one build, with the fold it belongs to.
type packageRow struct {
	TargetID      int64      `bun:"target_id"`
	ComponentID   int64      `bun:"component_id"`
	FoldKey       string     `bun:"fold_key"`
	Stream        string     `bun:"stream"`
	Variant       string     `bun:"variant"`
	Source        string     `bun:"source"`
	SourceVersion string     `bun:"source_version"`
	Name          string     `bun:"name"`
	Version       string     `bun:"version"`
	Purl          string     `bun:"purl"`
	Summary       string     `bun:"summary"`
	ProjectURL    string     `bun:"project_url"`
	Supplier      string     `bun:"supplier"`
	License       string     `bun:"license"`
	Newest        string     `bun:"latest_version"`
	NewestAt      *time.Time `bun:"latest_released_at"`
	FirstSeen     time.Time  `bun:"first_seen_at"`
	Consumers     int        `bun:"consumers"`
}

// packagesAcross is every binary package of the folds, per build that ships
// it.
//
// Driven off the graph rather than the findings: no findings is an answer, and
// it is the answer for every package that carries its risk underneath it. What
// is open against each is counted with the rest of what is open, where
// visibility narrows it: the presence of a component is readable to anybody
// who may read the build, while what is open against it is not.
func (s *Store) packagesAcross(ctx context.Context, targets []int64, held heldBy) ([]packageRow, error) {
	// Restricted to the fold's components before it is grouped. Grouped over
	// the whole build and joined after, it counts every component the build
	// holds to answer for a handful.
	ids := held.ids()
	pullers := s.db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Join(`JOIN "graph_node" AS "ch" ON "ch"."id" = "e"."child_id"`).
		ColumnExpr(`"ch"."target_id" AS "target_id"`).
		ColumnExpr(`"ch"."component_id" AS "component_id"`).
		ColumnExpr(`COUNT(DISTINCT "e"."parent_id") AS "consumers"`).
		Where(`"e"."target_id" IN (?)`, bun.List(targets)).
		Where(`"e"."closed_scan_id" IS NULL`).
		Where(`"e"."parent_id" <> "e"."child_id"`).
		Where(`"ch"."component_id" IN (?)`, bun.List(ids)).
		GroupExpr(`"ch"."target_id", "ch"."component_id"`)

	var rows []packageRow
	err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		Join(`JOIN "target" AS "tg" ON "tg"."id" = "n"."target_id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		Join(`LEFT JOIN (?) AS "pl" ON "pl"."target_id" = "n"."target_id" AND "pl"."component_id" = "n"."component_id"`, pullers).
		ColumnExpr(`"n"."target_id" AS "target_id"`).
		ColumnExpr(`"n"."component_id" AS "component_id"`).
		ColumnExpr(`"c"."fold_key" AS "fold_key"`).
		ColumnExpr(`"st"."name" AS "stream"`).
		ColumnExpr(`"va"."name" AS "variant"`).
		ColumnExpr(SourceName+` AS "source"`).
		ColumnExpr(SourceVersion+` AS "source_version"`).
		ColumnExpr(`"c"."name" AS "name"`).
		ColumnExpr(`"c"."version" AS "version"`).
		ColumnExpr(`COALESCE("c"."purl", '') AS "purl"`).
		ColumnExpr(`COALESCE("c"."summary", '') AS "summary"`).
		ColumnExpr(`COALESCE("c"."project_url", '') AS "project_url"`).
		ColumnExpr(`COALESCE("c"."supplier", '') AS "supplier"`).
		ColumnExpr(`COALESCE("c"."license", '') AS "license"`).
		ColumnExpr(`COALESCE("c"."latest_version", '') AS "latest_version"`).
		ColumnExpr(`"c"."latest_released_at" AS "latest_released_at"`).
		ColumnExpr(`"c"."first_seen_at" AS "first_seen_at"`).
		ColumnExpr(`COALESCE("pl"."consumers", 1) AS "consumers"`).
		Where(`"n"."target_id" IN (?)`, bun.List(targets)).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, false).
		Where(`"n"."component_id" IN (?)`, bun.List(ids)).
		OrderExpr(`"st"."name", "va"."name", "c"."name", "c"."version"`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read a source package across its builds: %w", err)
	}
	return rows, nil
}

// counted is what is open across one fold in one build.
type counted struct {
	Issues        int
	Places        int
	DueAt         *time.Time
	Exploited     int
	ExploitedHere int
	Fixable       int
}

// openFolds is what is open across each fold, per build.
type openFolds struct {
	counted map[foldIn]counted
	// bands is the distinct issues by how they were rated.
	bands    map[foldIn]map[string]int
	upgrades map[foldIn][]Candidate
	// promised is the promise that stands over the fold.
	promised map[foldIn]promise
	// onEach is the distinct issues on each binary of the fold.
	onEach map[binaryIn]int
}

// binaryIn is one component in one build.
type binaryIn struct {
	target    int64
	component int64
}

// promiseSpan separates the two parts of a promise's key: how the promise
// ranks, above it, and the claim, below it. Claim identifiers stay below it.
const promiseSpan = int64(1) << 40

// promiseRank orders the promises: one naming a version over one naming none,
// which says nothing about where to; then one with a date over one without;
// then the latest date, since a replanned date is the one that stands. Ranked
// densely, two promises alike in all three share a rank, and the later claim
// stands.
const promiseRank = `DENSE_RANK() OVER (ORDER BY` +
	` CASE WHEN COALESCE("cl"."upgrade_to", '') <> '' THEN 1 ELSE 0 END,` +
	` CASE WHEN "cl"."committed_to" IS NULL THEN 0 ELSE 1 END, "cl"."committed_to")`

// openAcross is what is open across each fold, per build: the counts, how they
// were rated, where the fold could go, and what has been promised for it.
//
// Counted over the fold rather than summed from its packages: one issue on
// three binaries is one issue. The rating bands count distinct issues too, so
// the parts sum to the whole rather than to the number of places.
//
// One pass over the places, grouped three times. The places are grouped first
// to one row per fix an issue names on each component, on identifiers and the
// fix alone; then to one row per issue in each fold; then to one row per fix,
// rating band and fold, which is what is returned. An issue is rated one way in
// a product, so it lands in one band, and the counts per band sum to the counts
// per fold. On the bench kernel, 322,616 places are 17,866 issues on a
// component and 174 rows returned.
//
// An issue whose binaries name more than one fix is returned on a row of its
// own, by identifier, and what it names is read after. Every other issue is
// counted under the one fix it names, which is all where it could go needs:
// what a release fixes and what reaching it closes are counts of issues.
//
// What has been promised rides on the same pass, as the greatest key of the
// promises on a fold's places: the promise's rank above the claim's
// identifier, so the greatest is the one that stands and names its claim.
// A decision is keyed on a place and a build is what a place sits in, so a
// promise is reached through the places. Read in a statement of its own, it
// read the bench kernel's 322,616 places a second time, 152 ms; joined here
// it adds 64 ms.
func (s *Store) openAcross(ctx context.Context, productID int64, targets []int64,
	visible []access.Visibility, held heldBy) (openFolds, error) {

	ids := held.ids()
	// The argument, which is where the outcome and the promise live: one act
	// is one argument, and the rows underneath say where it lands.
	ranked := s.db.NewSelect().
		TableExpr(`"claim" AS "cl"`).
		ColumnExpr(`"cl"."id" AS "id"`).
		ColumnExpr(promiseRank+` * ? + "cl"."id" AS "promise"`, promiseSpan).
		Where(`"cl"."outcome" = ?`, OutcomeUpgradeNeeded)
	// Every build here is in one product — the scope names it — so one bound
	// identifier is the product a decision is correlated by. One row per
	// issue and place, so a place under two promises is still one place.
	promises := s.db.NewSelect().
		TableExpr(Decisions).
		Join(`JOIN (?) AS "rk" ON "rk"."id" = "de"."claim_id"`, ranked).
		ColumnExpr(`"dv"."issue_id" AS "issue_id"`).
		ColumnExpr(`"de"."place_identity" AS "place_identity"`).
		ColumnExpr(`MAX("rk"."promise") AS "promise"`).
		Where(`"de"."product_id" = ?`, productID).
		Where(`"de"."live_key" IS NOT NULL`).
		GroupExpr(`"dv"."issue_id", "de"."place_identity"`)
	folds, foldOf, foldArgs := held.folds(`"pf"."component_id"`)
	perFix := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."target_id" AS "target_id"`).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."fixed_in" AS "fixed_in"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`MIN("f"."due_at") AS "due_at"`).
		ColumnExpr(exploitedAcross+` AS "exploited"`).
		ColumnExpr(exploitedHereAcross+` AS "exploited_here"`).
		ColumnExpr(`MAX("pd"."promise") AS "promise"`).
		Join(`LEFT JOIN (?) AS "pd" ON `+decidedPlaceIn(`"pd"."issue_id"`, `"pd"."place_identity"`, "f"), promises).
		Where(`"f"."target_id" IN (?)`, bun.List(targets)).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(`"f"."component_id" IN (?)`, bun.List(ids)).
		GroupExpr(`"f"."target_id", "f"."component_id", "f"."vulnerability_id", "f"."fixed_in"`)
	// The fix an issue names across its fold, as the lowest and the highest
	// string: equal where it names one. An empty string is no fix, and is
	// left out of both.
	perIssue := s.db.NewSelect().
		TableExpr(`(?) AS "pf"`, perFix).
		ColumnExpr(`"pf"."target_id" AS "target_id"`).
		ColumnExpr(foldOf+` AS "fold"`, foldArgs...).
		ColumnExpr(`"pf"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`SUM("pf"."places") AS "places"`).
		ColumnExpr(`MIN("pf"."due_at") AS "due_at"`).
		ColumnExpr(`MAX("pf"."exploited") AS "exploited"`).
		ColumnExpr(`MAX("pf"."exploited_here") AS "exploited_here"`).
		ColumnExpr(`MAX("pf"."promise") AS "promise"`).
		ColumnExpr(`MIN(CASE WHEN "pf"."fixed_in" <> '' THEN "pf"."fixed_in" END) AS "lo"`).
		ColumnExpr(`MAX(CASE WHEN "pf"."fixed_in" <> '' THEN "pf"."fixed_in" END) AS "hi"`).
		GroupExpr(`"pf"."target_id", `+foldOf+`, "pf"."vulnerability_id"`, foldArgs...)
	// Whether the issue is on each binary, one column per binary, so each
	// binary's own count rides the same pass. Read in a statement of its own
	// it read the places again: 47 ms on PostgreSQL and 219 ms on SQLite for
	// the kernel. Past binaryColumns the statement would carry more columns
	// than an engine takes, and the count is read on its own.
	columns, bound := ids, binaryColumns
	if s.binaryColumns > 0 {
		bound = s.binaryColumns
	}
	if len(columns) > bound {
		columns = nil
	}
	for j, id := range columns {
		perIssue = perIssue.ColumnExpr(`MAX(CASE WHEN "pf"."component_id" = ? THEN 1 END) AS ?`,
			id, bun.Ident(fmt.Sprint("on_", j)))
	}

	const (
		oneFix    = `CASE WHEN "pi"."lo" = "pi"."hi" THEN "pi"."lo" END`
		severalOf = `CASE WHEN "pi"."lo" <> "pi"."hi" THEN "pi"."vulnerability_id" END`
	)
	// Scanned a column at a time, because the columns are as many as the
	// binaries.
	var (
		targetOf      []int64
		foldAt        []int
		fixedIn       []sql.NullString
		severalOn     []sql.NullInt64
		band          []string
		issues        []int
		places        []int
		dueAt         []bun.NullTime
		exploited     []int
		exploitedHere []int
		promised      []sql.NullInt64
		onBinary      = make([][]int, len(columns))
	)
	into := []any{&targetOf, &foldAt, &fixedIn, &severalOn, &band, &issues, &places, &dueAt,
		&exploited, &exploitedHere, &promised}
	q := s.db.NewSelect().
		TableExpr(`(?) AS "pi"`, perIssue).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "pi"."vulnerability_id"`).
		// This product's rating where it has stated one. Every build here is
		// in one product — the scope names it — so one bound identifier
		// answers for all of them.
		Join(rating.Here, productID).
		ColumnExpr(`"pi"."target_id" AS "target_id"`).
		ColumnExpr(`"pi"."fold" AS "fold"`).
		ColumnExpr(oneFix + ` AS "fixed_in"`).
		ColumnExpr(severalOf + ` AS "several"`).
		ColumnExpr(rating.EffectiveExpr + ` AS "band"`).
		ColumnExpr(`COUNT(*) AS "issues"`).
		ColumnExpr(`SUM("pi"."places") AS "places"`).
		ColumnExpr(`MIN("pi"."due_at") AS "due_at"`).
		ColumnExpr(`MAX("pi"."exploited") AS "exploited"`).
		ColumnExpr(`MAX("pi"."exploited_here") AS "exploited_here"`).
		ColumnExpr(`MAX("pi"."promise") AS "promise"`)
	for j := range columns {
		column := bun.Ident(fmt.Sprint("on_", j))
		q = q.ColumnExpr(`COUNT("pi".?) AS ?`, column, column)
		into = append(into, &onBinary[j])
	}
	err := q.GroupExpr(`"pi"."target_id", "pi".fold, `+oneFix+`, `+severalOf+`, `+rating.EffectiveExpr).
		Scan(ctx, into...)
	if err != nil {
		return openFolds{}, fmt.Errorf("read what is open across a source package: %w", err)
	}

	open := map[foldIn]counted{}
	bands := map[foldIn]map[string]int{}
	fixes := map[foldIn]map[string]int{}
	several := map[foldIn]map[int64]bool{}
	standing := map[foldIn]int64{}
	onEach := map[binaryIn]int{}
	for i, target := range targetOf {
		key := foldIn{target, folds[foldAt[i]]}
		if promised[i].Valid && promised[i].Int64 > standing[key] {
			standing[key] = promised[i].Int64
		}
		sum := open[key]
		sum.Issues += issues[i]
		sum.Places += places[i]
		sum.Exploited = max(sum.Exploited, exploited[i])
		sum.ExploitedHere = max(sum.ExploitedHere, exploitedHere[i])
		if due := dueAt[i].Time; !due.IsZero() && (sum.DueAt == nil || due.Before(*sum.DueAt)) {
			sum.DueAt = &due
		}
		switch {
		case fixedIn[i].Valid:
			sum.Fixable += issues[i]
			if fixes[key] == nil {
				fixes[key] = map[string]int{}
			}
			fixes[key][fixedIn[i].String] += issues[i]
		case severalOn[i].Valid:
			sum.Fixable += issues[i]
			if several[key] == nil {
				several[key] = map[int64]bool{}
			}
			several[key][severalOn[i].Int64] = true
		}
		open[key] = sum
		// A scanner's "unknown" and no rating at all are the same state, and
		// two entries for it is two names for one nothing.
		if bands[key] == nil {
			bands[key] = map[string]int{}
		}
		bands[key][BandOf(band[i])] += issues[i]
		for j, id := range columns {
			if n := onBinary[j][i]; n > 0 {
				onEach[binaryIn{target, id}] += n
			}
		}
	}

	per := map[foldIn][]namedFix{}
	for key, named := range fixes {
		// Each fix stands for the issues counted under it, which no other
		// entry holds, so a key of its own that no issue's identifier takes.
		strs := make([]string, 0, len(named))
		for fixedIn := range named {
			strs = append(strs, fixedIn)
		}
		sort.Strings(strs)
		for i, fixedIn := range strs {
			if versions := versionsIn(fixedIn); len(versions) > 0 {
				per[key] = append(per[key], namedFix{issue: -int64(i + 1), issues: named[fixedIn], versions: versions})
			}
		}
	}
	if len(several) > 0 {
		if err := s.severalFixes(ctx, targets, visible, held, several, per); err != nil {
			return openFolds{}, err
		}
	}
	upgrades := make(map[foldIn][]Candidate, len(per))
	for key, found := range per {
		upgrades[key] = candidatesFrom(found, held.scheme(key.fold))
	}
	standingPromises, err := s.promisesNamed(ctx, standing)
	if err != nil {
		return openFolds{}, err
	}
	if columns == nil {
		if onEach, err = s.issuesOnEach(ctx, targets, visible, ids); err != nil {
			return openFolds{}, err
		}
	}
	return openFolds{counted: open, bands: bands, upgrades: upgrades, promised: standingPromises,
		onEach: onEach}, nil
}

// binaryColumns is the most binaries whose counts ride the pass over the
// places as columns of their own. PostgreSQL refuses a statement selecting
// more than 1,664 columns, and MariaDB and SQLite fail not far above that; a
// source package's binaries in one image number a handful.
const binaryColumns = 512

// issuesOnEach is the distinct issues open on each binary, per build, read in a
// statement of its own.
func (s *Store) issuesOnEach(ctx context.Context, targets []int64, visible []access.Visibility,
	ids []int64) (map[binaryIn]int, error) {

	// Grouped to one row per issue before counting, which groups in memory
	// where a distinct count over the places sorts them.
	perIssue := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."target_id" AS "target_id"`).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		Where(`"f"."target_id" IN (?)`, bun.List(targets)).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(`"f"."component_id" IN (?)`, bun.List(ids)).
		GroupExpr(`"f"."target_id", "f"."component_id", "f"."vulnerability_id"`)
	var rows []struct {
		TargetID    int64 `bun:"target_id"`
		ComponentID int64 `bun:"component_id"`
		Issues      int   `bun:"issues"`
	}
	err := s.db.NewSelect().
		TableExpr(`(?) AS "oi"`, perIssue).
		ColumnExpr(`"oi"."target_id" AS "target_id"`).
		ColumnExpr(`"oi"."component_id" AS "component_id"`).
		ColumnExpr(`COUNT(*) AS "issues"`).
		GroupExpr(`"oi"."target_id", "oi"."component_id"`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is open on each binary: %w", err)
	}
	out := make(map[binaryIn]int, len(rows))
	for _, row := range rows {
		out[binaryIn{row.TargetID, row.ComponentID}] = row.Issues
	}
	return out, nil
}

// promisesNamed is the date and the version of the promise each key names.
func (s *Store) promisesNamed(ctx context.Context, standing map[foldIn]int64) (map[foldIn]promise, error) {
	if len(standing) == 0 {
		return nil, nil
	}
	claims := make([]int64, 0, len(standing))
	for _, key := range standing {
		claims = append(claims, key%promiseSpan)
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i] < claims[j] })
	var rows []struct {
		ID          int64      `bun:"id"`
		CommittedTo *time.Time `bun:"committed_to"`
		UpgradeTo   string     `bun:"upgrade_to"`
	}
	err := s.db.NewSelect().
		TableExpr(`"claim" AS "cl"`).
		ColumnExpr(`"cl"."id" AS "id"`).
		ColumnExpr(`"cl"."committed_to" AS "committed_to"`).
		ColumnExpr(`COALESCE("cl"."upgrade_to", '') AS "upgrade_to"`).
		Where(`"cl"."id" IN (?)`, bun.List(claims)).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is already promised: %w", err)
	}
	said := make(map[int64]promise, len(rows))
	for _, row := range rows {
		said[row.ID] = promise{at: row.CommittedTo, to: row.UpgradeTo}
	}
	out := make(map[foldIn]promise, len(standing))
	for key, one := range standing {
		if claim, ok := said[one%promiseSpan]; ok {
			out[key] = claim
		}
	}
	return out, nil
}

// severalFixes adds to where each fold could go the issues whose binaries
// name more than one fix there, one entry per issue holding every version any
// of them names.
//
// Read by issue, and only where there are any: a fold's binaries are one
// source package at one version and almost always agree.
func (s *Store) severalFixes(ctx context.Context, targets []int64, visible []access.Visibility,
	held heldBy, several map[foldIn]map[int64]bool, per map[foldIn][]namedFix) error {

	var issues []int64
	asked := map[int64]bool{}
	for _, ids := range several {
		for id := range ids {
			if !asked[id] {
				asked[id] = true
				issues = append(issues, id)
			}
		}
	}
	sort.Slice(issues, func(i, j int) bool { return issues[i] < issues[j] })
	var rows []struct {
		TargetID    int64  `bun:"target_id"`
		ComponentID int64  `bun:"component_id"`
		Issue       int64  `bun:"vulnerability_id"`
		FixedIn     string `bun:"fixed_in"`
	}
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`"f"."target_id" AS "target_id"`).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."fixed_in" AS "fixed_in"`).
		Where(`"f"."target_id" IN (?)`, bun.List(targets)).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(`"f"."component_id" IN (?)`, bun.List(held.ids())).
		Where(`"f"."vulnerability_id" IN (?)`, bun.List(issues)).
		Where(`"f"."fixed_in" IS NOT NULL`).
		Where(`"f"."fixed_in" <> ?`, "").
		GroupExpr(`"f"."target_id", "f"."component_id", "f"."vulnerability_id", "f"."fixed_in"`).
		Scan(ctx, &rows)
	if err != nil {
		return fmt.Errorf("read the fixes an issue's binaries disagree about: %w", err)
	}
	type issueIn struct {
		key   foldIn
		issue int64
	}
	var order []issueIn
	named := map[issueIn][]string{}
	for _, row := range rows {
		one := issueIn{foldIn{row.TargetID, held[row.ComponentID].fold}, row.Issue}
		// The issues are read by identifier alone, so the rows include
		// builds and folds where its binaries agree, and those are counted
		// under their one fix already.
		if !several[one.key][one.issue] {
			continue
		}
		if _, seen := named[one]; !seen {
			order = append(order, one)
		}
		named[one] = append(named[one], versionsIn(row.FixedIn)...)
	}
	for _, one := range order {
		if versions := named[one]; len(versions) > 0 {
			per[one.key] = append(per[one.key], namedFix{issue: one.issue, issues: 1, versions: versions})
		}
	}
	return nil
}

// pullersAcross is how many things outside each fold pull it in, per build.
//
// From the graph rather than from the findings: it is a fact about the build,
// true whether or not anything is open. A binary of the fold pulling in another
// is the fold depending on itself, which is not somebody consuming it.
func (s *Store) pullersAcross(ctx context.Context, targets []int64,
	folds []string) (map[foldIn]int, error) {

	var rows []struct {
		TargetID  int64  `bun:"target_id"`
		FoldKey   string `bun:"fold_key"`
		Consumers int    `bun:"consumers"`
	}
	err := s.db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Join(`JOIN "graph_node" AS "ch" ON "ch"."id" = "e"."child_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "ch"."component_id"`).
		Join(`JOIN "graph_node" AS "pn" ON "pn"."id" = "e"."parent_id"`).
		Join(`JOIN "component" AS "pc" ON "pc"."id" = "pn"."component_id"`).
		ColumnExpr(`"ch"."target_id" AS "target_id"`).
		ColumnExpr(`"c"."fold_key" AS "fold_key"`).
		ColumnExpr(`COUNT(DISTINCT "e"."parent_id") AS "consumers"`).
		Where(`"e"."target_id" IN (?)`, bun.List(targets)).
		Where(`"e"."closed_scan_id" IS NULL`).
		Where(FoldedOn+" IN (?)", bun.List(folds)).
		Where(`"pc"."fold_key" <> "c"."fold_key"`).
		GroupExpr(`"ch"."target_id", "c"."fold_key"`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what pulls a source package in: %w", err)
	}
	out := make(map[foldIn]int, len(rows))
	for _, row := range rows {
		out[foldIn{row.TargetID, row.FoldKey}] = row.Consumers
	}
	return out, nil
}

// promise is what somebody committed to for a fold: the date and the version.
type promise struct {
	at *time.Time
	to string
}
