// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
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
	packages, err := s.packagesAcross(ctx, targets, visible, held)
	if err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, nil
	}
	open, bands, err := s.openAcross(ctx, productID, targets, visible, held)
	if err != nil {
		return nil, err
	}
	pullers, err := s.pullersAcross(ctx, targets, folds)
	if err != nil {
		return nil, err
	}
	upgrades, err := s.upgradesAcross(ctx, targets, visible, held)
	if err != nil {
		return nil, err
	}
	promised, err := s.promisedAcross(ctx, productID, targets, visible, held)
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
				BySeverity: bands[key], Upgrades: upgrades[key],
				// Contained by the build itself where nothing outside the fold
				// pulls it in, which counts as the one thing pulling it in.
				Consumers: max(pullers[key], 1),
			}
			if counted, ok := open[key]; ok {
				row.Issues, row.Places, row.DueAt = counted.Issues, counted.Places, counted.DueAt
				row.Exploited, row.ExploitedHere = counted.Exploited > 0, counted.ExploitedHere > 0
				row.Fixable = counted.Fixable
			}
			if said, ok := promised[key]; ok {
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
			Issues: one.Issues, Consumers: one.Consumers,
		})
	}

	out := make([]PerBuild, 0, len(order))
	for _, key := range order {
		out = append(out, *rows[key])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Stream != out[j].Stream {
			return out[i].Stream < out[j].Stream
		}
		if out[i].Variant != out[j].Variant {
			return out[i].Variant < out[j].Variant
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].SourceVersion < out[j].SourceVersion
	})
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
	q := foldsNamed(db, targets, name).ColumnExpr("cn.fold_key").Distinct()
	if version = strings.TrimSpace(version); version != "" {
		q = q.Where(sourceVersionOf+" = ?", version)
	}
	var folds []string
	if err := q.OrderExpr("cn.fold_key").Scan(ctx, &folds); err != nil {
		return nil, fmt.Errorf("read what %q names in these builds: %w", strings.TrimSpace(name), err)
	}
	return folds, nil
}

// sourceVersionOf is SourceVersion over the component joined as "cn".
const sourceVersionOf = `CASE WHEN COALESCE(cn.upstream_version, '') <> ''
	THEN cn.upstream_version ELSE cn.version END`

func foldsNamed(db bun.IDB, targets []int64, name string) *bun.SelectQuery {
	q := db.NewSelect().
		TableExpr(`"component" AS "cn"`).
		Join(`JOIN "graph_node" AS "nn" ON nn.component_id = cn.id`).
		Where("nn.target_id IN (?)", bun.List(targets)).
		Where("nn.closed_scan_id IS NULL")
	folded := graph.Folded(strings.TrimSpace(name))
	if folded == "" {
		return q.Where("1 = 0")
	}
	return q.Where("(cn.name_folded = ? OR cn.upstream_folded = ?)", folded, folded)
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
		ColumnExpr(`nn.target_id AS "target_id"`).
		ColumnExpr(`cn.fold_key AS "fold_key"`).
		ColumnExpr(sourceVersionOf+` AS "source_version"`).
		ColumnExpr(`COALESCE(cn.purl, '') AS "purl"`).
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
		ColumnExpr(`c.id AS "id"`).
		ColumnExpr(`c.fold_key AS "fold_key"`).
		ColumnExpr(`COALESCE(c.purl, '') AS "purl"`).
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
	Issues        int        `bun:"issues"`
	Consumers     int        `bun:"consumers"`
}

// packagesAcross is every binary package of the folds, per build that ships
// it.
//
// Driven off the graph rather than the findings: no findings is an answer, and
// it is the answer for every package that carries its risk underneath it.
// Narrowed by visibility where the counts are, because the presence of a
// component is readable to anybody who may read the build while what is open
// against it is not.
func (s *Store) packagesAcross(ctx context.Context, targets []int64,
	visible []access.Visibility, held heldBy) ([]packageRow, error) {

	// Both counts are restricted to the fold's components before they are
	// grouped. Grouped over the whole build and joined after, they count
	// every component the build holds to answer for a handful.
	ids := held.ids()
	// The distinct issues on a component are its rows once grouped to one
	// per issue, which groups in memory where a distinct count over the
	// places sorts them: on the bench kernel, 80 ms where the sort of 322,616
	// places spilled to disk and took 150 ms.
	issues := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("f.component_id IN (?)", bun.List(ids)).
		GroupExpr("f.target_id, f.component_id, f.vulnerability_id")
	open := s.db.NewSelect().
		TableExpr(`(?) AS "oi"`, issues).
		ColumnExpr(`"oi".target_id AS "target_id"`).
		ColumnExpr(`"oi".component_id AS "component_id"`).
		ColumnExpr(`COUNT(*) AS "issues"`).
		GroupExpr(`"oi".target_id, "oi".component_id`)
	pullers := s.db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Join(`JOIN "graph_node" AS "ch" ON ch.id = e.child_id`).
		ColumnExpr(`ch.target_id AS "target_id"`).
		ColumnExpr(`ch.component_id AS "component_id"`).
		ColumnExpr(`COUNT(DISTINCT e.parent_id) AS "consumers"`).
		Where("e.target_id IN (?)", bun.List(targets)).
		Where("e.closed_scan_id IS NULL").
		Where("e.parent_id <> e.child_id").
		Where("ch.component_id IN (?)", bun.List(ids)).
		GroupExpr("ch.target_id, ch.component_id")

	var rows []packageRow
	err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON c.id = n.component_id`).
		Join(`JOIN "target" AS "tg" ON tg.id = n.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		Join(`LEFT JOIN (?) AS "op" ON "op".target_id = n.target_id AND "op".component_id = n.component_id`, open).
		Join(`LEFT JOIN (?) AS "pl" ON "pl".target_id = n.target_id AND "pl".component_id = n.component_id`, pullers).
		ColumnExpr(`n.target_id AS "target_id"`).
		ColumnExpr(`c.fold_key AS "fold_key"`).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`va.name AS "variant"`).
		ColumnExpr(SourceName+` AS "source"`).
		ColumnExpr(SourceVersion+` AS "source_version"`).
		ColumnExpr(`c.name AS "name"`).
		ColumnExpr(`c.version AS "version"`).
		ColumnExpr(`COALESCE(c.purl, '') AS "purl"`).
		ColumnExpr(`COALESCE(c.summary, '') AS "summary"`).
		ColumnExpr(`COALESCE(c.project_url, '') AS "project_url"`).
		ColumnExpr(`COALESCE(c.supplier, '') AS "supplier"`).
		ColumnExpr(`COALESCE(c.license, '') AS "license"`).
		ColumnExpr(`COALESCE(c.latest_version, '') AS "latest_version"`).
		ColumnExpr(`c.latest_released_at AS "latest_released_at"`).
		ColumnExpr(`c.first_seen_at AS "first_seen_at"`).
		ColumnExpr(`COALESCE("op".issues, 0) AS "issues"`).
		ColumnExpr(`COALESCE("pl".consumers, 1) AS "consumers"`).
		Where("n.target_id IN (?)", bun.List(targets)).
		Where("n.closed_scan_id IS NULL").
		Where("n.is_root = ?", false).
		Where("n.component_id IN (?)", bun.List(ids)).
		OrderExpr("st.name, va.name, c.name, c.version").
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

// openAcross is what is open across each fold, per build, and how it was
// rated.
//
// Counted over the fold rather than summed from its packages: one issue on
// three binaries is one issue. The rating bands count distinct issues too, so
// the parts sum to the whole rather than to the number of places.
//
// Grouped twice. The places are grouped first to one row per issue on each
// component, on identifiers alone; the fold, the issue's rating and the
// distinct counts are worked out over those rows. An issue is rated one way
// in a product, so each lands in one band, and the counts per band sum to the
// counts per fold. On the bench kernel, 322,616 places are 17,866 issues on a
// component, and the fold's text key and the rating are joined to those.
func (s *Store) openAcross(ctx context.Context, productID int64, targets []int64,
	visible []access.Visibility, held heldBy) (map[foldIn]counted, map[foldIn]map[string]int, error) {

	perIssue := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`MIN(f.due_at) AS "due_at"`).
		ColumnExpr(exploitedAcross+` AS "exploited"`).
		ColumnExpr(exploitedHereAcross+` AS "exploited_here"`).
		ColumnExpr("MAX(CASE WHEN f.fixed_in IS NOT NULL AND f.fixed_in <> ''"+
			` THEN 1 ELSE 0 END) AS "fixable"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("f.component_id IN (?)", bun.List(held.ids())).
		GroupExpr("f.target_id, f.component_id, f.vulnerability_id")

	var rows []struct {
		TargetID      int64      `bun:"target_id"`
		FoldKey       string     `bun:"fold_key"`
		Band          string     `bun:"band"`
		Issues        int        `bun:"issues"`
		Places        int        `bun:"places"`
		DueAt         *time.Time `bun:"due_at"`
		Exploited     int        `bun:"exploited"`
		ExploitedHere int        `bun:"exploited_here"`
		Fixable       int        `bun:"fixable"`
	}
	err := s.db.NewSelect().
		TableExpr(`(?) AS "pi"`, perIssue).
		Join(`JOIN "component" AS "c" ON c.id = "pi".component_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = "pi".vulnerability_id`).
		// This product's rating where it has stated one. Every build here is
		// in one product — the scope names it — so one bound identifier
		// answers for all of them.
		Join(rating.Here, productID).
		ColumnExpr(`"pi".target_id AS "target_id"`).
		ColumnExpr(`c.fold_key AS "fold_key"`).
		ColumnExpr(rating.EffectiveExpr+` AS "band"`).
		ColumnExpr(`COUNT(DISTINCT "pi".vulnerability_id) AS "issues"`).
		ColumnExpr(`SUM("pi".places) AS "places"`).
		ColumnExpr(`MIN("pi".due_at) AS "due_at"`).
		ColumnExpr(`MAX("pi".exploited) AS "exploited"`).
		ColumnExpr(`MAX("pi".exploited_here) AS "exploited_here"`).
		ColumnExpr(`COUNT(DISTINCT CASE WHEN "pi".fixable = 1 THEN "pi".vulnerability_id END) AS "fixable"`).
		GroupExpr(`"pi".target_id, c.fold_key, `+rating.EffectiveExpr).
		Scan(ctx, &rows)
	if err != nil {
		return nil, nil, fmt.Errorf("read what is open across a source package: %w", err)
	}
	open := make(map[foldIn]counted, len(rows))
	bands := map[foldIn]map[string]int{}
	for _, row := range rows {
		key := foldIn{row.TargetID, row.FoldKey}
		sum := open[key]
		sum.Issues += row.Issues
		sum.Places += row.Places
		sum.Fixable += row.Fixable
		sum.Exploited = max(sum.Exploited, row.Exploited)
		sum.ExploitedHere = max(sum.ExploitedHere, row.ExploitedHere)
		if row.DueAt != nil && (sum.DueAt == nil || row.DueAt.Before(*sum.DueAt)) {
			sum.DueAt = row.DueAt
		}
		open[key] = sum
		// A scanner's "unknown" and no rating at all are the same state, and
		// two entries for it is two names for one nothing.
		if bands[key] == nil {
			bands[key] = map[string]int{}
		}
		bands[key][BandOf(row.Band)] += row.Issues
	}
	return open, bands, nil
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
		Join(`JOIN "graph_node" AS "ch" ON ch.id = e.child_id`).
		Join(`JOIN "component" AS "c" ON c.id = ch.component_id`).
		Join(`JOIN "graph_node" AS "pn" ON pn.id = e.parent_id`).
		Join(`JOIN "component" AS "pc" ON pc.id = pn.component_id`).
		ColumnExpr(`ch.target_id AS "target_id"`).
		ColumnExpr(`c.fold_key AS "fold_key"`).
		ColumnExpr(`COUNT(DISTINCT e.parent_id) AS "consumers"`).
		Where("e.target_id IN (?)", bun.List(targets)).
		Where("e.closed_scan_id IS NULL").
		Where(FoldedOn+" IN (?)", bun.List(folds)).
		Where("pc.fold_key <> c.fold_key").
		GroupExpr("ch.target_id, c.fold_key").
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

// upgradesAcross is where each fold could go, answered per build.
//
// Grouped per version, not per string. What a scanner records as the fix is
// one field, and some ecosystems put several versions in it — "1.25.13, 1.26.6,
// 1.27.0-rc.3" is one string naming three releases, any of which closes the
// issue. Grouped on the string, one version lands in several groups and its own
// coverage is reported nowhere.
//
// And counted twice. What a release fixed is what names it; what an upgrade
// to it closes is that plus everything fixed before it. The second needs the
// ecosystem's ordering and is the question somebody choosing a version asks, so
// where the ordering is unavailable the candidates carry equal counts and say
// they are unranked rather than being ranked by the first.
func (s *Store) upgradesAcross(ctx context.Context, targets []int64,
	visible []access.Visibility, held heldBy) (map[foldIn][]Candidate, error) {

	var rows []struct {
		TargetID    int64  `bun:"target_id"`
		ComponentID int64  `bun:"component_id"`
		Issue       int64  `bun:"vulnerability_id"`
		FixedIn     string `bun:"fixed_in"`
	}
	// One row per issue and fix on each component rather than a grouped
	// count, because the grouping is per version and a version has to be read
	// out of the string first. An issue on several binaries of the fold counts
	// once, because the candidates count issues rather than rows. The fold and
	// the ecosystem are the component's, already read, so each row carries
	// identifiers and the string alone: on the bench kernel that is 13,938
	// rows where one per place was 274,068, each carrying the fold key and
	// the package identifier, and 5 s on a 100 Mbit link.
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.fixed_in AS "fixed_in"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("f.component_id IN (?)", bun.List(held.ids())).
		Where("f.fixed_in IS NOT NULL").
		Where("f.fixed_in <> ?", "").
		GroupExpr("f.target_id, f.component_id, f.vulnerability_id, f.fixed_in").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read where a source package could go in each build: %w", err)
	}

	per := map[foldIn][]namedFix{}
	scheme := map[foldIn]vercmp.Scheme{}
	for _, row := range rows {
		versions := versionsIn(row.FixedIn)
		if len(versions) == 0 {
			continue
		}
		component := held[row.ComponentID]
		key := foldIn{row.TargetID, component.fold}
		per[key] = append(per[key], namedFix{issue: row.Issue, versions: versions})
		scheme[key] = vercmp.SchemeOf(graph.EcosystemOf(component.purl))
	}
	out := make(map[foldIn][]Candidate, len(per))
	for key, found := range per {
		out[key] = candidatesFrom(found, scheme[key])
	}
	return out, nil
}

type promise struct {
	at *time.Time
	to string
}

// promisedAcross is what has already been committed for each fold in each
// build, read off the decisions rather than a record beside them.
func (s *Store) promisedAcross(ctx context.Context, productID int64, targets []int64,
	visible []access.Visibility, held heldBy) (map[foldIn]promise, error) {

	var rows []struct {
		TargetID    int64      `bun:"target_id"`
		ComponentID int64      `bun:"component_id"`
		ClaimID     int64      `bun:"claim_id"`
		CommittedTo *time.Time `bun:"committed_to"`
		UpgradeTo   string     `bun:"upgrade_to"`
	}
	// Through the finding, because a decision is keyed on a place and a build
	// is what a place sits in. Every build here is in one product — the scope
	// names it — so one bound identifier is the product a decision is
	// correlated by. One row per promise on each component, so the date and
	// the version reported come from the same one, and the fold is the
	// component's, already read.
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN (`+Decisions+`) ON `+DecisionAt("?"), productID).
		// The argument, which is where the outcome and the promise live: one
		// act is one argument, and the rows underneath say where it lands.
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`cl.id AS "claim_id"`).
		ColumnExpr(`cl.committed_to AS "committed_to"`).
		ColumnExpr(`COALESCE(cl.upgrade_to, '') AS "upgrade_to"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("f.component_id IN (?)", bun.List(held.ids())).
		Where("cl.outcome = ?", "upgrade-needed").
		Where("de.live_key IS NOT NULL").
		GroupExpr("f.target_id, f.component_id, cl.id, cl.committed_to, cl.upgrade_to").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is already promised: %w", err)
	}
	// One promise stands where there are several. A promise naming a version
	// stands over one naming none, which says nothing about where to; then the
	// latest date, since a replanned date is the one that stands; then the
	// later claim.
	type standing struct {
		promise
		claim int64
	}
	best := make(map[foldIn]standing, len(rows))
	later := func(a, b standing) bool {
		if (a.to != "") != (b.to != "") {
			return a.to != ""
		}
		switch {
		case a.at == nil && b.at != nil:
			return false
		case a.at != nil && b.at == nil:
			return true
		case a.at != nil && !a.at.Equal(*b.at):
			return a.at.After(*b.at)
		}
		return a.claim > b.claim
	}
	for _, row := range rows {
		key := foldIn{row.TargetID, held[row.ComponentID].fold}
		one := standing{promise{at: row.CommittedTo, to: row.UpgradeTo}, row.ClaimID}
		if held, ok := best[key]; !ok || later(one, held) {
			best[key] = one
		}
	}
	out := make(map[foldIn]promise, len(best))
	for key, one := range best {
		out[key] = one.promise
	}
	return out, nil
}
