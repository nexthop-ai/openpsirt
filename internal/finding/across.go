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
	folds := FoldsNamed(s.db, targets, name)

	packages, err := s.packagesAcross(ctx, targets, visible, folds)
	if err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, nil
	}
	open, err := s.openAcross(ctx, targets, visible, folds)
	if err != nil {
		return nil, err
	}
	pullers, err := s.pullersAcross(ctx, targets, folds)
	if err != nil {
		return nil, err
	}
	upgrades, err := s.upgradesAcross(ctx, targets, visible, folds)
	if err != nil {
		return nil, err
	}
	promised, err := s.promisedAcross(ctx, targets, visible, folds)
	if err != nil {
		return nil, err
	}
	bands, err := s.bandsAcross(ctx, productID, targets, visible, folds)
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

// FoldsNamed is the folds a name reaches in these builds, as a subquery
// returning fold keys.
//
// A name reaches a fold where a live binary in one of the builds carries it
// or was built from a source carrying it, compared without regard to capitals.
// Restricted to the builds asked about, so a name shipped at one version here
// and another elsewhere answers for what these builds ship, and never for a
// component row nothing here carries.
func FoldsNamed(db bun.IDB, targets []int64, name string) *bun.SelectQuery {
	folded := graph.Folded(strings.TrimSpace(name))
	return db.NewSelect().
		TableExpr(`"component" AS "cn"`).
		Join(`JOIN "graph_node" AS "nn" ON nn.component_id = cn.id`).
		ColumnExpr("cn.fold_key").
		Where("nn.target_id IN (?)", bun.List(targets)).
		Where("nn.closed_scan_id IS NULL").
		Where("(cn.name_folded = ? OR cn.upstream_folded = ?)", folded, folded)
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
	visible []access.Visibility, folds *bun.SelectQuery) ([]packageRow, error) {

	open := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		ColumnExpr(`COUNT(DISTINCT f.vulnerability_id) AS "issues"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		GroupExpr("f.target_id, f.component_id")
	pullers := s.db.NewSelect().
		TableExpr(`"graph_edge" AS "e"`).
		Join(`JOIN "graph_node" AS "ch" ON ch.id = e.child_id`).
		ColumnExpr(`ch.target_id AS "target_id"`).
		ColumnExpr(`ch.component_id AS "component_id"`).
		ColumnExpr(`COUNT(DISTINCT e.parent_id) AS "consumers"`).
		Where("e.target_id IN (?)", bun.List(targets)).
		Where("e.closed_scan_id IS NULL").
		Where("e.parent_id <> e.child_id").
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
		Where("c.fold_key IN (?)", folds).
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

// openAcross is what is open across each fold, per build.
//
// Counted over the fold rather than summed from its packages: one issue on
// three binaries is one issue.
func (s *Store) openAcross(ctx context.Context, targets []int64,
	visible []access.Visibility, folds *bun.SelectQuery) (map[foldIn]counted, error) {

	var rows []struct {
		TargetID      int64      `bun:"target_id"`
		FoldKey       string     `bun:"fold_key"`
		Issues        int        `bun:"issues"`
		Places        int        `bun:"places"`
		DueAt         *time.Time `bun:"due_at"`
		Exploited     int        `bun:"exploited"`
		ExploitedHere int        `bun:"exploited_here"`
		Fixable       int        `bun:"fixable"`
	}
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`c.fold_key AS "fold_key"`).
		ColumnExpr(`COUNT(DISTINCT f.vulnerability_id) AS "issues"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		ColumnExpr(`MIN(f.due_at) AS "due_at"`).
		ColumnExpr(exploitedAcross+` AS "exploited"`).
		ColumnExpr(exploitedHereAcross+` AS "exploited_here"`).
		ColumnExpr("COUNT(DISTINCT CASE WHEN f.fixed_in IS NOT NULL AND f.fixed_in <> ''"+
			` THEN f.vulnerability_id END) AS "fixable"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.fold_key IN (?)", folds).
		GroupExpr("f.target_id, c.fold_key").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is open across a source package: %w", err)
	}
	out := make(map[foldIn]counted, len(rows))
	for _, row := range rows {
		out[foldIn{row.TargetID, row.FoldKey}] = counted{
			Issues: row.Issues, Places: row.Places, DueAt: row.DueAt,
			Exploited: row.Exploited, ExploitedHere: row.ExploitedHere, Fixable: row.Fixable,
		}
	}
	return out, nil
}

// pullersAcross is how many things outside each fold pull it in, per build.
//
// From the graph rather than from the findings: it is a fact about the build,
// true whether or not anything is open. A binary of the fold pulling in another
// is the fold depending on itself, which is not somebody consuming it.
func (s *Store) pullersAcross(ctx context.Context, targets []int64,
	folds *bun.SelectQuery) (map[foldIn]int, error) {

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
		Where("c.fold_key IN (?)", folds).
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
	visible []access.Visibility, folds *bun.SelectQuery) (map[foldIn][]Candidate, error) {

	var rows []struct {
		TargetID int64  `bun:"target_id"`
		FoldKey  string `bun:"fold_key"`
		Issue    int64  `bun:"vulnerability_id"`
		FixedIn  string `bun:"fixed_in"`
		Purl     string `bun:"purl"`
	}
	// One row per finding rather than a grouped count, because the grouping is
	// per version and a version has to be read out of the string first. An
	// issue on several binaries of the fold counts once, because the candidates
	// count issues rather than rows.
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`c.fold_key AS "fold_key"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.fixed_in AS "fixed_in"`).
		ColumnExpr(`COALESCE(c.purl, '') AS "purl"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.fold_key IN (?)", folds).
		Where("f.fixed_in IS NOT NULL").
		Where("f.fixed_in <> ?", "").
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
		key := foldIn{row.TargetID, row.FoldKey}
		per[key] = append(per[key], namedFix{issue: row.Issue, versions: versions})
		scheme[key] = vercmp.SchemeOf(graph.EcosystemOf(row.Purl))
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
func (s *Store) promisedAcross(ctx context.Context, targets []int64,
	visible []access.Visibility, folds *bun.SelectQuery) (map[foldIn]promise, error) {

	var rows []struct {
		TargetID    int64      `bun:"target_id"`
		FoldKey     string     `bun:"fold_key"`
		CommittedTo *time.Time `bun:"committed_to"`
		UpgradeTo   string     `bun:"upgrade_to"`
	}
	// Through the finding, because a decision is keyed on a place and a build
	// is what a place sits in. The latest promise wins where there are
	// several: a replanned date is the one that stands. A product is reached
	// through the build rather than carried on the finding, which is where the
	// correlation everywhere else starts from.
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`JOIN "decision" AS "de" ON de.product_id = st.product_id`+
			" AND de.vulnerability_id = f.vulnerability_id"+
			" AND de.place_identity = f.place_identity").
		// The argument, which is where the outcome and the promise live: one
		// act is one argument, and the rows underneath say where it lands.
		Join(`JOIN "claim" AS "cl" ON cl.id = de.claim_id`).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`c.fold_key AS "fold_key"`).
		ColumnExpr(`MAX(cl.committed_to) AS "committed_to"`).
		ColumnExpr(`MIN(COALESCE(cl.upgrade_to, '')) AS "upgrade_to"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.fold_key IN (?)", folds).
		Where("cl.outcome = ?", "upgrade-needed").
		Where("de.live_key IS NOT NULL").
		GroupExpr("f.target_id, c.fold_key").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what is already promised: %w", err)
	}
	out := make(map[foldIn]promise, len(rows))
	for _, row := range rows {
		out[foldIn{row.TargetID, row.FoldKey}] = promise{at: row.CommittedTo, to: row.UpgradeTo}
	}
	return out, nil
}

// bandsAcross is how what is open across each fold was rated, per build.
//
// Distinct issues, like the count beside it, so the parts sum to the whole
// rather than to the number of places.
func (s *Store) bandsAcross(ctx context.Context, productID int64, targets []int64,
	visible []access.Visibility, folds *bun.SelectQuery) (map[foldIn]map[string]int, error) {

	var rows []struct {
		TargetID int64  `bun:"target_id"`
		FoldKey  string `bun:"fold_key"`
		Band     string `bun:"band"`
		Issues   int    `bun:"issues"`
	}
	err := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		// This product's rating where it has stated one. Every build here is
		// in one product — the scope names it — so one bound identifier
		// answers for all of them.
		Join(rating.Here, productID).
		ColumnExpr(`f.target_id AS "target_id"`).
		ColumnExpr(`c.fold_key AS "fold_key"`).
		ColumnExpr(rating.EffectiveExpr+` AS "band"`).
		ColumnExpr(`COUNT(DISTINCT f.vulnerability_id) AS "issues"`).
		Where("f.target_id IN (?)", bun.List(targets)).
		Where("f.closed_at IS NULL").
		Where("f.visibility IN (?)", bun.List(visible)).
		Where("c.fold_key IN (?)", folds).
		GroupExpr("f.target_id, c.fold_key, "+rating.EffectiveExpr).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read how what is open here was rated: %w", err)
	}
	out := map[foldIn]map[string]int{}
	for _, row := range rows {
		// A scanner's "unknown" and no rating at all are the same state, and
		// two entries for it is two names for one nothing.
		key := foldIn{row.TargetID, row.FoldKey}
		if out[key] == nil {
			out[key] = map[string]int{}
		}
		out[key][BandOf(row.Band)] += row.Issues
	}
	return out, nil
}
