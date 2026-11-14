// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// GroupBy is how a build's components are listed instead of as a tree.
type GroupBy string

const (
	// ByRepository is one row per source repository a package identifier of
	// type github names, counting what is at its components and beneath them.
	ByRepository GroupBy = "repository"
	// ByEcosystem is one row per package identifier type, counting what is at
	// its components; asked for one ecosystem, one row per package in it.
	ByEcosystem GroupBy = "ecosystem"
)

// GroupedBy is every way a build's components are grouped.
func GroupedBy() []GroupBy { return []GroupBy{ByRepository, ByEcosystem} }

// NoEcosystem is the ecosystem word for components with no package identifier.
const NoEcosystem = "none"

// ListedGroup is one row of a build's components listed by repository, ecosystem or
// package. Grouping is presentation (REQ-17): each count is of issues at
// components in the trend's unit, worked out from the findings beneath.
type ListedGroup struct {
	// Key is the repository's or package's identifier with the version cut,
	// or the ecosystem word.
	Key string
	// Versions is what the build ships of the group's components now, as
	// their identifiers state it, at most mostVersions: a repository's
	// commits, a package's versions.
	Versions []string
	// Components is how many of the build's components the group holds now.
	Components int
	// Open is issues at components open in the build; Fixed is those left by
	// a fix with nothing of them open in the build now.
	Open, Fixed    int
	OpenBySeverity map[string]int
	// One is the group's component where it holds exactly one, named in the
	// four parts a component reference takes, so a row links beneath it.
	One *graph.Parts
}

// mostVersions is how many shipped versions a row names.
const mostVersions = 5

// Grouped lists a build's components by repository or by ecosystem, or the
// packages of one ecosystem, most open first, counted with what the subject
// may read in the build's product.
//
// A repository counts what is at its components and everything beneath them,
// the walk the tree and the burndown take. An ecosystem and a package count
// what is at their own components. A finding on a version a rescan replaced
// counts where the build's present version of its name is.
func (s *Store) Grouped(ctx context.Context, subject access.Subject, buildID int64, by GroupBy,
	ecosystem string) ([]ListedGroup, error) {

	var productID int64
	if err := s.db.NewSelect().TableExpr(`"build" AS "tg"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`"st"."product_id"`).Where(`"tg"."id" = ?`, buildID).
		Scan(ctx, &productID); err != nil {
		return nil, fmt.Errorf("read the product of build %d: %w", buildID, err)
	}
	visible, err := access.Readable(subject, productID)
	if err != nil {
		return nil, err
	}
	if by != ByRepository && by != ByEcosystem {
		return nil, refusal.Errorf("components are grouped by repository or by ecosystem, not %q", by)
	}

	var live []struct {
		ID      int64  `bun:"id"`
		Name    string `bun:"name"`
		Version string `bun:"version"`
		Purl    string `bun:"purl"`
	}
	if err := s.db.NewSelect().TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		ColumnExpr(`"c"."id", `+graph.NodeName("n", "c")+` AS "name", `+graph.NodeVersion("n", "c")+
			` AS "version", COALESCE("c"."purl", '') AS "purl"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, false).
		Scan(ctx, &live); err != nil {
		return nil, fmt.Errorf("read what build %d holds: %w", buildID, err)
	}

	type held struct {
		group    *ListedGroup
		members  []int64
		versions map[string]bool
	}
	groups := map[string]*held{}
	var order []string
	for _, c := range live {
		parts := graph.PartsOfPurl(c.Purl)
		var key string
		switch {
		case by == ByRepository:
			if parts.Type != "github" {
				continue
			}
			key = graph.PackageName(c.Purl)
		case ecosystem == "":
			key = parts.Type
			if key == "" {
				key = NoEcosystem
			}
		default:
			mine := parts.Type
			if mine == "" {
				mine = NoEcosystem
			}
			if !strings.EqualFold(mine, ecosystem) {
				continue
			}
			key = graph.PackageName(c.Purl)
			if key == "" {
				key = c.Name
			}
		}
		one, ok := groups[key]
		if !ok {
			one = &held{group: &ListedGroup{Key: key, OpenBySeverity: map[string]int{}}, versions: map[string]bool{}}
			groups[key] = one
			order = append(order, key)
		}
		one.members = append(one.members, c.ID)
		one.group.Components++
		// What the identifier states, where it states one: a source
		// repository's commit is there, beside a version its producer made up.
		shipped := c.Version
		if _, stated := graph.PackageOf(c.Purl); stated != "" {
			shipped = stated
		}
		if shipped != "" && !one.versions[shipped] {
			one.versions[shipped] = true
			one.group.Versions = append(one.group.Versions, shipped)
		}
		if one.group.Components == 1 {
			p := graph.Parts{Type: parts.Type, Namespace: parts.Namespace, Name: c.Name, Version: c.Version}
			one.group.One = &p
		} else {
			one.group.One = nil
		}
	}
	if len(groups) == 0 {
		return nil, nil
	}

	// What each group counts: its own components, or for a repository
	// everything beneath them too, and the replaced versions of those names.
	counted := map[string][]int64{}
	if by == ByRepository {
		var starts []int64
		for _, key := range order {
			starts = append(starts, groups[key].members...)
		}
		reached, err := graph.Reaching(ctx, s.db, buildID, starts)
		if err != nil {
			return nil, err
		}
		for _, key := range order {
			seen := map[int64]bool{}
			for _, m := range groups[key].members {
				for _, r := range reached[m] {
					if !seen[r] {
						seen[r] = true
						counted[key] = append(counted[key], r)
					}
				}
			}
		}
	} else {
		for _, key := range order {
			counted[key] = groups[key].members
		}
	}
	replaced, err := graph.Replaced(ctx, s.db, buildID)
	if err != nil {
		return nil, err
	}
	for _, key := range order {
		counted[key] = append(counted[key], graph.ReplacedAmong(replaced, counted[key])...)
	}

	var all []int64
	seen := map[int64]bool{}
	for _, ids := range counted {
		for _, id := range ids {
			if !seen[id] {
				seen[id] = true
				all = append(all, id)
			}
		}
	}
	type issueAt struct {
		ComponentID     int64  `bun:"component_id"`
		VulnerabilityID int64  `bun:"vulnerability_id"`
		Name            string `bun:"name_folded"`
		Open            int    `bun:"open"`
		Resolved        int    `bun:"resolved"`
		Band            string `bun:"band"`
	}
	on := map[int64][]issueAt{}
	kinds, kindArgs := kind.Statistics.Where(`"f"."kind"`)
	for start := 0; start < len(all); start += database.BatchSize {
		chunk := all[start:min(start+database.BatchSize, len(all))]
		var read []issueAt
		grouped := s.db.NewSelect().TableExpr(`"finding" AS "f"`).
			ColumnExpr(`"f"."component_id" AS "component_id"`).
			ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
			ColumnExpr(`MAX(CASE WHEN "f"."closed_at" IS NULL THEN 1 ELSE 0 END) AS "open"`).
			ColumnExpr(`MAX(CASE WHEN "f"."closed_because" IN (?) THEN 1 ELSE 0 END) AS "resolved"`,
				bun.List(Resolving())).
			Where(`"f"."build_id" = ?`, buildID).
			Where(`"f"."visibility" IN (?)`, bun.List(visible)).
			Where(kinds, kindArgs...).
			Where(`COALESCE("f"."closed_because", '') NOT IN (?)`, bun.List(NeverPresent())).
			Where(wasOpen).
			Where(`"f"."component_id" IN (?)`, bun.List(chunk)).
			GroupExpr(`"f"."component_id", "f"."vulnerability_id"`)
		if err := s.db.NewSelect().TableExpr(`(?) AS "g"`, grouped).
			Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "g"."vulnerability_id"`).
			Join(`JOIN "component" AS "c" ON "c"."id" = "g"."component_id"`).
			Join(rating.Here, productID).
			ColumnExpr(`"g"."component_id", "g"."vulnerability_id", "c"."name_folded", "g"."open", "g"."resolved"`).
			ColumnExpr(rating.BandExpr+` AS "band"`).
			Scan(ctx, &read); err != nil {
			return nil, fmt.Errorf("read what is open and fixed in each group: %w", err)
		}
		for _, r := range read {
			on[r.ComponentID] = append(on[r.ComponentID], r)
		}
	}

	out := make([]ListedGroup, 0, len(order))
	for _, key := range order {
		type identity struct {
			issue int64
			name  string
		}
		open := map[identity]string{}
		resolved := map[identity]bool{}
		for _, id := range counted[key] {
			for _, r := range on[id] {
				at := identity{r.VulnerabilityID, r.Name}
				if r.Open == 1 {
					if was, ok := open[at]; !ok || Ranks(r.Band) > Ranks(was) {
						open[at] = r.Band
					}
				}
				if r.Resolved == 1 {
					resolved[at] = true
				}
			}
		}
		g := groups[key].group
		g.Open = len(open)
		for _, band := range open {
			g.OpenBySeverity[band]++
		}
		for at := range resolved {
			if _, still := open[at]; !still {
				g.Fixed++
			}
		}
		slices.Sort(g.Versions)
		if len(g.Versions) > mostVersions {
			g.Versions = g.Versions[:mostVersions]
		}
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b ListedGroup) int {
		if a.Open != b.Open {
			return b.Open - a.Open
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out, nil
}
