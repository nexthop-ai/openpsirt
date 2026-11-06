// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the burndown and the by-repository list cost on the full-size image
// with thirteen weeks of history: a first scan, and twelve weekly rescans each
// moving the version of some packages, which fixes their issues and replaces
// their components, dropping the issue from as many more without a move, and
// the last bringing a little back; and dismissals in force.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package finding_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// repositories is how many source repositories are hung into the image, each
// pulled in by nothing and pulling in a share of what the root does: the shape
// a SONiC inventory gives its source repositories, with every repository
// reaching a wide subtree.
const repositories = 30

func TestMeasureTheBurndownAndTheRepositoryList(t *testing.T) {
	doc := fullSizeImage(t)
	catalogSeed.Each(t, func(t *testing.T, db *database.DB, c seededCatalog) {
		f := &fixture{
			db: db, store: finding.NewStore(db.DB), graph: graph.NewStore(db.DB),
			build: c.build, productID: c.product, tag: c.tag, variant: c.variant,
			scans: ingest.NewStore(db.DB),
			scope: finding.Scope{ProductID: &c.product},
			built: time.Now().UTC().Add(-100 * 24 * time.Hour),
		}
		ctx := t.Context()
		snap := doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})
		var tops []graph.Described
		for _, d := range snap.Dependencies {
			if d.Parent == snap.Root {
				tops = append(tops, d.Child)
			}
		}
		for r := range repositories {
			repo := graph.Described{
				Purl: fmt.Sprintf("pkg:github/sonic-net/sonic-repo-%02d@%012x", r, 0xabc000+r),
				Name: fmt.Sprintf("repo-%02d", r), Version: "1.0.0",
			}
			snap.Components = append(snap.Components, repo)
			for i := r; i < len(tops); i += repositories {
				snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: repo, Child: tops[i]})
			}
			// Every fifth also ships at a second commit, over the same
			// components and the next repository's.
			if r%5 == 0 {
				again := repo
				again.Purl = fmt.Sprintf("pkg:github/sonic-net/sonic-repo-%02d@%012x", r, 0xdef000+r)
				snap.Components = append(snap.Components, again)
				for i := r; i < len(tops); i += repositories {
					snap.Dependencies = append(snap.Dependencies,
						graph.Dependency{Parent: again, Child: tops[i]},
						graph.Dependency{Parent: again, Child: tops[(i+1)%len(tops)]})
				}
			}
		}

		// Every package carries one issue and the kernel a real one's.
		var packages []graph.Described
		kernel := -1
		types := map[string]int{}
		for _, c := range snap.Components {
			if c.Purl == "" || strings.HasPrefix(c.Purl, "pkg:github/") {
				continue
			}
			types[graph.Ecosystem(c.Purl)]++
			if kernel < 0 && strings.Contains(c.Purl, "/linux-image-") {
				kernel = len(packages)
			}
			packages = append(packages, c)
		}
		if kernel < 0 {
			t.Fatal("the image carries no kernel")
		}
		t.Logf("%d packages by type %v, %d repositories over %d top-level components",
			len(packages), types, repositories, len(tops))
		gone := map[int]bool{}
		// moved is the packages whose version a rescan moved, each with what
		// it moved to.
		moved := map[int]graph.Described{}
		at := func(i int) graph.Described {
			if c, ok := moved[i]; ok {
				return c
			}
			return packages[i]
		}
		report := func(step int) []finding.Reported {
			var out []finding.Reported
			for i := range packages {
				if gone[i] && (step != 12 || i%400 != 1) {
					continue
				}
				out = append(out, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: []string{"critical", "high", "medium", "low"}[i%4]},
					Component: at(i),
				})
			}
			for k := range kernelIssues - 1 {
				if step < 6 || k%3 != 0 {
					out = append(out, finding.Reported{
						Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%05d", k), Severity: "medium"},
						Component: packages[kernel],
					})
				}
			}
			return out
		}
		// scanned is the image as a rescan describes it: each moved package
		// at its new version, wherever it appears.
		scanned := func() graph.Snapshot {
			to := map[string]graph.Described{}
			for i, c := range moved {
				to[packages[i].Purl] = c
			}
			swap := func(d graph.Described) graph.Described {
				if c, ok := to[d.Purl]; ok && d.Purl != "" {
					return c
				}
				return d
			}
			out := snap
			out.Components = make([]graph.Described, len(snap.Components))
			for i, c := range snap.Components {
				out.Components[i] = swap(c)
			}
			out.Dependencies = make([]graph.Dependency, len(snap.Dependencies))
			for i, d := range snap.Dependencies {
				out.Dependencies[i] = graph.Dependency{Parent: swap(d.Parent), Child: swap(d.Child)}
			}
			return out
		}
		for step := 0; step <= 12; step++ {
			if step > 0 {
				for i, c := range packages {
					if i%100 != step || i == kernel {
						continue
					}
					gone[i] = true
					if i%200 < 100 {
						c.Version += ".1"
						base, rest, _ := strings.Cut(c.Purl, "@")
						version, tail, found := strings.Cut(rest, "?")
						c.Purl = base + "@" + version + ".1"
						if found {
							c.Purl += "?" + tail
						}
						moved[i] = c
					}
				}
			}
			f.scannedAt(t, scanned(), ago(7*(13-step)), report(step)...)
		}
		// Fifty package issues dismissed and agreed four weeks back.
		agreed := ago(28)
		dismissedIssues := 0
		for i := 50; dismissedIssues < 50 && i < len(packages); i += 97 {
			if gone[i] || i == kernel {
				continue
			}
			f.dismissed(t, dismissal{issue: fmt.Sprintf("CVE-2026-%05d", i), proposed: ago(30), agreed: &agreed})
			dismissedIssues++
		}
		dbtest.SettleStatistics(t, db)

		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{f.productID: {access.PublicRead, access.PrivateRead}}, 0)
		const reads = 5
		timed := func(read func() error) []time.Duration {
			var took []time.Duration
			for range reads + 1 {
				start := time.Now()
				if err := read(); err != nil {
					t.Fatal(err)
				}
				took = append(took, time.Since(start))
			}
			return took[1:]
		}

		var rootID, kernelID int64
		if err := db.DB.NewSelect().TableExpr(`"graph_node" AS "n"`).ColumnExpr(`"n"."component_id"`).
			Where(`"n"."build_id" = ?`, f.build).Where(`"n"."is_root" = ?`, true).
			Where(`"n"."closed_scan_id" IS NULL`).Limit(1).Scan(ctx, &rootID); err != nil {
			t.Fatal(err)
		}
		if err := db.DB.NewSelect().TableExpr(`"component" AS "c"`).ColumnExpr(`"c"."id"`).
			Where(`"c"."purl" = ?`, packages[kernel].Purl).Limit(1).Scan(ctx, &kernelID); err != nil {
			t.Fatal(err)
		}
		build := finding.Scope{ProductID: &f.productID, BranchOrTagID: &c.branchOrTag, VariantID: &c.variant}
		// The repository the build holds as the most components.
		var widest []int64
		var widestPurl string
		seen := map[string]bool{}
		for _, c := range snap.Components {
			pkg := graph.PackageName(c.Purl)
			if !strings.HasPrefix(pkg, "pkg:github/") || seen[pkg] {
				continue
			}
			seen[pkg] = true
			starts, err := f.graph.ComponentsOf(ctx, f.build, graph.ParsePurlPrefix(pkg))
			if err != nil {
				t.Fatal(err)
			}
			if len(starts) > len(widest) {
				widest, widestPurl = starts, pkg
			}
		}
		t.Logf("the widest repository is %s, at %d components", widestPurl, len(widest))
		for _, read := range []struct {
			name   string
			scope  finding.Scope
			least  string
			within finding.Within
		}{
			{"the product", f.scope, "", finding.Within{}},
			{"the product, high and worse", f.scope, "high", finding.Within{}},
			{"the kernel by its name", f.scope, "", finding.Within{Component: packages[kernel].Name}},
			{"pkg:deb/ as a prefix", f.scope, "", finding.Within{Purl: mustPrefix(t, "pkg:deb/")}},
			{"beneath the root", build, "", finding.Within{Beneath: []int64{rootID}}},
			{"beneath the kernel", build, "", finding.Within{Beneath: []int64{kernelID}}},
			{"beneath the widest repository's every commit", build, "", finding.Within{Beneath: widest}},
			{"beneath the widest repository's first commit", build, "", finding.Within{Beneath: widest[:1]}},
		} {
			var b *finding.Burndown
			took := timed(func() (err error) {
				b, err = f.store.Burndown(ctx, who, read.scope, time.Time{}, read.least, read.within)
				return err
			})
			got := burnedOver(b)
			t.Logf("burndown of %s: %d days, %d at day 0, %d left, %d new, %d returned, %d fixed, %d dismissed; read in %v",
				read.name, len(b.Points), b.Start, got.left, got.fresh, got.returned, got.fixed, got.dismissed, took)
		}
		for name, starts := range map[string][]int64{
			"every commit": widest, "the first commit": widest[:1],
		} {
			var total int
			took := timed(func() (err error) {
				_, total, err = f.store.Groups(ctx, who, build, 50, 0, finding.Filter{Beneath: starts})
				return err
			})
			t.Logf("the list beneath the widest repository's %s: %d rows; read in %v", name, total, took)
		}
		for _, read := range []struct {
			name      string
			by        finding.GroupBy
			ecosystem string
		}{
			{"by repository", finding.ByRepository, ""},
			{"by ecosystem", finding.ByEcosystem, ""},
			{"the deb packages", finding.ByEcosystem, "deb"},
		} {
			var rows []finding.ListedGroup
			took := timed(func() (err error) {
				rows, err = f.store.Grouped(ctx, who, f.build, read.by, read.ecosystem)
				return err
			})
			open := 0
			for _, r := range rows {
				open += r.Open
			}
			t.Logf("components %s: %d rows, %d open across them; read in %v", read.name, len(rows), open, took)
		}
	})
}

func mustPrefix(t *testing.T, typed string) graph.PurlPrefix {
	t.Helper()
	p := graph.ParsePurlPrefix(typed)
	if p.Empty() {
		t.Fatalf("%s is no prefix", typed)
	}
	return p
}
