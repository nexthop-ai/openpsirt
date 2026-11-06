// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the burndown and the by-repository list cost on the full-size image
// with thirteen weeks of history: a first scan, twelve weekly rescans fixing
// some of it and bringing a little back, and dismissals in force.
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
	catalogSeed.Two(t, func(t *testing.T, db *database.DB, c seededCatalog) {
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
		report := func(step int) []finding.Reported {
			var out []finding.Reported
			for i, c := range packages {
				if gone[i] && !(step == 12 && i%400 == 1) {
					continue
				}
				out = append(out, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: []string{"critical", "high", "medium", "low"}[i%4]},
					Component: c,
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
		for step := 0; step <= 12; step++ {
			if step > 0 {
				for i := range packages {
					if i%100 == step {
						gone[i] = true
					}
				}
			}
			f.scannedAt(t, snap, ago(7*(13-step)), report(step)...)
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
			{"beneath the root", build, "", finding.Within{Beneath: &rootID}},
			{"beneath the kernel", build, "", finding.Within{Beneath: &kernelID}},
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
