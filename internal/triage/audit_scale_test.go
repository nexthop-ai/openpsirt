// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What a full page of the decision record costs, each decision a promise
// covering one package at a different version on every release line.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package triage_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The most a page of the record holds, the releases each promise reaches, and
// the shape under each: every package at a new version in every release, three
// issues each, pulled in by four containers. A fourth of the packages carry
// their version in their name, so every release renames them.
const (
	auditPage       = 200
	auditReleases   = 24
	auditIssues     = 3
	auditContainers = 4
)

func TestMeasureAPageOfTheDecisionRecord(t *testing.T) {
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		ctx := t.Context()
		db := w.DB
		person, err := access.NewStore(db.DB).Ensure(ctx, "triager", "A triager", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		who := access.NewPerson(person.ID, "triager", false,
			map[int64][]access.Role{w.Product.ID: {
				access.PublicRead, access.PrivateRead, access.PublicTriage, access.PrivateTriage,
			}}, 0)

		at := func(p, release int) graph.Described {
			if p%4 == 0 {
				name := fmt.Sprintf("lib%d-%d.0", p, release)
				return graph.Described{Purl: "pkg:deb/debian/" + name + "@" + fmt.Sprintf("%d.0-1", release),
					Name: name, Version: fmt.Sprintf("%d.0-1", release)}
			}
			return described(fmt.Sprintf("package-%d", p), fmt.Sprintf("1.%d", release))
		}
		promised := func(p int) string {
			if p%4 == 0 {
				return at(p, auditReleases-1).Name
			}
			return fmt.Sprintf("package-%d", p)
		}

		started := time.Now()
		findings := finding.NewStore(db.DB)
		var builds []int64
		opened := 0
		for release := range auditReleases {
			line := w.DeclareBranchOrTag(w.Product, fmt.Sprintf("release-1.%d", release), catalog.Branch, nil)
			build := w.BuildFor(line, w.Customer)
			builds = append(builds, build.ID)
			root := described("sonic", fmt.Sprintf("1.%d", release))
			snap := graph.Snapshot{Root: root, Components: []graph.Described{root}}
			for h := range auditContainers {
				holder := described(fmt.Sprintf("container-%d", h), "1.0")
				snap.Components = append(snap.Components, holder)
				snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: holder})
			}
			var reported []finding.Reported
			for p := range auditPage {
				c := at(p, release)
				snap.Components = append(snap.Components, c)
				for _, holder := range snap.Components[1 : auditContainers+1] {
					snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: holder, Child: c})
				}
				for i := range auditIssues {
					reported = append(reported, finding.Reported{
						Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%d-%d", p, i), Severity: "high"},
						Component: c, FixState: finding.FixedUpstream, FixedIn: "99.0",
					})
				}
			}
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				BuildID: build.ID, ContentHash: fmt.Sprintf("audit-%d", release), BuiltAt: time.Now().UTC(),
				ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixtures.ApplyGraph(ctx, db.DB, build.ID, scan.ID, snap); err != nil {
				t.Fatal(err)
			}
			run, err := findings.Begin(ctx, finding.Run{
				BuildID: build.ID, Scanner: "measure", ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			applied, err := findings.Apply(ctx, build.ID, run.ID, reported)
			if err != nil {
				t.Fatal(err)
			}
			if err := findings.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
				t.Fatal(err)
			}
			opened += applied.Opened
		}

		store := triage.NewStore(db.DB)
		occurrences := 0
		for p := range auditPage {
			done, err := store.PlanUpgrade(ctx, who, triage.Upgrade{
				ProductID: w.Product.ID, Component: promised(p), To: "99.0",
				By: time.Now().UTC().AddDate(0, 0, 30), Builds: builds,
				Reasoning: "Measuring what a page of the record costs to read.",
			})
			if err != nil {
				t.Fatalf("promise %s: %v", promised(p), err)
			}
			occurrences += done.Occurrences
		}
		t.Logf("%d findings over %d releases, %d promises over %d occurrences, seeded in %s",
			opened, auditReleases, auditPage, occurrences, time.Since(started).Round(time.Second))
		dbtest.SettleStatistics(t, db)

		const reads = 5
		var took []time.Duration
		var page []triage.AuditedDecision
		for n := range reads + 1 {
			start := time.Now()
			if page, _, err = store.AuditDecisions(ctx, who, triage.Filter{}, time.Time{}, time.Time{},
				database.AList.Most, 0); err != nil {
				t.Fatal(err)
			}
			if n > 0 {
				took = append(took, time.Since(start))
			}
		}
		components := 0
		for _, d := range page {
			components += d.Components
		}
		t.Logf("decision record: %d decisions, %d components counted; read in %v", len(page), components, took)
	})
}
