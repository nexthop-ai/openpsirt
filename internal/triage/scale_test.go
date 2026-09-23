// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// The cost of an unbounded bulk promise, measured rather than assumed.
//
// A bulk judgment is bounded and a promise to upgrade is not, because the next
// scan re-checks every row a promise names. Removing the bound moves the
// question from "will this be refused" to "will this commit", and the answer
// is a property of four database engines rather than of this code — so it is
// measured on all four, on real servers, and the numbers are written down.
//
// It times the act that lost its bound, not a neighbour of it: PlanUpgrade
// resolves every place on a component inside the transaction, folds them,
// writes a claim, a decision per place and the fix targets. A measurement of
// the bulk judgment path would describe a different transaction, and the whole
// point of keeping a number beside a decision is that somebody can re-run it in
// two years and get an answer to the same question.
//
// Behind a build tag because it is a measurement and not a gate: it takes
// minutes, it asserts almost nothing, and its output is numbers. `make measure`
// runs it.
package triage_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The sizes a real image produces. One kernel bump reaches 4,485 findings
// across 44,016 places; a cumulative bundle reaches 243,945, which is the
// largest single act the data can ask for.
var promiseSizes = []int{2_000, 44_016, 243_945}

// holders is how many containers pull the bumped component in. A real image
// reached 241,021 places from 7,035 components, so about 34.
const holders = 34

func TestMeasureAnUnboundedPromise(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		branch, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, branch.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		// A real person row, because a claim names who made it and the schema
		// holds it to that.
		rights := access.NewStore(db.DB)
		person, err := rights.Ensure(ctx, "triager", "A triager", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		who := access.NewPerson(person.ID, "triager", false,
			map[int64][]access.Role{product.ID: {access.PrivateTriage}}, 0)

		// One component per size, each under the same containers, so the three
		// acts do not decide about each other's places — and each with its own
		// issues, since a promise covers everything open on the component.
		root := described("sonic", "1.0")
		snap := graph.Snapshot{Root: root, Components: []graph.Described{root}}
		for h := range holders {
			holder := described(fmt.Sprintf("container-%d", h), "1.0")
			snap.Components = append(snap.Components, holder)
			snap.Dependencies = append(snap.Dependencies,
				graph.Dependency{Parent: root, Child: holder})
		}
		var reported []finding.Reported
		for n, size := range promiseSizes {
			bumped := described(fmt.Sprintf("bumped-%d", n), "1.0")
			snap.Components = append(snap.Components, bumped)
			for _, holder := range snap.Components[1 : holders+1] {
				snap.Dependencies = append(snap.Dependencies,
					graph.Dependency{Parent: holder, Child: bumped})
			}
			// Places are the issues at that component times the containers
			// pulling it in, which is the shape a kernel has.
			for i := range (size + holders - 1) / holders {
				reported = append(reported, finding.Reported{
					Issue: finding.Named{
						Identifier: fmt.Sprintf("CVE-2026-%d-%06d", n, i),
						Severity:   [...]string{"low", "medium", "high", "critical"}[i%4],
					},
					Component: bumped,
					FixState:  finding.FixedUpstream, FixedIn: "2.0",
				})
			}
		}

		scans := ingest.NewStore(db.DB)
		scan, _, err := scans.Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: "promise", BuiltAt: time.Now().UTC(),
			ParserVersion: "measure",
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := graph.NewStore(db.DB).Apply(ctx, target.ID, scan.ID, snap); err != nil {
			t.Fatal(err)
		}
		findings := finding.NewStore(db.DB)
		run, err := findings.Begin(ctx, finding.Run{
			TargetID: target.ID, Scanner: "measure",
			ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		seeding := time.Now()
		applied, err := findings.Apply(ctx, target.ID, run.ID, reported)
		if err != nil {
			t.Fatal(err)
		}
		if err := findings.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
			t.Fatal(err)
		}
		t.Logf("seeded %d findings in %s",
			applied.Opened, time.Since(seeding).Round(time.Second))

		store := triage.NewStore(db.DB)
		by := time.Now().UTC().AddDate(0, 0, 30)
		for n, size := range promiseSizes {
			t.Run(fmt.Sprintf("%d places", size), func(t *testing.T) {
				started := time.Now()
				done, err := store.PlanUpgrade(ctx, who, triage.Upgrade{
					ProductID: product.ID,
					Component: fmt.Sprintf("bumped-%d", n),
					To:        "2.0", By: by,
					Builds:    []int64{target.ID},
					Reasoning: "Measuring what one promise of this size costs to commit.",
				})
				took := time.Since(started)
				if err != nil {
					t.Fatalf("a promise over %d places: %v (after %s)", size, err, took)
				}
				t.Logf("%8d decisions over %d issues in one transaction: %s (%.0f rows/s)",
					done.Decisions, done.Issues, took.Round(time.Millisecond),
					float64(done.Decisions)/took.Seconds())
			})
		}
	})
}

// described is one component, named and versioned.
func described(name, version string) graph.Described {
	return graph.Described{
		Purl: "pkg:generic/" + name + "@" + version, Name: name, Version: version,
	}
}
