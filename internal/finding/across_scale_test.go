// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

package finding_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// issuesAtAKernelPlace is how many issues one kernel place carries. A real switch
// image carried 6,610 undecided issues at the place of one kernel claim, which
// is what the case against that claim counts on the review queue.
const issuesAtAKernelPlace = 6_000

// The two screens a person opens first, across products: the findings list
// with its default filters, and the review queue.
//
// Both read decisions against a large open set. The list asks every open row
// whether a decision stands at it, and the queue counts what else sits
// undecided at a claim's place. Each prints the per-product list beside it,
// because that is the same work bound to one product, and a gap between the
// two is a join order rather than a size.
func TestMeasureTheListAcrossProducts(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		product, target := w.Product, w.Target
		store := finding.NewStore(db.DB)
		other := seedAcross(t, w)

		// Decisions to read: an upgrade promised over ten packages, and one
		// claim at a kernel place waiting for a second person. The kernel is a
		// second build of the same product, so the claim is counted against
		// the promises' decisions, and the promises are planned over the build
		// without it. Planning over the kernel is measured on its own, below.
		person, err := access.NewStore(db.DB).Ensure(ctx, "triager", "A triager", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		triager := access.NewPerson(person.ID, "triager", false,
			map[int64][]access.Role{
				product.ID: {access.PublicTriage, access.PrivateTriage},
				other.ID:   {access.PublicTriage, access.PrivateTriage},
			}, 0)
		decisions := triage.NewStore(db.DB)
		promised := 0
		for n := range 10 {
			done, err := decisions.PlanUpgrade(ctx, triager, triage.Upgrade{
				ProductID: product.ID, Component: fmt.Sprintf("package-%d", n), To: "9.9",
				By: time.Now().UTC().AddDate(0, 0, 30), Builds: []int64{target.ID},
				Reasoning: "Measuring the lists with decisions in them.",
			})
			if err != nil {
				t.Fatal(err)
			}
			promised += done.Decisions
		}
		var kernel struct {
			Issue      int64  `bun:"vulnerability_id"`
			Place      string `bun:"place_identity"`
			Visibility string `bun:"visibility"`
		}
		if err := db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			ColumnExpr("f.vulnerability_id, f.place_identity, f.visibility").
			Where("c.name = ?", "kernel").OrderExpr("f.id").Limit(1).
			Scan(ctx, &kernel); err != nil {
			t.Fatal(err)
		}
		if _, err := decisions.Propose(ctx, triager, triage.Proposal{
			Place: triage.Place{
				ProductID: product.ID, VulnerabilityID: kernel.Issue, PlaceIdentity: kernel.Place,
				Visibility:        access.Visibility(kernel.Visibility),
				ComponentUpstream: "6.1", ConsumerUpstream: "1.0",
			},
			Outcome: triage.NotApplicable, Justification: triage.CodeNotInExecutePath,
			Reasoning: "The driver is not built.", By: person.ID, NeedsApproval: true,
		}); err != nil {
			t.Fatal(err)
		}
		var open int
		if err := db.DB.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr("COUNT(*)").
			Where("f.closed_at IS NULL").Scan(ctx, &open); err != nil {
			t.Fatal(err)
		}
		t.Logf("%d open rows, %d promised decisions and one kernel claim", open, promised)
		dbtest.SettleStatistics(t, db)

		slow := &slowStatements{t: t, over: time.Second, dir: os.Getenv("OPENPSIRT_MEASURE_SLOW")}
		db.AddQueryHook(slow)

		reader := access.NewPerson(person.ID+1, "a reader", false, map[int64][]access.Role{
			product.ID: {access.PublicRead, access.PrivateRead},
			other.ID:   {access.PublicRead, access.PrivateRead},
		}, 0)
		asked := []struct {
			name   string
			filter finding.Filter
		}{
			{"no filter", finding.Filter{}},
			{"undecided", finding.Filter{States: []finding.ClaimStanding{finding.StandingUndecided}}},
			{"unassigned", finding.Filter{Assigned: []string{"nobody"}}},
			{"the list's defaults", finding.Filter{
				Workable: finding.Working([]string{finding.OnBranch}, []string{finding.InSupport}),
				States:   []finding.ClaimStanding{finding.StandingUndecided},
				Assigned: []string{"nobody"},
				Planned:  finding.NotPlanned,
			}},
		}
		for _, one := range asked {
			at := time.Now()
			_, across, err := store.Anywhere(ctx, reader, 1, 0, one.filter)
			if err != nil {
				t.Fatal(err)
			}
			acrossTook := time.Since(at)
			at = time.Now()
			_, here, err := store.Groups(ctx, reader, finding.Scope{ProductID: &product.ID}, 1, 0, one.filter)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%-20s across products %9s (%d) · one product %9s (%d)", one.name,
				acrossTook.Round(time.Millisecond), across, time.Since(at).Round(time.Millisecond), here)
		}

		// The component and fix-bundle views keep the list's groups under the
		// same conditions over a group, grouped at their own grain.
		for _, one := range []struct {
			name   string
			filter finding.Filter
		}{
			{"undecided", finding.Filter{States: []finding.ClaimStanding{finding.StandingUndecided}}},
			{"waiting", finding.Filter{States: []finding.ClaimStanding{finding.StandingWaiting}}},
			{"planned", finding.Filter{Planned: finding.PlannedOnly}},
		} {
			at := time.Now()
			_, components, err := store.ComponentGroups(ctx, reader, finding.Scope{ProductID: &product.ID}, 1, 0, one.filter)
			if err != nil {
				t.Fatal(err)
			}
			componentsTook := time.Since(at)
			at = time.Now()
			_, bundles, err := store.Bundles(ctx, reader, finding.Scope{ProductID: &product.ID}, 1, 0, one.filter)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%-20s components %9s (%d) · fix bundles %9s (%d)", one.name,
				componentsTook.Round(time.Millisecond), components, time.Since(at).Round(time.Millisecond), bundles)
		}

		approver := access.NewPerson(person.ID+2, "an approver", false, map[int64][]access.Role{
			product.ID: {access.PublicTriage, access.PrivateTriage, access.Approver},
			other.ID:   {access.PublicTriage, access.PrivateTriage, access.Approver},
		}, 0)
		at := time.Now()
		page, waiting, err := decisions.Queue(ctx, approver, triage.QueueFilter{}, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		undecided := 0
		if len(page) > 0 {
			undecided = page[0].Counter.Undecided
		}
		t.Logf("review queue, first card %s (%d waiting, %d undecided beside the claim)",
			time.Since(at).Round(time.Millisecond), waiting, undecided)
	})
}

// Planning an upgrade in the build that carries the kernel, beside that build's
// findings list.
//
// Planning resolves every place it covers in one read and then writes a
// decision at each. The read is timed on its own, on the statistics the load
// left and again once they are refreshed, because a large scan leaves the
// server's statistics behind the table until its own refresh reaches it. The
// acts are timed whole: a small package on both, and the kernel once, after
// the refresh, since its act commits. Each is bounded rather than left to run.
func TestMeasurePlanningOverAKernel(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		product := w.Product
		store := finding.NewStore(db.DB)
		seedAcross(t, w)
		kernelBuild := w.TargetFor(w.Branch, w.Internal)

		person, err := access.NewStore(db.DB).Ensure(ctx, "triager", "A triager", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		triager := access.NewPerson(person.ID, "triager", false,
			map[int64][]access.Role{product.ID: {access.PublicTriage, access.PrivateTriage}}, 0)
		slow := &slowStatements{t: t, over: time.Second, dir: os.Getenv("OPENPSIRT_MEASURE_SLOW")}
		db.AddQueryHook(slow)

		read := func(statistics string) {
			t.Helper()
			bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			at := time.Now()
			bundled, err := store.PlacesOnComponentWithin(bounded, db.DB, triager, product.ID,
				[]int64{kernelBuild.ID}, "kernel", "")
			took := time.Since(at)
			places := 0
			for _, one := range bundled {
				places += len(one.Places)
			}
			switch {
			case bounded.Err() != nil:
				t.Logf("the kernel's places, %-11s unfinished after %s", statistics, took.Round(time.Second))
			case err != nil:
				t.Fatal(err)
			default:
				t.Logf("the kernel's places, %-11s %9s (%d)", statistics, took.Round(time.Millisecond), places)
			}
		}
		plan := func(statistics, component string) {
			t.Helper()
			bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			at := time.Now()
			done, err := triage.NewStore(db.DB).PlanUpgrade(bounded, triager, triage.Upgrade{
				ProductID: product.ID, Component: component, To: "9.9",
				By: time.Now().UTC().AddDate(0, 0, 30), Builds: []int64{kernelBuild.ID},
				Reasoning: "Measuring what planning in a build with a kernel costs.",
			})
			took := time.Since(at)
			switch {
			case bounded.Err() != nil:
				t.Logf("planning %-9s %-11s unfinished after %s", component, statistics, took.Round(time.Second))
			case err != nil:
				t.Fatalf("planning %s: %v", component, err)
			default:
				t.Logf("planning %-9s %-11s %9s (%d decisions over %d issues)", component, statistics,
					took.Round(time.Millisecond), done.Decisions, done.Issues)
			}
		}

		read("as loaded")
		plan("as loaded", "package-0")
		dbtest.SettleStatistics(t, db)

		at := time.Now()
		_, listed, err := store.Groups(ctx, triager, finding.Scope{
			ProductID: &product.ID, StreamID: &w.Branch.ID, VariantID: &w.Internal.ID,
		}, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("the kernel build's list          %9s (%d)", time.Since(at).Round(time.Millisecond), listed)
		read("refreshed")
		plan("refreshed", "package-1")
		plan("refreshed", "kernel")
	})
}

// seedAcross loads the full-size fixture the cross-product measurements read:
// the world's build at full size, a second product, and a second build of the
// first product carrying a kernel under every consumer. It returns the second
// product.
func seedAcross(t *testing.T, w *world.World) *catalog.Product {
	t.Helper()
	ctx := t.Context()
	db := w.DB
	store := finding.NewStore(db.DB)
	scans := ingest.NewStore(db.DB)
	seed := func(target *catalog.Target, extra, kernel int) {
		t.Helper()
		scan, _, err := scans.Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: fmt.Sprint("across-", target.ID),
			BuiltAt: time.Now().UTC(), ParserVersion: "measure",
		})
		if err != nil {
			t.Fatal(err)
		}
		versionOf := func(int) string { return "1.0" }
		snap := shape(versionOf)
		reported := reports(versionOf, extra)
		if kernel > 0 {
			// One more package under every consumer, carrying far more
			// issues than any other: the shape a kernel has.
			k := at("kernel", "6.1")
			snap.Components = append(snap.Components, k)
			for c := range consumers {
				snap.Dependencies = append(snap.Dependencies,
					graph.Dependency{Parent: snap.Components[1+c], Child: k})
			}
			for i := range kernel {
				reported = append(reported, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%05d", i), Severity: "medium"},
					Component: k,
				})
			}
		}
		if _, err := graph.NewStore(db.DB).Apply(ctx, target.ID, scan.ID, snap); err != nil {
			t.Fatal(err)
		}
		run, err := store.Begin(ctx, finding.Run{
			TargetID: target.ID, Scanner: "measure",
			ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Apply(ctx, target.ID, run.ID, reported); err != nil {
			t.Fatal(err)
		}
		if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
			t.Fatal(err)
		}
	}
	seed(w.Target, bigIssues-issues, 0)
	other := w.DeclareProduct("other", "Other")
	seed(w.TargetFor(w.DeclareStream(other, "main", catalog.Branch, nil),
		w.DeclareVariant(other, "only", true)), 0, 0)
	seed(w.TargetFor(w.Branch, w.Internal), 0, issuesAtAKernelPlace)
	return other
}

// slowStatements names each statement that took longer than a bound, so a
// slow screen says which of its statements the time went to. Where a directory
// is named, the statement is written there whole, to be explained on the
// engine that ran it.
type slowStatements struct {
	t    *testing.T
	over time.Duration
	dir  string
	n    int
}

func (s *slowStatements) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (s *slowStatements) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	took := time.Since(event.StartTime)
	if took < s.over {
		return
	}
	s.n++
	shown := strings.Join(strings.Fields(event.Query), " ")
	if len(shown) > 160 {
		shown = shown[:160] + "..."
	}
	s.t.Logf("    slow statement %d, %s: %s", s.n, took.Round(time.Millisecond), shown)
	if s.dir != "" {
		name := fmt.Sprintf("%s/%s-%d.sql", s.dir, strings.ReplaceAll(s.t.Name(), "/", "-"), s.n)
		if err := os.WriteFile(name, []byte(event.Query), 0o600); err != nil {
			s.t.Logf("    could not keep it: %v", err)
		}
	}
}
