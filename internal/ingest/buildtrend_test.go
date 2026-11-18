// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

var (
	trendRoot = graph.Described{Name: "sonic", Version: "1.0"}
	kernelOld = graph.Described{Name: "linux-image", Version: "6.12.41",
		Purl: "pkg:deb/debian/linux-image@6.12.41"}
	kernelNew = graph.Described{Name: "linux-image", Version: "6.12.94",
		Purl: "pkg:deb/debian/linux-image@6.12.94"}
	curl = graph.Described{Name: "curl", Version: "8.14.1", Purl: "pkg:deb/debian/curl@8.14.1"}
)

// uploads sends inventories of one build and scans them, each at the moment
// given relative to now.
type uploads struct {
	t     *testing.T
	w     *world.World
	build int64
	now   time.Time
	n     int
}

// upload files an inventory built at built, arriving at arrived, applied to
// the build's graph, and answers its scan.
func (u *uploads) upload(built, arrived time.Time, components ...graph.Described) int64 {
	u.t.Helper()
	ctx := u.t.Context()
	u.n++
	s := ingest.NewStore(u.w.DB.DB)
	scan, _, err := s.Record(ctx, ingest.Arriving{
		BuildID: u.build, ContentHash: fmt.Sprintf("upload-%d", u.n), BuiltAt: built,
		ParserVersion: "test",
	})
	if err != nil {
		u.t.Fatal(err)
	}
	if _, err := u.w.DB.DB.NewUpdate().Table("scan").Set(`"received_at" = ?`, arrived).
		Where(`"id" = ?`, scan.ID).Exec(ctx); err != nil {
		u.t.Fatal(err)
	}
	if _, err := world.ApplyGraph(ctx, u.w.DB.DB, u.build, scan.ID,
		graph.Snapshot{Root: trendRoot, Components: components}); err != nil {
		u.t.Fatal(err)
	}
	if err := s.Made(ctx, scan.ID, len(components), len(components), ""); err != nil {
		u.t.Fatal(err)
	}
	return scan.ID
}

// scan runs a scan of the build starting at started, reporting these issues.
func (u *uploads) scan(started time.Time, reported ...finding.Reported) int64 {
	u.t.Helper()
	ctx := u.t.Context()
	store := finding.NewStore(u.w.DB.DB)
	run, err := store.Begin(ctx, finding.Run{BuildID: u.build, Scanner: "test", ScannerVersion: "0",
		DatabaseVersion: "0", RanHere: true})
	if err != nil {
		u.t.Fatal(err)
	}
	if _, err := u.w.DB.DB.NewUpdate().Table("scan_run").Set(`"started_at" = ?`, started).
		Where(`"id" = ?`, run.ID).Exec(ctx); err != nil {
		u.t.Fatal(err)
	}
	if _, err := store.Apply(ctx, u.build, run.ID, reported); err != nil {
		u.t.Fatal(err)
	}
	if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
		u.t.Fatal(err)
	}
	return run.ID
}

func issue(id, severity string, at graph.Described) finding.Reported {
	return finding.Reported{Issue: finding.Named{Identifier: id, Severity: severity}, Component: at}
}

// reader reads every product.
func reader(w *world.World) access.Subject {
	return access.NewPerson(w.Person.ID, "a reader", false,
		map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)
}

// day is a step of the trend by build date.
const day = 24 * time.Hour

// builtTrend reads the trend by build date over a scope, daily.
func builtTrend(t *testing.T, w *world.World, who access.Subject, scope finding.Scope,
	within finding.Within) []finding.Point {
	t.Helper()
	return builtTrendOf(t, w, who, scope, within, 12)
}

// builtTrendOf reads the trend by build date over a scope, daily, keeping the
// latest limit points.
func builtTrendOf(t *testing.T, w *world.World, who access.Subject, scope finding.Scope,
	within finding.Within, limit int) []finding.Point {
	t.Helper()
	points, err := ingest.NewStore(w.DB.DB).BuiltTrend(t.Context(), who, scope, within, day, limit)
	if err != nil {
		t.Fatal(err)
	}
	return points
}

func TestATrendByBuildDateCountsEachUploadAsOfItsLastScanAtItsBuildDate(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		u := &uploads{t: t, w: w, build: w.Build.ID, now: now}

		// September's image, scanned twice while it was current. The second
		// scan finds one more issue, so the point is its last scan's.
		u.upload(now.Add(-60*day), now.Add(-5*day), kernelOld, curl)
		u.scan(now.Add(-5*day+time.Minute),
			issue("CVE-2026-0001", "critical", kernelOld), issue("CVE-2026-0002", "high", kernelOld),
			issue("CVE-2026-0003", "high", curl))
		u.scan(now.Add(-4*day),
			issue("CVE-2026-0001", "critical", kernelOld), issue("CVE-2026-0002", "high", kernelOld),
			issue("CVE-2026-0003", "high", curl), issue("CVE-2026-0004", "high", kernelOld))
		// An upload replaced before any scan reached it is no point.
		u.upload(now.Add(-30*day), now.Add(-3*day), kernelOld, curl)
		// November's: the kernel moved past its issues, and curl's stays.
		u.upload(now.Add(-day), now.Add(-2*day), kernelNew, curl)
		u.scan(now.Add(-2*day+time.Minute), issue("CVE-2026-0003", "high", curl))

		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{})
		if len(points) != 2 {
			t.Fatalf("got %d points, want 2: September and November, and nothing for the unscanned upload: %+v",
				len(points), points)
		}
		sep, nov := points[0], points[1]
		// A point is its step's end, as on the calendar trend, which names it
		// by the day before.
		if want := now.Add(-60 * day).Truncate(day).Add(day); !sep.At.Equal(want) {
			t.Errorf("September ends at %v, want %v, the end of the day its inventory states it was built",
				sep.At, want)
		}
		if want := now.Add(-day).Truncate(day).Add(day); !nov.At.Equal(want) {
			t.Errorf("November ends at %v, want %v", nov.At, want)
		}
		if sep.Open != 4 || sep.BySeverity["critical"] != 1 || sep.BySeverity["high"] != 3 {
			t.Errorf("September holds %d open %v, want 4 as of its last scan: 1 critical, 3 high",
				sep.Open, sep.BySeverity)
		}
		if sep.Baseline != 4 || sep.FirstScans != 1 || sep.New != 0 {
			t.Errorf("September brought %d baseline and %d new from %d first uploads, want 4, 0 and 1",
				sep.Baseline, sep.New, sep.FirstScans)
		}
		if nov.Open != 1 || nov.Corrected != 3 || nov.CorrectedBySeverity["critical"] != 1 || nov.New != 0 {
			t.Errorf("November holds %d open, %d corrected (%v), %d new; want 1, 3 with 1 critical, 0",
				nov.Open, nov.Corrected, nov.CorrectedBySeverity, nov.New)
		}
	})
}

func TestATrendByBuildDateReadsEachBuildAtItsOwnUpload(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		a := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		b := &uploads{t: t, w: w, build: w.BuildFor(w.Branch, w.Internal).ID, now: now}

		// Both builds hold one issue at curl in September; the second build's
		// copy is the same issue at the same component, counted once. The
		// second build alone also holds one at the kernel.
		a.upload(now.Add(-60*day), now.Add(-6*day), curl)
		a.scan(now.Add(-6*day+time.Minute), issue("CVE-2026-0003", "high", curl))
		b.upload(now.Add(-60*day), now.Add(-6*day), curl, kernelOld)
		b.scan(now.Add(-6*day+time.Minute), issue("CVE-2026-0003", "high", curl),
			issue("CVE-2026-0001", "critical", kernelOld))
		// November: the first build finds a second issue, which is new. The
		// second build is not uploaded again, so September is the upload it
		// holds and is read now, after a later scan stopped reporting the
		// kernel's issue: at neither point is that issue open.
		a.upload(now.Add(-day), now.Add(-2*day), curl)
		a.scan(now.Add(-2*day+time.Minute),
			issue("CVE-2026-0003", "high", curl), issue("CVE-2026-0005", "medium", curl))
		b.scan(now.Add(-time.Hour), issue("CVE-2026-0003", "high", curl))

		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{})
		if len(points) != 2 {
			t.Fatalf("got %d points, want 2: %+v", len(points), points)
		}
		if points[0].Open != 1 || points[0].Baseline != 1 || points[0].FirstScans != 2 {
			t.Errorf("September holds %d open, %d baseline, %d first uploads; want 1, 1 and 2: one issue at one component in two builds",
				points[0].Open, points[0].Baseline, points[0].FirstScans)
		}
		if points[1].Open != 2 || points[1].New != 1 || points[1].Corrected != 0 {
			t.Errorf("November holds %d open, %d new, %d corrected; want 2, 1 and 0", points[1].Open,
				points[1].New, points[1].Corrected)
		}
	})
}

func TestABuildFirstUploadedLaterBringsBaselineNotNewWork(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		a := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		b := &uploads{t: t, w: w, build: w.BuildFor(w.Branch, w.Internal).ID, now: now}
		a.upload(now.Add(-60*day), now.Add(-6*day), curl)
		a.scan(now.Add(-6*day+time.Minute), issue("CVE-2026-0003", "high", curl))
		b.upload(now.Add(-day), now.Add(-2*day), kernelOld)
		b.scan(now.Add(-2*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))

		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{})
		if len(points) != 2 {
			t.Fatalf("got %d points, want 2: %+v", len(points), points)
		}
		if p := points[1]; p.Open != 2 || p.Baseline != 1 || p.New != 0 || p.FirstScans != 1 {
			t.Errorf("the later build's first upload gave %d open, %d baseline, %d new from %d first uploads; want 2, 1, 0 and 1",
				p.Open, p.Baseline, p.New, p.FirstScans)
		}
	})
}

func TestAnIssueTheScannerStoppedReportingIsNotCorrectedByBuildDate(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		u := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		u.upload(now.Add(-60*day), now.Add(-6*day), curl)
		u.scan(now.Add(-6*day+time.Minute), issue("CVE-2026-0003", "high", curl))
		// The same curl, and the scanner says nothing of it: no fix.
		u.upload(now.Add(-day), now.Add(-2*day), curl)
		u.scan(now.Add(-2*day + time.Minute))

		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{})
		if len(points) != 2 || points[1].Open != 0 || points[1].Corrected != 0 {
			t.Fatalf("got %+v, want November holding nothing and correcting nothing", points)
		}
	})
}

func TestAnIssueBackAfterAnUploadWithoutItIsReturned(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		u := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		u.upload(now.Add(-60*day), now.Add(-9*day), kernelOld)
		u.scan(now.Add(-9*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))
		u.upload(now.Add(-30*day), now.Add(-6*day), kernelNew)
		u.scan(now.Add(-6*day + time.Minute))
		u.upload(now.Add(-day), now.Add(-2*day), kernelOld)
		u.scan(now.Add(-2*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))

		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{})
		if len(points) != 3 {
			t.Fatalf("got %d points, want 3: %+v", len(points), points)
		}
		if points[1].Corrected != 1 || points[2].Returned != 1 || points[2].New != 0 {
			t.Errorf("got corrected %d, then returned %d and new %d; want 1, 1 and 0",
				points[1].Corrected, points[2].Returned, points[2].New)
		}
	})
}

func TestATrendByBuildDateCountsOnlyWhatTheNarrowingKeeps(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		u := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		u.upload(now.Add(-time.Hour), now.Add(-time.Hour), kernelOld, curl)
		u.scan(now.Add(-time.Hour+time.Minute),
			issue("CVE-2026-0001", "critical", kernelOld), issue("CVE-2026-0003", "high", curl))

		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID},
			finding.Within{Component: "curl"})
		if len(points) != 1 || points[0].Open != 1 {
			t.Fatalf("got %+v, want one point holding curl's one issue", points)
		}
	})
}

func TestATrendByBuildDateShowsAStrangerNothing(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		u := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		u.upload(now.Add(-time.Hour), now.Add(-time.Hour), curl)
		u.scan(now.Add(-time.Hour+time.Minute), issue("CVE-2026-0003", "high", curl))

		stranger := access.NewPerson(w.Person.ID, "a stranger", false, map[int64][]access.Role{}, 0)
		if points := builtTrend(t, w, stranger, finding.Scope{}, finding.Within{}); len(points) != 0 {
			t.Fatalf("a stranger read %+v, want nothing", points)
		}
	})
}

func TestATrendByBuildDateCountsAnIssueInTwoProductsInTheStrictestBandEitherGivesIt(t *testing.T) {
	// One row per issue and build reaches the count, in no order anything
	// sets, so the band has to be chosen rather than left to whichever row
	// came last.
	world.Each(t, func(t *testing.T, w *world.World) {
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Second)
		other := w.DeclareProduct("hedgehog", "Hedgehog")
		branch := w.DeclareBranchOrTag(other, "main", catalog.Branch, nil)
		variant := w.DeclareVariant(other, "box", true)
		a := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		b := &uploads{t: t, w: w, build: w.BuildFor(branch, variant).ID, now: now}
		both := []finding.Reported{issue("CVE-2026-0006", "", curl), issue("CVE-2026-0007", "", curl)}
		a.upload(now.Add(-day), now.Add(-2*day), curl)
		a.scan(now.Add(-2*day+time.Minute), both...)
		b.upload(now.Add(-day), now.Add(-2*day), curl)
		b.scan(now.Add(-2*day+time.Minute), both...)
		rate := func(product int64, identifier, severity string) {
			var id int64
			if err := w.DB.DB.NewSelect().TableExpr(`"vulnerability" AS "v"`).ColumnExpr(`"v"."id"`).
				Where(`"v"."identifier" = ?`, identifier).Scan(ctx, &id); err != nil {
				t.Fatal(err)
			}
			if _, err := w.DB.DB.NewInsert().Model(&finding.IssueRating{
				VulnerabilityID: id, ProductID: product, Severity: severity,
			}).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		rate(w.Product.ID, "CVE-2026-0006", "low")
		rate(other.ID, "CVE-2026-0006", "medium")
		rate(w.Product.ID, "CVE-2026-0007", "medium")
		rate(other.ID, "CVE-2026-0007", "low")

		who := access.NewPerson(w.Person.ID, "a reader", false, map[int64][]access.Role{
			w.Product.ID: {access.PublicRead}, other.ID: {access.PublicRead}}, 0)
		points := builtTrend(t, w, who, finding.Scope{}, finding.Within{})
		if len(points) != 1 || points[0].Open != 2 || points[0].BySeverity["medium"] != 2 {
			t.Fatalf("two issues each rated low in one product and medium in the other gave %+v; want one point, 2 open, both medium",
				points)
		}
	})
}

func TestAFlawRecordedInTwoBuildsIsReadInEachAtItsOwnMoment(t *testing.T) {
	// A flaw recorded by hand opens in every build named at one moment with no
	// scan, so its rows in two builds are alike in all but the build. Each
	// build is read at its own moment, so neither may stand for the other.
	world.Each(t, func(t *testing.T, w *world.World) {
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Second)
		a := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		other := w.BuildFor(w.Branch, w.Internal)
		b := &uploads{t: t, w: w, build: other.ID, now: now}
		a.upload(now.Add(-60*day), now.Add(-9*day), curl)
		a.scan(now.Add(-9*day + time.Minute))
		b.upload(now.Add(-60*day), now.Add(-9*day), curl)
		b.scan(now.Add(-9*day + time.Minute))
		a.upload(now.Add(-day), now.Add(-2*day), curl)
		a.scan(now.Add(-2*day + time.Minute))

		planner := access.NewPerson(w.Person.ID, "a planner", false, map[int64][]access.Role{
			w.Product.ID: {access.PublicRead, access.PrivateRead, access.PublicTriage, access.PrivateTriage}}, 0)
		if _, _, err := finding.NewStore(w.DB.DB).Enter(ctx, planner, finding.Entering{
			BuildIDs: []int64{w.Build.ID, other.ID}, Component: curl.Name, Severity: "high",
			Summary: "The parser accepts a message it should refuse.",
		}); err != nil {
			t.Fatal(err)
		}

		// September: the first build is read at its September scan, before
		// the flaw; the second holds September still, so it is read now.
		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{})
		if len(points) != 2 || points[0].Open != 1 || points[1].Open != 1 {
			t.Fatalf("got %+v; want two points each holding the flaw, September through the second build", points)
		}
	})
}

func TestABuildWhoseFirstDayHoldsTwoUploadsBringsBaselineNotNewWork(t *testing.T) {
	// Two uploads built on one day share a point, and the first of them is
	// the build's first upload.
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		a := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		b := &uploads{t: t, w: w, build: w.BuildFor(w.Branch, w.Internal).ID, now: now}
		a.upload(now.Add(-60*day), now.Add(-9*day), curl)
		a.scan(now.Add(-9*day+time.Minute), issue("CVE-2026-0003", "high", curl))
		morning := now.Truncate(day).Add(-10*day + time.Hour)
		b.upload(morning, now.Add(-8*day), kernelOld)
		b.scan(now.Add(-8*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))
		b.upload(morning.Add(4*time.Hour), now.Add(-7*day), kernelOld)
		b.scan(now.Add(-7*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))

		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{})
		if len(points) != 2 {
			t.Fatalf("got %d points, want 2: %+v", len(points), points)
		}
		if p := points[1]; p.Open != 2 || p.Baseline != 1 || p.New != 0 || p.FirstScans != 1 {
			t.Errorf("a build first uploaded twice in one day gave %d open, %d baseline, %d new from %d first uploads; want 2, 1, 0 and 1",
				p.Open, p.Baseline, p.New, p.FirstScans)
		}
	})
}

func TestABuildWhoseFirstUploadIsCutOffBringsNoBaseline(t *testing.T) {
	// Baseline is an inventory arriving. A point whose earlier points the limit
	// cut off is not where any build arrived.
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		a := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		b := &uploads{t: t, w: w, build: w.BuildFor(w.Branch, w.Internal).ID, now: now}
		a.upload(now.Add(-60*day), now.Add(-9*day), curl)
		a.scan(now.Add(-9*day+time.Minute), issue("CVE-2026-0003", "high", curl))
		b.upload(now.Add(-60*day), now.Add(-9*day), kernelOld)
		b.scan(now.Add(-9*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))
		a.upload(now.Add(-30*day), now.Add(-6*day), curl)
		a.scan(now.Add(-6*day+time.Minute), issue("CVE-2026-0003", "high", curl))
		a.upload(now.Add(-day), now.Add(-2*day), curl)
		a.scan(now.Add(-2*day+time.Minute), issue("CVE-2026-0003", "high", curl))

		points := builtTrendOf(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{}, 2)
		if len(points) != 2 {
			t.Fatalf("got %d points, want 2: %+v", len(points), points)
		}
		if p := points[0]; p.Open != 2 || p.Baseline != 0 || p.FirstScans != 0 {
			t.Errorf("the first point kept gave %d open, %d baseline from %d first uploads; want 2, 0 and 0",
				p.Open, p.Baseline, p.FirstScans)
		}
	})
}

// fillers are packages carrying nothing, so an upload losing them moves a
// sharp share of the inventory.
func fillers(n int) []graph.Described {
	out := make([]graph.Described, n)
	for i := range out {
		name := fmt.Sprintf("filler%02d", i)
		out[i] = graph.Described{Name: name, Version: "1.0", Purl: "pkg:deb/debian/" + name + "@1.0"}
	}
	return out
}

func TestAReturnAfterASharpRemovalIsRestoredByBuildDate(t *testing.T) {
	// An upload that lost most of the inventory is a broken one, so what comes
	// back after it is the inventory put right.
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		u := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		whole := append(fillers(12), kernelOld, curl)
		u.upload(now.Add(-60*day), now.Add(-9*day), whole...)
		u.scan(now.Add(-9*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))
		u.upload(now.Add(-30*day), now.Add(-6*day), curl)
		u.scan(now.Add(-6*day + time.Minute))
		u.upload(now.Add(-day), now.Add(-2*day), whole...)
		u.scan(now.Add(-2*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))

		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{})
		if len(points) != 3 {
			t.Fatalf("got %d points, want 3: %+v", len(points), points)
		}
		if p := points[2]; p.Restored != 1 || p.Returned != 0 || len(p.ReturnedBySeverity) != 0 || p.New != 0 {
			t.Errorf("the inventory put right gave %d restored, %d returned %v, %d new; want 1, 0, none and 0",
				p.Restored, p.Returned, p.ReturnedBySeverity, p.New)
		}
	})
}

func TestAReturnAfterASmallRemovalIsReturnedByBuildDate(t *testing.T) {
	// One package of fourteen leaving moves too little of the inventory to be
	// a broken upload, so its issue coming back is a return.
	world.Each(t, func(t *testing.T, w *world.World) {
		now := time.Now().UTC().Truncate(time.Second)
		u := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		whole := append(fillers(12), kernelOld, curl)
		u.upload(now.Add(-60*day), now.Add(-9*day), whole...)
		u.scan(now.Add(-9*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))
		u.upload(now.Add(-30*day), now.Add(-6*day), append(fillers(12), curl)...)
		u.scan(now.Add(-6*day + time.Minute))
		u.upload(now.Add(-day), now.Add(-2*day), whole...)
		u.scan(now.Add(-2*day+time.Minute), issue("CVE-2026-0001", "critical", kernelOld))

		points := builtTrend(t, w, reader(w), finding.Scope{ProductID: &w.Product.ID}, finding.Within{})
		if len(points) != 3 {
			t.Fatalf("got %d points, want 3: %+v", len(points), points)
		}
		if p := points[2]; p.Returned != 1 || p.ReturnedBySeverity["critical"] != 1 || p.Restored != 0 {
			t.Errorf("a small removal put back gave %d returned %v and %d restored; want 1 critical and 0",
				p.Returned, p.ReturnedBySeverity, p.Restored)
		}
	})
}
