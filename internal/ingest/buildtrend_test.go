// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
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

func TestABuildTrendCountsEachUploadAsOfItsLastScanAtItsBuildTime(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Second)
		day := 24 * time.Hour
		u := &uploads{t: t, w: w, build: w.Build.ID, now: now}

		// September's image, scanned twice while it was current. The second
		// scan finds one more issue, so the point is its last scan's.
		september := u.upload(now.Add(-60*day), now.Add(-5*day), kernelOld, curl)
		u.scan(now.Add(-5*day+time.Minute),
			issue("CVE-2026-0001", "critical", kernelOld), issue("CVE-2026-0002", "high", kernelOld),
			issue("CVE-2026-0003", "high", curl))
		u.scan(now.Add(-4*day),
			issue("CVE-2026-0001", "critical", kernelOld), issue("CVE-2026-0002", "high", kernelOld),
			issue("CVE-2026-0003", "high", curl), issue("CVE-2026-0004", "high", kernelOld))
		// An upload replaced before any scan reached it is no point.
		u.upload(now.Add(-30*day), now.Add(-3*day), kernelOld, curl)
		// November's: the kernel moved past its issues, and curl's stays.
		november := u.upload(now.Add(-day), now.Add(-2*day), kernelNew, curl)
		u.scan(now.Add(-2*day+time.Minute), issue("CVE-2026-0003", "high", curl))

		scope := finding.Scope{ProductID: &w.Product.ID, BranchOrTagID: &w.Branch.ID, VariantID: &w.Customer.ID}
		points, err := ingest.NewStore(w.DB.DB).BuildTrend(ctx, reader(w), scope, finding.Within{}, 12)
		if err != nil {
			t.Fatal(err)
		}
		if len(points) != 2 {
			t.Fatalf("got %d points, want 2: September and November, and nothing for the unscanned upload: %+v",
				len(points), points)
		}
		sep, nov := points[0], points[1]
		if sep.ScanID != september || nov.ScanID != november {
			t.Fatalf("points are uploads %d and %d, want %d then %d", sep.ScanID, nov.ScanID, september, november)
		}
		if !sep.BuiltAt.Equal(now.Add(-60*day)) || !nov.BuiltAt.Equal(now.Add(-day)) {
			t.Errorf("points sit at %v and %v, want the build times each inventory states", sep.BuiltAt, nov.BuiltAt)
		}
		if sep.Open != 4 || sep.BySeverity["critical"] != 1 || sep.BySeverity["high"] != 3 {
			t.Errorf("September holds %d open %v, want 4 as of its last scan: 1 critical, 3 high", sep.Open, sep.BySeverity)
		}
		if !sep.AsOf.Equal(now.Add(-4*day)) || sep.Current {
			t.Errorf("September is counted at %v (current %v), want its last scan's start, replaced", sep.AsOf, sep.Current)
		}
		if nov.Open != 1 || !nov.Current {
			t.Errorf("November holds %d open (current %v), want 1, the inventory the build holds", nov.Open, nov.Current)
		}
	})
}

func TestABuildTrendCountsOnlyWhatTheNarrowingKeeps(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		ctx := t.Context()
		now := time.Now().UTC().Truncate(time.Second)
		u := &uploads{t: t, w: w, build: w.Build.ID, now: now}
		u.upload(now.Add(-time.Hour), now.Add(-time.Hour), kernelOld, curl)
		u.scan(now.Add(-time.Hour+time.Minute),
			issue("CVE-2026-0001", "critical", kernelOld), issue("CVE-2026-0003", "high", curl))

		scope := finding.Scope{ProductID: &w.Product.ID, BranchOrTagID: &w.Branch.ID, VariantID: &w.Customer.ID}
		points, err := ingest.NewStore(w.DB.DB).BuildTrend(ctx, reader(w), scope,
			finding.Within{Component: "curl"}, 12)
		if err != nil {
			t.Fatal(err)
		}
		if len(points) != 1 || points[0].Open != 1 {
			t.Fatalf("got %+v, want one point holding curl's one issue", points)
		}
	})
}

func TestABuildTrendIsRefusedForASelectionThatIsNotOneBuild(t *testing.T) {
	world.Each(t, func(t *testing.T, w *world.World) {
		ctx := t.Context()
		w.BuildFor(w.Branch, w.Internal)
		s := ingest.NewStore(w.DB.DB)
		// Two variants of the branch are two builds.
		branch := finding.Scope{ProductID: &w.Product.ID, BranchOrTagID: &w.Branch.ID}
		if _, err := s.BuildTrend(ctx, reader(w), branch, finding.Within{}, 12); !errors.Is(err, finding.ErrNotOneBuild) {
			t.Errorf("a branch of two variants answered %v, want it refused as not one build", err)
		}
		// Somebody holding nothing on the product reads no build of it.
		stranger := access.NewPerson(w.Person.ID, "a stranger", false, map[int64][]access.Role{}, 0)
		one := finding.Scope{ProductID: &w.Product.ID, BranchOrTagID: &w.Branch.ID, VariantID: &w.Customer.ID}
		if _, err := s.BuildTrend(ctx, stranger, one, finding.Within{}, 12); !errors.Is(err, finding.ErrNotOneBuild) {
			t.Errorf("a stranger's build trend answered %v, want it refused as not a build they read", err)
		}
	})
}
