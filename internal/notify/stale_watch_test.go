// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func TestTheWatchTellsAdministratorsWhenTheVulnerabilityDataStopsMoving(t *testing.T) {
	// Nothing fails when the data stops moving, which is the whole danger: the
	// scans keep succeeding, every screen keeps answering, and each answer is
	// as old as the data behind it without saying so. So it has to be looked
	// for rather than waited for.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		reader, err := rights.Ensure(ctx, "reader@example.com", "Reader", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		target := aScannedTarget(t, w)
		watch := notify.NewWatch(db.DB, quiet)

		// A month of runs, every one of them against the same data. Nothing
		// here has failed and nothing has gone quiet: the scans are arriving.
		ranAt := func(when time.Time, version string) {
			t.Helper()
			finished := when.Add(time.Minute)
			if _, err := db.DB.NewInsert().Model(&finding.Run{
				TargetID: target, Scanner: "grype", ScannerVersion: "0.112.0",
				DatabaseVersion: version, RanHere: true,
				StartedAt: when, FinishedAt: &finished,
			}).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for day := 30; day >= 0; day-- {
			ranAt(time.Now().UTC().Add(-time.Duration(day)*24*time.Hour), "2026-08-19")
		}

		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := waiting(t, db, admin); n == 0 {
			t.Fatal("the data has not moved in a month and nobody was told")
		}
		if n := waiting(t, db, reader); n != 0 {
			t.Errorf("somebody who administers nothing was told %d things", n)
		}

		// The data moves. The condition clears itself, because what was wrong
		// has stopped being true — nobody dismisses it.
		ranAt(time.Now().UTC(), "2026-09-18")
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := waiting(t, db, admin); n != 0 {
			t.Errorf("the data moved and %d alerts are still waiting", n)
		}
	})
}

func TestDataThatMovedRecentlyIsNotReportedAsStale(t *testing.T) {
	// The other arm, and the one that decides whether the condition is worth
	// having: a deployment whose data moves is told nothing at all.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		admin, err := access.NewStore(db.DB).Ensure(ctx, "admin@example.com", "Admin",
			new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		target := aScannedTarget(t, w)
		for day, version := range map[int]string{3: "2026-09-15", 1: "2026-09-17"} {
			at := time.Now().UTC().Add(-time.Duration(day) * 24 * time.Hour)
			finished := at.Add(time.Minute)
			if _, err := db.DB.NewInsert().Model(&finding.Run{
				TargetID: target, Scanner: "grype", DatabaseVersion: version,
				RanHere: true, StartedAt: at, FinishedAt: &finished,
			}).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}

		if _, _, err := notify.NewWatch(db.DB, quiet).Once(ctx); err != nil {
			t.Fatal(err)
		}
		_, total, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, admin), 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 0 {
			t.Errorf("the data moved two days ago and %d alerts were raised", total)
		}
	})
}

// aScannedTarget files a scan against the world's build, so that the deployment
// is not also reported as having gone quiet.
func aScannedTarget(t *testing.T, w *fixture.World) int64 {
	t.Helper()
	db := w.DB
	ctx := t.Context()
	target := w.Target
	if _, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "scanned",
		BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "test",
	}); err != nil {
		t.Fatal(err)
	}
	return target.ID
}

func TestAStaleAlertNamesTheDataInForceRatherThanTheDataItWasRaisedFor(t *testing.T) {
	// The data moving does not always mean it started moving. A deployment
	// that fetched once and stopped again has a newer version and the same
	// problem — and an alert still naming the version it was first raised for
	// sends somebody to check a fetch that did happen.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		admin, err := access.NewStore(db.DB).Ensure(ctx, "admin@example.com", "Admin",
			new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		target := aScannedTarget(t, w)
		ranAt := func(daysAgo int, version string) {
			t.Helper()
			at := time.Now().UTC().Add(-time.Duration(daysAgo) * 24 * time.Hour)
			finished := at.Add(time.Minute)
			if _, err := db.DB.NewInsert().Model(&finding.Run{
				TargetID: target, Scanner: "grype", DatabaseVersion: version,
				RanHere: true, StartedAt: at, FinishedAt: &finished,
			}).Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		watch := notify.NewWatch(db.DB, quiet)
		// The row's identity as well as its words. A version-keyed condition
		// passes an assertion on the text alone: the second sweep clears the old
		// row and opens a new one carrying the newer version, Waiting returns
		// whatever is uncleared, and the reader gets a fresh unread alert about
		// something that never stopped being true.
		said := func() (int64, string) {
			t.Helper()
			rows, _, err := notify.NewStore(db.DB).Waiting(ctx, asks(t, db, admin), 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range rows {
				if row.Kind == notify.VulnerabilityDataStale {
					return row.ID, row.Body
				}
			}
			return 0, ""
		}

		// Stuck on one version for a month.
		for day := 40; day >= 30; day-- {
			ranAt(day, "2026-08-01")
		}
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		was, body := said()
		if !strings.Contains(body, "2026-08-01") {
			t.Fatalf("the alert says %q, want it to name the data in force", body)
		}

		// One fetch landed, then nothing again. Newer data, same problem.
		for day := 20; day >= 0; day-- {
			ranAt(day, "2026-08-29")
		}
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		now, body := said()
		if body == "" {
			t.Fatal("the data is still twenty days old and nothing is being said")
		}
		if !strings.Contains(body, "2026-08-29") {
			t.Errorf("the alert says %q, want it to name the data in force now", body)
		}
		if now != was {
			t.Errorf("the alert was cleared and re-raised as %d, was %d: the condition is "+
				"that the data stopped moving, which never stopped being true", now, was)
		}
	})
}

// A version that comes back is not the data moving, and is not the data
// standing still since the first time it was ever seen.
//
// A data bundle is a build stamp, so restoring an older one reproduces a
// version string exactly. Measured as the first sighting of whichever version
// ran most recently, an air-gapped deployment re-importing last quarter's
// bundle would be told the data had not moved in seven months, about data that
// moved two days earlier.
func TestAVersionComingBackIsNotTheDataStandingStill(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		admin, err := access.NewStore(db.DB).Ensure(ctx, "admin@example.com", "Admin",
			new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		target := aScannedTarget(t, w)
		ran := ranOn(t, db, target)

		// Last quarter's bundle, then a fetch two days ago, then the old
		// bundle restored today. The data moved two days ago, so under the
		// shipped week nothing is wrong.
		ran(200, "grype-db-v6-2026-03-01")
		ran(2, "grype-db-v6-2026-09-17")
		ran(0, "grype-db-v6-2026-03-01")

		watch := notify.NewWatch(db.DB, quiet)
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if body := staleness(t, db, admin); body != "" {
			t.Fatalf("a restored bundle raised %q: the data moved two days ago", body)
		}
	})
}

// Two replicas holding different data do not make an alert that never settles.
//
// The chart ships more than one replica with a scanner cache each, so two of
// them can be a fetch apart and both keep scanning. Read as the first sighting
// of whichever ran last, the answer alternated with whichever pod finished
// most recently — and a condition that holds on one sweep and not the next is
// a fresh unread alert every sweep, for ever, which is what REQ-49 is about.
func TestTwoReplicasADataFetchApartDoNotAlternate(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		admin, err := access.NewStore(db.DB).Ensure(ctx, "admin@example.com", "Admin",
			new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		target := aScannedTarget(t, w)
		ran := ranOn(t, db, target)

		// One replica has been on the same data for two months; the other
		// fetched two days ago. Both keep scanning, and which of them finished
		// last is whichever the scheduler got to.
		for day := 60; day >= 0; day-- {
			ran(day, "grype-db-v6-2026-07-20")
		}
		for day := 2; day >= 0; day-- {
			ran(day, "grype-db-v6-2026-09-17")
		}

		watch := notify.NewWatch(db.DB, quiet)
		for sweep := range 3 {
			// The stale replica finishing last on every other sweep, which is
			// the ordering that decided the answer before.
			ran(0, "grype-db-v6-2026-07-20")
			if _, _, err := watch.Once(ctx); err != nil {
				t.Fatal(err)
			}
			if body := staleness(t, db, admin); body != "" {
				t.Fatalf("sweep %d raised %q: one replica is two months behind and "+
					"the data itself moved two days ago", sweep, body)
			}
		}
	})
}

// The window is a setting, and a window under a day is said in words.
//
// Set here to a value other than the compiled default, so a read replaced by
// the default fails. The words matter at the same time: "0 days" is what
// arithmetic gives for a
// threshold measured in hours, and a deployment fetching nightly has a reason
// to set one.
func TestHowLongCountsAsStoppedIsASettingAndIsSaidInWords(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

		admin, err := access.NewStore(db.DB).Ensure(ctx, "admin@example.com", "Admin",
			new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		target := aScannedTarget(t, w)
		finished := time.Now().UTC().Add(-18*time.Hour + time.Minute)
		if _, err := db.DB.NewInsert().Model(&finding.Run{
			TargetID: target, Scanner: "grype", DatabaseVersion: "2026-09-18",
			RanHere: true, StartedAt: time.Now().UTC().Add(-18 * time.Hour),
			FinishedAt: &finished,
		}).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		watch := notify.NewWatch(db.DB, quiet)
		// Eighteen hours is nothing against the shipped week.
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if body := staleness(t, db, admin); body != "" {
			t.Fatalf("the shipped week raised %q about data eighteen hours old", body)
		}

		if _, _, err := setting.NewStore(db.DB).Change(ctx,
			setting.VulnerabilityDataStaleAfter, "12h"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		body := staleness(t, db, admin)
		if body == "" {
			t.Fatal("the window was set to twelve hours and eighteen-hour-old data " +
				"was not reported: nothing reads the setting")
		}
		if strings.Contains(body, "0 days") {
			t.Errorf("the alert says %q, which is what arithmetic gives and not "+
				"what anybody says", body)
		}
	})
}

// The data in force is the newest run's version, dated from when a version
// was last seen for the first time, beside how long counts as stopped.
func TestTheDataInForceIsTheNewestVersionDatedFromWhenItFirstArrived(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		watch := notify.NewWatch(db.DB, slog.New(slog.NewTextHandler(io.Discard, nil)))

		none, err := watch.DataInForce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if none.Version != "" || none.Since != nil || none.After <= 0 {
			t.Fatalf("with nothing run the data reads %+v", none)
		}

		ran := ranOn(t, db, aScannedTarget(t, w))
		ran(9, "v5:2026-01-01")
		ran(5, "v5:2026-01-05")
		ran(2, "v5:2026-01-05")
		got, err := watch.DataInForce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got.Version != "v5:2026-01-05" {
			t.Errorf("the data in force reads %q", got.Version)
		}
		arrived := time.Now().UTC().Add(-5 * 24 * time.Hour)
		if got.Since == nil || got.Since.Sub(arrived).Abs() > time.Hour {
			t.Errorf("the data last moved at %v, want about %v", got.Since, arrived)
		}
	})
}

func ranOn(t *testing.T, db *database.DB, target int64) func(daysAgo int, version string) {
	t.Helper()
	return func(daysAgo int, version string) {
		t.Helper()
		at := time.Now().UTC().Add(-time.Duration(daysAgo) * 24 * time.Hour)
		finished := at.Add(time.Minute)
		if _, err := db.DB.NewInsert().Model(&finding.Run{
			TargetID: target, Scanner: "grype", DatabaseVersion: version,
			RanHere: true, StartedAt: at, FinishedAt: &finished,
		}).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

// staleness is what this administrator is currently being told about the
// vulnerability data, or nothing.
func staleness(t *testing.T, db *database.DB, admin *access.Account) string {
	t.Helper()
	rows, _, err := notify.NewStore(db.DB).Waiting(t.Context(), asks(t, db, admin), 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Kind == notify.VulnerabilityDataStale {
			return row.Body
		}
	}
	return ""
}
