// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// dated is a scanner whose data is dated a given moment.
type dated struct {
	at       time.Time
	reported []finding.Reported
	asked    int
}

func (d *dated) Name() string { return "stub" }

func (d *dated) Scan(_ context.Context, inventory io.Reader) (scanner.Result, error) {
	d.asked++
	_, _ = io.ReadAll(inventory)
	return scanner.Result{Version: "9.9.9", DatabaseVersion: d.at.Format(time.RFC3339),
		Reported: d.reported}, nil
}

// checkFixture is a branch build whose first inventory was replaced, with
// the moments that matter to its check.
type checkFixture struct {
	*runFixture
	old, replacement int64
	arrived          time.Time
	replaced         time.Time
	since            time.Time
}

var libnlFixed = at("libnl-3-200", "3.9.0")

// replacedInventory stores a second inventory moving the library, and dates
// both and the scan of the first.
func replacedInventory(t *testing.T, w *fixture.World) *checkFixture {
	t.Helper()
	f := &checkFixture{runFixture: newRun(t, w)}
	f.rebuilt(t, libnlFixed)
	return f.dated(t)
}

// replacedInventoryOf is replacedInventory with these two inventories.
func replacedInventoryOf(t *testing.T, w *fixture.World, first, second graph.Snapshot) *checkFixture {
	t.Helper()
	f := &checkFixture{runFixture: newRunOf(t, w, first)}
	f.rebuiltAs(t, second)
	return f.dated(t)
}

// dated dates the two inventories and the scan of the first.
func (f *checkFixture) dated(t *testing.T) *checkFixture {
	t.Helper()
	ctx := t.Context()

	var scans []int64
	if err := f.db.NewSelect().TableExpr(`"scan"`).ColumnExpr(`"id"`).
		Where(`"build_id" = ?`, f.build).OrderExpr(`"id"`).Scan(ctx, &scans); err != nil {
		t.Fatal(err)
	}
	f.old, f.replacement = scans[0], scans[1]
	f.arrived = time.Now().UTC().Add(-10 * 24 * time.Hour).Truncate(time.Second)
	f.since = f.arrived
	f.replaced = f.arrived.Add(3 * 24 * time.Hour)
	for id, when := range map[int64]time.Time{f.old: f.arrived, f.replacement: f.replaced} {
		if _, err := f.db.NewUpdate().Table("scan").Set(`"received_at" = ?`, when).
			Set(`"components" = ?`, 2).Where(`"id" = ?`, id).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// The first inventory's own scan, with data dated the day it arrived.
	findings := finding.NewStore(f.db.DB)
	run, err := findings.Begin(ctx, finding.Run{BuildID: f.build, Scanner: "stub", RanHere: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := findings.Finish(ctx, run.ID, "9.9.9", f.since.Format(time.RFC3339), "", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.NewUpdate().Table("scan_run").
		Set(`"started_at" = ?`, f.arrived.Add(time.Hour)).
		Set(`"finished_at" = ?`, f.arrived.Add(time.Hour)).
		Where(`"id" = ?`, run.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return f
}

// published files an issue as OSV dated it.
func (f *checkFixture) published(t *testing.T, name string, when time.Time) {
	t.Helper()
	ctx := t.Context()
	if _, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
		[]finding.Named{{Identifier: name, Severity: "high"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.NewUpdate().Table("vulnerability").
		Set(`"published_at" = ?`, when).Set(`"dates_asked_at" = ?`, time.Now().UTC()).
		Where(`"identifier" = ?`, name).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

func reportAt(name string, c graph.Described) finding.Reported {
	return finding.Reported{Issue: finding.Named{Identifier: name, Severity: "high"}, Component: c}
}

// check runs the check of the first inventory with data dated at.
func (f *checkFixture) check(t *testing.T, s *dated) *scanner.Checking {
	t.Helper()
	if _, err := f.queue.Add(t.Context(), queue.Check, strconv.FormatInt(f.old, 10)); err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	checking, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Check(t.Context())
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	return checking
}

func TestAReplacedInventoryRecordsWhatWasPublishedWhileItWasCurrent(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		meanwhile := f.arrived.Add(24 * time.Hour)
		f.published(t, "CVE-2026-0007", meanwhile)
		f.published(t, "CVE-2026-0008", f.arrived.Add(-5*24*time.Hour))
		f.published(t, "CVE-2026-0009", meanwhile)
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{
			// Published after the last scan, held only by the replaced inventory.
			reportAt("CVE-2026-0007", libnl),
			// Published before the last scan, which saw it or had no reason to.
			reportAt("CVE-2026-0008", libnl),
			// Held by the replacement too, whose own scan reports it.
			reportAt("CVE-2026-0009", swss),
		}}

		checking := f.check(t, s)
		if checking == nil {
			t.Fatal("a check was waiting and nothing was done")
		}
		if checking.Checked.Dated != 2 || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want two dated between the scan and the replacement and one recorded",
				checking.Checked)
		}
		var rows []finding.Finding
		if err := f.db.NewSelect().Model(&rows).Where(`"build_id" = ?`, f.build).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("%d findings recorded, want 1", len(rows))
		}
		got := rows[0]
		switch {
		case !got.OpenedAt.Equal(meanwhile):
			t.Errorf("opened at %s, want its publication at %s", got.OpenedAt, meanwhile)
		case got.ClosedAt == nil || !got.ClosedAt.Equal(f.replaced):
			t.Errorf("closed at %v, want the replacement at %s", got.ClosedAt, f.replaced)
		case got.ClosedBecause != finding.Upgraded || got.MovedTo != "3.9.0":
			t.Errorf("closed because %q moving to %q, want upgraded to 3.9.0", got.ClosedBecause, got.MovedTo)
		case got.OpenedRunID == nil || *got.OpenedRunID != checking.RunID ||
			got.ClosedRunID == nil || *got.ClosedRunID != checking.RunID:
			t.Errorf("opened by %v and closed by %v, want both the check run %d",
				got.OpenedRunID, got.ClosedRunID, checking.RunID)
		case got.DueAt != nil || got.AssignedTo != nil:
			t.Errorf("due %v and assigned %v, want neither: it was fixed before anybody knew",
				got.DueAt, got.AssignedTo)
		}

		var run finding.Run
		if err := f.db.NewSelect().Model(&run).Where(`"id" = ?`, checking.RunID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if run.CheckedScanID == nil || *run.CheckedScanID != f.old {
			t.Errorf("the run checked %v, want the replaced inventory %d", run.CheckedScanID, f.old)
		}

		// The receipt of the replaced upload carries it, and the replacement's
		// own receipt answers nothing from it.
		receipts, _, err := ingest.NewStore(f.db.DB).Receipts(ctx, access.Everything("a test reading receipts"), f.build, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range receipts {
			switch r.Scan.ID {
			case f.old:
				if r.Checked == nil || r.Checked.ID != checking.RunID {
					t.Errorf("the replaced upload's receipt carries check %v, want run %d", r.Checked, checking.RunID)
				}
			case f.replacement:
				if r.Checked != nil || (r.RunID != nil && *r.RunID == checking.RunID) {
					t.Error("the replacement's receipt answers from the check of the inventory before it")
				}
			}
		}
	})
}

func TestACheckWritesNothingAnExistingRowAlreadyCovers(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0007", f.arrived.Add(24*time.Hour))
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0007", libnl)}}
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("the first check recorded %+v, want 1", checking)
		}
		// Asked again, as a check that failed after writing would be.
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 0 {
			t.Fatalf("the second check recorded %+v, want nothing", checking)
		}
		n, err := f.db.NewSelect().Table("finding").Where(`"build_id" = ?`, f.build).Count(ctx)
		if err != nil || n != 1 {
			t.Fatalf("%d findings, %v; want 1", n, err)
		}
	})
}

func TestACheckWaitsForDataDatedPastTheSettleDelay(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		f.published(t, "CVE-2026-0007", f.arrived.Add(24*time.Hour))
		// A day after the replacement, inside the two days the check waits.
		s := &dated{at: f.replaced.Add(24 * time.Hour),
			reported: []finding.Reported{reportAt("CVE-2026-0007", libnl)}}
		if checking := f.check(t, s); checking != nil {
			t.Fatalf("checked with data dated inside the settle delay: %+v", checking)
		}
		n, err := f.db.NewSelect().Table("scan_run").Where(`"checked_scan_id" IS NOT NULL`).Count(ctx)
		if err != nil || n != 0 {
			t.Fatalf("%d check runs, %v; want none", n, err)
		}
		// Shortened, the same data is late enough.
		if _, _, err := setting.NewStore(f.db.DB).Change(ctx, setting.CheckSettle, "12h"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.NewUpdate().Table("job").Set(`"state" = ?`, queue.Failed).
			Where(`"kind" = ?`, queue.Check).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if checking := f.check(t, s); checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want one recorded", checking)
		}
	})
}

func TestADatelessIssueIsDatedByWhenItWasFirstSeenHere(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		// OSV was asked and knows nothing; the issue arrived here inside the
		// stretch the inventory was current.
		f.published(t, "CVE-2026-0007", f.arrived)
		if _, err := f.db.NewUpdate().Table("vulnerability").
			Set(`"published_at" = NULL`).Set(`"first_seen_at" = ?`, f.arrived.Add(36*time.Hour)).
			Where(`"identifier" = ?`, "CVE-2026-0007").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0007", libnl)}}
		checking := f.check(t, s)
		if checking == nil || checking.Checked.Recorded != 1 {
			t.Fatalf("checked %+v, want one recorded", checking)
		}
		var opened time.Time
		if err := f.db.NewSelect().Table("finding").Column("opened_at").
			Where(`"build_id" = ?`, f.build).Scan(ctx, &opened); err != nil {
			t.Fatal(err)
		}
		if want := f.arrived.Add(36 * time.Hour); !opened.Equal(want) {
			t.Errorf("opened at %s, want when it was first seen, %s", opened, want)
		}
	})
}

func TestAnIssueNobodyAskedAboutWaitsForTheDatePass(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		// Never seen here: the check files it and waits for OSV to be asked.
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0010", libnl)}}
		if checking := f.check(t, s); checking != nil {
			t.Fatalf("checked before the issue could be dated: %+v", checking)
		}
		n, err := f.db.NewSelect().Table("vulnerability").Where(`"identifier" = ?`, "CVE-2026-0010").Count(ctx)
		if err != nil || n != 1 {
			t.Fatalf("the issue is filed %d times, %v; want once, for the date pass to ask", n, err)
		}
	})
}

func TestEveryReplacedBranchInventoryIsOwedOneCheck(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		schedule := scanner.NewSchedule(f.db, f.queue, quiet, "test")
		owed := func() []string {
			var refs []string
			if err := f.db.NewSelect().Table("job").Column("reference").
				Where(`"kind" = ?`, queue.Check).Scan(ctx, &refs); err != nil {
				t.Fatal(err)
			}
			return refs
		}
		if _, err := schedule.Once(ctx); err != nil {
			t.Fatal(err)
		}
		// The newest data is the old scan's, dated before the replacement.
		if refs := owed(); len(refs) != 0 {
			t.Fatalf("checks %v asked for before any data is dated past the settle delay", refs)
		}
		f.published(t, "CVE-2026-0007", f.arrived.Add(24*time.Hour))
		s := &dated{at: time.Now().UTC(), reported: []finding.Reported{reportAt("CVE-2026-0007", libnl)}}
		f.waiting(t)
		if _, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(ctx); err != nil {
			t.Fatal(err)
		}
		if err := queue.NewLeases(f.db.DB).Release(ctx, scanner.ScheduleLease, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := schedule.Once(ctx); err != nil {
			t.Fatal(err)
		}
		refs := owed()
		if len(refs) != 1 || refs[0] != strconv.FormatInt(f.old, 10) {
			t.Fatalf("checks asked for %v, want the replaced inventory %d alone", refs, f.old)
		}
		quietly := scanner.NewRunner(f.db, f.queue, s, quiet, "test")
		if checking, err := quietly.Check(ctx); err != nil || checking == nil {
			t.Fatalf("check: %+v %v", checking, err)
		}
		if err := queue.NewLeases(f.db.DB).Release(ctx, scanner.ScheduleLease, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := schedule.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if refs := owed(); len(refs) != 1 {
			t.Fatalf("checks asked for %v after the one owed finished, want it alone", refs)
		}
	})
}

func TestAnInventoryReplacedBeforeTheUpgradeIsNeverAskedFor(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		f := replacedInventory(t, w)
		if _, err := f.db.NewUpdate().Table("scan").Set(`"replaced_unchecked" = ?`, true).
			Where(`"id" = ?`, f.old).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		s := &dated{at: time.Now().UTC()}
		f.waiting(t)
		if _, err := scanner.NewRunner(f.db, f.queue, s, quiet, "test").Once(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := scanner.NewSchedule(f.db, f.queue, quiet, "test").Once(ctx); err != nil {
			t.Fatal(err)
		}
		n, err := f.db.NewSelect().Table("job").Where(`"kind" = ?`, queue.Check).Count(ctx)
		if err != nil || n != 0 {
			t.Fatalf("%d checks asked for, %v; want none", n, err)
		}
	})
}
