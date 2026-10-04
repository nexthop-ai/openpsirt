// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package obligation_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// tag declares a tag of the fixture's product, with a release date where one
// is given.
func (f *fixture) tag(t *testing.T, name string, on *time.Time) *catalog.Stream {
	t.Helper()
	cat := catalog.NewStore(f.db.DB)
	stream, err := cat.DeclareStream(t.Context(), f.product, name, catalog.Tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	if on != nil {
		if err := cat.SetReleasedOn(t.Context(), stream.ID, on); err != nil {
			t.Fatal(err)
		}
	}
	return stream
}

// fromFix is the window counting from the fix, as the shelf runs it.
func (f *fixture) fromFix(t *testing.T, windowID int64) obligation.Due {
	t.Helper()
	shelf, err := f.store.Shelf(t.Context(), f.triager)
	if err != nil {
		t.Fatal(err)
	}
	if len(shelf) != 1 {
		t.Fatalf("%d incidents on the shelf, want 1", len(shelf))
	}
	for _, due := range shelf[0].Windows {
		if due.Window.ID == windowID {
			return due
		}
	}
	t.Fatal("the window counting from the fix is not on the shelf")
	return obligation.Due{}
}

func day(y int, m time.Month, d int) *time.Time {
	on := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	return &on
}

// A window counting from the fix starts at the start of the earliest release
// date stated for a tag the record names. A named tag with no stated date
// contributes nothing, its declaration date included, and with none stated
// the window has no start. Withdrawing the earliest moves the start to the
// next.
func TestAWindowCountingFromTheFixStartsAtTheEarliestStatedReleaseDate(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		window, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Fix available", Hours: 72, FromFix: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !window.FromFix {
			t.Fatal("the window declared from the fix does not say so")
		}
		record := f.attacked(t)

		waiting := f.fromFix(t, window.ID)
		if waiting.Started || !waiting.StartsAt.IsZero() || !waiting.EndsAt.IsZero() {
			t.Errorf("with no tag named the window reads %+v, want no start", waiting)
		}

		// The fixture's tag has no stated release date, only the day it was
		// declared.
		if _, err := f.store.NameFix(ctx, f.triager, record.ID, world.TagName); err != nil {
			t.Fatal(err)
		}
		if undated := f.fromFix(t, window.ID); undated.Started || !undated.StartsAt.IsZero() {
			t.Errorf("with only an undated tag named the window reads %+v, want no start", undated)
		}

		later := f.tag(t, "v2.5.0", day(2026, 9, 25))
		f.tag(t, "v2.4.2", day(2026, 9, 23))
		if _, err := f.store.NameFix(ctx, f.triager, record.ID, later.Name); err != nil {
			t.Fatal(err)
		}
		named, err := f.store.NameFix(ctx, f.triager, record.ID, "V2.4.2")
		if err != nil {
			t.Fatal(err)
		}
		started := f.fromFix(t, window.ID)
		if want := *day(2026, 9, 23); !started.Started || !started.StartsAt.Equal(want) {
			t.Errorf("the window starts %s (started %v), want %s", started.StartsAt, started.Started, want)
		}
		if want := day(2026, 9, 23).Add(72 * time.Hour); !started.EndsAt.Equal(want) {
			t.Errorf("the window ends %s, want %s", started.EndsAt, want)
		}

		if err := f.store.WithdrawFix(ctx, f.triager, record.ID, named.ID); err != nil {
			t.Fatal(err)
		}
		if moved := f.fromFix(t, window.ID); !moved.StartsAt.Equal(*day(2026, 9, 25)) {
			t.Errorf("after withdrawing the earliest the window starts %s, want 2026-09-25", moved.StartsAt)
		}

		// The release date is read when asked: correcting it moves the start.
		if err := catalog.NewStore(f.db.DB).SetReleasedOn(ctx, later.ID, day(2026, 9, 24)); err != nil {
			t.Fatal(err)
		}
		if moved := f.fromFix(t, window.ID); !moved.StartsAt.Equal(*day(2026, 9, 24)) {
			t.Errorf("after correcting the release date the window starts %s, want 2026-09-24", moved.StartsAt)
		}
	})
}

// A release date still to come is a start that has not arrived: the window
// says when it starts and is not counting, so nothing is near or passed.
func TestAFixReleaseStillToComeStartsNothingYet(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		window, err := f.store.DeclareWindow(ctx, f.admin, obligation.WindowSaid{
			Name: "Fix available", Hours: 24, LeadHours: ptr(1), FromFix: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		record := f.attacked(t)
		ahead := time.Now().UTC().AddDate(0, 1, 0)
		coming := f.tag(t, "v3.0.0", &ahead)
		if _, err := f.store.NameFix(ctx, f.triager, record.ID, coming.Name); err != nil {
			t.Fatal(err)
		}
		due := f.fromFix(t, window.ID)
		if due.Started || due.Passed || due.Near {
			t.Errorf("a window starting next month reads %+v, want not started", due)
		}
		y, m, d := ahead.Date()
		if want := time.Date(y, m, d, 0, 0, 0, 0, time.UTC); !due.StartsAt.Equal(want) {
			t.Errorf("the window starts %s, want %s", due.StartsAt, want)
		}
	})
}

// A window counts from one moment, so one counting from a notice and from the
// fix at once is refused.
func TestAWindowCountsFromTheFixOrANoticeNotBoth(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		notification := f.window(t, "Notification", 72)
		if _, err := f.store.DeclareWindow(t.Context(), f.admin, obligation.WindowSaid{
			Name: "Final report", Hours: 720, From: &notification.ID, FromFix: true,
		}); err == nil {
			t.Error("a window counting from a notice and from the fix was declared")
		}
		changed, err := f.store.ChangeWindow(t.Context(), f.admin, notification.ID, obligation.WindowSaid{
			Name: "Notification", Hours: 72, FromFix: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !changed.FromFix {
			t.Error("a window changed to count from the fix does not say so")
		}
		windows, err := f.store.Windows(t.Context(), f.admin)
		if err != nil {
			t.Fatal(err)
		}
		if len(windows) != 1 || !windows[0].FromFix {
			t.Errorf("read back, the windows are %+v, want one counting from the fix", windows)
		}
	})
}

// A fix is named in a tag of the record's product that is in use, once at a
// time. A branch, a retired tag, another product's tag and a name nobody
// declared are refused; a withdrawn tag may be named again.
func TestAFixIsNamedInATagOfTheRecordsProductOnceAtATime(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		record := f.attacked(t)
		cat := catalog.NewStore(f.db.DB)
		elsewhere, err := cat.ProductByName(ctx, "other")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareStream(ctx, elsewhere.ID, "v9.9.9", catalog.Tag, nil); err != nil {
			t.Fatal(err)
		}
		retired := f.tag(t, "v1.0.0", nil)
		if err := cat.RetireStream(ctx, retired.ID); err != nil {
			t.Fatal(err)
		}

		for _, tc := range []struct{ name, release string }{
			{"a branch", world.BranchName},
			{"a retired tag", retired.Name},
			{"another product's tag", "v9.9.9"},
			{"a tag nobody declared", "v0.0.1"},
			{"nothing", "  "},
		} {
			if _, err := f.store.NameFix(ctx, f.triager, record.ID, tc.release); err == nil {
				t.Errorf("%s was named as carrying the fix", tc.name)
			}
		}
		if _, err := f.store.NameFix(ctx, f.triager, record.ID, "v0.0.1"); !errors.Is(err, obligation.ErrNoSuchRelease) {
			t.Errorf("a tag nobody declared answered %v", err)
		}

		first, err := f.store.NameFix(ctx, f.triager, record.ID, world.TagName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.NameFix(ctx, f.triager, record.ID, world.TagName); !errors.Is(err, obligation.ErrFixNamed) {
			t.Errorf("naming the same tag twice answered %v", err)
		}
		if err := f.store.WithdrawFix(ctx, f.triager, record.ID, first.ID); err != nil {
			t.Fatal(err)
		}
		if err := f.store.WithdrawFix(ctx, f.triager, record.ID, first.ID); !errors.Is(err, obligation.ErrNoSuchFix) {
			t.Errorf("withdrawing a withdrawn naming answered %v", err)
		}
		if _, err := f.store.NameFix(ctx, f.triager, record.ID, world.TagName); err != nil {
			t.Errorf("a withdrawn tag could not be named again: %v", err)
		}

		fixes, err := f.store.FixesOf(ctx, f.triager, []int64{record.ID})
		if err != nil {
			t.Fatal(err)
		}
		got := fixes[record.ID]
		if len(got) != 2 {
			t.Fatalf("%d namings read back, want the withdrawn one and the one standing", len(got))
		}
		if got[0].Standing() || got[0].WithdrawnBy == nil || *got[0].WithdrawnBy != f.triager.ID {
			t.Errorf("the withdrawn naming reads %+v, want withdrawn by the triager", got[0])
		}
		if !got[1].Standing() || got[1].Release != world.TagName {
			t.Errorf("the standing naming reads %+v", got[1])
		}
	})
}

// Naming and withdrawing a fix release ask for triage on the record's product,
// and the namings are read only by whoever may be told of the attack.
func TestAFixIsNamedAndReadOnlyByWhoMayTriageTheProduct(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		record := f.attacked(t)
		if _, err := f.store.NameFix(ctx, f.outsider, record.ID, world.TagName); !errors.Is(err, obligation.ErrNoSuchRecord) {
			t.Errorf("somebody with nothing on the product naming a fix answered %v", err)
		}
		if _, err := f.store.NameFix(ctx, f.triager, record.ID+1000, world.TagName); !errors.Is(err, obligation.ErrNoSuchRecord) {
			t.Errorf("a record nobody kept answered %v", err)
		}
		named, err := f.store.NameFix(ctx, f.triager, record.ID, world.TagName)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.WithdrawFix(ctx, f.outsider, record.ID, named.ID); !errors.Is(err, obligation.ErrNoSuchRecord) {
			t.Errorf("somebody with nothing on the product withdrawing a fix answered %v", err)
		}
		if _, err := f.store.NameFix(ctx, access.Everything("a background pass"), record.ID,
			world.TagName); err == nil {
			t.Error("a fix was named by no person")
		}
		read, err := f.store.FixesOf(ctx, f.outsider, []int64{record.ID})
		if err != nil {
			t.Fatal(err)
		}
		if len(read) != 0 {
			t.Errorf("somebody with nothing on the product read %v", read)
		}
	})
}

// A cleared record is read as it stood: no release is named on it or
// withdrawn from it.
func TestAClearedRecordNamesNoFurtherFix(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		record := f.attacked(t)
		named, err := f.store.NameFix(ctx, f.triager, record.ID, world.TagName)
		if err != nil {
			t.Fatal(err)
		}
		if err := triage.NewStore(f.db.DB).ClearExploitedHere(ctx, f.triager, record.ID,
			"It was a test harness."); err != nil {
			t.Fatal(err)
		}
		other := f.tag(t, "v2.5.0", nil)
		if _, err := f.store.NameFix(ctx, f.triager, record.ID, other.Name); err == nil {
			t.Error("a release was named on a cleared record")
		}
		if err := f.store.WithdrawFix(ctx, f.triager, record.ID, named.ID); err == nil {
			t.Error("a release was withdrawn from a cleared record")
		}
	})
}

// Naming a fix release and withdrawing one are each a row in the
// administrative trail, beside the record they belong to.
func TestNamingAFixReleaseLandsInTheAdministrativeTrail(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		record := f.attacked(t)
		named, err := f.store.NameFix(ctx, f.triager, record.ID, world.TagName)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.WithdrawFix(ctx, f.triager, record.ID, named.ID); err != nil {
			t.Fatal(err)
		}
		var rows []struct {
			Kind   string         `bun:"kind"`
			By     sql.NullInt64  `bun:"by"`
			Was    sql.NullString `bun:"was"`
			Became sql.NullString `bun:"became"`
		}
		if err := f.db.DB.NewSelect().TableExpr(`"admin_change"`).
			ColumnExpr(`"kind", "by", "was", "became"`).
			Where("about = ?", "CVE-2026-1 on "+world.ProductName+", fix release").
			OrderExpr(`"id" ASC`).Scan(ctx, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("%d trail rows about the fix release, want 2", len(rows))
		}
		if rows[0].Kind != "exploited-here" || rows[0].By.Int64 != f.triager.ID ||
			rows[0].Was.Valid || rows[0].Became.String != world.TagName {
			t.Errorf("naming it trailed %+v", rows[0])
		}
		if rows[1].Was.String != world.TagName || rows[1].Became.Valid {
			t.Errorf("withdrawing it trailed %+v", rows[1])
		}
	})
}

// A named tag says whether its latest scans hold the issue open, once a scan
// of it exists, at the visibility the reader holds. It moves no window.
func TestAFixReleaseSaysWhetherItsLatestScansHoldTheIssueOpen(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		record := f.attacked(t)
		cat := catalog.NewStore(f.db.DB)
		tag, err := cat.StreamByName(ctx, f.product, world.TagName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.NameFix(ctx, f.triager, record.ID, world.TagName); err != nil {
			t.Fatal(err)
		}
		state := func(t *testing.T, subject access.Subject) finding.ReleaseState {
			t.Helper()
			fixes, err := f.store.FixesOf(ctx, subject, []int64{record.ID})
			if err != nil {
				t.Fatal(err)
			}
			if len(fixes[record.ID]) != 1 {
				t.Fatalf("%d namings read, want 1", len(fixes[record.ID]))
			}
			return fixes[record.ID][0].State
		}
		if got := state(t, f.triager); got.Scanned || got.Open {
			t.Errorf("a tag nobody scanned reads %+v", got)
		}

		variant, err := cat.VariantByName(ctx, f.product, world.CustomerVariant)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, tag.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		run, err := finding.NewStore(f.db.DB).Begin(ctx, finding.Run{
			TargetID: target.ID, Scanner: "grype", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Table("target").Set("last_run_id = ?", run.ID).
			Where("id = ?", target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if got := state(t, f.triager); !got.Scanned || got.Open {
			t.Errorf("a scanned tag holding nothing of the issue reads %+v", got)
		}

		// Undisclosed at the tag: the insider reads it open and the triager,
		// who reads disclosed findings only, does not.
		var component int64
		if err := f.db.DB.NewSelect().TableExpr(`"component"`).ColumnExpr(`"id"`).
			Limit(1).Scan(ctx, &component); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		open := &finding.Finding{
			TargetID: target.ID, Kind: finding.Vulnerable, VulnerabilityID: f.issue,
			Visibility: access.Private, ComponentID: component, PlaceIdentity: "place-of-libfoo",
			LastChangedAt: now, OpenedAt: now, OpenedRunID: &run.ID,
		}
		if _, err := f.db.DB.NewInsert().Model(open).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if got := state(t, f.insider); !got.Open {
			t.Errorf("the insider reads the tag holding the issue as %+v", got)
		}
		if got := state(t, f.triager); got.Open {
			t.Errorf("a reader of disclosed findings reads an undisclosed one open: %+v", got)
		}

		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("closed_at = ?", now).Where("id = ?", open.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if got := state(t, f.insider); !got.Scanned || got.Open {
			t.Errorf("a tag whose finding closed reads %+v", got)
		}
	})
}
