// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A CVE record stating that a version is unaffected closes the finding a
// scanner's range opened there. The scanner still matches, so the finding is
// wanted, and it closes rather than opens.

// recordSays is the lines a record states, as a run hands them over.
const recordSays = `[{"entry":"Linux","version":"6.18.27","status":"unaffected","lessThanOrEqual":"6.18.*"}]`

// unaffectedBy is a report the issue's record excludes.
func unaffectedBy(component graph.Described, lines string) finding.Reported {
	r := found("CVE-2026-1", component)
	r.Unaffected = lines
	return r
}

// reported applies a run with the reports given, and answers what it changed.
func (f *fixture) reported(t *testing.T, reports ...finding.Reported) (finding.Applied, int64) {
	t.Helper()
	runID := f.run(t)
	applied, err := f.store.Apply(t.Context(), f.target, runID, reports)
	if err != nil {
		t.Fatal(err)
	}
	return applied, runID
}

func TestAnOpenFindingClosesOnTheScanWhoseRecordExcludesItsVersion(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if applied, _ := f.reported(t, found("CVE-2026-1", libnl)); applied.Opened != 2 {
			t.Fatalf("opened %d, want one per consumer", applied.Opened)
		}

		applied, runID := f.reported(t, unaffectedBy(libnl, recordSays))
		if applied.Closed != 2 || applied.Unaffected != 2 {
			t.Errorf("closed %d and unaffected %d, want 2 of each", applied.Closed, applied.Unaffected)
		}
		if open := f.open(t); len(open) != 0 {
			t.Errorf("%d findings the record excludes are still open", len(open))
		}
		rows := f.every(t)
		if len(rows) != 2 {
			t.Fatalf("%d rows, want the two that closed and no others", len(rows))
		}
		for _, row := range rows {
			if row.ClosedBecause != finding.Unaffected {
				t.Errorf("closed as %q, want %q", row.ClosedBecause, finding.Unaffected)
			}
			if row.ClosedRunID == nil || *row.ClosedRunID != runID {
				t.Error("the finding is not closed by the run that read the record")
			}
			if row.UnaffectedBy != recordSays {
				t.Errorf("the closed row keeps %q, want the record's lines", row.UnaffectedBy)
			}
		}
	})
}

func TestAFindingFirstSeenExcludedIsRecordedClosed(t *testing.T) {
	// Recorded rather than never opened: a release comparison against a build
	// that held the issue reads from this row that this one never did.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		applied, _ := f.reported(t, unaffectedBy(libnl, recordSays))
		if applied.Opened != 0 {
			t.Errorf("opened %d findings the record excludes", applied.Opened)
		}
		if applied.Unaffected != 2 {
			t.Errorf("unaffected %d, want 2", applied.Unaffected)
		}
		if applied.Unchanged() {
			t.Error("a run that recorded two unaffected findings reads as having changed nothing")
		}
		for _, row := range f.every(t) {
			if row.ClosedAt == nil || row.ClosedBecause != finding.Unaffected || row.DueAt != nil {
				t.Errorf("recorded closed %v because %q due %v, want closed as unaffected with no deadline",
					row.ClosedAt, row.ClosedBecause, row.DueAt)
			}
		}
	})
}

func TestRescanningAnExcludedBuildWritesNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		f.reported(t, unaffectedBy(libnl, recordSays))
		applied, _ := f.reported(t, unaffectedBy(libnl, recordSays))
		if !applied.Unchanged() {
			t.Errorf("re-scanning an excluded build wrote %+v", applied)
		}
		if rows := f.every(t); len(rows) != 2 {
			t.Errorf("%d rows after a second scan, want the same 2", len(rows))
		}
	})
}

func TestAnExcludedFindingKeepsTheLinesTheRecordStatesNow(t *testing.T) {
	// A record corrected in a way that still excludes the version moves the
	// evidence, and writes no new row.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		f.reported(t, unaffectedBy(libnl, recordSays))
		corrected := `[{"entry":"Linux","version":"6.18.20","status":"unaffected","lessThanOrEqual":"6.18.*"}]`
		f.reported(t, unaffectedBy(libnl, corrected))
		rows := f.every(t)
		if len(rows) != 2 {
			t.Fatalf("%d rows, want the same 2", len(rows))
		}
		for _, row := range rows {
			if row.UnaffectedBy != corrected {
				t.Errorf("the row keeps %q, want the corrected lines", row.UnaffectedBy)
			}
		}
	})
}

func TestAFindingOpensAgainWhenTheRecordStopsExcludingIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		f.reported(t, unaffectedBy(libnl, recordSays))

		applied, _ := f.reported(t, found("CVE-2026-1", libnl))
		if applied.Opened != 2 {
			t.Errorf("opened %d once the record stopped excluding it, want 2", applied.Opened)
		}
		for _, row := range f.open(t) {
			if row.UnaffectedBy != "" || row.ArrivedFrom != "" {
				t.Errorf("a reopened finding carries lines %q and arrived from %q, want neither",
					row.UnaffectedBy, row.ArrivedFrom)
			}
		}
	})
}

func TestABumpOntoAnExcludedVersionClosesAsAnUpgrade(t *testing.T) {
	// The version moved and the record says the new one is unaffected: the
	// bump reached past the issue. Superseded would say it is open at the new
	// version, and unaffected would say the old version never held it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		f.reported(t, found("CVE-2026-1", libnl))

		f.shipped(t, movedTo(libnlNew))
		applied, _ := f.reported(t, unaffectedBy(libnlNew, recordSays))
		if applied.Opened != 0 {
			t.Errorf("opened %d at a version the record excludes", applied.Opened)
		}
		rows := f.every(t)
		if len(rows) != 4 {
			t.Fatalf("%d rows, want the two that closed and the two recorded unaffected", len(rows))
		}
		for _, row := range rows {
			switch row.ComponentID {
			case rows[0].ComponentID:
				if row.ClosedBecause != finding.Upgraded {
					t.Errorf("the old version closed as %q, want %q", row.ClosedBecause, finding.Upgraded)
				}
			default:
				if row.ClosedBecause != finding.Unaffected {
					t.Errorf("the new version recorded as %q, want %q", row.ClosedBecause, finding.Unaffected)
				}
			}
		}
	})
}

func TestADeclaredPatchIsAskedBeforeTheRecord(t *testing.T) {
	// Both close the finding, and the build's word about its own code is the
	// one already on record.
	each(t, func(t *testing.T, f *fixture) {
		f.claimed(t, aPatch)
		applied, _ := f.reported(t, unaffectedBy(libnl, recordSays))
		if applied.Patched != 2 || applied.Unaffected != 0 {
			t.Errorf("patched %d and unaffected %d, want 2 patched", applied.Patched, applied.Unaffected)
		}
		for _, row := range f.every(t) {
			if row.ClosedBecause != finding.Patched || row.UnaffectedBy != "" {
				t.Errorf("closed as %q with lines %q, want patched and none", row.ClosedBecause, row.UnaffectedBy)
			}
		}
	})
}

func TestTheRegisterListsWhatTheRecordsClosedWithTheirLines(t *testing.T) {
	// A wrong record hides a real finding, so what the records closed has to
	// be listable on its own and readable against the record.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		f.reported(t, found("CVE-2026-1", libnl), found("CVE-2026-2", libnl))
		f.reported(t, unaffectedBy(libnl, recordSays), found("CVE-2026-2", libnl))

		who := f.holding(t, access.PublicRead)
		rows, err := f.store.RegisterPage(t.Context(), who, f.target,
			finding.Registering{Because: []finding.Closure{finding.Unaffected}}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 {
			t.Fatalf("kept %d rows, want the two places closed as unaffected", len(rows))
		}
		for _, row := range rows {
			if row.Vulnerability != "CVE-2026-1" || row.UnaffectedBy != recordSays || row.Met != nil {
				t.Errorf("kept %s with lines %q met %v, want CVE-2026-1, the record's lines and no deadline judged",
					row.Vulnerability, row.UnaffectedBy, row.Met)
			}
		}
	})
}

func TestAFindingTheRecordClosedMetAndMissedNoDeadline(t *testing.T) {
	// It carried a deadline while it was believed to be present. Closing it
	// says it never was, which is neither meeting the deadline nor missing it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		f.reported(t, found("CVE-2026-1", libnl))
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("due_at = ?", time.Now().UTC().Add(-48*time.Hour)).
			Where("target_id = ?", f.target).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		f.reported(t, unaffectedBy(libnl, recordSays))

		rates, err := f.store.Compliance(t.Context(), f.holding(t, access.PublicRead),
			f.wholeProduct(), time.Time{}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rates {
			if r.Closed != 0 || r.Late != 0 {
				t.Errorf("%s: %d closed and %d late against a deadline, for a release never affected",
					r.Severity, r.Closed, r.Late)
			}
		}
	})
}
