package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestARowCarriesItsOwnAgeAndSaysWhyItHasNoDeadline(t *testing.T) {
	// The age a deadline relates to is how long this has been open here,
	// and a blank deadline column would mean two deliberate things at once
	// on the one screen whose purpose is noticing what is running out.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if err := f.setting(t, "triage.floor", "medium"); err != nil {
			t.Fatal(err)
		}
		run := f.run(t)
		quiet := found("CVE-2026-QUIET", swss)
		quiet.Issue.Severity = "low"
		loud := found("CVE-2026-LOUD", teamd)
		loud.Issue.Severity = "high"
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{quiet, loud}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicTriage)
		// Below the line as well, because what it says about itself is the
		// point and it is out of the list by default.
		line := finding.Filter{Floor: finding.Floor{Word: "medium"}, BelowFloor: true}

		rows := func(t *testing.T) map[string]finding.Group {
			t.Helper()
			listed, _, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, line)
			if err != nil {
				t.Fatal(err)
			}
			by := make(map[string]finding.Group, len(listed))
			for _, row := range listed {
				by[row.Vulnerability] = row
			}
			return by
		}

		by := rows(t)
		above, below := by["CVE-2026-LOUD"], by["CVE-2026-QUIET"]

		if above.OpenedAt.IsZero() {
			t.Error("a row does not say when it opened, so nothing can say how old it is")
		}
		if above.DueAt == nil {
			t.Error("something above the line carries no deadline")
		}
		if above.NoDeadline != "" {
			t.Errorf("something with a deadline explains away the one it has: %q",
				above.NoDeadline)
		}

		if below.DueAt != nil {
			t.Error("something below the line is on a clock")
		}
		if below.NoDeadline != finding.BelowTheLine {
			t.Errorf("a finding below the line says %q, want it to say the line",
				below.NoDeadline)
		}

		// And the other reason. A release past its end of life takes the
		// deadline off everything in it, whatever the line says.
		gone := time.Now().UTC().AddDate(0, 0, -1)
		if err := catalog.NewStore(f.db.DB).SetStreamEndOfLife(
			t.Context(), *f.scope.StreamID, &gone); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Recompute(t.Context(), finding.DefaultWindows()); err != nil {
			t.Fatal(err)
		}
		if retired := rows(t)["CVE-2026-LOUD"]; retired.NoDeadline != finding.OutOfSupport {
			t.Errorf("a finding in a release past its end of life says %q, want it to say so",
				retired.NoDeadline)
		}
	})
}

func TestOnlyAnAllowedColumnReachesTheOrder(t *testing.T) {
	// The interface refuses an unknown sort by its own list of words,
	// which makes that the outer control; this is the inner one. A
	// placeholder cannot bind a column name, so if anything a caller sends
	// were ever to become the expression, it would be the one place in
	// this codebase where text reaches the statement.
	//
	// Asked of the store directly, because that is the only way to hand it
	// a key the interface would never pass on.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, run, []finding.Reported{
			found("CVE-2026-1", swss), found("CVE-2026-2", teamd),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicTriage)

		for _, hostile := range []finding.SortKey{
			"id",
			"urgency DESC, (SELECT identity FROM \"person\" LIMIT 1)",
			"places); DROP TABLE finding; --",
			"1",
			"f.assigned_to",
			"",
		} {
			rows, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
				finding.Filter{SortBy: hostile})
			if err != nil {
				t.Fatalf("a sort key nobody allows made the list fail rather than "+
					"fall back: %q: %v", hostile, err)
			}
			if total != 2 || len(rows) != 2 {
				t.Errorf("%q changed what the list answers: %d rows of %d",
					hostile, len(rows), total)
			}
		}

		// And every allowed one is a sort that works.
		for _, by := range finding.SortKeys() {
			if _, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
				finding.Filter{SortBy: by}); err != nil || total != 2 {
				t.Errorf("sorting by %q answered %d: %v", by, total, err)
			}
		}
	})
}
