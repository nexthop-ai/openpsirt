package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func TestTheLineKeepsThingsOutOfTheListAndSaysHowMany(t *testing.T) {
	// Below the line a finding is still recorded and still counted — it
	// leaves the working list, not the system — and the list says what it
	// is keeping out rather than showing a smaller number with nothing
	// explaining it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		run := f.run(t)

		low := found("CVE-2026-LOW", swss)
		low.Issue.Severity = "low"
		high := found("CVE-2026-HIGH", teamd)
		high.Issue.Severity = "high"
		// Rated in a word nobody recognizes. Unknown is not harmless, so it
		// is judged as a medium wherever severity is read.
		odd := found("CVE-2026-ODD", swss)
		odd.Issue.Severity = "unknown"
		// Being exploited is a fact about the world rather than a rating, so
		// no line sets it aside however it is scored.
		used := found("CVE-2026-USED", teamd)
		used.Issue.Severity = "low"
		used.Issue.Exploited = true

		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{low, high, odd, used}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicTriage)
		line := finding.Filter{Floor: finding.Floor{Word: "medium"}}

		rows, total, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, line)
		if err != nil {
			t.Fatal(err)
		}
		named := map[string]bool{}
		for _, row := range rows {
			named[row.Vulnerability] = true
		}
		for _, want := range []string{"CVE-2026-HIGH", "CVE-2026-ODD", "CVE-2026-USED"} {
			if !named[want] {
				t.Errorf("%s is at or above the line and was kept out", want)
			}
		}
		if named["CVE-2026-LOW"] {
			t.Error("a low was shown with the line set at medium")
		}
		if total != 3 {
			t.Errorf("the total counts %d, want the three the line admits", total)
		}

		hidden, err := f.store.Hidden(t.Context(), who, f.scope, line)
		if err != nil {
			t.Fatal(err)
		}
		if hidden != 1 {
			t.Errorf("the list says it is hiding %d, want the one low", hidden)
		}

		// And asking for them brings them back rather than needing the line
		// changed.
		open := line
		open.BelowFloor = true
		_, all, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, open)
		if err != nil {
			t.Fatal(err)
		}
		if all != 4 {
			t.Errorf("asking below the line counts %d, want all four", all)
		}
	})
}

func TestNothingBelowTheLineIsOnAClock(t *testing.T) {
	// A line says this is not work and a deadline says this is work and it
	// is late; holding both means one of them is lying.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if err := f.setting(t, "triage.floor", "medium"); err != nil {
			t.Fatal(err)
		}
		run := f.run(t)
		low := found("CVE-2026-QUIET", swss)
		low.Issue.Severity = "low"
		high := found("CVE-2026-LOUD", teamd)
		high.Issue.Severity = "high"
		if _, err := f.store.Apply(t.Context(), f.target, run,
			[]finding.Reported{low, high}); err != nil {
			t.Fatal(err)
		}

		if got := f.deadlineOrZero(t, "CVE-2026-QUIET"); !got.IsZero() {
			t.Errorf("something below the line is on a clock, due %s", got)
		}
		if got := f.deadlineOrZero(t, "CVE-2026-LOUD"); got.IsZero() {
			t.Error("something above the line has no deadline")
		}
	})
}

func TestAProductsOwnLineIsWhatAppliesToIt(t *testing.T) {
	// the line a deployment triages at's second half. A single number for
	// an estate is either too strict somewhere or too loose somewhere
	// else, so a product may say something different — and what it says
	// has to be what the line actually is, wherever the line is read.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		products := catalog.NewStore(f.db.DB)
		settings := setting.NewStore(f.db.DB)

		// Nothing said anywhere: the line hides nothing, which is what a
		// deployment starts with.
		line, err := finding.FloorFor(ctx, f.db.DB, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if line.Hides() || line.FromProduct {
			t.Errorf("with nothing stated the line is %+v, want one that hides nothing", line)
		}

		// The deployment states one, and the product inherits it.
		if err := settings.Set(ctx, setting.TriageFloor, "medium"); err != nil {
			t.Fatal(err)
		}
		line, err = finding.FloorFor(ctx, f.db.DB, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if line.Word != "medium" || line.FromProduct {
			t.Errorf("inherited line is %+v, want medium and not the product's own", line)
		}

		// The product says something stricter, and that is what applies.
		if err := products.SetTriageFloor(ctx, f.productID, "high"); err != nil {
			t.Fatal(err)
		}
		line, err = finding.FloorFor(ctx, f.db.DB, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if line.Word != "high" || !line.FromProduct {
			t.Errorf("the product's own line reads as %+v, want high and stated here", line)
		}

		// The deployment changes its mind and the product does not follow,
		// because it has an opinion of its own.
		if err := settings.Set(ctx, setting.TriageFloor, "low"); err != nil {
			t.Fatal(err)
		}
		line, err = finding.FloorFor(ctx, f.db.DB, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if line.Word != "high" {
			t.Errorf("the product followed the deployment while holding its own line: %+v", line)
		}

		// Cleared, and it follows again — including where the deployment has
		// moved since. Storing the deployment's word instead of clearing would
		// have frozen it at whatever it was the day somebody looked.
		if err := products.SetTriageFloor(ctx, f.productID, ""); err != nil {
			t.Fatal(err)
		}
		line, err = finding.FloorFor(ctx, f.db.DB, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if line.Word != "low" || line.FromProduct {
			t.Errorf("after clearing, the line is %+v, want the deployment's low", line)
		}
	})
}

func TestOneProductsLineLeavesAnotherAlone(t *testing.T) {
	// The reason it is per product at all: products differ in what they can
	// afford to ignore, and a line stated on one must not quietly narrow what
	// somebody sees on another.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other := f.inAnotherProduct(t, "another-product")
		products := catalog.NewStore(f.db.DB)
		if err := products.SetTriageFloor(ctx, f.productID, "critical"); err != nil {
			t.Fatal(err)
		}

		mine, err := finding.FloorFor(ctx, f.db.DB, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := finding.FloorFor(ctx, f.db.DB, f.productOf(t, other))
		if err != nil {
			t.Fatal(err)
		}
		if mine.Word != "critical" {
			t.Errorf("the product that stated a line reads as %+v", mine)
		}
		if theirs.Hides() || theirs.FromProduct {
			t.Errorf("a product that stated nothing reads as %+v", theirs)
		}
	})
}

func TestNothingOnAReleaseOutOfSupportIsOnAClock(t *testing.T) {
	// Otherwise the overdue figure and the escalation view fill
	// permanently with releases nobody will ever fix, and both stop being
	// read — which is the same failure a deadline nobody agreed to causes,
	// arrived at from another direction.
	//
	// Nothing is hidden by it: the findings are still recorded, still
	// counted and still reportable. What ends is the clock.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		for _, row := range f.open(t) {
			if row.DueAt == nil {
				t.Fatal("a finding on a supported release has no deadline, so this proves nothing")
			}
		}

		// Support ended yesterday.
		products := catalog.NewStore(f.db.DB)
		yesterday := time.Now().UTC().Add(-24 * time.Hour)
		if err := products.SetProductEndOfLife(ctx, f.productID, &yesterday); err != nil {
			t.Fatal(err)
		}

		// What is already open loses its clock when the policy is applied.
		if _, err := f.store.Recompute(ctx, finding.DefaultWindows()); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) == 0 {
			t.Fatal("the findings were removed rather than taken off the clock")
		}
		for _, row := range open {
			if row.DueAt != nil {
				t.Errorf("a finding on a release out of support is due %s", row.DueAt)
			}
		}

		// And a finding opening afterwards gets none either.
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
		}); err != nil {
			t.Fatal(err)
		}
		for _, row := range f.open(t) {
			if row.DueAt != nil {
				t.Errorf("a finding opened on a release out of support is due %s", row.DueAt)
			}
		}
	})
}

func TestAReleaseSaysWhenItGoesOutOfSupportOrFollowsItsProduct(t *testing.T) {
	// A date rather than a flag, reversible, and inherited rather than
	// copied — a release holding the product's current date would stop
	// following it the next time the product moved.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		products := catalog.NewStore(f.db.DB)
		stream := f.streamOf(t, f.target)

		held, err := products.EndOfLifeFor(ctx, stream)
		if err != nil {
			t.Fatal(err)
		}
		if held.On != nil || held.FromStream {
			t.Errorf("with nothing stated the date is %+v", held)
		}
		if held.Past(time.Now().UTC()) {
			t.Error("a release nobody has dated reads as out of support")
		}

		march := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
		if err := products.SetProductEndOfLife(ctx, f.productID, &march); err != nil {
			t.Fatal(err)
		}
		held, err = products.EndOfLifeFor(ctx, stream)
		if err != nil {
			t.Fatal(err)
		}
		if held.On == nil || !held.On.Equal(march) || held.FromStream {
			t.Errorf("the inherited date is %+v, want the product's March date", held)
		}

		// The release says something else, and that is what applies.
		june := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
		if err := products.SetStreamEndOfLife(ctx, stream, &june); err != nil {
			t.Fatal(err)
		}
		held, err = products.EndOfLifeFor(ctx, stream)
		if err != nil {
			t.Fatal(err)
		}
		if held.On == nil || !held.On.Equal(june) || !held.FromStream {
			t.Errorf("the release's own date is %+v, want its June date", held)
		}

		// Cleared, and it follows the product again — including where the
		// product has moved since.
		september := time.Date(2027, 9, 1, 0, 0, 0, 0, time.UTC)
		if err := products.SetProductEndOfLife(ctx, f.productID, &september); err != nil {
			t.Fatal(err)
		}
		if err := products.SetStreamEndOfLife(ctx, stream, nil); err != nil {
			t.Fatal(err)
		}
		held, err = products.EndOfLifeFor(ctx, stream)
		if err != nil {
			t.Fatal(err)
		}
		if held.On == nil || !held.On.Equal(september) || held.FromStream {
			t.Errorf("after clearing, the date is %+v, want the product's September date", held)
		}

		// And a product's date is reversible too, because extended support
		// happens and recreating a product to undo one is not an answer.
		if err := products.SetProductEndOfLife(ctx, f.productID, nil); err != nil {
			t.Fatal(err)
		}
		held, err = products.EndOfLifeFor(ctx, stream)
		if err != nil {
			t.Fatal(err)
		}
		if held.On != nil {
			t.Errorf("a cleared date is still %+v", held)
		}
	})
}
