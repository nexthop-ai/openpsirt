package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// A finding's provenance.
//
// **The question a corrected feed makes urgent.** A vulnerability database
// shipping bad data for a week is corrected afterwards, and the work done on
// the strength of it has to be found — "which scanner and which vulnerability
// database produced the finding you dismissed on 3 March" was unanswerable,
// because only the newest finished run's versions were ever reported.
func TestAFindingSaysWhatProducedIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		first, err := f.store.Begin(t.Context(), finding.Run{
			TargetID: f.target, Scanner: "grype", ScannerVersion: "0.100.0",
			DatabaseVersion: "2026-03-01", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(t.Context(), f.target, first.ID,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Finish(t.Context(), first.ID, "0.100.0", "2026-03-01", "", nil); err != nil {
			t.Fatal(err)
		}

		// A later run against a newer database, which finds the same thing.
		// It does not reopen the finding, so what produced it stays the run
		// that first said it — which is the whole point: the run that answers
		// now is not the run that answered.
		second, err := f.store.Begin(t.Context(), finding.Run{
			TargetID: f.target, Scanner: "grype", ScannerVersion: "0.101.0",
			DatabaseVersion: "2026-09-01", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(t.Context(), f.target, second.ID,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Finish(t.Context(), second.ID, "0.101.0", "2026-09-01", "", nil); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicRead)
		evidence, err := f.store.Detail(t.Context(), who, f.target,
			f.issueID(t, "CVE-2026-1"), f.componentID(t, libnl.Name))
		if err != nil {
			t.Fatal(err)
		}
		if evidence.FoundBy == nil {
			t.Fatal("the finding says nothing about what produced it")
		}
		if evidence.FoundBy.DatabaseVersion != "2026-03-01" {
			t.Errorf("produced by the database of %q, wanted the run that first said it",
				evidence.FoundBy.DatabaseVersion)
		}
		if evidence.FoundBy.ScannerVersion != "0.100.0" || evidence.FoundBy.Scanner != "grype" ||
			!evidence.FoundBy.RanHere {
			t.Errorf("produced by %+v", evidence.FoundBy)
		}
		if evidence.FoundBy.RanAt == nil {
			t.Error("the run that produced it says nothing about when it finished")
		}
		if evidence.OpenedAt.IsZero() {
			t.Error("the finding says nothing about when it first appeared")
		}
	})
}
