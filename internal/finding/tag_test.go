package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// The words people put on findings.
//
// Three controls, each watched failing before it was kept: the fold that makes
// two spellings one mark, the right that marking asks for, and the filter
// agreeing with the row about which findings carry a word.
func TestMarkingAFindingWithAWord(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
		}); err != nil {
			t.Fatal(err)
		}
		// A real person, because a mark records who made it and the row points
		// at one — a subject invented for a test passes on the engine that
		// does not check and fails on the three that do.
		who := f.someoneElse(t, access.PublicTriage)
		issue := f.issueID(t, "CVE-2026-1")
		component := f.componentID(t, libnl.Name)

		if err := f.store.TagIt(t.Context(), who, f.productID, issue, component,
			"  Waiting On Vendor "); err != nil {
			t.Fatal(err)
		}
		// The spelling somebody used is what comes back, because a mark shown
		// folded reads as the tool having changed what they wrote.
		on, err := f.store.TagsOn(t.Context(), f.productID, issue, component)
		if err != nil {
			t.Fatal(err)
		}
		if len(on) != 1 || on[0] != "Waiting On Vendor" {
			t.Fatalf("marked with %q, wanted the spelling that was typed", on)
		}

		// Marking again in another capitalization is the same mark rather than
		// a second one, and the first spelling stands: a tag that re-spelled
		// itself on every use would make the list of what exists unstable.
		if err := f.store.TagIt(t.Context(), who, f.productID, issue, component,
			"waiting on vendor"); err != nil {
			t.Fatal(err)
		}
		if on, err = f.store.TagsOn(t.Context(), f.productID, issue, component); err != nil {
			t.Fatal(err)
		}
		if len(on) != 1 || on[0] != "Waiting On Vendor" {
			t.Errorf("marking it twice left %q, wanted one mark spelled as first typed", on)
		}

		// A word says nothing on its own.
		if err := f.store.TagIt(t.Context(), who, f.productID, issue, component,
			"   "); err == nil {
			t.Error("an empty tag was accepted")
		}

		// Somebody who may only read may not mark: a tag changes what a
		// filtered list answers, so marking is triage.
		reader := f.holding(t, access.PublicRead)
		if err := f.store.TagIt(t.Context(), reader, f.productID, issue, component,
			"mine"); err == nil {
			t.Error("somebody who may only read marked a finding")
		}
		if err := f.store.Untag(t.Context(), reader, f.productID, issue, component,
			"waiting on vendor"); err == nil {
			t.Error("somebody who may only read took a mark off")
		}

		// The filter and the row agree. Both directions, because a filter that
		// never excludes and one that excludes everything look alike from one.
		all, allTotal, err := f.store.Groups(t.Context(), who, f.scope, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		if allTotal < 2 {
			t.Fatalf("wanted more than one group to narrow, got %d", allTotal)
		}
		kept, keptTotal, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			// Asked in a capitalization nobody typed, which is the point of
			// the fold.
			finding.Filter{Tags: []string{"WAITING ON VENDOR"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(kept) != 1 || keptTotal != 1 {
			t.Fatalf("the marked finding narrowed to %d rows and counted %d, wanted one of each",
				len(kept), keptTotal)
		}
		if kept[0].Vulnerability != "CVE-2026-1" || len(kept[0].Tags) != 1 ||
			kept[0].Tags[0] != "Waiting On Vendor" {
			t.Errorf("kept %s marked %q", kept[0].Vulnerability, kept[0].Tags)
		}
		// A row nobody marked carries no marks, so the page's single read is
		// keyed on the right row rather than smearing one row's tags over the
		// page.
		for _, row := range all {
			if row.Vulnerability == "CVE-2026-2" && len(row.Tags) != 0 {
				t.Errorf("an unmarked finding came back marked %q", row.Tags)
			}
		}
		// Two words are either pile, not both marks on one row. A
		// person's tags are their own filing, and asking for two of
		// them means "either of these" — asked as "both", a word
		// nobody used would empty the list rather than adding nothing
		// to it.
		either, eitherTotal, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Tags: []string{"waiting on vendor", "nobody wrote this"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(either) != 1 || eitherTotal != 1 {
			t.Errorf("a used word and an unused one kept %d rows and counted %d, "+
				"wanted the one that is marked", len(either), eitherTotal)
		}

		none, noneTotal, err := f.store.Groups(t.Context(), who, f.scope, 50, 0,
			finding.Filter{Tags: []string{"nobody wrote this"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(none) != 0 || noneTotal != 0 {
			t.Errorf("a word nobody used kept %d rows and counted %d", len(none), noneTotal)
		}

		// What is in use is what people wrote, which is what a filter offers.
		inUse, err := f.store.TagsInUse(t.Context(), who, f.productID)
		if err != nil {
			t.Fatal(err)
		}
		if len(inUse) != 1 || inUse[0] != "Waiting On Vendor" {
			t.Errorf("in use: %q", inUse)
		}

		// Taking off what is not there changes nothing, and taking off what is
		// there in another capitalization takes off the mark.
		if err := f.store.Untag(t.Context(), who, f.productID, issue, component,
			"never applied"); err != nil {
			t.Fatal(err)
		}
		if err := f.store.Untag(t.Context(), who, f.productID, issue, component,
			"WAITING on vendor"); err != nil {
			t.Fatal(err)
		}
		if on, err = f.store.TagsOn(t.Context(), f.productID, issue, component); err != nil {
			t.Fatal(err)
		}
		if len(on) != 0 {
			t.Errorf("after taking the mark off, %q remained", on)
		}
	})
}
