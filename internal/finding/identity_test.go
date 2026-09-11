package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// One issue, however many names it goes by.
//
// Identity spans the aliases, because which identifier a report carries is a
// property of whichever database matched it rather than of the flaw.

func TestOneIssueUnderTwoNamesIsOneIssue(t *testing.T) {
	// Which identifier a scanner calls primary is a preference of whichever
	// database it consulted. A decision keyed on that choice would lapse the
	// day the scanner changed its mind.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		// First run: reported under an advisory identifier that knows the
		// national one as an alias.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("GHSA-aaaa-bbbb-cccc", libnl, "CVE-2026-1")}); err != nil {
			t.Fatal(err)
		}
		opened := f.open(t)
		if len(opened) != 2 {
			t.Fatalf("opened %d findings", len(opened))
		}

		// Second run: the same issue, reported the other way round.
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("the same issue under another name wrote %+v", applied)
		}

		var issues int
		if issues, err = f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).Count(t.Context()); err != nil {
			t.Fatal(err)
		}
		if issues != 1 {
			t.Errorf("%d vulnerabilities recorded, want 1", issues)
		}
	})
}

func TestAnAliasSuppliedLaterFindsTheIssueAlreadyHeld(t *testing.T) {
	// The order that matters. One scanner reports the national identifier and
	// nothing else; another later reports its own identifier and knows the
	// first as an alias. Only looking up the name a report happened to lead
	// with would make those two issues, splitting the findings and every
	// decision between them.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("GHSA-aaaa-bbbb-cccc", libnl, "CVE-2026-1")})
		if err != nil {
			t.Fatalf("an issue reported under a second name: %v", err)
		}
		if !applied.Unchanged() {
			t.Errorf("the same issue under a second name wrote %+v", applied)
		}

		issues, err := f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if issues != 1 {
			t.Errorf("%d vulnerabilities recorded, want 1", issues)
		}
	})
}

func TestAnIssueIsFiledUnderItsMostRecognizedName(t *testing.T) {
	// What somebody sees should be the name they will find in an advisory,
	// not whichever database the scanner happened to consult first.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("GHSA-aaaa-bbbb-cccc", libnl, "CVE-2026-1")}); err != nil {
			t.Fatal(err)
		}
		var held finding.Vulnerability
		if err := f.db.DB.NewSelect().Model(&held).Limit(1).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if held.Identifier != "CVE-2026-1" {
			t.Errorf("filed under %q, want the national identifier", held.Identifier)
		}
	})
}

func TestAnIssueAgainstSomethingWeDoNotHaveIsReported(t *testing.T) {
	// A report that does not match the inventory it was produced from is
	// worth seeing, not quietly discarding.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-9", at("openssl", "3.0.11"))})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Unplaced != 1 || applied.Opened != 0 {
			t.Errorf("applied %+v, want one unplaced and nothing opened", applied)
		}
	})
}
