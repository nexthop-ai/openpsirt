package finding_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
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

// What kind of flaw an issue is, kept as rows rather than as a packed column.
//
// It was one comma-joined string, which made the filter that asks "is this
// issue a CWE-79" a substring match — and a substring match answers CWE-79 for
// a search for CWE-7 unless it is written as four patterns to respect the
// commas, none of which an index can be used for. Every other list in this
// schema is a table, and this is the one that was queried on.
//
// What the rows have to hold to: a second report adds what it knows, a report
// that carries no classification takes nothing away, and a re-scan of
// unchanged data writes nothing.
func TestWhatKindOfFlawAnIssueIsIsAddedToAndNeverTakenAway(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())

		kinds := func() []string {
			t.Helper()
			var rows []string
			if err := f.db.DB.NewSelect().TableExpr("\"vulnerability_weakness\" AS \"vw\"").
				Join("JOIN \"vulnerability\" AS \"v\" ON v.id = vw.vulnerability_id").
				ColumnExpr("vw.cwe").Where("v.identifier = ?", "CVE-2026-1").
				Order("vw.cwe").Scan(ctx, &rows); err != nil {
				t.Fatal(err)
			}
			return rows
		}
		reported := func(cwes ...string) {
			t.Helper()
			one := found("CVE-2026-1", swss)
			one.Issue.Weaknesses = cwes
			if _, err := f.store.Apply(ctx, f.target, f.run(t),
				[]finding.Reported{one}); err != nil {
				t.Fatal(err)
			}
		}

		reported("CWE-125")
		if got := kinds(); len(got) != 1 || got[0] != "CWE-125" {
			t.Fatalf("the first report recorded %v", got)
		}
		// A second feed knows another, and the same one again.
		reported("cwe-125", "CWE-787")
		if got := kinds(); len(got) != 2 || got[0] != "CWE-125" || got[1] != "CWE-787" {
			t.Errorf("a second report left %v, want both and no repeat", got)
		}
		// And a report that says nothing about the classification says
		// nothing about it, rather than unclassifying the issue.
		reported()
		if got := kinds(); len(got) != 2 {
			t.Errorf("a report carrying no classification left %v", got)
		}

		// The filter finds it, whole and not as a prefix.
		who := f.holding(t, access.PublicTriage)
		for _, each := range []struct {
			cwe  string
			want int
		}{{"CWE-125", 1}, {"cwe-787", 1}, {"CWE-12", 0}, {"CWE-1", 0}} {
			_, total, err := f.store.Groups(ctx, who, f.scope, 50, 0,
				finding.Filter{Weaknesses: []string{each.cwe}})
			if err != nil {
				t.Fatal(err)
			}
			if total != each.want {
				t.Errorf("%s kept %d groups, want %d", each.cwe, total, each.want)
			}
		}
	})
}
