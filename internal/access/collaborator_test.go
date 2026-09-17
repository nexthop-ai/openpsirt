package access_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// TestBringingSomebodyIntoACaseTwiceLeavesOneGrant pins the same idempotence
// for a case, and reads back what the row carries.
//
// OnCase and CaseRows were both at 0.0%: who is on an embargoed case, and who
// put them there, are what is asked after a disclosure goes wrong.
func TestBringingSomebodyIntoACaseTwiceLeavesOneGrant(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		product := f.products["sonic"]
		person, err := f.store.Ensure(ctx, "ana", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		granter, err := f.store.Ensure(ctx, "bo", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		interned, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx,
			[]finding.Named{{Identifier: "CVE-2026-1", Severity: "high"}})
		if err != nil {
			t.Fatal(err)
		}
		issue := interned["CVE-2026-1"]

		for i := range 2 {
			if err := f.store.AddToCase(ctx, product, issue, person.ID, granter.ID); err != nil {
				t.Fatalf("bringing them in, attempt %d: %v", i+1, err)
			}
		}
		on, err := f.store.OnCase(ctx, product, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(on) != 1 || on[0] != person.ID {
			t.Errorf("the case carries %v, want the one person", on)
		}

		// And the row says who brought them in and when, which is what is
		// asked afterwards.
		rows, err := f.store.CaseRows(ctx, product, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("the case has %d rows, want one", len(rows))
		}
		if rows[0].AddedBy != granter.ID || rows[0].AddedAt.IsZero() {
			t.Errorf("the grant does not say who made it or when: %+v", rows[0])
		}

		// Taken off, the grant stops and the record stays.
		if err := f.store.RemoveFromCase(ctx, product, issue, person.ID, granter.ID); err != nil {
			t.Fatal(err)
		}
		on, err = f.store.OnCase(ctx, product, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(on) != 0 {
			t.Errorf("somebody taken off the case is still on it: %v", on)
		}
		rows, err = f.store.CaseRows(ctx, product, issue)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Errorf("CaseRows carries a withdrawn grant: %+v", rows)
		}
	})
}
