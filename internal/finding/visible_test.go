// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Read access, asked of the store rather than of a handler.
//
// The rule is enforced in the data layer with a subject on the query, so these
// ask the store directly: a check that only a handler makes is a check the
// next handler forgets.

func TestOnlyWhatSomebodyMayReadIsRead(t *testing.T) {
	// Visibility on the query. The enforcement is on the query, so this tests
	// the query rather than a handler that remembered to ask.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// One of the two is not disclosed. Read first and then updated,
		// because one engine refuses to name the table being updated inside a
		// subquery of its own statement.
		var hidden int64
		if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			ColumnExpr("MIN(id)").Scan(t.Context(), &hidden); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("visibility = ?", access.Private).
			Where("id = ?", hidden).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		for _, c := range []struct {
			what   string
			who    access.Subject
			want   int
			denied bool
		}{
			{"public reader", f.holding(t, access.PublicRead), 1, false},
			{"public triager", f.holding(t, access.PublicTriage), 1, false},
			// The undisclosed half alone reads the undisclosed row and not
			// the disclosed one: each visibility is its own grant.
			{"private reader", f.holding(t, access.PrivateRead), 1, false},
			{"private triager", f.holding(t, access.PrivateTriage), 1, false},
			{"a reader of both", f.holding(t, access.PublicRead, access.PrivateRead), 2, false},
			{"a triager of both", f.holding(t, access.PublicTriage, access.PrivateTriage), 2, false},
			{"an approver alone", f.holding(t), 0, true},
			// An administrator holds no role here, so they read
			// nothing here. Administering the catalog is not reading
			// what is open against it, and this is the row that
			// says so.
			{"an administrator granted nothing", access.NewPerson(1, "admin", true, nil, 0), 0, true},
			{"an administrator granted private reading", f.admin(t, access.PublicRead, access.PrivateRead), 2, false},
			{"a pipeline", access.NewPipeline(1, "nightly", access.Scope{ProductID: f.productID}), 0, true},
		} {
			rows, err := f.store.Open(t.Context(), c.who, f.target)
			switch {
			case c.denied && !errors.Is(err, access.ErrDenied):
				t.Errorf("%s was not refused: %d rows, %v", c.what, len(rows), err)
			case c.denied:
				continue
			case err != nil:
				t.Errorf("%s: %v", c.what, err)
			case len(rows) != c.want:
				t.Errorf("%s read %d findings, want %d", c.what, len(rows), c.want)
			}
			for _, row := range rows {
				if !c.who.Reads(row.Visibility, f.productID) {
					t.Errorf("%s read a %s finding", c.what, row.Visibility)
				}
			}
		}
	})
}

func TestFindingsInAProductSomebodyHoldsNothingOnAreRefused(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// Holding everything, but on a different product.
		elsewhere := access.NewPerson(1, "elsewhere", false,
			map[int64][]access.Role{f.productID + 999: {access.PrivateRead}}, 0)

		if _, err := f.store.Open(t.Context(), elsewhere, f.target); !errors.Is(err, access.ErrDenied) {
			t.Errorf("reading another product's findings: %v", err)
		}
	})
}

func TestWhatIsOpenPerBuildIsNarrowedToWhatSomebodyMayRead(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
			found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		// One of the two issues undisclosed, so a reader sees a *smaller*
		// number rather than none. With everything hidden the checks below
		// never had a positive case, and the test could only fail by returning
		// something it should not — never by returning the wrong number.
		//
		// Every place of that issue, not one row: an issue sits at several
		// places, and hiding one leaves it visible through another, which is
		// correct and is what this counts.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("visibility = ?", access.Private).
			Where("vulnerability_id = ?", f.issueID(t, "CVE-2026-1")).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		open := func(who access.Subject) int {
			t.Helper()
			releases, err := f.store.Releases(t.Context(), who, f.productID)
			if err != nil {
				t.Fatalf("releases: %v", err)
			}
			total := 0
			for _, r := range releases {
				total += r.Open
			}
			return total
		}

		// Two issues at one component: two rows for somebody who may read
		// both, one for somebody who may read only what is disclosed.
		if got := open(f.holding(t, access.PublicRead, access.PrivateRead)); got != 2 {
			t.Errorf("a reader of everything was told %d, expected 2", got)
		}
		if got := open(f.holding(t, access.PublicRead)); got != 1 {
			t.Errorf("a reader of disclosed findings only was told %d, expected 1", got)
		}
		if got := open(access.NewPerson(2, "stranger", false, nil, 0)); got != 0 {
			t.Errorf("somebody with no rights was told %d", got)
		}
	})
}

// TestAPipelineKeyIsRefusedByTheReadRatherThanAnsweredEmpty pins the rule
// DESIGN-access.md places in the data layer, over the reads that answer a
// selection rather than one row.
//
// Roughly twenty of them answered a credential that is not a person with an
// empty result, so the invariant lived in one function at the HTTP edge — and
// a check in a handler is the one somebody forgets. Subject.Kind is a string,
// so the zero subject took every one of those branches too.
func TestAPipelineKeyIsRefusedByTheReadRatherThanAnsweredEmpty(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		key := access.NewPipeline(1, "nightly", access.Scope{ProductID: f.productID})
		// The zero subject, which is what a caller that forgot to resolve one
		// passes. Kind is a string, so it is not a Person either.
		var nobody access.Subject

		for _, who := range []struct {
			what    string
			subject access.Subject
		}{{"a pipeline key", key}, {"the zero subject", nobody}} {
			for _, read := range []struct {
				what string
				ask  func(access.Subject) error
			}{
				{"findings across products", func(s access.Subject) error {
					_, _, err := f.store.Anywhere(ctx, s, 10, 0, finding.Filter{})
					return err
				}},
				{"who is holding work", func(s access.Subject) error {
					_, err := f.store.HeldBy(ctx, s, f.productID)
					return err
				}},
				{"what the releases hold", func(s access.Subject) error {
					_, err := f.store.Releases(ctx, s, f.productID)
					return err
				}},
				{"what is running out of time", func(s access.Subject) error {
					_, _, err := f.store.RunningOut(ctx, s, finding.Scope{}, 14*24*time.Hour, 10)
					return err
				}},
			} {
				if err := read.ask(who.subject); !errors.Is(err, access.ErrDenied) {
					t.Errorf("%s asking %s got %v, want a refusal",
						who.what, read.what, err)
				}
			}
		}
	})
}
