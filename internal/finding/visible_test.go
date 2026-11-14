// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Read access, asked of the store rather than of a handler.
//
// The rule is enforced in the data layer with a subject on the query, so these
// ask the store directly: a check that only a handler makes is a check the
// next handler forgets.

// openOccurrences is how many occurrences the findings list shows open in the
// fixture's build to who.
func (f *fixture) openOccurrences(t *testing.T, who access.Subject) (int, error) {
	t.Helper()
	groups, _, err := f.store.Groups(t.Context(), who, f.scope, 100, 0, finding.Filter{})
	occurrences := 0
	for _, g := range groups {
		occurrences += g.Occurrences
	}
	return occurrences, err
}

func TestOnlyWhatSomebodyMayReadIsRead(t *testing.T) {
	// Visibility on the query. The enforcement is on the query, so this tests
	// the query rather than a handler that remembered to ask.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// One of the two is not disclosed. Read first and then updated,
		// because one engine refuses to name the table being updated inside a
		// subquery of its own statement.
		var hidden int64
		if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			ColumnExpr(`MIN("id")`).Scan(t.Context(), &hidden); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"visibility" = ?`, access.Private).
			Where(`"id" = ?`, hidden).Exec(t.Context()); err != nil {
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
			occurrences, err := f.openOccurrences(t, c.who)
			switch {
			case c.denied && !errors.Is(err, access.ErrDenied):
				t.Errorf("%s was not refused: %d occurrences, %v", c.what, occurrences, err)
			case c.denied:
				continue
			case err != nil:
				t.Errorf("%s: %v", c.what, err)
			case occurrences != c.want:
				t.Errorf("%s read %d occurrences, want %d", c.what, occurrences, c.want)
			}
		}
	})
}

func TestFindingsInAProductSomebodyHoldsNothingOnAreRefused(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// Holding everything, but on a different product.
		elsewhere := access.NewPerson(1, "elsewhere", false,
			map[int64][]access.Role{f.productID + 999: {access.PrivateRead}}, 0)

		if _, err := f.openOccurrences(t, elsewhere); !errors.Is(err, access.ErrDenied) {
			t.Errorf("reading another product's findings: %v", err)
		}
	})
}

func TestWhatIsOpenPerBuildIsNarrowedToWhatSomebodyMayRead(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.build, f.run(t), []finding.Reported{
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
		// Every occurrence of that issue, not one row: an issue sits at several
		// occurrences, and hiding one leaves it visible through another, which
		// is correct and is what this counts.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"visibility" = ?`, access.Private).
			Where(`"vulnerability_id" = ?`, f.issueID(t, "CVE-2026-1")).
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
		if _, err := f.store.Releases(t.Context(), access.NewPerson(2, "stranger", false, nil, 0),
			f.productID); !errors.Is(err, access.ErrDenied) {
			t.Errorf("somebody with no rights got %v, want a refusal", err)
		}
	})
}

// TestAPipelineKeyIsRefusedByTheReadRatherThanAnsweredEmpty pins the rule
// design-docs/access-enforcement.md places in the data layer, over the reads that answer a
// selection rather than one row.
//
// Refused by the read itself, because a check in a handler is the one somebody
// forgets. Subject.Kind is a string, so the zero subject is not a person either
// and takes the same branches.
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
					_, _, err := f.store.RunningOutPage(ctx, s, finding.Scope{}, 14*24*time.Hour, 10, 0)
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

// TestABuildsFindingsAreRefusedToWhoeverMayReadNoneOfThem pins one answer
// across the reads of one build: a subject that sees the product and may read
// none of its findings is refused, never answered empty. An empty answer says
// the build has nothing to report, which is a different statement from "you
// may not ask".
func TestABuildsFindingsAreRefusedToWhoeverMayReadNoneOfThem(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		runID := f.run(t)
		if _, err := f.store.Apply(ctx, f.build, runID,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		issue := f.open(t)[0].VulnerabilityID

		for _, who := range []struct {
			what    string
			subject access.Subject
		}{
			{"a pipeline key", access.NewPipeline(1, "nightly", access.Scope{ProductID: f.productID})},
			{"an administrator granted nothing", f.admin(t)},
			{"an approver alone", f.holding(t, access.Approver)},
		} {
			for _, read := range []struct {
				what string
				ask  func(access.Subject) error
			}{
				{"what is open", func(s access.Subject) error {
					_, err := f.openOccurrences(t, s)
					return err
				}},
				{"what each run changed", func(s access.Subject) error {
					_, err := f.store.Changes(ctx, s, f.build, []int64{runID})
					return err
				}},
				{"what no run changed", func(s access.Subject) error {
					_, err := f.store.Changes(ctx, s, f.build, nil)
					return err
				}},
				{"one run", func(s access.Subject) error {
					_, err := f.store.Ran(ctx, s, f.build, runID)
					return err
				}},
				{"the upgrades promised", func(s access.Subject) error {
					_, err := f.store.PlannedUpgradesFor(ctx, s, f.build)
					return err
				}},
				{"the patches carried", func(s access.Subject) error {
					_, _, err := f.store.CarriedPatches(ctx, s, f.build, "", 10, 0)
					return err
				}},
				{"what publishers said", func(s access.Subject) error {
					_, err := f.store.SaidAbout(ctx, s, f.productID, issue,
						[]string{"CVE-2026-1"}, "libnl", "", f.build, 0)
					return err
				}},
				{"how the builds stand", func(s access.Subject) error {
					_, _, err := f.store.HowItStands(ctx, s, f.productID)
					return err
				}},
				{"what the releases hold", func(s access.Subject) error {
					_, err := f.store.Releases(ctx, s, f.productID)
					return err
				}},
				{"the labels in use", func(s access.Subject) error {
					_, err := f.store.LabelsInUse(ctx, s, f.productID)
					return err
				}},
				{"how a release is trending", func(s access.Subject) error {
					_, err := f.store.ReleaseTrend(ctx, s,
						finding.Scope{ProductID: &f.productID}, 10)
					return err
				}},
			} {
				if err := read.ask(who.subject); !errors.Is(err, access.ErrDenied) {
					t.Errorf("%s asking %s got %v, want a refusal", who.what, read.what, err)
				}
			}
		}
	})
}

// A commitment carries no visibility of its own, so it is read through what it
// is about: one over undisclosed work is told to nobody who may not read that
// work. Without a decision that is its fold's findings in the build; argued by
// a decision it is every occurrence the decision covers, whatever the build's
// own findings are. A case widens no read of a build, so it reaches nothing
// here.
func TestACommitmentOverUndisclosedWorkIsToldOnlyToItsReaders(t *testing.T) {
	for _, argued := range []bool{false, true} {
		name := "without a decision"
		if argued {
			name = "argued by a decision"
		}
		t.Run(name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				ctx := t.Context()
				f.shipped(t, twoConsumers())
				f.foundOnLibnl(t)
				by := f.somebodyElse(t)
				decisionID := decisionSaying(t, f.db, by, "upgrade-needed")
				if argued {
					// The build's findings stay disclosed; the decision
					// covers an undisclosed occurrence, so only the
					// decision withholds the commitment.
					f.decision(t, decisionRow{
						By: by, Decision: decisionID, Issue: f.issue(t, "CVE-2026-1"),
						Occurrence: "libnl", State: "approved", Visibility: string(access.Private),
					})
				} else if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
					Set(`"visibility" = ?`, access.Private).Where("1 = 1").Exec(ctx); err != nil {
					t.Fatal(err)
				}
				committer := f.someoneElse(t, access.PrivateTriage)
				if _, err := f.store.CommitWithin(ctx, f.db.DB, committer, f.productID,
					f.componentID(t, libnl.Name), "3.9.0", nil, decisionID,
					[]int64{f.build}, map[int64]string{}); err != nil {
					t.Fatal(err)
				}
				// Every commitment this records names its decision, so one
				// without a decision is written directly.
				if !argued {
					if _, err := f.db.DB.NewUpdate().TableExpr(`"upgrade"`).
						Set(`"decision_id" = NULL`).Where("1 = 1").Exec(ctx); err != nil {
						t.Fatal(err)
					}
				}

				cases := []struct {
					what string
					who  access.Subject
					want int
				}{
					{"a reader of disclosed work alone", f.holding(t, access.PublicRead), 0},
					{"a reader of both", f.holding(t, access.PublicRead, access.PrivateRead), 1},
				}
				if argued {
					cases = append(cases, struct {
						what string
						who  access.Subject
						want int
					}{"somebody on the issue's case", f.holding(t, access.PublicRead).OnCases(
						map[int64][]int64{f.productID: {f.issue(t, "CVE-2026-1")}}), 0})
				}
				for _, c := range cases {
					planned, err := f.store.PlannedUpgradesFor(ctx, c.who, f.build)
					if err != nil {
						t.Fatal(err)
					}
					if len(planned) != c.want {
						t.Errorf("%s is told of %d commitments, want %d", c.what, len(planned), c.want)
						continue
					}
					if c.want == 1 && planned[0].State != finding.UpgradePlanned {
						t.Errorf("%s reads the commitment as %s, want planned", c.what, planned[0].State)
					}
				}
			})
		})
	}
}

// A commitment argued by a decision that covers nothing is told to nobody, as
// reading that decision answers it absent.
func TestACommitmentWhoseDecisionCoversNothingIsToldToNobody(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.foundOnLibnl(t)
		id := decisionSaying(t, f.db, f.somebodyElse(t), "upgrade-needed")
		committer := f.someoneElse(t, access.PrivateTriage)
		if _, err := f.store.CommitWithin(ctx, f.db.DB, committer, f.productID,
			f.componentID(t, libnl.Name), "3.9.0", nil, id,
			[]int64{f.build}, map[int64]string{}); err != nil {
			t.Fatal(err)
		}
		planned, err := f.store.PlannedUpgradesFor(ctx, f.holding(t, access.PublicRead, access.PrivateRead), f.build)
		if err != nil {
			t.Fatal(err)
		}
		if len(planned) != 0 {
			t.Errorf("a reader of everything is told of %d commitments over a decision covering nothing", len(planned))
		}
	})
}

// A decision row is read in its own product. A bulk decision can reach an
// undisclosed occurrence in a product the reader holds nothing on, and reading
// undisclosed work in the build's product says nothing about that one.
func TestACommitmentIsReadAtEachDecisionRowInItsOwnProduct(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		f.foundOnLibnl(t)
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "edge-router", "Edge")
		if err != nil {
			t.Fatal(err)
		}
		by := f.somebodyElse(t)
		id := decisionSaying(t, f.db, by, "upgrade-needed")
		issue := f.issue(t, "CVE-2026-1")
		f.decision(t, decisionRow{
			By: by, Decision: id, Issue: issue, Occurrence: "libnl", State: "approved",
		})
		f.decision(t, decisionRow{
			By: by, Decision: id, Product: other.ID, Issue: issue, Occurrence: "libnl",
			State: "approved", Visibility: string(access.Private),
		})
		committer := f.someoneElse(t, access.PrivateTriage)
		if _, err := f.store.CommitWithin(ctx, f.db.DB, committer, f.productID,
			f.componentID(t, libnl.Name), "3.9.0", nil, id,
			[]int64{f.build}, map[int64]string{}); err != nil {
			t.Fatal(err)
		}

		for _, c := range []struct {
			what string
			who  access.Subject
			want int
		}{
			{"a reader of both halves of this product alone",
				f.holding(t, access.PublicRead, access.PrivateRead), 0},
			{"a reader of both halves of both products",
				f.holdingIn(t, []int64{f.productID, other.ID}, access.PublicRead, access.PrivateRead), 1},
		} {
			planned, err := f.store.PlannedUpgradesFor(ctx, c.who, f.build)
			if err != nil {
				t.Fatal(err)
			}
			if len(planned) != c.want {
				t.Errorf("%s is told of %d commitments, want %d", c.what, len(planned), c.want)
			}
		}
	})
}
