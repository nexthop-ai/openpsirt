// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestADeadlineRunsFromWhenTheFixExistedRatherThanFromWhenWeSawIt(t *testing.T) {
	// The common case for an inventory made of distribution packages: the
	// flaw is seen before upstream has released anything, and counting from
	// the sighting would set a deadline against a version that does not exist
	// yet.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		// Seen with nothing to take, then a fix appears a hundred days later.
		none := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-LATE", Severity: "high"},
			Component: libnl, FixState: finding.FixUnknown,
		}
		opening := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, opening,
			[]finding.Reported{none}); err != nil {
			t.Fatal(err)
		}
		f.backdate(t, opening, 100*24*time.Hour)
		f.backdateOpenings(t, 100*24*time.Hour)
		opened := f.startedAt(t, opening)

		released := none
		released.FixState = finding.FixedUpstream
		released.FixedIn = "3.5.7"
		arrived := opened.Add(100 * 24 * time.Hour)
		released.FixedAt = &arrived

		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{released}); err != nil {
			t.Fatal(err)
		}
		// Thirty days from when the fix existed, not from when the finding
		// opened — which would have been seventy days in the past.
		want := arrived.Add(finding.DefaultWindows().High)
		if got := f.deadline(t, "CVE-2026-LATE"); !got.Equal(want) {
			t.Errorf("the deadline is %s, want %s — counted from when the fix arrived",
				got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	})
}

// Rewriting every deadline under the windows counts from the same moment a
// scan counts from: the latest of the opening, the learning of exploitation,
// and the arrival of a fix. Recounted from the opening alone, a fix that
// arrived a hundred days in makes the finding seventy days overdue the moment
// somebody saves a window.
func TestRewritingTheWindowsCountsFromWhenTheFixArrived(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		none := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-LATE", Severity: "high"},
			Component: libnl, FixState: finding.FixUnknown,
		}
		early := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-EARLY", Severity: "high"},
			Component: swss, FixState: finding.FixUnknown,
		}
		opening := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, opening,
			[]finding.Reported{none, early}); err != nil {
			t.Fatal(err)
		}
		f.backdate(t, opening, 100*24*time.Hour)
		f.backdateOpenings(t, 100*24*time.Hour)
		opened := f.startedAt(t, opening)

		released := none
		released.FixState, released.FixedIn = finding.FixedUpstream, "3.5.7"
		// A day, as a feed dates a fix and as the column holds it.
		arrived := opened.Add(100 * 24 * time.Hour).Truncate(24 * time.Hour)
		released.FixedAt = &arrived
		// A fix dated before the opening leaves the clock at the opening.
		already := early
		already.FixState, already.FixedIn = finding.FixedUpstream, "1.0.1"
		before := opened.Add(-10 * 24 * time.Hour)
		already.FixedAt = &before
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{released, already}); err != nil {
			t.Fatal(err)
		}

		if _, err := f.store.Recompute(t.Context(), finding.DefaultWindows()); err != nil {
			t.Fatal(err)
		}
		if got, want := f.deadline(t, "CVE-2026-LATE"), arrived.Add(finding.DefaultWindows().High); !got.Equal(want) {
			t.Errorf("rewritten, the deadline is %s, want %s — counted from when the fix arrived",
				got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
		if got, want := f.deadline(t, "CVE-2026-EARLY"), opened.Add(finding.DefaultWindows().High); !got.Equal(want) {
			t.Errorf("rewritten, the deadline is %s, want %s — counted from the opening",
				got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	})
}

// Being attacked here keeps a finding below the line on the clock when the
// windows are rewritten, as it does when a scan counts it.
func TestRewritingTheWindowsKeepsAnIssueAttackedHereOnTheClock(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if err := catalog.NewStore(f.db.DB).SetTriageFloor(t.Context(), f.productID, "medium"); err != nil {
			t.Fatal(err)
		}
		low := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-ATTACKED", Severity: "low"},
			Component: libnl, FixState: finding.FixedUpstream, FixedIn: "3.9.0",
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{low}); err != nil {
			t.Fatal(err)
		}
		if err := finding.ExploitedHereChanged(t.Context(), f.db.DB,
			f.productID, f.issue(t, "CVE-2026-ATTACKED"), true); err != nil {
			t.Fatal(err)
		}
		if f.deadlineOrZero(t, "CVE-2026-ATTACKED").IsZero() {
			t.Fatal("an issue attacked here carries no deadline before anything is rewritten, so this checks nothing")
		}
		if _, err := f.store.Recompute(t.Context(), testWindows); err != nil {
			t.Fatal(err)
		}
		if f.deadlineOrZero(t, "CVE-2026-ATTACKED").IsZero() {
			t.Error("rewriting the windows took the deadline off an issue this product was attacked through")
		}
	})
}

func TestAFixThatLandedBeforeWeSawItLeavesTheDeadlineWhereItWas(t *testing.T) {
	// The other direction, and the ordinary case. If a fix already existed
	// when the finding opened, the clock starts at the sighting: the response
	// time genuinely is from when it was learned, and counting from an older
	// fix date would set a deadline in the past.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		long := time.Now().UTC().Add(-365 * 24 * time.Hour)
		old := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-OLD", Severity: "high"},
			Component: libnl, FixState: finding.FixedUpstream,
			FixedIn: "3.5.7", FixedAt: &long,
		}
		opening := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, opening,
			[]finding.Reported{old}); err != nil {
			t.Fatal(err)
		}
		want := f.startedAt(t, opening).Add(finding.DefaultWindows().High)
		if got := f.deadline(t, "CVE-2026-OLD"); !got.Equal(want) {
			t.Errorf("the deadline is %s, want %s — counted from when we saw it",
				got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	})
}

func TestNothingUpstreamWouldCloseItSoItCarriesNoDeadline(t *testing.T) {
	// A deadline nobody can meet is not a deadline. Where upstream has
	// released nothing, and where upstream has declined, there is no version
	// to take — and the clock runs anyway, so the overdue list carries rows no
	// upgrade would answer, which is how people stop reading the color.
	//
	// A scanner that did not answer is a different thing, and stays on the
	// clock: reading silence as "nothing exists" is a claim about the world
	// made out of a gap in a report.
	for _, one := range []struct {
		what       string
		identifier string
		state      finding.FixState
		clock      bool
	}{
		{"upstream has released nothing", "CVE-2026-NONE", finding.NoFix, false},
		{"upstream declined", "CVE-2026-DECLINED", finding.WontFix, false},
		{"the scanner did not say", "CVE-2026-SILENT", finding.FixUnknown, true},
		{"a fix exists", "CVE-2026-READY", finding.FixedUpstream, true},
	} {
		t.Run(one.what, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.shipped(t, twoConsumers())
				identifier := one.identifier
				reported := finding.Reported{
					Issue:     finding.Named{Identifier: identifier, Severity: "high"},
					Component: libnl, FixState: one.state,
				}
				if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
					[]finding.Reported{reported}); err != nil {
					t.Fatal(err)
				}
				due := f.deadlineOrZero(t, identifier)
				if one.clock && due.IsZero() {
					t.Errorf("%s carries no deadline, and an upgrade would answer it", one.what)
				}
				if !one.clock && !due.IsZero() {
					t.Errorf("%s carries a deadline of %s, and no upgrade would answer it",
						one.what, due.Format(time.RFC3339))
				}
				// It still exists and still ranks. What ends is the clock.
				if f.urgency(t, identifier) == 0 {
					t.Errorf("%s left the finding unranked", one.what)
				}
			})
		})
	}
}

func TestAFixArrivingStartsAClockThatWasNotRunning(t *testing.T) {
	// The corollary, and the half a rule keyed on what moved would miss: a fix
	// appearing upstream touches no ranking signal at all, so a deadline
	// recounted only when the ranking moved would leave the finding with none
	// for ever.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		none := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-APPEARS", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{none}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-APPEARS"); !due.IsZero() {
			t.Fatalf("a finding with nothing to take carries a deadline of %s", due)
		}

		released := none
		released.FixState = finding.FixedUpstream
		released.FixedIn = "3.5.7"
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{released}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-APPEARS"); due.IsZero() {
			t.Error("a fix appeared upstream and the finding still carries no deadline")
		}
	})
}

func TestUpstreamWithdrawingAFixStopsTheClock(t *testing.T) {
	// And back the other way, because the rule is one rule rather than two.
	// A finding whose fix is withdrawn has nothing to take again, and a
	// deadline left standing is one nobody can meet.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		released := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-WITHDRAWN", Severity: "high"},
			Component: libnl, FixState: finding.FixedUpstream, FixedIn: "3.5.7",
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{released}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-WITHDRAWN"); due.IsZero() {
			t.Fatal("a finding with a fix available carries no deadline")
		}

		gone := released
		gone.FixState, gone.FixedIn = finding.NoFix, ""
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{gone}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-WITHDRAWN"); !due.IsZero() {
			t.Errorf("the fix went away and the deadline of %s stayed", due.Format(time.RFC3339))
		}
	})
}

func TestNoOtherPathHandsBackAClockNothingCouldMeet(t *testing.T) {
	// The rule landed on the scan path and three other places write a
	// deadline. Each of them is reached by an ordinary act — somebody rating
	// an issue, an administrator saving a window, a feed reporting
	// exploitation — so a rule enforced on one of four is a rule that holds
	// until somebody does their job.
	//
	// Worse on a tag, which is scanned once: a branch corrects itself the next
	// night, and a tag keeps whatever it was handed for as long as the finding
	// is open.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		nothing := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-STUCK", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(ctx, f.target, f.run(t),
			[]finding.Reported{nothing}); err != nil {
			t.Fatal(err)
		}
		if due := f.deadlineOrZero(t, "CVE-2026-STUCK"); !due.IsZero() {
			t.Fatalf("a finding with nothing to take opened with a deadline of %s", due)
		}

		for _, act := range []struct {
			what string
			do   func(t *testing.T)
		}{
			{
				// Somebody rates the issue, which recounts every deadline it
				// is open against. Through the store rather than by writing a
				// rating row, because the recount is what is being tested and
				// a row written straight to the table never reaches it.
				"somebody rates the issue",
				func(t *testing.T) {
					t.Helper()
					f.recorded(t, 1, "someone")
					if _, err := f.store.Assess(ctx, f.holding(t, access.PublicTriage),
						f.productID, f.issue(t, "CVE-2026-STUCK"), "critical",
						"Reachable from the network in how we ship it."); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				// An administrator saves a remediation window, which recounts
				// every deadline in the deployment.
				"an administrator saves a window",
				func(t *testing.T) {
					t.Helper()
					shorter := testWindows
					shorter.High = 15 * 24 * time.Hour
					if _, err := f.store.Recompute(ctx, shorter); err != nil {
						t.Fatal(err)
					}
				},
			},
			{
				// A feed reports it as exploited, which sets an exploited
				// clock on every build it is open in.
				"a feed reports it exploited",
				func(t *testing.T) {
					t.Helper()
					exploited := nothing
					exploited.Issue.Exploited = true
					if _, err := f.store.Apply(ctx, f.target, f.run(t),
						[]finding.Reported{exploited}); err != nil {
						t.Fatal(err)
					}
				},
			},
		} {
			act.do(t)
			if due := f.deadlineOrZero(t, "CVE-2026-STUCK"); !due.IsZero() {
				t.Errorf("after %s, a finding with nothing to take carries %s",
					act.what, due.Format(time.RFC3339))
			}
		}
	})
}

func TestAFixDatedAfterWeSawItIsNotWhatTheClockRunsFrom(t *testing.T) {
	// The fix date is a feed's, parsed and never checked, and this rule made
	// it load-bearing. One entry dated two centuries out would carry the
	// deadline with it — and the finding would leave the overdue list and the
	// compliance rate for as long as it stayed open, which is the silent
	// disappearance this whole rule exists to stop, arriving through the field
	// that implements it.
	//
	// A fix cannot have arrived after the moment we saw that it had, so that
	// is the ceiling.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		ahead := time.Now().UTC().Add(180 * 365 * 24 * time.Hour)
		absurd := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-AHEAD", Severity: "high"},
			Component: libnl, FixState: finding.FixedUpstream,
			FixedIn: "3.9.0", FixedAt: &ahead,
		}
		opening := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, opening,
			[]finding.Reported{absurd}); err != nil {
			t.Fatal(err)
		}
		// Counted from when we saw it, as though the feed had said nothing.
		want := f.startedAt(t, opening).Add(finding.DefaultWindows().High)
		got := f.deadline(t, "CVE-2026-AHEAD")
		if !got.Equal(want) {
			t.Errorf("the deadline is %s, want %s — the fix date is in the future",
				got.Format(time.RFC3339), want.Format(time.RFC3339))
		}
	})
}

func TestAnUpstreamRefusalOfAnExploitedIssueKeepsItsDeadline(t *testing.T) {
	// A refusal leaves nothing to take, and on an issue nobody is using that
	// is no clock. On one somebody is using, the refusal leaves work only this
	// deployment can do, so the clock stays. Each case reaches one writer of
	// the column: the scan opening a finding, the scan learning exploitation
	// on one already open, a record that this product was attacked, and the
	// recount an edited window runs.
	refused := func(identifier string, exploited bool) finding.Reported {
		return finding.Reported{
			Issue: finding.Named{Identifier: identifier, Severity: "high",
				Exploited: exploited},
			Component: libnl, FixState: finding.WontFix,
		}
	}

	t.Run("opened exploited", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			f.shipped(t, twoConsumers())
			missing := refused("CVE-2026-NOFIX-USED", true)
			missing.FixState = finding.NoFix
			if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
				[]finding.Reported{refused("CVE-2026-REFUSED-USED", true), missing}); err != nil {
				t.Fatal(err)
			}
			if f.deadlineOrZero(t, "CVE-2026-REFUSED-USED").IsZero() {
				t.Error("an exploited issue upstream refuses to fix carries no deadline")
			}
			// A missing fix is not a refusal: one may arrive, and waiting is
			// the only way to meet a deadline set against it.
			if due := f.deadlineOrZero(t, "CVE-2026-NOFIX-USED"); !due.IsZero() {
				t.Errorf("an exploited issue with no fix released carries a deadline of %s", due)
			}
		})
	})

	t.Run("exploitation learned while open", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			f.shipped(t, twoConsumers())
			if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
				[]finding.Reported{refused("CVE-2026-REFUSED-LATER", false)}); err != nil {
				t.Fatal(err)
			}
			if due := f.deadlineOrZero(t, "CVE-2026-REFUSED-LATER"); !due.IsZero() {
				t.Fatalf("a refusal nobody is exploiting carries a deadline of %s", due)
			}
			if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
				[]finding.Reported{refused("CVE-2026-REFUSED-LATER", true)}); err != nil {
				t.Fatal(err)
			}
			if f.deadlineOrZero(t, "CVE-2026-REFUSED-LATER").IsZero() {
				t.Error("an issue became exploited, upstream refuses to fix it, and it carries no deadline")
			}
		})
	})

	t.Run("learned by scanning another build", func(t *testing.T) {
		// Learning reaches every open finding of the issue, and a build that
		// is not being scanned hears of it here or not at all.
		each(t, func(t *testing.T, f *fixture) {
			other := f.anotherBranch(t, "release-2")
			f.shippedTo(t, other, twoConsumers())
			if _, err := f.store.Apply(t.Context(), other, f.runOn(t, other),
				[]finding.Reported{refused("CVE-2026-REFUSED-ELSEWHERE", false)}); err != nil {
				t.Fatal(err)
			}
			if due := f.deadlineIn(t, other, "CVE-2026-REFUSED-ELSEWHERE"); !due.IsZero() {
				t.Fatalf("a refusal nobody is exploiting carries a deadline of %s", due)
			}
			f.shipped(t, twoConsumers())
			if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
				[]finding.Reported{refused("CVE-2026-REFUSED-ELSEWHERE", true)}); err != nil {
				t.Fatal(err)
			}
			if f.deadlineIn(t, other, "CVE-2026-REFUSED-ELSEWHERE").IsZero() {
				t.Error("a scan of one build learned the issue is exploited, and the refusal on another build carries no deadline")
			}
		})
	})

	t.Run("attacked here", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			f.shipped(t, twoConsumers())
			if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
				[]finding.Reported{refused("CVE-2026-REFUSED-HERE", false)}); err != nil {
				t.Fatal(err)
			}
			issue := f.issue(t, "CVE-2026-REFUSED-HERE")
			if err := finding.ExploitedHereChanged(t.Context(), f.db.DB,
				f.productID, issue, true); err != nil {
				t.Fatal(err)
			}
			if f.deadlineOrZero(t, "CVE-2026-REFUSED-HERE").IsZero() {
				t.Error("this product was attacked through an issue upstream refuses to fix, and it carries no deadline")
			}
			if err := finding.ExploitedHereChanged(t.Context(), f.db.DB,
				f.productID, issue, false); err != nil {
				t.Fatal(err)
			}
			if due := f.deadlineOrZero(t, "CVE-2026-REFUSED-HERE"); !due.IsZero() {
				t.Errorf("the record was cleared and the refusal still carries a deadline of %s", due)
			}
		})
	})

	t.Run("a window edited", func(t *testing.T) {
		each(t, func(t *testing.T, f *fixture) {
			f.shipped(t, twoConsumers())
			if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
				[]finding.Reported{
					refused("CVE-2026-REFUSED-KEPT", true),
					refused("CVE-2026-REFUSED-IDLE", false),
				}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.Recompute(t.Context(), testWindows); err != nil {
				t.Fatal(err)
			}
			if f.deadlineOrZero(t, "CVE-2026-REFUSED-KEPT").IsZero() {
				t.Error("editing a window took the deadline off an exploited refusal")
			}
			if due := f.deadlineOrZero(t, "CVE-2026-REFUSED-IDLE"); !due.IsZero() {
				t.Errorf("editing a window gave a refusal nobody exploits a deadline of %s", due)
			}
		})
	})
}
