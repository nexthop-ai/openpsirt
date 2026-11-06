// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// dismissal is a decision about every open finding of one issue, written as
// the triage store writes one: a decision, a revision, an agreement where it
// needs one, and a row per occurrence at the versions the finding holds.
type dismissal struct {
	issue   string
	outcome string
	// Proposed is when it was made; Agreed when a second person agreed, nil
	// for one waiting; Withdrawn when that agreement was taken back; Ended
	// when the row stopped applying.
	proposed          time.Time
	agreed, withdrawn *time.Time
	ended             *time.Time
	needsNobody       bool
	state             string
	// oneOccurrence answers only the first open finding of the issue.
	oneOccurrence bool
}

func (f *fixture) dismissed(t *testing.T, d dismissal) {
	t.Helper()
	ctx := t.Context()
	by := f.somebodyElse(t)
	outcome := d.outcome
	if outcome == "" {
		outcome = finding.OutcomeNotApplicable
	}
	decision := decisionSaying(t, f.db, by, outcome)
	revision := map[string]any{
		"decision_id": decision, "ordinal": 1, "body": "not reachable", "written_by": by,
		"written_at": d.proposed,
	}
	if _, err := f.db.DB.NewInsert().Model(&revision).TableExpr(`"decision_revision"`).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var revisionID int64
	if err := f.db.DB.NewSelect().TableExpr(`"decision_revision"`).ColumnExpr(`MAX("id")`).
		Scan(ctx, &revisionID); err != nil {
		t.Fatal(err)
	}
	if d.agreed != nil {
		approval := map[string]any{
			"decision_id": decision, "revision_id": revisionID, "approved_by": by, "approved_at": *d.agreed,
		}
		if d.withdrawn != nil {
			approval["withdrawn_at"] = *d.withdrawn
		}
		if _, err := f.db.DB.NewInsert().Model(&approval).TableExpr(`"decision_approval"`).Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	state := d.state
	if state == "" {
		state = "approved"
	}
	for i, row := range f.open(t) {
		if row.VulnerabilityID != f.issueID(t, d.issue) {
			continue
		}
		component := f.upstreamOf(t, row.ComponentID)
		occurrence := decisionRow{
			By: by, Decision: decision, Issue: row.VulnerabilityID, Occurrence: row.OccurrenceIdentity,
			State: state, Unreviewed: d.needsNobody, Component: &component, ProposedAt: d.proposed,
			Ended: d.ended,
		}
		if row.ConsumerID != nil {
			consumer := f.upstreamOf(t, *row.ConsumerID)
			occurrence.Consumer = &consumer
		}
		if d.ended == nil {
			occurrence.Key = d.issue + string(rune('a'+i))
		}
		f.decision(t, occurrence)
		if d.oneOccurrence {
			return
		}
	}
}

// upstreamOf is the version a decision about a component is keyed on.
func (f *fixture) upstreamOf(t *testing.T, component int64) string {
	t.Helper()
	var version string
	if err := f.db.DB.NewSelect().TableExpr(`"component" AS "c"`).
		ColumnExpr(finding.ComponentUpstreamExpr).Where(`"c"."id" = ?`, component).
		Scan(t.Context(), &version); err != nil {
		t.Fatal(err)
	}
	return version
}

// burned is the sum of each flow over a burndown, and what is left at its end.
type burned struct{ left, fresh, returned, fixed, dismissed, restored, baseline int }

func burnedOver(b *finding.Burndown) burned {
	var out burned
	for _, p := range b.Points {
		out.fresh += p.New
		out.returned += p.Returned
		out.fixed += p.Fixed
		out.dismissed += p.Dismissed
		out.restored += p.Restored
		out.baseline += p.Baseline
	}
	if len(b.Points) > 0 {
		out.left = b.Points[len(b.Points)-1].Left
	}
	return out
}

// pointOn is the burndown's day holding a moment.
func pointOn(b *finding.Burndown, at time.Time) finding.BurnPoint {
	for _, p := range b.Points {
		if !p.At.Before(at) {
			return p
		}
	}
	return finding.BurnPoint{}
}

func ago(days int) time.Time { return time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour) }

// fourIssues is a first scan of three issues and a later one adding a fourth on
// the same component as the first.
func (f *fixture) fourIssues(t *testing.T) {
	t.Helper()
	f.scannedAt(t, twoConsumers(), ago(20),
		found("CVE-2026-1", libnl), found("CVE-2026-2", teamd), found("CVE-2026-3", swss))
	f.scannedAt(t, twoConsumers(), ago(15),
		found("CVE-2026-1", libnl), found("CVE-2026-2", teamd), found("CVE-2026-3", swss),
		found("CVE-2026-4", libnl))
}

func (f *fixture) burndown(t *testing.T, least string, within finding.Within) *finding.Burndown {
	t.Helper()
	return f.burndownSince(t, time.Time{}, least, within)
}

func (f *fixture) burndownSince(t *testing.T, since time.Time, least string, within finding.Within) *finding.Burndown {
	t.Helper()
	b, err := f.store.Burndown(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
		since, least, within)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestABurndownCountsAFixAndADismissalInForceAsDoneAndAWaitingOneAsLeft(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.fourIssues(t)
		f.closeIt(t, "CVE-2026-1", finding.Upgraded, ago(10))
		agreed := ago(8)
		f.dismissed(t, dismissal{issue: "CVE-2026-2", proposed: ago(9), agreed: &agreed})
		// A proposal nobody agreed to answers nothing.
		f.dismissed(t, dismissal{issue: "CVE-2026-3", proposed: ago(6), state: "proposed"})

		b := f.burndown(t, "", finding.Within{})
		if got := burnedOver(b); got != (burned{left: 2, fresh: 1, fixed: 1, dismissed: 1, baseline: 3}) {
			t.Errorf("counted %+v, want three baseline, one new, one fixed, one dismissed and two left", got)
		}
		if p := pointOn(b, agreed); p.Dismissed != 1 {
			t.Errorf("the day it was agreed says %d dismissed, want the dismissal counted when it took effect", p.Dismissed)
		}
		if want := ago(20).Truncate(24 * time.Hour); !b.Since.Equal(want) {
			t.Errorf("day 0 is %s, want the day the first scan found anything, %s", b.Since, want)
		}
		if b.Start != 0 {
			t.Errorf("%d were left before day 0, want none before the first scan", b.Start)
		}
	})
}

func TestADismissalNeedingNobodyIsDoneFromItsProposal(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.fourIssues(t)
		f.dismissed(t, dismissal{issue: "CVE-2026-2", proposed: ago(7), needsNobody: true, state: "proposed"})

		b := f.burndown(t, "", finding.Within{})
		if p := pointOn(b, ago(7)); p.Dismissed != 1 {
			t.Errorf("the day it was proposed says %d dismissed, want one", p.Dismissed)
		}
	})
}

func TestADismissalThatStopsStandingPutsTheIssueBackAsReturned(t *testing.T) {
	// A lapsed or withdrawn dismissal answered the issue for a while. It is
	// back now, so it is not done, and coming back is a return.
	for name, d := range map[string]func(agreed, stopped time.Time) dismissal{
		"lapsed": func(agreed, stopped time.Time) dismissal {
			return dismissal{issue: "CVE-2026-2", proposed: agreed, agreed: &agreed, ended: &stopped, state: "lapsed"}
		},
		"agreement withdrawn": func(agreed, stopped time.Time) dismissal {
			return dismissal{issue: "CVE-2026-2", proposed: agreed, agreed: &agreed, withdrawn: &stopped, state: "proposed"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.fourIssues(t)
				f.dismissed(t, d(ago(8), ago(4)))

				b := f.burndown(t, "", finding.Within{})
				if got := burnedOver(b); got.dismissed != 0 || got.returned != 1 || got.left != 4 {
					t.Errorf("counted %+v, want nothing dismissed, one returned and four left", got)
				}
				if p := pointOn(b, ago(4)); p.Returned != 1 {
					t.Errorf("the day it stopped says %d returned, want one", p.Returned)
				}
				if p := pointOn(b, ago(6)); p.Left != 3 {
					t.Errorf("while it stood %d were left, want three", p.Left)
				}
			})
		})
	}
}

func TestAStatementThatItIsNotAffectedIsDoneAndAClosureThatIsNoFixIsNot(t *testing.T) {
	for _, one := range []struct {
		because          finding.Closure
		fixed, dismissed int
	}{
		{finding.Disclaimed, 0, 1},
		{finding.Patched, 1, 0},
		{finding.Superseded, 0, 0},
		{finding.Unexplained, 0, 0},
	} {
		t.Run(string(one.because), func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.fourIssues(t)
				f.closeIt(t, "CVE-2026-3", one.because, ago(5))

				got := burnedOver(f.burndown(t, "", finding.Within{}))
				if got.fixed != one.fixed || got.dismissed != one.dismissed || got.left != 3 {
					t.Errorf("closed as %s counted %+v, want %d fixed, %d dismissed and three left",
						one.because, got, one.fixed, one.dismissed)
				}
			})
		})
	}
}

func TestADeferralAndAPromiseAreNotDone(t *testing.T) {
	for _, outcome := range []string{finding.OutcomeDeferred, finding.OutcomeUpgradeNeeded, finding.OutcomeAffected} {
		t.Run(outcome, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.fourIssues(t)
				agreed := ago(8)
				f.dismissed(t, dismissal{issue: "CVE-2026-2", outcome: outcome, proposed: agreed, agreed: &agreed})

				if got := burnedOver(f.burndown(t, "", finding.Within{})); got.dismissed != 0 || got.left != 4 {
					t.Errorf("a %s decision counted %+v, want nothing done and four left", outcome, got)
				}
			})
		})
	}
}

func TestTheProjectionReachesZeroOnlyWhereDoneOutrunsAdded(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.fourIssues(t)
		f.closeIt(t, "CVE-2026-1", finding.Upgraded, ago(10))
		f.closeIt(t, "CVE-2026-2", finding.Upgraded, ago(9))

		ahead := f.burndown(t, "", finding.Within{}).Ahead
		if ahead.Days != finding.ProjectionDays || ahead.Done != 2 || ahead.Added != 0 || !ahead.Converging {
			t.Fatalf("projected %+v, want two done and none added over %d days", ahead, finding.ProjectionDays)
		}
		// Two left at two in fourteen days is fourteen days.
		want := time.Now().UTC().Truncate(24 * time.Hour).Add(14 * 24 * time.Hour)
		if ahead.ZeroOn == nil || ahead.ZeroOn.Sub(want).Abs() > 24*time.Hour {
			t.Errorf("reaches zero on %v, want about %s", ahead.ZeroOn, want)
		}
	})
}

func TestTheProjectionDrawsNoZeroDateWhereAddedKeepsPace(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.fourIssues(t)
		f.closeIt(t, "CVE-2026-1", finding.Upgraded, ago(10))
		f.scannedAt(t, twoConsumers(), ago(3), found("CVE-2026-2", teamd), found("CVE-2026-3", swss),
			found("CVE-2026-4", libnl), found("CVE-2026-5", libnl), found("CVE-2026-6", teamd))

		ahead := f.burndown(t, "", finding.Within{}).Ahead
		if ahead.Converging || ahead.ZeroOn != nil || ahead.PerDay >= 0 {
			t.Errorf("projected %+v, want no zero date where two arrived against one done", ahead)
		}
	})
}

func TestABurndownNarrowsBySeverityAndByPackageIdentifier(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		low := found("CVE-2026-9", teamd)
		low.Issue.Severity = "low"
		f.scannedAt(t, twoConsumers(), ago(20), found("CVE-2026-1", libnl), found("CVE-2026-2", teamd), low)

		if got := burnedOver(f.burndown(t, "high", finding.Within{})); got.left != 2 {
			t.Errorf("high and worse left %d, want the two high issues", got.left)
		}
		chosen := f.burndown(t, "", finding.Within{Purl: graph.ParsePurlPrefix("pkg:deb/debian/libnl-3-200")})
		if got := burnedOver(chosen); got.left != 1 {
			t.Errorf("chosen by identifier, %d left, want the one issue on libnl", got.left)
		}
		if len(chosen.Chosen) != 1 || chosen.Chosen[0].Package != "pkg:deb/debian/libnl-3-200" ||
			chosen.Chosen[0].Ecosystem != "deb" {
			t.Errorf("chose %+v, want libnl's package in deb", chosen.Chosen)
		}
		if got := burnedOver(f.burndown(t, "", finding.Within{Purl: graph.ParsePurlPrefix("pkg:deb/debian/")})); got.left != 3 {
			t.Errorf("everything under the path left %d, want all three", got.left)
		}
	})
}

func TestAnIssueAnsweredAtOneOccurrenceAndOpenAtAnotherIsNotDone(t *testing.T) {
	// CVE-2026-1 sits on libnl under swss and under teamd: one answered is
	// not the issue at the component answered.
	each(t, func(t *testing.T, f *fixture) {
		f.fourIssues(t)
		agreed := ago(8)
		f.dismissed(t, dismissal{issue: "CVE-2026-1", proposed: agreed, agreed: &agreed, oneOccurrence: true})
		if got := burnedOver(f.burndown(t, "", finding.Within{})); got.dismissed != 0 || got.left != 4 {
			t.Errorf("counted %+v, want nothing dismissed and four left", got)
		}
	})
}

func TestABurndownFromAPickedDayZeroStartsFromWhatWasLeftThen(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.fourIssues(t)
		b := f.burndownSince(t, ago(12), "", finding.Within{})
		if b.Start != 4 || !b.Since.Equal(ago(12).Truncate(24*time.Hour)) {
			t.Errorf("started on %s with %d left, want day 0 as picked with all four", b.Since, b.Start)
		}
		if got := burnedOver(b); got.fresh != 0 || got.baseline != 0 || got.left != 4 {
			t.Errorf("counted %+v, want nothing added after day 0 and four left", got)
		}
	})
}

func TestADayZeroMoreThanTheWidestWindowBackIsMovedToItsStart(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.fourIssues(t)
		b := f.burndownSince(t, ago(800), "", finding.Within{})
		want := time.Now().UTC().Truncate(24 * time.Hour).Add(-(finding.MostBurndownDays - 1) * 24 * time.Hour)
		if !b.Since.Equal(want) || len(b.Points) != finding.MostBurndownDays {
			t.Errorf("started on %s over %d days, want %s over %d", b.Since, len(b.Points), want, finding.MostBurndownDays)
		}
	})
}

func TestAChosenNameIsNamedWhereNothingOfItReachesTheSeverity(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		low := found("CVE-2026-9", teamd)
		low.Issue.Severity = "low"
		f.scannedAt(t, twoConsumers(), ago(20), found("CVE-2026-1", libnl), low)
		b := f.burndown(t, "critical", finding.Within{Component: "teamd"})
		if got := burnedOver(b); got.left != 0 {
			t.Errorf("critical on teamd left %d, want none", got.left)
		}
		if len(b.Chosen) != 1 || b.MoreChosen {
			t.Errorf("chose %+v (more: %v), want teamd's one package", b.Chosen, b.MoreChosen)
		}
	})
}

func TestABurndownMarksAReturnAfterASharpRemovalAndCountsASmallOneAsReturned(t *testing.T) {
	for name, c := range map[string]struct {
		removed            func() graph.Snapshot
		restored, returned int
	}{
		"the whole inventory lost": {rootOnly, 1, 0},
		"one package of fifteen":   {func() graph.Snapshot { return widened(libnl) }, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.scannedAt(t, widened(), ago(20), found("CVE-2026-1", libnl))
				f.scannedAt(t, c.removed(), ago(10))
				f.scannedAt(t, widened(), ago(9), found("CVE-2026-1", libnl))
				got := burnedOver(f.burndown(t, "", finding.Within{}))
				if got.restored != c.restored || got.returned != c.returned || got.left != 1 {
					t.Errorf("counted %+v, want %d restored, %d returned and one left", got, c.restored, c.returned)
				}
			})
		})
	}
}
