// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestCarryingBringsTheReasoningAndNotTheConclusion(t *testing.T) {
	// A version moved, which is exactly what made the old decision stop
	// applying — so what travels is the thinking, and somebody still has
	// to look at the new code.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.agreed(t, f.at())
		// The line the decision was made on, and a second one holding the same
		// occurrence at a version that moved.
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")

		offered, err := f.store.WouldCarry(ctx, f.triager, was, next)
		if err != nil {
			t.Fatal(err)
		}
		if len(offered.Moved) != 1 || offered.Moved[0].DecisionOccurrenceID != agreed.ID {
			t.Fatalf("the new line was offered %+v, want the one decision whose version moved",
				offered.Moved)
		}

		carried, err := f.store.Carry(ctx, f.triager, was, next,
			[]int64{agreed.ID}, triage.DefaultBounds())
		if err != nil {
			t.Fatal(err)
		}
		if carried != 1 {
			t.Fatalf("carried %d, want 1", carried)
		}

		// A decision waiting for somebody lands, carrying the old words.
		rows, _, err := f.store.Queue(ctx, f.reviewer, triage.QueueFilter{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, row := range rows {
			if row.DecisionOccurrence.OccurrenceIdentity == agreed.OccurrenceIdentity &&
				row.DecisionOccurrence.ID != agreed.ID {
				found = true
				if row.DecisionOccurrence.State != triage.Proposed {
					t.Errorf("a carried decision arrived as %q, want one waiting for agreement",
						row.DecisionOccurrence.State)
				}
				if row.Reasoning == "" {
					t.Error("a carried decision arrived with no reasoning to start from")
				}
			}
		}
		if !found {
			t.Error("nothing arrived on the new line's queue")
		}
	})
}

// Two findings at one occurrence on the new line, each holding its own pair of
// versions. The component version and the consumer version a carried
// decision is keyed on come from the same one of them: a pair drawn half from
// each is a key no finding holds, and the carried decision would answer nothing.
func TestACarriedOccurrenceTakesBothVersionsFromOneFinding(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.agreed(t, f.at())
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "9.0")
		f.occurrenceAt(t, "202411", next, "2.0", "4.5.6")

		offered, err := f.store.WouldCarry(ctx, f.triager, was, next)
		if err != nil {
			t.Fatal(err)
		}
		if len(offered.Moved) != 1 || offered.Moved[0].Now != "1.2.4" {
			t.Fatalf("the new line was offered %+v, want the decision moving to 1.2.4", offered.Moved)
		}
		if _, err := f.store.Carry(ctx, f.triager, was, next,
			[]int64{agreed.ID}, triage.DefaultBounds()); err != nil {
			t.Fatal(err)
		}
		var landed triage.DecisionOccurrence
		if err := f.db.DB.NewSelect().Model(&landed).
			Where(`"de"."id" <> ?`, agreed.ID).
			OrderExpr(`"de"."id" DESC`).Limit(1).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		component, consumer := "", ""
		if landed.ComponentUpstreamVersion != nil {
			component = *landed.ComponentUpstreamVersion
		}
		if landed.ConsumerUpstreamVersion != nil {
			consumer = *landed.ConsumerUpstreamVersion
		}
		if component != "1.2.4" || consumer != "9.0" {
			t.Errorf("the carried decision is keyed at %s under %s, want 1.2.4 under 9.0, the pair one finding holds",
				component, consumer)
		}
	})
}

// The preview reads the same one finding's pair. Two findings at the occurrence,
// each holding one of the decision's versions and not the other: a pair drawn
// half from each is the decision's own key, and the decision would read as
// already applying and never be offered.
func TestACrossedPairIsNotReadAsAlreadyApplying(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.agreed(t, f.at())
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.3", "9.0")
		f.occurrenceAt(t, "202411", next, "2.0", "4.5.6")

		offered, err := f.store.WouldCarry(t.Context(), f.triager, was, next)
		if err != nil {
			t.Fatal(err)
		}
		if offered.Applying != 0 || len(offered.Moved) != 1 {
			t.Fatalf("offered %+v with %d already applying, want the decision offered as moved",
				offered.Moved, offered.Applying)
		}
	})
}

func TestAPromiseIsCarriedWithItsDateAndVersion(t *testing.T) {
	// A patch promise is refused without its date, so a carry that left it
	// behind could never land.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		by := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
		promised, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Occurrence: f.at(), Outcome: triage.PatchNeeded, CommittedTo: &by,
			Reasoning: "Patching the parser out.", By: f.proposer, NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, promised.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		was := f.anotherLineOf(t, catalog.Branch, "main", "1.2.3", "4.5.6")
		next := f.anotherLineOf(t, catalog.Branch, "next", "1.2.4", "4.5.6")

		carried, err := f.store.Carry(ctx, f.triager, was, next,
			[]int64{promised.ID}, triage.DefaultBounds())
		if err != nil {
			t.Fatalf("carrying a promise: %v", err)
		}
		if carried != 1 {
			t.Fatalf("carried %d, want 1", carried)
		}
		var landed triage.Decision
		if err := f.db.DB.NewSelect().Model(&landed).
			Where(`"cl"."id" <> ?`, promised.DecisionID).
			OrderExpr(`"cl"."id" DESC`).Limit(1).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if landed.CommittedTo == nil || landed.CommittedTo.Format(time.DateOnly) != by.Format(time.DateOnly) {
			t.Errorf("the carried promise is due %v, want %v", landed.CommittedTo, by)
		}
	})
}

func TestAPromisedUpgradeIsPlannedAgainRatherThanCarried(t *testing.T) {
	// An upgrade records what each release it names is waiting on. A decision
	// carried onto one occurrence writes none of that, so a moved upgrade is
	// counted apart and refused if named.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		by := time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
		promised, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Occurrence: f.at(), Outcome: triage.UpgradeNeeded, UpgradeTo: "1.3.0", CommittedTo: &by,
			Reasoning: "Moving the package forward.", By: f.proposer, NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, promised.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		was := f.anotherLineOf(t, catalog.Branch, "main", "1.2.3", "4.5.6")
		next := f.anotherLineOf(t, catalog.Branch, "next", "1.2.4", "4.5.6")

		offered, err := f.store.WouldCarry(ctx, f.triager, was, next)
		if err != nil {
			t.Fatal(err)
		}
		if offered.Upgrades != 1 || len(offered.Moved) != 0 {
			t.Errorf("a moved upgrade was offered as %d moved and counted as %d upgrades, want 0 and 1",
				len(offered.Moved), offered.Upgrades)
		}
		if _, err := f.store.Carry(ctx, f.triager, was, next,
			[]int64{promised.ID}, triage.DefaultBounds()); err == nil {
			t.Error("a promised upgrade was carried onto a new line")
		}
	})
}

func TestOnlyWhatTheNewLineWasOfferedMayBeCarried(t *testing.T) {
	// A decision that already applies has nothing to agree to, and one
	// covering nothing here has nothing to apply to. Refused rather than
	// skipped: a caller that got the set wrong should hear so.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.agreed(t, f.at())
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		// The same versions, so it reaches the new line by matching.
		same := f.anotherLine(t, "202411", "1.2.3", "4.5.6")

		offered, err := f.store.WouldCarry(ctx, f.triager, was, same)
		if err != nil {
			t.Fatal(err)
		}
		if offered.Applying != 1 || len(offered.Moved) != 0 {
			t.Fatalf("the matching line was offered %+v, want it applying already", offered)
		}
		// Asserted on the refusal itself, which the bounds, an empty set and
		// the write can all fail differently from. Verified by deleting the
		// not-offered return in Carry.
		if _, err := f.store.Carry(ctx, f.triager, was, same,
			[]int64{agreed.ID}, triage.DefaultBounds()); !errors.Is(err, triage.ErrNotOffered) {
			t.Errorf("a decision that already applies was not refused as unoffered: %v", err)
		}
	})
}

func TestCarryingIsBoundedByTheIssuesAReviewerReads(t *testing.T) {
	// Every decision carried waits for a second person, so the reviewer's
	// issue limit holds. Two issues against a limit of one is refused, and
	// the same two under a limit of two go through, so the count is what
	// refused it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		second := f.secondIssue(t)
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")
		f.alsoCarries(t, second, was, next)

		first := f.agreed(t, f.at())
		other := f.at()
		other.VulnerabilityID = second
		also := f.agreed(t, other)

		chosen := []int64{first.ID, also.ID}
		if _, err := f.store.Carry(ctx, f.triager, was, next, chosen,
			triage.Bounds{Review: 1}); err == nil {
			t.Fatal("carrying two issues under a limit of one was allowed")
		}
		if carried, err := f.store.Carry(ctx, f.triager, was, next, chosen,
			triage.Bounds{Review: 2}); err != nil || carried != 2 {
			t.Errorf("carrying two issues under a limit of two answered %d, %v", carried, err)
		}
	})
}

// alsoCarries puts a second issue at the fixture's occurrence on each line, beside
// the first.
func (f *fixture) alsoCarries(t *testing.T, issue int64, targets ...int64) {
	t.Helper()
	var rows []finding.Finding
	if err := f.db.DB.NewSelect().Model(&rows).
		Where(`"target_id" IN (?)`, bun.List(targets)).
		Where(`"vulnerability_id" = ?`, f.issue).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		row.ID = 0
		row.VulnerabilityID = issue
		if _, err := f.db.DB.NewInsert().Model(&row).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSomebodyWhoMayNotDecideHereCarriesNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		agreed := f.agreed(t, f.at())
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")
		if _, err := f.store.Carry(t.Context(), f.onlooker, was, next,
			[]int64{agreed.ID}, triage.DefaultBounds()); err == nil {
			t.Error("somebody who may not decide here carried a decision")
		}
	})
}

func TestADecisionIsNotCarriedOntoAnOccurrenceUndisclosedToItsCarrier(t *testing.T) {
	// The visibility a carried decision is written at is the new line's. A
	// triager of disclosed work carrying a disclosed decision onto a line
	// where the occurrence is undisclosed would write on work they may not argue
	// about, so it is neither offered nor written.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.agreed(t, f.at())
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"visibility" = ?`, access.Private).
			Where(`"target_id" = ?`, next).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		offered, err := f.store.WouldCarry(ctx, f.triager, was, next)
		if err != nil {
			t.Fatal(err)
		}
		if len(offered.Moved) != 0 {
			t.Errorf("an occurrence undisclosed on the new line was offered: %+v", offered.Moved)
		}
		// Refused as not offered: the offer is narrowed inside the same
		// transaction, so the visibility check on the written proposal is a
		// backstop this cannot reach.
		if _, err := f.store.Carry(ctx, f.triager, was, next,
			[]int64{agreed.ID}, triage.DefaultBounds()); !errors.Is(err, triage.ErrNotOffered) {
			t.Errorf("a decision carried onto an occurrence undisclosed to its carrier answered %v", err)
		}
		written, err := f.db.DB.NewSelect().Model((*triage.DecisionOccurrence)(nil)).
			Where(`"visibility" = ?`, access.Private).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if written != 0 {
			t.Errorf("%d undisclosed rows were written by somebody who may not argue them", written)
		}
	})
}

// anotherLine declares a build of this product holding the fixture's own occurrence
// at the given versions, and returns its target.
//
// A carry is about two lines holding the same occurrence at different versions, so
// a test of it needs findings on both — the decision alone says nothing about
// where it would land.
func (f *fixture) anotherLine(t *testing.T, stream, component, consumer string) int64 {
	t.Helper()
	return f.anotherLineOf(t, catalog.Tag, stream, component, consumer)
}

// anotherLineOf is anotherLine for a stream of the given kind. A dated
// decision is refused on a tag, so carrying one needs a branch.
func (f *fixture) anotherLineOf(t *testing.T, kind catalog.Kind, stream, component, consumer string) int64 {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(f.db.DB)
	declared, err := cat.DeclareStream(ctx, f.product, stream, kind, nil)
	if err != nil {
		t.Fatalf("declare %s: %v", stream, err)
	}
	// Declared once and looked up after, because two lines of the same product
	// are the same variant built twice.
	variant, err := cat.VariantByName(ctx, f.product, "broadcom")
	if err != nil {
		if variant, err = cat.DeclareVariant(ctx, f.product, "broadcom", true); err != nil {
			t.Fatalf("variant: %v", err)
		}
	}
	target, err := cat.TargetFor(ctx, declared.ID, variant.ID)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	f.occurrenceAt(t, stream, target.ID, component, consumer)
	return target.ID
}

// occurrenceAt records one open finding at the fixture's occurrence, at these versions.
func (f *fixture) occurrenceAt(t *testing.T, stream string, target int64, component, consumer string) {
	t.Helper()
	ctx := t.Context()
	carrier := &graph.Component{
		Identity: "c-" + stream + "-" + component + "-" + consumer, Name: "libfoo", Version: component,
		UpstreamName: "libfoo", UpstreamVersion: component,
		Purl: "pkg:deb/debian/libfoo@" + component,
	}
	holder := &graph.Component{
		Identity: "u-" + stream + "-" + component + "-" + consumer, Name: "libbar", Version: consumer,
		UpstreamName: "libbar", UpstreamVersion: consumer,
		Purl: "pkg:deb/debian/libbar@" + consumer,
	}
	for _, c := range []*graph.Component{carrier, holder} {
		if _, err := f.db.DB.NewInsert().Model(c).Exec(ctx); err != nil {
			t.Fatalf("record a component: %v", err)
		}
	}
	row := &finding.Finding{
		TargetID: target, Kind: finding.Vulnerable, VulnerabilityID: f.issue,
		Visibility: access.Public, ComponentID: carrier.ID, ConsumerID: &holder.ID,
		OccurrenceIdentity: f.at().OccurrenceIdentity, Urgency: 1, OpenedAt: time.Now().UTC(),
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatalf("record a finding: %v", err)
	}
}

// Carrying a decision onto a new line goes through the same validation every
// other write does.
//
// The occurrence a carried decision is about records whether the new line is a tag,
// so the rule that refuses a dated decision on a release built once applies
// here as it does to a decision written by hand. A dated promise about a release
// that cannot change is exactly the case that rule exists to refuse.
func TestCarryingADatedDecisionOntoATagIsRefused(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		soon := time.Now().UTC().Add(30 * 24 * time.Hour)
		if _, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Occurrence: f.at(), Outcome: triage.Deferred, DeferredUntil: &soon,
			Reasoning: "Not this sprint.", By: f.proposer,
		}); err != nil {
			t.Fatal(err)
		}
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")

		offered, err := f.store.WouldCarry(ctx, f.triager, was, next)
		if err != nil {
			t.Fatal(err)
		}
		if len(offered.Postponed) != 1 {
			t.Fatalf("the new line was offered %d postponements, want the one there is",
				len(offered.Postponed))
		}
		if _, err := f.store.Carry(ctx, f.triager, was, next,
			[]int64{offered.Postponed[0].DecisionOccurrenceID}, triage.DefaultBounds()); err == nil {
			t.Fatal("a deferral was carried onto a release that was built once")
		} else if !strings.Contains(err.Error(), "built once") {
			t.Errorf("it was refused, but not for being a tag: %v", err)
		}
	})
}

// And a decision whose date has already gone by is not offered at all, and is
// counted as past its date.
//
// A carried decision keeps its date rather than having it quietly moved
// forward, so carrying one that has run out writes a decision that is finished
// the moment it lands — and offering it is offering something the act behind
// the button turns down.
func TestADecisionThatHasRunOutIsNotOfferedToANewLine(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		soon := time.Now().UTC().Add(30 * 24 * time.Hour)
		ran, err := f.store.Propose(ctx, f.triager, triage.Proposal{
			Occurrence: f.at(), Outcome: triage.Deferred, DeferredUntil: &soon,
			Reasoning: "Not this sprint.", By: f.proposer,
		})
		if err != nil {
			t.Fatal(err)
		}
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")

		// The date arrives, moved here rather than waited for.
		if _, err := f.db.DB.NewUpdate().Table("decision").
			Set(`"deferred_until" = ?`, time.Now().UTC().Add(-time.Hour)).
			Where(`"id" = ?`, ran.DecisionID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		offered, err := f.store.WouldCarry(ctx, f.triager, was, next)
		if err != nil {
			t.Fatal(err)
		}
		if len(offered.Postponed) != 0 {
			t.Errorf("a deferral that has run out was offered: %+v", offered.Postponed)
		}
		// Counted as past its date, not as covering nothing: its occurrence is
		// on the new line, and the finding there is left with no answer.
		if offered.Expired != 1 || offered.Absent != 0 {
			t.Errorf("a deferral past its date at an occurrence the line holds counts as %d expired, "+
				"%d absent; want 1 and 0", offered.Expired, offered.Absent)
		}
	})
}

func TestACarriedDecisionRecordsHowBadTheIssueIsNow(t *testing.T) {
	// The baseline a later rise is measured from. Without it a carried decision
	// reads as made about an unrated issue, and a rating into high lapses it
	// though nothing was rated worse since it was carried.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.agreed(t, f.at())
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")
		f.rateIssue(t, 750)

		if _, err := f.store.Carry(ctx, f.triager, was, next,
			[]int64{agreed.ID}, triage.DefaultBounds()); err != nil {
			t.Fatal(err)
		}
		var baseline *int
		if err := f.db.DB.NewSelect().Table("decision_occurrence").Column("severity_centi").
			Where(`"occurrence_identity" = ?`, agreed.OccurrenceIdentity).Where(`"id" <> ?`, agreed.ID).
			Scan(ctx, &baseline); err != nil {
			t.Fatal(err)
		}
		if baseline == nil || *baseline != 750 {
			t.Errorf("the carried decision's baseline is %v, want the rating in force, 750", baseline)
		}
	})
}

// A limit left unset is the deployment's setting, read by the act itself.
//
// The handler read the settings before the transaction opened and passed the
// numbers in, so a retry wrote against limits from before it began. Read in
// the transaction that writes, a limit an administrator lowered holds on the
// act that follows.
func TestAnUnsetLimitIsTheDeploymentsSetting(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		second := f.secondIssue(t)
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")
		f.alsoCarries(t, second, was, next)

		first := f.agreed(t, f.at())
		other := f.at()
		other.VulnerabilityID = second
		also := f.agreed(t, other)

		if _, _, err := setting.NewStore(f.db.DB).Change(ctx, setting.ReviewIssues, "1"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Carry(ctx, f.triager, was, next, []int64{first.ID, also.ID},
			triage.Bounds{}); err == nil {
			t.Error("carrying two issues went through a deployment limit of one")
		}
	})
}

func TestACorrectionWhoseVersionMovedIsAlreadyApplying(t *testing.T) {
	// A correction stands at any version, so it reaches the new line however
	// far the version moved, and carrying it would be refused as the occurrence
	// already decided.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		corrected, err := f.corrects(t, f.at(), triage.ComponentNotPresent)
		if err != nil {
			t.Fatal(err)
		}
		if err := agreeTo(ctx, f.store, f.reviewer, corrected.DecisionID, ""); err != nil {
			t.Fatal(err)
		}
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")

		offered, err := f.store.WouldCarry(ctx, f.triager, was, next)
		if err != nil {
			t.Fatal(err)
		}
		if offered.Applying != 1 || len(offered.Moved) != 0 {
			t.Fatalf("offered %+v with %d already applying, want the correction applying",
				offered.Moved, offered.Applying)
		}
	})
}
