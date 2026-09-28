// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The page and the count are two questions, and the export asks only one.
//
// Counting a register is a scan of every finding in the build — a quarter of a
// million rows on a real image — and a file is written by asking for a page a
// thousand times, so the export was answering "how many are there altogether"
// a thousand times to fill in a number the file has no column for. The two
// readers are separate now, and this is what keeps them saying the same thing:
// a page read without the count has to be the page read with it.
func TestTheRegistersPageIsTheSameWithoutItsCount(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
			found("CVE-2026-3", teamd),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)

		withCount, total, err := f.store.Register(t.Context(), who, f.target, finding.Registering{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		without, err := f.store.RegisterPage(t.Context(), who, f.target, finding.Registering{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total == 0 || len(withCount) == 0 {
			t.Fatal("the register is empty for a build holding three findings")
		}
		if len(without) != len(withCount) {
			t.Fatalf("the page is %d rows without the count and %d with it",
				len(without), len(withCount))
		}
		for i := range withCount {
			if asText(without[i]) != asText(withCount[i]) {
				t.Errorf("row %d differs:\n without %s\n with    %s",
					i, asText(without[i]), asText(withCount[i]))
			}
		}
		// And the same refusal. A reader who may see nothing here has to be
		// refused by both, or the export is the way around the check.
		nobody := f.holdingIn(t, nil, access.PublicRead)
		if _, err := f.store.RegisterPage(t.Context(), nobody, f.target, finding.Registering{}, 50, 0); err == nil {
			t.Error("a page read without the count answered somebody holding nothing")
		}
		if err := f.store.RegisterEach(t.Context(), nobody, f.target, finding.Registering{},
			func(finding.Disposed) error { return nil }); err == nil {
			t.Error("the walk answered somebody holding nothing")
		}
	})
}

// The walk and the page are the same register.
//
// The export streams and the screen pages, which is two readers over one
// statement — so this is what stops them drifting into two registers. It is
// the same shape as the count check above and exists for the same reason: an
// auditor's file and the screen it is checked against have to be the same
// rows in the same order.
func TestTheRegisterWalkedIsTheRegisterPaged(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
			found("CVE-2026-3", teamd), found("CVE-2026-4", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)

		paged, err := f.store.RegisterPage(t.Context(), who, f.target, finding.Registering{}, 500, 0)
		if err != nil {
			t.Fatal(err)
		}
		var walked []finding.Disposed
		if err := f.store.RegisterEach(t.Context(), who, f.target, finding.Registering{},
			func(row finding.Disposed) error {
				walked = append(walked, row)
				return nil
			}); err != nil {
			t.Fatal(err)
		}
		if len(paged) == 0 {
			t.Fatal("the register is empty for a build holding four findings")
		}
		if len(walked) != len(paged) {
			t.Fatalf("the walk gave %d rows and the page gave %d", len(walked), len(paged))
		}
		for i := range paged {
			if asText(walked[i]) != asText(paged[i]) {
				t.Errorf("row %d differs:\n walked %s\n paged  %s",
					i, asText(walked[i]), asText(paged[i]))
			}
		}

		// A walk that gives up partway gives up: the caller's refusal is the
		// export saying it could not finish, and swallowing it is how a file
		// ends early and reads as complete.
		stop := fmt.Errorf("enough")
		seen := 0
		err = f.store.RegisterEach(t.Context(), who, f.target, finding.Registering{}, func(finding.Disposed) error {
			seen++
			return stop
		})
		if !errors.Is(err, stop) {
			t.Errorf("a walk told to stop answered %v", err)
		}
		if seen != 1 {
			t.Errorf("it kept walking after being told to stop, %d rows in", seen)
		}
	})
}

// asText is one register row as a value rather than as a struct holding
// pointers. Two reads of the same row allocate different pointers, so
// comparing the structs compares where the times live rather than when they
// are — which is a test that fails on every row and says nothing.
func asText(row finding.Disposed) string {
	at := func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.UTC().Format(time.RFC3339Nano)
	}
	met := "-"
	if row.Met != nil {
		met = fmt.Sprint(*row.Met)
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		row.Vulnerability, row.Severity, row.Component, row.Version, row.Place,
		row.State, row.Outcome, row.Justification, row.ProposedBy, at(row.ProposedAt),
		row.ApprovedBy, at(row.ApprovedAt), at(&row.OpenedAt), at(row.ClosedAt), met)
}

// A lapsed judgment is part of the record, and the register says so.
//
// The join asked for a live decision, and a lapse nulls the live key in the
// same statement that marks it — so the place reported as never decided and
// the register lost who proposed and who approved it, which is what a
// compliance reader comes here for. The findings list calls the same place
// lapsed, so the two surfaces disagreed about one build.
func TestARegisterSaysWhoDecidedSomethingThatHasSinceLapsed(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		open := f.open(t)
		if len(open) == 0 {
			t.Fatal("nothing opened to decide about")
		}
		f.recorded(t, 1, "proposer")
		f.recorded(t, 2, "approver")

		decided := f.decidedAndLapsed(t, open[0])
		rows, _, err := f.store.Register(ctx, f.holding(t, access.PublicRead), f.target, finding.Registering{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var found *finding.Disposed
		for i, row := range rows {
			if row.Place == decided {
				found = &rows[i]
			}
		}
		if found == nil {
			t.Fatalf("the place the decision was about is not in the register: %+v", rows)
		}
		if found.State != "lapsed" {
			t.Errorf("a place whose judgment lapsed reads as %q", found.State)
		}
		if found.ProposedBy == "" || found.ApprovedBy == "" {
			t.Errorf("the register lost who decided it: proposed by %q, approved by %q",
				found.ProposedBy, found.ApprovedBy)
		}
		if found.Outcome == "" {
			t.Error("the register lost what was decided")
		}
	})
}

// decidedAndLapsed puts an agreed judgment on a finding's place and then lets
// it lapse, and answers with the place it was about.
//
// Written here rather than through the triage store because a lapse is what
// the store does when the code moves, and what is being measured is what the
// register says about the row that leaves behind: agreed, then not applying,
// with both people still named.
func (f *fixture) decidedAndLapsed(t *testing.T, at finding.Finding) string {
	t.Helper()
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Microsecond)

	claim := &triage.Claim{
		Kind: triage.FindingClaim, ProposedBy: 1, ProposedAt: now,
		Outcome: triage.WontFix,
	}
	if _, err := f.db.DB.NewInsert().Model(claim).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	revision := &triage.Revision{
		ClaimID: claim.ID, Ordinal: 1, Body: "Not worth the churn.",
		WrittenBy: 1, WrittenAt: now,
	}
	if _, err := f.db.DB.NewInsert().Model(revision).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.NewUpdate().Model((*triage.Claim)(nil)).
		Set("revision_id = ?", revision.ID).Where("id = ?", claim.ID).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.NewInsert().Model(&triage.Approval{
		ClaimID: claim.ID, RevisionID: revision.ID, ApprovedBy: 2, ApprovedAt: now,
	}).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	// Lapsed: the state a sweep writes when the last build holding the
	// versions moves on, which nulls the live key in the same statement.
	decision := &triage.Decision{
		ClaimID: claim.ID, ProductID: f.productID, VulnerabilityID: at.VulnerabilityID,
		PlaceIdentity: at.PlaceIdentity, Visibility: access.Public,
		NeedsApproval: true, State: triage.LapsedState,
		ProposedBy: 1, ProposedAt: now, EndedAt: &now,
	}
	if _, err := f.db.DB.NewInsert().Model(decision).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return at.PlaceIdentity
}

func TestTheRegisterCarriesWhyAPersonClosedSomething(t *testing.T) {
	// A closure with no reason is refused of whoever writes one, and the
	// sentence they typed was then readable nowhere: no body carried it, no
	// query outside a test selected it, no screen drew it. The refusal is a
	// promise that the words go somewhere.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)

		rows, _, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Component: swss.Name, Severity: "high",
			Summary: "The management socket accepts a request nobody authenticated.",
		})
		if err != nil {
			t.Fatal(err)
		}
		const because = "The patch was backported in 2.4.1-3."
		if _, err := f.store.Resolve(ctx, who, f.target, rows[0].VulnerabilityID, because); err != nil {
			t.Fatal(err)
		}

		register, _, err := f.store.Register(ctx, who, f.target, finding.Registering{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var closed *finding.Disposed
		for i := range register {
			if register[i].ClosedAt != nil {
				closed = &register[i]
			}
		}
		if closed == nil {
			t.Fatalf("the register holds no closed row: %+v", register)
		}
		// The category and the sentence. The first says a fix happened and
		// the second says what the fix was, which is the half somebody has
		// years later.
		if closed.ClosedBecause != finding.Fixed {
			t.Errorf("closed because %q, want the word a person writes", closed.ClosedBecause)
		}
		if closed.ClosedNote != because {
			t.Errorf("the register states the reason as %q", closed.ClosedNote)
		}
	})
}

func TestAStateWordTheRegisterDoesNotKnowKeepsNothing(t *testing.T) {
	// A filter that silently widens is how a register reads as complete about
	// rows it left out. The route's own vocabulary refuses an unknown word at
	// the door, so this is the guard behind it: a caller inside this process
	// asking for a word none of the four recognizes gets nothing, not
	// everything.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)
		whole, err := f.store.RegisterPage(t.Context(), who, f.target,
			finding.Registering{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(whole) == 0 {
			t.Fatal("the fixture's register is empty, so this checks nothing")
		}
		nonsense, err := f.store.RegisterPage(t.Context(), who, f.target,
			finding.Registering{States: []string{"whatever"}}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(nonsense) != 0 {
			t.Errorf("a word the register does not know kept %d of %d rows",
				len(nonsense), len(whole))
		}
	})
}

// A place reads once in the register, whatever history it carries.
//
// Decision rows are never deleted: a withdrawal or a lapse clears the live key
// and leaves the row. The register reports the one decision on the record — the
// live one, or the latest lapsed one where nothing is live — so a place claimed
// again after a withdrawal is one row, waiting, and not also a second row
// reading as undecided.
func TestAPlaceWithAWithdrawnOrLapsedPastReadsOnceInTheRegister(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", swss), found("CVE-2026-2", teamd), found("CVE-2026-3", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, before, err := f.store.Register(ctx, who, f.target, finding.Registering{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		withdrawn := finding.PlaceIdentity(swss.Name, "")
		lapsed := finding.PlaceIdentity(teamd.Name, "")
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-1"), withdrawn, "withdrawn", swss.Version, "")
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-1"), withdrawn, "proposed", swss.Version, "again")
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-2"), lapsed, "lapsed", teamd.Version, "")
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-2"), lapsed, "lapsed", teamd.Version, "")
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-2"), lapsed, "approved", teamd.Version, "anew")
		// Lapsed, claimed again and lapsed again, with nothing live: the
		// latest lapse is the record.
		twice := finding.PlaceIdentity(libnl.Name, swss.Name)
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-3"), twice, "lapsed", libnl.Version, "")
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-3"), twice, "lapsed", libnl.Version, "")

		rows, total, err := f.store.Register(ctx, who, f.target, finding.Registering{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != before || len(rows) != before {
			t.Errorf("the register holds %d rows and says %d, want the %d it held before any decision",
				len(rows), total, before)
		}
		states := map[string][]string{}
		for _, row := range rows {
			states[row.Place] = append(states[row.Place], row.State)
		}
		if got := states[withdrawn]; len(got) != 1 || got[0] != "waiting" {
			t.Errorf("a place withdrawn and claimed again reads %v, want one row waiting", got)
		}
		if got := states[lapsed]; len(got) != 1 || got[0] != "agreed" {
			t.Errorf("a place lapsed and agreed again reads %v, want one row agreed", got)
		}
		if got := states[twice]; len(got) != 1 || got[0] != "lapsed" {
			t.Errorf("a place lapsed twice with nothing live reads %v, want one row lapsed", got)
		}
		undecided, total, err := f.store.Register(ctx, who, f.target,
			finding.Registering{States: []string{"undecided"}}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range undecided {
			if row.Place == withdrawn || row.Place == lapsed {
				t.Errorf("undecided lists %s, which a live decision answers", row.Place)
			}
		}
		if total != len(undecided) {
			t.Errorf("undecided says %d and holds %d", total, len(undecided))
		}
	})
}

// The register says what the findings list says about a place a live decision
// was keyed on at other versions: nothing stands there.
func TestTheRegisterReportsALiveDecisionOnlyAtTheVersionsItWasKeyedOn(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		directly := func(library graph.Described) graph.Snapshot {
			return graph.Snapshot{
				Root: root, Components: []graph.Described{library},
				Dependencies: []graph.Dependency{{Parent: root, Child: library}},
			}
		}
		f.shipped(t, directly(libnl))
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		other := f.anotherBuild(t, "202411")
		f.shippedTo(t, other, directly(libnlNew))
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-1", libnlNew),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		f.decided(t, somebody.ID, f.issueID(t, "CVE-2026-1"),
			finding.PlaceIdentity(libnl.Name, ""), "approved", libnl.Version, "old")

		reads := func(target int64, want string) {
			t.Helper()
			rows, total, err := f.store.Register(ctx, who, target, finding.Registering{}, 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			if total != 1 || len(rows) != 1 || rows[0].State != want {
				t.Fatalf("build %d's register reads %+v (total %d), want one row %q", target, rows, total, want)
			}
			if want == "undecided" && (rows[0].Outcome != "" || rows[0].ProposedBy != "") {
				t.Errorf("build %d's register names a judgment that does not cover it: %+v", target, rows[0])
			}
		}
		reads(f.target, "agreed")
		reads(other, "undecided")
	})
}

// A finding two live decisions cover reads once: a claim keyed on its versions
// and a correction, which covers the place at any version. The register names
// the one the finding's screen names — the correction once it is in force, and
// the older claim before that.
func TestAFindingTwoLiveDecisionsCoverReadsOnceInTheRegister(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", swss),
		}); err != nil {
			t.Fatal(err)
		}
		who := f.holding(t, access.PublicRead)
		somebody, err := access.NewStore(f.db.DB).Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		issue, place := f.issueID(t, "CVE-2026-1"), finding.PlaceIdentity(swss.Name, "")
		f.decided(t, somebody.ID, issue, place, "approved", swss.Version, "keyed")
		correction := map[string]any{
			"claim_id":   claimSaying(t, f.db, somebody.ID, "mismatched"),
			"product_id": f.productID, "vulnerability_id": issue,
			"place_identity": place, "visibility": "public", "state": "proposed",
			"needs_approval": true, "proposed_by": somebody.ID,
			"proposed_at":                time.Now().UTC(),
			"component_upstream_version": "0.9.0", "live_key": "anywhere",
		}
		if _, err := f.db.DB.NewInsert().Model(&correction).
			TableExpr("\"decision\"").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		reads := func(because, outcome string) {
			t.Helper()
			rows, total, err := f.store.Register(ctx, who, f.target, finding.Registering{}, 50, 0)
			if err != nil {
				t.Fatal(err)
			}
			var here []finding.Disposed
			for _, row := range rows {
				if row.Place == place {
					here = append(here, row)
				}
			}
			if len(here) != 1 || total != len(rows) {
				t.Fatalf("%s: the place reads %d times, total %d of %d rows", because,
					len(here), total, len(rows))
			}
			if here[0].Outcome != outcome {
				t.Errorf("%s: the place reads %q, want %q", because, here[0].Outcome, outcome)
			}
		}
		reads("a correction waiting beside an agreed claim", "not-applicable")
		if _, err := f.db.DB.NewUpdate().Table("decision").Set("state = ?", "approved").
			Where("live_key = ?", "anywhere").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		reads("a correction in force beside an agreed claim", "mismatched")
	})
}
