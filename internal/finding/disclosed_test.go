// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// undisclosed counts the findings and the decisions of one issue that are
// still undisclosed, closed places included.
func (f *fixture) undisclosed(t *testing.T, issue int64) (findings, decisions int) {
	t.Helper()
	var err error
	findings, err = f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
		Where("vulnerability_id = ?", issue).
		Where("visibility = ?", access.Private).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	decisions, err = f.db.DB.NewSelect().TableExpr(`"decision"`).
		Where(`"vulnerability_id" = ?`, issue).
		Where(`"visibility" = ?`, access.Private).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return findings, decisions
}

// dated moves every place of an issue's embargo to end at one moment.
func (f *fixture) dated(t *testing.T, issue int64, at time.Time) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
		Set("disclose_at = ?", at.UTC()).
		Where("vulnerability_id = ?", issue).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestDisclosingMakesTheWholeRecordPublic(t *testing.T) {
	// Disclosed, the whole record goes public (REQ-40). A closed place still
	// carries comments and decisions, and a decision carries the visibility
	// of the finding it was made about, so both follow.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.embargoed(t, who)
		f.dated(t, issue, time.Now().Add(-24*time.Hour))

		var places []finding.Finding
		if err := f.db.DB.NewSelect().Model(&places).
			Where("vulnerability_id = ?", issue).Order("id").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(places) == 0 {
			t.Fatal("the flaw sits nowhere")
		}
		// Closed, so the place disclosed is one no list of open work shows.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("closed_at = ?", time.Now().UTC()).
			Where("id = ?", places[0].ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		f.decided(t, who.ID, issue, places[0].PlaceIdentity, "proposed", "1.0", "")
		if _, err := f.db.DB.NewUpdate().TableExpr(`"decision"`).
			Set(`"visibility" = ?`, access.Private).
			Where(`"vulnerability_id" = ?`, issue).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		// The controls, broken: no reason, and nobody who may not triage
		// undisclosed work here.
		if _, err := f.store.Disclose(ctx, who, f.productID, issue, "  "); err == nil {
			t.Error("an issue was disclosed for no stated reason")
		}
		if _, err := f.store.Disclose(ctx, f.planner(t, access.PublicTriage),
			f.productID, issue, "Because."); err == nil {
			t.Error("somebody holding only public triage disclosed an issue")
		}
		if n, d := f.undisclosed(t, issue); n != len(places) || d != 1 {
			t.Fatalf("a refused disclosure changed something: %d findings, %d decisions undisclosed", n, d)
		}

		// The date has arrived, so it takes effect at once.
		done, err := f.store.Disclose(ctx, who, f.productID, issue, "The advisory is out.")
		if err != nil {
			t.Fatal(err)
		}
		if done.NeedsApproval || !done.InForce() || done.Act != finding.Disclosure {
			t.Errorf("disclosing on the date recorded %+v, want a disclosure in force", done)
		}
		if n, d := f.undisclosed(t, issue); n != 0 || d != 0 {
			t.Errorf("after disclosure %d findings and %d decisions are still undisclosed", n, d)
		}

		// One way: nothing is left to disclose or to move.
		if _, err := f.store.Disclose(ctx, who, f.productID, issue, "Again."); !errors.Is(err, finding.ErrDisclosed) {
			t.Errorf("disclosing twice answered %v, want ErrDisclosed", err)
		}
		if _, err := f.store.Extend(ctx, who, f.productID, issue,
			time.Now().Add(30*24*time.Hour), "Hide it again."); !errors.Is(err, finding.ErrNotEmbargoed) {
			t.Errorf("extending a disclosed issue answered %v, want ErrNotEmbargoed", err)
		}
	})
}

func TestDisclosingEarlyIsAShortening(t *testing.T) {
	// Before the date it brings the end of the embargo to today, and the
	// threshold a shortening has applies unchanged. Past it a second person
	// agrees, and until they do nothing is public.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		other := f.someoneElse(t, access.PrivateTriage)

		// A week early is under the thirty-day threshold.
		near := f.embargoed(t, who)
		f.dated(t, near, time.Now().Add(7*24*time.Hour))
		soon, err := f.store.Disclose(ctx, who, f.productID, near, "The coordinator published.")
		if err != nil {
			t.Fatal(err)
		}
		if soon.NeedsApproval {
			t.Error("disclosing a week early was sent to a queue")
		}
		if n, _ := f.undisclosed(t, near); n != 0 {
			t.Errorf("%d findings are still undisclosed after a disclosure in force", n)
		}

		// Two months early is past it.
		far := f.embargoed(t, who)
		f.dated(t, far, time.Now().Add(60*24*time.Hour))
		asked, err := f.store.Disclose(ctx, who, f.productID, far, "It leaked.")
		if err != nil {
			t.Fatal(err)
		}
		if !asked.NeedsApproval {
			t.Fatal("disclosing two months early stood on one person's say-so")
		}
		if n, _ := f.undisclosed(t, far); n == 0 {
			t.Fatal("a disclosure waiting for agreement made the issue public")
		}
		if _, err := f.store.Disclose(ctx, who, f.productID, far, "Still leaked."); !errors.Is(
			err, finding.ErrDisclosureWaiting) {
			t.Errorf("asking twice answered %v, want ErrDisclosureWaiting", err)
		}
		if _, err := f.store.AgreeToMovement(ctx, who, asked.ID); !errors.Is(err, finding.ErrSamePerson) {
			t.Errorf("agreeing to your own disclosure answered %v, want ErrSamePerson", err)
		}
		if _, err := f.store.AgreeToMovement(ctx, other, asked.ID); err != nil {
			t.Fatal(err)
		}
		if n, _ := f.undisclosed(t, far); n != 0 {
			t.Errorf("%d findings are still undisclosed after a second person agreed", n)
		}
	})
}

func TestAFlawWithNoDateNeedsASecondPersonToDisclose(t *testing.T) {
	// A flaw found here has no end anybody agreed to, so the disclosure is the
	// whole decision.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		rows, _, err := f.store.Enter(ctx, who, finding.Entering{
			TargetIDs: []int64{f.target}, Severity: "high",
			Summary: "Found in our own review.",
			Told:    finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		issue := rows[0].VulnerabilityID
		asked, err := f.store.Disclose(ctx, who, f.productID, issue, "Fixed in every release.")
		if err != nil {
			t.Fatal(err)
		}
		if !asked.NeedsApproval {
			t.Error("a flaw with no disclosure date was disclosed on one person's say-so")
		}
		if n, _ := f.undisclosed(t, issue); n == 0 {
			t.Error("a disclosure waiting for agreement made the issue public")
		}
	})
}

func TestADisclosedIssueLeavesNothingWaitingToBeMoved(t *testing.T) {
	// An extension left waiting when the issue was disclosed can no longer be
	// agreed to, so the queue a second person reads does not list it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		other := f.someoneElse(t, access.PrivateTriage)
		issue := f.embargoed(t, who)
		f.dated(t, issue, time.Now().Add(-time.Hour))

		long, err := f.store.Extend(ctx, who, f.productID, issue,
			time.Now().Add(90*24*time.Hour), "Upstream has not answered.")
		if err != nil {
			t.Fatal(err)
		}
		if !long.NeedsApproval {
			t.Fatal("a three-month extension stood alone")
		}
		if waiting, _, err := f.store.PendingPage(ctx, other, 50, 0); err != nil || len(waiting) != 1 {
			t.Fatalf("before disclosure the queue holds %d (%v), want the extension", len(waiting), err)
		}
		if _, err := f.store.Disclose(ctx, who, f.productID, issue, "Published."); err != nil {
			t.Fatal(err)
		}
		waiting, total, err := f.store.PendingPage(ctx, other, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(waiting) != 0 || total != 0 {
			t.Errorf("after disclosure the queue still lists %d (total %d)", len(waiting), total)
		}
		if _, err := f.store.AgreeToMovement(ctx, other, long.ID); !errors.Is(err, finding.ErrNotEmbargoed) {
			t.Errorf("agreeing to an extension of a disclosed issue answered %v", err)
		}
	})
}

func TestDisclosingAnIssueInOneProductLeavesItUndisclosedInAnother(t *testing.T) {
	// The unit is one issue in one product. The same issue embargoed in a
	// second product keeps its findings, its decisions and its waiting
	// movements private when the first discloses it.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.embargoed(t, who)
		f.dated(t, issue, time.Now().Add(-time.Hour))

		elsewhere := f.inAnotherProduct(t, "router")
		other := f.productOf(t, elsewhere)
		var there finding.Finding
		if err := f.db.DB.NewSelect().Model(&there).
			Where("vulnerability_id = ?", issue).Limit(1).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		there.ID = 0
		there.TargetID = elsewhere
		farOff := time.Now().Add(90 * 24 * time.Hour).UTC()
		there.DiscloseAt = &farOff
		if _, err := f.db.DB.NewInsert().Model(&there).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		row := map[string]any{
			"claim_id":   claimBy(t, f.db, who.ID),
			"product_id": other, "vulnerability_id": issue,
			"place_identity": there.PlaceIdentity, "visibility": "private",
			"state": "proposed", "needs_approval": true, "proposed_by": who.ID,
			"proposed_at": time.Now().UTC(),
		}
		if _, err := f.db.DB.NewInsert().Model(&row).TableExpr(`"decision"`).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		both := access.NewPerson(who.ID, "both@example.com", false, map[int64][]access.Role{
			f.productID: {access.PrivateTriage}, other: {access.PrivateTriage},
		}, 0)
		asked, err := f.store.Extend(ctx, both, other, issue,
			farOff.Add(90*24*time.Hour), "Upstream has not answered.")
		if err != nil {
			t.Fatal(err)
		}
		if !asked.NeedsApproval {
			t.Fatal("a three-month extension stood alone")
		}

		if _, err := f.store.Disclose(ctx, who, f.productID, issue, "Published here."); err != nil {
			t.Fatal(err)
		}
		var private int
		private, err = f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			Where("target_id = ?", elsewhere).
			Where("visibility = ?", access.Private).Count(ctx)
		if err != nil || private != 1 {
			t.Errorf("the other product's finding is undisclosed %d times (%v), want once", private, err)
		}
		private, err = f.db.DB.NewSelect().TableExpr(`"decision"`).
			Where(`"product_id" = ?`, other).
			Where(`"visibility" = ?`, access.Private).Count(ctx)
		if err != nil || private != 1 {
			t.Errorf("the other product's decision is undisclosed %d times (%v), want once", private, err)
		}
		waiting, _, err := f.store.PendingPage(ctx, both, 50, 0)
		if err != nil || len(waiting) != 1 || waiting[0].ProductID != other {
			t.Errorf("after disclosing elsewhere the queue holds %+v (%v), want the other product's extension",
				waiting, err)
		}
	})
}

func TestADisclosureWaitingDoesNotHoldBackOneThatNeedsNobody(t *testing.T) {
	// A disclosure asked for early waits for a second person. Once the date
	// has arrived a new one needs nobody, and the one still waiting does not
	// stand in its way.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.embargoed(t, who)
		f.dated(t, issue, time.Now().Add(60*24*time.Hour))
		early, err := f.store.Disclose(ctx, who, f.productID, issue, "It may leak.")
		if err != nil || !early.NeedsApproval {
			t.Fatalf("disclosing two months early answered %+v, %v", early, err)
		}

		f.dated(t, issue, time.Now().Add(-time.Hour))
		done, err := f.store.Disclose(ctx, who, f.productID, issue, "The date has come.")
		if err != nil {
			t.Fatalf("disclosing on the date with one waiting answered %v", err)
		}
		if !done.InForce() {
			t.Errorf("disclosing on the date waited: %+v", done)
		}
		if n, _ := f.undisclosed(t, issue); n != 0 {
			t.Errorf("%d findings are still undisclosed", n)
		}
	})
}

func TestTheEndOfAnEmbargoIsReadFromTheOpenPlaces(t *testing.T) {
	// A movement reads and moves the open places. A closed place keeps the
	// date it closed with, and a date it carries that is later than the one
	// the open places have been moved to is not the end of the embargo.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		issue := f.embargoed(t, who)
		var places []finding.Finding
		if err := f.db.DB.NewSelect().Model(&places).
			Where("vulnerability_id = ?", issue).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		closed := places[0]
		closed.ID = 0
		// A place identity is a digest at the column's full width, so a
		// second place is a different digest of that width.
		closed.PlaceIdentity = strings.Repeat("f", len(closed.PlaceIdentity))
		now := time.Now().UTC()
		later := now.Add(60 * 24 * time.Hour)
		closed.DiscloseAt = &later
		closed.ClosedAt = &now
		if _, err := f.db.DB.NewInsert().Model(&closed).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("disclose_at = ?", now.Add(-time.Hour)).
			Where("vulnerability_id = ?", issue).
			Where("closed_at IS NULL").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		done, err := f.store.Disclose(ctx, who, f.productID, issue, "The date has come.")
		if err != nil {
			t.Fatal(err)
		}
		if done.NeedsApproval {
			t.Error("a closed place's later date sent a disclosure whose date has arrived to a queue")
		}
	})
}

func TestADisclosedIssueCarriesNoDateAndItsHistoryIsPublic(t *testing.T) {
	// A public finding carries no disclosure date, and the history of the
	// embargo is part of the record disclosing opens.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		public := f.planner(t, access.PublicRead)
		issue := f.embargoed(t, who)
		f.dated(t, issue, time.Now().Add(-time.Hour))

		if _, err := f.store.Movements(ctx, public, f.productID, issue); err == nil {
			t.Error("a public reader read the history of an embargo still running")
		}
		if _, err := f.store.Disclose(ctx, who, f.productID, issue, "Published."); err != nil {
			t.Fatal(err)
		}
		dated, err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			Where("vulnerability_id = ?", issue).
			Where("disclose_at IS NOT NULL").Count(ctx)
		if err != nil || dated != 0 {
			t.Errorf("%d disclosed findings still carry a disclosure date (%v)", dated, err)
		}
		history, err := f.store.Movements(ctx, public, f.productID, issue)
		if err != nil {
			t.Fatalf("a public reader could not read the history of a disclosed issue: %v", err)
		}
		if len(history) != 1 || history[0].Act != finding.Disclosure || history[0].Reason != "Published." {
			t.Errorf("the history reads %+v, want the disclosure and its reason", history)
		}
	})
}
