// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// The two names one issue goes by while the feeds disagree: the national
// identifier a distribution's feed matched, and the advisory identifier
// another feed matched before a national one was assigned.
const (
	national = "CVE-2026-4040"
	advisory = "GHSA-aaaa-bbbb-cccc"
)

// reporting runs the scanner over what is stored, reporting exactly these.
func (f *runFixture) reporting(t *testing.T, reported ...finding.Reported) *scanner.Outcome {
	t.Helper()
	f.waiting(t)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	outcome, err := scanner.NewRunner(f.db, f.queue, &stub{reported: reported}, quiet, "test").
		TellingSuperseded(notify.Superseded(f.db.DB, quiet)).
		Once(t.Context())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if outcome == nil {
		t.Fatal("there was work waiting and nothing was done")
	}
	return outcome
}

// named is one issue a report gives under one name and these others.
func named(identifier string, component graph.Described, aliases ...string) finding.Reported {
	return finding.Reported{
		Issue:     finding.Named{Identifier: identifier, Aliases: aliases, Severity: "high"},
		Component: component, FixState: finding.NoFix,
	}
}

// triagers is two people holding triage on the product, the second of whom
// may approve.
func (f *runFixture) triagers(t *testing.T) (proposer, approver access.Subject) {
	t.Helper()
	ctx := t.Context()
	rights := access.NewStore(f.db.DB)
	product, err := catalog.NewStore(f.db.DB).ProductByName(ctx, "sonic")
	if err != nil {
		t.Fatal(err)
	}
	var people []access.Subject
	for _, who := range []string{"proposer", "approver"} {
		person, err := rights.Ensure(ctx, who, "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, person.ID, product.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		subject, err := rights.Resolve(ctx, who)
		if err != nil {
			t.Fatal(err)
		}
		people = append(people, subject)
	}
	return people[0], people[1]
}

// placeOf is where one issue sits on one component under swss, as the
// finding reads it now.
func (f *runFixture) placeOf(t *testing.T, who access.Subject, issueName, component string) triage.Place {
	t.Helper()
	ctx := t.Context()
	issue, err := finding.NewVulnerabilities(f.db.DB).ByName(ctx, issueName)
	if err != nil {
		t.Fatal(err)
	}
	consumer := "libswsscommon"
	if component == "libswsscommon" {
		consumer = ""
	}
	where, err := finding.NewStore(f.db.DB).PlaceFor(ctx, who, f.target, issue,
		finding.PlaceIdentity(component, consumer))
	if err != nil {
		t.Fatal(err)
	}
	return triage.Place{
		ProductID: where.ProductID, VulnerabilityID: where.VulnerabilityID,
		PlaceIdentity: where.PlaceIdentity, Visibility: where.Visibility,
		ComponentUpstream: where.ComponentUpstream, ConsumerUpstream: where.ConsumerUpstream,
	}
}

// claims records one judgment at a place, agreed to by the approver where
// agreed is set.
func (f *runFixture) claims(t *testing.T, proposer, approver access.Subject, at triage.Place,
	outcome triage.Outcome, agreed bool) *triage.Decision {

	t.Helper()
	ctx := t.Context()
	store := triage.NewStore(f.db.DB)
	proposal := triage.Proposal{
		Place: at, Outcome: outcome,
		Reasoning: "Read against the code this build ships.",
		By:        proposer.ID, NeedsApproval: agreed,
	}
	if outcome == triage.NotApplicable {
		proposal.Justification = triage.CodeNotInExecutePath
	}
	made, err := store.Propose(ctx, proposer, proposal)
	if err != nil {
		t.Fatal(err)
	}
	if agreed {
		if _, err := store.ApproveClaim(ctx, approver, made.ClaimID, "", nil, ""); err != nil {
			t.Fatal(err)
		}
	}
	return made
}

// recorded is what a decision says about itself, read back as stored.
type recorded struct {
	ID              int64     `bun:"id"`
	ClaimID         int64     `bun:"claim_id"`
	VulnerabilityID int64     `bun:"vulnerability_id"`
	PlaceIdentity   string    `bun:"place_identity"`
	State           string    `bun:"state"`
	ProposedBy      int64     `bun:"proposed_by"`
	ProposedAt      time.Time `bun:"proposed_at"`
}

func (f *runFixture) decisionRows(t *testing.T) map[int64]recorded {
	t.Helper()
	var rows []recorded
	if err := f.db.DB.NewSelect().TableExpr(`"decision" AS "de"`).
		ColumnExpr("de.id, de.claim_id, de.vulnerability_id, de.place_identity").
		ColumnExpr("de.state, de.proposed_by, de.proposed_at").
		Scan(t.Context(), &rows); err != nil {
		t.Fatal(err)
	}
	out := map[int64]recorded{}
	for _, row := range rows {
		out[row.ID] = row
	}
	return out
}

func TestAReportJoiningTwoIssuesHeldApartMergesThemAndApplies(t *testing.T) {
	// One feed matched the national identifier on the distribution's copy of
	// a library; another matched its own advisory on a second copy before a
	// national identifier was assigned. When the second learns the first,
	// its report names both. Refused, that report failed the scan it was in
	// and every scan of the build after it, so the build never updated again.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.reporting(t, named(national, libnl), named(advisory, swss))
		proposer, approver := f.triagers(t)
		onLibnl := f.claims(t, proposer, approver, f.placeOf(t, proposer, national, "libnl-3-200"),
			triage.Affected, false)
		onSwss := f.claims(t, proposer, approver, f.placeOf(t, proposer, advisory, "libswsscommon"),
			triage.NotApplicable, true)
		before := f.decisionRows(t)

		outcome := f.reporting(t, named(national, libnl), named(advisory, swss, national))
		if outcome.Applied.Merged != 1 {
			t.Errorf("the report merged %d issues, want 1", outcome.Applied.Merged)
		}

		// One issue, under the name it is best known by, and every name
		// finds it.
		issues := finding.NewVulnerabilities(f.db.DB)
		kept, err := issues.ByName(ctx, national)
		if err != nil {
			t.Fatal(err)
		}
		also, err := issues.ByName(ctx, advisory)
		if err != nil {
			t.Fatal(err)
		}
		if kept != also {
			t.Fatalf("%s is issue %d and %s is issue %d after a report named them together",
				national, kept, advisory, also)
		}
		merges, err := finding.MergesInto(ctx, f.db.DB, kept)
		if err != nil {
			t.Fatal(err)
		}
		if len(merges) != 1 || merges[0].AbsorbedID != onSwss.VulnerabilityID ||
			merges[0].RunID == nil {
			t.Errorf("the merge is recorded as %+v, want %d merged into %d by the run",
				merges, onSwss.VulnerabilityID, kept)
		}
		for _, open := range f.openFindings(t) {
			if open.VulnerabilityID != kept {
				t.Errorf("finding %d is still filed under issue %d", open.ID, open.VulnerabilityID)
			}
		}

		// What was decided under either name applies to the one issue.
		store := triage.NewStore(f.db.DB)
		for name, at := range map[string]triage.Place{
			"the national name's": f.placeOf(t, proposer, national, "libnl-3-200"),
			"the advisory name's": f.placeOf(t, proposer, advisory, "libswsscommon"),
		} {
			standing, err := store.Applying(ctx, at)
			if err != nil {
				t.Fatal(err)
			}
			if standing == nil {
				t.Errorf("%s decision no longer applies once the issues merged", name)
			}
		}
		if got := f.undecided(t, proposer); got != 0 {
			t.Errorf("%d rows read as undecided after the merge, want none", got)
		}
		if got := f.stateOf(t, proposer, "libswsscommon"); got != "agreed" {
			t.Errorf("the row agreed under the advisory name reads %q after the merge", got)
		}

		// And what was recorded is what it was: the issue each decision was
		// filed under, its claim, its place, its state, who made it and when.
		after := f.decisionRows(t)
		for id, was := range before {
			if now := after[id]; now != was {
				t.Errorf("decision %d was %+v and is %+v", id, was, now)
			}
		}
		if len(after) != len(before) {
			t.Errorf("the merge wrote %d decisions beside %d", len(after), len(before))
		}

		// A claim about the same place under the issue that stands meets the
		// one filed under the other name.
		if _, err := store.Propose(ctx, proposer, triage.Proposal{
			Place: f.placeOf(t, proposer, national, "libswsscommon"), Outcome: triage.Affected,
			Reasoning: "Read again.", By: proposer.ID,
		}); !errors.Is(err, triage.ErrAlreadyDecided) {
			t.Errorf("a second claim at a place decided under the merged name answered %v", err)
		}

		// The next report finds one issue and merges nothing.
		again := f.reporting(t, named(national, libnl), named(advisory, swss, national))
		if again.Applied.Merged != 0 || again.Applied.Closed != 0 {
			t.Errorf("the next scan merged %d and closed %d", again.Applied.Merged, again.Applied.Closed)
		}
		_ = onLibnl
	})
}

func TestAMergeMeetingTwoDecisionsThatDisagreeKeepsTheApprovedOneAndTellsTheTriagers(t *testing.T) {
	// One feed and another both matched the library before either knew the
	// other's name, so one place held a finding under each and somebody
	// decided each. Merged, the place holds one finding and has to hold one
	// live decision. The approved one is the older, so only standing keeps
	// it.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.reporting(t, named(national, libnl), named(advisory, libnl))
		proposer, approver := f.triagers(t)
		agreed := f.claims(t, proposer, approver, f.placeOf(t, proposer, advisory, "libnl-3-200"),
			triage.NotApplicable, true)
		waiting := f.claims(t, proposer, approver, f.placeOf(t, proposer, national, "libnl-3-200"),
			triage.Affected, false)

		f.reporting(t, named(advisory, libnl, national))

		if open := f.openFindings(t); len(open) != 1 {
			t.Errorf("one place is held by %d open findings after the merge", len(open))
		}
		after := f.decisionRows(t)
		if after[agreed.ID].State != string(triage.Approved) {
			t.Errorf("the approved decision is %s after the merge", after[agreed.ID].State)
		}
		if after[waiting.ID].State != string(triage.LapsedState) {
			t.Errorf("the proposed decision it disagreed with is %s, want lapsed",
				after[waiting.ID].State)
		}
		var why []finding.SupersededDecision
		if err := f.db.DB.NewSelect().Model(&why).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if len(why) != 1 || why[0].DecisionID != waiting.ID || why[0].StandingID != agreed.ID ||
			!why[0].Disagreed {
			t.Errorf("the lapse is recorded as %+v", why)
		}
		standing, err := triage.NewStore(f.db.DB).Applying(ctx,
			f.placeOf(t, proposer, national, "libnl-3-200"))
		if err != nil {
			t.Fatal(err)
		}
		if standing == nil || standing.ID != agreed.ID {
			t.Errorf("the place is answered by %+v, want decision %d", standing, agreed.ID)
		}

		// Everybody who triages the product is told, because nobody chose
		// which of the two stands.
		for _, who := range []access.Subject{proposer, approver} {
			if told := f.toldOf(t, who, notify.MergeSuperseded); told != 1 {
				t.Errorf("%s was told %d times that a merge superseded a decision",
					who.Identity, told)
			}
		}
	})
}

func TestAMergeMeetingTwoDecisionsThatAgreeKeepsOneAndTellsNobody(t *testing.T) {
	// Two people reached the same answer under the two names. The place keeps
	// one live decision, the newer, and nothing about it is news.
	eachRun(t, func(t *testing.T, f *runFixture) {
		f.reporting(t, named(national, libnl), named(advisory, libnl))
		proposer, approver := f.triagers(t)
		older := f.claims(t, proposer, approver, f.placeOf(t, proposer, national, "libnl-3-200"),
			triage.NotApplicable, true)
		newer := f.claims(t, proposer, approver, f.placeOf(t, proposer, advisory, "libnl-3-200"),
			triage.NotApplicable, true)

		f.reporting(t, named(advisory, libnl, national))

		after := f.decisionRows(t)
		if after[newer.ID].State != string(triage.Approved) ||
			after[older.ID].State != string(triage.LapsedState) {
			t.Errorf("after the merge the older is %s and the newer %s",
				after[older.ID].State, after[newer.ID].State)
		}
		for _, who := range []access.Subject{proposer, approver} {
			if told := f.toldOf(t, who, notify.MergeSuperseded); told != 0 {
				t.Errorf("%s was told %d times about two decisions that agreed",
					who.Identity, told)
			}
		}
	})
}

func TestARatingInForceUnderTheAbsorbedNameRatesTheMergedIssue(t *testing.T) {
	// A product that rated the issue under the name it was filed under then
	// has said what it thinks of the one issue. Left behind, the merged
	// issue's findings rank and come due by the published word the product
	// had disagreed with.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.reporting(t, named(national, libnl), named(advisory, swss))
		proposer, approver := f.triagers(t)
		issues := finding.NewVulnerabilities(f.db.DB)
		filed, err := issues.ByName(ctx, advisory)
		if err != nil {
			t.Fatal(err)
		}
		product, err := catalog.NewStore(f.db.DB).ProductByName(ctx, "sonic")
		if err != nil {
			t.Fatal(err)
		}
		store := finding.NewStore(f.db.DB)
		claim, err := store.Assess(ctx, proposer, product.ID, filed, "low",
			"Reachable only from the management network.")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Agree(ctx, approver, claim.ID); err != nil {
			t.Fatal(err)
		}

		f.reporting(t, named(national, libnl), named(advisory, swss, national))

		kept, err := issues.ByName(ctx, national)
		if err != nil {
			t.Fatal(err)
		}
		rated, err := finding.RatingIn(ctx, f.db.DB, product.ID, kept)
		if err != nil {
			t.Fatal(err)
		}
		if rated != "low" {
			t.Errorf("the merged issue is rated %q in the product, want the product's low", rated)
		}

		// And taking the claim back puts the published word back for the one
		// issue, not for a row nothing reads.
		if _, err := store.Withdraw(ctx, proposer, claim.ID); err != nil {
			t.Fatal(err)
		}
		rated, err = finding.RatingIn(ctx, f.db.DB, product.ID, kept)
		if err != nil {
			t.Fatal(err)
		}
		if rated != "" {
			t.Errorf("withdrawn, the merged issue is still rated %q in the product", rated)
		}
	})
}

func TestAMergeMeetingTwoRatingsThatDisagreeKeepsTheOneInForceAndTellsTheTriagers(t *testing.T) {
	// The product rated the issue under each name before a report joined
	// them: worse under one, in force at once, and later milder under the
	// other, waiting for a second person. One issue carries one rating
	// claim, and the one in force outranks the newer.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.reporting(t, named(national, libnl), named(advisory, swss))
		proposer, approver := f.triagers(t)
		product, store, issues := f.rating(t)
		underNational, err := issues.ByName(ctx, national)
		if err != nil {
			t.Fatal(err)
		}
		underAdvisory, err := issues.ByName(ctx, advisory)
		if err != nil {
			t.Fatal(err)
		}
		worse, err := store.Assess(ctx, approver, product, underAdvisory, "critical",
			"Reachable from any port the switch answers on.")
		if err != nil {
			t.Fatal(err)
		}
		milder, err := store.Assess(ctx, proposer, product, underNational, "low",
			"Reachable only from the management network.")
		if err != nil {
			t.Fatal(err)
		}

		f.reporting(t, named(national, libnl), named(advisory, swss, national))

		claims := map[int64]finding.Assessment{}
		var rows []finding.Assessment
		if err := f.db.DB.NewSelect().Model(&rows).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			claims[row.ID] = row
		}
		if got := claims[worse.ID]; got.State != finding.AssessmentLive ||
			got.LiveVulnerabilityID == nil || *got.LiveVulnerabilityID != underNational {
			t.Errorf("the claim in force is %s and held under %v, want live under %d",
				got.State, got.LiveVulnerabilityID, underNational)
		}
		gone := claims[milder.ID]
		want := "Superseded when " + strings.ToUpper(advisory) + " merged into " + national + "."
		if gone.State != finding.AssessmentWithdrawn || gone.LiveVulnerabilityID != nil ||
			gone.DecidedBy != nil || gone.WithdrawnBecause == nil || *gone.WithdrawnBecause != want {
			t.Errorf("the claim with less standing is %s, held under %v, decided by %v, because %v",
				gone.State, gone.LiveVulnerabilityID, gone.DecidedBy, deref(gone.WithdrawnBecause))
		}
		rated, err := finding.RatingIn(ctx, f.db.DB, product, underNational)
		if err != nil {
			t.Fatal(err)
		}
		if rated != "critical" {
			t.Errorf("the merged issue is rated %q in the product, want critical", rated)
		}
		// The claim that stands holds the key for the one issue, so a third
		// claim finds it in the way.
		if _, err := store.Assess(ctx, proposer, product, underNational, "medium",
			"A third reading."); !errors.Is(err, finding.ErrAlreadyAssessed) {
			t.Errorf("a new claim beside the one that stands answered %v", err)
		}
		f.trailedByMerge(t, trail.Merge, 1)
		for _, who := range []access.Subject{proposer, approver} {
			if told := f.toldOf(t, who, notify.MergeSuperseded); told != 1 {
				t.Errorf("%s was told %d times that a merge superseded a rating",
					who.Identity, told)
			}
		}
	})
}

func TestAMergeMeetingTwoRatingsThatAgreeKeepsTheNewerAndTellsNobody(t *testing.T) {
	// Both in force and both the same word: the newer stands and nothing
	// about the product's rating changed.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.reporting(t, named(national, libnl), named(advisory, swss))
		proposer, approver := f.triagers(t)
		product, store, issues := f.rating(t)
		underNational, err := issues.ByName(ctx, national)
		if err != nil {
			t.Fatal(err)
		}
		underAdvisory, err := issues.ByName(ctx, advisory)
		if err != nil {
			t.Fatal(err)
		}
		older, err := store.Assess(ctx, approver, product, underAdvisory, "critical",
			"Reachable from any port the switch answers on.")
		if err != nil {
			t.Fatal(err)
		}
		newer, err := store.Assess(ctx, proposer, product, underNational, "critical",
			"Reachable from the data plane.")
		if err != nil {
			t.Fatal(err)
		}

		f.reporting(t, named(national, libnl), named(advisory, swss, national))

		var rows []finding.Assessment
		if err := f.db.DB.NewSelect().Model(&rows).OrderExpr("id").Scan(ctx); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			want := finding.AssessmentLive
			if row.ID == older.ID {
				want = finding.AssessmentWithdrawn
			}
			if row.ID != older.ID && row.ID != newer.ID {
				t.Errorf("claim %d is not one the test made", row.ID)
			}
			if row.State != want {
				t.Errorf("claim %d is %s after the merge, want %s", row.ID, row.State, want)
			}
		}
		for _, who := range []access.Subject{proposer, approver} {
			if told := f.toldOf(t, who, notify.MergeSuperseded); told != 0 {
				t.Errorf("%s was told %d times about two ratings that agreed",
					who.Identity, told)
			}
		}
	})
}

func TestAMergeMeetingTwoRecordsOfAnAttackKeepsTheNewerAndTellsTheTriagers(t *testing.T) {
	// The product recorded being attacked under each name, dated
	// differently. Every window after an attack counts from the date, so
	// which one stands is news to the product.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		f.reporting(t, named(national, libnl), named(advisory, swss))
		proposer, approver := f.triagers(t)
		product, _, issues := f.rating(t)
		underNational, err := issues.ByName(ctx, national)
		if err != nil {
			t.Fatal(err)
		}
		underAdvisory, err := issues.ByName(ctx, advisory)
		if err != nil {
			t.Fatal(err)
		}
		records := triage.NewStore(f.db.DB)
		known := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
		older, _, err := records.RecordExploitedHere(ctx, proposer, product, underAdvisory,
			known, "A customer's switch was taken over through the netlink parser.")
		if err != nil {
			t.Fatal(err)
		}
		newer, _, err := records.RecordExploitedHere(ctx, approver, product, underNational,
			known.Add(24*time.Hour), "Our own lab reproduced the takeover.")
		if err != nil {
			t.Fatal(err)
		}

		f.reporting(t, named(national, libnl), named(advisory, swss, national))

		var rows []triage.ExploitedHere
		if err := f.db.DB.NewSelect().Model(&rows).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		got := map[int64]triage.ExploitedHere{}
		for _, row := range rows {
			got[row.ID] = row
		}
		if stands := got[newer.ID]; !stands.Standing() || stands.LiveVulnerabilityID == nil ||
			*stands.LiveVulnerabilityID != underNational {
			t.Errorf("the newer record stands %v under %v, want standing under %d",
				stands.Standing(), stands.LiveVulnerabilityID, underNational)
		}
		gone := got[older.ID]
		want := "Superseded when " + strings.ToUpper(advisory) + " merged into " + national + "."
		if gone.Standing() || gone.LiveVulnerabilityID != nil || gone.ClearedBy != nil ||
			gone.ClearedBecause == nil || *gone.ClearedBecause != want {
			t.Errorf("the older record stands %v, held under %v, cleared by %v, because %v",
				gone.Standing(), gone.LiveVulnerabilityID, gone.ClearedBy, deref(gone.ClearedBecause))
		}
		if _, _, err := records.RecordExploitedHere(ctx, proposer, product, underNational,
			known, "A third report."); !errors.Is(err, triage.ErrAlreadyExploitedHere) {
			t.Errorf("a new record beside the one that stands answered %v", err)
		}
		f.trailedByMerge(t, trail.Merge, 1)
		for _, who := range []access.Subject{proposer, approver} {
			if told := f.toldOf(t, who, notify.MergeSuperseded); told != 1 {
				t.Errorf("%s was told %d times that a merge superseded a record of an attack",
					who.Identity, told)
			}
		}
	})
}

// rating is the product the fixture's build belongs to, and the stores a
// rating is recorded and read through.
func (f *runFixture) rating(t *testing.T) (int64, *finding.Store, *finding.Vulnerabilities) {
	t.Helper()
	product, err := catalog.NewStore(f.db.DB).ProductByName(t.Context(), "sonic")
	if err != nil {
		t.Fatal(err)
	}
	return product.ID, finding.NewStore(f.db.DB), finding.NewVulnerabilities(f.db.DB)
}

// openFindings is every open finding of the fixture's build.
func (f *runFixture) openFindings(t *testing.T) []finding.Finding {
	t.Helper()
	var rows []finding.Finding
	if err := f.db.DB.NewSelect().Model(&rows).
		Where("target_id = ?", f.target).Where("closed_at IS NULL").
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

// undecided is how many rows of the build's list read as undecided.
func (f *runFixture) undecided(t *testing.T, who access.Subject) int {
	t.Helper()
	product, err := catalog.NewStore(f.db.DB).ProductByName(t.Context(), "sonic")
	if err != nil {
		t.Fatal(err)
	}
	scope := finding.Scope{ProductID: &product.ID}
	_, total, err := finding.NewStore(f.db.DB).Groups(t.Context(), who, scope, 50, 0,
		finding.Filter{States: []finding.ClaimStanding{"undecided"}})
	if err != nil {
		t.Fatal(err)
	}
	return total
}

// stateOf is the word the build's list gives the row for one component.
func (f *runFixture) stateOf(t *testing.T, who access.Subject, component string) string {
	t.Helper()
	product, err := catalog.NewStore(f.db.DB).ProductByName(t.Context(), "sonic")
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := finding.NewStore(f.db.DB).Groups(t.Context(), who,
		finding.Scope{ProductID: &product.ID}, 50, 0, finding.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Component == component {
			return string(row.State)
		}
	}
	t.Fatalf("no row for %s", component)
	return ""
}

// toldOf counts what one person has waiting of one kind.
func (f *runFixture) toldOf(t *testing.T, who access.Subject, kind notify.Kind) int {
	t.Helper()
	waiting, _, err := notify.NewStore(f.db.DB).Waiting(t.Context(), who, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, one := range waiting {
		if one.Kind == kind {
			n++
		}
	}
	return n
}

// deref reads a text column that may hold nothing.
func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
