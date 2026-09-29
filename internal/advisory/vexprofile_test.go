// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// What an advisory states about a release its decisions cover.
//
// Every test here runs on every engine: what each pins is what the query that
// reads the decisions does, and the join deciding what a customer is told is
// where a portability trap shows.

const (
	// stops is what a mitigation says, which a document publishes.
	stops = "The management socket is bound to the loopback interface only."
	// argued is what the reasoning says, which a document never publishes.
	argued = "Read the unit files and the socket options on every image we ship."
)

var (
	master  = "sonic:" + fixtures.BranchName + ":broadcom"
	tagged  = "sonic:" + fixtures.TagName + ":broadcom"
	onPlace = finding.PlaceIdentity(carrier.Name, "")
)

// issueOf is the issue a flaw was recorded as.
func (f *fixture) issueOf(t *testing.T, identifier string) int64 {
	t.Helper()
	id, err := finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), identifier)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// claimed has the first person claim something about the flaw at one place in
// one build, made on that build, and answers the claim. Nobody has agreed to
// it.
func (f *fixture) claimed(t *testing.T, target int64, identifier, place string,
	outcome triage.Outcome, why triage.Justification, mitigation string) int64 {

	t.Helper()
	return f.claimedOn(t, target, []int64{target}, identifier, place, outcome, why, mitigation)
}

// claimedOn is the same, recorded as made on the builds given: the one on
// screen and those chosen beside it, or none.
func (f *fixture) claimedOn(t *testing.T, target int64, madeOn []int64, identifier,
	place string, outcome triage.Outcome, why triage.Justification, mitigation string) int64 {

	t.Helper()
	ctx := t.Context()
	at, err := f.finds.PlaceFor(ctx, f.who, target, f.issueOf(t, identifier), place)
	if err != nil {
		t.Fatalf("finding the place to decide about: %v", err)
	}
	decision, err := triage.NewStore(f.db.DB).Propose(ctx, f.who, triage.Proposal{
		Place: triage.Place{
			ProductID: at.ProductID, VulnerabilityID: at.VulnerabilityID,
			PlaceIdentity: at.PlaceIdentity, Visibility: at.Visibility,
			ComponentUpstream: at.ComponentUpstream, ConsumerUpstream: at.ConsumerUpstream,
			OnTag: at.OnTag,
		},
		Outcome: outcome, Justification: why, Mitigation: mitigation,
		Reasoning: argued, By: f.who.ID, NeedsApproval: true, MadeOn: madeOn,
	})
	if err != nil {
		t.Fatalf("claiming %s: %v", outcome, err)
	}
	return decision.ClaimID
}

// agree has the second person agree to a claim.
func (f *fixture) agree(t *testing.T, claim int64) {
	t.Helper()
	if _, err := triage.NewStore(f.db.DB).ApproveClaim(t.Context(), f.approver, claim,
		"", nil, ""); err != nil {
		t.Fatalf("agreeing to the claim: %v", err)
	}
}

// dismissed is a claim that the flaw does not apply at its place, agreed to.
func (f *fixture) dismissed(t *testing.T, target int64, identifier string) int64 {
	t.Helper()
	claim := f.claimed(t, target, identifier, onPlace, triage.NotApplicable,
		triage.MitigationsExist, stops)
	f.agree(t, claim)
	return claim
}

// elsewhereIn files the same issue against a second place in a build, which a
// decision about the first place does not reach.
func (f *fixture) elsewhereIn(t *testing.T, identifier string, target int64) {
	t.Helper()
	f.filed(t, identifier, target, finding.PlaceIdentity(carrier.Name, "the other consumer"),
		nil, "")
}

// filed writes one finding of the issue in a build at a place, closed for a
// reason where one is given.
func (f *fixture) filed(t *testing.T, identifier string, target int64, place string,
	closed *time.Time, because finding.Closure) {

	t.Helper()
	ctx := t.Context()
	var componentID int64
	if err := f.db.DB.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON c.id = n.component_id`).
		ColumnExpr("c.id").
		Where("n.target_id = ?", target).
		Where("c.name = ?", carrier.Name).
		Limit(1).Scan(ctx, &componentID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := &finding.Finding{
		TargetID: target, Kind: finding.Vulnerable, Visibility: access.Private,
		VulnerabilityID: f.issueOf(t, identifier), ComponentID: componentID,
		PlaceIdentity: place, LastChangedAt: now, OpenedAt: now,
		ClosedAt: closed, ClosedBecause: because,
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatal(err)
	}
}

// rated gives the flaw a version 3 rating, which the document states a score
// for.
func (f *fixture) rated(t *testing.T, identifier string) {
	t.Helper()
	if _, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(), []finding.Named{{
		Identifier: identifier,
		Ratings: []finding.CVSS{{Generation: 3, ScoreCenti: 810,
			Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", Version: "3.1"}},
	}}); err != nil {
		t.Fatalf("rating the flaw: %v", err)
	}
}

// generated is the advisory's document as it stands.
func (f *fixture) generated(t *testing.T, named string) *advisory.Document {
	t.Helper()
	doc, err := f.store.ForAdvisory(t.Context(), f.who, issuer, named)
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	return doc
}

// placedAt is what the advisory screen reads about one release.
func (f *fixture) placedAt(t *testing.T, named, release string) advisory.Placed {
	t.Helper()
	rows, err := f.store.Releases(t.Context(), f.who, named)
	if err != nil {
		t.Fatalf("reading the releases: %v", err)
	}
	for _, row := range rows {
		if row.ProductID(row.Covered.Product) == release {
			return row
		}
	}
	t.Fatalf("no release %s among %d", release, len(rows))
	return advisory.Placed{}
}

func TestAReleaseEveryOpenPlaceOfWhichIsDismissedIsKnownNotAffected(t *testing.T) {
	// The advisory says "known not affected, because…" of a release whose
	// every open place stands under an approved, live claim that the flaw
	// does not apply, which is what the VEX document of one build already
	// says of it. The reason is the flag a machine reads; the mitigation is
	// the impact a person reads.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		f.alsoIn(t, identifier, f.tagged)
		// The tag holds the flaw at a second place nobody dismissed, so the
		// document carries a release that stays affected beside the one that
		// does not — which is what remediations and scores are asked of.
		f.elsewhereIn(t, identifier, f.tagged)
		f.rated(t, identifier)
		f.dismissed(t, f.master, identifier)
		named := f.covering(t, [2]string{"sonic", identifier})

		doc := f.generated(t, named)
		one := doc.Vulnerabilities[0]
		if !slices.Equal(one.Status.KnownNotAffected, []string{master}) {
			t.Errorf("known not affected: %v, want the branch", one.Status.KnownNotAffected)
		}
		if !slices.Equal(one.Status.KnownAffected, []string{tagged}) {
			t.Errorf("known affected: %v, want the tag", one.Status.KnownAffected)
		}
		if len(one.Flags) != 1 || one.Flags[0].Label != string(triage.MitigationsExist) ||
			!slices.Equal(one.Flags[0].ProductIDs, []string{master}) {
			t.Errorf("flags: %+v, want the reason on the branch", one.Flags)
		}
		if len(one.Threats) != 1 || one.Threats[0].Category != "impact" ||
			one.Threats[0].Details != stops ||
			!slices.Equal(one.Threats[0].ProductIDs, []string{master}) {
			t.Errorf("threats: %+v, want the mitigation as the branch's impact", one.Threats)
		}
		// Neither scored nor told to update: a rating is stated for a release
		// the flaw is in, and a remediation for a release that has to act.
		for _, score := range one.Scores {
			if slices.Contains(score.Products, master) {
				t.Errorf("a score is stated for the release that is not affected: %v",
					score.Products)
			}
		}
		if len(one.Scores) == 0 {
			t.Error("the fixture's flaw carries no score, so this checked nothing")
		}
		for _, fix := range one.Remediations {
			if slices.Contains(fix.ProductIDs, master) {
				t.Errorf("a remediation is stated for the release that is not affected: %+v", fix)
			}
		}
		if len(one.Remediations) == 0 {
			t.Error("the affected tag has no remediation, which the profile asks for")
		}
		if doc.Document.Category != "csaf_security_advisory" {
			t.Errorf("a document stating a release not affected declares %q",
				doc.Document.Category)
		}
		required(t, doc)
		explained(t, doc)

		// The screen names the decision and where it was made.
		row := f.placedAt(t, named, master)
		if row.Grounds == nil || row.Grounds.Reason != string(triage.MitigationsExist) ||
			!slices.Equal(variantsOf(row.Grounds.MadeOn), []string{"broadcom"}) || row.MadeElsewhere() {
			t.Errorf("the screen reads %+v, want the decision made here on broadcom", row.Grounds)
		}
	})
}

func TestTheDecisionsReasoningNeverReachesTheDocument(t *testing.T) {
	// The reasoning is the argument a triager put to a second person here.
	// Published it is this deployment's review of itself, in front of every
	// customer; the mitigation is the half a holder of the release can act on.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		f.dismissed(t, f.master, identifier)
		doc := f.generated(t, f.covering(t, [2]string{"sonic", identifier}))
		body, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), stops) {
			t.Fatal("the mitigation is not in the document, so this checked nothing")
		}
		if strings.Contains(string(body), "unit files") {
			t.Errorf("the reasoning reached the document: %s", body)
		}
	})
}

func TestAReleaseWithAPlaceNobodyDismissedStaysKnownAffected(t *testing.T) {
	// One dismissal at one place does not speak for a release the flaw sits
	// at another place in. The document has no finer grain than the release.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		f.elsewhereIn(t, identifier, f.master)
		f.dismissed(t, f.master, identifier)
		named := f.covering(t, [2]string{"sonic", identifier})

		one := f.generated(t, named).Vulnerabilities[0]
		if !slices.Equal(one.Status.KnownAffected, []string{master}) ||
			len(one.Status.KnownNotAffected) != 0 || len(one.Flags) != 0 {
			t.Errorf("a partly dismissed release reads %+v with flags %+v", one.Status, one.Flags)
		}
		if f.placedAt(t, named, master).Grounds != nil {
			t.Error("the screen names a decision covering a release it covers part of")
		}
	})
}

func TestADismissalNobodyAgreedToOrThatWasWithdrawnLeavesTheReleaseAffected(t *testing.T) {
	// A proposal is one person's opinion, and a withdrawn claim covers
	// nothing. Only an approved, live decision moves what a document says.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		claim := f.claimed(t, f.master, identifier, onPlace, triage.NotApplicable,
			triage.CodeNotPresent, "")
		named := f.covering(t, [2]string{"sonic", identifier})

		status := func() advisory.Status {
			t.Helper()
			return f.generated(t, named).Vulnerabilities[0].Status
		}
		if got := status(); !slices.Equal(got.KnownAffected, []string{master}) {
			t.Errorf("a proposal nobody agreed to moved the release: %+v", got)
		}
		f.agree(t, claim)
		if got := status(); !slices.Equal(got.KnownNotAffected, []string{master}) {
			t.Errorf("an agreed dismissal left the release at %+v", got)
		}
		if err := triage.NewStore(f.db.DB).Withdraw(t.Context(), f.who, claim); err != nil {
			t.Fatal(err)
		}
		if got := status(); !slices.Equal(got.KnownAffected, []string{master}) {
			t.Errorf("a withdrawn dismissal still moves the release: %+v", got)
		}
	})
}

func TestAnAlreadyFixedClaimStatesTheReleaseFixed(t *testing.T) {
	// The claim that the fix is already in the release, agreed to, is what
	// the VEX document of a build states as fixed. The advisory states the
	// same of the release, and names it where it tells others to update.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		f.alsoIn(t, identifier, f.tagged)
		f.elsewhereIn(t, identifier, f.master)
		// Only the tag's one place is claimed fixed, and the branch keeps a
		// place the claim does not reach.
		at, err := f.finds.PlaceFor(t.Context(), f.who, f.tagged, f.issueOf(t, identifier), onPlace)
		if err != nil {
			t.Fatal(err)
		}
		decision, err := triage.NewStore(f.db.DB).Propose(t.Context(), f.who, triage.Proposal{
			Place: triage.Place{
				ProductID: at.ProductID, VulnerabilityID: at.VulnerabilityID,
				PlaceIdentity: at.PlaceIdentity, Visibility: at.Visibility,
				ComponentUpstream: at.ComponentUpstream, ConsumerUpstream: at.ConsumerUpstream,
				OnTag: at.OnTag,
			},
			Outcome: triage.AlreadyFixed, FixedVersion: "1.0.0-patched",
			Reasoning: argued, By: f.who.ID, NeedsApproval: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		f.agree(t, decision.ClaimID)

		one := f.generated(t, f.covering(t, [2]string{"sonic", identifier})).Vulnerabilities[0]
		if !slices.Equal(one.Status.Fixed, []string{tagged}) ||
			!slices.Equal(one.Status.KnownAffected, []string{master}) {
			t.Errorf("the status reads %+v, want the tag fixed and the branch affected", one.Status)
		}
		if len(one.Remediations) != 1 || !strings.Contains(one.Remediations[0].Details, "v2.4.1") {
			t.Errorf("the remediation does not name the fixed release: %+v", one.Remediations)
		}
	})
}

func TestAnAdvisoryIsASecurityAdvisoryWhateverItStates(t *testing.T) {
	// An advisory stating a release known not affected stays a security
	// advisory. Switching category between editions by what it contains, it
	// drops out of every reader that filters on the category, this
	// deployment's own supplier reader included; VEX is a separate document.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		named := f.covering(t, [2]string{"sonic", identifier})
		if got := f.generated(t, named).Document.Category; got != "csaf_security_advisory" {
			t.Errorf("a document stating nothing not affected declares %q", got)
		}
		f.dismissed(t, f.master, identifier)
		doc := f.generated(t, named)
		// Its only status is known not affected, which still states one for
		// every release it names, so it is complete.
		if len(doc.Vulnerabilities[0].Status.KnownAffected) != 0 ||
			len(doc.Vulnerabilities[0].Status.Fixed) != 0 ||
			len(doc.Vulnerabilities[0].Status.KnownNotAffected) == 0 {
			t.Fatalf("the fixture states more than not affected: %+v",
				doc.Vulnerabilities[0].Status)
		}
		if doc.Document.Category != "csaf_security_advisory" {
			t.Errorf("a document stating only not affected declares %q", doc.Document.Category)
		}
		required(t, doc)
		explained(t, doc)
	})
}

func TestAReleaseTakenOutOfAFlawsBuildsIsNotListedAsFixed(t *testing.T) {
	// Narrowing the builds a flaw is filed against closes the finding in a
	// build taken out, because that build never shipped the flaw. Named as
	// fixed, it reads as the release somebody upgrades to.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		issue := f.issueOf(t, identifier)
		if _, err := f.finds.Affects(t.Context(), f.who, f.product, issue,
			[]int64{f.master, f.tagged}, ""); err != nil {
			t.Fatalf("widening: %v", err)
		}
		if _, err := f.finds.Affects(t.Context(), f.who, f.product, issue,
			[]int64{f.master}, "The tag never shipped the socket."); err != nil {
			t.Fatalf("narrowing: %v", err)
		}

		doc := f.generated(t, f.covering(t, [2]string{"sonic", identifier}))
		one := doc.Vulnerabilities[0]
		if len(one.Status.Fixed) != 0 || !slices.Equal(one.Status.KnownAffected, []string{master}) {
			t.Errorf("the status reads %+v, want the branch alone", one.Status)
		}
		for _, product := range doc.ProductTree.Branches[0].Branches {
			for _, release := range product.Branches {
				if release.Product.ID == tagged {
					t.Error("the product tree names the release that never shipped the flaw")
				}
			}
		}
	})
}

func TestASupersededClosureIsNeverReadAsAFix(t *testing.T) {
	// A superseded row closed because the version moved and the flaw came
	// with it. A release whose only closure says that is still affected; one
	// where a later row closed for a reason that is a fix is fixed.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		then := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
		f.filed(t, identifier, f.tagged, onPlace, &then, finding.Superseded)
		named := f.covering(t, [2]string{"sonic", identifier})

		one := f.generated(t, named).Vulnerabilities[0]
		if len(one.Status.Fixed) != 0 || !slices.Contains(one.Status.KnownAffected, tagged) {
			t.Errorf("a release whose only closure is superseded reads %+v", one.Status)
		}
		// A scanner falling silent is not a fix either.
		f.filed(t, identifier, f.tagged, onPlace, &then, finding.Unexplained)
		one = f.generated(t, named).Vulnerabilities[0]
		if len(one.Status.Fixed) != 0 || !slices.Contains(one.Status.KnownAffected, tagged) {
			t.Errorf("a release whose closures are superseded and unexplained reads %+v", one.Status)
		}

		f.filed(t, identifier, f.tagged, onPlace, &then, finding.Upgraded)
		one = f.generated(t, named).Vulnerabilities[0]
		if !slices.Equal(one.Status.Fixed, []string{tagged}) {
			t.Errorf("a release a later closure fixed reads %+v", one.Status)
		}
	})
}

func TestMarkingAReleaseAffectedIsAnEditionOfWhatTheAdvisorySays(t *testing.T) {
	// The person preparing the advisory can say a release is affected
	// whatever its decisions say. That is part of what the document says, so
	// it opens an edition and takes back every agreement, as retitling does.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		f.dismissed(t, f.master, identifier)
		named := f.covering(t, [2]string{"sonic", identifier})
		f.agreed(t, named)

		editions := func() int {
			t.Helper()
			var highest int
			if err := f.db.DB.NewSelect().TableExpr(`"advisory_edition" AS "ae"`).
				Join(`JOIN "advisory" AS "ad" ON ad.id = ae.advisory_id`).
				ColumnExpr("MAX(ae.ordinal)").
				Where("ad.identifier = ?", named).Scan(ctx, &highest); err != nil {
				t.Fatal(err)
			}
			return highest
		}
		before := editions()

		if err := f.store.MarkAffected(ctx, f.who, named, "sonic", identifier,
			fixtures.BranchName, "broadcom", true); err != nil {
			t.Fatalf("marking: %v", err)
		}
		if got := f.generated(t, named).Vulnerabilities[0].Status; !slices.Equal(
			got.KnownAffected, []string{master}) || len(got.KnownNotAffected) != 0 {
			t.Errorf("a marked release reads %+v", got)
		}
		if editions() != before+1 {
			t.Errorf("marking opened %d editions, want one", editions()-before)
		}
		where, err := f.store.Where(ctx, f.who, named)
		if err != nil {
			t.Fatal(err)
		}
		if len(where.Agreed) != 0 {
			t.Error("the agreement to what it said before the mark still stands")
		}
		row := f.placedAt(t, named, master)
		if !row.Overridden || row.Decided() != advisory.KnownNotAffected {
			t.Errorf("the screen reads %+v", row.Release)
		}

		// Asked again, nothing moves.
		if err := f.store.MarkAffected(ctx, f.who, named, "sonic", identifier,
			fixtures.BranchName, "BROADCOM", true); err != nil {
			t.Fatal(err)
		}
		if editions() != before+1 {
			t.Error("marking what was already marked opened an edition")
		}

		// Cleared, the decisions speak again, in an edition of its own.
		if err := f.store.MarkAffected(ctx, f.who, named, "sonic", identifier,
			fixtures.BranchName, "broadcom", false); err != nil {
			t.Fatal(err)
		}
		if got := f.generated(t, named).Vulnerabilities[0].Status; !slices.Equal(
			got.KnownNotAffected, []string{master}) {
			t.Errorf("a cleared mark leaves the release at %+v", got)
		}
		if editions() != before+2 {
			t.Errorf("clearing the mark left %d editions past the first", editions()-before)
		}

		// A release the issue is not in is refused by name.
		if err := f.store.MarkAffected(ctx, f.who, named, "sonic", identifier,
			fixtures.TagName, "broadcom", true); err == nil {
			t.Error("a release the issue is not in was marked")
		}
	})
}

func TestADecisionAgreedAfterTheAdvisoryMovesItsStatusAndTheAgreementStands(t *testing.T) {
	// The advisory's agreement is to what it says, and a decision is its own
	// record with its own second person. One approved afterwards moves the
	// release, says so, and withdraws nothing.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		claim := f.claimed(t, f.master, identifier, onPlace, triage.NotApplicable,
			triage.CodeNotInExecutePath, "")
		named := f.covering(t, [2]string{"sonic", identifier})
		f.agreed(t, named)
		if _, err := f.store.Issued(ctx, f.who, issuer, named, ""); err != nil {
			t.Fatalf("recording that it went out: %v", err)
		}
		if row := f.placedAt(t, named, master); row.Changed || row.Status != advisory.KnownAffected {
			t.Fatalf("before the decision the release reads %+v", row)
		}
		unmoved, err := f.store.Changed(ctx, f.who, issuer, named)
		if err != nil || unmoved == nil || *unmoved {
			t.Fatalf("before the decision the advisory reads as moved: %v %v", unmoved, err)
		}

		f.agree(t, claim)

		row := f.placedAt(t, named, master)
		if !row.Changed || row.Status != advisory.KnownNotAffected {
			t.Errorf("after the decision the release reads %+v", row)
		}
		where, err := f.store.Where(ctx, f.who, named)
		if err != nil {
			t.Fatal(err)
		}
		if len(where.Agreed) != 1 {
			t.Errorf("%d agreements stand, want the one given before the decision", len(where.Agreed))
		}
		moved, err := f.store.Changed(ctx, f.who, issuer, named)
		if err != nil || moved == nil || !*moved {
			t.Errorf("what would go out now reads as what went out: %v %v", moved, err)
		}
	})
}

func TestAReleaseADecisionReachesByLookupIsFlaggedAsMadeElsewhere(t *testing.T) {
	// The same kernel at the same versions in two variants, with an option
	// compiled out of one. Both hold the place when the decision is made on
	// master for broadcom, and it reaches mellanox because the versions
	// match. What it was made on is what was recorded, so mellanox is
	// flagged. The tag built for broadcom, reached by lookup too, is the same
	// configuration and is not.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, f.otherVariant)
		identifier := f.recorded(t, f.master)
		f.alsoIn(t, identifier, f.otherVariant)
		f.alsoIn(t, identifier, f.tagged)
		f.dismissed(t, f.master, identifier)
		named := f.covering(t, [2]string{"sonic", identifier})

		reached := f.placedAt(t, named, mellanox)
		if reached.Status != advisory.KnownNotAffected || reached.Grounds == nil {
			t.Fatalf("mellanox reads %+v, want it reached by the decision", reached)
		}
		if !slices.Equal(variantsOf(reached.Grounds.MadeOn), []string{"broadcom"}) {
			t.Errorf("the decision reads as made on %v, want broadcom alone",
				variantsOf(reached.Grounds.MadeOn))
		}
		if !reached.MadeElsewhere() {
			t.Error("mellanox, reached by lookup, is not flagged")
		}
		if f.placedAt(t, named, master).MadeElsewhere() {
			t.Error("broadcom, the build it was made on, is flagged")
		}
		tag := f.placedAt(t, named, tagged)
		if tag.Grounds == nil || tag.MadeElsewhere() {
			t.Errorf("the broadcom tag, reached by lookup, reads %+v flagged %v, want covered "+
				"and not flagged", tag.Grounds, tag.MadeElsewhere())
		}
	})
}

func TestABuildChosenBesideTheOneOnScreenCountsAsMadeOn(t *testing.T) {
	// Ticking a build on the reach sheet is choosing it, so the decision was
	// made on it too and it is not flagged.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, f.otherVariant)
		identifier := f.recorded(t, f.master)
		f.alsoIn(t, identifier, f.otherVariant)
		claim := f.claimedOn(t, f.master, []int64{f.master, f.otherVariant}, identifier,
			onPlace, triage.NotApplicable, triage.CodeNotPresent, "")
		f.agree(t, claim)
		named := f.covering(t, [2]string{"sonic", identifier})

		row := f.placedAt(t, named, mellanox)
		if row.Grounds == nil || row.MadeElsewhere() {
			t.Errorf("a build chosen beside the one on screen reads %+v", row.Grounds)
		}
		if f.placedAt(t, named, master).MadeElsewhere() {
			t.Error("the build on screen is flagged")
		}
		if got := variantsOf(row.Grounds.MadeOn); !slices.Equal(got, []string{"broadcom", "mellanox"}) {
			t.Errorf("the decision reads as made on %v, want both", got)
		}
	})
}

func TestADecisionRecordingNoBuildSaysNothingAboutWhereItWasMade(t *testing.T) {
	// A claim made where no build was in hand, and every claim an upgraded
	// deployment held, records none. Nothing is guessed, and nothing is
	// flagged.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, f.otherVariant)
		identifier := f.recorded(t, f.master)
		f.alsoIn(t, identifier, f.otherVariant)
		claim := f.claimedOn(t, f.master, nil, identifier, onPlace, triage.NotApplicable,
			triage.CodeNotPresent, "")
		f.agree(t, claim)
		named := f.covering(t, [2]string{"sonic", identifier})

		for _, release := range []string{master, mellanox} {
			row := f.placedAt(t, named, release)
			if row.Grounds == nil {
				t.Fatalf("%s reads as covered by nothing", release)
			}
			if len(row.Grounds.MadeOn) != 0 || row.MadeElsewhere() {
				t.Errorf("%s reads as made on %v, flagged %v, want nothing recorded",
					release, row.Grounds.MadeOn, row.MadeElsewhere())
			}
		}
	})
}

func TestAReleaseNobodyWillFixIsToldSoAndNotToUpdate(t *testing.T) {
	// A release a decision says will not be fixed stays known affected, and
	// its remediation says no fix is planned. Told to update, or that no fix
	// is available yet, a customer on it reads that one is coming.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		f.alsoIn(t, identifier, f.tagged)
		f.alsoIn(t, identifier, f.older)
		// The older tag is fixed, so the ordinary remediation has a release to
		// name, and the tag holds a second place nobody decided, so it keeps
		// the ordinary remediation.
		issue := f.issueOf(t, identifier)
		if _, err := f.finds.Resolve(t.Context(), f.who, f.older, issue, "Patched."); err != nil {
			t.Fatal(err)
		}
		f.elsewhereIn(t, identifier, f.tagged)
		// One decision, which the tag's place at the same versions reaches too.
		f.agree(t, f.claimed(t, f.master, identifier, onPlace, triage.WontFix, "", stops))
		doc := f.generated(t, f.covering(t, [2]string{"sonic", identifier}))
		one := doc.Vulnerabilities[0]

		if !slices.Equal(one.Status.KnownAffected, []string{master, tagged}) {
			t.Fatalf("known affected: %v, want the branch and the tag", one.Status.KnownAffected)
		}
		byCategory := map[string][]string{}
		details := map[string]string{}
		for _, fix := range one.Remediations {
			byCategory[fix.Category] = append(byCategory[fix.Category], fix.ProductIDs...)
			details[fix.Category] = fix.Details
		}
		if !slices.Equal(byCategory["no_fix_planned"], []string{master}) {
			t.Errorf("no fix planned: %v, want the branch", byCategory["no_fix_planned"])
		}
		if !slices.Equal(byCategory["vendor_fix"], []string{tagged}) {
			t.Errorf("vendor fix: %v, want the partly covered tag alone", byCategory["vendor_fix"])
		}
		if !slices.Equal(byCategory["mitigation"], []string{master}) || details["mitigation"] != stops {
			t.Errorf("mitigation: %v %q, want what stops it on the branch",
				byCategory["mitigation"], details["mitigation"])
		}
		body, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "unit files") {
			t.Errorf("the reasoning reached the document: %s", body)
		}
		required(t, doc)
		explained(t, doc)
	})
}

func TestAReleaseNobodyWillFixWithNoMitigationStatesOnlyThat(t *testing.T) {
	// A decision naming nothing that stops the flaw adds no mitigation, and
	// the release still says no fix is planned.
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t, f.master)
		f.agree(t, f.claimed(t, f.master, identifier, onPlace, triage.WontFix, "", ""))
		one := f.generated(t, f.covering(t, [2]string{"sonic", identifier})).Vulnerabilities[0]
		if len(one.Remediations) != 1 || one.Remediations[0].Category != "no_fix_planned" ||
			!slices.Equal(one.Remediations[0].ProductIDs, []string{master}) {
			t.Errorf("remediations: %+v, want no fix planned for the branch alone", one.Remediations)
		}
	})
}

// mellanox is the branch built as the second variant.
var mellanox = "sonic:" + fixtures.BranchName + ":mellanox"

// variantsOf is the variants of the builds a decision was made on.
func variantsOf(built []advisory.Built) []string {
	out := make([]string, 0, len(built))
	for _, one := range built {
		out = append(out, one.Variant)
	}
	return out
}

// explained fails on a release the document states without saying why or
// what to do: a flag or an impact for every release known not affected, and a
// remediation for every release known affected.
func explained(t *testing.T, doc *advisory.Document) {
	t.Helper()
	examined := 0
	for _, one := range doc.Vulnerabilities {
		if one.CVE == "" && len(one.IDs) == 0 {
			t.Error("a vulnerability names neither a CVE nor an identifier")
		}
		for _, release := range one.Status.KnownNotAffected {
			examined++
			stated := false
			for _, flag := range one.Flags {
				stated = stated || slices.Contains(flag.ProductIDs, release)
			}
			for _, threat := range one.Threats {
				stated = stated || (threat.Category == "impact" &&
					slices.Contains(threat.ProductIDs, release))
			}
			if !stated {
				t.Errorf("%s is known not affected with no impact statement", release)
			}
		}
		for _, release := range one.Status.KnownAffected {
			examined++
			acted := false
			for _, fix := range one.Remediations {
				acted = acted || slices.Contains(fix.ProductIDs, release)
			}
			if !acted {
				t.Errorf("%s is known affected with no action statement", release)
			}
		}
	}
	if examined == 0 {
		t.Fatal("no release was examined, so this checked nothing")
	}
}

func TestAnAgreementGivenBeforeStatusesWereRecordedMarksNothingChanged(t *testing.T) {
	// An agreement given before the upgrade recorded no release's status. It
	// says nothing about what it saw, and read as having seen nothing, every
	// release of every advisory agreed to then reads as changed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		claim := f.claimed(t, f.master, identifier, onPlace, triage.NotApplicable,
			triage.CodeNotPresent, "")
		named := f.covering(t, [2]string{"sonic", identifier})
		f.agreed(t, named)
		if _, err := f.db.DB.NewDelete().TableExpr(`"advisory_agreed_status"`).
			Where("1 = 1").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		f.agree(t, claim)

		row := f.placedAt(t, named, master)
		if row.Status != advisory.KnownNotAffected {
			t.Fatalf("the release reads %s, so the decision moved nothing to compare", row.Status)
		}
		if row.Changed {
			t.Error("an agreement that recorded nothing reads the release as changed")
		}
	})
}

func TestAMarkAndAnAgreementFollowAnIssueThatMergedIntoAnother(t *testing.T) {
	// An issue on the advisory merges into another. A mark set on it is the
	// other's, and clearing it clears it; what an agreement saw about it is
	// what it saw about the other.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := f.recorded(t, f.master)
		second := f.recorded(t, f.master)
		f.dismissed(t, f.master, second)
		named := f.covering(t, [2]string{"sonic", second})
		if err := f.store.MarkAffected(ctx, f.who, named, "sonic", second,
			fixtures.BranchName, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		f.agreed(t, named)

		if _, err := finding.NewVulnerabilities(f.db.DB).Intern(ctx, []finding.Named{
			{Identifier: first, Aliases: []string{second}},
		}); err != nil {
			t.Fatalf("merge the two: %v", err)
		}

		row := f.placedAt(t, named, master)
		if !row.Overridden {
			t.Fatal("the mark set before the merge does not follow the issue")
		}
		if row.Changed {
			t.Error("the merge alone reads the release as changed since the agreement")
		}
		if err := f.store.MarkAffected(ctx, f.who, named, "sonic", first,
			fixtures.BranchName, "broadcom", false); err != nil {
			t.Fatal(err)
		}
		if f.placedAt(t, named, master).Overridden {
			t.Error("clearing the mark after the merge left it standing")
		}
	})
}
