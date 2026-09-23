// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// holding is somebody holding exactly the roles given, per product, and
// nothing anywhere else.
func (f *fixture) holding(t *testing.T, identity string, grants map[int64][]access.Role) access.Subject {
	t.Helper()
	ctx := t.Context()
	rights := access.NewStore(f.db.DB)
	person, err := rights.Ensure(ctx, identity, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for product, roles := range grants {
		for _, role := range roles {
			if err := rights.GrantRole(ctx, person.ID, product, role); err != nil {
				t.Fatal(err)
			}
		}
	}
	resolved, err := rights.Resolve(ctx, identity)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

// secondProduct declares another product, for the rules that are asked per
// product.
func (f *fixture) secondProduct(t *testing.T) int64 {
	t.Helper()
	product, err := catalog.NewStore(f.db.DB).DeclareProduct(t.Context(), "switchd", "Switch Daemon")
	if err != nil {
		t.Fatal(err)
	}
	return product.ID
}

// proposes records one judgment across the places given, as the subject
// given, waiting on a second person.
func (f *fixture) proposes(t *testing.T, who access.Subject, places ...triage.Place) *triage.Decision {
	t.Helper()
	proposals := make([]triage.Proposal, 0, len(places))
	for _, at := range places {
		proposals = append(proposals, triage.Proposal{
			Place: at, Outcome: triage.NotApplicable,
			Justification: triage.CodeNotInExecutePath,
			Reasoning:     "The parser is never reached: we only call the encoder.",
			By:            who.ID, NeedsApproval: true,
		})
	}
	recorded, err := f.store.ProposeMany(t.Context(), who, proposals, triage.DefaultTogetherCap)
	if err != nil {
		t.Fatal(err)
	}
	return recorded[0]
}

// placeIn is a place in one product at one visibility, keyed at the version
// the fixture's findings ship and with no consumer, so it matches them.
func (f *fixture) placeIn(product int64, identity string, visibility access.Visibility) triage.Place {
	at := f.at()
	at.ProductID = product
	at.PlaceIdentity = identity
	at.Visibility = visibility
	at.ConsumerUpstream = ""
	return at
}

// splitAcrossBuilds opens the fixture's issue at one place in two builds of a
// product, disclosed in the first and undisclosed in the second, and answers
// the two builds' names.
func (f *fixture) splitAcrossBuilds(t *testing.T, product int64, place string) (disclosed, undisclosed string) {
	t.Helper()
	libfoo := f.component(t, fmt.Sprintf("libfoo-%d", product), "1.2.3")
	f.finds(t, f.build(t, product, "2026.03"), libfoo, place, access.Public)
	f.finds(t, f.build(t, product, "2026.06"), libfoo, place, access.Private)
	return "2026.03 · broadcom", "2026.06 · broadcom"
}

// coversOnly checks what one reader is told a claim reaches: the builds named
// and the findings counted, both narrowed to the findings they read.
func (f *fixture) coversOnly(t *testing.T, who access.Subject, claimID int64, what string, builds ...string) {
	t.Helper()
	whole, err := f.store.Whole(t.Context(), who, claimID)
	if err != nil {
		t.Fatalf("reading %s: %v", what, err)
	}
	if !slices.Equal(whole.Builds, builds) {
		t.Errorf("%s names builds %v, want %v", what, whole.Builds, builds)
	}
	if whole.Reach.Findings != len(builds) {
		t.Errorf("%s counts %d findings, want %d", what, whole.Reach.Findings, len(builds))
	}
}

func TestReadingUndisclosedFindingsDoesNotReachDisclosedOnesThroughADecision(t *testing.T) {
	// A decision matches every finding at its place, whatever the finding's
	// own visibility. Somebody holding private reading alone reads the
	// undisclosed findings it matches and none of the disclosed ones, because
	// each visibility is its own grant.
	each(t, func(t *testing.T, f *fixture) {
		_, undisclosed := f.splitAcrossBuilds(t, f.product, "place-of-libfoo")
		claim := f.proposes(t, f.privately(t),
			f.placeIn(f.product, "place-of-libfoo", access.Private))

		privately := f.holding(t, "private-reader", map[int64][]access.Role{
			f.product: {access.PrivateRead},
		})
		f.coversOnly(t, privately, claim.ClaimID, "an undisclosed claim, to a private reader", undisclosed)
	})
}

func TestAFindingIsReadAtTheVisibilityHeldInItsOwnProduct(t *testing.T) {
	// Public reading on one product and private reading on another reach the
	// disclosed findings of the first and the undisclosed findings of the
	// second, and neither of the other two.
	each(t, func(t *testing.T, f *fixture) {
		other := f.secondProduct(t)
		disclosedHere, _ := f.splitAcrossBuilds(t, f.product, "place-of-libfoo")
		_, undisclosedThere := f.splitAcrossBuilds(t, other, "place-of-libfoo")

		here := f.proposes(t, f.triager, f.placeIn(f.product, "place-of-libfoo", access.Public))
		insider := f.holding(t, "switchd-insider", map[int64][]access.Role{
			other: {access.PublicTriage, access.PrivateTriage},
		})
		there := f.proposes(t, insider, f.placeIn(other, "place-of-libfoo", access.Private))

		mixed := f.holding(t, "mixed-reader", map[int64][]access.Role{
			f.product: {access.PublicRead},
			other:     {access.PrivateRead},
		})
		f.coversOnly(t, mixed, here.ClaimID, "a disclosed claim in the public product", disclosedHere)
		f.coversOnly(t, mixed, there.ClaimID, "an undisclosed claim in the private product", undisclosedThere)
	})
}

func TestSomebodyBroughtOntoACaseReadsTheFindingsOfTheirOwnClaim(t *testing.T) {
	// A collaborator holds nothing on the product and reads the one issue
	// they were brought in on at either visibility. A claim they made about
	// it names the builds it covers and is among what stands there; another
	// issue in the same product is not reached.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		disclosed, undisclosed := f.splitAcrossBuilds(t, f.product, "place-of-libfoo")
		rights := access.NewStore(f.db.DB)
		person, err := rights.Ensure(ctx, "collaborator", "Collaborator", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.AddToCase(ctx, f.product, f.issue, person.ID, f.proposer); err != nil {
			t.Fatal(err)
		}
		brought, err := rights.Resolve(ctx, "collaborator")
		if err != nil {
			t.Fatal(err)
		}
		if brought.Sees(f.product) {
			t.Fatal("the collaborator holds the product outright, so this tests nothing")
		}

		theirs := f.proposes(t, brought, f.placeIn(f.product, "place-of-libfoo", access.Private))
		f.coversOnly(t, brought, theirs.ClaimID, "the collaborator's own claim", disclosed, undisclosed)

		keyed := f.keyed("place-of-libfoo")
		keyed[0].ConsumerUpstream = ""
		standing, err := f.store.StandingAt(ctx, brought, f.product, f.issue, keyed)
		if err != nil {
			t.Fatal(err)
		}
		if len(standing) != 1 {
			t.Errorf("the collaborator's own claim reads as %d claims standing on their case", len(standing))
		}

		// Another issue at the same place, which the case does not name.
		elsewhere := f.secondIssue(t)
		at := f.placeIn(f.product, "place-of-libfoo", access.Private)
		at.VulnerabilityID = elsewhere
		notTheirs := f.proposes(t, f.privately(t), at)
		if standing, err := f.store.StandingAt(ctx, f.privately(t), f.product, elsewhere, keyed); err != nil ||
			len(standing) != 1 {
			t.Fatalf("the claim about the other issue reads as %+v to its proposer (%v)", standing, err)
		}
		standing, err = f.store.StandingAt(ctx, brought, f.product, elsewhere, keyed)
		if err != nil {
			t.Fatal(err)
		}
		if len(standing) != 0 {
			t.Errorf("the case grant reached %d claims about an issue it does not name", len(standing))
		}
		if _, err := f.store.Whole(ctx, brought, notTheirs.ClaimID); !errors.Is(err, triage.ErrNotTheirs) {
			t.Errorf("the case grant read a claim about an issue it does not name: %v", err)
		}
	})
}

func TestADecisionIsReadAndAgreedToAtTheVisibilityHeldInItsOwnProduct(t *testing.T) {
	// Reading and agreeing are asked per product and per visibility. With
	// public reading on one product and private reading on another, somebody
	// holding the approver capability on both reads and is asked to agree to
	// the disclosed claim in the first and the undisclosed claim in the
	// second, and neither of the other two.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other := f.secondProduct(t)
		insiderThere := f.holding(t, "switchd-insider", map[int64][]access.Role{
			other: {access.PublicTriage, access.PrivateTriage},
		})
		publicHere := f.proposes(t, f.triager, f.placeIn(f.product, "under-a", access.Public))
		f.proposes(t, f.privately(t), f.placeIn(f.product, "under-b", access.Private))
		f.proposes(t, insiderThere, f.placeIn(other, "under-c", access.Public))
		privateThere := f.proposes(t, insiderThere, f.placeIn(other, "under-d", access.Private))
		want := []int64{publicHere.ClaimID, privateThere.ClaimID}
		slices.Sort(want)

		mixed := f.holding(t, "mixed-approver", map[int64][]access.Role{
			f.product: {access.PublicRead, access.Approver},
			other:     {access.PrivateRead, access.Approver},
		})

		judged, _, err := f.store.Audit(ctx, mixed, triage.Filter{}, time.Time{}, time.Time{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var read []int64
		for _, one := range judged {
			read = append(read, one.ClaimID)
		}
		slices.Sort(read)
		if !slices.Equal(read, want) {
			t.Errorf("the record shows claims %v, want %v", read, want)
		}

		waiting, _, err := f.store.Queue(ctx, mixed, false, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var asked []int64
		for _, one := range waiting {
			asked = append(asked, one.Claim.ID)
		}
		slices.Sort(asked)
		if !slices.Equal(asked, want) {
			t.Errorf("the queue asks for agreement to claims %v, want %v", asked, want)
		}
	})
}

func TestAClaimWithARowTheReaderMayNotAgreeToIsNotWaitingOnThem(t *testing.T) {
	// A claim is agreed to whole. Somebody who may agree to undisclosed work
	// alone is asked about a claim that is wholly undisclosed, and not about
	// one with a disclosed row in it or one that is wholly disclosed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		insider := f.privately(t)
		private := f.proposes(t, insider, f.placeIn(f.product, "under-a", access.Private))
		mixedClaim := f.proposes(t, insider,
			f.placeIn(f.product, "under-b", access.Private),
			f.placeIn(f.product, "under-c", access.Public))
		public := f.proposes(t, f.triager, f.placeIn(f.product, "under-d", access.Public))

		privateApprover := f.holding(t, "private-approver", map[int64][]access.Role{
			f.product: {access.PrivateRead, access.Approver},
		})
		waiting, total, err := f.store.Queue(ctx, privateApprover, false, 0, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(waiting) != 1 || waiting[0].Claim.ID != private.ClaimID {
			var asked []int64
			for _, one := range waiting {
				asked = append(asked, one.Claim.ID)
			}
			t.Errorf("a private approver is asked about claims %v of %d; want only the undisclosed claim %d"+
				" (the mixed claim is %d, the disclosed one %d)",
				asked, total, private.ClaimID, mixedClaim.ClaimID, public.ClaimID)
		}
		if count, err := f.store.WaitingIn(ctx, privateApprover, f.product); err != nil || count != 1 {
			t.Errorf("the product counts %d claims waiting on a private approver (%v), want 1", count, err)
		}

		// Somebody who may agree at both visibilities is asked about all
		// three, so the narrowing above is the visibility and not the claims.
		both := f.holding(t, "approver-of-both", map[int64][]access.Role{
			f.product: {access.PublicRead, access.PrivateRead, access.Approver},
		})
		if _, total, err := f.store.Queue(ctx, both, false, 0, 50, 0); err != nil || total != 3 {
			t.Errorf("an approver at both visibilities is asked about %d claims (%v), want 3", total, err)
		}
	})
}
