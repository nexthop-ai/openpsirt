// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Each visibility is its own grant.
//
// Reading or triaging undisclosed work reaches undisclosed findings alone, and
// the disclosed half is a second grant. These pin the places where a subject
// holding one half is most easily handed the other: the work list an
// assignment carries a row into, moving work, marking a finding, and a
// release note.

// undisclose marks one issue at one component of one build as undisclosed.
//
// Narrowed to the build, because a component row is shared by every build
// shipping that name at that version, and the checks across products need one
// product's row hidden and the other's left disclosed.
func (f *fixture) undisclose(t *testing.T, target int64, identifier, component string) {
	t.Helper()
	at, err := graph.NewStore(f.db.DB).ComponentAt(t.Context(), target, component)
	if err != nil {
		t.Fatalf("resolve %s: %v", component, err)
	}
	if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
		Set("visibility = ?", access.Private).
		Where("target_id = ?", target).
		Where("vulnerability_id = ?", f.issueID(t, identifier)).
		Where("component_id = ?", at).
		Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// handTo puts one issue at one component of one build on a party directly, so
// the holder's own grants play no part in how it got there.
func (f *fixture) handTo(t *testing.T, target int64, identifier, component string, party int64) {
	t.Helper()
	at, err := graph.NewStore(f.db.DB).ComponentAt(t.Context(), target, component)
	if err != nil {
		t.Fatalf("resolve %s: %v", component, err)
	}
	if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
		Set("assigned_to = ?", party).
		Where("target_id = ?", target).
		Where("vulnerability_id = ?", f.issueID(t, identifier)).
		Where("component_id = ?", at).
		Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// oneDisclosedOneNot opens a disclosed issue at libnl and an undisclosed one
// at swss in the fixture's build.
func (f *fixture) oneDisclosedOneNot(t *testing.T) {
	t.Helper()
	f.shipped(t, twoConsumers())
	if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
		found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
	}); err != nil {
		t.Fatal(err)
	}
	f.undisclose(t, f.target, "CVE-2026-2", swss.Name)
}

func TestACarriedDisclosedFindingIsInTheHoldersWorkAndNotInTheProductsAnswers(t *testing.T) {
	// An assignment carries a disclosed row to whoever holds it, whatever they
	// read, and it carries it into their own work list alone. A count, the
	// list across products and the rest answer about the product, and a
	// private-only reader does not read the product's disclosed work.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.oneDisclosedOneNot(t)
		who := f.holding(t, access.PrivateRead)
		f.handTo(t, f.target, "CVE-2026-1", libnl.Name, who.Party())

		mine, total, err := f.store.AssignedTo(ctx, who, who.Mine(), finding.Scope{}, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var held []string
		for _, row := range mine {
			held = append(held, row.Vulnerability)
		}
		if total != 1 || len(held) != 1 || held[0] != "CVE-2026-1" {
			t.Errorf("the holder's work list reads %v with a total of %d, want the "+
				"disclosed finding handed to them", held, total)
		}

		counted, err := f.store.OpenBy(ctx, who, finding.Scope{}, finding.ByProduct)
		if err != nil {
			t.Fatal(err)
		}
		if counted[f.productID] != 1 {
			t.Errorf("the catalog counts %d open in the product, want the one undisclosed "+
				"finding alone", counted[f.productID])
		}

		rows, across, err := f.store.Anywhere(ctx, who, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		var listed []string
		for _, row := range rows {
			listed = append(listed, row.Vulnerability)
		}
		if across != 1 || len(listed) != 1 || listed[0] != "CVE-2026-2" {
			t.Errorf("the list across products reads %v with a total of %d, want the "+
				"undisclosed finding alone", listed, across)
		}
	})
}

func TestTheListAcrossProductsReadsEachProductAtItsOwnGrant(t *testing.T) {
	// Disclosed reading on one product and undisclosed on another is two
	// grants, and neither reaches the other product's half. A disclosed row
	// in the second product handed to them stays out as well: holding it is
	// no answer about the product.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.oneDisclosedOneNot(t)

		other := f.inAnotherProduct(t, "other-product")
		f.shippedTo(t, other, twoConsumers())
		if _, err := f.store.Apply(ctx, other, f.runOn(t, other), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", swss),
		}); err != nil {
			t.Fatal(err)
		}
		f.undisclose(t, other, "CVE-2026-2", swss.Name)
		otherProduct := f.productOf(t, other)

		who := access.NewPerson(1, "someone", false, map[int64][]access.Role{
			f.productID:  {access.PublicRead},
			otherProduct: {access.PrivateRead},
		}, 101)
		f.handTo(t, other, "CVE-2026-1", libnl.Name, who.Party())

		rows, total, err := f.store.Anywhere(ctx, who, 50, 0, finding.Filter{})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, row := range rows {
			got[row.Product] += row.Vulnerability + " "
		}
		want := map[string]string{"sonic": "CVE-2026-1 ", "other-product": "CVE-2026-2 "}
		if total != 2 || len(rows) != 2 || got["sonic"] != want["sonic"] ||
			got["other-product"] != want["other-product"] {
			t.Errorf("the list reads %v with a total of %d, want %v", got, total, want)
		}
	})
}

func TestAPrivateOnlyTriagerHandsBackDisclosedWorkTheyHold(t *testing.T) {
	// A disclosed finding handed to somebody who triages undisclosed work
	// alone is theirs, and handing back their own is part of triaging. The
	// row moves rather than the call matching nothing and reporting success.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.oneDisclosedOneNot(t)
		who := f.holding(t, access.PrivateTriage)
		f.handTo(t, f.target, "CVE-2026-1", libnl.Name, who.Party())

		moved, _, err := f.store.Assign(ctx, who, f.target, f.issueID(t, "CVE-2026-1"),
			f.componentID(t, libnl.Name), nil)
		if err != nil {
			t.Fatal(err)
		}
		if moved == 0 {
			t.Error("handing back a disclosed finding they hold moved nothing")
		}
		if held := f.assigned(t); len(held) != 0 {
			t.Errorf("%d findings are still held after being handed back", len(held))
		}
	})
}

func TestDispatchReachesOnlyTheVisibilitiesTheCallerTriages(t *testing.T) {
	// Putting work on somebody else is an act on the finding. Reading the
	// disclosed half without triaging it does not reach it, and triaging the
	// undisclosed half does.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.oneDisclosedOneNot(t)
		who := f.holding(t, access.PublicRead, access.PrivateTriage, access.Assigner)
		other := int64(2)

		moved, _, err := f.store.Assign(ctx, who, f.target, f.issueID(t, "CVE-2026-1"),
			f.componentID(t, libnl.Name), &other)
		if err != nil && !errors.Is(err, access.ErrDenied) {
			t.Fatal(err)
		}
		if moved != 0 {
			t.Errorf("a disclosed finding the caller only reads was dispatched: %d moved", moved)
		}
		if held := f.assigned(t); len(held) != 0 {
			t.Errorf("%d findings were dispatched, want none yet", len(held))
		}

		moved, _, err = f.store.Assign(ctx, who, f.target, f.issueID(t, "CVE-2026-2"),
			f.componentID(t, swss.Name), &other)
		if err != nil {
			t.Fatal(err)
		}
		if moved == 0 {
			t.Error("an undisclosed finding the caller triages was not dispatched")
		}
	})
}

func TestMarkingIsAskedAtTheFindingsOwnVisibility(t *testing.T) {
	// A tag names one issue at one component. The same issue undisclosed at
	// another component of the product does not make the disclosed one
	// markable by somebody triaging undisclosed work alone.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-1", swss),
		}); err != nil {
			t.Fatal(err)
		}
		f.undisclose(t, f.target, "CVE-2026-1", swss.Name)
		issue := f.issueID(t, "CVE-2026-1")
		disclosed, undisclosed := f.componentID(t, libnl.Name), f.componentID(t, swss.Name)

		// A mark already on the disclosed finding, so taking it off has
		// something to take.
		if err := f.store.TagIt(ctx, f.someoneElse(t, access.PublicTriage), f.productID,
			issue, disclosed, "vendor"); err != nil {
			t.Fatal(err)
		}

		who := f.someoneElse(t, access.PrivateTriage)
		if err := f.store.TagIt(ctx, who, f.productID, issue, disclosed,
			"mine"); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a private-only triager marked a disclosed finding: %v", err)
		}
		if err := f.store.Untag(ctx, who, f.productID, issue, disclosed,
			"vendor"); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a private-only triager took a mark off a disclosed finding: %v", err)
		}
		if on, err := f.store.TagsOn(ctx, f.productID, issue, disclosed); err != nil {
			t.Fatal(err)
		} else if len(on) != 1 || on[0] != "vendor" {
			t.Errorf("the disclosed finding is marked %q, want the one mark put there", on)
		}

		if err := f.store.TagIt(ctx, who, f.productID, issue, undisclosed, "mine"); err != nil {
			t.Errorf("a private triager could not mark an undisclosed finding: %v", err)
		}
	})
}

func TestAReleaseNoteIsRefusedToSomebodyReadingOnlyUndisclosedWork(t *testing.T) {
	// A release note is disclosed work. Somebody reading only the undisclosed
	// half is refused rather than handed a comparison that reads as "nothing
	// fixed, nothing new".
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.oneDisclosedOneNot(t)
		earlier := f.target
		later := f.anotherBuild(t, "v2")
		f.shippedTo(t, later, twoConsumers())
		if _, err := f.store.Apply(ctx, later, f.runOn(t, later), nil); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PrivateRead)
		for _, includePrivate := range []bool{false, true} {
			if _, err := f.store.Compare(ctx, who, earlier, later,
				includePrivate); !errors.Is(err, access.ErrDenied) {
				t.Errorf("asking with undisclosed work %v was answered (%v), want a refusal",
					includePrivate, err)
			}
		}

		// A disclosed reader is answered, so the refusal above is about the
		// grant rather than about the builds.
		if _, err := f.store.Compare(ctx, f.holding(t, access.PublicRead), earlier, later,
			false); err != nil {
			t.Errorf("a disclosed reader was refused: %v", err)
		}
	})
}
