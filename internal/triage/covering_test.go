// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"errors"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// build is one target of a product with a scan run to open findings under,
// which is the least a finding needs to exist.
type build struct {
	target, run int64
}

// build declares a release of a product and returns it as somewhere to put
// findings.
func (f *fixture) build(t *testing.T, productID int64, stream string) build {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(f.db.DB)
	declared, err := cat.DeclareStream(ctx, productID, stream, catalog.Tag, nil)
	if err != nil {
		t.Fatalf("declare %s: %v", stream, err)
	}
	// One variant per product, declared the first time a build of it is
	// asked for.
	variant, err := cat.VariantByName(ctx, productID, "broadcom")
	if err != nil {
		if variant, err = cat.DeclareVariant(ctx, productID, "broadcom", true); err != nil {
			t.Fatalf("declare the variant: %v", err)
		}
	}
	target, err := cat.TargetFor(ctx, declared.ID, variant.ID)
	if err != nil {
		t.Fatalf("target for %s: %v", stream, err)
	}
	run, err := finding.NewStore(f.db.DB).Begin(ctx, finding.Run{
		TargetID: target.ID, Scanner: "grype", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return build{target: target.ID, run: run.ID}
}

// component records one package at one version, stating no upstream, so the
// version a decision is keyed on is the one shipped.
func (f *fixture) component(t *testing.T, name, version string) int64 {
	t.Helper()
	row := &graph.Component{
		Identity: name + "@" + version, Name: name, Version: version,
		FirstSeenAt: time.Now().Truncate(time.Microsecond),
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	return row.ID
}

// finds opens the fixture's issue against a component at a place in a build,
// with no consumer, and returns the finding.
func (f *fixture) finds(t *testing.T, in build, componentID int64, place string, visibility access.Visibility) int64 {
	t.Helper()
	row := &finding.Finding{
		TargetID: in.target, Kind: finding.Vulnerable, VulnerabilityID: f.issue,
		Visibility: visibility, ComponentID: componentID, PlaceIdentity: place,
		LastChangedAt: time.Now().Truncate(time.Microsecond),
		OpenedAt:      time.Now().Truncate(time.Microsecond), OpenedRunID: &in.run,
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	return row.ID
}

// moves closes a build's finding and opens the same issue at the same place
// against another component, which is what a version bump looks like on the
// finding's side.
func (f *fixture) moves(t *testing.T, in build, findingID, toComponent int64, place string) {
	t.Helper()
	if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
		Set("closed_at = ?", time.Now().UTC()).
		Set("closed_run_id = ?", in.run).
		Where("id = ?", findingID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.finds(t, in, toComponent, place, access.Public)
}

// stateOf reads where a decision has got to.
func (f *fixture) stateOf(t *testing.T, id int64) triage.State {
	t.Helper()
	var row triage.Decision
	if err := f.db.DB.NewSelect().Model(&row).Where("id = ?", id).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return row.State
}

func TestADecisionStandsWhileAnyBuildInTheProductStillMatchesIt(t *testing.T) {
	// A decision is a lookup shared by every build whose code matches it .
	// One release stream moving on while another still ships the version
	// decided about leaves the judgment covering the other, and a judgment
	// about code that is still there is not one anybody needs to make
	// again. It lapses when the last build holding those versions moves.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first := f.build(t, f.product, "2026.03")
		second := f.build(t, f.product, "2026.06")
		old := f.component(t, "libfoo", "1.2.3")
		bumped := f.component(t, "libfoo", "1.2.4")
		inFirst := f.finds(t, first, old, "place-of-libfoo", access.Public)
		inSecond := f.finds(t, second, old, "place-of-libfoo", access.Public)

		at := f.at()
		at.PlaceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		decided := f.agreed(t, at)

		// A sweep of a build that moved nothing marks nothing.
		if n, err := f.store.Lapse(ctx, first.target); err != nil || n.Rows != 0 {
			t.Fatalf("a sweep of an unmoved build marked %d decisions (%v)", n.Rows, err)
		}

		// The first build moves. The second still ships 1.2.3, so the
		// decision still covers it and stands.
		f.moves(t, first, inFirst, bumped, "place-of-libfoo")
		if n, err := f.store.Lapse(ctx, first.target); err != nil || n.Rows != 0 {
			t.Fatalf("a decision still covering another build was marked: %d (%v)", n.Rows, err)
		}
		if state := f.stateOf(t, decided.ID); state != triage.Approved {
			t.Fatalf("the decision is %s while a build still ships what it was about", state)
		}

		// The second moves too, and nothing in the product matches any more.
		f.moves(t, second, inSecond, bumped, "place-of-libfoo")
		if n, err := f.store.Lapse(ctx, second.target); err != nil || n.Rows != 1 {
			t.Fatalf("the last build moving marked %d decisions, want 1 (%v)", n.Rows, err)
		}
		if state := f.stateOf(t, decided.ID); state != triage.LapsedState {
			t.Errorf("the decision is %s after every build moved on", state)
		}
	})
}

func TestASweepOfAnotherProductLeavesADecisionAlone(t *testing.T) {
	// A place is a pair of names, and the same pair sits in other products.
	// Their versions moving says nothing about this product's judgment.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		other, err := catalog.NewStore(f.db.DB).DeclareProduct(ctx, "other", "Other")
		if err != nil {
			t.Fatal(err)
		}
		theirs := f.build(t, other.ID, "2026.03")
		f.finds(t, theirs, f.component(t, "libfoo", "1.2.4"), "place-of-libfoo", access.Public)

		at := f.at()
		at.PlaceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		decided := f.agreed(t, at)

		if n, err := f.store.Lapse(ctx, theirs.target); err != nil || n.Rows != 0 {
			t.Fatalf("another product's sweep marked %d decisions (%v)", n.Rows, err)
		}
		if state := f.stateOf(t, decided.ID); state != triage.Approved {
			t.Errorf("the decision is %s after another product's sweep", state)
		}
	})
}

func TestAClaimStandsOnlyAtTheVersionsItWasMadeAbout(t *testing.T) {
	// The same place sits in every build of a product, at whatever version
	// each ships. A finding asks what stands at its places by key — the
	// versions it holds — or a decision keyed at one build's version would
	// stand on a build shipping another.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.claimsMany(t, f.places("under-a"))

		standing, err := f.store.StandingAt(ctx, f.reviewer, f.product, f.issue, f.keyed("under-a"))
		if err != nil || len(standing) != 1 {
			t.Fatalf("the claim does not stand at the versions it was made about: %d (%v)", len(standing), err)
		}
		moved := f.keyed("under-a")
		moved[0].ComponentUpstream = "1.2.4"
		standing, err = f.store.StandingAt(ctx, f.reviewer, f.product, f.issue, moved)
		if err != nil || len(standing) != 0 {
			t.Errorf("the claim stands at a version it was not made about: %d (%v)", len(standing), err)
		}
	})
}

func TestTheProposerMayNotSetTheirOwnRowsAside(t *testing.T) {
	// Setting rows aside is an approver's act as much as agreeing is, so the
	// proposer naming every row of their own claim as set aside is the
	// proposer acting on their own claim.
	each(t, func(t *testing.T, f *fixture) {
		recorded := f.claimsMany(t, f.places("under-a", "under-b"))
		_, err := f.store.ApproveClaim(t.Context(), f.triager, recorded[0].ClaimID, "",
			[]int64{recorded[0].ID, recorded[1].ID}, "Not these.")
		if !errors.Is(err, triage.ErrSamePerson) {
			t.Errorf("the proposer set their own rows aside: %v", err)
		}
	})
}

func TestBuildsAClaimCoversAreOnlyThoseTheReaderMaySee(t *testing.T) {
	// A build named beside a claim says the build holds the issue. A
	// decision somebody may read can match findings they may not, so the
	// builds are narrowed like every other count served back.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		disclosed := f.build(t, f.product, "2026.03")
		undisclosed := f.build(t, f.product, "2026.06")
		libfoo := f.component(t, "libfoo", "1.2.3")
		f.finds(t, disclosed, libfoo, "place-of-libfoo", access.Public)
		f.finds(t, undisclosed, libfoo, "place-of-libfoo", access.Private)

		at := f.at()
		at.PlaceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		f.claimsMany(t, []triage.Place{at})
		keyed := []finding.Deciding{{
			PlaceIdentity: "place-of-libfoo", ComponentUpstream: "1.2.3",
		}}

		standing, err := f.store.StandingAt(ctx, f.reviewer, f.product, f.issue, keyed)
		if err != nil || len(standing) != 1 {
			t.Fatalf("standing reads as %+v (%v)", standing, err)
		}
		if len(standing[0].Builds) != 1 || standing[0].Builds[0] != "2026.03 · broadcom" {
			t.Errorf("somebody reading disclosed findings is shown builds %v", standing[0].Builds)
		}
		standing, err = f.store.StandingAt(ctx, f.privately(t), f.product, f.issue, keyed)
		if err != nil || len(standing) != 1 {
			t.Fatalf("standing reads as %+v (%v)", standing, err)
		}
		if len(standing[0].Builds) != 2 {
			t.Errorf("somebody reading undisclosed findings is shown builds %v", standing[0].Builds)
		}
	})
}

func TestAClaimCoversOnlyWhatItsLiveRowsMatch(t *testing.T) {
	// A card says how many of the issue's places in a build the claim
	// covers. Counted over every place the claim ever named, a claim whose
	// rows lapsed, or which was keyed at another build's version, reported
	// places it does not cover.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		in := f.build(t, f.product, "2026.03")
		f.finds(t, in, f.component(t, "libfoo", "1.2.4"), "place-of-libfoo", access.Public)

		at := f.at()
		at.PlaceIdentity = "place-of-libfoo"
		at.ConsumerUpstream = ""
		decided := f.claims(t, at)
		described, err := f.store.Describe(ctx, f.reviewer, []triage.Decision{*decided})
		if err != nil {
			t.Fatal(err)
		}
		card, ok := described[decided.ID]
		if !ok {
			t.Fatal("a decision at a place the build holds was not described")
		}
		if card.Places != 1 || card.Decided != 0 {
			t.Errorf("a claim keyed at 1.2.3 reads as covering %d of %d places at 1.2.4", card.Decided, card.Places)
		}
	})
}
