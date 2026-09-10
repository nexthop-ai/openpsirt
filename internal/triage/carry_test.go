package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestCarryingBringsTheReasoningAndNotTheConclusion(t *testing.T) {
	// A version moved, which is exactly what made the old judgment stop
	// applying — so what travels is the thinking, and somebody still has
	// to look at the new code.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		agreed := f.agreed(t, f.at())
		// The line the judgment was made on, and a second one holding the same
		// place at a version that moved.
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")

		offered, err := f.store.WouldCarry(ctx, f.triager, was, next)
		if err != nil {
			t.Fatal(err)
		}
		if len(offered.Moved) != 1 || offered.Moved[0].DecisionID != agreed.ID {
			t.Fatalf("the new line was offered %+v, want the one judgment whose version moved",
				offered.Moved)
		}

		carried, err := f.store.Carry(ctx, f.triager, was, next,
			[]int64{agreed.ID}, triage.DefaultTogetherCap)
		if err != nil {
			t.Fatal(err)
		}
		if carried != 1 {
			t.Fatalf("carried %d, want 1", carried)
		}

		// What landed is a claim waiting for somebody, carrying the old words.
		rows, _, err := f.store.Queue(ctx, f.reviewer, false, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, row := range rows {
			if row.Decision.PlaceIdentity == agreed.PlaceIdentity &&
				row.Decision.ID != agreed.ID {
				found = true
				if row.Decision.State != triage.Proposed {
					t.Errorf("a carried judgment arrived as %q, want one waiting for agreement",
						row.Decision.State)
				}
				if row.Reasoning == "" {
					t.Error("a carried judgment arrived with no reasoning to start from")
				}
			}
		}
		if !found {
			t.Error("nothing arrived on the new line's queue")
		}
	})
}

func TestOnlyWhatTheNewLineWasOfferedMayBeCarried(t *testing.T) {
	// A judgment that already applies has nothing to agree to, and one
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
		if _, err := f.store.Carry(ctx, f.triager, was, same,
			[]int64{agreed.ID}, triage.DefaultTogetherCap); err == nil {
			t.Error("a judgment that already applies was carried again")
		}
	})
}

func TestCarryingIsBounded(t *testing.T) {
	// one judgment across many issues's rule, which is about any action
	// that writes many rows.
	each(t, func(t *testing.T, f *fixture) {
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")
		if _, err := f.store.Carry(t.Context(), f.triager, was, next,
			[]int64{1, 2, 3}, 2); err == nil {
			t.Error("carrying more than the cap was allowed")
		}
	})
}

func TestSomebodyWhoMayNotDecideHereCarriesNothing(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		agreed := f.agreed(t, f.at())
		was := f.anotherLine(t, "202408", "1.2.3", "4.5.6")
		next := f.anotherLine(t, "202411", "1.2.4", "4.5.6")
		if _, err := f.store.Carry(t.Context(), f.onlooker, was, next,
			[]int64{agreed.ID}, triage.DefaultTogetherCap); err == nil {
			t.Error("somebody who may not decide here carried a judgment")
		}
	})
}

// anotherLine declares a build of this product holding the fixture's own place
// at the given versions, and returns its target.
//
// A carry is about two lines holding the same place at different versions, so
// a test of it needs findings on both — the decision alone says nothing about
// where it would land.
func (f *fixture) anotherLine(t *testing.T, stream, component, consumer string) int64 {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(f.db.DB)
	declared, err := cat.DeclareStream(ctx, f.product, stream, catalog.Tag, nil)
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
	f.placeAt(t, stream, target.ID, component, consumer)
	return target.ID
}

// placeAt records one open finding at the fixture's place, at these versions.
func (f *fixture) placeAt(t *testing.T, stream string, target int64, component, consumer string) {
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
		TargetID: target, Kind: "dependency", VulnerabilityID: f.issue,
		Visibility: access.Public, ComponentID: carrier.ID, ConsumerID: &holder.ID,
		PlaceIdentity: f.at().PlaceIdentity, Urgency: 1, OpenedAt: time.Now().UTC(),
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatalf("record a finding: %v", err)
	}
}
