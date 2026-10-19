// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Anybody at all is handed what the products whose documents are published
// say about disclosed work, and nothing else: not a product that does not
// publish, beside one that does, and not a flaw of ours nobody has disclosed —
// not its identifier, not what it is, not that there is one.
func TestAnybodyIsHandedOnlyWhatIsPublished(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		ctx := t.Context()
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Target, reported{"CVE-2026-1001", openssl})
		w.decide(w.Target, "CVE-2026-1001", openssl,
			claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})

		// A flaw of ours in the published product, recorded and undisclosed.
		_, flaw, err := w.findings.Enter(ctx, w.proposer, finding.Entering{
			TargetIDs: []int64{w.Target.ID}, Component: swss.Name,
			Summary: "The management socket answers anybody.",
			Told:    finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}

		// A second product beside it, which does not publish.
		other := w.DeclareProduct("hidden-os", "Hidden OS")
		w.hold(other)
		otherBranch := w.DeclareStream(other, "main", "branch", nil)
		otherVariant := w.DeclareVariant(other, "x86", true)
		otherTarget := w.TargetFor(otherBranch, otherVariant)
		otherRoot := graph.Described{Purl: "pkg:generic/hidden-os@1.0", Name: "hidden-os", Version: "1.0"}
		w.ship(otherTarget, otherRoot, edge{otherRoot, zlib})
		w.report(otherTarget, reported{"CVE-2026-2001", zlib})

		w.publishes(w.Product, true)
		w.write()

		all := w.everything()
		if !strings.Contains(all, "CVE-2026-1001") {
			t.Fatalf("the published product's disclosed issue is not published:\n%s", all)
		}
		for _, secret := range []string{flaw, "management socket", "hidden-os", "Hidden OS", "CVE-2026-2001"} {
			if strings.Contains(all, secret) {
				t.Errorf("anybody is handed %q", secret)
			}
		}
		for _, one := range w.listed("all") {
			if strings.Contains(one.Path, other.Name) {
				t.Errorf("a product that does not publish is listed at %s", one.Path)
			}
		}

		// Turned off, nothing about it is handed over, without anything being
		// written again.
		w.publishes(w.Product, false)
		if listed := w.listed("all"); len(listed) != 0 {
			t.Errorf("%d documents are listed for a product that stopped publishing", len(listed))
		}
		path := publish.OpenVEXPath + w.Product.Name + "/" + w.Branch.Name + ".json"
		if _, err := w.documents.At(ctx, access.Published([]int64{other.ID}), path, "all"); !errors.Is(err, publish.ErrNotPublished) {
			t.Errorf("a reader of another product is handed this one's document: %v", err)
		}
	})
}

// A flaw of ours nobody has disclosed keeps its name and its summary out of a
// document even where a report names it beside an issue that is published:
// the issue's other names and its description are not published while a flaw
// recorded about it sits out of anybody's reach.
func TestAnUndisclosedFlawsNameIsNotPublishedAsAnotherIssuesAlias(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		ctx := t.Context()
		w := newWorld(t, f)
		w.shipped()
		_, flaw, err := w.findings.Enter(ctx, w.proposer, finding.Entering{
			TargetIDs: []int64{w.Target.ID}, Component: swss.Name,
			Summary: "The management socket answers anybody.",
			Told:    finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		// A report learns the flaw's name for a CVE it finds in openssl.
		run, err := w.findings.Begin(ctx, finding.Run{TargetID: w.Target.ID, Scanner: "grype", RanHere: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.findings.Apply(ctx, w.Target.ID, run.ID, []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-3001", Aliases: []string{flaw}, Severity: "high"},
			Component: openssl,
		}}); err != nil {
			t.Fatal(err)
		}
		w.decide(w.Target, "CVE-2026-3001", openssl,
			claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.publishes(w.Product, true)
		w.write()
		all := w.everything()
		if !strings.Contains(all, "CVE-2026-3001") {
			t.Fatalf("the disclosed issue is not published:\n%s", all)
		}
		if strings.Contains(all, flaw) {
			t.Errorf("anybody is handed %s, the name of a flaw nobody has disclosed", flaw)
		}
		if strings.Contains(all, "management socket") {
			t.Error("anybody is handed the summary of a flaw nobody has disclosed")
		}
	})
}

// Only anybody at all, and the deployment itself, read the published
// documents here. A signed-in person reads findings through the API, where
// their own grants answer.
func TestThePublishedDocumentsAreReadOnlyAsAnybody(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		w.report(w.Target, reported{"CVE-2026-1001", openssl})
		w.decide(w.Target, "CVE-2026-1001", openssl,
			claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.publishes(w.Product, true)
		w.write()
		if _, err := w.documents.Listed(t.Context(), w.proposer, "all"); !errors.Is(err, access.ErrDenied) {
			t.Errorf("a person reading the published documents here got %v, want a refusal", err)
		}
		if listed, err := w.documents.Listed(t.Context(),
			access.Everything("reading the published documents"), "all"); err != nil || len(listed) == 0 {
			t.Errorf("the deployment itself read %d documents: %v", len(listed), err)
		}
	})
}
