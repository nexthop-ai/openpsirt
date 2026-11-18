// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

var linuxPerf = graph.Described{Purl: "pkg:deb/debian/linux-perf@6.12.57-1", Name: "linux-perf", Version: "6.12.57-1"}

// A finding a correction by source paths answers is published as not
// affected, as any wrong match is, once a second person agrees, and not
// before: in CSAF, with the reason as its flag, and in OpenVEX, with the
// reason as its justification and no impact statement.
func TestACorrectionBySourcePathsPublishesAsAWrongMatchOnceAgreed(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.ship(w.Build, sonicRoot, edge{sonicRoot, openssl}, edge{sonicRoot, linuxPerf})
		w.Report(w.Build, finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2024-26600", Severity: "high", Description: "A driver flaw."},
			Component: linuxPerf, MatchedThrough: "linux",
			RecordRead: true, RecordFiles: []string{"drivers/phy/ti/phy-omap-usb2.c"},
		}, finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-1001", Severity: "high", Description: "An unrelated project."},
			Component: openssl,
		})
		// A wrong match recorded by hand, to publish beside.
		w.decide(w.Build, "CVE-2026-1001", openssl,
			decision{outcome: triage.Mismatched, justification: triage.CodeNotPresent})
		proposed, err := w.decisions.ProposeBySource(t.Context(), w.proposer, triage.SourceProposal{
			ProductID: w.Product.ID, Package: "linux-perf", Source: "linux",
			Paths: []string{"tools/perf", "tools/lib", "tools/include"}, Justification: triage.CodeNotPresent,
			Reasoning: "linux-perf is built from tools/ alone.", By: w.proposer.ID,
		})
		if err != nil {
			t.Fatal(err)
		}
		w.publishes(w.Product, true)
		w.write()
		if doc := w.csafAbout(w.Product, "CVE-2024-26600"); doc != nil &&
			len(doc.Vulnerabilities[0].Status.KnownNotAffected) > 0 {
			t.Errorf("a correction nobody agreed to publishes not affected: %+v", doc.Vulnerabilities[0].Status)
		}
		if said := statementAbout(w.openVEXAbout(w.Product, w.Branch.Name), "CVE-2024-26600"); said != nil &&
			said.Status == vex.NotAffected {
			t.Errorf("a correction nobody agreed to publishes %+v in OpenVEX", *said)
		}

		if _, err := w.decisions.ApproveDecision(t.Context(), w.approver, proposed.DecisionID, "", nil, ""); err != nil {
			t.Fatal(err)
		}
		w.write()
		corrected := w.csafAbout(w.Product, "CVE-2024-26600")
		byHand := w.csafAbout(w.Product, "CVE-2026-1001")
		if corrected == nil || byHand == nil {
			t.Fatalf("CSAF documents: corrected %v, by hand %v", corrected != nil, byHand != nil)
		}
		if got := corrected.Vulnerabilities[0].Status.KnownNotAffected; len(got) != 1 {
			t.Errorf("known not affected %v, want linux-perf", got)
		}
		if !sameShape(corrected.Vulnerabilities[0], byHand.Vulnerabilities[0]) {
			t.Errorf("the correction publishes %+v, a wrong match by hand %+v",
				corrected.Vulnerabilities[0], byHand.Vulnerabilities[0])
		}

		statements := w.openVEXAbout(w.Product, w.Branch.Name)
		perf, hand := statementAbout(statements, "CVE-2024-26600"), statementAbout(statements, "CVE-2026-1001")
		if perf == nil || hand == nil {
			t.Fatalf("OpenVEX statements: corrected %v, by hand %v", perf, hand)
		}
		if perf.Status != vex.NotAffected || perf.Justification != string(triage.CodeNotPresent) ||
			perf.Status != hand.Status || perf.Justification != hand.Justification ||
			perf.ImpactStatement != hand.ImpactStatement {
			t.Errorf("OpenVEX says %+v of the correction, %+v of the wrong match by hand", *perf, *hand)
		}
	})
}

// sameShape reports whether two vulnerabilities of CSAF documents say the
// same about their one product: the statuses it is listed under, the flags,
// and the threats, by label and detail.
func sameShape(a, b advisory.Vulnerability) bool {
	listed := func(s advisory.Status) []int {
		return []int{len(s.KnownAffected), len(s.KnownNotAffected), len(s.Fixed)}
	}
	flags := func(v advisory.Vulnerability) []string {
		var out []string
		for _, f := range v.Flags {
			out = append(out, f.Label)
		}
		return out
	}
	threats := func(v advisory.Vulnerability) []string {
		var out []string
		for _, t := range v.Threats {
			out = append(out, t.Category+":"+t.Details)
		}
		return out
	}
	return slices.Equal(listed(a.Status), listed(b.Status)) &&
		slices.Equal(flags(a), flags(b)) && slices.Equal(threats(a), threats(b))
}

// statementAbout is the statement an OpenVEX document makes about an issue,
// or nil.
func statementAbout(doc *vex.Statements, issue string) *vex.Statement {
	if doc == nil {
		return nil
	}
	for i := range doc.Statements {
		if doc.Statements[i].Vulnerability.Name == issue {
			return &doc.Statements[i]
		}
	}
	return nil
}
