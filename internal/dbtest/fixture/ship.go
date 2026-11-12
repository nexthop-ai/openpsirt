// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Ship records a scan of a build, built at builtAt: its root and the
// dependencies beneath it. builtAt also names the scan's content, so two
// scans of one build differ by it.
func (w *World) Ship(build *catalog.Build, builtAt time.Time, root graph.Described, edges ...graph.Dependency) {
	w.t.Helper()
	ctx := w.t.Context()
	scan, outcome, err := ingest.NewStore(w.DB.DB).Record(ctx, ingest.Arriving{
		BuildID: build.ID, ContentHash: "hash-" + builtAt.UTC().Format(time.RFC3339Nano),
		BuiltAt: builtAt, ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		w.t.Fatalf("record a scan: %v %v", outcome, err)
	}
	snap := graph.Snapshot{Root: root, Dependencies: edges}
	seen := map[string]bool{}
	for _, one := range edges {
		for _, part := range []graph.Described{one.Parent, one.Child} {
			if part != root && !seen[part.Purl] {
				seen[part.Purl] = true
				snap.Components = append(snap.Components, part)
			}
		}
	}
	if _, err := ApplyGraph(ctx, w.DB.DB, build.ID, scan.ID, snap); err != nil {
		w.t.Fatal(err)
	}
	if root.Purl != "" {
		if _, err := w.DB.DB.NewUpdate().TableExpr(`"scan"`).
			Set(`"root_identifier" = ?`, root.Purl).
			Where(`"id" = ?`, scan.ID).Exec(ctx); err != nil {
			w.t.Fatal(err)
		}
	}
}

// Report runs a scanner over a build, reporting these and nothing else.
func (w *World) Report(build *catalog.Build, found ...finding.Reported) {
	w.t.Helper()
	ctx := w.t.Context()
	findings := finding.NewStore(w.DB.DB)
	run, err := findings.Begin(ctx, finding.Run{BuildID: build.ID, Scanner: "grype", RanHere: true})
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := findings.Apply(ctx, build.ID, run.ID, found); err != nil {
		w.t.Fatal(err)
	}
}

// Decide has proposer record said at every open occurrence of an issue in the
// component named, in one build, and has approver agree where the decision
// needs a second person. A nil approver leaves it waiting.
//
// said carries what the decision says; where it stands and who made it are
// filled in, and a decision with no reasoning is given some.
func (w *World) Decide(build *catalog.Build, issue, component string, said triage.Proposal,
	proposer access.Subject, approver *access.Subject) {

	w.t.Helper()
	ctx := w.t.Context()
	vulnerability, err := finding.NewVulnerabilities(w.DB.DB).ByName(ctx, issue)
	if err != nil {
		w.t.Fatal(err)
	}
	var open []finding.Finding
	if err := w.DB.DB.NewSelect().Model(&open).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Where(`"f"."build_id" = ?`, build.ID).
		Where(`"f"."vulnerability_id" = ?`, vulnerability).
		Where(`"c"."name" = ?`, component).
		Where(`"f"."closed_at" IS NULL`).
		Scan(ctx); err != nil || len(open) == 0 {
		w.t.Fatalf("%s is open at %d occurrences of %s: %v", issue, len(open), component, err)
	}
	if said.Reasoning == "" {
		said.Reasoning = "Read the code."
	}
	said.By, said.MadeOn, said.BindingAcross = proposer.ID, []int64{build.ID}, []int64{build.ID}
	findings := finding.NewStore(w.DB.DB)
	var proposals []triage.Proposal
	placed := map[string]bool{}
	for _, one := range open {
		// One occurrence holds every version of a name it ever shipped, so two
		// findings of one issue may share it.
		if placed[one.OccurrenceIdentity] {
			continue
		}
		placed[one.OccurrenceIdentity] = true
		at, err := findings.OccurrenceFor(ctx, proposer, build.ID, vulnerability, one.OccurrenceIdentity)
		if err != nil {
			w.t.Fatal(err)
		}
		said.Occurrence = triage.Occurrence{
			ProductID: at.ProductID, VulnerabilityID: at.VulnerabilityID,
			OccurrenceIdentity: at.OccurrenceIdentity, Visibility: at.Visibility,
			ComponentUpstream: at.ComponentUpstream, ConsumerUpstream: at.ConsumerUpstream,
			OnTag: at.OnTag,
		}
		proposals = append(proposals, said)
	}
	decisions := triage.NewStore(w.DB.DB)
	recorded, err := decisions.ProposeMany(ctx, proposer, proposals)
	if err != nil {
		w.t.Fatal(err)
	}
	if recorded[0].NeedsApproval && approver != nil {
		if _, err := decisions.ApproveDecision(ctx, *approver, recorded[0].DecisionID, "", nil, ""); err != nil {
			w.t.Fatal(err)
		}
	}
}
