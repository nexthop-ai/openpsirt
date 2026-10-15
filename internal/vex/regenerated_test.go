// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

func TestAnIssuanceRetriedAfterAClaimWasWithdrawnRecordsTheDocumentAsItNowStands(t *testing.T) {
	// The document is generated inside the transaction that records it, on
	// every attempt. A claim withdrawn between a refused commit and its retry
	// is gone from what is recorded: a document generated once, before, would
	// record a statement nobody stands behind any more.
	ctx := t.Context()
	var between func()
	handle, race := dbtest.Racing(t, func() { between() })
	w := fixture.New(t, handle)
	db := handle.DB

	root := graph.Described{Purl: "pkg:deb/debian/sonic@1.0", Name: "sonic", Version: "1.0"}
	carrier := graph.Described{Purl: "pkg:deb/debian/libnl@3.7.0", Name: "libnl", Version: "3.7.0"}
	scan, outcome, err := ingest.NewStore(db).Record(ctx, ingest.Arriving{
		TargetID: w.Target.ID, ContentHash: "hash-1",
		BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := fixture.ApplyGraph(ctx, db, w.Target.ID, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{carrier},
		Dependencies: []graph.Dependency{{Parent: root, Child: carrier}},
	}); err != nil {
		t.Fatal(err)
	}
	findings := finding.NewStore(db)
	run, err := findings.Begin(ctx, finding.Run{TargetID: w.Target.ID, Scanner: "grype", RanHere: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Apply(ctx, w.Target.ID, run.ID, []finding.Reported{{
		Issue: finding.Named{Identifier: "CVE-2026-0001", Severity: "high"}, Component: carrier,
	}}); err != nil {
		t.Fatal(err)
	}
	issue, err := finding.NewVulnerabilities(db).ByName(ctx, "CVE-2026-0001")
	if err != nil {
		t.Fatal(err)
	}

	rights := access.NewStore(db)
	roles := []access.Role{access.PublicRead, access.PublicTriage, access.Approver}
	person := func(identity string) access.Subject {
		account, err := rights.Ensure(ctx, identity, identity, new(false), nil)
		if err != nil {
			t.Fatal(err)
		}
		return access.NewPerson(account.ID, identity, false,
			map[int64][]access.Role{w.Product.ID: roles}, 0)
	}
	proposer, approver := person("ana@example.com"), person("ben@example.com")
	var open []finding.Finding
	if err := db.NewSelect().Model(&open).Where(`"target_id" = ?`, w.Target.ID).Scan(ctx); err != nil ||
		len(open) != 1 {
		t.Fatalf("the scan opened %d findings: %v", len(open), err)
	}
	at, err := findings.PlaceFor(ctx, proposer, w.Target.ID, issue, open[0].PlaceIdentity)
	if err != nil {
		t.Fatal(err)
	}
	decisions := triage.NewStore(db)
	decision, err := decisions.Propose(ctx, proposer, triage.Proposal{
		Place: triage.Place{
			ProductID: at.ProductID, VulnerabilityID: at.VulnerabilityID,
			PlaceIdentity: at.PlaceIdentity, Visibility: at.Visibility,
			ComponentUpstream: at.ComponentUpstream, ConsumerUpstream: at.ConsumerUpstream,
			OnTag: at.OnTag,
		},
		Outcome: triage.NotApplicable, Justification: triage.CodeNotPresent,
		Reasoning: "The routine is not built into any image we ship.",
		By:        proposer.ID, NeedsApproval: true, MadeOn: []int64{w.Target.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decisions.ApproveClaim(ctx, approver, decision.ClaimID, "", nil, ""); err != nil {
		t.Fatal(err)
	}

	named := publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}
	store := vex.NewStore(db)
	standing, err := store.For(ctx, proposer, named, "sonic", "master", "broadcom", false, vex.Ours)
	if err != nil {
		t.Fatal(err)
	}
	before, err := json.Marshal(standing)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), "not_affected") {
		t.Fatalf("the agreed claim is not in the document before the race: %s", before)
	}

	between = func() {
		if err := decisions.Withdraw(ctx, proposer, decision.ClaimID); err != nil {
			t.Errorf("withdrawing between the attempts: %v", err)
		}
	}
	race.Arm(1)
	recorded, err := store.Issued(ctx, proposer, named, "sonic", "master", "broadcom", vex.Ours)
	if err != nil {
		t.Fatal(err)
	}
	if race.Unspent() != 0 {
		t.Fatal("no commit was refused, so nothing ran between the attempts")
	}
	if strings.Contains(recorded.Document, "not_affected") {
		t.Errorf("the recorded document states a claim withdrawn before it was recorded: %s",
			recorded.Document)
	}
}
