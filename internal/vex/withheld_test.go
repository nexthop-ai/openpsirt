// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// A build's document of disclosed work names no other name of an issue that is
// also a flaw of ours nobody has disclosed: one of them is the name minted for
// it. A preview including undisclosed work, for somebody who may read it,
// keeps them.
func TestAnUndisclosedFlawsNameIsNotAnAliasInADocumentOfDisclosedWork(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		db := w.DB.DB
		root := graph.Described{Purl: "pkg:deb/debian/sonic@1.0", Name: "sonic", Version: "1.0"}
		swss := graph.Described{Purl: "pkg:deb/sonic/swss@1.0.0", Name: "swss", Version: "1.0.0"}
		openssl := graph.Described{Purl: "pkg:deb/debian/openssl@3.0.11", Name: "openssl", Version: "3.0.11"}
		scan, outcome, err := ingest.NewStore(db).Record(ctx, ingest.Arriving{
			TargetID: w.Target.ID, ContentHash: "hash-1",
			BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record scan: %v %v", outcome, err)
		}
		if _, err := fixture.ApplyGraph(ctx, db, w.Target.ID, scan.ID, graph.Snapshot{
			Root: root, Components: []graph.Described{swss, openssl},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: root, Child: openssl}},
		}); err != nil {
			t.Fatal(err)
		}
		roles := []access.Role{access.PublicRead, access.PublicTriage, access.PrivateRead,
			access.PrivateTriage, access.Approver}
		person := func(identity string) access.Subject {
			account, err := access.NewStore(db).Ensure(ctx, identity, identity, new(false), nil)
			if err != nil {
				t.Fatal(err)
			}
			return access.NewPerson(account.ID, identity, false,
				map[int64][]access.Role{w.Product.ID: roles}, 0)
		}
		proposer, approver := person("ana@example.com"), person("ben@example.com")
		findings := finding.NewStore(db)
		_, flaw, err := findings.Enter(ctx, proposer, finding.Entering{
			TargetIDs: []int64{w.Target.ID}, Component: swss.Name,
			Summary: "The management socket answers anybody.", Told: finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		run, err := findings.Begin(ctx, finding.Run{TargetID: w.Target.ID, Scanner: "grype", RanHere: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := findings.Apply(ctx, w.Target.ID, run.ID, []finding.Reported{{
			Issue:     finding.Named{Identifier: "CVE-2026-3001", Aliases: []string{flaw}, Severity: "high"},
			Component: openssl,
		}}); err != nil {
			t.Fatal(err)
		}
		issue, err := finding.NewVulnerabilities(db).ByName(ctx, "CVE-2026-3001")
		if err != nil {
			t.Fatal(err)
		}
		var open []finding.Finding
		if err := db.NewSelect().Model(&open).
			Where(`"target_id" = ?`, w.Target.ID).Where(`"visibility" = ?`, access.Public).
			Where(`"closed_at" IS NULL`).Scan(ctx); err != nil || len(open) != 1 {
			t.Fatalf("the report opened %d disclosed findings: %v", len(open), err)
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
			},
			Outcome: triage.NotApplicable, Justification: triage.CodeNotPresent,
			Reasoning: "Not built.", By: proposer.ID, NeedsApproval: true, MadeOn: []int64{w.Target.ID},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decisions.ApproveClaim(ctx, approver, decision.ClaimID, "", nil, ""); err != nil {
			t.Fatal(err)
		}

		named := publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}
		store := vex.NewStore(db)
		for _, tc := range []struct {
			undisclosed bool
			names       bool
		}{{false, false}, {true, true}} {
			doc, err := store.For(ctx, proposer, named, "sonic", "master", "broadcom", tc.undisclosed, vex.Ours)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), "CVE-2026-3001") {
				t.Fatalf("the agreed claim is not in the document: %s", body)
			}
			if named := strings.Contains(string(body), flaw); named != tc.names {
				t.Errorf("with undisclosed work %v, the document names %s %v, want %v",
					tc.undisclosed, flaw, named, tc.names)
			}
		}
	})
}
