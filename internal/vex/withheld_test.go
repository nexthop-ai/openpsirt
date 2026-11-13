// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// aliasedByAFlaw records a flaw in the build `in` and an agreed decision on a
// disclosed issue in the world's build that carries the flaw's minted name as
// an alias. It returns a person holding every role in the world's product
// alone, and the minted name.
func aliasedByAFlaw(t *testing.T, w *fixture.World, in *catalog.Build, inProduct int64) (access.Subject, string) {
	t.Helper()
	ctx := t.Context()
	db := w.DB.DB
	root := graph.Described{Purl: "pkg:deb/debian/sonic@1.0", Name: "sonic", Version: "1.0"}
	swss := graph.Described{Purl: "pkg:deb/sonic/swss@1.0.0", Name: "swss", Version: "1.0.0"}
	openssl := graph.Described{Purl: "pkg:deb/debian/openssl@3.0.11", Name: "openssl", Version: "3.0.11"}
	builds := []int64{w.Build.ID}
	if in.ID != w.Build.ID {
		builds = append(builds, in.ID)
	}
	for _, build := range builds {
		scan, outcome, err := ingest.NewStore(db).Record(ctx, ingest.Arriving{
			BuildID: build, ContentHash: fmt.Sprintf("hash-%d", build),
			BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record scan: %v %v", outcome, err)
		}
		if _, err := fixture.ApplyGraph(ctx, db, build, scan.ID, graph.Snapshot{
			Root: root, Components: []graph.Described{swss, openssl},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: root, Child: openssl}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	roles := []access.Role{access.PublicRead, access.PublicTriage, access.PrivateRead,
		access.PrivateTriage, access.Approver}
	person := func(identity string, product int64) access.Subject {
		account, err := access.NewStore(db).Ensure(ctx, identity, identity, new(false), nil)
		if err != nil {
			t.Fatal(err)
		}
		return access.NewPerson(account.ID, identity, false,
			map[int64][]access.Role{product: roles}, 0)
	}
	proposer, approver := person("ana@example.com", w.Product.ID), person("ben@example.com", w.Product.ID)
	recorder := person("cy@example.com", inProduct)
	findings := finding.NewStore(db)
	_, flaw, err := findings.Enter(ctx, recorder, finding.Entering{
		BuildIDs: []int64{in.ID}, Component: swss.Name,
		Summary: "The management socket answers anybody.", Told: finding.Told{FoundHere: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	run, err := findings.Begin(ctx, finding.Run{BuildID: w.Build.ID, Scanner: "grype", RanHere: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Apply(ctx, w.Build.ID, run.ID, []finding.Reported{{
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
		Where(`"build_id" = ?`, w.Build.ID).Where(`"visibility" = ?`, access.Public).
		Where(`"closed_at" IS NULL`).Scan(ctx); err != nil || len(open) != 1 {
		t.Fatalf("the report opened %d disclosed findings: %v", len(open), err)
	}
	at, err := findings.OccurrenceFor(ctx, proposer, w.Build.ID, issue, open[0].OccurrenceIdentity)
	if err != nil {
		t.Fatal(err)
	}
	decisions := triage.NewStore(db)
	occurrence, err := decisions.Propose(ctx, proposer, triage.Proposal{
		Occurrence: triage.Occurrence{
			ProductID: at.ProductID, VulnerabilityID: at.VulnerabilityID,
			OccurrenceIdentity: at.OccurrenceIdentity, Visibility: at.Visibility,
			ComponentUpstream: at.ComponentUpstream, ConsumerUpstream: at.ConsumerUpstream,
		},
		Outcome: triage.NotApplicable, Justification: triage.CodeNotPresent,
		Reasoning: "Not built.", By: proposer.ID, NeedsApproval: true, MadeOn: []int64{w.Build.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decisions.ApproveDecision(ctx, approver, occurrence.DecisionID, "", nil, ""); err != nil {
		t.Fatal(err)
	}
	return proposer, flaw
}

// namesIt is whether the document the reader asks for names the flaw.
func namesIt(t *testing.T, w *fixture.World, reader access.Subject, undisclosed bool, flaw string) bool {
	t.Helper()
	named := publisher.Named{Name: "Example Networks", Namespace: "https://example.test"}
	doc, err := vex.NewStore(w.DB.DB).For(t.Context(), reader, named, "sonic", "master", "broadcom",
		undisclosed, vex.Ours)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "CVE-2026-3001") {
		t.Fatalf("the agreed decision is not in the document: %s", body)
	}
	return strings.Contains(string(body), flaw)
}

// A build's document of disclosed work names no other name of an issue that is
// also a flaw of ours nobody has disclosed: one of them is the name minted for
// it. A preview including undisclosed work, for somebody who may read it,
// keeps them.
func TestAnUndisclosedFlawsNameIsNotAnAliasInADocumentOfDisclosedWork(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		reader, flaw := aliasedByAFlaw(t, w, w.Build, w.Product.ID)
		for _, tc := range []struct {
			undisclosed bool
			names       bool
		}{{false, false}, {true, true}} {
			if named := namesIt(t, w, reader, tc.undisclosed, flaw); named != tc.names {
				t.Errorf("with undisclosed work %v, the document names %s %v, want %v",
					tc.undisclosed, flaw, named, tc.names)
			}
		}
	})
}

// A preview including undisclosed work keeps only the names its reader may
// read: reading undisclosed work in one product says nothing of a flaw
// recorded in another.
func TestAPreviewNamesNoFlawRecordedWhereItsReaderMayNotRead(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		other := w.DeclareProduct("other", "Other Images")
		branch := w.DeclareBranchOrTag(other, "main", catalog.Branch, nil)
		variant := w.DeclareVariant(other, "x86", true)
		reader, flaw := aliasedByAFlaw(t, w, w.BuildFor(branch, variant), other.ID)
		for _, undisclosed := range []bool{false, true} {
			if namesIt(t, w, reader, undisclosed, flaw) {
				t.Errorf("with undisclosed work %v, the document names %s, recorded in a product its reader holds nothing on",
					undisclosed, flaw)
			}
		}
	})
}
