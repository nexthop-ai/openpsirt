// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package vex_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// The published facts name no other name of an issue that a flaw of ours
// nobody has disclosed wrote onto it, whoever asks for them: what they return
// is published, so the reach of the subject asking withholds nothing more.
func TestPublishedFactsWithholdAnUndisclosedFlawsNameWhoeverAsks(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		db := w.DB.DB
		root := graph.Described{Purl: "pkg:deb/debian/sonic@1.0", Name: "sonic", Version: "1.0"}
		swss := graph.Described{Purl: "pkg:deb/sonic/swss@1.0.0", Name: "swss", Version: "1.0.0"}
		openssl := graph.Described{Purl: "pkg:deb/debian/openssl@3.0.11", Name: "openssl", Version: "3.0.11"}
		w.Ship(w.Build, time.Now().UTC().Add(-time.Hour), root,
			graph.Dependency{Parent: root, Child: swss}, graph.Dependency{Parent: root, Child: openssl})
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
		_, flaw, err := finding.NewStore(db).Enter(ctx, proposer, finding.Entering{
			BuildIDs: []int64{w.Build.ID}, Component: swss.Name,
			Summary: "The management socket answers anybody.", Told: finding.Told{FoundHere: true},
		})
		if err != nil {
			t.Fatal(err)
		}
		w.Report(w.Build, finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-3001", Aliases: []string{flaw}, Severity: "high"},
			Component: openssl,
		})
		w.Decide(w.Build, "CVE-2026-3001", openssl.Name, triage.Proposal{
			Outcome: triage.NotApplicable, Justification: triage.CodeNotPresent, NeedsApproval: true,
		}, proposer, &approver)

		named, err := w.Catalog.Locate(ctx, fixture.ProductName, fixture.BranchName, fixture.CustomerVariant)
		if err != nil {
			t.Fatal(err)
		}
		built, err := vex.NewStore(db).Public(ctx, proposer, named, w.Build.ID)
		if err != nil {
			t.Fatal(err)
		}
		examined := 0
		for _, fact := range built.Facts {
			if fact.Issue != "CVE-2026-3001" {
				continue
			}
			examined++
			if slices.Contains(fact.Aliases, flaw) {
				t.Errorf("a subject reading undisclosed work had %s published as another name of %s",
					flaw, fact.Issue)
			}
		}
		if examined == 0 {
			t.Fatalf("the agreed decision is not among the facts: %+v", built.Facts)
		}
	})
}
