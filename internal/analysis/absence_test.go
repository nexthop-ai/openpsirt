// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// atVersion is a document whose analyzer states another version.
func atVersion(doc, version string) string {
	return strings.Replace(doc, `"version":"18.1.3"`, `"version":"`+version+`"`, 1)
}

// atCommits is a document whose checkout holds the top repository and FRR at
// these commits.
func atCommits(doc, top, frr string) string {
	return strings.NewReplacer(`"revisionId":"abc"`, `"revisionId":"`+top+`"`,
		`"revisionId":"def"`, `"revisionId":"`+frr+`"`).Replace(doc)
}

func TestACodeFindingLastSeenByAnotherToolVersionIsNotMarkedNoLongerDetected(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-4 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR, inSWSS}, 10))
		// An upgraded analyzer is not comparable to the run before it.
		upgraded, _ := w.send(t, w.Build.ID, start.Add(time.Hour), atVersion(document([]sent{inSWSS}, 10), "19.1.0"))
		if upgraded.Reason != series.ToolChanged {
			t.Fatalf("the upgraded run is %q; want tool-changed", upgraded.Reason)
		}
		// The next run is comparable to the upgraded one, and not to the run
		// that last saw the FRR code finding.
		run, _ := w.send(t, w.Build.ID, start.Add(2*time.Hour), atVersion(document([]sent{inSWSS}, 10), "19.1.0"))
		if run.Comparable == nil || !*run.Comparable {
			t.Fatalf("comparable %v (%q); want comparable", run.Comparable, run.Reason)
		}
		if r := receiptOf(t, run); r.NoLongerDetected != 0 || r.Uncompared != 1 || r.Seen != 1 {
			t.Errorf("receipt %+v; want the FRR code finding left open and counted as uncompared", r)
		}
		var absent int
		if err := w.DB.DB.NewSelect().TableExpr(`"sighting" AS "si"`).ColumnExpr(`COUNT(*)`).
			Where(`"si"."absent_run_id" IS NOT NULL`).Scan(t.Context(), &absent); err != nil {
			t.Fatal(err)
		}
		if absent != 0 {
			t.Errorf("%d code findings marked no longer detected; want none", absent)
		}
	})
}

func TestTheFirstRunOnABranchFingerprintedAnewTakesItsParentsCodeFindingOnTheUnprintedKey(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		tag := w.BuildFor(w.Tag, w.Customer)
		w.inventory(t, w.Build.ID)
		w.inventory(t, tag.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		printed := inside{inFRR, "", "a1"}
		w.send(t, w.Build.ID, start, documentOf([]interface{ json() string }{printed}, 10, "0123456789abcdef"))

		// The salt rotated before the branch's first run: the fingerprint
		// changed and nothing else, and the line moved.
		printed.print = "b1"
		printed.line += 3
		run, _ := w.send(t, tag.ID, start.Add(time.Hour),
			documentOf([]interface{ json() string }{printed}, 10, "fedcba9876543210"))
		if r := receiptOf(t, run); !r.FingerprintsChanged || r.Inherited != 1 || r.Probable != 0 {
			t.Errorf("receipt %+v; want a fingerprint change inheriting the code finding strongly", r)
		}
		branch, cut := w.codeFindings(t, w.Build.ID), w.codeFindings(t, tag.ID)
		if len(branch) != 1 || len(cut) != 1 || branch[0].OccurrenceIdentity != cut[0].OccurrenceIdentity {
			t.Errorf("branch %+v, tag %+v; want one code finding each at one occurrence", branch, cut)
		}
	})
}

func TestAResultIsPlacedOnTheComponentWhosePlatformEnumerationNamesItsRepository(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventoryWith(t, w.Build.ID, graph.Described{Purl: "pkg:deb/debian/frr@10.2", Name: "frr",
			Version: "10.2", CPE: "cpe:2.3:a:frrouting:frr:10.2:*:*:*:*:*:*:*"})
		if _, status := w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour),
			document([]sent{inFRR}, 10)); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		if codeFindings := w.codeFindings(t, w.Build.ID); len(codeFindings) != 1 || codeFindings[0].ComponentID != w.frr {
			t.Errorf("findings %+v; want one on FRR (%d)", codeFindings, w.frr)
		}
	})
}

func TestAPlatformEnumerationNamingAnotherOwnerPlacesNothing(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventoryWith(t, w.Build.ID, graph.Described{Purl: "pkg:deb/debian/frr@10.2", Name: "frr",
			Version: "10.2", CPE: "cpe:2.3:a:debian:frr:10.2:*:*:*:*:*:*:*"})
		w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
		if codeFindings := w.codeFindings(t, w.Build.ID); len(codeFindings) != 1 || codeFindings[0].ComponentID != w.root {
			t.Errorf("findings %+v; want one on the build (%d)", codeFindings, w.root)
		}
	})
}

func TestACodeFindingNoLongerSeenNamesItsRepositorysCommitInBothBuilds(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, atCommits(document([]sent{inFRR, inSWSS}, 10), "1111111", "AAAAAAA"))
		w.send(t, w.Build.ID, start.Add(time.Hour), atCommits(document([]sent{inSWSS}, 10), "2222222", "bbbbbbb"))
		reader := w.holding(t, "analyst", access.InternalRead)
		for _, codeFinding := range w.codeFindings(t, w.Build.ID) {
			got, err := EvidenceOf(t.Context(), w.DB.DB, reader, &codeFinding, w.Product.ID)
			if err != nil {
				t.Fatal(err)
			}
			switch codeFinding.ComponentID {
			case w.frr:
				if got.LastCommit != "aaaaaaa" || got.NotSeenCommit != "bbbbbbb" {
					t.Errorf("the FRR code finding names %q and %q; want FRR's commits", got.LastCommit, got.NotSeenCommit)
				}
			default:
				if got.LastCommit != "2222222" || got.NotSeenCommit != "" {
					t.Errorf("the code finding on the build names %q and %q; want the top commit it was last seen at",
						got.LastCommit, got.NotSeenCommit)
				}
			}
		}
	})
}
