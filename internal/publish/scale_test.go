// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the published documents of a real image come to: how many, how large,
// and how long a pass takes to work them out and to find that nothing moved.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package publish_test

import (
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// kernelIssues is how many issues the kernel of a real switch image carried:
// 4,943 of the 6,822 rows on its findings list.
const kernelIssues = 4943

// fullSizeImage reads the full-size fixture the inventory reader is tested
// against.
func fullSizeImage(t *testing.T) *sbom.Document {
	t.Helper()
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("xz is not available, so the full-size fixture cannot be read here")
	}
	dir, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	out, err := dir.Create("image.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("xz", "--decompress", "--stdout", "../sbom/testdata/switch-image.cdx.json.xz")
	cmd.Stdout = out
	runErr := cmd.Run()
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatalf("decompress the fixture: %v", runErr)
	}
	in, err := dir.Open("image.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close() })
	doc, err := sbom.Read(in, sbom.Limits{})
	if err != nil {
		t.Fatalf("read the fixture: %v", err)
	}
	return doc
}

// The switch image built as both variants of a branch, every component with
// a package identifier carrying one issue and the kernel the 4,943 a real one
// did, and a tenth of the issues agreed not to apply, as the documents a
// published product would serve. On PostgreSQL alone: four engines seeded at
// once measure each other.
func TestMeasurePublishedDocumentsOfARealImage(t *testing.T) {
	doc := fullSizeImage(t)
	dbtest.Only(t, database.Postgres, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := newWorld(t, fixture.New(t, db))
		root := graph.Described{Purl: "pkg:generic/sonic@master.1", Name: "sonic", Version: "master.1"}
		snap := doc.Snapshot(root)
		var reported []finding.Reported
		for i, component := range doc.Components {
			if component.Purl == "" {
				continue
			}
			reported = append(reported, finding.Reported{
				Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
				Component: component,
			})
			if strings.Contains(component.Purl, "/linux-image-") {
				for k := range kernelIssues - 1 {
					reported = append(reported, finding.Reported{
						Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%05d", k), Severity: "medium"},
						Component: component,
					})
				}
			}
		}
		for _, target := range []int64{w.Target.ID, w.TargetFor(w.Branch, w.Internal).ID} {
			scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
				TargetID: target, ContentHash: fmt.Sprintf("full-size-%d", target),
				BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.ApplyGraph(ctx, db.DB, target, scan.ID, snap); err != nil {
				t.Fatal(err)
			}
			run, err := w.findings.Begin(ctx, finding.Run{TargetID: target, Scanner: "measure", RanHere: true})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.findings.Apply(ctx, target, run.ID, reported); err != nil {
				t.Fatal(err)
			}
		}
		// A tenth of the distribution packages' own issues agreed not to
		// apply because the code is not there, in the customer build.
		decided := 0
		seen := map[string]bool{}
		for i, one := range reported {
			if i%10 != 0 || strings.HasPrefix(one.Issue.Identifier, "CVE-2025-") ||
				!strings.HasPrefix(one.Component.Purl, "pkg:deb/") ||
				seen[one.Issue.Identifier+" "+one.Component.Name] {
				continue
			}
			seen[one.Issue.Identifier+" "+one.Component.Name] = true
			w.decide(w.Target, one.Issue.Identifier, one.Component,
				claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
			decided++
		}
		w.publishes(w.Product, true)
		dbtest.SettleStatistics(t, db)

		start := time.Now()
		first := w.write()
		firstTook := time.Since(start)
		start = time.Now()
		again := w.write()
		againTook := time.Since(start)

		var sizes []int
		total, csafCount, openvexCount := 0, 0, 0
		var largestOpenVEX int
		for _, one := range w.listed("all") {
			held, err := w.documents.At(ctx, w.anybody(), one.Path, "all")
			if err != nil {
				t.Fatal(err)
			}
			total += len(held.Body)
			switch one.Kind {
			case publish.CSAFVEX:
				csafCount++
				sizes = append(sizes, len(held.Body))
			case publish.OpenVEX:
				openvexCount++
				largestOpenVEX = max(largestOpenVEX, len(held.Body))
			}
		}
		slices.Sort(sizes)
		s := surfaceOver(w, 1_000_000, nil)
		feed, index := len(s.body(publish.FeedPath)), len(s.body(publish.IndexPath))
		answered := func(path string) []time.Duration {
			var took []time.Duration
			for range 6 {
				start := time.Now()
				s.body(path)
				took = append(took, time.Since(start))
			}
			return took[1:]
		}
		one := strings.Fields(string(s.body(publish.IndexPath)))[0]
		t.Logf("answering the feed: %v; the provider description: %v; one document: %v; "+
			"its digest: %v", answered(publish.FeedPath), answered(publish.MetadataPath),
			answered(publish.DirectoryPath+one), answered(publish.DirectoryPath+one+publish.SHA256Suffix))
		t.Logf("%d issue-at-component pairs per build, two builds, %d agreed not to apply", len(reported), decided)
		t.Logf("first pass: %d documents written in %s; a pass over nothing moved: %d revised in %s",
			first.Revised, firstTook, again.Revised, againTook)
		t.Logf("%d CSAF VEX documents, median %d bytes, largest %d; %d OpenVEX documents, %d bytes; "+
			"%d bytes held in all; feed %d bytes, index %d bytes",
			csafCount, sizes[len(sizes)/2], sizes[len(sizes)-1], openvexCount, largestOpenVEX, total, feed, index)
	})
}
