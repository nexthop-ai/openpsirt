// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What reading the kinds of package present costs on a real image.
//
// The kind is read out of each distinct package identifier in Go, after the
// statement has counted what is open per component. The alternative is
// reading it in the statement, which is spelled once per engine, and the
// choice between the two waits on this number.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package finding_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
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

func TestMeasurePackageKindsOnARealImage(t *testing.T) {
	doc := fullSizeImage(t)
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		scan, _, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
			TargetID: w.Target.ID, ContentHash: "full-size", BuiltAt: time.Now().UTC(),
			ParserVersion: "measure",
		})
		if err != nil {
			t.Fatal(err)
		}
		snap := doc.Snapshot(graph.Described{Name: "sonic", Version: "1.0"})
		if _, err := graph.NewStore(db.DB).Apply(ctx, w.Target.ID, scan.ID, snap); err != nil {
			t.Fatal(err)
		}

		// Every component with a package identifier carries one issue, which
		// is every distinct identifier the statement can hand back, and the
		// kernel carries what a real one did.
		var reported []finding.Reported
		identifiers := 0
		for i, component := range doc.Components {
			if component.Purl == "" {
				continue
			}
			identifiers++
			reported = append(reported, finding.Reported{
				Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
				Component: component,
			})
			if strings.Contains(component.Purl, "/linux-image-") {
				for k := range kernelIssues - 1 {
					reported = append(reported, finding.Reported{
						Issue: finding.Named{
							Identifier: fmt.Sprintf("CVE-2025-%05d", k), Severity: "medium",
						},
						Component: component,
					})
				}
			}
		}
		store := finding.NewStore(db.DB)
		run, err := store.Begin(ctx, finding.Run{
			TargetID: w.Target.ID, Scanner: "measure", ScannerVersion: "0",
			DatabaseVersion: "0", RanHere: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		applied, err := store.Apply(ctx, w.Target.ID, run.ID, reported)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%d components, %d with a package identifier; %d issue-at-component pairs "+
			"reported, %d findings opened in %s",
			len(doc.Components), identifiers, len(reported), applied.Opened, time.Since(start))

		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)
		scope := finding.Scope{ProductID: &w.Product.ID}

		// The first read warms the engine's cache; the rest are the number.
		const reads = 5
		var kinds []finding.PackageKind
		var took []time.Duration
		for range reads + 1 {
			start := time.Now()
			kinds, err = store.PackageKinds(ctx, who, scope)
			if err != nil {
				t.Fatal(err)
			}
			took = append(took, time.Since(start))
		}
		open := 0
		for _, kind := range kinds {
			open += kind.Open
		}
		t.Logf("package kinds: %d kinds over %d pairs, read in %v", len(kinds), open, took[1:])

		// Beside it, the list's first page, which is what the panel is opened
		// over.
		var page []time.Duration
		for range reads + 1 {
			start := time.Now()
			if _, _, err := store.Groups(ctx, who, scope, 50, 0, finding.Filter{}); err != nil {
				t.Fatal(err)
			}
			page = append(page, time.Since(start))
		}
		t.Logf("the findings list's first page, for comparison: %v", page[1:])
	})
}
