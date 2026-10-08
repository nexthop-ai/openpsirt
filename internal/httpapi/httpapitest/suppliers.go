// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// AcmeSays is the supplier fixture the readers are tested against: Acme's
// product Y, at 4.2, bundling zlib, with Acme's statements about three issues.
func AcmeSays(t *testing.T) string {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	body, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "sbom", "testdata",
		"supplier-product-inside.openvex.json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// ScannedInsideAcme stores a build of mine on master for broadcom holding
// Acme's product Y with zlib inside it, and zlib pulled in by curl as well
// where outsideToo says so, then applies a run reporting CVE-2022-37434
// against zlib.
func (r *Reach) ScannedInsideAcme(t *testing.T, hash string, outsideToo bool) {
	t.Helper()
	ctx := t.Context()

	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: hash, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	acmeY := graph.Described{Purl: "pkg:generic/acme-y@4.2", Name: "acme-y", Version: "4.2"}
	zlib := graph.Described{Purl: "pkg:generic/zlib@1.2.11", Name: "zlib", Version: "1.2.11"}
	curl := graph.Described{Purl: "pkg:deb/debian/curl@8.5.0", Name: "curl", Version: "8.5.0"}
	snap := graph.Snapshot{
		Root:       product,
		Components: []graph.Described{acmeY, zlib},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: acmeY},
			{Parent: acmeY, Child: zlib},
		},
	}
	if outsideToo {
		snap.Components = append(snap.Components, curl)
		snap.Dependencies = append(snap.Dependencies,
			graph.Dependency{Parent: product, Child: curl}, graph.Dependency{Parent: curl, Child: zlib})
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, snap); err != nil {
		t.Fatal(err)
	}

	findings := finding.NewStore(r.DB.DB)
	run, err := findings.Begin(ctx, finding.Run{
		TargetID: target.ID, Scanner: "grype", ScannerVersion: "0.112.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{{
		Issue: finding.Named{
			Identifier: "CVE-2022-37434", Severity: "critical",
			Description: "A heap overflow in inflateGetHeader.", Score: 9.8,
		},
		Component: zlib, FixState: finding.FixedUpstream, FixedIn: "1.2.12",
	}}); err != nil {
		t.Fatal(err)
	}
}
