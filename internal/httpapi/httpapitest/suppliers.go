// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
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
// Acme's product Y at 4.2 with zlib inside it, and zlib pulled in by curl as
// well where outsideToo says so, then applies a run reporting CVE-2022-37434
// against zlib.
func (r *Reach) ScannedInsideAcme(t *testing.T, hash string, outsideToo bool) {
	t.Helper()
	r.ScannedInsideAcmeAt(t, hash, "4.2", outsideToo, nil)
}

// ScannedInsideAcmeAt is ScannedInsideAcme with Y at a version of the caller's
// choosing, and with what the build argues about what it ships.
func (r *Reach) ScannedInsideAcmeAt(t *testing.T, hash, version string, outsideToo bool,
	claims []sbom.Suppression) {

	t.Helper()
	acmeY := graph.Described{Purl: "pkg:generic/acme-y@" + version, Name: "acme-y", Version: version}
	zlib := graph.Described{Purl: "pkg:generic/zlib@1.2.11", Name: "zlib", Version: "1.2.11"}
	curl := graph.Described{Purl: "pkg:deb/debian/curl@8.5.0", Name: "curl", Version: "8.5.0"}
	snap := graph.Snapshot{
		Root:       SeededRoot,
		Components: []graph.Described{acmeY, zlib},
		Dependencies: []graph.Dependency{
			{Parent: SeededRoot, Child: acmeY},
			{Parent: acmeY, Child: zlib},
		},
	}
	if outsideToo {
		snap.Components = append(snap.Components, curl)
		snap.Dependencies = append(snap.Dependencies,
			graph.Dependency{Parent: SeededRoot, Child: curl}, graph.Dependency{Parent: curl, Child: zlib})
	}
	target, scan := r.Shipped(t, SeededBuild, hash, snap)
	r.Argued(t, target, scan, claims)
	r.Ran(t, target, []finding.Reported{{
		Issue: finding.Named{
			Identifier: "CVE-2022-37434", Severity: "critical",
			Description: "A heap overflow in inflateGetHeader.", Score: 9.8,
		},
		Component: zlib, FixState: finding.FixedUpstream, FixedIn: "1.2.12",
	}})
}
