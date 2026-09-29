// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapitest

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// StateOf is how far one build has decided the finding the helpers seed.
func (r *Reach) StateOf(t *testing.T, variant string) string {
	t.Helper()
	var out struct {
		Items []struct {
			State string `json:"state"`
		} `json:"items"`
	}
	Read(t, r, "triager",
		"/v1/products/mine/findings?stream=master&variant="+variant, &out)
	if len(out.Items) != 1 {
		t.Fatalf("%s lists %d rows, want the one the fixture seeds", variant, len(out.Items))
	}
	return out.Items[0].State
}

// ScannedShared is a build where one library sits under two containers and
// carries two issues: the shape a tree count has to answer per path.
func (r *Reach) ScannedShared(t *testing.T) {
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
		TargetID: target.ID, ContentHash: "shared", BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	a := graph.Described{Purl: "pkg:oci/docker-a@1", Name: "docker-a", Version: "1"}
	b := graph.Described{Purl: "pkg:oci/docker-b@1", Name: "docker-b", Version: "1"}
	lib := graph.Described{Purl: "pkg:deb/debian/libyang@2.1", Name: "libyang", Version: "2.1"}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:       product,
		Components: []graph.Described{a, b, lib},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: a}, {Parent: product, Child: b},
			{Parent: a, Child: lib}, {Parent: b, Child: lib},
		},
	}); err != nil {
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
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{Issue: finding.Named{Identifier: "CVE-2026-1", Severity: "high"}, Component: lib, FixState: finding.NoFix},
		{Issue: finding.Named{Identifier: "CVE-2026-2", Severity: "low"}, Component: lib, FixState: finding.NoFix},
	}); err != nil {
		t.Fatal(err)
	}
}

// AlsoIn ships the same graph and the same findings in a second variant of the
// same product, so a product's own totals can be told from a sum over its
// builds.
func (r *Reach) AlsoIn(t *testing.T, variant string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	product, err := names.ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := names.DeclareVariant(ctx, product.ID, variant, true); err != nil {
		t.Fatal(err)
	}
	located, err := names.Locate(ctx, "mine", "master", variant)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "shared-" + variant,
		BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	root := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	lib := graph.Described{Purl: "pkg:deb/debian/libyang@2.1", Name: "libyang", Version: "2.1"}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:         root,
		Components:   []graph.Described{lib},
		Dependencies: []graph.Dependency{{Parent: root, Child: lib}},
	}); err != nil {
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
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{Issue: finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: lib, FixState: finding.NoFix},
		{Issue: finding.Named{Identifier: "CVE-2026-2", Severity: "low"},
			Component: lib, FixState: finding.NoFix},
	}); err != nil {
		t.Fatal(err)
	}
}

// AlsoHolds gives another product's build a finding for one issue by name.
//
// Beside AlsoScannedInto, which seeds its own issue. A vulnerability is one
// row however many products report it, so naming the identifier is what puts
// two products on the same row — which is the state a query joining an
// advisory to a release through the finding table has to tell apart.
func (r *Reach) AlsoHolds(t *testing.T, product, stream, variant, identifier string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(ctx, product, stream, variant)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
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
		Issue:     finding.Named{Identifier: identifier, Severity: "high"},
		Component: SeededLib,
		FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
	}}); err != nil {
		t.Fatal(err)
	}
}

// ScannedAlso is a second build of the same product, holding the same issue at
// the same place, with the library at the given version.
func (r *Reach) ScannedAlso(t *testing.T, variant, version string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	first, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	declared, err := names.DeclareVariant(ctx, first.ProductID, variant, true)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, first.StreamID, declared.ID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "also-" + variant, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	library := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@" + version, Name: "libnl-3-200", Version: version,
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:         product,
		Components:   []graph.Described{library},
		Dependencies: []graph.Dependency{{Parent: product, Child: library}},
	}); err != nil {
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
		Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
		Component: library,
		FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
	}}); err != nil {
		t.Fatal(err)
	}
}

// ShipsTwice re-applies the build's graph holding one name at two versions,
// which is the ordinary case rather than a contrived one: a real image ships
// three vendored copies of one library.
func (r *Reach) ShipsTwice(t *testing.T) {
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
		TargetID: target.ID, ContentHash: "two-versions", ParserVersion: "test",
		// Newer than the first, and not ahead of the clock: a build stamped in
		// the future is refused, because accepting one means no later scan is
		// ever newer.
		BuiltAt: time.Now().UTC(),
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	consumer := graph.Described{
		Purl: "pkg:deb/debian/libswsscommon@1.0.0", Name: "libswsscommon", Version: "1.0.0",
	}
	older := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
	}
	newer := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@3.9.0", Name: "libnl-3-200", Version: "3.9.0",
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root:       product,
		Components: []graph.Described{consumer, older, newer},
		Dependencies: []graph.Dependency{
			{Parent: product, Child: consumer},
			{Parent: consumer, Child: older},
			{Parent: consumer, Child: newer},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

// SeededTwin is SeededLib described again under a namespace of the producer's
// own: one name, one version, one ecosystem, and a second component.
var SeededTwin = graph.Described{
	Purl: "pkg:deb/sonic/libnl-3-200@3.7.0?arch=amd64", Name: "libnl-3-200", Version: "3.7.0",
}

// ShipsUnderTwoNamespaces is a build holding one package under two
// namespaces, with the issue open at the components named.
func (r *Reach) ShipsUnderTwoNamespaces(t *testing.T, carrying ...graph.Described) {
	t.Helper()
	reported := make([]finding.Reported, 0, len(carrying))
	for _, component := range carrying {
		reported = append(reported, finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
			Component: component,
		})
	}
	r.Scan(t, "two-namespaces", graph.Snapshot{
		Root:       SeededRoot,
		Components: []graph.Described{SeededConsumer, SeededLib, SeededTwin},
		Dependencies: []graph.Dependency{
			{Parent: SeededRoot, Child: SeededConsumer},
			{Parent: SeededConsumer, Child: SeededLib},
			{Parent: SeededConsumer, Child: SeededTwin},
		},
	}, reported)
}

// ScannedOneIssueAtTwoVersions files one issue on one component name at two
// versions, which is two folds and so two rows of the blocking list.
//
// The shape a build has when it ships a library twice: the same source package
// at two versions, both vulnerable to the same issue.
func (r *Reach) ScannedOneIssueAtTwoVersions(t *testing.T) {
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
		TargetID: target.ID, ContentHash: "one-issue-two-versions", BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	older := graph.Described{
		Purl: "pkg:golang/golang.org/x/crypto@0.14.0", Name: "golang.org/x/crypto",
		Version: "0.14.0", UpstreamName: "golang.org/x/crypto", UpstreamVersion: "0.14.0",
	}
	newer := graph.Described{
		Purl: "pkg:golang/golang.org/x/crypto@0.17.0", Name: "golang.org/x/crypto",
		Version: "0.17.0", UpstreamName: "golang.org/x/crypto", UpstreamVersion: "0.17.0",
	}
	shipped := []graph.Described{older, newer}
	edges := make([]graph.Dependency, 0, len(shipped))
	for _, one := range shipped {
		edges = append(edges, graph.Dependency{Parent: product, Child: one})
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root: product, Components: shipped, Dependencies: edges,
	}); err != nil {
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
	var reported []finding.Reported
	for _, at := range shipped {
		reported = append(reported, finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-46595", Severity: "critical"},
			Component: at, FixState: finding.FixedUpstream, FixedIn: "0.31.0",
		})
	}
	if _, err := findings.Apply(ctx, target.ID, run.ID, reported); err != nil {
		t.Fatal(err)
	}
}

// ScannedTag declares a tag of "mine" built as broadcom and scans it holding
// the seeded library at a version of its own, with the seeded issue against it.
func (r *Reach) ScannedTag(t *testing.T, tag, version string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	product, err := names.ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := names.DeclareStream(ctx, product.ID, tag, catalog.Tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	variant, err := names.VariantByName(ctx, product.ID, "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, stream.ID, variant.ID)
	if err != nil {
		t.Fatal(err)
	}
	made, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "tag-" + tag, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	lib := graph.Described{
		Purl: "pkg:deb/debian/libnl-3-200@" + version, Name: "libnl-3-200", Version: version,
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, made.ID, graph.Snapshot{
		Root: SeededRoot, Components: []graph.Described{lib},
		Dependencies: []graph.Dependency{{Parent: SeededRoot, Child: lib}},
	}); err != nil {
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
		Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
		Component: lib, FixState: finding.FixedUpstream, FixedIn: "3.9.0",
	}}); err != nil {
		t.Fatal(err)
	}
}

// AlsoScannedInto puts the same component and issue behind a second product,
// so that a place identity — which carries no product, deliberately — is the
// same key in both.
func (r *Reach) AlsoScannedInto(t *testing.T, product, stream, variant string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(ctx, product, stream, variant)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	made, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "elsewhere-" + product, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, made.ID, graph.Snapshot{
		Root:         SeededRoot,
		Components:   []graph.Described{SeededLib},
		Dependencies: []graph.Dependency{{Parent: SeededRoot, Child: SeededLib}},
	}); err != nil {
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
		Issue:     finding.Named{Identifier: "CVE-2026-9999", Severity: "high"},
		Component: SeededLib,
		FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
	}}); err != nil {
		t.Fatal(err)
	}
}

// AheadOfUs is a date still to come and inside the deadline anything in these
// fixtures already has, so a promise landing on it stands rather than waiting.
//
// A date typed in goes past, and a promise landing on a date already gone is
// refused — so every test about promising work would start failing on a day
// that has nothing to do with what it pins.
//
// Two days rather than one: read as a date, tomorrow is midnight tonight, and
// a run that starts before midnight and reaches these tests after it finds
// tomorrow already behind it. Two days rather than a month, because a promise
// past the deadline it covers is gated and these tests are about what a
// promise reaches — the shortest window in the fixture is three days.
var AheadOfUs = time.Now().UTC().AddDate(0, 0, 2).Format(time.DateOnly)

// ScannedSiblings puts two packages built from one source into a build, each
// carrying the same two issues, plus one issue nothing has released a fix for.
//
// The shape the fix bundle is about: curl, libcurl4t64 and libcurl3t64 are one
// source package bumping once, and keying on the component would make that
// three rows that all say the same thing.
func (r *Reach) ScannedSiblings(t *testing.T) {
	t.Helper()
	r.siblingsIn(t, "broadcom")
}

// SiblingsAlsoIn puts the same two packages, at the same versions, in a second
// variant of the same branch. A decision is keyed on the place and the two
// upstream versions and on no build at all, so this is the fixture in which
// one decision covers two findings — and the one in which proposing per
// finding writes the same key twice.
func (r *Reach) SiblingsAlsoIn(t *testing.T, variant string) {
	t.Helper()
	if _, err := catalog.NewStore(r.DB.DB).DeclareVariant(t.Context(),
		r.productID(t), variant, true); err != nil {
		t.Fatal(err)
	}
	r.siblingsIn(t, variant)
}

func (r *Reach) productID(t *testing.T) int64 {
	t.Helper()
	product, err := catalog.NewStore(r.DB.DB).ProductByName(t.Context(), "mine")
	if err != nil {
		t.Fatal(err)
	}
	return product.ID
}

// ScannedTwoSources puts two packages of two different source packages in the
// build, both carrying one issue.
//
// The fixture for anything about two answers to one issue: one judgment covers
// a whole fold, so two different answers within one fold is not a state
// anything can reach.
func (r *Reach) ScannedTwoSources(t *testing.T) {
	t.Helper()
	r.siblingsIn(t, "broadcom", graph.Described{
		Purl: "pkg:deb/debian/libexpat1@2.5.0-1", Name: "libexpat1", Version: "2.5.0-1",
		UpstreamName: "expat", UpstreamVersion: "2.5.0-1",
	})
}

func (r *Reach) siblingsIn(t *testing.T, variant string, also ...graph.Described) {
	t.Helper()
	ctx := t.Context()

	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(ctx, "mine", "master", variant)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "siblings-" + variant, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	// Two binary packages of one source, which is what the key collapses.
	four := graph.Described{
		Purl: "pkg:deb/debian/libcurl4t64@8.4.0-1", Name: "libcurl4t64", Version: "8.4.0-1",
		UpstreamName: "curl", UpstreamVersion: "8.4.0-1",
	}
	three := graph.Described{
		Purl: "pkg:deb/debian/libcurl3t64@8.4.0-1", Name: "libcurl3t64", Version: "8.4.0-1",
		UpstreamName: "curl", UpstreamVersion: "8.4.0-1",
	}
	shipped := append([]graph.Described{four, three}, also...)
	edges := make([]graph.Dependency, 0, len(shipped))
	for _, one := range shipped {
		edges = append(edges, graph.Dependency{Parent: product, Child: one})
	}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root: product, Components: shipped, Dependencies: edges,
	}); err != nil {
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
	var reported []finding.Reported
	for _, at := range shipped {
		reported = append(reported,
			finding.Reported{
				Issue: finding.Named{
					Identifier: "CVE-2026-CURL1", Severity: "critical", Exploited: true,
				},
				Component: at, FixState: finding.FixedUpstream, FixedIn: "8.5.0-1",
			},
			finding.Reported{
				Issue:     finding.Named{Identifier: "CVE-2026-CURL2", Severity: "low"},
				Component: at, FixState: finding.FixedUpstream, FixedIn: "8.5.0-1",
			},
		)
	}
	// And one nothing has released a fix for, which is in no bundle.
	reported = append(reported, finding.Reported{
		Issue:     finding.Named{Identifier: "CVE-2026-CURL3", Severity: "high"},
		Component: four, FixState: finding.NoFix,
	})
	if _, err := findings.Apply(ctx, target.ID, run.ID, reported); err != nil {
		t.Fatal(err)
	}
}
