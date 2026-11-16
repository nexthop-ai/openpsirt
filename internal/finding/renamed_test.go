// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// kernelPackage is a Debian kernel package named after the kernel's version,
// as SONiC's inventory describes it.
func kernelPackage(prefix, version, suffix string) graph.Described {
	name := prefix + version + suffix
	return graph.Described{
		Purl: "pkg:deb/debian/" + strings.ReplaceAll(name, "+", "%2B") + "@" + version + "-1" +
			"?arch=amd64&distro=debian-13&upstream=linux",
		Name: name, Version: version + "-1",
	}
}

// kernelShipped is the product shipping the kernel image beneath its headers,
// both named after the kernel's version.
func kernelShipped(version string) (graph.Snapshot, graph.Described) {
	headers := kernelPackage("linux-headers-", version, "+deb13-sonic-amd64")
	image := kernelPackage("linux-image-", version, "+deb13-sonic-amd64-unsigned")
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{headers, image},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: headers},
			{Parent: headers, Child: image},
		},
	}, image
}

func TestAKernelRenamedByItsUpgradeContinuesItsFindingsAndDecisions(t *testing.T) {
	// The kernel moving from 6.12.41 to 6.12.94 renames the image and the
	// headers it sits beneath. The issue still open supersedes its finding at
	// the same occurrence, the dismissal made before carries to it, the issue
	// the upgrade fixed closes as upgraded, and the inventory's changes list
	// both packages as changed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		before, image := kernelShipped("6.12.41")
		f.shipped(t, before)
		if _, err := f.store.Apply(ctx, f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", image), found("CVE-2026-2", image)}); err != nil {
			t.Fatal(err)
		}
		open := map[int64]finding.Finding{}
		for _, row := range f.open(t) {
			open[row.VulnerabilityID] = row
		}
		stays, fixed := open[f.issueID(t, "CVE-2026-1")], open[f.issueID(t, "CVE-2026-2")]
		if stays.ID == 0 || fixed.ID == 0 {
			t.Fatalf("the first scan opened %v, want both issues on the kernel", open)
		}
		f.decision(t, decisionRow{
			By: f.somebodyElse(t), Decision: decisionSaying(t, f.db, f.somebodyElse(t), finding.OutcomeDismissed),
			Issue: stays.VulnerabilityID, Occurrence: stays.OccurrenceIdentity, State: "approved", Key: "dismissed",
		})
		if got := f.agreedHere(t); got.Agreed != 1 {
			t.Fatalf("before the upgrade: agreed %d, want 1", got.Agreed)
		}

		after, upgraded := kernelShipped("6.12.94")
		f.shipped(t, after)
		applied, err := f.store.Apply(ctx, f.build, f.run(t), []finding.Reported{found("CVE-2026-1", upgraded)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 1 || applied.Closed != 2 || applied.Unexplained != 0 {
			t.Errorf("the upgrade opened %d, closed %d, %d unexplained; want one superseded at the new version "+
				"and the fixed issue closed", applied.Opened, applied.Closed, applied.Unexplained)
		}
		for _, row := range f.every(t) {
			switch {
			case row.ID == stays.ID && row.ClosedBecause != finding.Superseded:
				t.Errorf("the issue still open at the old kernel closed as %v, want superseded", row.ClosedBecause)
			case row.ID == fixed.ID && row.ClosedBecause != finding.Upgraded:
				t.Errorf("the issue the upgrade fixed closed as %v, want upgraded", row.ClosedBecause)
			case row.ClosedAt == nil && row.OccurrenceIdentity != stays.OccurrenceIdentity:
				t.Errorf("the issue still open sits at another occurrence after the upgrade")
			case row.ClosedAt == nil && row.ArrivedFrom != "6.12.41-1":
				t.Errorf("the issue still open arrived from %q, want the kernel it moved from", row.ArrivedFrom)
			}
		}
		if got := f.agreedHere(t); got.Agreed != 1 || got.Undecided != 0 {
			t.Errorf("after the upgrade: agreed %d, undecided %d; want the dismissal answering the renamed kernel",
				got.Agreed, got.Undecided)
		}

		listed, _, err := graph.NewStore(f.db.DB).Changes(ctx, f.holding(t, access.PublicRead), f.build,
			f.lastScan, "", 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, change := range listed {
			got = append(got, string(change.Kind)+" "+change.Name)
		}
		want := []string{
			"changed linux-headers-6.12.94+deb13-sonic-amd64",
			"changed linux-image-6.12.94+deb13-sonic-amd64-unsigned",
		}
		if strings.Join(got, "; ") != strings.Join(want, "; ") {
			t.Errorf("the inventory's changes read %v, want %v", got, want)
		}
	})
}

func TestAnOccurrenceMarkedAffectedStaysOpenWhereTheNameHoldsItsVersion(t *testing.T) {
	// A supplier's statement is not applied where somebody decided the issue
	// applies, asked at the occurrence the finding is keyed on: the name
	// with its own version taken out. Without the decision the statement
	// closes the finding, so the decision is what keeps it open.
	for _, decided := range []bool{false, true} {
		t.Run(map[bool]string{false: "undecided", true: "decided affected"}[decided], func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				named := graph.Described{Purl: "pkg:deb/debian/zlib-1.2.11@1.2.11-1", Name: "zlib-1.2.11", Version: "1.2.11-1"}
				f.shipped(t, graph.Snapshot{
					Root:         root,
					Components:   []graph.Described{acmeY, named},
					Dependencies: []graph.Dependency{{Parent: root, Child: acmeY}, {Parent: acmeY, Child: named}},
				})
				f.reported(t, found(inside, named))
				here := placedAt(t, f, f.open(t))[named.Name+" under "+acmeY.Name]
				if here.ID == 0 {
					t.Fatal("nothing is open inside the product")
				}
				if decided {
					somebody := f.somebodyElse(t)
					f.decision(t, decisionRow{
						By: somebody, Decision: decisionSaying(t, f.db, somebody, finding.OutcomeAffected),
						Issue: here.VulnerabilityID, Occurrence: here.OccurrenceIdentity,
						State: "proposed", Unreviewed: true,
						Component: ptr(named.Version), Consumer: ptr(acmeY.Version), Key: "affected-here",
					})
				}
				claims, err := sbom.ReadSuppressions(strings.NewReader(`{
				"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://acme.example/vex/zlib",
				"author": "Acme Security", "timestamp": "2026-10-01T00:00:00Z", "version": 1,
				"statements": [{"vulnerability": {"name": "`+inside+`"},
					"products": [{"@id": "pkg:generic/acme-y@4.2",
						"subcomponents": [{"@id": "pkg:deb/debian/zlib-1.2.11@1.2.11-1"}]}],
					"status": "not_affected", "justification": "vulnerable_code_not_in_execute_path"}]}`),
					sbom.Limits{})
				if err != nil {
					t.Fatal(err)
				}
				var said []finding.Statement
				for _, claim := range claims {
					for _, target := range claim.Targets {
						said = append(said, finding.StatementOf(claim, target))
					}
				}
				f.publishes(t, said, "sha256:acme-zlib")
				applied, _ := f.reported(t, found(inside, named))
				if want := map[bool]int{false: 1, true: 0}[decided]; applied.Disclaimed != want {
					t.Errorf("decided %v: disclaimed %d, want %d", decided, applied.Disclaimed, want)
				}
			})
		})
	}
}

func TestAFlawRecordedOnAKernelIsKeyedWhereAScanOfItsNextVersionWouldKeyIt(t *testing.T) {
	// A flaw recorded by hand against the kernel and the same flaw scanned
	// after the kernel moves are one occurrence, keyed by names with the
	// kernel's version taken out, the consumer's included.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		before, image := kernelShipped("6.12.41")
		f.shipped(t, before)
		rows, _, err := f.store.Enter(ctx, f.planner(t, access.PublicTriage, access.PrivateTriage),
			finding.Entering{
				BuildIDs: []int64{f.build}, Component: image.Name, Severity: "high",
				Summary: "The driver reads past the end of a buffer.",
			})
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("recorded %d findings, want one", len(rows))
		}

		after, upgraded := kernelShipped("6.12.94")
		f.shipped(t, after)
		if _, err := f.store.Apply(ctx, f.build, f.run(t), []finding.Reported{found("CVE-2026-1", upgraded)}); err != nil {
			t.Fatal(err)
		}
		var scanned []string
		if err := f.db.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			ColumnExpr(`"f"."occurrence_identity"`).
			Where(`"f"."build_id" = ?`, f.build).
			Where(`"f"."kind" = ?`, finding.Vulnerable).
			Scan(ctx, &scanned); err != nil {
			t.Fatal(err)
		}
		if len(scanned) != 1 || scanned[0] != rows[0].OccurrenceIdentity {
			t.Errorf("the scan keys %v and the recorded flaw %s, want one occurrence",
				scanned, rows[0].OccurrenceIdentity)
		}
	})
}

func TestAFlawOnAKernelReachesABuildShippingItsNextVersion(t *testing.T) {
	// A build of another variant ships the kernel at the next version, named
	// after it. Research saying that build is affected opens the flaw there,
	// at the occurrence the first build's finding holds.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		before, image := kernelShipped("6.12.41")
		f.shipped(t, before)
		other := f.anotherVariant(t, "mellanox")
		after, _ := kernelShipped("6.12.94")
		f.shippedTo(t, other, after)
		who := f.planner(t, access.PublicTriage, access.PrivateTriage)
		rows, _, err := f.store.Enter(ctx, who, finding.Entering{
			BuildIDs: []int64{f.build}, Component: image.Name, Severity: "high",
			Summary: "The driver reads past the end of a buffer.",
		})
		if err != nil {
			t.Fatal(err)
		}
		changed, err := f.store.Affects(ctx, who, f.productID, rows[0].VulnerabilityID, []int64{f.build, other}, "")
		if err != nil {
			t.Fatalf("widening to the build shipping the next kernel: %v", err)
		}
		if changed.Added != 1 {
			t.Fatalf("widening added %d, want 1", changed.Added)
		}
		var there []string
		if err := f.db.DB.NewSelect().TableExpr(`"finding"`).ColumnExpr(`"occurrence_identity"`).
			Where(`"build_id" = ?`, other).Where(`"vulnerability_id" = ?`, rows[0].VulnerabilityID).
			Scan(ctx, &there); err != nil {
			t.Fatal(err)
		}
		if len(there) != 1 || there[0] != rows[0].OccurrenceIdentity {
			t.Errorf("the other build holds %v, want the occurrence %s", there, rows[0].OccurrenceIdentity)
		}
	})
}
