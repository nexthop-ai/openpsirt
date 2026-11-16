// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"strings"
	"testing"
	"time"

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
	// applies, asked at the occurrence the finding is keyed on: the names
	// with their own versions taken out, the component's and the consumer's.
	// Without the decision the statement closes the finding, so the decision
	// is what keeps it open.
	for consumerName, consumer := range map[string]graph.Described{
		"under a product":          acmeY,
		"under the kernel headers": kernelPackage("linux-headers-", "6.12.41", "+deb13-sonic-amd64"),
	} {
		for _, decided := range []bool{false, true} {
			t.Run(consumerName+", "+map[bool]string{false: "undecided", true: "decided affected"}[decided], func(t *testing.T) {
				each(t, func(t *testing.T, f *fixture) {
					named := graph.Described{Purl: "pkg:deb/debian/zlib-1.2.11@1.2.11-1", Name: "zlib-1.2.11", Version: "1.2.11-1"}
					f.shipped(t, graph.Snapshot{
						Root:         root,
						Components:   []graph.Described{consumer, named},
						Dependencies: []graph.Dependency{{Parent: root, Child: consumer}, {Parent: consumer, Child: named}},
					})
					f.reported(t, found(inside, named))
					here := placedAt(t, f, f.open(t))[named.Name+" under "+consumer.Name]
					if here.ID == 0 {
						t.Fatal("nothing is open inside the product")
					}
					if decided {
						somebody := f.somebodyElse(t)
						f.decision(t, decisionRow{
							By: somebody, Decision: decisionSaying(t, f.db, somebody, finding.OutcomeAffected),
							Issue: here.VulnerabilityID, Occurrence: here.OccurrenceIdentity,
							State: "proposed", Unreviewed: true,
							Component: ptr(named.Version), Consumer: ptr(consumer.Version), Key: "affected-here",
						})
					}
					claims, err := sbom.ReadSuppressions(strings.NewReader(`{
					"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://acme.example/vex/zlib",
					"author": "Acme Security", "timestamp": "2026-10-01T00:00:00Z", "version": 1,
					"statements": [{"vulnerability": {"name": "`+inside+`"},
						"products": [{"@id": "`+consumer.Purl+`",
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

func TestAnIssueCarriedAcrossARenamingUpgradeIsNeitherFixedNorNew(t *testing.T) {
	// The kernel moves from 6.12.41 to 6.12.94, renamed by the move. The
	// issue it still carries is one issue at one package throughout: neither
	// the trend nor the burndown counts it new at the move, and the
	// ecosystem's row counts it open and not fixed. The issue the move fixed
	// is fixed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		before, image := kernelShipped("6.12.41")
		f.scannedAt(t, before, ago(10), found("CVE-2026-1", image), found("CVE-2026-2", image))
		after, upgraded := kernelShipped("6.12.94")
		f.scannedAt(t, after, ago(5), found("CVE-2026-1", upgraded))
		who := f.holding(t, access.PublicRead)

		points, err := f.store.Trend(ctx, who, f.scope, ago(12), 24*time.Hour, 13, finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		var fresh, corrected int
		for _, p := range points {
			fresh += p.New
			corrected += p.Corrected
		}
		if open := points[len(points)-1].Open; open != 1 || fresh != 0 || corrected != 1 {
			t.Errorf("the trend ends at %d open with %d new and %d corrected, want 1, 0 and 1", open, fresh, corrected)
		}

		b, err := f.store.Burndown(ctx, who, f.scope, time.Time{}, "", finding.Within{})
		if err != nil {
			t.Fatal(err)
		}
		if got := burnedOver(b); got.left != 1 || got.fresh != 0 || got.fixed != 1 {
			t.Errorf("the burndown leaves %d with %d new and %d fixed, want 1, 0 and 1", got.left, got.fresh, got.fixed)
		}

		// Closed as removed, as an upgrade under v0.12.0 closed it and the
		// upgrade to v0.13.0 leaves it: still open at the next version, so
		// not fixed.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"closed_because" = ?`, finding.Removed).
			Where(`"vulnerability_id" = ?`, f.issueID(t, "CVE-2026-1")).
			Where(`"closed_at" IS NOT NULL`).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		rows, err := f.store.Grouped(ctx, who, f.build, finding.ByEcosystem, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Key != "deb" || rows[0].Open != 1 || rows[0].Fixed != 1 {
			t.Errorf("the ecosystem rows read %+v, want deb with one open and one fixed", rows)
		}
	})
}

func TestComparingBuildsPairsAPackageRenamedByItsUpgrade(t *testing.T) {
	// A release ships the kernel at 6.12.41; the branch moved on through
	// 6.12.60 to 6.12.94, renamed at each move. The issue carried is still
	// present with the dismissal standing over it, and the one fixed on the
	// way is fixed by the upgrade that closed it, listed and counted.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		first, image := kernelShipped("6.12.41")
		f.shipped(t, first)
		if _, err := f.store.Apply(ctx, f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", image), found("CVE-2026-2", image)}); err != nil {
			t.Fatal(err)
		}
		carried := f.open(t)[0]
		for _, row := range f.open(t) {
			if row.VulnerabilityID == f.issueID(t, "CVE-2026-1") {
				carried = row
			}
		}
		f.decision(t, decisionRow{
			By: f.somebodyElse(t), Decision: decisionSaying(t, f.db, f.somebodyElse(t), finding.OutcomeDismissed),
			Issue: carried.VulnerabilityID, Occurrence: carried.OccurrenceIdentity, State: "approved", Key: "dismissed",
		})

		release := f.anotherBuild(t, "v1")
		f.shippedTo(t, release, first)
		if _, err := f.store.Apply(ctx, release, f.runOn(t, release),
			[]finding.Reported{found("CVE-2026-1", image), found("CVE-2026-2", image)}); err != nil {
			t.Fatal(err)
		}

		between, moved := kernelShipped("6.12.60")
		f.shipped(t, between)
		if _, err := f.store.Apply(ctx, f.build, f.run(t),
			[]finding.Reported{found("CVE-2026-1", moved), found("CVE-2026-2", moved)}); err != nil {
			t.Fatal(err)
		}
		last, upgraded := kernelShipped("6.12.94")
		f.shipped(t, last)
		if _, err := f.store.Apply(ctx, f.build, f.run(t), []finding.Reported{found("CVE-2026-1", upgraded)}); err != nil {
			t.Fatal(err)
		}

		comparison, err := f.store.Compare(ctx, f.holding(t, access.PublicRead), release, f.build, false)
		if err != nil {
			t.Fatal(err)
		}
		still := entries(comparison.Still)["CVE-2026-1"]
		if len(comparison.Still) != 1 || still.Outcome != finding.OutcomeDismissed || len(comparison.Newly) != 0 {
			t.Errorf("still %+v, newly %+v; want the carried issue still present and dismissed, nothing new",
				comparison.Still, comparison.Newly)
		}
		if fixed := entries(comparison.Fixed)["CVE-2026-2"]; len(comparison.Fixed) != 1 || fixed.Because != finding.Upgraded {
			t.Errorf("fixed %+v, closed %+v; want the issue the move fixed upgraded away",
				comparison.Fixed, comparison.Closed)
		}

		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set(`"visibility" = ?`, access.Private).
			Where(`"vulnerability_id" = ?`, f.issueID(t, "CVE-2026-2")).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		omitted, err := f.store.OmittedFixes(ctx, f.holding(t, access.PublicRead, access.PrivateRead), release, f.build)
		if err != nil {
			t.Fatal(err)
		}
		if omitted != 1 {
			t.Errorf("the comparison leaves out %d undisclosed fixes, want the one the move fixed", omitted)
		}
	})
}

func TestAFlawOnAKernelIsWidenedOnlyWhereOneComponentInItsEcosystemContinuesIt(t *testing.T) {
	// The flaw is recorded on the kernel at 6.12.41. A build shipping the
	// kernel at two later versions holds two components it could be, and is
	// refused. One shipping it at a later version beside the kernel's name at
	// another version under another ecosystem holds one: an identifying name
	// is matched within its ecosystem.
	image94 := kernelPackage("linux-image-", "6.12.94", "+deb13-sonic-amd64-unsigned")
	image100 := kernelPackage("linux-image-", "6.12.100", "+deb13-sonic-amd64-unsigned")
	generic := graph.Described{Name: image100.Name, Version: image100.Version,
		Purl: "pkg:generic/" + strings.ReplaceAll(image100.Name, "+", "%2B") + "@" + image100.Version}
	for _, c := range []struct {
		what    string
		ships   []graph.Described
		refused error
	}{
		{"two later versions", []graph.Described{image94, image100}, finding.ErrSeveralLikeIt},
		{"a later version and another ecosystem's", []graph.Described{image94, generic}, nil},
	} {
		t.Run(c.what, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				ctx := t.Context()
				before, image := kernelShipped("6.12.41")
				f.shipped(t, before)
				other := f.anotherVariant(t, "mellanox")
				snap := graph.Snapshot{Root: root, Components: c.ships}
				for _, one := range c.ships {
					snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: root, Child: one})
				}
				f.shippedTo(t, other, snap)
				who := f.planner(t, access.PublicTriage, access.PrivateTriage)
				rows, _, err := f.store.Enter(ctx, who, finding.Entering{
					BuildIDs: []int64{f.build}, Component: image.Name, Severity: "high",
					Summary: "The driver reads past the end of a buffer.",
				})
				if err != nil {
					t.Fatal(err)
				}
				changed, err := f.store.Affects(ctx, who, f.productID, rows[0].VulnerabilityID, []int64{f.build, other}, "")
				switch {
				case c.refused != nil && !errors.Is(err, c.refused):
					t.Errorf("widening to a build shipping %s: %v, want %v", c.what, err, c.refused)
				case c.refused == nil && (err != nil || changed.Added != 1):
					t.Errorf("widening to a build shipping %s: %+v, %v; want the flaw added there", c.what, changed, err)
				}
			})
		})
	}
}
