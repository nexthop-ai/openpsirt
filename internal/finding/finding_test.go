package finding_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// fixture is one migrated database with a variant, a stored graph, and a way
// to mint scan runs in order.
type fixture struct {
	db        *database.DB
	store     *finding.Store
	graph     *graph.Store
	target    int64
	productID int64
	// scope is the fixture's own build as a selection, which is what the
	// lists take: one build is a selection with all three levels named.
	scope    finding.Scope
	lastScan int64
	scans    *ingest.Store
	built    time.Time
	seq      int
}

func at(name, version string) graph.Described {
	return graph.Described{
		Purl: "pkg:deb/debian/" + name + "@" + version, Name: name, Version: version,
	}
}

var (
	root     = at("sonic", "1.0")
	swss     = at("libswsscommon", "1.0.0")
	teamd    = at("teamd", "1.31")
	libnl    = at("libnl-3-200", "3.7.0")
	libnlNew = at("libnl-3-200", "3.9.0")
)

// shipped stores a graph: libnl sits under two consumers, which is the case
// the whole place definition exists for.
func (f *fixture) shipped(t *testing.T, snap graph.Snapshot) {
	t.Helper()
	f.seq++
	f.built = f.built.Add(time.Hour)
	scan, outcome, err := f.scans.Record(t.Context(), ingest.Arriving{
		TargetID: f.target, ContentHash: fmt.Sprintf("hash-%d", f.seq), BuiltAt: f.built,
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := f.graph.Apply(t.Context(), f.target, scan.ID, snap); err != nil {
		t.Fatalf("apply graph: %v", err)
	}
	f.lastScan = scan.ID
}

// anotherBuild declares a second release of the same product, as a tag, and
// returns its target.
//
// Anything reporting *per build* has to be tested against more than one, or
// the grouping is enforced by there being nothing to group.
func (f *fixture) anotherBuild(t *testing.T, stream string) int64 {
	t.Helper()
	return f.buildOfKind(t, stream, catalog.Tag)
}

// anotherBranch is the same for a release that moves, which is what a test
// about deadlines needs: a tag was built once and carries none.
func (f *fixture) anotherBranch(t *testing.T, stream string) int64 {
	t.Helper()
	return f.buildOfKind(t, stream, catalog.Branch)
}

func (f *fixture) buildOfKind(t *testing.T, stream string, kind catalog.Kind) int64 {
	t.Helper()
	cat := catalog.NewStore(f.db.DB)
	declared, err := cat.DeclareStream(t.Context(), f.productID, stream, kind, nil)
	if err != nil {
		t.Fatalf("declare %s: %v", stream, err)
	}
	variant, err := cat.VariantByName(t.Context(), f.productID, "broadcom")
	if err != nil {
		t.Fatalf("variant: %v", err)
	}
	target, err := cat.TargetFor(t.Context(), declared.ID, variant.ID)
	if err != nil {
		t.Fatalf("target for %s: %v", stream, err)
	}
	return target.ID
}

// shippedTo stores a graph against a build other than the fixture's own.
func (f *fixture) shippedTo(t *testing.T, target int64, snap graph.Snapshot) {
	t.Helper()
	f.seq++
	f.built = f.built.Add(time.Hour)
	scan, outcome, err := f.scans.Record(t.Context(), ingest.Arriving{
		TargetID: target, ContentHash: fmt.Sprintf("hash-%d", f.seq), BuiltAt: f.built,
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := f.graph.Apply(t.Context(), target, scan.ID, snap); err != nil {
		t.Fatalf("apply graph: %v", err)
	}
}

// runOn starts a scan run against a build other than the fixture's own.
func (f *fixture) runOn(t *testing.T, target int64) int64 {
	t.Helper()
	r, err := f.store.Begin(t.Context(), finding.Run{
		TargetID: target, Scanner: "grype", ScannerVersion: "0.100.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

// twoConsumers is the graph most of these tests use.
func twoConsumers() graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{swss, teamd, libnl},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: swss},
			{Parent: root, Child: teamd},
			{Parent: swss, Child: libnl},
			{Parent: teamd, Child: libnl},
		},
	}
}

// run starts a scan run and returns its identifier.
func (f *fixture) run(t *testing.T) int64 {
	t.Helper()
	r, err := f.store.Begin(t.Context(), finding.Run{
		TargetID: f.target, Scanner: "grype", ScannerVersion: "0.100.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

// found is one reported issue against a component.
func found(id string, component graph.Described, aliases ...string) finding.Reported {
	return finding.Reported{
		Issue:     finding.Named{Identifier: id, Aliases: aliases, Severity: "high"},
		Component: component,
		FixState:  finding.FixedUpstream, FixedIn: "3.9.0",
	}
}

// openClaims is what the build currently argues about what it ships, read
// straight from the table. It was a store method once, exported and reached by
// nothing but these two tests — which is the shape AGENTS.md calls a defect
// rather than spare capacity, and a test reading the row it is asserting about
// is the honest way to assert it.
func (f *fixture) openClaims(t *testing.T) []finding.Claim {
	t.Helper()
	var rows []finding.Claim
	if err := f.db.DB.NewSelect().Model(&rows).
		Where("target_id = ?", f.target).Where("closed_scan_id IS NULL").
		Order("id").Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

func (f *fixture) open(t *testing.T) []finding.Finding {
	t.Helper()
	var rows []finding.Finding
	err := f.db.DB.NewSelect().Model(&rows).
		Where("target_id = ?", f.target).Where("closed_at IS NULL").Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := schema.Up(ctx, db, quiet); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}

		fn(t, &fixture{
			db: db, store: finding.NewStore(db.DB), graph: graph.NewStore(db.DB),
			target: target.ID, productID: product.ID, scans: ingest.NewStore(db.DB),
			scope: finding.Scope{
				ProductID: &product.ID, StreamID: &stream.ID, VariantID: &variant.ID,
			},
			built: time.Now().UTC().Add(-72 * time.Hour),
		})
	})
}

func TestOneReportedIssueBecomesOneFindingPerConsumer(t *testing.T) {
	// The whole point of the fan-out. A scanner says "libnl-3-200 3.7.0 is
	// affected" and stops, because it never saw the graph. Two things pull it
	// in, so there are two decisions to make about it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 2 {
			t.Fatalf("opened %d findings, want one per consumer", applied.Opened)
		}

		consumers := map[int64]bool{}
		for _, row := range f.open(t) {
			if row.ConsumerID == nil {
				t.Error("a finding under a consumer recorded none")
				continue
			}
			consumers[*row.ConsumerID] = true
		}
		if len(consumers) != 2 {
			t.Errorf("findings sit under %d distinct consumers, want 2", len(consumers))
		}
	})
}

func TestTheSamePlaceInTwoVariantsKeysTheSame(t *testing.T) {
	// A decision is carried forward by the place, so the key must not contain
	// anything that differs between variants or moves on a rebuild.
	first := finding.PlaceIdentity("libnl-3-200", "libswsscommon")
	again := finding.PlaceIdentity("libnl-3-200", "libswsscommon")
	if first != again {
		t.Error("the same place keyed differently")
	}
	if finding.PlaceIdentity("libnl-3-200", "teamd") == first {
		t.Error("two consumers of one component share a key")
	}
	// Under the product itself, the component stands alone: the product's name
	// differs per variant, so including it would stop the same place being
	// recognized across them.
	if finding.PlaceIdentity("libnl-3-200", "") == first {
		t.Error("a component under the product keys the same as one under a consumer")
	}
}

func TestRescanningWithNothingChangedWritesNothing(t *testing.T) {
	// Re-scanning runs nightly against a database that has barely moved. If an
	// unchanged run wrote rows, storage would track the calendar rather than
	// what is actually happening.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		reported := []finding.Reported{found("CVE-2026-1", libnl)}

		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), reported); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), reported)
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("an unchanged re-scan wrote %+v", applied)
		}
	})
}

func TestAnUpgradeClosesWithTheReason(t *testing.T) {
	// "Fixed by upgrading" and "we cannot account for this" are different
	// things to whoever reads the report later.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		// The next build ships a newer libnl, and the scanner no longer
		// reports it.
		upgraded := twoConsumers()
		upgraded.Components = []graph.Described{swss, teamd, libnlNew}
		upgraded.Dependencies = []graph.Dependency{
			{Parent: root, Child: swss}, {Parent: root, Child: teamd},
			{Parent: swss, Child: libnlNew}, {Parent: teamd, Child: libnlNew},
		}
		f.shipped(t, upgraded)

		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Closed != 2 {
			t.Fatalf("closed %d findings, want 2", applied.Closed)
		}
		if applied.Unexplained != 0 {
			t.Errorf("%d closures went unexplained", applied.Unexplained)
		}

		var closed []finding.Finding
		if err := f.db.DB.NewSelect().Model(&closed).
			Where("closed_at IS NOT NULL").Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, row := range closed {
			if row.ClosedBecause != finding.Upgraded {
				t.Errorf("closed because %q, want %q", row.ClosedBecause, finding.Upgraded)
			}
		}
	})
}

func TestAComponentGoneAltogetherClosesAsRemoved(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		f.shipped(t, graph.Snapshot{
			Root: root, Components: []graph.Described{swss, teamd},
			Dependencies: []graph.Dependency{{Parent: root, Child: swss}, {Parent: root, Child: teamd}},
		})
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), nil); err != nil {
			t.Fatal(err)
		}

		var closed []finding.Finding
		if err := f.db.DB.NewSelect().Model(&closed).
			Where("closed_at IS NOT NULL").Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(closed) != 2 {
			t.Fatalf("closed %d findings, want 2", len(closed))
		}
		for _, row := range closed {
			if row.ClosedBecause != finding.Removed {
				t.Errorf("closed because %q, want %q", row.ClosedBecause, finding.Removed)
			}
		}
	})
}

func TestADisappearanceNothingExplainsIsFlagged(t *testing.T) {
	// The component is present, unchanged, and the scanner stopped reporting
	// it. There is no volume at which "we cannot account for this" stops
	// mattering, so it is never quietly folded into the others.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), nil)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Unexplained != 2 {
			t.Errorf("%d closures were flagged as unexplained, want 2", applied.Unexplained)
		}
	})
}

func TestOneIssueUnderTwoNamesIsOneIssue(t *testing.T) {
	// Which identifier a scanner calls primary is a preference of whichever
	// database it consulted. A decision keyed on that choice would lapse the
	// day the scanner changed its mind.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		// First run: reported under an advisory identifier that knows the
		// national one as an alias.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("GHSA-aaaa-bbbb-cccc", libnl, "CVE-2026-1")}); err != nil {
			t.Fatal(err)
		}
		opened := f.open(t)
		if len(opened) != 2 {
			t.Fatalf("opened %d findings", len(opened))
		}

		// Second run: the same issue, reported the other way round.
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("the same issue under another name wrote %+v", applied)
		}

		var issues int
		if issues, err = f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).Count(t.Context()); err != nil {
			t.Fatal(err)
		}
		if issues != 1 {
			t.Errorf("%d vulnerabilities recorded, want 1", issues)
		}
	})
}

func TestAnAliasSuppliedLaterFindsTheIssueAlreadyHeld(t *testing.T) {
	// The order that matters. One scanner reports the national identifier and
	// nothing else; another later reports its own identifier and knows the
	// first as an alias. Only looking up the name a report happened to lead
	// with would make those two issues, splitting the findings and every
	// decision between them.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("GHSA-aaaa-bbbb-cccc", libnl, "CVE-2026-1")})
		if err != nil {
			t.Fatalf("an issue reported under a second name: %v", err)
		}
		if !applied.Unchanged() {
			t.Errorf("the same issue under a second name wrote %+v", applied)
		}

		issues, err := f.db.DB.NewSelect().Model((*finding.Vulnerability)(nil)).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if issues != 1 {
			t.Errorf("%d vulnerabilities recorded, want 1", issues)
		}
	})
}

func TestAnIssueIsFiledUnderItsMostRecognizedName(t *testing.T) {
	// What somebody sees should be the name they will find in an advisory,
	// not whichever database the scanner happened to consult first.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("GHSA-aaaa-bbbb-cccc", libnl, "CVE-2026-1")}); err != nil {
			t.Fatal(err)
		}
		var held finding.Vulnerability
		if err := f.db.DB.NewSelect().Model(&held).Limit(1).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if held.Identifier != "CVE-2026-1" {
			t.Errorf("filed under %q, want the national identifier", held.Identifier)
		}
	})
}

func TestAnIssueAgainstSomethingWeDoNotHaveIsReported(t *testing.T) {
	// A report that does not match the inventory it was produced from is
	// worth seeing, not quietly discarding.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-9", at("openssl", "3.0.11"))})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Unplaced != 1 || applied.Opened != 0 {
			t.Errorf("applied %+v, want one unplaced and nothing opened", applied)
		}
	})
}

func TestAComponentUnderTheProductSitsUnderNothing(t *testing.T) {
	// The product's name differs per variant, so a place under it keys on the
	// component alone — otherwise the same place in two variants would be two
	// places and a decision would not carry.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-2", swss)}); err != nil {
			t.Fatal(err)
		}
		rows := f.open(t)
		if len(rows) != 1 {
			t.Fatalf("opened %d findings, want 1", len(rows))
		}
		if rows[0].ConsumerID != nil {
			t.Error("a component under the product recorded a consumer")
		}
		if rows[0].PlaceIdentity != finding.PlaceIdentity("libswsscommon", "") {
			t.Error("a component under the product keyed on something else")
		}
	})
}

// aClaim is what a build argues about one of its components.
func aClaim(vulnerability string, status sbom.Status, subject graph.Described, origin sbom.Origin) sbom.Suppression {
	return sbom.Suppression{
		Vulnerability: vulnerability, Status: status,
		Justification: "vulnerable_code_not_in_execute_path",
		Statement:     "resolved by a patch the build carries",
		Targets:       []sbom.Target{{Purl: subject.Purl, Name: subject.Name}},
		Origin:        origin,
	}
}

func TestAFindingTheBuildHasAnsweredIsMarkedNotDropped(t *testing.T) {
	// The whole reason the claims are applied here rather than upstream. A
	// finding a build has argued about stays visible and says what was
	// argued; one that simply never arrived is indistinguishable from a
	// scanner that failed, and lands in the bucket nothing may explain away.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		scanID := f.lastScan
		if _, err := f.store.RecordClaims(t.Context(), f.target, scanID,
			[]sbom.Suppression{aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree)}); err != nil {
			t.Fatal(err)
		}

		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Opened != 2 {
			t.Fatalf("opened %d findings, want one per consumer even though the build answered them", applied.Opened)
		}
		if applied.Suppressed != 2 {
			t.Errorf("%d findings carry what the build argued, want 2", applied.Suppressed)
		}
		for _, row := range f.open(t) {
			if row.SuppressedBy == nil {
				t.Error("a finding the build answered does not say so")
			}
		}
	})
}

func TestAClaimAboutSomethingElseLeavesAFindingAlone(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{
				// Right component, different issue.
				aClaim("CVE-2026-9", sbom.NotAffected, libnl, sbom.FromStatement),
				// Right issue, different component.
				aClaim("CVE-2026-1", sbom.NotAffected, swss, sbom.FromStatement),
			}); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Suppressed != 0 {
			t.Errorf("%d findings were marked by a claim about something else", applied.Suppressed)
		}
	})
}

func TestSayingItIsAffectedSuppressesNothing(t *testing.T) {
	// A build saying it is affected, or that it has not decided, is telling us
	// it looked. That is information, not an answer.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{aClaim("CVE-2026-1", sbom.Affected, libnl, sbom.FromStatement)}); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Suppressed != 0 {
			t.Errorf("a build saying it is affected suppressed %d findings", applied.Suppressed)
		}
	})
}

func TestArguingTheSameThingAgainWritesNothing(t *testing.T) {
	// A build argues the same things night after night.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		claims := []sbom.Suppression{aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree)}

		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, claims); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, twoConsumers())
		applied, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, claims)
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("re-arguing the same claims wrote %+v", applied)
		}

		// Withdrawing one closes it rather than deleting it: what a release
		// argued is a question asked years later.
		applied, err = f.store.RecordClaims(t.Context(), f.target, f.lastScan, nil)
		if err != nil {
			t.Fatal(err)
		}
		if applied.Closed != 1 {
			t.Errorf("withdrawing a claim closed %d", applied.Closed)
		}
		if open := f.openClaims(t); len(open) != 0 {
			t.Errorf("%d claims still open", len(open))
		}
	})
}

func TestAClaimAttachedToItsComponentWinsOverOneThatNamedIt(t *testing.T) {
	// A claim that arrived on the component knows exactly what it is about. A
	// claim in a document may name a whole source tree and match by name, so
	// where both cover a finding the precise one is the one recorded.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		// Recorded in two steps so the vaguer claim is the older one. If
		// preferring the precise one were removed, the older would win, and a
		// test that relied on insertion order within a single call would pass
		// or fail depending on what a map felt like doing.
		vague := aClaim("CVE-2026-1", sbom.NotAffected, libnl, sbom.FromStatement)
		precise := aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree)
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{vague}); err != nil {
			t.Fatal(err)
		}
		f.shipped(t, twoConsumers())
		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{vague, precise}); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		open := f.openClaims(t)
		attached := map[int64]bool{}
		for _, claim := range open {
			if claim.Origin == string(sbom.FromPedigree) {
				attached[claim.ID] = true
			}
		}
		for _, row := range f.open(t) {
			if row.SuppressedBy == nil || !attached[*row.SuppressedBy] {
				t.Error("a finding recorded the vaguer of two claims that covered it")
			}
		}
	})
}

func TestAFindingThatMovesIsUpdated(t *testing.T) {
	// Somebody waiting on a fix is waiting for exactly this. A finding opened
	// when no fix existed would otherwise report that indefinitely, however
	// many times it was re-scanned.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		noFix := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{noFix}); err != nil {
			t.Fatal(err)
		}
		opened := f.open(t)
		if len(opened) != 2 {
			t.Fatalf("opened %d findings", len(opened))
		}
		was := opened[0].LastChangedAt

		// The next run knows a fix exists.
		fixed := noFix
		fixed.FixState = finding.FixedUpstream
		fixed.FixedIn = "3.9.0"
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{fixed})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Updated != 2 {
			t.Errorf("%d findings moved, want 2", applied.Updated)
		}
		if applied.Opened != 0 || applied.Closed != 0 {
			t.Errorf("a fix appearing opened %d and closed %d findings", applied.Opened, applied.Closed)
		}
		if applied.Unchanged() {
			t.Error("a fix appearing reported as no change at all")
		}

		for _, row := range f.open(t) {
			if row.FixState != finding.FixedUpstream || row.FixedIn != "3.9.0" {
				t.Errorf("still reports %q / %q", row.FixState, row.FixedIn)
			}
			if !row.LastChangedAt.After(was) {
				t.Error("nothing recorded that it moved")
			}
		}

		// And a run that finds the same thing again still writes nothing.
		applied, err = f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{fixed})
		if err != nil {
			t.Fatal(err)
		}
		if !applied.Unchanged() {
			t.Errorf("an unchanged re-scan wrote %+v", applied)
		}

	})
}

func TestUpstreamDecliningToFixIsAMovement(t *testing.T) {
	// The only thing that changes is the state — there is no version to point
	// at either before or after. It is a permanent condition that changes the
	// outcome somebody should reach, so it must not be the one kind of
	// movement that slips past because nothing else moved with it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		noFix := finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{noFix}); err != nil {
			t.Fatal(err)
		}

		declined := noFix
		declined.FixState = finding.WontFix
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{declined})
		if err != nil {
			t.Fatal(err)
		}
		if applied.Updated != 2 {
			t.Errorf("upstream declining to fix moved %d findings, want 2", applied.Updated)
		}
		for _, row := range f.open(t) {
			if row.FixState != finding.WontFix {
				t.Errorf("still reports %q", row.FixState)
			}
		}
	})
}

func TestEveryStatusTheFormatDefinesCanBeStored(t *testing.T) {
	// The vocabulary belongs to the exchange format rather than to us, and its
	// longest word is longer than a short identifier column allows. A claim
	// that cannot be stored fails the whole scan that carried it.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		var claims []sbom.Suppression
		for _, status := range []sbom.Status{
			sbom.NotAffected, sbom.Affected, sbom.AlreadyFixed, sbom.UnderInvestigation,
		} {
			claim := aClaim("CVE-2026-1", status, libnl, sbom.FromStatement)
			claim.Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
			claims = append(claims, claim)
		}
		applied, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan, claims)
		if err != nil {
			t.Fatalf("recording every status the format defines: %v", err)
		}
		if applied.Opened != 4 {
			t.Errorf("stored %d claims, want one per status", applied.Opened)
		}
	})
}

func TestAClaimThatReachedNothingIsCounted(t *testing.T) {
	// The ordinary case, not the exceptional one: a producer's
	// automatically-extracted claims name source trees rather than packages,
	// so they land on nothing. A finding the build believes it answered then
	// comes back as noise, and nothing distinguishes that from a finding
	// nobody has looked at.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		reaches := aClaim("CVE-2026-1", sbom.AlreadyFixed, libnl, sbom.FromPedigree)
		misses := aClaim("CVE-2026-2", sbom.NotAffected,
			graph.Described{Purl: "pkg:generic/libnl3", Name: "libnl3"}, sbom.FromStatement)

		if _, err := f.store.RecordClaims(t.Context(), f.target, f.lastScan,
			[]sbom.Suppression{reaches, misses}); err != nil {
			t.Fatal(err)
		}
		applied, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)})
		if err != nil {
			t.Fatal(err)
		}
		if applied.ClaimsReaching != 1 {
			t.Errorf("%d claims reached something, want 1", applied.ClaimsReaching)
		}
		if applied.ClaimsReachingNothing != 1 {
			t.Errorf("%d claims reached nothing, want 1", applied.ClaimsReachingNothing)
		}
	})
}

func TestAnAbsurdlyLongValueDoesNotFailTheScanThatCarriedIt(t *testing.T) {
	// Everything here comes from somebody else's output. A value longer than a
	// column would fail the whole run, and a run that failed is
	// indistinguishable from a product that stopped having problems.
	each(t, func(t *testing.T, f *fixture) {
		long := strings.Repeat("x", 5000)
		f.shipped(t, graph.Snapshot{
			Root: root,
			Components: []graph.Described{{
				Purl: "pkg:deb/debian/sprawling@1.0", Name: "sprawling", Version: long,
				UpstreamName: long, UpstreamVersion: long,
			}},
			Dependencies: []graph.Dependency{{Parent: root, Child: graph.Described{
				Purl: "pkg:deb/debian/sprawling@1.0", Name: "sprawling", Version: long,
				UpstreamName: long, UpstreamVersion: long,
			}}},
		})

		applied, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{{
			Issue: finding.Named{Identifier: "CVE-2026-1" + long, Severity: "high"},
			Component: graph.Described{
				Purl: "pkg:deb/debian/sprawling@1.0", Name: "sprawling", Version: long,
				UpstreamName: long, UpstreamVersion: long,
			},
			FixState: finding.FixedUpstream, FixedIn: long,
		}})
		if err != nil {
			t.Fatalf("a long value failed the scan carrying it: %v", err)
		}
		if applied.Opened != 1 {
			t.Errorf("opened %d findings", applied.Opened)
		}
	})
}

// interned records one vulnerability by name and returns its identifier, for
// the findings a test writes directly rather than through a scan. Unlike
// issue, which looks up what a scan already stored, this puts it there.
func (f *fixture) interned(t *testing.T, name string) int64 {
	t.Helper()
	ids, err := finding.NewVulnerabilities(f.db.DB).Intern(t.Context(),
		[]finding.Named{{Identifier: name, Severity: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	return ids[name]
}

// someoneElse is a second real person holding a role here, for the checks that
// need two — agreeing to somebody else's request, most of all.
func (f *fixture) someoneElse(t *testing.T, roles ...access.Role) access.Subject {
	t.Helper()
	person, err := access.NewStore(f.db.DB).Ensure(t.Context(), "other@example.com", "Other", false)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPerson(person.ID, "other@example.com", false,
		map[int64][]access.Role{f.productID: roles}, 0)
}

// holding returns a subject holding one role on the product this fixture's
// target belongs to.
func (f *fixture) holding(t *testing.T, roles ...access.Role) access.Subject {
	t.Helper()
	grants := map[int64][]access.Role{f.productID: roles}
	// The party they are assignable as, deliberately not their person
	// identifier: the two are different numbers in a real deployment as soon
	// as a team exists, and anything still comparing the wrong one has to
	// fail here rather than pass by coincidence.
	return access.NewPerson(1, "someone", false, grants, 101)
}

func TestOnlyWhatSomebodyMayReadIsRead(t *testing.T) {
	// What visibility on the query is actually about. The enforcement is
	// on the query, so this tests the query rather than a handler that
	// remembered to ask.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// One of the two is not disclosed. Read first and then updated,
		// because one engine refuses to name the table being updated inside a
		// subquery of its own statement.
		var hidden int64
		if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
			ColumnExpr("MIN(id)").Scan(t.Context(), &hidden); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("visibility = ?", access.Private).
			Where("id = ?", hidden).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		for _, c := range []struct {
			what   string
			who    access.Subject
			want   int
			denied bool
		}{
			{"public reader", f.holding(t, access.PublicRead), 1, false},
			{"public triager", f.holding(t, access.PublicTriage), 1, false},
			{"private reader", f.holding(t, access.PrivateRead), 2, false},
			{"private triager", f.holding(t, access.PrivateTriage), 2, false},
			{"an approver alone", f.holding(t), 0, true},
			// An administrator holds no role here, so they read
			// nothing here . Administering the catalog is not
			// reading what is open against it, and this is the row
			// that used to say otherwise.
			{"an administrator granted nothing", access.NewPerson(1, "admin", true, nil, 0), 0, true},
			{"an administrator granted private reading", f.admin(t, access.PrivateRead), 2, false},
			{"a pipeline", access.NewPipeline(1, "nightly", access.Scope{ProductID: f.productID}), 0, true},
		} {
			rows, err := f.store.Open(t.Context(), c.who, f.target)
			switch {
			case c.denied && !errors.Is(err, access.ErrDenied):
				t.Errorf("%s was not refused: %d rows, %v", c.what, len(rows), err)
			case c.denied:
				continue
			case err != nil:
				t.Errorf("%s: %v", c.what, err)
			case len(rows) != c.want:
				t.Errorf("%s read %d findings, want %d", c.what, len(rows), c.want)
			}
		}
	})
}

func TestFindingsInAProductSomebodyHoldsNothingOnAreRefused(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		// Holding everything, but on a different product.
		elsewhere := access.NewPerson(1, "elsewhere", false,
			map[int64][]access.Role{f.productID + 999: {access.PrivateRead}}, 0)

		if _, err := f.store.Open(t.Context(), elsewhere, f.target); !errors.Is(err, access.ErrDenied) {
			t.Errorf("reading another product's findings: %v", err)
		}
	})
}

func TestTwoRunsAgainstOneTargetDoNotBothOpenTheSameFinding(t *testing.T) {
	// The queue hands different jobs to different workers by design, so two
	// runs against one target overlapping is ordinary rather than exotic.
	// Without a hold on the target, both read the same open findings, both
	// compute the same difference, and both write it — leaving two open rows
	// for one finding, which everything downstream reads as two problems and
	// which two separate triage decisions can then be made about.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		first, second := f.run(t), f.run(t)
		reported := []finding.Reported{found("CVE-2026-1", libnl)}

		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, runID := range []int64{first, second} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = f.store.Apply(context.WithoutCancel(t.Context()), f.target, runID, reported)
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}

		// Two consumers pull the component in, so two findings — not four, and
		// not two of one and two of the other.
		open := f.open(t)
		if len(open) != 2 {
			t.Fatalf("%d findings are open after two overlapping runs, want 2", len(open))
		}
		seen := map[string]bool{}
		for _, row := range open {
			if seen[row.PlaceIdentity] {
				t.Errorf("two open findings for one place: %s", row.PlaceIdentity)
			}
			seen[row.PlaceIdentity] = true
		}
	})
}

func TestWhatIsStoredAboutAnIssueDoesNotDependOnWhichScanRanLast(t *testing.T) {
	// Reports disagree and arrive in an order nobody controls. Overwriting
	// makes what is stored a fact about scheduling; filling only the gap makes
	// it a fact about which report arrived first. Neither is a fact about the
	// vulnerability.
	//
	// So the worst claim anybody made wins, whichever order it arrived in —
	// and this puts the same two reports through in both orders and asserts
	// they agree.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())

		graded := func(id string, score, likelihood float64) finding.Reported {
			r := found(id, libnl)
			r.Issue.Score, r.Issue.Likelihood = score, likelihood
			return r
		}
		// One issue hears the mild report first, the other the severe one.
		for _, order := range [][]finding.Reported{
			{graded("CVE-2026-A", 4.2, 0.01), graded("CVE-2026-A", 9.1, 0.86)},
			{graded("CVE-2026-B", 9.1, 0.86), graded("CVE-2026-B", 4.2, 0.01)},
		} {
			for _, report := range order {
				if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
					[]finding.Reported{report}); err != nil {
					t.Fatal(err)
				}
			}
		}

		rising, falling := f.issueScore(t, "CVE-2026-A"), f.issueScore(t, "CVE-2026-B")
		if rising != falling {
			t.Errorf("the stored score is %d one way round and %d the other", rising, falling)
		}
		if rising != 910 {
			t.Errorf("kept %d, want 910 — the worst claim anybody made", rising)
		}
	})
}

// issueScore reads what is stored about an issue, in hundredths.
func (f *fixture) issueScore(t *testing.T, name string) int {
	t.Helper()
	var score int
	if err := f.db.DB.NewSelect().
		TableExpr("vulnerability AS v").
		ColumnExpr("COALESCE(v.score_centi, 0)").
		Where("v.identifier = ?", name).
		Scan(t.Context(), &score); err != nil {
		t.Fatal(err)
	}
	return score
}

// counter counts the statements a store actually issues.
//
// "It batches" is exactly the kind of claim that stays in a comment after the
// code stops doing it, so the test counts instead of asserting.
type counter struct{ queries atomic.Int64 }

func (c *counter) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	c.queries.Add(1)
	return ctx
}

func (c *counter) AfterQuery(context.Context, *bun.QueryEvent) {}

func TestNamingAPageOfFindingsDoesNotCostAQueryPerRow(t *testing.T) {
	// This is the screen somebody opens first, against the largest product
	// they have. Each row used to be named by two queries of its own, so a
	// page of fifty was a hundred and one round trips and the cost grew with
	// the page instead of staying flat.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
			found("CVE-2026-3", swss), found("CVE-2026-4", teamd),
		}); err != nil {
			t.Fatal(err)
		}

		// Four more issues over the same components, so the same fixture
		// answers a page of four and a page of eight.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl), found("CVE-2026-2", libnl),
			found("CVE-2026-3", swss), found("CVE-2026-4", teamd),
			found("CVE-2026-5", libnl), found("CVE-2026-6", swss),
			found("CVE-2026-7", teamd), found("CVE-2026-8", teamd),
		}); err != nil {
			t.Fatal(err)
		}

		read := func(limit int) (int, int64) {
			counted := &counter{}
			f.db.AddQueryHook(counted)
			groups, _, err := f.store.Groups(t.Context(), f.holding(t, access.PublicRead),
				f.scope, limit, 0, finding.Filter{})
			if err != nil {
				t.Fatal(err)
			}
			for _, group := range groups {
				if group.Vulnerability == "" || group.Component == "" {
					t.Errorf("a row came back unnamed: %+v", group)
				}
			}
			return len(groups), counted.queries.Load()
		}

		few, atFew := read(4)
		many, atMany := read(8)
		if few != 4 || many != 8 {
			t.Fatalf("read %d and %d rows, want 4 and 8", few, many)
		}
		// The invariant is that the cost does not grow with the page, stated
		// by comparing two page sizes rather than by a number somebody has to
		// keep up to date. A count is a moving target — a pass that is itself
		// flat legitimately adds to it, and a test pinned to the total fails
		// for that and reads as a regression.
		if atFew != atMany {
			t.Errorf("four rows took %d statements and eight took %d; "+
				"the cost grows with the page", atFew, atMany)
		}
		// And a loose ceiling, so a flat pass nobody needs is still noticed:
		// which product this is, the groups, the count, what is shown about
		// them, a lookup per kind of name, and — for both ends of the chain
		// each row sits at — the build's product and one climb to its root.
		const ceiling = 12
		if atMany > ceiling {
			t.Errorf("naming a page took %d statements, want no more than %d", atMany, ceiling)
		}
	})
}

func TestABumpThatFixedNothingIsNotRecordedAsAFix(t *testing.T) {
	// A version change closes the old row and opens a new one, because
	// component identity carries the version. Nothing asked whether the issue
	// had actually gone, so a bump that resolved nothing was recorded as
	// "fixed by upgrading" — and the same issue then appeared as fixed and as
	// newly present in one release comparison, which is a document that goes
	// to customers.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		// Bumped, and the scanner still reports it: 3.9.0 is not far enough.
		f.shipped(t, movedTo(libnlNew))
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnlNew)}); err != nil {
			t.Fatal(err)
		}

		closed, opened := f.byState(t)
		if len(closed) != 2 || len(opened) != 2 {
			t.Fatalf("closed %d and opened %d, want 2 and 2", len(closed), len(opened))
		}
		for _, row := range closed {
			if row.ClosedBecause != finding.Superseded {
				t.Errorf("a bump that fixed nothing closed as %q", row.ClosedBecause)
			}
		}
		// And what it moved from is on the new row, so saying "3.7.0 → 3.9.0"
		// costs no second query.
		for _, row := range opened {
			if row.ArrivedFrom != "3.7.0" {
				t.Errorf("the new finding says it arrived from %q, want 3.7.0", row.ArrivedFrom)
			}
		}
	})
}

func TestABumpThatDidFixItStillReadsAsAFix(t *testing.T) {
	// The direction that must not break. An upgrade that actually resolved
	// something is the ordinary good case, and calling it superseded would
	// make every real fix disappear from what was fixed.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}

		// Bumped, and the scanner reports nothing against the new version.
		f.shipped(t, movedTo(libnlNew))
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t),
			[]finding.Reported{}); err != nil {
			t.Fatal(err)
		}

		closed, opened := f.byState(t)
		if len(opened) != 0 {
			t.Fatalf("%d findings are still open after a real fix", len(opened))
		}
		for _, row := range closed {
			if row.ClosedBecause != finding.Upgraded {
				t.Errorf("a bump that resolved it closed as %q", row.ClosedBecause)
			}
			if row.ArrivedFrom != "" {
				t.Errorf("a resolved finding was marked as having arrived from %q", row.ArrivedFrom)
			}
		}
	})
}

// movedTo is the same graph with the library at another version.
func movedTo(library graph.Described) graph.Snapshot {
	return graph.Snapshot{
		Root:       root,
		Components: []graph.Described{swss, teamd, library},
		Dependencies: []graph.Dependency{
			{Parent: root, Child: swss}, {Parent: root, Child: teamd},
			{Parent: swss, Child: library}, {Parent: teamd, Child: library},
		},
	}
}

// byState splits this target's findings into closed and open.
func (f *fixture) byState(t *testing.T) (closed, opened []finding.Finding) {
	t.Helper()
	var rows []finding.Finding
	if err := f.db.NewSelect().Model(&rows).
		Where("target_id = ?", f.target).Order("id").Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.ClosedRunID != nil {
			closed = append(closed, row)
			continue
		}
		opened = append(opened, row)
	}
	return closed, opened
}

// The number a release-over-release chart is drawn from. Nothing reported it
// before, so the comparison screen could say what changed between two builds
// and not whether the estate was getting better or worse across all of them.
func TestWhatIsOpenIsReportedPerBuild(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// A **second** build, because "per build" tested against one build
		// proves nothing: collapsing the grouping key to a constant passed.
		second := f.anotherBuild(t, "202411")

		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
			found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		// One issue on the other build, so the two must not be added together.
		f.shippedTo(t, second, twoConsumers())
		if _, err := f.store.Apply(t.Context(), second, f.runOn(t, second),
			[]finding.Reported{found("CVE-2026-3", libnl)}); err != nil {
			t.Fatal(err)
		}

		releases, err := f.store.Releases(t.Context(),
			f.holding(t, access.PublicRead), f.productID)
		if err != nil {
			t.Fatalf("releases: %v", err)
		}
		if len(releases) != 2 {
			t.Fatalf("reported %d builds, expected 2: %+v", len(releases), releases)
		}
		by := map[string]finding.Release{}
		for _, r := range releases {
			by[r.Stream] = r
		}
		// Two issues at one component is two rows on the findings list, not
		// the six places they sit at. Counting places is the mistake the trend
		// chart already made and recorded.
		if got := by["master"].Open; got != 2 {
			t.Errorf("master reports %d open, expected 2 — one per issue at a "+
				"component, not one per place", got)
		}
		if got := by["202411"].Open; got != 1 {
			t.Errorf("202411 reports %d open, expected 1", got)
		}
		// The split has to name the band, not merely add up: incrementing both
		// counters from the same value in the same loop is a tautology, and
		// renaming the band to nonsense used to pass.
		if got := by["master"].BySeverity["high"]; got != 2 {
			t.Errorf("master reports %d high, expected 2 (by_severity: %v)",
				got, by["master"].BySeverity)
		}
	})
}

func TestWhatIsOpenPerBuildIsNarrowedToWhatSomebodyMayRead(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
			found("CVE-2026-2", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		// One of the two issues undisclosed, so a reader sees a *smaller*
		// number rather than none. With everything hidden the checks below
		// never had a positive case, and the test could only fail by returning
		// something it should not — never by returning the wrong number.
		//
		// Every place of that issue, not one row: an issue sits at several
		// places, and hiding one leaves it visible through another, which is
		// correct and is what this counts.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("visibility = ?", access.Private).
			Where("vulnerability_id = ?", f.issueID(t, "CVE-2026-1")).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		open := func(who access.Subject) int {
			t.Helper()
			releases, err := f.store.Releases(t.Context(), who, f.productID)
			if err != nil {
				t.Fatalf("releases: %v", err)
			}
			total := 0
			for _, r := range releases {
				total += r.Open
			}
			return total
		}

		// Two issues at one component: two rows for somebody who may read
		// both, one for somebody who may read only what is disclosed.
		if got := open(f.holding(t, access.PrivateRead)); got != 2 {
			t.Errorf("a reader of everything was told %d, expected 2", got)
		}
		if got := open(f.holding(t, access.PublicRead)); got != 1 {
			t.Errorf("a reader of disclosed findings only was told %d, expected 1", got)
		}
		if got := open(access.NewPerson(2, "stranger", false, nil, 0)); got != 0 {
			t.Errorf("somebody with no rights was told %d", got)
		}
	})
}

// A build reporting nothing wrong and a build last measured against a database
// from March look identical on every screen without this.
func TestTheLastRunSaysWhatItWasMeasuredWith(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.holding(t, access.PublicRead)
		f.shipped(t, twoConsumers())

		// A run that has started and not finished is not an answer. Reporting
		// it would say the build was measured against a database version that
		// nothing has been measured against yet.
		running := f.run(t)
		if _, err := f.store.Apply(t.Context(), f.target, running,
			[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
			t.Fatal(err)
		}
		unfinished, err := f.store.LatestRun(t.Context(), who, f.target)
		if err != nil {
			t.Fatalf("latest run: %v", err)
		}
		if unfinished != nil {
			t.Fatalf("an unfinished run was reported: %+v", unfinished)
		}
		if err := f.store.Finish(t.Context(), running, "0.100.1", "2026-08-29", "", nil); err != nil {
			t.Fatal(err)
		}

		// A second, later run. "Most recent" is untestable with one.
		later := f.run(t)
		if err := f.store.Finish(t.Context(), later, "0.101.0", "2026-09-02", "", nil); err != nil {
			t.Fatal(err)
		}

		last, err := f.store.LatestRun(t.Context(), who, f.target)
		if err != nil {
			t.Fatalf("latest run: %v", err)
		}
		if last == nil {
			t.Fatal("nothing reported after two runs finished")
		}
		if last.ID != later {
			t.Errorf("reported run %d, expected the most recent (%d)", last.ID, later)
		}
		if last.DatabaseVersion != "2026-09-02" {
			t.Errorf("database version is %q, expected the later run's",
				last.DatabaseVersion)
		}
		if last.Scanner != "grype" || last.FinishedAt == nil {
			t.Errorf("a finished run reported without its scanner or time: %+v", last)
		}

		// And somebody who may not see this product is told nothing, on the
		// query rather than by the caller remembering to ask.
		stranger := access.NewPerson(2, "stranger", false, nil, 0)
		if hidden, err := f.store.LatestRun(t.Context(), stranger, f.target); err != nil {
			t.Fatalf("latest run for a stranger: %v", err)
		} else if hidden != nil {
			t.Errorf("somebody with no rights was told what it was measured with: %+v", hidden)
		}
	})
}

// A name that ships at several versions is answerable, and answering with
// every version of the name is a list where most choices lead to "no such
// finding" — which is a worse answer than the refusal it replaced.
func TestOnlyTheVersionsCarryingTheIssueAreOffered(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		// Enough that every filter has something to exclude. With one finding
		// and one component this test passed with **every** filter deleted —
		// the vulnerability, the closed check, the name and the visibility —
		// because a join through `finding` could not return anything else
		// whatever the query said. Absent data was doing the work the code was
		// supposed to do.
		carrying := graph.Described{
			Purl: "pkg:golang/example.com/lib@v1", Name: "example.com/lib", Version: "v1",
		}
		clean := graph.Described{
			Purl: "pkg:golang/example.com/lib@v2", Name: "example.com/lib", Version: "v2",
		}
		// Same version, different ecosystem: the source repository and the
		// package built from it, which is why a version alone cannot pick one.
		sibling := graph.Described{
			Purl: "pkg:github/example.com/lib@v1", Name: "example.com/lib", Version: "v1",
		}
		// Another name entirely, so the name filter has something to drop.
		elsewhere := graph.Described{
			Purl: "pkg:golang/example.com/other@v9", Name: "example.com/other", Version: "v9",
		}
		f.shipped(t, graph.Snapshot{
			Root:       root,
			Components: []graph.Described{carrying, clean, sibling, elsewhere},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: carrying}, {Parent: root, Child: clean},
				{Parent: root, Child: sibling}, {Parent: root, Child: elsewhere},
			},
		})
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{
			found("CVE-2026-9", carrying),
			// A different issue at the clean version: the vulnerability filter
			// has to drop this, not the absence of a row.
			found("CVE-2026-8", clean),
			// The same issue under a different name.
			found("CVE-2026-9", elsewhere),
			// And the same issue at the same version in another ecosystem.
			found("CVE-2026-9", sibling),
		}); err != nil {
			t.Fatal(err)
		}

		who := f.holding(t, access.PublicRead)
		issue := f.issueID(t, "CVE-2026-9")
		got, err := f.store.VersionsWithIssue(t.Context(), who, f.target, issue,
			"example.com/lib")
		if err != nil {
			t.Fatalf("versions: %v", err)
		}
		want := []graph.Choice{
			{Version: "v1", Ecosystem: "golang"},
			{Version: "v1", Ecosystem: "github"},
		}
		if !sameChoices(got, want) {
			t.Errorf("offered %v, expected %v", got, want)
		}

		// Closed findings are not offered: following one leads to a finding
		// that is not there.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("closed_at = ?", time.Now().UTC()).
			Set("closed_run_id = ?", f.run(t)).
			Where("target_id = ?", f.target).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		closed, err := f.store.VersionsWithIssue(t.Context(), who, f.target, issue,
			"example.com/lib")
		if err != nil {
			t.Fatalf("versions after closing: %v", err)
		}
		if len(closed) != 0 {
			t.Errorf("offered %v after every finding closed", closed)
		}
	})
}

// sameChoices compares without caring about order, which the query does not
// promise beyond being stable.
func sameChoices(got, want []graph.Choice) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[graph.Choice]int{}
	for _, c := range got {
		seen[c]++
	}
	for _, c := range want {
		seen[c]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// issueID resolves an issue by the name it was reported under.
func (f *fixture) issueID(t *testing.T, identifier string) int64 {
	t.Helper()
	id, err := finding.NewVulnerabilities(f.db.DB).ByName(t.Context(), identifier)
	if err != nil {
		t.Fatalf("resolve %s: %v", identifier, err)
	}
	return id
}

// backdate moves a scan run's start into the past, so that a deadline counted
// from the opening and a deadline counted from the scan in hand land far
// enough apart to tell apart.
func (f *fixture) backdate(t *testing.T, runID int64, by time.Duration) {
	t.Helper()
	var started time.Time
	if err := f.db.DB.NewSelect().TableExpr("scan_run AS r").
		ColumnExpr("r.started_at").Where("r.id = ?", runID).
		Scan(t.Context(), &started); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.DB.NewUpdate().TableExpr("scan_run").
		Set("started_at = ?", started.Add(-by)).
		Where("id = ?", runID).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// startedAt is when a scan run began, as stored.
func (f *fixture) startedAt(t *testing.T, runID int64) time.Time {
	t.Helper()
	var started time.Time
	if err := f.db.DB.NewSelect().TableExpr("scan_run AS r").
		ColumnExpr("r.started_at").Where("r.id = ?", runID).
		Scan(t.Context(), &started); err != nil {
		t.Fatal(err)
	}
	return started
}

// assessment reads one claim back, whatever state it is in.
func (f *fixture) assessment(t *testing.T, id int64) finding.Assessment {
	t.Helper()
	var held finding.Assessment
	if err := f.db.DB.NewSelect().Model(&held).Where("id = ?", id).
		Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return held
}

// liveAssessments counts the claims still standing about an issue.
func (f *fixture) liveAssessments(t *testing.T, vulnerabilityID int64) int {
	t.Helper()
	n, err := f.db.DB.NewSelect().Model((*finding.Assessment)(nil)).
		Where("live_vulnerability_id = ?", vulnerabilityID).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// vulnerability names one of a run of issues, zero-padded so the order a test
// reads them in is the order it wrote them.
func vulnerability(i int) string { return fmt.Sprintf("CVE-2026-%04d", i) }

// inAnotherProduct declares a build of a product of its own and returns its
// target, for the checks about reaching across products.
func (f *fixture) inAnotherProduct(t *testing.T, name string) int64 {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(f.db.DB)
	product, err := cat.DeclareProduct(ctx, name, name)
	if err != nil {
		t.Fatalf("declare %s: %v", name, err)
	}
	stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
	if err != nil {
		t.Fatalf("declare a line of %s: %v", name, err)
	}
	variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
	if err != nil {
		t.Fatalf("declare a variant of %s: %v", name, err)
	}
	target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
	if err != nil {
		t.Fatalf("target for %s: %v", name, err)
	}
	return target.ID
}

// productOf is which product a build belongs to.
func (f *fixture) productOf(t *testing.T, target int64) int64 {
	t.Helper()
	var productID int64
	if err := f.db.DB.NewSelect().
		TableExpr("target AS tg").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		ColumnExpr("st.product_id").
		Where("tg.id = ?", target).
		Scan(t.Context(), &productID); err != nil {
		t.Fatal(err)
	}
	return productID
}

// streamOf is which release a build belongs to.
func (f *fixture) streamOf(t *testing.T, target int64) int64 {
	t.Helper()
	var streamID int64
	if err := f.db.DB.NewSelect().
		TableExpr("target AS tg").
		ColumnExpr("tg.stream_id").
		Where("tg.id = ?", target).
		Scan(t.Context(), &streamID); err != nil {
		t.Fatal(err)
	}
	return streamID
}

// anotherVariant declares a second way this product is built and returns the
// target for it on the fixture's own stream.
func (f *fixture) anotherVariant(t *testing.T, name string) int64 {
	t.Helper()
	ctx := t.Context()
	cat := catalog.NewStore(f.db.DB)
	variant, err := cat.DeclareVariant(ctx, f.productID, name, true)
	if err != nil {
		t.Fatalf("declare variant %s: %v", name, err)
	}
	var streamID int64
	if err := f.db.DB.NewSelect().
		TableExpr("target AS tg").ColumnExpr("tg.stream_id").
		Where("tg.id = ?", f.target).Scan(ctx, &streamID); err != nil {
		t.Fatal(err)
	}
	target, err := cat.TargetFor(ctx, streamID, variant.ID)
	if err != nil {
		t.Fatalf("target for %s: %v", name, err)
	}
	return target.ID
}

// scopeOf is one build as a selection, for a build that is not the fixture's
// own — a second variant, or a second branch.
func (f *fixture) scopeOf(t *testing.T, targetID int64) finding.Scope {
	t.Helper()
	var row struct {
		ProductID int64 `bun:"product_id"`
		StreamID  int64 `bun:"stream_id"`
		VariantID int64 `bun:"variant_id"`
	}
	if err := f.db.DB.NewSelect().
		TableExpr("target AS tg").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		ColumnExpr("st.product_id AS product_id").
		ColumnExpr("tg.stream_id AS stream_id").
		ColumnExpr("tg.variant_id AS variant_id").
		Where("tg.id = ?", targetID).Scan(t.Context(), &row); err != nil {
		t.Fatalf("look up build %d: %v", targetID, err)
	}
	return finding.Scope{
		ProductID: &row.ProductID, StreamID: &row.StreamID, VariantID: &row.VariantID,
	}
}

// wholeProduct is every build of the fixture's product: what the picker
// selects with the branch and the variant left at "all".
func (f *fixture) wholeProduct() finding.Scope {
	return finding.Scope{ProductID: &f.productID}
}

// componentID is the component row one name resolves to in the fixture's build.
func (f *fixture) componentID(t *testing.T, name string) int64 {
	t.Helper()
	id, err := graph.NewStore(f.db.DB).ComponentAt(t.Context(), f.target, name)
	if err != nil {
		t.Fatalf("resolve %s: %v", name, err)
	}
	return id
}

func TestARunThatWarnsWhileSucceedingKeepsWhatItSaid(t *testing.T) {
	// The scanner's own words were read only when it failed, which discarded
	// the case that matters: a run that answers and says its answer is coarse.
	// Told to match Go binaries carrying no function symbols it falls back to
	// module granularity, which can report a component as affected when the
	// vulnerable function is not linked in — a qualification on every finding
	// the run produced.
	//
	// Kept apart from the failure, because a run that warned and a run that
	// failed are different things and one column holding either makes them one.
	each(t, func(t *testing.T, f *fixture) {
		const said = "go binary packages were found but none carry function symbols"
		run := f.run(t)
		if err := f.store.Finish(t.Context(), run, "0.118.0", "2026-09-04", said, nil); err != nil {
			t.Fatal(err)
		}

		var kept finding.Run
		if err := f.db.DB.NewSelect().Model(&kept).Where("id = ?", run).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if kept.Caution != said {
			t.Errorf("what the scanner said reads %q", kept.Caution)
		}
		if kept.Failure != "" {
			t.Errorf("a run that warned reads as failed: %q", kept.Failure)
		}
	})
}

// admin returns somebody who administers this deployment and has granted
// themselves roles on this fixture's product, which is how an administrator
// reaches findings now that administering grants no reading.
func (f *fixture) admin(t *testing.T, roles ...access.Role) access.Subject {
	t.Helper()
	return access.NewPerson(1, "admin", true, map[int64][]access.Role{f.productID: roles}, 0)
}

// holdingIn returns somebody holding roles on several products, for the reads
// that cross one.
func (f *fixture) holdingIn(t *testing.T, products []int64, roles ...access.Role) access.Subject {
	t.Helper()
	grants := map[int64][]access.Role{}
	for _, id := range products {
		grants[id] = roles
	}
	return access.NewPerson(1, "someone", false, grants, 101)
}
