// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// sent is one result as a document states it: a rule, a file under a
// named starting point, a line and a message.
type sent struct {
	rule, base, uri, message string
	line                     int
}

func (s sent) json() string {
	return fmt.Sprintf(`{"ruleId":%q,"message":{"text":%q},"locations":[{"physicalLocation":`+
		`{"artifactLocation":{"uri":%q,"uriBaseId":%q},"region":{"startLine":%d}}}]}`,
		s.rule, s.message, s.uri, s.base, s.line)
}

// document is one run of clang-tidy over a checkout holding FRR as a
// submodule, analyzing units of the ten it was meant to. Its rule list holds
// a rule that never fires, so the list is the rule set.
func document(results []sent, units int) string {
	rs := make([]string, len(results))
	for i, r := range results {
		rs[i] = r.json()
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clang-tidy","version":"18.1.3",` +
		`"rules":[{"id":"bugprone-use-after-move","properties":{"tags":["external/cwe/cwe-416"]}},` +
		`{"id":"bugprone-dangling-handle"}]}},` +
		`"originalUriBaseIds":{"SRCROOT":{"uri":"file:///home/builder/sonic/"},` +
		`"FRR":{"uri":"src/sonic-frr/frr/","uriBaseId":"SRCROOT"}},` +
		`"versionControlProvenance":[` +
		`{"repositoryUri":"https://github.com/sonic-net/sonic-buildimage","revisionId":"abc","mappedTo":{"uriBaseId":"SRCROOT"}},` +
		`{"repositoryUri":"https://github.com/FRRouting/frr.git","revisionId":"def","mappedTo":{"uriBaseId":"FRR"}}],` +
		fmt.Sprintf(`"properties":{"openpsirt/unitsExpected":%d,"openpsirt/unitsAnalyzed":%d},`, 10, units) +
		`"results":[` + strings.Join(rs, ",") + `]}]}`
}

var (
	inFRR  = sent{"bugprone-use-after-move", "FRR", "bgpd/bgp_attr.c", "x used after it was moved", 40}
	inSWSS = sent{"bugprone-use-after-move", "SRCROOT", "src/sonic-swss/orchagent/orch.cpp", "y used after it was moved", 12}
)

// world is a build with a read inventory holding FRR.
type world struct {
	*fixture.World
	applier *Applier
	frr     int64
	root    int64
}

func eachWorld(t *testing.T, fn func(t *testing.T, w *world)) {
	t.Helper()
	fixture.Each(t, func(t *testing.T, fw *fixture.World) {
		fn(t, &world{World: fw, applier: NewApplier(fw.DB, sarif.DefaultLimits())})
	})
}

// inventory records a read inventory for a build: the product, and FRR
// built from its repository.
func (w *world) inventory(t *testing.T, targetID int64) {
	t.Helper()
	ctx := t.Context()
	scans := ingest.NewStore(w.DB.DB)
	scan, outcome, err := scans.Record(ctx, ingest.Arriving{
		TargetID: targetID, ContentHash: fmt.Sprintf("inventory-%d", targetID),
		BuiltAt: time.Now().UTC().Add(-2 * time.Hour), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record the inventory: %v %v", outcome, err)
	}
	root := graph.Described{Purl: "pkg:generic/sonic@1.0", Name: "sonic", Version: "1.0"}
	frr := graph.Described{Purl: "pkg:github/frrouting/frr@10.2", Name: "frr", Version: "10.2"}
	if _, err := fixture.ApplyGraph(ctx, w.DB.DB, targetID, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{frr},
		Dependencies: []graph.Dependency{{Parent: root, Child: frr}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := scans.Made(ctx, scan.ID, 2, 2, "sonic"); err != nil {
		t.Fatal(err)
	}
	var nodes []struct {
		ID     int64 `bun:"component_id"`
		IsRoot bool  `bun:"is_root"`
	}
	if err := w.DB.DB.NewSelect().TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."component_id", "n"."is_root"`).
		Where(`"n"."target_id" = ?`, targetID).Scan(ctx, &nodes); err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		if n.IsRoot {
			w.root = n.ID
		} else {
			w.frr = n.ID
		}
	}
}

// send receives a run as the upload operation does and applies it.
func (w *world) send(t *testing.T, targetID int64, built time.Time, doc string) (*series.Run, series.Status) {
	t.Helper()
	ctx := t.Context()
	log, err := sarif.Read(strings.NewReader(doc), sarif.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	given := Describe([]sarif.Log{log}, Stated{Series: "clang-tidy/default", BuiltAt: built})
	sum := sha256.Sum256([]byte(doc))
	hash := RunHash([]string{hex.EncodeToString(sum[:])}, given.BuiltAt)
	var run *series.Run
	if err := database.InTransaction(ctx, w.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		store := series.NewStore(tx)
		var err error
		run, _, err = store.Receive(ctx, series.Arriving{
			ProductID: w.Product.ID, TargetID: targetID, Kind: kind.Analysis, Series: given.Series,
			ContentHash: hash, BuiltAt: given.BuiltAt, Params: given.Params,
		})
		if err != nil {
			return err
		}
		_, err = store.Write(ctx, run.ID, 0, strings.NewReader(doc))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	status, err := w.applier.Apply(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	run, err = series.NewStore(w.DB.DB).ByID(ctx, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	return run, status
}

func receiptOf(t *testing.T, run *series.Run) Receipt {
	t.Helper()
	var r Receipt
	if err := json.Unmarshal([]byte(run.Receipt), &r); err != nil {
		t.Fatalf("receipt %q: %v", run.Receipt, err)
	}
	return r
}

// leads is the build's open analysis findings, by component.
func (w *world) leads(t *testing.T, targetID int64) []finding.Finding {
	t.Helper()
	var rows []finding.Finding
	where, args := kind.In(`"f"."kind"`, []kind.Kind{kind.Analysis})
	if err := w.DB.DB.NewSelect().Model(&rows).
		Where(`"f"."target_id" = ?`, targetID).Where(where, args...).
		OrderExpr(`"f"."id" ASC`).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestARunWaitsUntilItsBuildHasAnInventory(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		built := time.Now().UTC().Add(-time.Hour)
		run, status := w.send(t, w.Target.ID, built, document([]sent{inFRR}, 10))
		if status != series.Waiting {
			t.Fatalf("status %s; want waiting with no inventory read", status)
		}
		if got := w.leads(t, w.Target.ID); len(got) != 0 {
			t.Errorf("%d findings opened before the build had components", len(got))
		}
		w.inventory(t, w.Target.ID)
		status, err := w.applier.Apply(t.Context(), run.ID)
		if err != nil || status != series.Applied {
			t.Fatalf("status %s, %v; want applied once the inventory is read", status, err)
		}
	})
}

func TestAResultIsAnInternalFindingOnTheComponentItsRepositoryBuilt(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		run, status := w.send(t, w.Target.ID, time.Now().UTC().Add(-time.Hour),
			document([]sent{inFRR, inSWSS}, 10))
		if status != series.Applied {
			t.Fatalf("status %s (%s); want applied", status, run.Failure)
		}
		if r := receiptOf(t, run); r.Opened != 2 {
			t.Errorf("receipt %+v; want two opened", r)
		}
		if !run.Baseline || run.Comparable == nil || !*run.Comparable {
			t.Errorf("the series' first comparable run is its baseline: baseline %v, comparable %v",
				run.Baseline, run.Comparable)
		}
		leads := w.leads(t, w.Target.ID)
		if len(leads) != 2 {
			t.Fatalf("%d findings; want 2", len(leads))
		}
		on := map[int64]int{}
		for _, f := range leads {
			if f.Visibility != access.Internal {
				t.Errorf("a finding opened %s; want internal", f.Visibility)
			}
			on[f.ComponentID]++
		}
		if on[w.frr] != 1 || on[w.root] != 1 {
			t.Errorf("findings by component %v; want one on FRR (%d) and one on the build (%d)", on, w.frr, w.root)
		}
		var issue finding.Vulnerability
		if err := w.DB.DB.NewSelect().Model(&issue).
			Where(`"vu"."id" = ?`, leads[0].VulnerabilityID).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if issue.Identifier != "clang-tidy/bugprone-use-after-move" || issue.Kind != kind.Rule {
			t.Errorf("filed under %q, a %s; want the tool's rule", issue.Identifier, issue.Kind)
		}
	})
}

func TestAComparableRunThatMissesAResultMarksItNotReproduced(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Target.ID, start, document([]sent{inFRR, inSWSS}, 10))

		run, _ := w.send(t, w.Target.ID, start.Add(time.Hour), document([]sent{inSWSS}, 10))
		if r := receiptOf(t, run); r.Seen != 1 || r.NotReproduced != 1 || r.Opened != 0 {
			t.Errorf("receipt %+v; want one seen and one not reproduced", r)
		}
		if got := w.leads(t, w.Target.ID); len(got) != 2 {
			t.Errorf("%d findings; not reproduced closes nothing", len(got))
		}

		run, _ = w.send(t, w.Target.ID, start.Add(2*time.Hour), document([]sent{inFRR, inSWSS}, 10))
		if r := receiptOf(t, run); r.Seen != 2 || r.Returned != 1 || r.Opened != 0 {
			t.Errorf("receipt %+v; want both seen, one of them returned", r)
		}
	})
}

func TestARunShortOfItsUnitsMarksNothingNotReproduced(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Target.ID, start, document([]sent{inFRR, inSWSS}, 10))
		run, _ := w.send(t, w.Target.ID, start.Add(time.Hour), document([]sent{inSWSS}, 4))
		if run.Comparable == nil || *run.Comparable || run.Reason != series.UnitsShort {
			t.Errorf("comparable %v for %q; want not comparable, units short", run.Comparable, run.Reason)
		}
		if r := receiptOf(t, run); r.NotReproduced != 0 || r.Seen != 1 {
			t.Errorf("receipt %+v; want one seen and none marked", r)
		}
	})
}

func TestARunBuiltBeforeTheLastAppliedIsSuperseded(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Target.ID, start, document([]sent{inFRR}, 10))
		_, status := w.send(t, w.Target.ID, start.Add(-time.Hour), document([]sent{inSWSS}, 10))
		if status != series.Superseded {
			t.Fatalf("status %s; want superseded", status)
		}
		if got := w.leads(t, w.Target.ID); len(got) != 1 {
			t.Errorf("%d findings; a superseded run opens nothing", len(got))
		}
	})
}

func TestARunThatWouldMarkMostOfABuildIsHeld(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		if _, _, err := setting.NewStore(w.DB.DB).Change(t.Context(), setting.AnalysisDropFloor, "1"); err != nil {
			t.Fatal(err)
		}
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Target.ID, start, document([]sent{inFRR, inSWSS}, 10))
		run, status := w.send(t, w.Target.ID, start.Add(time.Hour), document(nil, 10))
		if status != series.Held {
			t.Fatalf("status %s; want held", status)
		}
		if r := receiptOf(t, run); r.WouldMark != 2 || r.NotReproduced != 0 {
			t.Errorf("receipt %+v; want two it would mark and none marked", r)
		}
	})
}

func TestAResultOnAnotherBuildCarriesThePlaceItWasJudgedAt(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		tag, err := w.Catalog.TargetFor(t.Context(), w.Tag.ID, w.Customer.ID)
		if err != nil {
			t.Fatal(err)
		}
		w.inventory(t, tag.ID)
		built := time.Now().UTC().Add(-time.Hour)
		w.send(t, w.Target.ID, built, document([]sent{inFRR}, 10))
		w.send(t, tag.ID, built, document([]sent{inFRR}, 10))
		a, b := w.leads(t, w.Target.ID), w.leads(t, tag.ID)
		if len(a) != 1 || len(b) != 1 {
			t.Fatalf("%d and %d findings; want one on each build", len(a), len(b))
		}
		if a[0].PlaceIdentity != b[0].PlaceIdentity {
			t.Errorf("places %q and %q; want one place, so a decision on it reaches both", a[0].PlaceIdentity, b[0].PlaceIdentity)
		}
	})
}

func TestAnUploadOfAScannerAloneFails(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}`
		run, status := w.send(t, w.Target.ID, time.Now().UTC().Add(-time.Hour), doc)
		if status != series.Failed || run.Failure == "" {
			t.Fatalf("status %s, failure %q; want failed, saying why", status, run.Failure)
		}
		if r := receiptOf(t, run); len(r.Scanners) != 1 {
			t.Errorf("receipt %+v; want the scanner named", r)
		}
	})
}
