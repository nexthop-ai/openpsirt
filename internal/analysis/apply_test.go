// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"bytes"
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
	"github.com/nexthop-ai/openpsirt/internal/refusal"
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
		fn(t, &world{World: fw, applier: NewApplier(fw.DB)})
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
	run := w.receive(t, targetID, built, doc)
	status, err := w.applier.Apply(t.Context(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	run, err = series.NewStore(w.DB.DB).ByID(t.Context(), run.ID)
	if err != nil {
		t.Fatal(err)
	}
	return run, status
}

// receive receives a run as the upload operation does.
func (w *world) receive(t *testing.T, targetID int64, built time.Time, doc string) *series.Run {
	t.Helper()
	ctx := t.Context()
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(strings.NewReader(doc))
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
		placed, err := Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes)
		if err != nil {
			return err
		}
		return placed.Hold(ctx, store, run.ID)
	}); err != nil {
		t.Fatal(err)
	}
	return run
}

// spread is n results of one rule, each in a file of its own.
func spread(n int) []sent {
	out := make([]sent, n)
	for i := range out {
		out[i] = sent{"bugprone-use-after-move", "SRCROOT", fmt.Sprintf("src/f%d.c", i), "v used after it was moved", 1}
	}
	return out
}

// sightings is every sighting the build's leads have.
func (w *world) sightings(t *testing.T, targetID int64) []series.Sighting {
	t.Helper()
	var rows []series.Sighting
	if err := w.DB.DB.NewSelect().Model(&rows).
		Join(`JOIN "finding" AS "f" ON "f"."id" = "si"."finding_id"`).
		Where(`"f"."target_id" = ?`, targetID).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

// drops sets the share and floor a run is held past.
func (w *world) drops(t *testing.T, share, floor string) {
	t.Helper()
	settings := setting.NewStore(w.DB.DB)
	if _, _, err := settings.Change(t.Context(), setting.AnalysisDropShare, share); err != nil {
		t.Fatal(err)
	}
	if _, _, err := settings.Change(t.Context(), setting.AnalysisDropFloor, floor); err != nil {
		t.Fatal(err)
	}
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
		w.drops(t, "50", "1")
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Target.ID, start, document([]sent{inFRR, inSWSS}, 10))
		run, status := w.send(t, w.Target.ID, start.Add(time.Hour), document(nil, 10))
		if status != series.Held {
			t.Fatalf("status %s; want held", status)
		}
		if r := receiptOf(t, run); r.WouldMark != 2 || r.NotReproduced != 0 {
			t.Errorf("receipt %+v; want two it would mark and none marked", r)
		}
		for _, s := range w.sightings(t, w.Target.ID) {
			if s.AbsentRunID != nil {
				t.Errorf("finding %d marked not reproduced by a held run", s.FindingID)
			}
		}
	})
}

func TestARunPastOnlyOneOfTheTwoDropBoundsIsApplied(t *testing.T) {
	for name, c := range map[string]struct {
		share, floor string
		missed       int
	}{
		// Two of four is half, which the share of 50 does not pass.
		"past the floor alone": {"50", "1", 2},
		// Four of four is all of them, and four is short of the floor.
		"past the share alone": {"50", "5", 4},
	} {
		t.Run(name, func(t *testing.T) {
			eachWorld(t, func(t *testing.T, w *world) {
				w.inventory(t, w.Target.ID)
				w.drops(t, c.share, c.floor)
				start := time.Now().UTC().Add(-3 * time.Hour)
				all := spread(4)
				w.send(t, w.Target.ID, start, document(all, 10))
				run, status := w.send(t, w.Target.ID, start.Add(time.Hour), document(all[c.missed:], 10))
				if status != series.Applied {
					t.Fatalf("status %s; want applied", status)
				}
				if r := receiptOf(t, run); r.NotReproduced != c.missed {
					t.Errorf("receipt %+v; want %d not reproduced", r, c.missed)
				}
			})
		})
	}
}

func TestARunWaitingADayForItsInventoryFails(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		run, status := w.send(t, w.Target.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
		if status != series.Waiting {
			t.Fatalf("status %s; want waiting", status)
		}
		w.applier.now = func() time.Time { return run.ReceivedAt.Add(inventoryWait - time.Minute) }
		if status, err := w.applier.Apply(t.Context(), run.ID); err != nil || status != series.Waiting {
			t.Fatalf("status %s, %v; want still waiting short of a day", status, err)
		}
		w.applier.now = func() time.Time { return run.ReceivedAt.Add(inventoryWait) }
		if status, err := w.applier.Apply(t.Context(), run.ID); err != nil || status != series.Failed {
			t.Fatalf("status %s, %v; want failed after a day", status, err)
		}
		docs, err := series.NewStore(w.DB.DB).Documents(t.Context(), run.ID)
		if err != nil || len(docs) != 0 {
			t.Errorf("%d documents still held, %v", len(docs), err)
		}
	})
}

func TestARunHeldInAShapeThisReleaseDoesNotReadFailsOnceItsBuildIsInventoried(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		run := w.receive(t, w.Target.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
		store := series.NewStore(w.DB.DB)
		if err := store.Discard(t.Context(), run.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Write(t.Context(), run.ID, 1, strings.NewReader(`{"version":"2.1.0","runs":[]}`)); err != nil {
			t.Fatal(err)
		}
		// A waiting run is not read, so nothing yet finds what it holds.
		if status, err := w.applier.Apply(t.Context(), run.ID); err != nil || status != series.Waiting {
			t.Fatalf("status %s, %v; want waiting, unread", status, err)
		}
		w.inventory(t, w.Target.ID)
		status, err := w.applier.Apply(t.Context(), run.ID)
		if err != nil || status != series.Failed {
			t.Fatalf("status %s, %v; want failed", status, err)
		}
		run, err = store.ByID(t.Context(), run.ID)
		if err != nil || !strings.Contains(run.Failure, "could not be read") {
			t.Errorf("failure %q, %v; want the placed results could not be read", run.Failure, err)
		}
	})
}

func TestPlacedResultsPastTheByteBoundAreRefused(t *testing.T) {
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(strings.NewReader(document(spread(50), 10)))
	if err != nil {
		t.Fatal(err)
	}
	placed, err := Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	var held bytes.Buffer
	if err := placed.encode(&held); err != nil {
		t.Fatal(err)
	}
	if _, err := Place([]sarif.Log{log}, "", int64(held.Len())); err != nil {
		t.Errorf("refused at exactly its size: %v", err)
	}
	_, err = Place([]sarif.Log{log}, "", int64(held.Len())-1)
	if !refusal.In(err) || !strings.Contains(err.Error(), "configured limit") {
		t.Errorf("one byte short answered %v; want a refusal naming the limit", err)
	}
}

func TestWhatARunSaysOnceIsHeldOnce(t *testing.T) {
	tool := strings.Repeat("T", 4096)
	doc := strings.Replace(document(spread(200), 10), `"name":"clang-tidy"`, `"name":"`+tool+`"`, 1)
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	placed, err := Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	var held bytes.Buffer
	if err := placed.encode(&held); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(held.String(), tool); n != 1 {
		t.Errorf("the tool's name is held %d times; want once for its 200 results", n)
	}
	back, err := decode(&held)
	if err != nil || len(back.Results) != 200 || back.tool(199) != tool || back.remote(0) == "" {
		t.Errorf("read back %d results, %v; want 200 under the tool and its repository", len(back.Results), err)
	}
}

func TestAFailureSignalOutsideTheCheckoutMakesTheRunNotComparable(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		failed := sent{"clang-diagnostic-error", "", "file:///tmp/build/generated.h", "unknown type name", 3}
		run, _ := w.send(t, w.Target.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR, failed}, 10))
		if run.Comparable == nil || *run.Comparable || run.Reason != series.FailureSignal {
			t.Errorf("comparable %v for %q; want not comparable, a failure signal", run.Comparable, run.Reason)
		}
		if r := receiptOf(t, run); r.Dropped[DroppedFailure] != 1 || r.Dropped[DroppedOutside] != 0 {
			t.Errorf("receipt %+v; want the failure counted as one", r)
		}
	})
}

func TestTakingASeriesWritesItsRowEveryTime(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		run := w.receive(t, w.Target.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
		taken := func() string {
			t.Helper()
			if err := series.NewStore(w.DB.DB).Take(t.Context(), run.ID); err != nil {
				t.Fatal(err)
			}
			var by string
			if err := w.DB.DB.NewSelect().Table("series").Column("taken_by").
				Where(`"id" = ?`, run.SeriesID).Scan(t.Context(), &by); err != nil {
				t.Fatal(err)
			}
			return by
		}
		if first, second := taken(), taken(); first == "" || first == second {
			t.Errorf("taken by %q, then %q; want a new value each time", first, second)
		}
	})
}

func TestTwoRunsOfOneSeriesAreAppliedOneAfterTheOther(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		ctx := t.Context()
		run := w.receive(t, w.Target.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
		tx, err := w.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := series.NewStore(tx).Take(ctx, run.ID); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := w.applier.Apply(ctx, run.ID)
			done <- err
		}()
		select {
		case err := <-done:
			_ = tx.Rollback()
			t.Fatalf("applied while another apply held the series: %v", err)
		case <-time.After(300 * time.Millisecond):
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
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

func TestAResultTheBaselineHoldsElsewhereIsInTheBaselineOnANewBuild(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Target.ID)
		tag, err := w.Catalog.TargetFor(t.Context(), w.Tag.ID, w.Customer.ID)
		if err != nil {
			t.Fatal(err)
		}
		w.inventory(t, tag.ID)
		built := time.Now().UTC().Add(-time.Hour)
		w.send(t, w.Target.ID, built, document([]sent{inFRR}, 10))
		run, _ := w.send(t, tag.ID, built, document([]sent{inFRR, inSWSS}, 10))
		if run.Baseline {
			t.Fatal("the series' second comparable run is not its baseline")
		}
		var rows []struct {
			Path     string `bun:"path"`
			Baseline bool   `bun:"baseline"`
		}
		if err := w.DB.DB.NewSelect().TableExpr(`"sighting" AS "si"`).
			Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "si"."finding_id"`).
			Join(`JOIN "finding" AS "f" ON "f"."id" = "si"."finding_id"`).
			ColumnExpr(`"ar"."path", "si"."baseline"`).
			Where(`"f"."target_id" = ?`, tag.ID).Scan(t.Context(), &rows); err != nil {
			t.Fatal(err)
		}
		in := map[string]bool{}
		for _, r := range rows {
			in[r.Path] = r.Baseline
		}
		if len(rows) != 2 || !in["src/sonic-frr/frr/bgpd/bgp_attr.c"] || in[inSWSS.uri] {
			t.Errorf("baseline by path %v; want the result the baseline holds in it and the new one not", in)
		}
	})
}
