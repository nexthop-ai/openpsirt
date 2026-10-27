// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
	"github.com/nexthop-ai/openpsirt/internal/triage"
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

// inside is a result stated with the function it is in and a fingerprint,
// either of which may be empty.
type inside struct {
	sent
	function, print string
}

func (s inside) json() string {
	loc := fmt.Sprintf(`{"physicalLocation":{"artifactLocation":{"uri":%q,"uriBaseId":%q},"region":{"startLine":%d}}`,
		s.uri, s.base, s.line)
	if s.function != "" {
		loc += fmt.Sprintf(`,"logicalLocations":[{"fullyQualifiedName":%q}]`, s.function)
	}
	out := fmt.Sprintf(`{"ruleId":%q,"message":{"text":%q},"locations":[%s}]`, s.rule, s.message, loc)
	if s.print != "" {
		out += fmt.Sprintf(`,"partialFingerprints":{"hash/v1":%q}`, s.print)
	}
	return out + "}"
}

// quoted is a result stated with the source at it.
type quoted struct {
	sent
	snippet string
}

func (s quoted) json() string {
	return fmt.Sprintf(`{"ruleId":%q,"message":{"text":%q},"locations":[{"physicalLocation":`+
		`{"artifactLocation":{"uri":%q,"uriBaseId":%q},"region":{"startLine":%d,"snippet":{"text":%q}}}}]}`,
		s.rule, s.message, s.uri, s.base, s.line, s.snippet)
}

// document is one run of clang-tidy over a checkout holding FRR as a
// submodule, analyzing units of the ten it was meant to. Its rule list holds
// a rule that never fires, so the list is the rule set.
func document(results []sent, units int) string {
	rs := make([]interface{ json() string }, len(results))
	for i, r := range results {
		rs[i] = r
	}
	return documentOf(rs, units, "")
}

// documentOf is document with results stated any way, and the run's salt
// mark where salt is set.
func documentOf(results []interface{ json() string }, units int, salt string) string {
	rs := make([]string, len(results))
	for i, r := range results {
		rs[i] = r.json()
	}
	salted := ""
	if salt != "" {
		salted = fmt.Sprintf(`,"openpsirt/salt":%q`, salt)
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clang-tidy","version":"18.1.3",` +
		`"rules":[{"id":"bugprone-use-after-move","properties":{"tags":["external/cwe/cwe-416"]}},` +
		`{"id":"bugprone-dangling-handle"}]}},` +
		`"originalUriBaseIds":{"SRCROOT":{"uri":"file:///home/builder/sonic/"},` +
		`"FRR":{"uri":"src/sonic-frr/frr/","uriBaseId":"SRCROOT"}},` +
		`"versionControlProvenance":[` +
		`{"repositoryUri":"https://github.com/sonic-net/sonic-buildimage","revisionId":"abc","mappedTo":{"uriBaseId":"SRCROOT"}},` +
		`{"repositoryUri":"https://github.com/FRRouting/frr.git","revisionId":"def","mappedTo":{"uriBaseId":"FRR"}}],` +
		fmt.Sprintf(`"properties":{"openpsirt/unitsExpected":%d,"openpsirt/unitsAnalyzed":%d%s},`, 10, units, salted) +
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
func (w *world) inventory(t *testing.T, buildID int64) {
	t.Helper()
	w.inventoryWith(t, buildID, graph.Described{Purl: "pkg:github/frrouting/frr@10.2", Name: "frr", Version: "10.2"})
}

// inventoryWith records a read inventory for a build: the product, and FRR
// as the inventory describes it.
func (w *world) inventoryWith(t *testing.T, buildID int64, frr graph.Described) {
	t.Helper()
	ctx := t.Context()
	scans := ingest.NewStore(w.DB.DB)
	scan, outcome, err := scans.Record(ctx, ingest.Arriving{
		BuildID: buildID, ContentHash: fmt.Sprintf("inventory-%d", buildID),
		BuiltAt: time.Now().UTC().Add(-2 * time.Hour), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record the inventory: %v %v", outcome, err)
	}
	root := graph.Described{Purl: "pkg:generic/sonic@1.0", Name: "sonic", Version: "1.0"}
	if _, err := fixture.ApplyGraph(ctx, w.DB.DB, buildID, scan.ID, graph.Snapshot{
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
		Where(`"n"."build_id" = ?`, buildID).Scan(ctx, &nodes); err != nil {
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
func (w *world) send(t *testing.T, buildID int64, built time.Time, doc string) (*series.Run, series.Status) {
	t.Helper()
	run := w.receive(t, buildID, built, doc)
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
func (w *world) receive(t *testing.T, buildID int64, built time.Time, doc string) *series.Run {
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
			ProductID: w.Product.ID, BuildID: buildID, Kind: kind.Analysis, Series: given.Series,
			ContentHash: hash, BuiltAt: given.BuiltAt, Params: given.Params,
		})
		if err != nil {
			return err
		}
		repositories, err := sourcelink.NewStore(tx).Config(ctx, w.Product.ID)
		if err != nil {
			return err
		}
		placed, err := Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes, repositories.Snippets)
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

// drops sets the share and floor past which a run is a sharp drop.
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

// codeFindings is the build's open analysis findings, by component.
func (w *world) codeFindings(t *testing.T, buildID int64) []finding.Finding {
	t.Helper()
	var rows []finding.Finding
	where, args := kind.In(`"f"."kind"`, []kind.Kind{kind.Analysis})
	if err := w.DB.DB.NewSelect().Model(&rows).
		Where(`"f"."build_id" = ?`, buildID).Where(where, args...).
		OrderExpr(`"f"."id" ASC`).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestARunWaitsUntilItsBuildHasAnInventory(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		built := time.Now().UTC().Add(-time.Hour)
		run, status := w.send(t, w.Build.ID, built, document([]sent{inFRR}, 10))
		if status != series.Waiting {
			t.Fatalf("status %s; want waiting with no inventory read", status)
		}
		if got := w.codeFindings(t, w.Build.ID); len(got) != 0 {
			t.Errorf("%d findings opened before the build had components", len(got))
		}
		w.inventory(t, w.Build.ID)
		status, err := w.applier.Apply(t.Context(), run.ID)
		if err != nil || status != series.Applied {
			t.Fatalf("status %s, %v; want applied once the inventory is read", status, err)
		}
	})
}

func TestAResultIsAnInternalFindingOnTheComponentItsRepositoryBuilt(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		run, status := w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour),
			document([]sent{inFRR, inSWSS}, 10))
		if status != series.Applied {
			t.Fatalf("status %s (%s); want applied", status, run.Failure)
		}
		if r := receiptOf(t, run); r.Opened != 2 {
			t.Errorf("receipt %+v; want two opened", r)
		}
		if run.Comparable == nil || !*run.Comparable {
			t.Errorf("the series' first run with nothing before it is comparable: %v", run.Comparable)
		}
		codeFindings := w.codeFindings(t, w.Build.ID)
		if len(codeFindings) != 2 {
			t.Fatalf("%d findings; want 2", len(codeFindings))
		}
		on := map[int64]int{}
		for _, f := range codeFindings {
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
			Where(`"vu"."id" = ?`, codeFindings[0].VulnerabilityID).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if issue.Identifier != "clang-tidy/bugprone-use-after-move" || issue.Kind != kind.Rule {
			t.Errorf("filed under %q, a %s; want the tool's rule", issue.Identifier, issue.Kind)
		}
	})
}

func TestAComparableRunThatMissesAResultMarksItNoLongerDetected(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR, inSWSS}, 10))

		run, _ := w.send(t, w.Build.ID, start.Add(time.Hour), document([]sent{inSWSS}, 10))
		if r := receiptOf(t, run); r.Seen != 1 || r.NoLongerDetected != 1 || r.Opened != 0 {
			t.Errorf("receipt %+v; want one seen and one no longer detected", r)
		}
		if got := w.codeFindings(t, w.Build.ID); len(got) != 2 {
			t.Errorf("%d findings; no longer detected closes nothing", len(got))
		}

		run, _ = w.send(t, w.Build.ID, start.Add(2*time.Hour), document([]sent{inFRR, inSWSS}, 10))
		if r := receiptOf(t, run); r.Seen != 2 || r.Returned != 1 || r.Opened != 0 {
			t.Errorf("receipt %+v; want both seen, one of them returned", r)
		}
	})
}

func TestARunShortOfItsUnitsMarksNothingNoLongerDetected(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR, inSWSS}, 10))
		run, _ := w.send(t, w.Build.ID, start.Add(time.Hour), document([]sent{inSWSS}, 4))
		if run.Comparable == nil || *run.Comparable || run.Reason != series.UnitsShort {
			t.Errorf("comparable %v for %q; want not comparable, units short", run.Comparable, run.Reason)
		}
		if r := receiptOf(t, run); r.NoLongerDetected != 0 || r.Seen != 1 {
			t.Errorf("receipt %+v; want one seen and none marked", r)
		}
	})
}

func TestARunBuiltBeforeTheLastAppliedIsSuperseded(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR}, 10))
		_, status := w.send(t, w.Build.ID, start.Add(-time.Hour), document([]sent{inSWSS}, 10))
		if status != series.Superseded {
			t.Fatalf("status %s; want superseded", status)
		}
		if got := w.codeFindings(t, w.Build.ID); len(got) != 1 {
			t.Errorf("%d findings; a superseded run opens nothing", len(got))
		}
	})
}

func TestARunThatMarksMostOfABuildIsAppliedAndToldOnce(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		var told []Drop
		w.applier.TellingDrops(func(_ context.Context, d Drop) { told = append(told, d) })
		w.inventory(t, w.Build.ID)
		w.drops(t, "50", "1")
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR, inSWSS}, 10))
		run, status := w.send(t, w.Build.ID, start.Add(time.Hour), document(nil, 10))
		if status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		if r := receiptOf(t, run); !r.SharpDrop || r.NoLongerDetected != 2 {
			t.Errorf("receipt %+v; want a sharp drop that marked both", r)
		}
		if len(told) != 1 || told[0].RunID != run.ID || told[0].Missed != 2 || told[0].Live != 2 {
			t.Errorf("told %+v; want this run once, two of two", told)
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
				w.inventory(t, w.Build.ID)
				w.drops(t, c.share, c.floor)
				start := time.Now().UTC().Add(-3 * time.Hour)
				all := spread(4)
				w.send(t, w.Build.ID, start, document(all, 10))
				run, status := w.send(t, w.Build.ID, start.Add(time.Hour), document(all[c.missed:], 10))
				if status != series.Applied {
					t.Fatalf("status %s; want applied", status)
				}
				if r := receiptOf(t, run); r.NoLongerDetected != c.missed || r.SharpDrop {
					t.Errorf("receipt %+v; want %d no longer detected and no sharp drop", r, c.missed)
				}
			})
		})
	}
}

func TestARunWaitingADayForItsInventoryFails(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		run, status := w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
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
		run := w.receive(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
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
		w.inventory(t, w.Build.ID)
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

func TestAResultIsPlacedOnTheComponentWhoseReferenceNamesItsRepository(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		withCredential := graph.Described{Purl: "pkg:deb/debian/frr@10.2", Name: "frr", Version: "10.2", //nolint:gosec // G101: a placeholder credential to be removed
			Repository: "https://ci:SECRET@github.com/FRRouting/frr.git?ref=main"}
		w.inventoryWith(t, w.Build.ID, withCredential)
		if _, status := w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour),
			document([]sent{inFRR}, 10)); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		codeFindings := w.codeFindings(t, w.Build.ID)
		if len(codeFindings) != 1 || codeFindings[0].ComponentID != w.frr {
			t.Fatalf("findings %+v; want one on FRR (%d)", codeFindings, w.frr)
		}
		var held []string
		if err := w.DB.DB.NewSelect().TableExpr(`"graph_node" AS "n"`).ColumnExpr(`"n"."repository"`).
			Where(`"n"."repository" IS NOT NULL`).Scan(t.Context(), &held); err != nil {
			t.Fatal(err)
		}
		if len(held) != 1 || held[0] != "https://github.com/FRRouting/frr.git" {
			t.Errorf("the build holds %q; want the repository without its credential or query", held)
		}
	})
}

func TestPlacedResultsPastTheByteBoundAreRefused(t *testing.T) {
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(strings.NewReader(document(spread(50), 10)))
	if err != nil {
		t.Fatal(err)
	}
	placed, err := Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	var held bytes.Buffer
	if err := placed.encode(&held); err != nil {
		t.Fatal(err)
	}
	if _, err := Place([]sarif.Log{log}, "", int64(held.Len()), nil); err != nil {
		t.Errorf("refused at exactly its size: %v", err)
	}
	_, err = Place([]sarif.Log{log}, "", int64(held.Len())-1, nil)
	if !refusal.In(err) || !strings.Contains(err.Error(), "configured limit") {
		t.Errorf("one byte short answered %v; want a refusal naming the limit", err)
	}
}

func TestARepositoryIsRecordedWithoutItsCredential(t *testing.T) {
	doc := strings.Replace(document(spread(1), 10), "https://github.com/FRRouting/frr.git",
		"https://gitlab-ci-token:SECRET@github.com/FRRouting/frr.git", 1)
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	placed, err := Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes, nil)
	if err != nil {
		t.Fatal(err)
	}
	var remotes []string
	for _, m := range placed.Modules {
		remotes = append(remotes, m.Remote)
	}
	if !slices.Contains(remotes, "https://github.com/FRRouting/frr.git") || strings.Contains(strings.Join(remotes, " "), "SECRET") {
		t.Errorf("recorded %v; want FRR's remote without its credential", remotes)
	}
}

func TestWhatARunSaysOnceIsHeldOnce(t *testing.T) {
	tool := strings.Repeat("T", 4096)
	doc := strings.Replace(document(spread(200), 10), `"name":"clang-tidy"`, `"name":"`+tool+`"`, 1)
	log, err := sarif.NewUpload(sarif.DefaultLimits()).Read(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	placed, err := Place([]sarif.Log{log}, "", sarif.DefaultLimits().MaxBytes, nil)
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
		w.inventory(t, w.Build.ID)
		failed := sent{"clang-diagnostic-error", "", "file:///tmp/build/generated.h", "unknown type name", 3}
		run, _ := w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR, failed}, 10))
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
		run := w.receive(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
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
		w.inventory(t, w.Build.ID)
		ctx := t.Context()
		run := w.receive(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
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

func TestAResultOnAnotherBuildCarriesTheOccurrenceItWasJudgedAt(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		tag, err := w.Catalog.BuildFor(t.Context(), w.Tag.ID, w.Customer.ID)
		if err != nil {
			t.Fatal(err)
		}
		w.inventory(t, tag.ID)
		built := time.Now().UTC().Add(-time.Hour)
		w.send(t, w.Build.ID, built, document([]sent{inFRR}, 10))
		w.send(t, tag.ID, built, document([]sent{inFRR}, 10))
		a, b := w.codeFindings(t, w.Build.ID), w.codeFindings(t, tag.ID)
		if len(a) != 1 || len(b) != 1 {
			t.Fatalf("%d and %d findings; want one on each build", len(a), len(b))
		}
		if a[0].OccurrenceIdentity != b[0].OccurrenceIdentity {
			t.Errorf("occurrences %q and %q; want one occurrence, so a decision on it reaches both", a[0].OccurrenceIdentity, b[0].OccurrenceIdentity)
		}
	})
}

func TestASeriesFirstRunPutsEveryCodeFindingInTheQueue(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		if _, status := w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour),
			document([]sent{inFRR, inSWSS}, 10)); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		reader := w.holding(t, "analyst", access.InternalRead)
		queue, err := CodeFindingsOf(t.Context(), w.DB.DB, reader, Scope{ProductID: w.Product.ID}, "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if queue.Total != 2 || queue.ByState[Open] != 2 {
			t.Errorf("queue of %d, %v by state; want both code findings of the first run open in it",
				queue.Total, queue.ByState)
		}
	})
}

// matchedOn is how each of the build's code findings was last paired, by finding.
func (w *world) matchedOn(t *testing.T, buildID int64) map[int64]string {
	t.Helper()
	var rows []result
	if err := w.DB.DB.NewSelect().Model(&rows).Column("finding_id", "matched_on").
		Join(`JOIN "finding" AS "f" ON "f"."id" = "ar"."finding_id"`).
		Where(`"f"."build_id" = ?`, buildID).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	out := map[int64]string{}
	for _, r := range rows {
		out[r.FindingID] = r.MatchedOn
	}
	return out
}

func TestAResultMovedWithNoFingerprintIsSeenAgainOnItsNearestLine(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR}, 10))
		first := w.codeFindings(t, w.Build.ID)

		moved := inFRR
		moved.line += 6
		run, _ := w.send(t, w.Build.ID, start.Add(time.Hour), document([]sent{moved}, 10))
		if r := receiptOf(t, run); r.Seen != 1 || r.Opened != 0 || r.NoLongerDetected != 0 || r.Probable != 1 {
			t.Errorf("receipt %+v; want the code finding seen again, probably", r)
		}
		codeFindings := w.codeFindings(t, w.Build.ID)
		if len(codeFindings) != 1 || codeFindings[0].ID != first[0].ID {
			t.Fatalf("code findings %+v; want the one code finding the first run opened", codeFindings)
		}
		if on := w.matchedOn(t, w.Build.ID)[codeFindings[0].ID]; on != onLine {
			t.Errorf("paired on %q; want the nearest line", on)
		}
	})
}

func TestAResultMovedWithinItsFunctionIsSeenAgainOnTheFunction(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		before := inside{inFRR, "bgp_attr_parse", "a1"}
		w.send(t, w.Build.ID, start, documentOf([]interface{ json() string }{before}, 10, ""))
		after := before
		after.line, after.print = 400, "b2"
		run, _ := w.send(t, w.Build.ID, start.Add(time.Hour), documentOf([]interface{ json() string }{after}, 10, ""))
		if r := receiptOf(t, run); r.Seen != 1 || r.Opened != 0 || r.Probable != 1 {
			t.Errorf("receipt %+v; want the code finding seen again, probably", r)
		}
		for _, on := range w.matchedOn(t, w.Build.ID) {
			if on != onFunction {
				t.Errorf("paired on %q; want the function", on)
			}
		}
	})
}

func TestTheFirstRunOnABranchTakesTheOccurrencesOfTheLineItWasCutFrom(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		tag := w.BuildFor(w.Tag, w.Customer)
		w.inventory(t, w.Build.ID)
		w.inventory(t, tag.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR}, 10))

		moved := inFRR
		moved.line += 3
		run, _ := w.send(t, tag.ID, start.Add(time.Hour), document([]sent{moved}, 10))
		if r := receiptOf(t, run); r.Opened != 1 || r.Inherited != 1 || r.Probable != 1 {
			t.Errorf("receipt %+v; want one code finding opened, carried probably from the branch", r)
		}
		branch, cut := w.codeFindings(t, w.Build.ID), w.codeFindings(t, tag.ID)
		if len(branch) != 1 || len(cut) != 1 || branch[0].OccurrenceIdentity != cut[0].OccurrenceIdentity {
			t.Errorf("branch %+v, tag %+v; want one code finding each at one occurrence", branch, cut)
		}
	})
}

// dismissed records an approved dismissal at a code finding's occurrence.
func (w *world) dismissed(t *testing.T, codeFinding finding.Finding, at time.Time) *triage.DecisionOccurrence {
	t.Helper()
	ctx := t.Context()
	by, err := access.NewStore(w.DB.DB).Ensure(ctx, "analyst@example.com", "analyst", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reason := string(triage.FalsePositive)
	at = at.Truncate(time.Microsecond)
	decision := &triage.Decision{Kind: triage.FindingDecision, ProposedBy: by.ID, ProposedAt: at,
		Outcome: triage.Dismissed, Justification: &reason}
	if _, err := w.DB.DB.NewInsert().Model(decision).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	// Any key holding is live; the occurrence identity fits the column.
	live := codeFinding.OccurrenceIdentity
	decided := &triage.DecisionOccurrence{DecisionID: decision.ID, ProductID: w.Product.ID, VulnerabilityID: codeFinding.VulnerabilityID,
		OccurrenceIdentity: codeFinding.OccurrenceIdentity, Visibility: access.Internal, State: triage.Approved, LiveKey: &live,
		NeedsApproval: true, ProposedBy: by.ID, ProposedAt: at}
	if _, err := w.DB.DB.NewInsert().Model(decided).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return decided
}

// stateOf is a decision occurrence's state now.
func (w *world) stateOf(t *testing.T, id int64) triage.State {
	t.Helper()
	var after triage.DecisionOccurrence
	if err := w.DB.DB.NewSelect().Model(&after).Where(`"de"."id" = ?`, id).Scan(t.Context()); err != nil {
		t.Fatal(err)
	}
	return after.State
}

func TestARotatedSaltLapsesTheDismissalsOfTiesAlone(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		// One result alone under its key without the fingerprint, and two
		// that share one: the same rule, file, message and function.
		lone := inside{inFRR, "bgp_attr_parse", "a1"}
		tied, twin := inside{inSWSS, "Orch::doTask", "b1"}, inside{inSWSS, "Orch::doTask", "b2"}
		twin.line = 40
		w.send(t, w.Build.ID, start, documentOf([]interface{ json() string }{lone, tied, twin}, 10, "0123456789abcdef"))
		codeFindings := w.codeFindings(t, w.Build.ID)
		if len(codeFindings) != 3 {
			t.Fatalf("code findings %+v; want three", codeFindings)
		}
		decided := map[int64]*triage.DecisionOccurrence{}
		for _, codeFinding := range codeFindings {
			decided[codeFinding.ID] = w.dismissed(t, codeFinding, start.Add(time.Minute))
		}

		var heard []triage.ForPerson
		w.applier.TellingLapses(func(_ context.Context, told []triage.ForPerson) { heard = append(heard, told...) })

		// The salt rotates, so every fingerprint changes and nothing else.
		lone.print, tied.print, twin.print = "c1", "c2", "c3"
		run, _ := w.send(t, w.Build.ID, start.Add(time.Hour),
			documentOf([]interface{ json() string }{lone, tied, twin}, 10, "fedcba9876543210"))
		if r := receiptOf(t, run); !r.FingerprintsChanged || r.Opened != 0 || r.Seen != 3 || r.Probable != 2 {
			t.Errorf("receipt %+v; want a fingerprint change seeing all three, the two ties probably", r)
		}
		on := w.matchedOn(t, w.Build.ID)
		for _, codeFinding := range codeFindings {
			want := triage.LapsedState
			if codeFinding.ID == codeFindings[0].ID {
				want = triage.Approved
			}
			if got := w.stateOf(t, decided[codeFinding.ID].ID); got != want {
				t.Errorf("code finding %d paired on %q: dismissal %q; want %q", codeFinding.ID, on[codeFinding.ID], got, want)
			}
		}
		// Its proposer is told once, of both, as internal work.
		if len(heard) != 1 || heard[0].Rows != 2 || !heard[0].Probable || !heard[0].Internal {
			t.Errorf("told %+v; want the proposer told once of two lapsed decisions on code findings", heard)
		}
	})
}

func TestADismissalLapsesOnABranchItsCodeFindingIsCarriedToProbably(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		tag := w.BuildFor(w.Tag, w.Customer)
		w.inventory(t, w.Build.ID)
		w.inventory(t, tag.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR}, 10))
		codeFinding := w.codeFindings(t, w.Build.ID)[0]

		decided := w.dismissed(t, codeFinding, start.Add(time.Minute))

		// The tag's first run carries the code finding from the branch on its
		// nearest line, which is probable.
		moved := inFRR
		moved.line += 3
		w.send(t, tag.ID, start.Add(time.Hour), document([]sent{moved}, 10))
		if state := w.stateOf(t, decided.ID); state != triage.LapsedState {
			t.Errorf("the dismissal of a code finding carried probably is %q; want it lapsed", state)
		}
	})
}

func TestALaterRunOnABranchTakesNothingFromTheLineItWasCutFrom(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		tag := w.BuildFor(w.Tag, w.Customer)
		w.inventory(t, w.Build.ID)
		w.inventory(t, tag.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR}, 10))
		w.send(t, tag.ID, start.Add(time.Hour), document([]sent{inSWSS}, 10))

		moved := inFRR
		moved.line += 3
		run, _ := w.send(t, tag.ID, start.Add(2*time.Hour), document([]sent{inSWSS, moved}, 10))
		if r := receiptOf(t, run); r.Opened != 1 || r.Inherited != 0 {
			t.Errorf("receipt %+v; want the moved result opened as the tag's own", r)
		}
	})
}

func TestAResultAnotherBuildHoldsTakesThatCodeFindingsPlace(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		other := w.BuildFor(w.Branch, w.Internal)
		w.inventory(t, w.Build.ID)
		w.inventory(t, other.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR}, 10))
		moved := inFRR
		moved.line += 3
		w.send(t, w.Build.ID, start.Add(time.Hour), document([]sent{moved}, 10))

		// The other variant's first run reports the result where it has moved
		// to. The code finding's occurrence was minted from where it was first seen, so only
		// the code finding's newest key finds it.
		run, _ := w.send(t, other.ID, start.Add(2*time.Hour), document([]sent{moved}, 10))
		if r := receiptOf(t, run); r.Opened != 1 || r.Probable != 0 || r.Inherited != 0 {
			t.Errorf("receipt %+v; want one code finding opened, carried strongly", r)
		}
		here, there := w.codeFindings(t, w.Build.ID), w.codeFindings(t, other.ID)
		if len(here) != 1 || len(there) != 1 || here[0].OccurrenceIdentity != there[0].OccurrenceIdentity {
			t.Errorf("code findings %+v and %+v; want one occurrence", here, there)
		}
	})
}

func TestAClosedCodeFindingFoundAgainOpensAtItsOccurrence(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, w.Build.ID, start, document([]sent{inFRR}, 10))
		closed := w.codeFindings(t, w.Build.ID)[0]
		if _, err := w.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"closed_at" = ?`, start.Add(time.Minute)).
			Where(`"id" = ?`, closed.ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		run, _ := w.send(t, w.Build.ID, start.Add(time.Hour), document([]sent{inFRR}, 10))
		if r := receiptOf(t, run); r.Opened != 1 || r.Reopened != 1 {
			t.Errorf("receipt %+v; want one code finding opened at a closed code finding's occurrence", r)
		}
		codeFindings := w.codeFindings(t, w.Build.ID)
		if len(codeFindings) != 2 || codeFindings[1].OccurrenceIdentity != closed.OccurrenceIdentity {
			t.Errorf("code findings %+v; want a second at the first's occurrence", codeFindings)
		}
	})
}

func TestARunFingerprintedDifferentlyFromTheBuildsLastIsAFingerprintChange(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-5 * time.Hour)
		plain := inside{inFRR, "", ""}
		printed := inside{inFRR, "", "a1"}
		for i, c := range []struct {
			result inside
			salt   string
			want   bool
		}{
			{plain, "", false},
			{printed, "", true},
			{printed, "", false},
			{printed, "0123456789abcdef", true},
			{printed, "fedcba9876543210", true},
		} {
			run, status := w.send(t, w.Build.ID, start.Add(time.Duration(i)*time.Hour),
				documentOf([]interface{ json() string }{c.result}, 10, c.salt))
			if status != series.Applied || run.FingerprintsChanged != c.want || receiptOf(t, run).FingerprintsChanged != c.want {
				t.Errorf("run %d: %s, fingerprints changed %v; want %v", i, status, run.FingerprintsChanged, c.want)
			}
		}
	})
}

func TestAResultWithNoFingerprintBesideOthersIsNoFingerprintChange(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		elsewhere := inFRR
		elsewhere.line, elsewhere.message = 90, "z used after it was moved"
		plain := inside{elsewhere, "", ""}
		printed := inside{inFRR, "", "a1"}
		other := inside{inSWSS, "", "b2"}
		for i, results := range [][]interface{ json() string }{
			{printed, other},
			{printed, other, plain},
			{printed, other},
		} {
			run, _ := w.send(t, w.Build.ID, start.Add(time.Duration(i)*time.Hour), documentOf(results, 10, ""))
			if i > 0 && run.FingerprintsChanged {
				t.Errorf("run %d: a fingerprint change where one result carried no fingerprint (%q)", i, run.Fingerprints)
			}
		}
	})
}

func TestARunReportingNothingLeavesTheFingerprintsAsTheyWere(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		start := time.Now().UTC().Add(-5 * time.Hour)
		const salt = "0123456789abcdef"
		printed := inside{inFRR, "", "a1"}
		w.send(t, w.Build.ID, start, documentOf([]interface{ json() string }{printed}, 10, salt))
		// Short of its units, so it marks nothing no longer detected and is never
		// a sharp drop. Its salt mark alone says nothing of how results are
		// fingerprinted.
		empty, _ := w.send(t, w.Build.ID, start.Add(time.Hour), documentOf(nil, 4, salt))
		if empty.Fingerprints != "" {
			t.Errorf("a run reporting nothing carries %q", empty.Fingerprints)
		}
		run, _ := w.send(t, w.Build.ID, start.Add(2*time.Hour), documentOf([]interface{ json() string }{printed}, 10, salt))
		if run.FingerprintsChanged {
			t.Errorf("a fingerprint change after a run that reported nothing")
		}
	})
}

func TestAClosedCodeFindingFoundAgainIsReopenedWhereAnOlderBuildHoldsItToo(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		other := w.BuildFor(w.Branch, w.Internal)
		w.inventory(t, w.Build.ID)
		w.inventory(t, other.ID)
		start := time.Now().UTC().Add(-3 * time.Hour)
		w.send(t, other.ID, start, document([]sent{inFRR}, 10))
		w.send(t, w.Build.ID, start, document([]sent{inFRR}, 10))
		closed := w.codeFindings(t, w.Build.ID)[0]
		if _, err := w.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"closed_at" = ?`, start.Add(time.Minute)).
			Where(`"id" = ?`, closed.ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		run, _ := w.send(t, w.Build.ID, start.Add(time.Hour), document([]sent{inFRR}, 10))
		if r := receiptOf(t, run); r.Reopened != 1 {
			t.Errorf("receipt %+v; want the build's own closed code finding reopened", r)
		}
	})
}

func TestSourceIsStoredOnlyUnderAPathTheProductKeepsItFor(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		yes := true
		if err := sourcelink.NewStore(w.DB.DB).Replace(t.Context(), w.Product.ID,
			sourcelink.Config{Paths: []sourcelink.Path{{Prefix: "src/sonic-frr", Snippets: &yes}}}); err != nil {
			t.Fatal(err)
		}
		run, status := w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), documentOf(
			[]interface{ json() string }{quoted{inFRR, "free(x); use(x);"}, quoted{inSWSS, "private();"}}, 10, ""))
		if status != series.Applied {
			t.Fatalf("status %s (%s); want applied", status, run.Failure)
		}
		var rows []result
		if err := w.DB.DB.NewSelect().Model(&rows).OrderExpr(`"ar"."path" ASC`).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, r := range rows {
			got[r.Path] = r.Snippet
			if r.Snippet != "" && (r.SnippetLine == nil || *r.SnippetLine != inFRR.line) {
				t.Errorf("%s keeps its source from another line; want %d", r.Path, inFRR.line)
			}
		}
		if got["src/sonic-frr/frr/bgpd/bgp_attr.c"] != "free(x); use(x);" || got["src/sonic-swss/orchagent/orch.cpp"] != "" {
			t.Errorf("stored %v; want FRR's source alone", got)
		}
		if r := receiptOf(t, run); r.Discarded["snippets"] != 1 {
			t.Errorf("receipt discards %v; want the one snippet outside FRR", r.Discarded)
		}
	})
}

func TestARulesDocumentationOnAnAnalyzersHostIsRecordedWithItsIssue(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		const help = "https://clang.llvm.org/extra/clang-tidy/checks/bugprone/use-after-move.html"
		doc := strings.Replace(document([]sent{inFRR}, 10),
			`{"id":"bugprone-use-after-move",`, `{"id":"bugprone-use-after-move","helpUri":"`+help+`",`, 1)
		if _, status := w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), doc); status != series.Applied {
			t.Fatalf("status %s; want applied", status)
		}
		var refs []finding.Reference
		if err := w.DB.DB.NewSelect().Model(&refs).
			Where(`"vr"."vulnerability_id" = ?`, w.codeFindings(t, w.Build.ID)[0].VulnerabilityID).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(refs) != 1 || refs[0].URL != help || refs[0].Kind != finding.Documentation {
			t.Errorf("references %+v; want the rule's documentation", refs)
		}
	})
}

// holding is somebody holding one role on the world's product.
func (w *world) holding(t *testing.T, who string, role access.Role) access.Subject {
	t.Helper()
	ctx := t.Context()
	rights := access.NewStore(w.DB.DB)
	person, err := rights.Ensure(ctx, who, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rights.GrantRole(ctx, person.ID, w.Product.ID, role); err != nil {
		t.Fatal(err)
	}
	subject, err := rights.Resolve(ctx, who)
	if err != nil {
		t.Fatal(err)
	}
	return subject
}

func TestACodeFindingsEvidenceIsAnsweredOnlyWhereTheSubjectReadsIt(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		w.inventory(t, w.Build.ID)
		w.send(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
		codeFinding := w.codeFindings(t, w.Build.ID)[0]
		if _, err := EvidenceOf(t.Context(), w.DB.DB, w.holding(t, "public", access.PublicRead), &codeFinding, w.Product.ID); !errors.Is(err, finding.ErrNoOpenFinding) {
			t.Errorf("a public reader was answered %v; want no code finding", err)
		}
		got, err := EvidenceOf(t.Context(), w.DB.DB, w.holding(t, "analyst", access.InternalRead), &codeFinding, w.Product.ID)
		if err != nil || got.At.Path != "src/sonic-frr/frr/bgpd/bgp_attr.c" {
			t.Errorf("an internal reader was answered %+v, %v; want the code finding's occurrence", got.At, err)
		}
	})
}
