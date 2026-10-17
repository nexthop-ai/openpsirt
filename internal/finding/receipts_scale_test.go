// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the page of receipts costs on a real image scanned nightly.
//
// The year of nights in scale_test.go models a build of 700 components and
// times the receipts alone. This one applies the full-size switch image every
// night and times every read the page of receipts is made of, at the depth of
// a month and of a year.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it.
package finding_test

import (
	"fmt"
	"slices"
	"strconv"
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
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

const (
	// receiptNights is how many nightly builds the page is measured behind.
	receiptNights = 365
	// receiptArriving is how many issues the vulnerability database adds each
	// night against something the image ships.
	receiptArriving = 20
)

// receiptsMeasuredAt is the depths the page is timed at.
var receiptsMeasuredAt = []int{1, 30, receiptNights}

// receiptShapes is the two histories the page is measured behind: the fraction
// of the image's packages whose version moves on a night.
//
// The kernel is never among them: it holds most of the image's findings, and
// one bump of it reopens them all, which is a different measurement from a
// night. The heavier shape is what a build whose container images changed
// identity with every build accumulated, about 1,100 issues at components
// closed and opened a night.
var receiptShapes = []struct {
	name  string
	churn float64
}{
	{"quiet", 0.001},
	{"restamped", 0.01},
}

func TestMeasureThePageOfReceipts(t *testing.T) {
	doc := fullSizeImage(t)
	for _, shape := range receiptShapes {
		t.Run(shape.name, func(t *testing.T) {
			measureReceipts(t, doc, shape.churn)
		})
	}
}

// measureReceipts applies the image every night for a year, moving this
// fraction of its packages each night, and times the page of receipts.
func measureReceipts(t *testing.T, doc *sbom.Document, churn float64) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		target := w.Target.ID
		store := finding.NewStore(db.DB)
		scans := ingest.NewStore(db.DB)
		graphs := graph.NewStore(db.DB)
		documents := ingest.NewDocuments(db.DB)
		who := access.NewPerson(1, "a reader", false,
			map[int64][]access.Role{w.Product.ID: {access.PublicRead, access.PrivateRead}}, 0)

		root := graph.Described{Name: "sonic", Version: "1.0"}
		base := doc.Snapshot(root)

		// The packages that move, in a fixed order, and the kernel that does
		// not.
		var movable []int
		kernel := -1
		for i, c := range base.Components {
			switch {
			case c.Purl == "":
			case strings.Contains(c.Purl, "/linux-image-"):
				kernel = i
			default:
				movable = append(movable, i)
			}
		}
		if kernel < 0 {
			t.Fatal("the image carries no kernel, so this is not the image it models")
		}
		current := slices.Clone(base.Components)

		// tonight is the image with every bump so far applied to it.
		tonight := func() graph.Snapshot {
			moved := make(map[graph.Described]graph.Described)
			for i, c := range base.Components {
				if current[i] != c {
					moved[c] = current[i]
				}
			}
			snap := graph.Snapshot{Root: base.Root, Components: current}
			snap.Dependencies = make([]graph.Dependency, 0, len(base.Dependencies))
			for _, d := range base.Dependencies {
				if to, ok := moved[d.Parent]; ok {
					d.Parent = to
				}
				if to, ok := moved[d.Child]; ok {
					d.Child = to
				}
				snap.Dependencies = append(snap.Dependencies, d)
			}
			return snap
		}

		// reported is one issue per package, the kernel's issues, and what
		// the feed has added since the first night.
		reported := func(night int) []finding.Reported {
			var out []finding.Reported
			for i, c := range current {
				if c.Purl == "" {
					continue
				}
				out = append(out, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2026-%05d", i), Severity: "high"},
					Component: c,
				})
			}
			for k := range kernelIssues - 1 {
				out = append(out, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2025-%05d", k), Severity: "medium"},
					Component: current[kernel],
				})
			}
			for a := range (night - 1) * receiptArriving {
				c := current[movable[(a*7)%len(movable)]]
				out = append(out, finding.Reported{
					Issue:     finding.Named{Identifier: fmt.Sprintf("CVE-2027-%05d", a), Severity: "low"},
					Component: c,
				})
			}
			return out
		}

		built := time.Now().UTC().Add(-time.Duration(receiptNights) * 24 * time.Hour)
		var nightly time.Duration
		for night := 1; night <= receiptNights; night++ {
			if night > 1 {
				bumped := max(1, int(float64(len(movable))*churn))
				from := (night * bumped) % len(movable)
				for _, i := range movable[from:min(from+bumped, len(movable))] {
					c := current[i]
					was := c.Version
					c.Version = fmt.Sprintf("%s.n%d", was, night)
					c.Purl = strings.Replace(c.Purl, "@"+was, "@"+c.Version, 1)
					current[i] = c
				}
			}
			start := time.Now()
			built = built.Add(24 * time.Hour)
			scan, _, err := scans.Record(ctx, ingest.Arriving{
				TargetID: target, ContentHash: fmt.Sprintf("night-%d", night),
				BuiltAt: built, ParserVersion: "measure",
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := world.ApplyGraph(ctx, db.DB, target, scan.ID, tonight()); err != nil {
				t.Fatal(err)
			}
			// The read the upload endpoint enqueues, finished, so the run
			// below is attributed to this upload.
			read := time.Now().UTC()
			job := map[string]any{
				"kind": queue.Parse, "reference": strconv.FormatInt(scan.ID, 10),
				"state": queue.Done, "attempts": 1, "max_attempts": 5,
				"run_after": read, "created_at": read, "updated_at": read,
			}
			if _, err := db.DB.NewInsert().Model(&job).TableExpr(`"job"`).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			run, err := store.Begin(ctx, finding.Run{
				TargetID: target, Scanner: "measure", ScannerVersion: "0",
				DatabaseVersion: "0", RanHere: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Apply(ctx, target, run.ID, reported(night)); err != nil {
				t.Fatal(err)
			}
			if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
				t.Fatal(err)
			}
			nightly += time.Since(start)
			if !slices.Contains(receiptsMeasuredAt, night) {
				continue
			}

			var rows, open int
			if err := db.DB.NewSelect().TableExpr(`"finding"`).ColumnExpr("COUNT(*)").
				Scan(ctx, &rows); err != nil {
				t.Fatal(err)
			}
			if err := db.DB.NewSelect().TableExpr(`"finding"`).ColumnExpr("COUNT(*)").
				Where(`"closed_at" IS NULL`).Scan(ctx, &open); err != nil {
				t.Fatal(err)
			}
			dbtest.SettleStatistics(t, db)
			t.Logf("after night %d (%s a night on average): %d finding rows, %d open",
				night, (nightly / time.Duration(night)).Round(time.Millisecond), rows, open)

			// The page the screen asks for, read the way the handler reads it.
			// The first read warms the engine's cache; the best of the rest is
			// the number.
			const reads = 3
			best := map[string]time.Duration{}
			keep := func(part string, took time.Duration) {
				if was, ok := best[part]; !ok || took < was {
					best[part] = took
				}
			}
			var opened, closed, counted int
			for i := range reads + 1 {
				whole := time.Now()
				start := time.Now()
				page, _, err := scans.Receipts(ctx, who, target, 50, 0)
				if err != nil {
					t.Fatal(err)
				}
				receipts := time.Since(start)
				var runs, ids []int64
				for _, r := range page {
					ids = append(ids, r.Scan.ID)
					if r.RunID != nil {
						runs = append(runs, *r.RunID)
					}
				}
				start = time.Now()
				changed, err := store.Changes(ctx, who, target, runs)
				if err != nil {
					t.Fatal(err)
				}
				changes := time.Since(start)
				start = time.Now()
				if _, err := documents.Sent(ctx, ids); err != nil {
					t.Fatal(err)
				}
				sent := time.Since(start)
				start = time.Now()
				if _, err := graphs.Deltas(ctx, who, target, ids); err != nil {
					t.Fatal(err)
				}
				deltas := time.Since(start)
				start = time.Now()
				if _, err := store.LatestRun(ctx, who, target); err != nil {
					t.Fatal(err)
				}
				latest := time.Since(start)
				if i == 0 {
					continue
				}
				keep("receipts", receipts)
				keep("changes", changes)
				keep("sent", sent)
				keep("deltas", deltas)
				keep("latest", latest)
				keep("page", time.Since(whole))
				opened, closed, counted = 0, 0, len(changed)
				for _, c := range changed {
					opened += c.Opened
					closed += c.Closed
				}
			}
			ms := func(part string) string { return best[part].Round(100 * time.Microsecond).String() }
			t.Logf("    page %s · receipts %s · changes %s (%d runs, %d opened, %d closed) · "+
				"sent %s · deltas %s · last run %s",
				ms("page"), ms("receipts"), ms("changes"), counted, opened, closed,
				ms("sent"), ms("deltas"), ms("latest"))
		}
	})
}
