// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

// What the VEX document of the component hub's build costs: 16,000 components
// and 84,000 findings, some decided, some patched by the build and some closed
// by a supplier's statement, read through the document of one build, the one
// with suppliers' statements, and the statements published about it.
//
// Behind a build tag because it is a measurement and not a gate. `make
// measure` runs it; one engine at a time is OPENPSIRT_TEST_ENGINES.
package triageapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/vex"
)

// vexDecisions is how many kernel issues each decided kernel binary's decision
// names, the most one bulk decision takes.
const vexDecisions = 100

// TestMeasureTheVEXDocumentOfTheHubBuild times the reads a VEX document of the
// hub's build makes, on the statistics the load leaves and again after every
// table is analyzed, as a server start does.
//
// Once for the build alone, and once as a long-lived product holds it: the
// kernel binaries and the root images rebuilt vexRebuilds times before, and
// vexElsewhere issues the build does not hold decided in the product.
func TestMeasureTheVEXDocumentOfTheHubBuild(t *testing.T) {
	const n = 16000
	for _, lived := range []bool{false, true} {
		name := "one build"
		if lived {
			name = "a long-lived product"
		}
		t.Run(name, func(t *testing.T) { measureTheVEXDocument(t, n, lived) })
	}
}

// vexRebuilds is how many closed versions each rebuilt image of the long-lived
// product has behind its open one: a nightly build for three years.
const vexRebuilds = 1000

// vexElsewhere is how many issues the long-lived product decided that the build
// does not hold.
const vexElsewhere = 100000

func measureTheVEXDocument(t *testing.T, n int, lived bool) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		began := time.Now()
		vexSeeded(t, r, n)
		if lived {
			vexImaged(t, r, vexRebuilds)
			vexDecidedElsewhere(t, r, vexElsewhere)
		}
		t.Logf("%d components: seeded in %s", n, time.Since(began).Round(time.Second))
		slowest := &longestStatement{db: r.DB}
		deps := r.Deps
		deps.DB = dbtest.Hooked(r.DB, slowest)
		measured := *r
		measured.Handler, _ = httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, deps)
		const build = "/v1/products/mine/branches-and-tags/master/variants/broadcom/vex"
		reads := map[string]func() (string, error){}
		for _, path := range []string{build, build + "?kind=with-suppliers"} {
			reads["GET "+path] = func() (string, error) {
				got := httpapitest.AsPerson(t, &measured, "private", http.MethodGet, path, "")
				if got.Code != http.StatusOK {
					return "", fmt.Errorf("GET %s answered %d: %s", path, got.Code, got.Body.String())
				}
				var doc struct {
					Statements []json.RawMessage `json:"statements"`
				}
				if err := json.Unmarshal(got.Body.Bytes(), &doc); err != nil {
					t.Fatal(err)
				}
				return fmt.Sprintf("%d statements %s", len(doc.Statements), digest(doc.Statements)), nil
			}
		}
		product, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
		if err != nil {
			t.Fatal(err)
		}
		subject := access.Published([]int64{product.ID})
		named, err := catalog.NewStore(r.DB.DB).LocateVisible(ctx, subject, "mine", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		published := vex.NewStore(deps.DB.DB)
		reads["the statements published"] = func() (string, error) {
			built, err := published.Public(ctx, subject, named, r.BuildOf(t, httpapitest.SeededBuild))
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%d facts %s", len(built.Facts), digest(built.Facts)), nil
		}
		names := make([]string, 0, len(reads))
		for name := range reads {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, stats := range []string{"as loaded", "analyzed"} {
			if stats == "analyzed" {
				if _, err := database.AnalyzeEveryTable(ctx, r.DB); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range names {
				var took []time.Duration
				var statement time.Duration
				var said, which string
				var err error
				for i := range 4 {
					slowest.reset()
					began := time.Now()
					if said, err = reads[name](); err != nil {
						break
					}
					if i > 0 {
						took = append(took, time.Since(began))
						if longest, query := slowest.took(); longest > statement {
							statement, which = longest, query
						}
					}
				}
				if err != nil {
					query := slowest.stopped()
					if query == "" {
						t.Fatal(err)
					}
					t.Logf("%s, %s: stopped at a statement past %s: %s", stats, name, vexStatementCap, query)
					continue
				}
				slices.Sort(took)
				t.Logf("%s, %s: %s, %s; slowest statement %s: %s", stats, name,
					took[1].Round(time.Millisecond), said, statement.Round(time.Millisecond), which)
			}
		}
	})
}

// vexSeeded is the hub's build of n components with every third dependency
// finding closed, each at its own moment over a year. Three kernel binaries
// each carry a decision that a hundred of their issues do not apply, agreed,
// and a fourth one that a hundred apply. Of the closed findings, every tenth
// is patched by a claim the build makes and every tenth beside it closed by a
// supplier's statement.
func vexSeeded(t *testing.T, r *httpapitest.Reach, n int) {
	t.Helper()
	ctx := t.Context()
	hubSeeded(t, r, n, 4000)
	now := time.Now().UTC()
	for d := range 100 {
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"closed_at" = ?`, now.Add(-time.Duration(d*87)*time.Hour)).
			Where(`"kind" <> ?`, kind.Analysis).Where(`"id" % 3 = 0`).Where(`"id" % 300 BETWEEN ? AND ?`, 3*d, 3*d+2).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	decided := func(binary int, offset int, body string) {
		issues := make([]string, 0, vexDecisions)
		for v := range vexDecisions {
			issues = append(issues, fmt.Sprintf("%q", fmt.Sprintf("CVE-2026-%d", 100000+v*7+offset)))
		}
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/products/mine/branches-and-tags/master/variants/broadcom/components/linux-image-%d/bulk-decision", binary),
			`{"vulnerabilities":[`+strings.Join(issues, ",")+`],`+body+`}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding at linux-image-%d answered %d: %s", binary, got.Code, got.Body.String())
		}
		var made struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		r.Agreed(t, made.DecisionID)
	}
	for binary := range 3 {
		decided(binary, binary, `"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
			`"selected_by":"the driver","reasoning":"The driver is not built."`)
	}
	decided(3, 3, `"outcome":"affected","selected_by":"the driver","reasoning":"The driver is built and reachable."`)

	build := r.BuildOf(t, httpapitest.SeededBuild)
	var scan int64
	if err := r.DB.DB.NewSelect().TableExpr(`"scan"`).ColumnExpr(`MIN("id")`).
		Where(`"build_id" = ?`, build).Scan(ctx, &scan); err != nil {
		t.Fatal(err)
	}
	claim := map[string]any{
		"build_id": build, "identity": "measured-patch", "vulnerability": "CVE-2026-100000",
		"status": "fixed", "origin": "declared", "opened_scan_id": scan,
	}
	if _, err := r.DB.DB.NewInsert().Model(&claim).TableExpr(`"suppression"`).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var patch int64
	if err := r.DB.DB.NewSelect().TableExpr(`"suppression"`).ColumnExpr(`MAX("id")`).
		Where(`"identity" = ?`, "measured-patch").Scan(ctx, &patch); err != nil {
		t.Fatal(err)
	}
	var person int64
	if err := r.DB.DB.NewSelect().TableExpr(`"person"`).ColumnExpr(`MIN("id")`).Scan(ctx, &person); err != nil {
		t.Fatal(err)
	}
	product, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	statement := &finding.Statement{
		ProductID: product.ID, Publisher: "acme", Vulnerability: "cve-2026-100000",
		Component: "linux-image-0", Status: "not_affected", Justification: "component_not_present",
		Source: finding.FromVex, Document: "acme.json", Digest: strings.Repeat("0", 64),
		UploadedBy: person, UploadedAt: now,
	}
	if _, err := r.DB.DB.NewInsert().Model(statement).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	for _, closed := range []struct {
		because string
		column  string
		by      int64
		at      int
	}{{string(finding.Patched), "suppressed_by", patch, 0}, {string(finding.Disclaimed), "stated_by", statement.ID, 3}} {
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"closed_because" = ?`, closed.because).Set(`? = ?`, bun.Ident(closed.column), closed.by).
			Where(`"build_id" = ?`, build).Where(`"closed_at" IS NOT NULL`).Where(`"kind" <> ?`, kind.Analysis).
			Where(`"id" % 30 = ?`, closed.at).
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// vexImaged makes each kernel binary and the root of the hub's build an image
// stating its own identifier, with history closed versions behind it, as
// nightly rebuilds of one image leave them.
func vexImaged(t *testing.T, r *httpapitest.Reach, history int) {
	t.Helper()
	ctx := t.Context()
	build := r.BuildOf(t, httpapitest.SeededBuild)
	var scan int64
	if err := r.DB.DB.NewSelect().TableExpr(`"scan"`).ColumnExpr(`MIN("id")`).
		Where(`"build_id" = ?`, build).Scan(ctx, &scan); err != nil {
		t.Fatal(err)
	}
	var nodes []struct {
		ID   int64  `bun:"id"`
		Name string `bun:"name"`
		Purl string `bun:"purl"`
	}
	if err := r.DB.DB.NewSelect().TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "n"."component_id"`).
		ColumnExpr(`"n"."id", "c"."name", COALESCE("n"."purl", "c"."purl", '') AS "purl"`).
		Where(`"n"."build_id" = ?`, build).Where(`"n"."closed_scan_id" IS NULL`).
		Scan(ctx, &nodes); err != nil {
		t.Fatal(err)
	}
	var closed, open []graph.ImageVersion
	for _, n := range nodes {
		if n.Name != "sonic-image" && !strings.HasPrefix(n.Name, "linux-image-") {
			continue
		}
		for v := range history {
			closed = append(closed, graph.ImageVersion{NodeID: n.ID, Version: fmt.Sprintf("0.%d", v),
				Purl: fmt.Sprintf("%s-rebuild.%d", n.Purl, v), OpenedScanID: scan, ClosedScanID: &scan})
		}
		open = append(open, graph.ImageVersion{NodeID: n.ID, Version: "1.0", Purl: n.Purl, OpenedScanID: scan})
	}
	for _, rows := range [][]graph.ImageVersion{closed, open} {
		if err := database.InBatches(ctx, r.DB.DB, rows); err != nil {
			t.Fatal(err)
		}
	}
}

// vexDecidedElsewhere files count issues the hub's build does not hold, each
// with an agreed decision in the product, as builds a long-lived product no
// longer ships leave them.
func vexDecidedElsewhere(t *testing.T, r *httpapitest.Reach, count int) {
	t.Helper()
	ctx := t.Context()
	var model triage.DecisionOccurrence
	if err := r.DB.DB.NewSelect().Model(&model).
		Where(`"de"."live_key" IS NOT NULL`).Where(`"de"."state" = ?`, triage.Approved).
		OrderExpr(`"de"."id"`).Limit(1).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	var issueKind finding.Vulnerability
	if err := r.DB.DB.NewSelect().Model(&issueKind).Where(`"vu"."id" = ?`, model.VulnerabilityID).
		Scan(ctx); err != nil {
		t.Fatal(err)
	}
	const batch = 500
	for from := 0; from < count; from += batch {
		issues := make([]finding.Vulnerability, 0, batch)
		for i := from; i < min(from+batch, count); i++ {
			name := fmt.Sprintf("CVE-2020-%d", 100000+i)
			issues = append(issues, finding.Vulnerability{Identifier: name, IdentifierFolded: strings.ToLower(name),
				Kind: issueKind.Kind, Severity: "low", FirstSeenAt: model.ProposedAt})
		}
		if _, err := r.DB.DB.NewInsert().Model(&issues).Value("issue_id", "0").Exec(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.DB.DB.NewUpdate().TableExpr(`"vulnerability"`).Set(`"issue_id" = "id"`).
		Where(`"issue_id" = 0`).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	var ids []int64
	if err := r.DB.DB.NewSelect().TableExpr(`"vulnerability"`).Column("id").
		Where(`"identifier_folded" LIKE 'cve-2020-%'`).Scan(ctx, &ids); err != nil {
		t.Fatal(err)
	}
	if len(ids) != count {
		t.Fatalf("filed %d issues elsewhere, want %d", len(ids), count)
	}
	decided := make([]triage.DecisionOccurrence, 0, count)
	for _, id := range ids {
		row := model
		row.ID, row.VulnerabilityID = 0, id
		key := fmt.Sprintf("elsewhere-%d", id)
		row.LiveKey = &key
		decided = append(decided, row)
	}
	if err := database.InBatches(ctx, r.DB.DB, decided); err != nil {
		t.Fatal(err)
	}
}

// vexStatementCap is how long one statement runs before it is stopped, so a
// plan reading the build once per row is reported as past it rather than run
// for hours.
const vexStatementCap = 30 * time.Second

// longestStatement keeps how long the longest statement since the last reset
// took, and the head of it, and stops a statement past vexStatementCap in the
// driver and on the server.
type longestStatement struct {
	db      *database.DB
	mu      sync.Mutex
	longest time.Duration
	query   string
	past    string
	cancels map[*bun.QueryEvent]context.CancelFunc
}

func (s *longestStatement) BeforeQuery(ctx context.Context, event *bun.QueryEvent) context.Context {
	capped, cancel := context.WithTimeout(ctx, vexStatementCap)
	context.AfterFunc(capped, func() {
		if !errors.Is(capped.Err(), context.DeadlineExceeded) {
			return
		}
		s.mu.Lock()
		s.past = head(event.Query)
		s.mu.Unlock()
		_ = dbtest.StopPast(s.db, vexStatementCap-time.Second)
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancels == nil {
		s.cancels = map[*bun.QueryEvent]context.CancelFunc{}
	}
	s.cancels[event] = cancel
	return capped
}

func (s *longestStatement) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cancel := s.cancels[event]; cancel != nil {
		cancel()
		delete(s.cancels, event)
	}
	if took := time.Since(event.StartTime); took > s.longest {
		s.longest = took
		s.query = head(event.Query)
	}
}

// digest is a short hash of what a read answered, with every moment taken
// out, so two runs over fixtures seeded at different times are seen to answer
// the same.
func digest(answered any) string {
	body, err := json.Marshal(answered)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(moment.ReplaceAll(body, []byte(`"moment"`)))
	return hex.EncodeToString(sum[:6])
}

// moment is a moment as JSON writes one.
var moment = regexp.MustCompile(`"\d{4}-\d{2}-\d{2}T[^"]*"`)

// head is the start of a statement, on one line.
func head(query string) string {
	query = strings.Join(strings.Fields(query), " ")
	if len(query) > 160 {
		query = query[:160]
	}
	return query
}

func (s *longestStatement) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.longest, s.query, s.past = 0, "", ""
}

func (s *longestStatement) took() (time.Duration, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.longest, s.query
}

// stopped is the statement stopped past the cap since the last reset, empty
// where none was.
func (s *longestStatement) stopped() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.past
}
