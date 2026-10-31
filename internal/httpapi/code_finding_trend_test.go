// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

const trendOf = "/v1/products/mine/code-finding-trend"

// codeTrend is the trend of code findings as these tests read it.
type codeTrend struct {
	Points []struct {
		At       string         `json:"at"`
		NotFixed int            `json:"not_fixed"`
		Opened   int            `json:"opened"`
		Fixed    int            `json:"fixed"`
		ByTier   map[string]int `json:"by_tier"`
		BySeries map[string]int `json:"by_series"`
		ByMethod map[string]int `json:"by_method"`
	} `json:"points"`
	Markers []struct {
		At      string `json:"at"`
		Product string `json:"product"`
		Series  string `json:"series"`
		Change  string `json:"change"`
		Reason  string `json:"reason"`
		From    string `json:"from"`
		To      string `json:"to"`
		Builds  int    `json:"builds"`
	} `json:"markers"`
	NoLongerDetected int `json:"no_longer_detected"`
}

func readTrend(t *testing.T, r *httpapitest.Reach, who, query string) codeTrend {
	t.Helper()
	var out codeTrend
	httpapitest.Read(t, r, who, trendOf+query, &out)
	return out
}

// noResults is a run with every result taken out: what the analyzer sends
// once the code it reported is gone.
func noResults(doc string) string {
	return doc[:strings.Index(doc, `"results":[`)] + `"results":[]}]}`
}

// trendSeeded is the hub's three code findings opened ten days ago, then this
// week: clang-tidy at a new version, then again not seeing its code finding,
// which is closed as fixed; cppcheck with a rule added, then again comparably not
// seeing its code finding; semgrep short of its units; and a first run of
// CodeQL opening a memory safety code finding on the library.
func trendSeeded(t *testing.T, r *httpapitest.Reach) {
	t.Helper()
	httpapitest.HubCodeFindings(t, r)
	if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
		Set(`"opened_at" = ?`, time.Now().UTC().Add(-10*24*time.Hour)).
		Where(`"kind" = ?`, kind.Analysis).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
	leak := hubQueueOf(t, r, "security-testing-reader", "?series=clang-tidy/default").Items[0].Occurrence

	hour := time.Now().UTC().Add(-time.Hour)
	upgraded := strings.Replace(httpapitest.CodeFindingRun(true),
		`"name":"clang-tidy"`, `"name":"clang-tidy","version":"19.1"`, 1)
	// The second at the new version is comparable to the one that last saw
	// the leak, so its absence is evidence the fix can rest on.
	httpapitest.ApplyRunIn(t, r, "clang-tidy/default", hour, upgraded)
	httpapitest.ApplyRunIn(t, r, "clang-tidy/default", hour.Add(30*time.Minute), noResults(upgraded))
	cppcheck := strings.Replace(httpapitest.RunInRepository("cppcheck", "https://github.com/acme/zlib", "inflate.cpp", 40),
		`{"id":"unfired"}`, `{"id":"unfired"},{"id":"another"}`, 1)
	httpapitest.ApplyRunIn(t, r, "cppcheck/default", hour, cppcheck)
	httpapitest.ApplyRunIn(t, r, "cppcheck/default", hour.Add(30*time.Minute), noResults(cppcheck))
	httpapitest.ApplyRunIn(t, r, "semgrep/default", hour, strings.Replace(
		httpapitest.RunInRepository("semgrep", "https://github.com/acme/elsewhere", "main.go", 7),
		`"openpsirt/unitsAnalyzed":1`, `"openpsirt/unitsAnalyzed":0`, 1))
	httpapitest.ApplyRunIn(t, r, "codeql/default", hour, httpapitest.OtherToolRun("codeql", "overflow", "787", "src/x.c", 5))

	at := hubBuild + "/code-findings/" + leak
	body := httpapitest.FixedBody(t, r, at, "the leak is closed")
	if w := httpapitest.AsPerson(t, r, "security-testing-triager", http.MethodPost, at+"/fixed", body); w.Code != http.StatusOK {
		t.Fatalf("closing as fixed answered %d: %s", w.Code, w.Body.String())
	}
}

func TestATrendCountsWhatIsNotFixedBySplitAndMarksWhatChanged(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		got := readTrend(t, r, "security-testing-reader", "?weeks=2")
		if len(got.Points) != 2 {
			t.Fatalf("two weeks are %d points", len(got.Points))
		}
		before, now := got.Points[0], got.Points[1]
		if before.NotFixed != 3 || before.ByTier["other"] != 3 || before.ByTier["memory-safety"] != 0 ||
			before.ByMethod["sast"] != 3 || before.BySeries["clang-tidy/default"] != 1 || before.BySeries["codeql/default"] != 0 {
			t.Errorf("a week ago is %+v; want the hub's three, rated other, one in clang-tidy and none in CodeQL", before)
		}
		// Fixed leaves; no longer detected stays, because absence closes
		// nothing; the new one arrives.
		if now.NotFixed != 3 || now.Opened != 1 || now.Fixed != 1 {
			t.Errorf("this week is %+v; want three not fixed, one opened and one fixed", now)
		}
		if now.ByTier["memory-safety"] != 1 || now.ByTier["other"] != 2 || now.BySeries["clang-tidy/default"] != 0 ||
			now.BySeries["codeql/default"] != 1 || now.BySeries["cppcheck/default"] != 1 {
			t.Errorf("this week splits as %+v; want CodeQL's in memory safety and clang-tidy's gone", now)
		}
		if got.NoLongerDetected != 1 {
			t.Errorf("%d are no longer detected; want cppcheck's one", got.NoLongerDetected)
		}

		marked := map[string]string{}
		for _, m := range got.Markers {
			marked[m.Series+" "+m.Change] = m.Reason + "|" + m.From + "|" + m.To
			if m.Builds != 1 || m.At != now.At {
				t.Errorf("marker %+v; want one build, today", m)
			}
		}
		want := map[string]string{
			"clang-tidy/default tool-version": "||19.1",
			"cppcheck/default rules":          "|2|3",
			"semgrep/default not-comparable":  "units-short||",
		}
		if len(marked) != len(want) {
			t.Errorf("markers are %v; want %v", marked, want)
		}
		for key, said := range want {
			if marked[key] != said {
				t.Errorf("marker %s says %q; want %q (all: %v)", key, marked[key], said, marked)
			}
		}
	})
}

func TestATrendNarrowsAsTheQueueDoes(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		for _, c := range []struct {
			query       string
			before, now int
			markers     int
		}{
			{"?weeks=2&series=CPPCHECK/default", 1, 1, 1},
			{"?weeks=2&method=sast", 3, 3, 3},
			{"?weeks=2&component=zlib1g", 1, 1, 3},
			{"?weeks=2&branch_or_tag=master&variant=broadcom&beneath=libmine1", 2, 2, 3},
			{"?weeks=2&branch_or_tag=master&variant=broadcom&beneath=sonic-image", 3, 3, 3},
			{"?weeks=2&series=nosuch", 0, 0, 0},
		} {
			got := readTrend(t, r, "security-testing-reader", c.query)
			if len(got.Points) != 2 || got.Points[0].NotFixed != c.before || got.Points[1].NotFixed != c.now ||
				len(got.Markers) != c.markers {
				t.Errorf("%s is %+v; want %d then %d not fixed and %d markers", c.query, got, c.before, c.now, c.markers)
			}
		}
	})
}

// A run late on a week's last day opens a code finding and is not
// comparable: its marker and its opening are in the same week, because a week
// ends at the midnight its markers' days end at.
func TestAMarkerIsInTheWeekItsRunOpenedIn(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.HubCodeFindings(t, r)
		ctx := t.Context()
		now := time.Now().UTC()
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"opened_at" = ?`, now.Add(-30*24*time.Hour)).
			Where(`"kind" = ?`, kind.Analysis).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		short := strings.Replace(httpapitest.OtherToolRun("codeql", "overflow", "787", "src/x.c", 5),
			`"openpsirt/unitsAnalyzed":1`, `"openpsirt/unitsAnalyzed":0`, 1)
		httpapitest.ApplyRunIn(t, r, "codeql/default", now.Add(-time.Hour), short)
		// The last second of the day a week ago, the last day of the week
		// before this one.
		weekAgo := now.Truncate(24 * time.Hour).Add(-7 * 24 * time.Hour)
		late := weekAgo.Add(24*time.Hour - time.Second)
		recent := now.Add(-24 * time.Hour)
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).Set(`"opened_at" = ?`, late).
			Where(`"opened_at" > ?`, recent).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"series_run"`).Set(`"applied_at" = ?`, late).
			Where(`"applied_at" > ?`, recent).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		got := readTrend(t, r, "security-testing-reader", "?weeks=3")
		var marked string
		for _, m := range got.Markers {
			if m.Series == "codeql/default" {
				marked = m.At
			}
		}
		if want := late.Format(time.DateOnly); marked != want {
			t.Fatalf("CodeQL is marked on %q; want %s (all: %+v)", marked, want, got.Markers)
		}
		for _, p := range got.Points {
			if p.Opened != 0 && p.At != marked {
				t.Errorf("the week ending %s opened %d, and the marker is in the week ending %s", p.At, p.Opened, marked)
			}
			if p.At == marked && p.Opened != 1 {
				t.Errorf("the week ending %s holds the marker and opened %d; want CodeQL's one (all: %+v)", p.At, p.Opened, got.Points)
			}
		}
	})
}

// unitsShort is semgrep's run analyzing none of the units it expected, so its
// absences are no evidence.
func unitsShort() string {
	return strings.Replace(httpapitest.RunInRepository("semgrep", "https://github.com/acme/elsewhere", "main.go", 7),
		`"openpsirt/unitsAnalyzed":1`, `"openpsirt/unitsAnalyzed":0`, 1)
}

// shippedFor ships a build of the seeded product with nothing but its root,
// declaring its branch or variant where it is new, so a run has a build to
// place its results in.
func shippedFor(t *testing.T, r *httpapitest.Reach, b httpapitest.Build) {
	t.Helper()
	names := catalog.NewStore(r.DB.DB)
	mine, err := names.ProductByName(t.Context(), b.Product)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := names.VariantByName(t.Context(), mine.ID, b.Variant); err != nil {
		if _, err := names.DeclareVariant(t.Context(), mine.ID, b.Variant, true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := names.BranchOrTagByName(t.Context(), mine.ID, b.BranchOrTag); err != nil {
		if _, err := names.DeclareBranchOrTag(t.Context(), mine.ID, b.BranchOrTag, catalog.Branch, nil); err != nil {
			t.Fatal(err)
		}
	}
	root := graph.Described{Purl: "pkg:generic/mine-" + b.BranchOrTag + "-" + b.Variant + "@1.0",
		Name: "mine-" + b.BranchOrTag + "-" + b.Variant, Version: "1.0"}
	_, scan := r.Shipped(t, b, "markers-"+b.BranchOrTag+"-"+b.Variant, graph.Snapshot{Root: root})
	if err := ingest.NewStore(r.DB.DB).Made(t.Context(), scan, 1, 1, root.Name); err != nil {
		t.Fatal(err)
	}
}

// semgrep short of its units on two more builds, one on another variant and
// one on another branch, twice on the second: a marker counts each build once,
// and narrows by branch, variant and the build beneath names.
func TestATrendsMarkersNarrowToTheBuildsAsked(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		otherVariant := httpapitest.Build{Product: "mine", BranchOrTag: "master", Variant: "mellanox"}
		otherBranch := httpapitest.Build{Product: "mine", BranchOrTag: "v1", Variant: "broadcom"}
		shippedFor(t, r, otherVariant)
		shippedFor(t, r, otherBranch)
		hour := time.Now().UTC().Add(-time.Hour)
		httpapitest.ApplyRunAt(t, r, otherVariant, "semgrep/default", hour, unitsShort())
		httpapitest.ApplyRunAt(t, r, otherBranch, "semgrep/default", hour, unitsShort())
		httpapitest.ApplyRunAt(t, r, otherBranch, "semgrep/default", hour.Add(10*time.Minute), unitsShort())
		for _, c := range []struct {
			query  string
			builds int
		}{
			{"?weeks=1", 3},
			{"?weeks=1&variant=broadcom", 2},
			{"?weeks=1&branch_or_tag=master", 2},
			{"?weeks=1&branch_or_tag=master&variant=broadcom&beneath=sonic-image", 1},
		} {
			got := readTrend(t, r, "security-testing-reader", c.query)
			builds := 0
			for _, m := range got.Markers {
				if m.Series == "semgrep/default" && m.Change == "not-comparable" {
					builds += m.Builds
				}
			}
			if builds != c.builds {
				t.Errorf("%s marks semgrep short of its units on %d builds (%+v); want %d", c.query, builds, got.Markers, c.builds)
			}
		}
	})
}

// The trend and its file are at security testing visibility: refused to a
// reader of the product holding none before a name is resolved, and counted
// in the data layer over what the reader reads.
func TestWhoMayTrendCodeFindings(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		const (
			theirs  = "/v1/products/theirs/code-finding-trend"
			file    = trendOf + ".csv"
			beneath = trendOf + "?branch_or_tag=master&variant=broadcom&beneath=libmine1"
			absent  = trendOf + "?branch_or_tag=master&variant=broadcom&beneath=nosuch"
		)
		for _, c := range []struct {
			who  string
			path string
			want int
		}{
			{"", trendOf, http.StatusUnauthorized},
			{"security-testing-reader", trendOf, http.StatusOK},
			{"security-testing-triager", trendOf, http.StatusOK},
			{"code-finding-handler", trendOf, http.StatusOK},
			{"reader", trendOf, http.StatusForbidden},
			{"private", trendOf, http.StatusForbidden},
			{"approver", trendOf, http.StatusNotFound},
			{"outsider", trendOf, http.StatusNotFound},
			{"security-testing-reader", theirs, http.StatusNotFound},
			{"outsider", theirs, http.StatusForbidden},

			{"", file, http.StatusUnauthorized},
			{"security-testing-reader", file, http.StatusOK},
			{"reader", file, http.StatusForbidden},
			{"private", file, http.StatusForbidden},
			{"approver", file, http.StatusNotFound},

			{"security-testing-reader", beneath, http.StatusOK},
			{"security-testing-reader", absent, http.StatusNotFound},
			// Authorized before the name is resolved: a name held and a name
			// not held are refused alike.
			{"reader", beneath, http.StatusForbidden},
			{"reader", absent, http.StatusForbidden},
			{"outsider", absent, http.StatusNotFound},
		} {
			if got := httpapitest.AsPerson(t, r, c.who, http.MethodGet, c.path, ""); got.Code != c.want {
				t.Errorf("%q GET %s = %d, want %d: %s", c.who, c.path, got.Code, c.want, got.Body.String())
			}
		}

		// semgrep's code finding disclosed: counted for somebody reading
		// disclosed work beside security testing material, and not for
		// somebody reading security testing material alone.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"visibility" = ?`, access.Public).
			Where(`"kind" = ?`, kind.Analysis).
			Where(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" LIKE ?)`, "semgrep/%").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			who      string
			notFixed int
		}{
			{"security-testing-reader", 2},
			{"code-finding-handler", 3},
		} {
			got := readTrend(t, r, c.who, "?weeks=1")
			if got.Points[0].NotFixed != c.notFixed || got.Points[0].BySeries["semgrep/default"] != c.notFixed-2 {
				t.Errorf("%s reads %+v; want %d not fixed", c.who, got.Points[0], c.notFixed)
			}
		}
		w := httpapitest.AsPerson(t, r, "security-testing-reader", http.MethodGet, file+"?weeks=1", "")
		if strings.Contains(w.Body.String(), "series,semgrep/default") ||
			!strings.Contains(w.Body.String(), "series,cppcheck/default,1") ||
			!strings.Contains(w.Body.String(), "clang-tidy/default tool-version from not stated to 19.1") {
			t.Errorf("the file reads %s; want semgrep's disclosed code finding left out and the version change said", w.Body.String())
		}
	})
}
