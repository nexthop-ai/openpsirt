// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

const (
	countsAcross   = "/v1/code-finding-counts"
	trendAcross    = "/v1/code-finding-trend"
	judgeAcross    = "/v1/code-finding-time-to-judge"
	coverageAcross = "/v1/analysis-coverage"
)

// countsRead is the queue's counts across products as these tests read them.
type countsRead struct {
	Total   int            `json:"total"`
	States  map[string]int `json:"states"`
	Waiting int            `json:"waiting"`
	Ruled   int            `json:"ruled"`
	Ended   int            `json:"past_end_of_life"`
}

// theirsAnalyzed is the seeded code finding's run applied to the other
// product's build, opening its leak, then a run at a new version of the tool,
// which marks the trend there.
func theirsAnalyzed(t *testing.T, r *httpapitest.Reach) {
	t.Helper()
	root := graph.Described{Purl: "pkg:generic/theirs-image@1.0", Name: "theirs-image", Version: "1.0"}
	_, scan := r.Shipped(t, httpapitest.TheirBuild, "theirs-code-finding", graph.Snapshot{Root: root})
	if err := ingest.NewStore(r.DB.DB).Made(t.Context(), scan, 1, 1, root.Name); err != nil {
		t.Fatal(err)
	}
	hour := time.Now().UTC().Add(-time.Hour)
	httpapitest.ApplyRunAt(t, r, httpapitest.TheirBuild, "clang-tidy/default", hour.Add(-time.Hour),
		httpapitest.CodeFindingRun(true))
	httpapitest.ApplyRunAt(t, r, httpapitest.TheirBuild, "clang-tidy/default", hour, strings.Replace(
		httpapitest.CodeFindingRun(true), `"name":"clang-tidy"`, `"name":"clang-tidy","version":"20.1"`, 1))
}

// bothSeeded is the trend's seeding in the seeded product, the other
// product's leak, a dismissal of it proposed there, and the security testing
// reader reading security testing material in both.
func bothSeeded(t *testing.T, r *httpapitest.Reach) {
	t.Helper()
	trendSeeded(t, r)
	theirsAnalyzed(t, r)
	readsSecurityTestingIn(t, r, "security-testing-reader", "theirs")
	grantIn(t, r, "security-testing-triager", "theirs", access.SecurityTestingTriage)
	var theirs acrossListed
	httpapitest.Read(t, r, "security-testing-reader", "/v1/products/theirs/code-findings", &theirs)
	if len(theirs.Items) != 1 {
		t.Fatalf("theirs lists %d code findings; want its leak", len(theirs.Items))
	}
	decided(t, r, "/v1/products/theirs/branches-and-tags/master/variants/mellanox/code-findings/"+
		theirs.Items[0].Occurrence, dismissal, false)
}

// Every figure across products is each product's own added together, or
// merged where it is a list: a code finding is one product's, so a total
// across products missing a product, or counting one twice, is a wrong total.
func TestEveryFigureAcrossProductsIsEachProductsOwnAddedTogether(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		bothSeeded(t, r)
		const who = "security-testing-reader"
		products := []string{"mine", "theirs"}

		// The queue's counts.
		var counted countsRead
		httpapitest.Read(t, r, who, countsAcross, &counted)
		var total, waiting, ruled, ended int
		states := map[string]int{}
		for _, product := range products {
			var one acrossListed
			httpapitest.Read(t, r, who, "/v1/products/"+product+"/code-findings", &one)
			total, waiting, ruled, ended = total+one.Total, waiting+one.Waiting, ruled+one.Ruled, ended+one.Ended
			for state, n := range one.States {
				states[state] += n
			}
		}
		if counted.Total != total || counted.Waiting != waiting || counted.Ruled != ruled || counted.Ended != ended {
			t.Errorf("counts across products are %+v; the products sum to %d queued, %d waiting, %d ruled, %d ended",
				counted, total, waiting, ruled, ended)
		}
		if counted.Total == 0 || waiting == 0 || states["no-longer-detected"] == 0 {
			t.Errorf("the seeding counts %d queued, %d waiting and %v; want each above zero, or the sums prove nothing",
				total, waiting, states)
		}
		for state, n := range counted.States {
			if n != states[state] {
				t.Errorf("%d %s across products; the products sum to %d", n, state, states[state])
			}
		}
		for state, n := range states {
			if counted.States[state] != n {
				t.Errorf("%s is %d across products; the products sum to %d", state, counted.States[state], n)
			}
		}

		// The trend: each week's counts add, a series of one name in two
		// products is one split, and each marker is its product's.
		across := readTrendAt(t, r, who, trendAcross+"?weeks=2")
		var each []codeTrend
		for _, product := range products {
			each = append(each, readTrendAt(t, r, who, "/v1/products/"+product+"/code-finding-trend?weeks=2"))
		}
		for i, point := range across.Points {
			notFixed, opened, fixed := 0, 0, 0
			tiers, series, methods := map[string]int{}, map[string]int{}, map[string]int{}
			for _, one := range each {
				p := one.Points[i]
				notFixed, opened, fixed = notFixed+p.NotFixed, opened+p.Opened, fixed+p.Fixed
				for k, n := range p.ByTier {
					tiers[k] += n
				}
				for k, n := range p.BySeries {
					series[k] += n
				}
				for k, n := range p.ByMethod {
					methods[k] += n
				}
			}
			if point.NotFixed != notFixed || point.Opened != opened || point.Fixed != fixed ||
				!sameCounts(point.ByTier, tiers) || !sameCounts(point.BySeries, series) ||
				!sameCounts(point.ByMethod, methods) {
				t.Errorf("week %d across products is %+v; the products sum to %d not fixed, %d opened, %d fixed, %v, %v, %v",
					i, point, notFixed, opened, fixed, tiers, series, methods)
			}
		}
		if across.NoLongerDetected != each[0].NoLongerDetected+each[1].NoLongerDetected {
			t.Errorf("%d no longer detected across products; the products sum to %d", across.NoLongerDetected,
				each[0].NoLongerDetected+each[1].NoLongerDetected)
		}
		marked := func(trend codeTrend) []string {
			var out []string
			for _, m := range trend.Markers {
				out = append(out, fmt.Sprintf("%s %s %s %s %s>%s %d", m.At, m.Product, m.Series, m.Change, m.From, m.To, m.Builds))
			}
			sort.Strings(out)
			return out
		}
		wantMarks := append(marked(each[0]), marked(each[1])...)
		sort.Strings(wantMarks)
		if got := marked(across); !slices.Equal(got, wantMarks) {
			t.Errorf("markers across products are %v; want each product's, %v", got, wantMarks)
		}
		theirsMarked := false
		for _, m := range across.Markers {
			theirsMarked = theirsMarked || (m.Product == "theirs" && m.Series == "clang-tidy/default" && m.To == "20.1")
		}
		if !theirsMarked {
			t.Errorf("markers across products are %v; want theirs' new clang-tidy named for its product", marked(across))
		}

		// The time to judge: every product's waits together, the queue's
		// ages added, and the oldest the oldest of any product's queue.
		var judged judgingRead
		httpapitest.Read(t, r, who, judgeAcross+"?weeks=2", &judged)
		var ones []judgingRead
		for _, product := range products {
			var one judgingRead
			httpapitest.Read(t, r, who, "/v1/products/"+product+"/code-finding-time-to-judge?weeks=2", &one)
			ones = append(ones, one)
		}
		if judged.Judged.All.Count != ones[0].Judged.All.Count+ones[1].Judged.All.Count || ones[1].Judged.All.Count == 0 {
			t.Errorf("%d judged across products; the products judged %d and %d, the second above zero",
				judged.Judged.All.Count, ones[0].Judged.All.Count, ones[1].Judged.All.Count)
		}
		for _, tier := range judged.Judged.ByTier {
			if tier.Count != ones[0].Judged.tier(tier.Tier).Count+ones[1].Judged.tier(tier.Tier).Count {
				t.Errorf("%d judged in %s across products; the products sum to %d", tier.Count, tier.Tier,
					ones[0].Judged.tier(tier.Tier).Count+ones[1].Judged.tier(tier.Tier).Count)
			}
		}
		for i, aged := range judged.Waiting {
			sum := ones[0].Waiting[i].Waiting + ones[1].Waiting[i].Waiting
			if aged.Waiting != sum {
				t.Errorf("%d wait %s across products; the products sum to %d", aged.Waiting, aged.Label, sum)
			}
			for tier, n := range aged.ByTier {
				if n != ones[0].Waiting[i].ByTier[tier]+ones[1].Waiting[i].ByTier[tier] {
					t.Errorf("%d %s wait %s across products; the products sum to %d", n, tier, aged.Label,
						ones[0].Waiting[i].ByTier[tier]+ones[1].Waiting[i].ByTier[tier])
				}
			}
		}
		oldest := ""
		for _, one := range ones {
			if one.Oldest != "" && (oldest == "" || one.Oldest < oldest) {
				oldest = one.Oldest
			}
		}
		if judged.Oldest != oldest || oldest == "" {
			t.Errorf("the oldest across products opened %q; the products' oldest is %q", judged.Oldest, oldest)
		}
		if judged.NoLongerDetected != ones[0].NoLongerDetected+ones[1].NoLongerDetected {
			t.Errorf("%d no longer detected across products; the products sum to %d", judged.NoLongerDetected,
				ones[0].NoLongerDetected+ones[1].NoLongerDetected)
		}

		// Analysis coverage: every product's rows, each naming its product.
		var covered coverageRead
		httpapitest.Read(t, r, who, coverageAcross+"?weeks=2", &covered)
		rows := func(c coverageRead) []string {
			var out []string
			for _, item := range c.Items {
				out = append(out, fmt.Sprintf("%s %s %s %v %d", item.Product, item.BranchOrTag, item.Series,
					item.Quiet, item.AppliedRuns))
			}
			sort.Strings(out)
			return out
		}
		var wantRows []string
		quiet := 0
		for _, product := range products {
			var one coverageRead
			httpapitest.Read(t, r, who, "/v1/products/"+product+"/analysis-coverage?weeks=2", &one)
			for _, item := range one.Items {
				if item.Product != product {
					t.Errorf("%s's coverage names %q as its product", product, item.Product)
				}
			}
			wantRows = append(wantRows, rows(one)...)
			quiet += one.Quiet
		}
		sort.Strings(wantRows)
		if got := rows(covered); !slices.Equal(got, wantRows) || covered.Quiet != quiet {
			t.Errorf("coverage across products is %v, %d quiet; want each product's, %v, %d quiet",
				got, covered.Quiet, wantRows, quiet)
		}
	})
}

// sameCounts is whether two splits count the same, a split named at zero in
// one and absent in the other included.
func sameCounts(a, b map[string]int) bool {
	for k, n := range a {
		if b[k] != n {
			return false
		}
	}
	for k, n := range b {
		if a[k] != n {
			return false
		}
	}
	return true
}

// readTrendAt reads a trend at a path.
func readTrendAt(t *testing.T, r *httpapitest.Reach, who, path string) codeTrend {
	t.Helper()
	var out codeTrend
	httpapitest.Read(t, r, who, path, &out)
	return out
}

// acrossFigures is what each figure across products counts, as one number
// these tests compare: the queue, not fixed this week, the queue by age, and
// the series and builds analyzed.
func acrossFigures(t *testing.T, r *httpapitest.Reach, who string) [4]int {
	t.Helper()
	var counted countsRead
	httpapitest.Read(t, r, who, countsAcross, &counted)
	trend := readTrendAt(t, r, who, trendAcross+"?weeks=1")
	var judged judgingRead
	httpapitest.Read(t, r, who, judgeAcross+"?weeks=1", &judged)
	waiting := 0
	for _, aged := range judged.Waiting {
		waiting += aged.Waiting
	}
	var covered coverageRead
	httpapitest.Read(t, r, who, coverageAcross+"?weeks=1", &covered)
	return [4]int{counted.Total + counted.States["open"], trend.Points[0].NotFixed, waiting, len(covered.Items)}
}

// The figures across products count the products in use, as the session
// lists them: a retired product is in no figure across products, though a
// kept link still reads its own.
func TestFiguresAcrossProductsLeaveOutARetiredProduct(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		bothSeeded(t, r)
		const who = "security-testing-reader"
		both := acrossFigures(t, r, who)
		named, err := catalog.NewStore(r.DB.DB).ProductByName(t.Context(), "theirs")
		if err != nil {
			t.Fatal(err)
		}
		if err := catalog.NewStore(r.DB.DB).RetireProduct(t.Context(), named.ID); err != nil {
			t.Fatal(err)
		}
		var session struct {
			Reach []struct {
				Product              string `json:"product"`
				ReadsSecurityTesting bool   `json:"reads_security_testing"`
			} `json:"reach"`
		}
		httpapitest.Read(t, r, who, "/v1/session/me", &session)
		var listed []string
		for _, can := range session.Reach {
			if can.ReadsSecurityTesting {
				listed = append(listed, can.Product)
			}
		}
		if !slices.Equal(listed, []string{"mine"}) {
			t.Fatalf("the session lists security testing read in %v; want mine alone once theirs is retired", listed)
		}
		// Every figure is the seeded product's alone, as one product's own
		// reads count it.
		mine := acrossFigures(t, r, who)
		var one acrossListed
		httpapitest.Read(t, r, who, "/v1/products/mine/code-findings", &one)
		var judged judgingRead
		httpapitest.Read(t, r, who, "/v1/products/mine/code-finding-time-to-judge?weeks=1", &judged)
		waiting := 0
		for _, aged := range judged.Waiting {
			waiting += aged.Waiting
		}
		var covered coverageRead
		httpapitest.Read(t, r, who, "/v1/products/mine/analysis-coverage?weeks=1", &covered)
		want := [4]int{one.Total + one.States["open"], readTrendAt(t, r, who, trendOf+"?weeks=1").Points[0].NotFixed,
			waiting, len(covered.Items)}
		if mine != want || mine == both {
			t.Errorf("with theirs retired the figures across products are %v; want mine's own %v, short of %v",
				mine, want, both)
		}
		if got := httpapitest.AsPerson(t, r, who, http.MethodGet, "/v1/products/theirs/code-finding-trend", ""); got.Code != http.StatusOK {
			t.Errorf("the retired product's own trend answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// Who may read the figures across products and their files: any person, a
// pipeline key never.
func TestWhoMayReadTheSecurityTestingFiguresAcrossProducts(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		theirsAnalyzed(t, r)
		paths := []string{countsAcross, trendAcross + "?weeks=1", judgeAcross + "?weeks=1", coverageAcross + "?weeks=1"}
		for _, path := range paths {
			files := []string{
				strings.Replace(path, "?", ".csv?", 1), strings.Replace(path, "?", ".json?", 1),
			}
			if !strings.Contains(path, "?") {
				files = []string{path + ".csv", path + ".json"}
			}
			for _, at := range append([]string{path}, files...) {
				for _, c := range []struct {
					who  string
					want int
				}{
					{"", http.StatusUnauthorized},
					{"security-testing-reader", http.StatusOK},
					{"security-testing-triager", http.StatusOK},
					{"code-finding-handler", http.StatusOK},
					{"reader", http.StatusOK},
					{"private", http.StatusOK},
					{"approver", http.StatusOK},
					{"outsider", http.StatusOK},
					{"auditor", http.StatusOK},
				} {
					if got := httpapitest.AsPerson(t, r, c.who, http.MethodGet, at, ""); got.Code != c.want {
						t.Errorf("%q GET %s = %d, want %d: %s", c.who, at, got.Code, c.want, got.Body.String())
					}
				}
				if got := r.WithKey(t, r.Key, http.MethodGet, at); got.Code != http.StatusForbidden {
					t.Errorf("a pipeline key read %s: %d %s", at, got.Code, got.Text)
				}
			}
		}

	})
}

// Each figure across products counts only the products where the reader
// reads security testing material, each at the visibilities they read in it:
// a product read for disclosed work alone contributes nothing, and a reader
// of security testing material nowhere has nothing counted.
func TestFiguresAcrossProductsCountOnlySecurityTestingReadProducts(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		trendSeeded(t, r)
		theirsAnalyzed(t, r)

		// The seeded product's figures alone, as its own reads count them.
		mine := acrossFigures(t, r, "security-testing-reader")
		if mine == ([4]int{}) {
			t.Fatal("the seeded product counts nothing across products, so this checks nothing")
		}

		// semgrep's code finding in the seeded product and the other
		// product's leak disclosed, and the security testing reader given
		// disclosed reading in the other product: the other product, read
		// for disclosed work alone, contributes nothing, and the disclosed
		// code finding is counted only for somebody reading disclosed work
		// beside security testing material where it is.
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"finding"`).
			Set(`"visibility" = ?`, access.Public).
			Where(`"kind" = ?`, kind.Analysis).
			WhereGroup(" AND ", func(q *bun.UpdateQuery) *bun.UpdateQuery {
				return q.WhereOr(`"vulnerability_id" IN (SELECT "id" FROM "vulnerability" WHERE "identifier" LIKE ?)`, "semgrep/%").
					WhereOr(`"build_id" = ?`, r.BuildOf(t, httpapitest.TheirBuild))
			}).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		grantIn(t, r, "security-testing-reader", "theirs", access.PublicRead)
		var theirs acrossListed
		httpapitest.Read(t, r, "security-testing-reader", "/v1/products/theirs/code-findings", &theirs)
		if theirs.Total != 1 {
			t.Fatalf("the security testing reader lists %d of theirs as disclosed; want its leak", theirs.Total)
		}
		var mineDisclosed acrossListed
		httpapitest.Read(t, r, "reader", "/v1/products/mine/code-findings?state=open", &mineDisclosed)
		if mineDisclosed.Total != 1 {
			t.Fatalf("the reader lists %d disclosed code findings in mine; want semgrep's", mineDisclosed.Total)
		}
		withoutSemgrep := acrossFigures(t, r, "security-testing-reader")
		handler := acrossFigures(t, r, "code-finding-handler")
		if withoutSemgrep[0] >= mine[0] || withoutSemgrep[1] >= mine[1] {
			t.Errorf("the security testing reader counts %v across products after semgrep's was disclosed; want less than %v and nothing of theirs",
				withoutSemgrep, mine)
		}
		if handler[0] != mine[0] || handler[1] != mine[1] {
			t.Errorf("code-finding-handler, reading disclosed work too, counts %v across products; want semgrep's still counted, %v",
				handler, mine)
		}
		var mineOnly countsRead
		httpapitest.Read(t, r, "security-testing-reader", countsAcross, &mineOnly)
		var mineOwn acrossListed
		httpapitest.Read(t, r, "security-testing-reader", "/v1/products/mine/code-findings", &mineOwn)
		if mineOnly.Total != mineOwn.Total {
			t.Errorf("the security testing reader counts %d queued across products; want mine's own %d and none of theirs",
				mineOnly.Total, mineOwn.Total)
		}

		// A reader of disclosed work alone, and readers of nothing at
		// security testing visibility, have nothing counted: no disclosed
		// code finding of theirs is a hidden count of security testing work.
		for _, who := range []string{"reader", "private", "approver", "outsider", "auditor"} {
			if got := acrossFigures(t, r, who); got != ([4]int{}) {
				t.Errorf("%s counts %v across products; want nothing", who, got)
			}
		}

		// No name resolves to a refusal: a series nobody holds counts
		// nothing, for a reader of it and a reader of nothing alike.
		for _, who := range []string{"security-testing-reader", "reader"} {
			for _, series := range []string{"clang-tidy/default", "nosuch"} {
				if got := httpapitest.AsPerson(t, r, who, http.MethodGet, countsAcross+"?series="+series, ""); got.Code != http.StatusOK {
					t.Errorf("%s GET counts for series %s = %d: %s", who, series, got.Code, got.Body.String())
				}
			}
		}
	})
}
