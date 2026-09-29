// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/reportsapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

const platforms = "/v1/products/mine/comparison/inventory" +
	"?from=master&from_variant=broadcom&to=master&to_variant=mellanox"

func TestTwoBuildsSayWhichNamesTheyDifferOn(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.TwoPlatforms(t)

		var out reportsapi.ListedInventoryDifferences
		httpapitest.Read(t, r, "reader", platforms, &out.Body)
		var got []string
		for _, row := range out.Body.Items {
			got = append(got, row.Change+" "+row.Name+" ["+strings.Join(row.Before, " ")+
				"] -> ["+strings.Join(row.After, " ")+"]")
		}
		want := []string{
			"removed zlib1g [1.3] -> []",
			"added curl [] -> [8.4.0]",
			"changed libc6 [2.41] -> [2.42]",
		}
		if strings.Join(got, "; ") != strings.Join(want, "; ") || out.Body.Total != 3 {
			t.Errorf("the comparison reads %v of %d, want %v", got, out.Body.Total, want)
		}

		httpapitest.Read(t, r, "reader", platforms+"&change=added", &out.Body)
		if out.Body.Total != 1 || len(out.Body.Items) != 1 || out.Body.Items[0].Name != "curl" {
			t.Errorf("the arrivals alone are %+v of %d, want curl alone", out.Body.Items, out.Body.Total)
		}
	})
}

func TestTheInventoryComparisonFileListsWhatTheScreenLists(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.TwoPlatforms(t)
		at := strings.Replace(platforms, "/inventory?", "/inventory.csv?", 1)

		file := httpapitest.AsPerson(t, r, "reader", http.MethodGet, at, "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
		}
		lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		body := httpapitest.RowsUnder(lines)
		var got []string
		for _, row := range body {
			got = append(got, strings.Join(row, ","))
		}
		want := []string{
			"change,name,before,after",
			"removed,zlib1g,1.3,",
			"added,curl,,8.4.0",
			"changed,libc6,2.41,2.42",
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("the file reads\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		if states(lines)["later build"] != "master (mellanox)" {
			t.Errorf("the file does not name the later build: %v", states(lines))
		}

		narrowed := httpapitest.AsPerson(t, r, "reader", http.MethodGet,
			strings.Replace(at, ".csv?", ".json?", 1)+"&change=removed", "")
		if narrowed.Code != http.StatusOK {
			t.Fatalf("exporting one kind answered %d: %s", narrowed.Code, narrowed.Body.String())
		}
		var rows struct {
			Items []map[string]string `json:"items"`
		}
		if err := json.Unmarshal(narrowed.Body.Bytes(), &rows); err != nil {
			t.Fatalf("decode: %v (%s)", err, narrowed.Body.String())
		}
		if len(rows.Items) != 1 || rows.Items[0]["name"] != "zlib1g" {
			t.Errorf("the removals alone export as %v, want zlib1g alone", rows.Items)
		}
	})
}

func TestAnInventoryComparisonAnswersOnlyWhatSomebodyMayRead(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.TwoPlatforms(t)
		at := strings.Replace(platforms, "/inventory?", "/inventory.csv?", 1)

		// Somebody holding nothing in the product is told the builds were
		// never scanned, which is what a product they cannot see answers.
		for _, path := range []string{platforms, at} {
			if got := httpapitest.AsPerson(t, r, "outsider", http.MethodGet, path, ""); got.Code != http.StatusNotFound {
				t.Errorf("GET %s answered an outsider %d: %s", path, got.Code, got.Body.String())
			}
			if got := httpapitest.AsPerson(t, r, "", http.MethodGet, path, ""); got.Code != http.StatusUnauthorized {
				t.Errorf("GET %s answered nobody %d: %s", path, got.Code, got.Body.String())
			}
		}
	})
}

func TestABuildWithNoInventoryIsNotComparedAgainst(t *testing.T) {
	// Compared against nothing, every name the other build holds would read
	// as added: a claim about a build nobody has described.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Inventoried(t, "broadcom", "broadcom", map[string]string{"libc6": "2.41"})
		ctx := t.Context()
		names := catalog.NewStore(r.DB.DB)
		mine, err := names.ProductByName(ctx, "mine")
		if err != nil {
			t.Fatal(err)
		}
		variant, err := names.DeclareVariant(ctx, mine.ID, "mellanox", true)
		if err != nil {
			t.Fatal(err)
		}
		located, err := names.Locate(ctx, "mine", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		target, err := names.TargetFor(ctx, located.StreamID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		// Uploaded, and not read yet.
		if _, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: "waiting", BuiltAt: time.Now().UTC(),
			ParserVersion: "test",
		}); err != nil || outcome != ingest.Accept {
			t.Fatalf("record scan: %v %v", outcome, err)
		}

		got := httpapitest.AsPerson(t, r, "reader", http.MethodGet, platforms, "")
		if got.Code != http.StatusNotFound || !strings.Contains(got.Body.String(), "no inventory") {
			t.Errorf("comparing against a build nothing was read for answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}
