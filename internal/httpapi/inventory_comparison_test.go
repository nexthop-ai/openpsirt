// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// Which names any two builds of a product differ on: two releases, two
// platforms of one release, or a tag and the branch it was cut from.

// inventoried reads an inventory of these names at these versions for one
// build of mine, declaring the variant where it is new.
func (r *reach) inventoried(t *testing.T, variant, hash string, held map[string]string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.db.DB)
	mine, err := names.ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := names.VariantByName(ctx, mine.ID, variant); err != nil {
		if _, err := names.DeclareVariant(ctx, mine.ID, variant, true); err != nil {
			t.Fatal(err)
		}
	}
	located, err := names.Locate(ctx, "mine", "master", variant)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: hash, BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	top := graph.Described{Purl: "pkg:generic/mine-" + variant + "@1.0", Name: "mine-" + variant, Version: "1.0"}
	snap := graph.Snapshot{Root: top}
	for name, version := range held {
		component := graph.Described{
			Purl: "pkg:deb/debian/" + name + "@" + version, Name: name, Version: version,
		}
		snap.Components = append(snap.Components, component)
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: top, Child: component})
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, snap); err != nil {
		t.Fatal(err)
	}
}

// twoPlatforms is one release built for two platforms that differ by one name
// each way and one version.
func (r *reach) twoPlatforms(t *testing.T) {
	t.Helper()
	r.inventoried(t, "broadcom", "broadcom", map[string]string{
		"libc6": "2.41", "zlib1g": "1.3", "openssl": "3.0.11",
	})
	r.inventoried(t, "mellanox", "mellanox", map[string]string{
		"libc6": "2.42", "curl": "8.4.0", "openssl": "3.0.11",
	})
}

const platforms = "/v1/products/mine/comparison/inventory" +
	"?from=master&from_variant=broadcom&to=master&to_variant=mellanox"

func TestTwoBuildsSayWhichNamesTheyDifferOn(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.twoPlatforms(t)

		var out httpapi.ListedInventoryDifferences
		read(t, r, "reader", platforms, &out.Body)
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

		read(t, r, "reader", platforms+"&change=added", &out.Body)
		if out.Body.Total != 1 || len(out.Body.Items) != 1 || out.Body.Items[0].Name != "curl" {
			t.Errorf("the arrivals alone are %+v of %d, want curl alone", out.Body.Items, out.Body.Total)
		}
	})
}

func TestTheInventoryComparisonFileListsWhatTheScreenLists(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.twoPlatforms(t)
		at := strings.Replace(platforms, "/inventory?", "/inventory.csv?", 1)

		file := asPerson(t, r, "reader", http.MethodGet, at, "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
		}
		lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		body := rowsUnder(lines)
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

		narrowed := asPerson(t, r, "reader", http.MethodGet,
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
	twoReach(t, func(t *testing.T, r *reach) {
		r.twoPlatforms(t)
		at := strings.Replace(platforms, "/inventory?", "/inventory.csv?", 1)

		// Somebody holding nothing in the product is told the builds were
		// never scanned, which is what a product they cannot see answers.
		for _, path := range []string{platforms, at} {
			if got := asPerson(t, r, "outsider", http.MethodGet, path, ""); got.Code != http.StatusNotFound {
				t.Errorf("GET %s answered an outsider %d: %s", path, got.Code, got.Body.String())
			}
			if got := asPerson(t, r, "", http.MethodGet, path, ""); got.Code != http.StatusUnauthorized {
				t.Errorf("GET %s answered nobody %d: %s", path, got.Code, got.Body.String())
			}
		}
	})
}

func TestABuildWithNoInventoryIsNotComparedAgainst(t *testing.T) {
	// Compared against nothing, every name the other build holds would read
	// as added: a claim about a build nobody has described.
	twoReach(t, func(t *testing.T, r *reach) {
		r.inventoried(t, "broadcom", "broadcom", map[string]string{"libc6": "2.41"})
		ctx := t.Context()
		names := catalog.NewStore(r.db.DB)
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
		if _, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: "waiting", BuiltAt: time.Now().UTC(),
			ParserVersion: "test",
		}); err != nil || outcome != ingest.Accept {
			t.Fatalf("record scan: %v %v", outcome, err)
		}

		got := asPerson(t, r, "reader", http.MethodGet, platforms, "")
		if got.Code != http.StatusNotFound || !strings.Contains(got.Body.String(), "no inventory") {
			t.Errorf("comparing against a build nothing was read for answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}
