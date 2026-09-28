// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/csv"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
)

func TestTheReasonsTheSchemaOffersAreTheReasonsAComponentIsGiven(t *testing.T) {
	// A reason the classifier gives and the schema does not name is refused as
	// a filter and fails the response's own validation.
	want := make([]string, 0, len(graph.Reasons))
	for _, reason := range graph.Reasons {
		want = append(want, string(reason))
	}
	if len(want) == 0 {
		t.Fatal("no reasons were found, so this checked nothing")
	}
	for _, of := range []reflect.Type{
		reflect.TypeFor[httpapi.UnmatchedBody](), reflect.TypeFor[httpapi.ReasonCountBody](),
	} {
		field, ok := of.FieldByName("Reason")
		if !ok {
			t.Fatalf("%s has no reason", of)
		}
		if got := strings.Split(field.Tag.Get("enum"), ","); !reflect.DeepEqual(got, want) {
			t.Errorf("%s names %v, want %v", of, got, want)
		}
	}
}

func TestABuildSaysWhatItHoldsThatNothingCanMatch(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		kernel := graph.Described{Purl: "pkg:deb/sonic/linux-image@6.12.41-1?arch=amd64",
			Name: "linux-image", Version: "6.12.41-1"}
		bash := graph.Described{Name: "bash", Version: "5.2"}
		awk := graph.Described{Name: "awk", Version: "1"}
		matched := graph.Described{Purl: "pkg:deb/debian/zlib@1.3?distro=debian-13",
			Name: "zlib", Version: "1.3"}
		held := []graph.Described{kernel, bash, awk, matched}
		snap := graph.Snapshot{Root: seededRoot, Components: held}
		for _, d := range held {
			snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: seededRoot, Child: d})
		}
		r.scan(t, "match-coverage", snap, nil)

		const build = "/v1/products/mine/streams/master/variants/broadcom/match-coverage"
		var all httpapi.MatchCoverageBody
		read(t, r, "reader", build, &all)
		if all.Components != 4 || all.Unmatched != 3 || all.Total != 3 {
			t.Errorf("holds %d, %d unmatched, %d listed; want 4, 3 and 3",
				all.Components, all.Unmatched, all.Total)
		}
		counts := map[string]int{}
		for _, reason := range all.Reasons {
			counts[reason.Reason] = reason.Count
		}
		if len(all.Reasons) != len(graph.Reasons) || counts["no-identifier"] != 2 ||
			counts["no-distribution"] != 1 {
			t.Errorf("the reasons read %+v", all.Reasons)
		}

		var one httpapi.MatchCoverageBody
		read(t, r, "reader", build+"?reason=no-identifier&limit=1&offset=1", &one)
		if one.Total != 2 || len(one.Items) != 1 || one.Items[0].Name != "bash" {
			t.Errorf("the second of the unidentified is %+v of %d, want bash of 2", one.Items, one.Total)
		}
		// The counts describe the build whatever the page narrows to.
		if one.Unmatched != 3 {
			t.Errorf("narrowed, the build reads as %d unmatched", one.Unmatched)
		}

		file := asPerson(t, r, "reader", http.MethodGet, build+".csv?reason=no-distribution", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
		}
		lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("it came back as something that is not a spreadsheet: %v", err)
		}
		rows := rowsUnder(lines)
		if len(rows) != 2 || rows[1][0] != "no-distribution" || rows[1][1] != "linux-image" ||
			rows[1][3] != kernel.Purl {
			t.Errorf("the file reads %v", rows)
		}
	})
}
