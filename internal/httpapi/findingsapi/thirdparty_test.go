// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/findingsapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// vendoredRun is one cppcheck run over the seeded checkout reporting an
// overflow in each file given, at line 4.
func vendoredRun(files ...string) string {
	results := make([]string, 0, len(files))
	for _, file := range files {
		results = append(results, `{"ruleId":"overflow","message":{"text":"overflow in `+file+`"},`+
			`"locations":[{"physicalLocation":{"artifactLocation":{"uri":`+strconv.Quote(file)+`,"uriBaseId":"SRCROOT"},`+
			`"region":{"startLine":4}}}]}`)
	}
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"cppcheck","rules":[{"id":"overflow"},{"id":"unfired"}]}},` +
		`"originalUriBaseIds":{"SRCROOT":{"uri":"file:///build/"}},` +
		`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/mine","revisionId":"` + httpapitest.LeadCommit +
		`","mappedTo":{"uriBaseId":"SRCROOT"}}],` +
		`"properties":{"openpsirt/unitsExpected":1,"openpsirt/unitsAnalyzed":1},` +
		`"results":[` + strings.Join(results, ",") + `]}]}`
}

// Code vendored into the tree without a repository of its own, declared
// third-party by the run, is one prefix at every depth, and the component
// confirmed for one lead under it is offered first for the next. The lead and
// the offer both say it is third-party; a lead outside it says nothing.
func TestVendoredCodeDeclaredThirdPartyIsOnePrefixAndIsSaidToBeThirdParty(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededLead(t, r)
		const shallow, deep, own = "src/vendor/zlib/inflate.c", "src/vendor/zlib/contrib/minizip/zip.c", "src/c.c"
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-time.Hour),
			vendoredRun(shallow, deep, own))
		r.PatchedRows(t, `UPDATE "series_run" SET "third_party" = '["src/vendor/zlib"]'
			WHERE "series_id" IN (SELECT "id" FROM "series" WHERE "name" = 'cppcheck/default')`)

		placeOf := map[string]string{}
		var rows []struct {
			Place string `bun:"place_identity"`
			Path  string `bun:"path"`
		}
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
			ColumnExpr(`"f"."place_identity", "ar"."path"`).
			Where(`"f"."kind" = ?`, kind.Analysis).Scan(t.Context(), &rows); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			placeOf[row.Path] = row.Place
		}
		for path, want := range map[string]struct {
			prefix string
			third  bool
		}{shallow: {"src/vendor/zlib", true}, deep: {"src/vendor/zlib", true}, own: {"src", false}} {
			place := placeOf[path]
			if place == "" {
				t.Fatalf("no lead was opened at %s: %v", path, placeOf)
			}
			if got := evidenceAs(t, r, "internal-reader", place); got.ThirdParty != want.third {
				t.Errorf("the lead at %s says third-party: %v; want %v", path, got.ThirdParty, want.third)
			}
			var offer findingsapi.HandoffOfferBody
			httpapitest.Read(t, r, "lead-handler", leadAt(place)+"/hand-off", &offer)
			if offer.Prefix != want.prefix || offer.ThirdParty != want.third {
				t.Errorf("the offer for %s is the prefix %q, third-party %v; want %q, %v",
					path, offer.Prefix, offer.ThirdParty, want.prefix, want.third)
			}
		}

		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadAt(placeOf[deep])+"/decision",
			`{"outcome":"confirmed","reasoning":"the window overflows"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "lead-handler", http.MethodPost, leadAt(placeOf[deep])+"/hand-off",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"component":"zlib","summary":"the window overflows"}`); got.Code != http.StatusCreated {
			t.Fatalf("the hand-off answered %d: %s", got.Code, got.Body)
		}
		var offer findingsapi.HandoffOfferBody
		// Learned for the declared path rather than the deeper lead's
		// directory, so a lead nearer the top of the vendored code is
		// offered it.
		httpapitest.Read(t, r, "lead-handler", leadAt(placeOf[shallow])+"/hand-off", &offer)
		if first := offer.Suggestions[0]; first.From != "confirmed" || first.Component != "zlib" {
			t.Errorf("the shallower vendored lead was offered %+v first; want zlib, as its prefix was confirmed", first)
		}
		httpapitest.Read(t, r, "lead-handler", leadAt(placeOf[own])+"/hand-off", &offer)
		if first := offer.Suggestions[0]; first.From == "confirmed" {
			t.Errorf("a lead outside the vendored code was offered %+v first", first)
		}
	})
}
