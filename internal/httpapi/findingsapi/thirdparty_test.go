// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/csv"
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
		`"versionControlProvenance":[{"repositoryUri":"https://github.com/acme/mine","revisionId":"` + httpapitest.CodeFindingCommit +
		`","mappedTo":{"uriBaseId":"SRCROOT"}}],` +
		`"properties":{"openpsirt/unitsExpected":1,"openpsirt/unitsAnalyzed":1},` +
		`"results":[` + strings.Join(results, ",") + `]}]}`
}

// Code vendored into the tree without a repository of its own, declared
// third-party by the run, is one prefix at every depth, and the component
// confirmed for one code finding under it is offered first for the next. The code finding and
// the offer both say it is third-party; a code finding outside it says nothing.
func TestVendoredCodeDeclaredThirdPartyIsOnePrefixAndIsSaidToBeThirdParty(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		const shallow, deep, own = "src/vendor/zlib/inflate.c", "src/vendor/zlib/contrib/minizip/zip.c", "src/c.c"
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-time.Hour),
			vendoredRun(shallow, deep, own))
		r.PatchedRows(t, `UPDATE "series_run" SET "third_party" = '["src/vendor/zlib"]'
			WHERE "series_id" IN (SELECT "id" FROM "series" WHERE "name" = 'cppcheck/default')`)

		occurrenceOf := map[string]string{}
		var rows []struct {
			Occurrence string `bun:"occurrence_identity"`
			Path       string `bun:"path"`
		}
		if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
			ColumnExpr(`"f"."occurrence_identity", "ar"."path"`).
			Where(`"f"."kind" = ?`, kind.Analysis).Scan(t.Context(), &rows); err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			occurrenceOf[row.Path] = row.Occurrence
		}
		for path, want := range map[string]struct {
			prefix string
			third  bool
		}{shallow: {"src/vendor/zlib", true}, deep: {"src/vendor/zlib", true}, own: {"src", false}} {
			occurrence := occurrenceOf[path]
			if occurrence == "" {
				t.Fatalf("no code finding was opened at %s: %v", path, occurrenceOf)
			}
			if got := evidenceAs(t, r, "internal-reader", occurrence); got.ThirdParty != want.third {
				t.Errorf("the code finding at %s says third-party: %v; want %v", path, got.ThirdParty, want.third)
			}
			var offer findingsapi.FlawOfferBody
			httpapitest.Read(t, r, "code-finding-handler", codeFindingAt(occurrence)+"/flaw", &offer)
			if offer.Prefix != want.prefix || offer.ThirdParty != want.third {
				t.Errorf("the offer for %s is the prefix %q, third-party %v; want %q, %v",
					path, offer.Prefix, offer.ThirdParty, want.prefix, want.third)
			}
		}

		// The queue's list and its file say the same, read from the same run.
		var listed struct {
			Items []struct {
				Path       string `json:"path"`
				ThirdParty bool   `json:"third_party"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/code-findings", &listed)
		file := httpapitest.AsPerson(t, r, "internal-reader", http.MethodGet,
			"/v1/products/mine/code-findings.csv", "")
		records, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("the file is not CSV a strict reader reads: %v\n%s", err, file.Body)
		}
		inFile := map[string]string{}
		var header []string
		for _, record := range records {
			switch {
			case strings.HasPrefix(record[0], "#"):
			case header == nil:
				header = record
			default:
				named := map[string]string{}
				for i, column := range header {
					named[column] = record[i]
				}
				inFile[named["path"]] = named["third_party"]
			}
		}
		inList := map[string]bool{}
		for _, item := range listed.Items {
			inList[item.Path] = item.ThirdParty
		}
		for _, path := range []string{shallow, deep, own, "src/a.c"} {
			want := strings.HasPrefix(path, "src/vendor/zlib/")
			if got, ok := inList[path]; !ok || got != want {
				t.Errorf("the queue lists %s as third-party %v (listed %v); want %v", path, got, ok, want)
			}
			if got := inFile[path]; got != strconv.FormatBool(want) {
				t.Errorf("the queue's file holds %s as third-party %q; want %v", path, got, want)
			}
		}

		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, codeFindingAt(occurrenceOf[deep])+"/decision",
			`{"outcome":"confirmed","reasoning":"the window overflows"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPost, codeFindingAt(occurrenceOf[deep])+"/flaw",
			`{"builds":[{"stream":"master","variant":"broadcom"}],"component":"zlib","summary":"the window overflows"}`); got.Code != http.StatusCreated {
			t.Fatalf("the flaw record answered %d: %s", got.Code, got.Body)
		}
		var offer findingsapi.FlawOfferBody
		// Learned for the declared path rather than the deeper code finding's
		// directory, so a code finding nearer the top of the vendored code is
		// offered it.
		httpapitest.Read(t, r, "code-finding-handler", codeFindingAt(occurrenceOf[shallow])+"/flaw", &offer)
		if first := offer.Suggestions[0]; first.From != "confirmed" || first.Component != "zlib" {
			t.Errorf("the shallower vendored code finding was offered %+v first; want zlib, as its prefix was confirmed", first)
		}
		httpapitest.Read(t, r, "code-finding-handler", codeFindingAt(occurrenceOf[own])+"/flaw", &offer)
		if first := offer.Suggestions[0]; first.From == "confirmed" {
			t.Errorf("a code finding outside the vendored code was offered %+v first", first)
		}
	})
}

// A code finding is third-party in the queue when the newest run that saw it declared
// it so, which is the run its evidence reads. An older run's declaration does
// not reach the queue once a newer run declares nothing.
func TestTheCodeFindingQueueReadsThirdPartyFromTheNewestRunThatSawTheCodeFinding(t *testing.T) {
	const vendored = "src/vendor/zlib/inflate.c"
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-2*time.Hour), vendoredRun(vendored))
		r.PatchedRows(t, `UPDATE "series_run" SET "third_party" = '["src/vendor/zlib"]'
			WHERE "series_id" IN (SELECT "id" FROM "series" WHERE "name" = 'cppcheck/default')`)
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-time.Hour), vendoredRun(vendored))

		var listed struct {
			Items []struct {
				Path       string `json:"path"`
				ThirdParty bool   `json:"third_party"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/code-findings", &listed)
		seen := false
		for _, item := range listed.Items {
			if item.Path != vendored {
				continue
			}
			seen = true
			if item.ThirdParty {
				t.Errorf("the queue lists %s as third-party from an older run; the newest run declared nothing", vendored)
			}
		}
		if !seen {
			t.Fatalf("the queue lists no code finding at %s: %+v", vendored, listed.Items)
		}
		if got := evidenceAs(t, r, "internal-reader", occurrenceAt(t, r, vendored)); got.ThirdParty {
			t.Errorf("the code finding at %s says third-party from an older run; the newest run declared nothing", vendored)
		}
	})
}

// occurrenceAt is the occurrence identity of the newest code finding at a path.
func occurrenceAt(t *testing.T, r *httpapitest.Reach, path string) string {
	t.Helper()
	var occurrence string
	if err := r.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		ColumnExpr(`"f"."occurrence_identity"`).
		Where(`"ar"."path" = ?`, path).Where(`"f"."kind" = ?`, kind.Analysis).
		OrderExpr(`"f"."id" DESC`).Limit(1).Scan(t.Context(), &occurrence); err != nil {
		t.Fatal(err)
	}
	return occurrence
}
