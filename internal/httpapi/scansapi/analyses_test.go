// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/scansapi"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

const clangRun = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clang-tidy","version":"18.1.3"}},` +
	`"results":[{"ruleId":"bugprone-use-after-move","message":{"text":"x used after it was moved"},` +
	`"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///home/builder/sonic/src/a.c"},` +
	`"region":{"startLine":4}}}]}]}]}`

// analyses is the path a build sends its analyzer runs to.
func analyses(f *httpapitest.IngestFixture) string {
	return strings.TrimSuffix(f.Path, "/sboms") + "/analyses"
}

// sendRun posts an analyzer run with the fields beside it, as a pipeline.
func sendRun(t *testing.T, f *httpapitest.IngestFixture, docs []string, fields map[string]string) (int, scansapi.AnalysisResult, string) {
	t.Helper()
	var parts []httpapitest.Part
	for _, d := range docs {
		parts = append(parts, httpapitest.Part{Field: "sarif", Filename: "run.sarif", Content: d})
	}
	for k, v := range fields {
		parts = append(parts, httpapitest.Part{Field: k, Content: v})
	}
	body, kind := httpapitest.Form(t, parts...)
	req := httptest.NewRequest(http.MethodPost, analyses(f), body)
	req.Header.Set("Content-Type", kind)
	rec := httptest.NewRecorder()
	f.Handler.ServeHTTP(rec, f.Sending(req))
	var out scansapi.AnalysisResult
	if rec.Code < 300 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, out, rec.Body.String()
}

func gzipped(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestAnAnalyzerRunIsQueuedAndASecondSendingIsTheSameRun(t *testing.T) {
	httpapitest.IngestOn(t, dbtest.Two, queue.DefaultOptions(), func(t *testing.T, f *httpapitest.IngestFixture) {
		fields := map[string]string{
			"series": "clang-tidy/default", "built": "2026-10-01T02:00:00Z",
			"source-root": "/home/builder/sonic", "units-expected": "3", "units-analyzed": "3",
		}
		code, first, body := sendRun(t, f, []string{gzipped(t, clangRun)}, fields)
		if code != http.StatusAccepted || first.Outcome != "queued" || first.Series != "clang-tidy/default" {
			t.Fatalf("answered %d %+v (%s); want 202 queued", code, first, body)
		}
		depth, err := f.Queue.Depth(t.Context(), queue.Analyze)
		if err != nil || depth != 1 {
			t.Fatalf("%d runs waiting, %v; want 1", depth, err)
		}

		code, again, _ := sendRun(t, f, []string{gzipped(t, clangRun)}, fields)
		if code != http.StatusOK || again.Outcome != "already_held" || again.RunID != first.RunID {
			t.Errorf("answered %d %+v; want 200 already_held for run %d", code, again, first.RunID)
		}

		// The same bytes from the next night's build are another run.
		fields["built"] = "2026-10-02T02:00:00Z"
		code, next, _ := sendRun(t, f, []string{gzipped(t, clangRun)}, fields)
		if code != http.StatusAccepted || next.RunID == first.RunID {
			t.Errorf("answered %d %+v; want a second run", code, next)
		}

		req := httptest.NewRequest(http.MethodGet, analyses(f), nil)
		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, f.Sending(req))
		var listed scansapi.AnalysisReceiptsOutput
		if err := json.Unmarshal(rec.Body.Bytes(), &listed.Body); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("answered %d (%s)", rec.Code, rec.Body.String())
		}
		if listed.Body.Total != 2 || listed.Body.Items[0].Status != core.RunStatus(series.Queued) {
			t.Errorf("receipts %+v; want two queued runs", listed.Body)
		}
	})
}

func TestAnAnalyzerRunIsHeldAsItsPlacedResultsAndNeverAsSent(t *testing.T) {
	httpapitest.IngestOn(t, dbtest.Two, queue.DefaultOptions(), func(t *testing.T, f *httpapitest.IngestFixture) {
		// The product keeps no source, so the snippet is only the document's.
		var product int64
		if err := f.DB.DB.NewSelect().TableExpr(`"product"`).ColumnExpr(`"id"`).Limit(1).
			Scan(t.Context(), &product); err != nil {
			t.Fatal(err)
		}
		no := false
		if err := sourcelink.NewStore(f.DB.DB).Replace(t.Context(), product,
			sourcelink.Config{Paths: []sourcelink.Path{{Prefix: "", Snippets: &no}}}); err != nil {
			t.Fatal(err)
		}
		sent := strings.Replace(clangRun, `"region":{"startLine":4}`,
			`"region":{"startLine":4,"snippet":{"text":"token = \"hunter2\""}}`, 1)
		code, run, body := sendRun(t, f, []string{sent}, map[string]string{
			"series": "clang-tidy/default", "source-root": "/home/builder/sonic",
		})
		if code != http.StatusAccepted {
			t.Fatalf("answered %d (%s); want 202", code, body)
		}
		store := series.NewStore(f.DB.DB)
		docs, err := store.Documents(t.Context(), run.RunID)
		if err != nil || len(docs) != 1 {
			t.Fatalf("%d documents held, %v; want the placed results alone", len(docs), err)
		}
		held, err := io.ReadAll(store.Open(t.Context(), &docs[0]))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(held), `"src/a.c"`) {
			t.Errorf("held %s; want the result placed at src/a.c", held)
		}
		for _, sentOnly := range []string{"hunter2", "/home/builder", "2.1.0"} {
			if strings.Contains(string(held), sentOnly) {
				t.Errorf("held %s; want nothing of %q, which only the document carried", held, sentOnly)
			}
		}
	})
}

func TestAnAnalyzerUploadIsRefusedInWordsTheSenderCanAct(t *testing.T) {
	httpapitest.IngestOn(t, dbtest.Two, queue.DefaultOptions(), func(t *testing.T, f *httpapitest.IngestFixture) {
		for name, c := range map[string]struct {
			docs   []string
			fields map[string]string
			says   string
		}{
			"no series":      {[]string{clangRun}, nil, "names no series"},
			"a bad time":     {[]string{clangRun}, map[string]string{"series": "s", "built": "yesterday"}, "RFC 3339"},
			"half the units": {[]string{clangRun}, map[string]string{"series": "s", "units-expected": "3"}, "together"},
			"not a number":   {[]string{clangRun}, map[string]string{"series": "s", "exit-status": "zero"}, "whole number"},
			"not SARIF":      {[]string{`{"runs":`}, map[string]string{"series": "s"}, "document 1"},
			"broken gzip":    {[]string{gzipped(t, clangRun)[:20]}, map[string]string{"series": "s"}, "gzip"},
			"in the future":  {[]string{clangRun}, map[string]string{"series": "s", "built": "2999-01-01T00:00:00Z"}, "future"},
			"too many at once": {[]string{clangRun, clangRun, clangRun, clangRun, clangRun, clangRun, clangRun, clangRun,
				clangRun, clangRun, clangRun, clangRun, clangRun, clangRun, clangRun, clangRun, clangRun},
				map[string]string{"series": "s"}, "per-unit documents"},
			"a scanner alone": {[]string{`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}`},
				map[string]string{"series": "s"}, "scanner's (Trivy)"},
			"a run that did not run": {[]string{`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"clang-tidy"}}}]}`},
				map[string]string{"series": "s"}, "did not run"},
			"a long series": {[]string{clangRun}, map[string]string{"series": strings.Repeat("s", database.NameWidth+1)},
				"may be at most"},
		} {
			t.Run(name, func(t *testing.T) {
				code, _, body := sendRun(t, f, c.docs, c.fields)
				if code != http.StatusUnprocessableEntity || !strings.Contains(body, c.says) {
					t.Errorf("answered %d (%s); want 422 saying %q", code, body, c.says)
				}
			})
		}
	})
}

func TestTheTextAProducerStatesIsRecordedAtAnyLength(t *testing.T) {
	httpapitest.IngestOn(t, dbtest.Two, queue.DefaultOptions(), func(t *testing.T, f *httpapitest.IngestFixture) {
		long := strings.Repeat("a", 4*database.NameWidth)
		doc := strings.Replace(clangRun, `"name":"clang-tidy","version":"18.1.3"`,
			`"name":"clang-tidy-`+long+`","version":"`+long+`"`, 1)
		doc = strings.Replace(doc, `"results"`, `"properties":{"openpsirt/client":"`+long[:200]+`"},"results"`, 1)
		code, _, body := sendRun(t, f, []string{doc}, map[string]string{
			"series": strings.Repeat("s", database.NameWidth), "commit": long,
		})
		if code != http.StatusAccepted {
			t.Errorf("answered %d (%s); want 202", code, body)
		}
	})
}

func TestAnAnalyzerUploadTurnedAwayIsRecordedAgainstItsSeries(t *testing.T) {
	httpapitest.IngestOn(t, dbtest.Two, queue.DefaultOptions(), func(t *testing.T, f *httpapitest.IngestFixture) {
		for _, fields := range []map[string]string{
			{"series": "nightly", "built": "yesterday"},
			{"series": "nightly", "exit-status": "zero"},
			nil,
		} {
			if code, _, body := sendRun(t, f, []string{clangRun}, fields); code != http.StatusUnprocessableEntity {
				t.Fatalf("answered %d (%s); want 422", code, body)
			}
		}
		req := httptest.NewRequest(http.MethodGet, analyses(f), nil)
		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, f.Sending(req))
		var listed struct {
			Refused []scansapi.AnalysisRefusalBody `json:"refused"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
			t.Fatalf("decode: %v (%s)", err, rec.Body.String())
		}
		got := map[string]string{}
		for _, r := range listed.Refused {
			got[r.Series] = r.Reason
		}
		if len(got) != 2 || !strings.Contains(got["nightly"], "whole number") ||
			!strings.Contains(got[""], "names no series") {
			t.Errorf("refused %+v; want the last refusal of nightly and the one naming no series", listed.Refused)
		}
	})
}

func TestAnAnalyzerUploadFromSomebodyNotAdmittedIsRecordedNowhere(t *testing.T) {
	// Signed in and reading the product's security testing work, but not triaging
	// it, so the upload is refused by admission rather than before it.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		body, form := httpapitest.Form(t, httpapitest.Part{Field: "sarif", Filename: "run.sarif", Content: `{"runs":`},
			httpapitest.Part{Field: "series", Content: "stranger"})
		got := r.Post(t, "security-testing-reader", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/analyses", body, form)
		if got.Code != http.StatusForbidden {
			t.Fatalf("an upload from somebody who does not triage security testing work answered %d: %s", got.Code, got.Body)
		}
		held, err := r.DB.DB.NewSelect().TableExpr(`"series_refusal"`).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if held != 0 {
			t.Errorf("%d refusals were recorded for an upload its sender was not admitted to send", held)
		}
	})
}
