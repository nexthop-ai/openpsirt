// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// formerBuild is the prefix every address of one build had before the paths
// were renamed.
const formerBuild = "/v1/products/{product}/streams/{stream}/variants/{variant}"

// formerAddresses is every address an operation answered at before the paths
// were renamed, other than the pipeline's, with the operation that moved. A
// rename of a path parameter alone leaves the address as it was, so none is
// listed.
var formerAddresses = []struct{ method, path, operation string }{
	{http.MethodGet, "/v1/audit/claims", "list-audit-decisions"},
	{http.MethodDelete, "/v1/claims/{id}", "withdraw-decision"},
	{http.MethodGet, "/v1/claims/{id}", "get-decision"},
	{http.MethodPost, "/v1/claims/{id}/approval", "approve-decision"},
	{http.MethodGet, "/v1/claims/{id}/approvals", "list-decision-approvals"},
	{http.MethodGet, "/v1/claims/{id}/comments", "list-decision-comments"},
	{http.MethodPost, "/v1/claims/{id}/comments", "comment-on-decision"},
	{http.MethodPut, "/v1/claims/{id}/elsewhere", "point-decision-elsewhere"},
	{http.MethodPut, "/v1/claims/{id}/promise", "repromise-upgrade"},
	{http.MethodPost, "/v1/claims/{id}/reaffirmation", "reaffirm-decision"},
	{http.MethodPut, "/v1/claims/{id}/reasoning", "revise-decision"},
	{http.MethodGet, "/v1/claims/{id}/revisions", "list-decision-revisions"},
	{http.MethodPost, "/v1/claims/{id}/send-back", "send-decision-back"},
	{http.MethodPost, "/v1/claims/{id}/split", "split-decision"},
	{http.MethodGet, "/v1/decisions", "list-decision-occurrences"},
	{http.MethodGet, "/v1/decisions/{id}", "get-decision-occurrence"},
	{http.MethodGet, "/v1/disclosing", "list-approaching-disclosure"},
	{http.MethodDelete, "/v1/exploited-here/{id}", "clear-incident"},
	{http.MethodPost, "/v1/exploited-here/{id}/fixes", "name-fix-release"},
	{http.MethodDelete, "/v1/exploited-here/{id}/fixes/{fix}", "withdraw-fix-release"},
	{http.MethodPost, "/v1/exploited-here/{id}/told", "record-told-outside"},
	{http.MethodGet, "/v1/my-claims", "list-my-decisions"},
	{http.MethodGet, "/v1/my-claims.{format}", "export-my-decisions"},
	{http.MethodGet, "/v1/obligation-windows", "list-response-windows"},
	{http.MethodPost, "/v1/obligation-windows", "declare-response-window"},
	{http.MethodDelete, "/v1/obligation-windows/{id}", "retire-response-window"},
	{http.MethodPut, "/v1/obligation-windows/{id}", "change-response-window"},
	{http.MethodGet, "/v1/obligations", "list-incidents"},
	{http.MethodGet, "/v1/patch-branches", "list-patch-branch-lookups"},
	{http.MethodGet, "/v1/products/{product}/advisory-sources", "list-supplier-advisory-feeds"},
	{http.MethodPost, "/v1/products/{product}/advisory-sources", "add-supplier-advisory-feed"},
	{http.MethodDelete, "/v1/products/{product}/advisory-sources/{name}", "withdraw-supplier-advisory-feed"},
	{http.MethodGet, "/v1/products/{product}/fix-bundles", "list-planned-upgrades"},
	{http.MethodGet, "/v1/products/{product}/fix-bundles.{format}", "export-planned-upgrades"},
	{http.MethodPost, "/v1/products/{product}/issues/{vulnerability}/exploited-here", "record-incident"},
	{http.MethodGet, "/v1/products/{product}/issues/{vulnerability}/lead", "get-flaw-code-finding"},
	{http.MethodGet, "/v1/products/{product}/lead-rules", "list-suppression-rules"},
	{http.MethodPost, "/v1/products/{product}/lead-rules", "propose-suppression-rule"},
	{http.MethodDelete, "/v1/products/{product}/lead-rules/{id}", "retire-suppression-rule"},
	{http.MethodPost, "/v1/products/{product}/lead-rules/{id}/approval", "approve-suppression-rule"},
	{http.MethodGet, "/v1/products/{product}/lead-series", "list-code-finding-series"},
	{http.MethodGet, "/v1/products/{product}/leads", "list-code-findings"},
	{http.MethodGet, "/v1/products/{product}/leads.{format}", "export-code-findings"},
	{http.MethodGet, "/v1/products/{product}/routing-rules", "list-assignment-rules"},
	{http.MethodPost, "/v1/products/{product}/routing-rules", "add-assignment-rule"},
	{http.MethodGet, "/v1/products/{product}/routing-rules/preview", "preview-assignment-rule"},
	{http.MethodDelete, "/v1/products/{product}/routing-rules/{id}", "retire-assignment-rule"},
	{http.MethodGet, "/v1/products/{product}/streams", "list-branches-and-tags"},
	{http.MethodPost, "/v1/products/{product}/streams", "declare-branch-or-tag"},
	{http.MethodDelete, "/v1/products/{product}/streams/{stream}", "retire-branch-or-tag"},
	{http.MethodPatch, "/v1/products/{product}/streams/{stream}", "amend-branch-or-tag"},
	{http.MethodPut, "/v1/products/{product}/streams/{stream}/end-of-life", "set-branch-or-tag-end-of-life"},
	{http.MethodPut, "/v1/products/{product}/streams/{stream}/release", "set-release-details"},
	{http.MethodGet, "/v1/products/{product}/streams/{stream}/variants", "list-release-variants"},
	{http.MethodGet, formerBuild + "/analyses", "list-analyses"},
	{http.MethodPost, formerBuild + "/analyses", "upload-analysis"},
	{http.MethodGet, formerBuild + "/carried", "preview-carried-decisions"},
	{http.MethodPost, formerBuild + "/carried", "carry-decisions"},
	{http.MethodGet, formerBuild + "/carried-patches", "list-carried-patches"},
	{http.MethodGet, formerBuild + "/components", "list-top-level-components"},
	{http.MethodGet, formerBuild + "/components/mine", "list-my-components"},
	{http.MethodGet, formerBuild + "/components/{component}/around", "get-component-neighbors"},
	{http.MethodPost, formerBuild + "/components/{component}/decisions", "decide-in-bulk"},
	{http.MethodGet, formerBuild + "/components/{component}/issues", "list-issues-at-component"},
	{http.MethodGet, formerBuild + "/findings/{vulnerability}/components/{component}", "get-finding"},
	{http.MethodPut, formerBuild + "/findings/{vulnerability}/components/{component}/assignment", "assign-finding"},
	{http.MethodPost, formerBuild + "/findings/{vulnerability}/components/{component}/decision", "decide-finding"},
	{http.MethodGet, formerBuild + "/findings/{vulnerability}/components/{component}/reach", "get-finding-reach"},
	{http.MethodDelete, formerBuild + "/findings/{vulnerability}/components/{component}/tags/{tag}", "unlabel-finding"},
	{http.MethodPut, formerBuild + "/findings/{vulnerability}/components/{component}/tags/{tag}", "label-finding"},
	{http.MethodGet, formerBuild + "/findings/{vulnerability}/places/{place}/decision", "get-finding-decision"},
	{http.MethodPost, formerBuild + "/findings/{vulnerability}/places/{place}/decision", "decide"},
	{http.MethodPost, formerBuild + "/findings/{vulnerability}/places/{place}/decision/reaffirmation", "reaffirm-finding-decision"},
	{http.MethodGet, formerBuild + "/findings/{vulnerability}/places/{place}/reach", "get-decision-reach"},
	{http.MethodPost, formerBuild + "/findings/{vulnerability}/resolve", "resolve-finding"},
	{http.MethodGet, formerBuild + "/leads/{place}", "get-code-finding-evidence"},
	{http.MethodPut, formerBuild + "/leads/{place}/assignment", "assign-code-finding"},
	{http.MethodGet, formerBuild + "/leads/{place}/collaborators", "list-code-finding-collaborators"},
	{http.MethodDelete, formerBuild + "/leads/{place}/collaborators/{identity}", "remove-code-finding-collaborator"},
	{http.MethodPut, formerBuild + "/leads/{place}/collaborators/{identity}", "add-code-finding-collaborator"},
	{http.MethodPost, formerBuild + "/leads/{place}/decision", "decide-code-finding"},
	{http.MethodPost, formerBuild + "/leads/{place}/fixed", "fix-code-finding"},
	{http.MethodGet, formerBuild + "/leads/{place}/hand-off", "get-code-finding-flaw"},
	{http.MethodPost, formerBuild + "/leads/{place}/hand-off", "record-code-finding-as-flaw"},
	{http.MethodPost, formerBuild + "/leads/{place}/hand-off/withdrawal", "undo-code-finding-flaw"},
	{http.MethodDelete, formerBuild + "/leads/{place}/move", "exclude-code-finding-from-disclosure"},
	{http.MethodPut, formerBuild + "/leads/{place}/move", "include-code-finding-in-disclosure"},
	{http.MethodGet, formerBuild + "/match-coverage", "list-unmatched-components"},
	{http.MethodGet, formerBuild + "/match-coverage.{format}", "export-unmatched-components"},
	{http.MethodGet, formerBuild + "/pending-upgrades", "list-build-planned-upgrades"},
	{http.MethodGet, formerBuild + "/pending-upgrades.{format}", "export-build-planned-upgrades"},
	{http.MethodGet, formerBuild + "/readiness", "get-readiness"},
	{http.MethodGet, formerBuild + "/register", "get-disposition-register"},
	{http.MethodGet, formerBuild + "/register.{format}", "export-disposition-register"},
	{http.MethodGet, formerBuild + "/runs/{run}", "get-scan-run"},
	{http.MethodGet, formerBuild + "/scans/{scan}/documents/{document}", "fetch-scan-document"},
	{http.MethodGet, formerBuild + "/uploads", "list-uploads"},
	{http.MethodGet, formerBuild + "/vex", "get-vex"},
	{http.MethodGet, formerBuild + "/vex/issuance", "list-published-vex"},
	{http.MethodPost, formerBuild + "/vex/issuance", "record-published-vex"},
	{http.MethodGet, formerBuild + "/vex/issuance/{version}", "get-published-vex"},
	{http.MethodGet, "/v1/products/{product}/tags", "list-labels"},
	{http.MethodPut, "/v1/products/{product}/triage-floor", "set-product-minimum-severity"},
	{http.MethodGet, "/v1/products/{product}/vex-statements", "list-vex-documents"},
	{http.MethodPost, "/v1/products/{product}/vex-statements", "upload-vex-statements"},
	{http.MethodGet, "/v1/scanning", "list-last-uploads"},
	{http.MethodGet, "/v1/scanning.{format}", "export-last-uploads"},
	{http.MethodGet, "/v1/work/set-aside", "list-failed-jobs"},
	{http.MethodPost, "/v1/work/set-aside/{id}/retry", "retry-failed-job"},
}

// formerNames stands in a value for each parameter of a former address.
var formerNames = strings.NewReplacer(
	"{product}", "mine", "{stream}", "master", "{branch_or_tag}", "master", "{variant}", "broadcom",
	"{vulnerability}", "CVE-2026-9999", "{component}", "libnl-3-200",
	"{place}", "1", "{id}", "1", "{scan}", "1", "{document}", "1", "{tag}", "one",
	"{identity}", "reader", "{format}", "json", "{name}", "one", "{fix}", "1",
	"{advisory}", "1", "{alias}", "CVE-2026-1000", "{version}", "1",
)

// operationsByID is every operation the document holds, by identifier, with
// the method and path it answers at.
func operationsByID(api huma.API) map[string][2]string {
	out := map[string][2]string{}
	for path, item := range api.OpenAPI().Paths {
		for method, op := range httpapitest.Operations(item) {
			out[op.OperationID] = [2]string{method, path}
		}
	}
	return out
}

// An address renamed without an alias answers as an address nothing ever
// answered, and the operation it named answers at its new address. The two
// renames that swap a path between operations leave the former address
// answering the operation now holding it, which is checked to be another one.
func TestARenamedAddressAnswersAsNoRoute(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		nothing := r.Body(t, "admin", http.MethodGet, "/v1/no-route-answers-this")
		if nothing.Code != http.StatusNotFound {
			t.Fatalf("an address nothing answers answered %d: %s", nothing.Code, nothing.Text)
		}
		held := operationsByID(r.API)
		moved, taken := 0, 0
		for _, former := range formerAddresses {
			now, ok := held[former.operation]
			if !ok {
				t.Errorf("%s is not in the document", former.operation)
				continue
			}
			if now[0] == former.method && now[1] == former.path {
				t.Errorf("%s still answers at %s %s", former.operation, former.method, former.path)
				continue
			}
			if got := r.Body(t, "admin", now[0], formerNames.Replace(now[1])); got.Text == nothing.Text {
				t.Errorf("%s at its new address %s %s answered as no route", former.operation, now[0], now[1])
			}

			holder := ""
			for id, at := range held {
				if at[0] == former.method && at[1] == former.path {
					holder = id
				}
			}
			if holder != "" {
				taken++
				continue
			}
			moved++
			at := formerNames.Replace(former.path)
			if got := r.Body(t, "admin", former.method, at); got.Code != nothing.Code || got.Text != nothing.Text {
				t.Errorf("%s %s answered %d, want what no route answers: %s",
					former.method, at, got.Code, got.Text)
			}
		}
		if moved == 0 || taken == 0 {
			t.Fatalf("%d former addresses answered as no route and %d are held by another "+
				"operation, so this checked less than it names", moved, taken)
		}
	})
}

// formerUpload is the pipeline's former upload address for the ingest
// fixture's build.
func formerUpload() string {
	return strings.NewReplacer("{product}", fixture.ProductName, "{branch_or_tag}", fixture.BranchName,
		"{variant}", fixture.CustomerVariant).Replace(core.FormerUpload)
}

// answered is what the server says to one request, as a caller sees it.
func answered(f *httpapitest.IngestFixture, req *http.Request) (int, string) {
	rec := httptest.NewRecorder()
	f.Handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// A pipeline uploads at the address it used before the paths were renamed
// exactly as at the new one: an inventory is taken alike, the same inventory
// sent to the other address is the upload already held, a refused request is
// refused in the same words, and the list of what was uploaded is the same
// list.
//
// Verified by dropping the former address from the upload's registration,
// which the first upload then fails on.
func TestAPipelineUploadsAtTheFormerAddressAsAtTheNewOne(t *testing.T) {
	httpapitest.IngestOn(t, dbtest.Two, queue.DefaultOptions(), func(t *testing.T, f *httpapitest.IngestFixture) {
		former := formerUpload()
		if former == f.Path {
			t.Fatalf("the former address is the new one, %s, so this compares nothing", former)
		}
		first := httpapitest.Inventory(httpapitest.Nowish(), "bash")
		second := httpapitest.Inventory(httpapitest.Nowish().Add(time.Minute), "zsh")

		formerCode, formerTaken := f.Send(t, httpapitest.Upload(t, former, first))
		newCode, newTaken := f.Send(t, httpapitest.Upload(t, f.Path, second))
		if formerCode != http.StatusAccepted || newCode != formerCode ||
			formerTaken.Outcome != newTaken.Outcome || formerTaken.ScanID == newTaken.ScanID {
			t.Fatalf("an inventory was taken at the former address with %d %+v and at the new one with %d %+v",
				formerCode, formerTaken, newCode, newTaken)
		}

		// The same inventory at the other address is the one already held,
		// with the same receipt either way.
		for _, sent := range []struct {
			inventory string
			scan      int64
		}{{first, formerTaken.ScanID}, {second, newTaken.ScanID}} {
			atFormer, formerBody := answered(f, f.Sending(httpapitest.Upload(t, former, sent.inventory)))
			atNew, newBody := answered(f, f.Sending(httpapitest.Upload(t, f.Path, sent.inventory)))
			if atFormer != atNew || formerBody != newBody {
				t.Errorf("sent again, the former address answered %d %s and the new one %d %s",
					atFormer, formerBody, atNew, newBody)
			}
			var receipt struct {
				ScanID  int64  `json:"scan_id"`
				Outcome string `json:"outcome"`
			}
			if err := json.Unmarshal([]byte(newBody), &receipt); err != nil {
				t.Fatalf("decode %s: %v", newBody, err)
			}
			if receipt.ScanID != sent.scan || receipt.Outcome != "already_held" {
				t.Errorf("sent again, the receipt was %s, want upload %d already held", newBody, sent.scan)
			}
		}

		// Refused alike: no credential, and a form with no inventory in it.
		refusals := map[string]struct {
			request func(path string) *http.Request
			status  int
		}{
			"no credential": {func(path string) *http.Request {
				return httpapitest.Upload(t, path, first)
			}, http.StatusUnauthorized},
			"no inventory": {func(path string) *http.Request {
				req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(nil))
				req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
				return f.Sending(req)
			}, http.StatusUnprocessableEntity},
		}
		for name, refusal := range refusals {
			atFormer, formerBody := answered(f, refusal.request(former))
			atNew, newBody := answered(f, refusal.request(f.Path))
			if atNew != refusal.status {
				t.Errorf("%s at the new address answered %d, want %d", name, atNew, refusal.status)
			}
			if atFormer != atNew || formerBody != newBody {
				t.Errorf("%s: the former address answered %d %s and the new one %d %s",
					name, atFormer, formerBody, atNew, newBody)
			}
		}

		formerList, formerListed := httpapitest.Receipts(t, f, f.Key, former)
		newList, newListed := httpapitest.Receipts(t, f, f.Key, f.Path)
		formerJSON, _ := json.Marshal(formerListed.Body)
		newJSON, _ := json.Marshal(newListed.Body)
		if formerList != http.StatusOK || newList != formerList || !bytes.Equal(formerJSON, newJSON) {
			t.Errorf("the uploads listed at the former address were %d %s and at the new one %d %s",
				formerList, formerJSON, newList, newJSON)
		}
		if len(newListed.Body.Items) != 2 {
			t.Errorf("the list holds %d uploads, want the two sent", len(newListed.Body.Items))
		}
	})
}

// What one upload changed reads the same at the former address as at the new
// one, to a pipeline's key, to a person and to nobody, and for an upload that
// does not exist.
//
// Verified by dropping the former address from the read's registration: every
// former request then answers 404.
func TestWhatAnUploadChangedReadsAtTheFormerAddressAsAtTheNewOne(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		former := strings.NewReplacer("{product}", "mine", "{branch_or_tag}", "master",
			"{variant}", "broadcom").Replace(core.FormerUploadChanges)
		current := "/v1/products/mine/branches-and-tags/master/variants/broadcom/sboms/{sbom}/changes"
		compared := 0
		for _, upload := range []string{"1", "999999"} {
			at := strings.ReplaceAll(former, "{sbom}", upload)
			now := strings.ReplaceAll(current, "{sbom}", upload)
			for who, ask := range map[string]func(path string) httpapitest.Response{
				"a pipeline": func(path string) httpapitest.Response {
					return r.WithKey(t, r.Key, http.MethodGet, path)
				},
				"a reader": func(path string) httpapitest.Response {
					return r.Body(t, "reader", http.MethodGet, path)
				},
				"nobody": func(path string) httpapitest.Response {
					return r.Body(t, "", http.MethodGet, path)
				},
			} {
				was, is := ask(at), ask(now)
				if was.Code != is.Code || was.Text != is.Text {
					t.Errorf("%s reading upload %s answered %d %s at the former address and %d %s at the new one",
						who, upload, was.Code, was.Text, is.Code, is.Text)
				}
				if upload == "1" && who != "nobody" && is.Code == http.StatusOK {
					compared++
				}
			}
		}
		if compared != 2 {
			t.Fatalf("%d readers read the upload's changes, want 2, so this compared refusals alone", compared)
		}
	})
}
