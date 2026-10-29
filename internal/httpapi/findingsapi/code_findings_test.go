// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/findingsapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const codeFindingsAt = "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/"

func TestACodeFindingsEvidenceLinksEachOccurrenceIntoItsSource(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		var got findingsapi.CodeFindingEvidenceBody
		httpapitest.Read(t, r, "security-testing-reader", codeFindingsAt+occurrence, &got)
		if want := "https://github.com/acme/mine/blob/" + httpapitest.CodeFindingCommit + "/src/a.c#L12-L12"; got.At.Link != want {
			t.Errorf("the code finding links to %q (%s); want %q", got.At.Link, got.At.Unlinked, want)
		}
		if got.At.Snippet != "return;" || got.At.SnippetLine != 12 || !got.Open || got.NotSeen != "" {
			t.Errorf("evidence %+v; want the open code finding with its source", got.At)
		}
		if len(got.Steps) != 1 || got.Steps[0].Message != "allocated" ||
			got.Steps[0].Link != "https://github.com/acme/mine/blob/"+httpapitest.CodeFindingCommit+"/src/b.c#L3-L3" {
			t.Errorf("steps %+v; want the allocation, linked", got.Steps)
		}

		httpapitest.ApplyRun(t, r, time.Now().UTC().Add(-time.Hour), httpapitest.CodeFindingRun(false))
		httpapitest.Read(t, r, "security-testing-reader", codeFindingsAt+occurrence, &got)
		if got.NotSeen == "" || !got.Unchanged || got.Compare != "" {
			t.Errorf("not seen %v, unchanged %v, compare %q; want a disappearance at the same commit said so",
				got.NotSeen, got.Unchanged, got.Compare)
		}
	})
}

func TestACodeFindingIsAnsweredOnlyToSomebodyReadingSecurityTestingMaterial(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		absent := httpapitest.AsPerson(t, r, "security-testing-reader", http.MethodGet, codeFindingsAt+"0000", "")
		if absent.Code != http.StatusNotFound {
			t.Fatalf("an occurrence holding no code finding answered %d; want 404", absent.Code)
		}
		// Somebody who cannot see the product is refused at its name, as on
		// every route under it.
		for _, who := range []string{"reader", "private", "split-triager"} {
			got := httpapitest.AsPerson(t, r, who, http.MethodGet, codeFindingsAt+occurrence, "")
			if got.Code != http.StatusNotFound || got.Body.String() != absent.Body.String() {
				t.Errorf("%s was answered %d %s; want what an occurrence holding nothing answers", who, got.Code, got.Body.String())
			}
		}
	})
}
