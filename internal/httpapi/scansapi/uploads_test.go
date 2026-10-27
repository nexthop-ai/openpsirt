// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/scansapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

const seededAt = "/v1/products/mine/branches-and-tags/master/variants/broadcom"

// uploadKinds reads the seeded build's uploads as somebody, or as the
// pipeline key where nobody is named.
func uploadKinds(t *testing.T, r *httpapitest.Reach, who string) (int, map[string]scansapi.UploadKindBody, []string) {
	t.Helper()
	return uploadKindsAt(t, r, seededAt, who)
}

func uploadKindsAt(t *testing.T, r *httpapitest.Reach, build, who string) (int, map[string]scansapi.UploadKindBody, []string) {
	t.Helper()
	var got httpapitest.Response
	if who == "" {
		got = r.WithKey(t, r.Key, http.MethodGet, build+"/uploads")
	} else {
		got = r.Body(t, who, http.MethodGet, build+"/uploads")
	}
	if got.Code != http.StatusOK {
		return got.Code, nil, nil
	}
	var out struct {
		Items []scansapi.UploadKindBody `json:"items"`
	}
	if err := json.Unmarshal([]byte(got.Text), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, got.Text)
	}
	byKind := map[string]scansapi.UploadKindBody{}
	var order []string
	for _, each := range out.Items {
		byKind[string(each.Type)] = each
		order = append(order, string(each.Type))
	}
	return got.Code, byKind, order
}

func TestABuildsUploadsListEachKindItsReaderMayRead(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		check := func(when string) {
			t.Helper()
			for who, want := range map[string][]string{
				// Static analysis results open at internal visibility, so a
				// reader of disclosed findings is not told about the runs.
				"reader":          {"sbom", "vex", "supplier-advisory"},
				"internal-reader": {"sbom", "sarif", "vex", "supplier-advisory"},
				// A key reads what was sent to a build it may send to.
				"": {"sbom", "sarif"},
			} {
				code, _, order := uploadKinds(t, r, who)
				if code != http.StatusOK || !slices.Equal(order, want) {
					t.Errorf("%s: %q answered %d listing %v, want %v", when, who, code, order, want)
				}
			}
			if code, _, _ := uploadKinds(t, r, "outsider"); code != http.StatusNotFound {
				t.Errorf("%s: somebody who may not see the product answered %d, want 404", when, code)
			}
		}
		r.ScannedWithEvidence(t)
		check("once the build was scanned")

		// A build declared and never sent anything lists the same kinds.
		if code := r.As(t, "admin", http.MethodPost, "/v1/products/mine/variants"); code != http.StatusCreated {
			t.Fatalf("declaring a variant answered %d", code)
		}
		const fresh = "/v1/products/mine/branches-and-tags/master/variants/declared-by-the-test"
		for who, want := range map[string][]string{
			"reader":          {"sbom", "vex", "supplier-advisory"},
			"internal-reader": {"sbom", "sarif", "vex", "supplier-advisory"},
		} {
			code, kinds, order := uploadKindsAt(t, r, fresh, who)
			if code != http.StatusOK || !slices.Equal(order, want) || kinds["sbom"].Total != 0 {
				t.Errorf("a build never sent anything: %q answered %d listing %v, want %v",
					who, code, order, want)
			}
		}
	})
}

func TestABuildsUploadsSayWhatBecameOfTheNewestOfEachKind(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.ScannedWithEvidence(t)
		if got := r.Vexed(t, "admin", "debian", httpapitest.Said("fixed", "", "")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}

		// A static analysis run, sent as a build sends one.
		body, form := httpapitest.Form(t,
			httpapitest.Part{Field: "sarif", Filename: "run.sarif", Content: clangRun},
			httpapitest.Part{Field: "series", Content: "nightly"},
			httpapitest.Part{Field: "source-root", Content: "/home/builder/sonic"})
		req := httptest.NewRequest(http.MethodPost, seededAt+"/analyses", body)
		req.Header.Set("Content-Type", form)
		req.Header.Set("Authorization", "Bearer "+r.Key)
		sent := httptest.NewRecorder()
		r.Handler.ServeHTTP(sent, req)
		if sent.Code != http.StatusAccepted {
			t.Fatalf("sending a run answered %d: %s", sent.Code, sent.Body.String())
		}

		_, kinds, _ := uploadKinds(t, r, "internal-reader")
		if sbom := kinds["sbom"]; sbom.Total != 1 || sbom.Latest == nil || sbom.Latest.Status == "refused" {
			t.Errorf("the SBOMs read %+v; want the one scanned", sbom)
		}
		if sarif := kinds["sarif"]; sarif.Total != 1 || sarif.Latest == nil || sarif.Latest.Status != "in-progress" {
			t.Errorf("the static analysis runs read %+v; want the one queued", sarif)
		}
		if vex := kinds["vex"]; vex.Total != 1 || vex.Latest == nil || vex.Latest.Status != "completed" {
			t.Errorf("the VEX documents read %+v; want debian's, completed", vex)
		}
		if advisories := kinds["supplier-advisory"]; advisories.Total != 0 || advisories.Latest != nil {
			t.Errorf("the supplier advisories read %+v; want none", advisories)
		}

		// An upload turned away after the newest one taken is the newest, and
		// it is not counted: nothing of it is held.
		build := r.BuildOf(t, httpapitest.SeededBuild)
		if err := ingest.NewStore(r.DB.DB).Refused(ctx, access.Everything("test"),
			ingest.Refusal{BuildID: build, Reason: "that is not an inventory"}); err != nil {
			t.Fatal(err)
		}
		if err := series.NewStore(r.DB.DB).Refused(ctx, series.Refusal{
			BuildID: build, Series: "nightly", Kind: kind.Analysis, Reason: "it names no commit",
		}); err != nil {
			t.Fatal(err)
		}
		_, kinds, _ = uploadKinds(t, r, "internal-reader")
		for each, reason := range map[string]string{
			"sbom": "that is not an inventory", "sarif": "it names no commit",
		} {
			got := kinds[each]
			if got.Latest == nil || got.Latest.Status != "refused" || got.Latest.Reason != reason {
				t.Errorf("%s reads %+v; want refused, saying %q", each, got.Latest, reason)
			}
		}
		if kinds["sbom"].Total != 1 || kinds["sarif"].Total != 1 {
			t.Errorf("a refusal was counted: %d SBOMs and %d runs", kinds["sbom"].Total, kinds["sarif"].Total)
		}

		// An upload taken after the refusal is the newest again.
		r.Recorded(t, build, "after-the-refusal")
		_, kinds, _ = uploadKinds(t, r, "internal-reader")
		if sbom := kinds["sbom"]; sbom.Total != 2 || sbom.Latest == nil || sbom.Latest.Status != "in-progress" {
			t.Errorf("the SBOMs read %+v; want the upload still being read", sbom.Latest)
		}
	})
}
