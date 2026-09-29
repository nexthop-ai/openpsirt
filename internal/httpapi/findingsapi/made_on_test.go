// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// madeOn is the variants of the builds one claim records it was made on.
func madeOn(t *testing.T, r *httpapitest.Reach, claim int64) []string {
	t.Helper()
	var variants []string
	if err := r.DB.DB.NewRaw(`SELECT "va"."name" FROM "claim_build" AS "cb"
		JOIN "target" AS "t" ON "t"."id" = "cb"."target_id"
		JOIN "variant" AS "va" ON "va"."id" = "t"."variant_id"
		WHERE "cb"."claim_id" = ?`, claim).Scan(t.Context(), &variants); err != nil {
		t.Fatal(err)
	}
	slices.Sort(variants)
	return variants
}

func TestAJudgmentRecordsTheBuildOnScreenAndTheBuildsChosenBesideIt(t *testing.T) {
	// A decision reaches every build whose versions match, so which builds
	// somebody was looking at is recorded when it is made: the one in the
	// path, and every one they named beside it. Nothing else.
	//
	// On every engine, because what this pins is rows a write leaves.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		r.ScannedAlso(t, "mellanox", "3.8.0")
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"

		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"wont-fix","reasoning":"Not worth it.",`+
				`"also":[{"stream":"master","variant":"mellanox","version":"3.8.0"}]}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding across two builds answered %d: %s", got.Code, got.Body.String())
		}
		var out decided
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if made := madeOn(t, r, out.ClaimID); !slices.Equal(made, []string{"broadcom", "mellanox"}) {
			t.Errorf("the judgment records it was made on %v, want both builds", made)
		}
	})
}

func TestAJudgmentMadeOnOneBuildRecordsThatBuildAlone(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		r.ScannedAlso(t, "mellanox", "3.8.0")

		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200/decision",
			`{"outcome":"wont-fix","reasoning":"Not worth it."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", got.Code, got.Body.String())
		}
		var out decided
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if made := madeOn(t, r, out.ClaimID); !slices.Equal(made, []string{"broadcom"}) {
			t.Errorf("the judgment records it was made on %v, want broadcom alone", made)
		}
	})
}
