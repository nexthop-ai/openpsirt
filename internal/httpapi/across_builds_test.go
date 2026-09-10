package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// decided is what one judgment reports having written.
type decided struct {
	ClaimID  int64 `json:"claim_id"`
	Recorded int   `json:"recorded"`
	Also     []struct {
		Stream   string `json:"stream"`
		Variant  string `json:"variant"`
		Recorded int    `json:"recorded"`
	} `json:"also"`
}

func TestOneJudgmentAcrossBuildsIsWrittenWholeOrNotAtAll(t *testing.T) {
	// Applied a build at a time, a judgment half-applies: a refusal
	// part-way leaves it recorded in some releases and not others, as an
	// act nobody performed and nobody can point at afterwards.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		r.scannedAlso(t, "mellanox", "3.8.0")

		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"

		// A build nobody scanned, named beside one somebody did.
		refused := asPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"wont-fix","reasoning":"Not worth it.",`+
				`"also":[{"stream":"master","variant":"nosuch"}]}`)
		if refused.Code != http.StatusNotFound {
			t.Fatalf("naming a build that is not there answered %d, want 404: %s",
				refused.Code, refused.Body.String())
		}

		// The whole point: the build that would have succeeded holds nothing.
		if state := r.stateOf(t, "broadcom"); state != "undecided" {
			t.Errorf("a refused judgment left the first build %q, so it half-applied", state)
		}

		// And the same judgment across two builds that are both there is one
		// claim covering both.
		got := asPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"wont-fix","reasoning":"Not worth it.",`+
				`"also":[{"stream":"master","variant":"mellanox","version":"3.8.0"}]}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding across two builds answered %d: %s", got.Code, got.Body.String())
		}
		var out decided
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if out.Recorded != 1 {
			t.Errorf("the build in the path recorded %d, want its one place", out.Recorded)
		}
		if len(out.Also) != 1 || out.Also[0].Variant != "mellanox" || out.Also[0].Recorded != 1 {
			t.Fatalf("the other build reported %+v, want one place in mellanox", out.Also)
		}
		// One action, one claim, so an approver agrees to the judgment rather
		// than to one release of it.
		if out.ClaimID == 0 {
			t.Error("a judgment across builds recorded no claim to agree to")
		}
		for _, variant := range []string{"broadcom", "mellanox"} {
			if state := r.stateOf(t, variant); state != "waiting" {
				t.Errorf("%s stands at %q after the judgment, want waiting", variant, state)
			}
		}
	})
}

// stateOf is how far one build has decided the finding the helpers seed.
func (r *reach) stateOf(t *testing.T, variant string) string {
	t.Helper()
	var out struct {
		Items []struct {
			State string `json:"state"`
		} `json:"items"`
	}
	read(t, r, "triager",
		"/v1/products/mine/findings?stream=master&variant="+variant, &out)
	if len(out.Items) != 1 {
		t.Fatalf("%s lists %d rows, want the one the fixture seeds", variant, len(out.Items))
	}
	return out.Items[0].State
}

func TestABuildNamedTwiceInOneJudgmentIsRefused(t *testing.T) {
	// One judgment is recorded against a build once. Naming it twice is a
	// mistake that would otherwise be reported as a conflict from the write,
	// which says nothing about what the caller got wrong.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200/decision",
			`{"outcome":"wont-fix","reasoning":"Not worth it.",`+
				`"also":[{"stream":"master","variant":"broadcom"}]}`)
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("naming the same build twice answered %d, want 422: %s",
				got.Code, got.Body.String())
		}
	})
}
