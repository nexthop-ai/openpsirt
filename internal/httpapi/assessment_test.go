package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// A rating waiting for a second person says whether that person is you.
//
// The server refuses your own either way, so what this buys is a screen that
// says so rather than one offering a button that answers 422: the embargo
// extensions listed beside these in the review queue already carry the same
// field, and this one did not.
func TestARatingSaysWhetherItIsYourOwn(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		// Milder than what was published, which is the direction that waits.
		made := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/issues/CVE-2026-9999/assessment",
			`{"severity":"low","reasoning":"Not reachable in how we build it."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording a rating answered %d: %s", made.Code, made.Body.String())
		}
		var claim struct {
			ID            int64 `json:"id"`
			NeedsApproval bool  `json:"needs_approval"`
			Mine          bool  `json:"mine"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &claim); err != nil {
			t.Fatal(err)
		}
		if !claim.NeedsApproval {
			t.Fatal("a milder rating needed nobody, so this tests nothing")
		}
		if !claim.Mine {
			t.Error("the rating you just made does not read as yours")
		}

		mine := func(who string) bool {
			t.Helper()
			var page struct {
				Items []struct {
					ID   int64 `json:"id"`
					Mine bool  `json:"mine"`
				} `json:"items"`
			}
			got := asPerson(t, r, who, http.MethodGet, "/v1/assessments?state=proposed", "")
			if got.Code != http.StatusOK {
				t.Fatalf("listing as %s answered %d: %s", who, got.Code, got.Body.String())
			}
			if err := json.Unmarshal(got.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			for _, row := range page.Items {
				if row.ID == claim.ID {
					return row.Mine
				}
			}
			t.Fatalf("%s cannot see the rating at all, so this tests nothing", who)
			return false
		}
		if !mine("triager") {
			t.Error("the person who made it is not told it is theirs")
		}
		if mine("reviewer") {
			t.Error("somebody else's rating reads as their own, so the screen would refuse to " +
				"offer the one action they are there for")
		}
	})
}
