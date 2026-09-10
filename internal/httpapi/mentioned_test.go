package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestAMentionTellsOnlySomebodyWhoCouldAlreadyReadIt(t *testing.T) {
	// and the rule that makes it safe. On an undisclosed finding the
	// notification itself would say a finding exists, so whoever is told
	// is exactly whoever the editor would have offered — from the same
	// query, so the two cannot come to disagree.
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)

		// A claim to hang comments off.
		made := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+place+"/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"The parser is never reached."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("proposing answered %d: %s", made.Code, made.Body.String())
		}
		var claimed struct {
			ID      int64 `json:"id"`
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &claimed); err != nil {
			t.Fatal(err)
		}

		// A comment naming a colleague who reads this product, and one naming
		// somebody who does not exist at all.
		said := asPerson(t, r, "triager", http.MethodPost,
			"/v1/claims/"+itoa(claimed.ClaimID)+"/comments",
			`{"body":"@reader could you look at this? @nobody-at-all too, and @triager wrote it."}`)
		if said.Code >= 400 {
			t.Fatalf("commenting answered %d: %s", said.Code, said.Body.String())
		}

		// The colleague hears about it.
		var theirs struct {
			Items []struct {
				Kind string `json:"kind"`
				Body string `json:"body"`
			} `json:"items"`
		}
		read(t, r, "reader", "/v1/notifications", &theirs)
		var named int
		for _, item := range theirs.Items {
			if item.Kind == "mentioned" {
				named++
			}
		}
		if named != 1 {
			t.Errorf("the person named was told %d times, want once: %+v", named, theirs.Items)
		}

		// Whoever wrote it named themselves and is not told about it: a tool
		// that reports back what you have just typed is one people stop
		// reading. A name nobody holds simply reaches nobody, with no error —
		// the comment is on record by then and refusing it helps nobody.
		var mine struct {
			Items []struct {
				Kind string `json:"kind"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/notifications", &mine)
		for _, item := range mine.Items {
			if item.Kind == "mentioned" {
				t.Error("the author was told they named somebody")
			}
		}
	})
}

func TestAMentionOnUndisclosedWorkReachesNobodyWhoMayNotSeeIt(t *testing.T) {
	// The disclosure this rule exists to prevent: being told you were named on
	// a finding is being told the finding exists.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		made := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+
				`"summary":"The management socket answers before anyone authenticated.",`+
				`"severity":"critical"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", made.Code, made.Body.String())
		}

		// A comment on the undisclosed finding's decision would be the place
		// to name somebody; what matters here is that the public reader is
		// never told anything about it however it is written.
		var theirs struct {
			Items []struct {
				Kind string `json:"kind"`
				Body string `json:"body"`
			} `json:"items"`
		}
		read(t, r, "reader", "/v1/notifications", &theirs)
		for _, item := range theirs.Items {
			if strings.Contains(item.Body, "management socket") {
				t.Errorf("somebody who may not read undisclosed work was told: %q", item.Body)
			}
		}
	})
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var out []byte
	for n > 0 {
		out = append([]byte{byte('0' + n%10)}, out...)
		n /= 10
	}
	return string(out)
}

func TestAMentionThatReachedNobodyIsReportedBack(t *testing.T) {
	// mentions reaching only readers says mentioning somebody who cannot
	// see the finding is refused while composing, and only the candidate
	// list enforced it. Writing the name anyway was accepted, nobody was
	// told, and the author had no way to know — so a question was asked of
	// somebody who never heard it.
	//
	// Reported rather than refused: the words are worth keeping either
	// way, and a comment rejected because one name in it was wrong loses
	// the paragraph to fix a word.
	//
	// And reported **without saying why**. A name nobody holds and a name
	// held by somebody who may not read this are one answer here, because
	// telling them apart would answer "can this person see undisclosed
	// work" one comment at a time.
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		_, claim := r.decidedAt(t, place)

		got := asPerson(t, r, "private-triage", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/comments", claim),
			`{"body":"@private-triage and @nobody-is-called-this, what do you think?"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("commenting answered %d: %s", got.Code, got.Body.String())
		}
		var said struct {
			NotNotified []string `json:"not_notified"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &said); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if len(said.NotNotified) != 1 || said.NotNotified[0] != "nobody-is-called-this" {
			t.Errorf("the answer says %v reached nobody, want the one unknown name",
				said.NotNotified)
		}

		// A comment naming only people who can read it says nothing, so the
		// report is a report rather than noise on every write.
		quiet := asPerson(t, r, "private-triage", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/comments", claim),
			`{"body":"@private-triage one more thing."}`)
		if quiet.Code != http.StatusCreated {
			t.Fatalf("commenting answered %d: %s", quiet.Code, quiet.Body.String())
		}
		var second struct {
			NotNotified []string `json:"not_notified"`
		}
		_ = json.Unmarshal(quiet.Body.Bytes(), &second)
		if len(second.NotNotified) != 0 {
			t.Errorf("a comment naming only readers reported %v", second.NotNotified)
		}
	})
}
