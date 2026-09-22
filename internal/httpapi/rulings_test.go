package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// rulingRead is what the ruling routes answer, as a test reads it.
type rulingRead struct {
	ID          int64    `json:"id"`
	Disposition string   `json:"disposition"`
	DuplicateOf string   `json:"duplicate_of"`
	Reports     []string `json:"reports"`
	State       string   `json:"state"`
	Yours       bool     `json:"yours"`
	ApprovedBy  string   `json:"approved_by"`
}

// rulingOf reads a report's disposition fields, which reportRead leaves out.
type rulingOf struct {
	Disposition string `json:"disposition"`
	Waiting     string `json:"waiting"`
	Ruling      int64  `json:"ruling"`
	DuplicateOf string `json:"duplicate_of"`
}

func (r *reach) claim(t *testing.T, summary string) string {
	t.Helper()
	got := asPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/reports",
		`{"summary":"`+summary+`"}`)
	if got.Code != http.StatusCreated {
		t.Fatalf("recording a claim answered %d: %s", got.Code, got.Body.String())
	}
	var recorded reportRead
	if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	return recorded.Reference
}

func TestSlopIsRejectedInOneActThatASecondPersonApproves(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		first := r.claim(t, "Generated text about a function this does not have.")
		second := r.claim(t, "More generated text about the same missing function.")

		got := asPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/report-rulings",
			fmt.Sprintf(`{"reports":[%q,%q,%q],"disposition":"rejected","reasoning":"Slop."}`,
				first, second, strings.ToLower(first)))
		if got.Code != http.StatusCreated {
			t.Fatalf("proposing answered %d: %s", got.Code, got.Body.String())
		}
		var proposed rulingRead
		if err := json.Unmarshal(got.Body.Bytes(), &proposed); err != nil {
			t.Fatal(err)
		}
		if proposed.State != "waiting" || !proposed.Yours || len(proposed.Reports) != 2 {
			t.Errorf("proposed, it reads %+v", proposed)
		}
		var report rulingOf
		read(t, r, "private-triage", "/v1/products/mine/reports/"+first, &report)
		if report.Disposition != "" || report.Waiting != "rejected" || report.Ruling != proposed.ID {
			t.Errorf("a report under a waiting rejection reads %+v", report)
		}

		// The approver sees it waiting, and that it is not theirs.
		var waiting struct {
			Items []rulingRead `json:"items"`
			Total int          `json:"total"`
		}
		read(t, r, "private-dispatcher", "/v1/products/mine/report-rulings?waiting=true", &waiting)
		if waiting.Total != 1 || waiting.Items[0].Yours {
			t.Errorf("the approver's waiting list reads %+v", waiting)
		}

		at := fmt.Sprintf("/v1/products/mine/report-rulings/%d", proposed.ID)
		if got := asPerson(t, r, "private-triage", http.MethodPost, at+"/approval", ""); got.Code !=
			http.StatusConflict {
			t.Errorf("the proposer approving answered %d: %s", got.Code, got.Body.String())
		}
		// Somebody who may read undisclosed work but not work reports. A
		// ruling they may not reach answers as one nobody issued.
		if code := r.as(t, "private", http.MethodPost, at+"/approval"); code != http.StatusNotFound {
			t.Errorf("a private reader approving answered %d", code)
		}
		got = asPerson(t, r, "private-dispatcher", http.MethodPost, at+"/approval", "")
		if got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		var approved rulingRead
		if err := json.Unmarshal(got.Body.Bytes(), &approved); err != nil {
			t.Fatal(err)
		}
		if approved.State != "in-force" || approved.ApprovedBy == "" {
			t.Errorf("approved, it reads %+v", approved)
		}
		report = rulingOf{}
		read(t, r, "private-triage", "/v1/products/mine/reports/"+second, &report)
		if report.Disposition != "rejected" || report.Waiting != "" {
			t.Errorf("an approved rejection reads %+v on its report", report)
		}

		// Undone, the reports are back in the inbox.
		if got := asPerson(t, r, "private-triage", http.MethodPost, at+"/withdrawal", ""); got.Code !=
			http.StatusOK {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body.String())
		}
		report = rulingOf{}
		read(t, r, "private-triage", "/v1/products/mine/reports/"+second, &report)
		if report.Disposition != "" || report.Ruling != 0 {
			t.Errorf("a withdrawn rejection still reads %+v on its report", report)
		}
	})
}

func TestADuplicateIsListedOnTheIssueItDuplicates(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		minted := r.embargoed(t)
		claimed := r.claim(t, "The management socket lets anybody in, with a screenshot.")

		got := asPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/report-rulings",
			fmt.Sprintf(`{"reports":[%q],"disposition":"duplicate","duplicate_of":%q}`,
				claimed, minted))
		if got.Code != http.StatusCreated {
			t.Fatalf("a duplicate answered %d: %s", got.Code, got.Body.String())
		}
		var report rulingOf
		read(t, r, "private-triage", "/v1/products/mine/reports/"+claimed, &report)
		if report.Disposition != "duplicate" || report.DuplicateOf != minted {
			t.Errorf("the duplicate reads %+v", report)
		}

		duplicates := "/v1/products/mine/issues/" + minted + "/duplicates"
		var listed struct {
			Items []reportRead `json:"items"`
		}
		read(t, r, "private-triage", duplicates, &listed)
		if len(listed.Items) != 1 || listed.Items[0].Reference != claimed {
			t.Errorf("the issue lists duplicates %+v", listed.Items)
		}
		// Somebody who reads the issue and may not work reports reads none.
		if code := r.as(t, "private", http.MethodGet, duplicates); code != http.StatusForbidden {
			t.Errorf("a private reader reading duplicates answered %d", code)
		}

		// An issue that is not here answers as one nobody may be told of.
		if got := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/report-rulings",
			fmt.Sprintf(`{"reports":[%q],"disposition":"duplicate","duplicate_of":"CVE-1999-0001"}`,
				r.claim(t, "Another."))); got.Code != http.StatusNotFound {
			t.Errorf("a duplicate of an issue not here answered %d: %s", got.Code, got.Body.String())
		}
	})
}
