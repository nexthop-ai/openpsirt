package httpapi_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestAClaimIsRecordedAnsweredAndThenSaidToBeAnIssue(t *testing.T) {
	// The whole of what a report is for, over the routes somebody uses. A
	// claim arrives, it is written down as it stands, somebody replies to
	// whoever sent it, and only afterwards does anybody say what it turned
	// out to be.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		arrived := time.Now().UTC().AddDate(0, 0, -3).Format(time.DateOnly)

		got := asPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/reports",
			`{"summary":"The management socket answers before anyone has authenticated.",`+
				`"reported_by":"A. Researcher","contact":"a@example.org",`+
				`"credit":"anonymous","received":"`+arrived+`"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording a claim answered %d: %s", got.Code, got.Body.String())
		}
		var recorded reportRead
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		if recorded.Reference == "" {
			t.Fatal("a recorded claim came back with no reference")
		}
		if recorded.Issue != "" {
			t.Errorf("a claim nobody judged came back as issue %q", recorded.Issue)
		}

		at := "/v1/products/mine/reports/" + recorded.Reference
		var one reportRead
		read(t, r, "private-triage", at, &one)
		if one.Summary != recorded.Summary || one.Received != arrived {
			t.Errorf("the claim reads as %+v", one)
		}
		if one.Evaluated != "" {
			t.Error("a claim nobody judged says when it was judged")
		}

		// It is in the product's list, which is what somebody works through.
		var listed struct {
			Items []reportRead `json:"items"`
			Total int          `json:"total"`
		}
		read(t, r, "private-triage", "/v1/products/mine/reports", &listed)
		if listed.Total != 1 || len(listed.Items) != 1 ||
			listed.Items[0].Reference != recorded.Reference {
			t.Errorf("the list holds %d of %d: %+v", len(listed.Items), listed.Total, listed.Items)
		}

		// Nobody has answered them, which is a condition rather than an
		// event: what is wrong is that nothing has happened. Named by the
		// reference, because a claim nobody has judged has no identifier.
		waiting := r.alerts(t, "private-triage", "unanswered-report")
		if len(waiting) != 1 {
			t.Fatalf("an unanswered claim raised %d notices: %v", len(waiting), waiting)
		}
		if !contains(waiting[0], recorded.Reference) {
			t.Errorf("the notice does not name the claim: %q", waiting[0])
		}
		if told := r.alerts(t, "triager", "unanswered-report"); len(told) != 0 {
			t.Errorf("somebody who triages only announced work was told: %v", told)
		}

		if got := asPerson(t, r, "private-triage", http.MethodPost,
			at+"/acknowledgement", ""); got.Code != http.StatusNoContent {
			t.Fatalf("acknowledging answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "private-triage", at, &one)
		if one.Acknowledged == "" || one.AcknowledgedBy == "" {
			t.Errorf("acknowledging recorded %q by %q", one.Acknowledged, one.AcknowledgedBy)
		}
		if still := r.alerts(t, "private-triage", "unanswered-report"); len(still) != 0 {
			t.Errorf("an answered claim is still reported as unanswered: %v", still)
		}

		// And then somebody says what it turned out to be. Recording the flaw
		// is its own act, because it carries the builds, the severity and the
		// embargo.
		minted := r.embargoed(t)
		if got := asPerson(t, r, "private-triage", http.MethodPut, at+"/issue",
			`{"vulnerability":"`+minted+`"}`); got.Code != http.StatusOK {
			t.Fatalf("judging answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "private-triage", at, &one)
		if one.Issue != minted {
			t.Errorf("the claim points at %q, want %q", one.Issue, minted)
		}
		if one.Evaluated == "" || one.EvaluatedBy == "" {
			t.Errorf("judging recorded %q by %q", one.Evaluated, one.EvaluatedBy)
		}

		// And it is the issue's report now, reachable at the route that was
		// always there. One row, two ways in — a claim that decoupled and
		// was then judged must not be the one report the issue screen
		// cannot find.
		var byIssue reportRead
		read(t, r, "private-triage",
			"/v1/products/mine/issues/"+minted+"/report", &byIssue)
		if byIssue.Reference != recorded.Reference {
			t.Errorf("the issue's report reads as %q, want %q",
				byIssue.Reference, recorded.Reference)
		}

		// Judging twice is refused, and so is a second claim at one issue.
		if got := asPerson(t, r, "private-triage", http.MethodPut, at+"/issue",
			`{"vulnerability":"`+minted+`"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("judging twice answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestAClaimNobodyHasJudgedIsReadWithPrivateReadAndWorkedWithPrivateTriage(t *testing.T) {
	// The matrix over the routes: a claim has no issue to be public about and
	// nobody has decided it is safe to repeat, so a role short of reading
	// unannounced work reaches none of it, a reader of unannounced work reads
	// it and may not work it — and a product somebody holds nothing on
	// answers as one that is not declared.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		got := asPerson(t, r, "private-triage", http.MethodPost, "/v1/products/mine/reports",
			`{"summary":"They say the management socket lets anybody in."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording a claim answered %d: %s", got.Code, got.Body.String())
		}
		var recorded reportRead
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		at := "/v1/products/mine/reports/" + recorded.Reference

		for _, c := range []struct {
			who    string
			method string
			path   string
			want   int
		}{
			{"reader", http.MethodGet, "/v1/products/mine/reports", http.StatusForbidden},
			// A reference they may not read and one that does not exist
			// answer alike, so asking is not a way to find out which
			// references a product holds.
			{"reader", http.MethodGet, at, http.StatusNotFound},
			{"private", http.MethodGet, "/v1/products/mine/reports", http.StatusOK},
			{"private", http.MethodGet, at, http.StatusOK},
			{"private", http.MethodGet, at + "/attachments", http.StatusOK},
			// Working one is refused in words, since they can open it, and
			// before the reference is looked up.
			{"private", http.MethodPost, "/v1/products/mine/reports", http.StatusForbidden},
			{"private", http.MethodPost, at + "/acknowledgement", http.StatusForbidden},
			{"private", http.MethodPut, at + "/issue", http.StatusForbidden},
			{"triager", http.MethodGet, "/v1/products/mine/reports", http.StatusForbidden},
			{"triager", http.MethodGet, at, http.StatusNotFound},
			{"triager", http.MethodGet, at + "/attachments", http.StatusNotFound},
			{"triager", http.MethodPost, "/v1/products/mine/reports", http.StatusForbidden},
			{"triager", http.MethodPost, at + "/acknowledgement", http.StatusNotFound},
			{"triager", http.MethodPut, at + "/issue", http.StatusNotFound},
			{"private-triage", http.MethodGet, "/v1/products/mine/reports", http.StatusOK},
			{"private-triage", http.MethodGet, at, http.StatusOK},
			// A product this person holds nothing on answers as one that was
			// never declared, which is what invisible means here.
			{"private-triage", http.MethodGet, "/v1/products/theirs/reports", http.StatusNotFound},
			// A reference nobody minted, in a product they do hold, answers
			// as a reference that is not there rather than saying so.
			{"private-triage", http.MethodGet,
				"/v1/products/mine/reports/MINE-R-2026-100000", http.StatusNotFound},
		} {
			if code := r.as(t, c.who, c.method, c.path); code != c.want {
				t.Errorf("%s %s as %q answered %d, want %d",
					c.method, c.path, c.who, code, c.want)
			}
		}
	})
}

// reportRead is what the report routes answer, as a test reads it.
type reportRead struct {
	Reference      string `json:"reference"`
	Summary        string `json:"summary"`
	ReportedBy     string `json:"reported_by"`
	Contact        string `json:"contact"`
	Received       string `json:"received"`
	Acknowledged   string `json:"acknowledged"`
	AcknowledgedBy string `json:"acknowledged_by"`
	Issue          string `json:"issue"`
	Evaluated      string `json:"evaluated"`
	EvaluatedBy    string `json:"evaluated_by"`
	RecordedBy     string `json:"recorded_by"`
	RecordedAt     string `json:"recorded_at"`
}
