// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestTheQueueListsOneEntryPerDecisionWithItsSize(t *testing.T) {
	// One decision, one entry — with how many rows it wrote, how many
	// issues and occurrences it covers, and the builds it reaches.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		decision, ids := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)

		got := httpapitest.AsPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		if got.Code != http.StatusOK {
			t.Fatalf("reading the queue answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Items []struct {
				Decision struct {
					ID   int64  `json:"id"`
					Kind string `json:"kind"`
				} `json:"decision"`
				DecisionOccurrence struct {
					DecisionID int64 `json:"decision_id"`
				} `json:"decision_occurrence"`
				Rows        int      `json:"rows"`
				Issues      int      `json:"issues"`
				Occurrences int      `json:"occurrences"`
				Builds      []string `json:"builds"`
				Reasoning   string   `json:"reasoning"`
			} `json:"items"`
			Total int `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if out.Total != 1 || len(out.Items) != 1 {
			t.Fatalf("%d entries (total %d), want one decision: %s", len(out.Items), out.Total, got.Body.String())
		}
		one := out.Items[0]
		if one.Decision.ID != decision || one.DecisionOccurrence.DecisionID != decision || one.Decision.Kind != "finding" {
			t.Errorf("the entry does not name the decision %d: %+v", decision, one)
		}
		if one.Rows != len(ids) || one.Issues != 1 || one.Occurrences != len(ids) {
			t.Errorf("the entry's size reads as %d/%d/%d, want %d/1/%d", one.Rows, one.Issues, one.Occurrences, len(ids), len(ids))
		}
		if len(one.Builds) != 1 || one.Builds[0] != "Master · Broadcom" {
			t.Errorf("the entry names builds %v, want the one it sits in", one.Builds)
		}
	})
}

func TestADecisionIsApprovedAsOneAndByAnotherPerson(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)

		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decision), `{}`); got.Code != http.StatusConflict {
			t.Errorf("the proposer approving their own decision answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			"/v1/decisions/999999/approval", `{}`); got.Code != http.StatusNotFound {
			t.Errorf("approving a decision that is not there answered %d", got.Code)
		}
		if got := httpapitest.AsPerson(t, r, "reader", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decision), `{}`); got.Code != http.StatusNotFound {
			t.Errorf("somebody who may not approve answered %d, want the same as not there", got.Code)
		}

		got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", decision), `{"batch":"tuesday"}`)
		if got.Code != http.StatusOK {
			t.Fatalf("approving the decision answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Approved int `json:"approved"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil || out.Approved != 1 {
			t.Errorf("approving reported %+v (%v)", out, err)
		}

		// Under a batch, so undone as one.
		got = httpapitest.AsPerson(t, r, "reviewer", http.MethodDelete, "/v1/approval-batches/tuesday", "")
		if got.Code != http.StatusOK {
			t.Fatalf("undoing the batch answered %d: %s", got.Code, got.Body.String())
		}
		got = httpapitest.AsPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var queue struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &queue); err != nil || queue.Total != 1 {
			t.Errorf("after undoing the batch the decision is not back in the queue: %+v", queue)
		}
	})
}

func TestABulkDecisionCarriesItsOutliersAndTheyCanBeSetAside(t *testing.T) {
	// Nobody reads three hundred rows. What a careful approver checks is
	// the handful that contradict the shape of the decision, and those are
	// handed to them — and may be set aside, so the rest is not held up.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)

		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/components/linux-image/bulk-decision",
			`{"vulnerabilities":["CVE-2026-9999","CVE-2026-1000"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_present",`+
				`"selected_by":"undecided, description contains \"driver\"",`+
				`"reasoning":"None of these drivers are built for this image."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("a bulk decision answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil || made.DecisionID == 0 {
			t.Fatalf("a bulk decision did not say which decision it made: %s", got.Body.String())
		}

		got = httpapitest.AsPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var out struct {
			Items []struct {
				Decision struct {
					Kind       string `json:"kind"`
					SelectedBy string `json:"selected_by"`
				} `json:"decision"`
				Issues   int `json:"issues"`
				Outliers *struct {
					Exploited int `json:"exploited"`
					Severe    int `json:"severe"`
					Fixable   int `json:"fixable"`
					Unmatched int `json:"unmatched"`
					Rows      []struct {
						DecisionOccurrenceID int64    `json:"decision_occurrence_id"`
						Vulnerability        string   `json:"vulnerability"`
						Why                  []string `json:"why"`
					} `json:"rows"`
				} `json:"outliers"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil || len(out.Items) != 1 {
			t.Fatalf("the queue reads as %s (%v)", got.Body.String(), err)
		}
		one := out.Items[0]
		if one.Decision.Kind != "together" || one.Issues != 2 || one.Outliers == nil {
			t.Fatalf("a bulk decision reads as %+v", one)
		}
		o := one.Outliers
		if o.Exploited != 1 || o.Severe != 1 || o.Fixable != 1 || o.Unmatched != 1 {
			t.Errorf("outliers counted %d exploited, %d severe, %d fixable, %d unmatched; want 1 of each", o.Exploited, o.Severe, o.Fixable, o.Unmatched)
		}
		if len(o.Rows) != 1 || o.Rows[0].Vulnerability != "CVE-2026-9999" || len(o.Rows[0].Why) != 4 {
			t.Fatalf("the rows that stood out are %+v, want the one that is exploited, severe, fixable and not about a driver", o.Rows)
		}

		// Set it aside: the other is approved, this one goes back.
		got = httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/approval", made.DecisionID),
			fmt.Sprintf(`{"except":[%d],"because":"Netfilter is not a driver, and it is exploited."}`, o.Rows[0].DecisionOccurrenceID))
		if got.Code != http.StatusOK {
			t.Fatalf("approving with a row set aside answered %d: %s", got.Code, got.Body.String())
		}
		var done struct {
			Approved         int   `json:"approved"`
			ReturnedDecision int64 `json:"returned_decision"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &done); err != nil || done.Approved != 1 || done.ReturnedDecision == 0 {
			t.Fatalf("setting aside reported %+v (%v)", done, err)
		}

		// The row set aside is the proposer's again, in a decision of its own,
		// with the reason on it.
		got = httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			fmt.Sprintf("/v1/decisions/%d/comments", done.ReturnedDecision), "")
		var said struct {
			Items []struct {
				Body string `json:"body"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &said); err != nil || len(said.Items) != 1 ||
			said.Items[0].Body != "Netfilter is not a driver, and it is exploited." {
			t.Errorf("the reason did not travel with the row: %s", got.Body.String())
		}
		// And nothing is waiting: one approved, one sent back.
		got = httpapitest.AsPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var queue struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &queue); err != nil || queue.Total != 0 {
			t.Errorf("%d still waiting after approving with a row set aside", queue.Total)
		}
	})
}

func TestAQueueEntryAndADecisionSayWhatTheyAreAbout(t *testing.T) {
	// An approver judges a row from the row: what the issue is, which
	// component, how bad, where it sits, and which build to open. The
	// entry carried only an identifier, and the occurrence screen no more.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		decision, ids := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)

		type ref struct {
			Product       string  `json:"product"`
			ProductName   string  `json:"product_name"`
			Stream        string  `json:"stream"`
			Variant       string  `json:"variant"`
			Vulnerability string  `json:"vulnerability"`
			Component     string  `json:"component"`
			Version       string  `json:"version"`
			Severity      string  `json:"severity"`
			Score         float64 `json:"score"`
			Exploited     bool    `json:"exploited"`
			FixState      string  `json:"fix_state"`
			FixedIn       string  `json:"fixed_in"`
			Description   string  `json:"description"`
			Owner         string  `json:"owner"`
			Parent        string  `json:"parent"`
			Occurrences   int     `json:"occurrences"`
			Decided       int     `json:"decided"`
		}
		check := func(what string, f *ref) {
			t.Helper()
			if f == nil {
				t.Fatalf("%s carries no finding", what)
			}
			if f.Product != "mine" || f.ProductName != httpapitest.ShownAs("mine") ||
				f.Stream != "master" || f.Variant != "broadcom" {
				t.Errorf("%s names build %s · %s · %s", what, f.Product, f.Stream, f.Variant)
			}
			if f.Vulnerability != "CVE-2026-9999" || f.Component != "linux-image" || f.Version != "5.10" {
				t.Errorf("%s names %s in %s %s", what, f.Vulnerability, f.Component, f.Version)
			}
			if f.Severity != "high" || f.Score != 8.1 || !f.Exploited || f.FixState != "fixed" || f.FixedIn != "5.10.0-27" {
				t.Errorf("%s says %s %.1f exploited=%v %s %s", what, f.Severity, f.Score, f.Exploited, f.FixState, f.FixedIn)
			}
			// The build holds the kernel directly, and the findings list names
			// both ends of a two-step way down as the component itself.
			if f.Description == "" || f.Owner != "linux-image" || f.Parent != "linux-image" {
				t.Errorf("%s says %q, owner %q, parent %q", what, f.Description, f.Owner, f.Parent)
			}
			if f.Occurrences != 1 || f.Decided != 1 {
				t.Errorf("%s counts %d occurrences, %d decided; want 1 and 1", what, f.Occurrences, f.Decided)
			}
		}

		got := httpapitest.AsPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var queue struct {
			Items []struct {
				Finding *ref `json:"finding"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &queue); err != nil || len(queue.Items) != 1 {
			t.Fatalf("the queue reads as %s (%v)", got.Body.String(), err)
		}
		check("the queue entry", queue.Items[0].Finding)

		got = httpapitest.AsPerson(t, r, "triager", http.MethodGet, fmt.Sprintf("/v1/decision-occurrences/%d", ids[0]), "")
		if got.Code != http.StatusOK {
			t.Fatalf("reading the decision occurrence answered %d: %s", got.Code, got.Body.String())
		}
		var detail struct {
			Finding *ref `json:"finding"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		check("the decision occurrence", detail.Finding)
		_ = decision
	})
}

func TestAProposerHoldsPartOfTheirOwnDecisionBack(t *testing.T) {
	// Recording in bulk and changing your mind one row at a time was the
	// split, and it was the wrong middle: an approver could hold rows back and
	// the author could only withdraw everything and start again.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/components/linux-image/bulk-decision",
			`{"vulnerabilities":["CVE-2026-9999","CVE-2026-1000"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_present",`+
				`"selected_by":"undecided, description contains \"driver\"",`+
				`"reasoning":"None of these drivers are built for this image."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			DecisionID int64   `json:"decision_id"`
			IDs        []int64 `json:"ids"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil || len(made.IDs) < 2 {
			t.Fatalf("the decision reads as %s (%v)", got.Body.String(), err)
		}

		// Somebody who did not make it cannot hold part of it back: that is
		// setting rows aside, and setting rows aside agrees to the rest.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/split", made.DecisionID),
			fmt.Sprintf(`{"rows":[%d],"because":"Not this one."}`, made.IDs[0])), http.StatusNotFound)

		got = httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/split", made.DecisionID),
			fmt.Sprintf(`{"rows":[%d],"because":"This one is the driver after all."}`, made.IDs[0]))
		if got.Code != http.StatusCreated {
			t.Fatalf("holding a row back answered %d: %s", got.Code, got.Body.String())
		}
		var held struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &held); err != nil || held.DecisionID == 0 {
			t.Fatalf("holding back answered %s (%v)", got.Body.String(), err)
		}
		if held.DecisionID == made.DecisionID {
			t.Fatal("the rows held back stayed in the decision they came from")
		}

		// The reason is on the new decision, which is where its author reads it.
		var said struct {
			Items []struct {
				Body string `json:"body"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d/comments", held.DecisionID), &said)
		if len(said.Items) != 1 || said.Items[0].Body != "This one is the driver after all." {
			t.Errorf("the reason did not travel with the rows: %+v", said.Items)
		}
	})
}

func TestOneActionRestoresEverythingOneActionClaimed(t *testing.T) {
	// A decision is bulk-capable at three grains and a re-decision at
	// none. A team answering one kernel issue writes one decision over all of its
	// occurrences in one action; when the kernel moves those lapse, and restoring
	// them was one request each with a separately typed justification — on a
	// demo image the kernel sits at 45 occurrences per issue.
	//
	// This is the one path that is safe to make cheap. A version bump is a
	// prompt to re-check rather than a new decision, and the earlier agreement is
	// already carried forward.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		claimed := r.AgreedThenLapsed(t)

		// One act restores both, with one reasoning and no second person: two
		// people already agreed, and nothing about the issue has changed.
		again := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; the transfer path is still not reached."}`)
		if again.Code != http.StatusCreated {
			t.Fatalf("re-affirming the decision answered %d: %s", again.Code, again.Body.String())
		}
		var restored struct {
			DecisionID          int64   `json:"decision_id"`
			DecisionOccurrences []int64 `json:"decision_occurrences"`
			Occurrences         int     `json:"occurrences"`
			Waiting             bool    `json:"waiting"`
		}
		if err := json.Unmarshal(again.Body.Bytes(), &restored); err != nil {
			t.Fatal(err)
		}
		if len(restored.DecisionOccurrences) != 2 || restored.Occurrences != 2 {
			t.Errorf("re-affirming wrote %d rows over %d occurrences, want two of each",
				len(restored.DecisionOccurrences), restored.Occurrences)
		}
		if restored.Waiting {
			t.Error("re-affirming an agreed decision after a bump asked for a second person")
		}
		if restored.DecisionID == claimed {
			t.Error("a re-affirmation reused the decision it re-makes rather than being its own act")
		}
		// Every row stands, not the first of them. One agreement is an
		// agreement to a decision's words, so it takes effect on all of them
		// together or the act is half decided.
		standing, err := r.DB.DB.NewSelect().Table("decision_occurrence").
			Where(`"decision_id" = ?`, restored.DecisionID).Where(`"state" = ?`, "approved").
			Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if standing != int64(len(restored.DecisionOccurrences)) {
			t.Errorf("%d of %d re-affirmed rows stand, want all of them",
				standing, len(restored.DecisionOccurrences))
		}
		// And the agreement is recorded once, not once per row.
		carried, err := r.DB.DB.NewSelect().Table("decision_approval").
			Where(`"decision_id" = ?`, restored.DecisionID).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if carried != 1 {
			t.Errorf("one carried agreement was recorded %d times", carried)
		}

		// And nobody else may do it. Re-affirming is the proposer's right: an
		// approver doing it becomes proposer of the new decision while their own
		// earlier agreement is carried onto it.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/reaffirmation", claimed),
			`{"reasoning":"Looks fine to me."}`), http.StatusNotFound)
	})
}

func TestADecisionInAProductYouCannotSeeAnswersLikeOneThatIsNotThere(t *testing.T) {
	// Refusing on the proposer before anything checks visibility answered a
	// decision elsewhere with one sentence and a missing decision with another, so
	// walking decision identifiers was a directory of every product in the
	// deployment (REQ-42).
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.Scanned(t)
		r.AlsoScannedInto(t, "theirs", "master", "mellanox")

		// Somebody who triages the other product makes a decision there. The
		// reader below holds nothing in it at all.
		theirs, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		person, err := r.Rights.Ensure(ctx, "private-triage", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.Rights.GrantRole(ctx, person.ID, theirs.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		made := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/theirs/branches-and-tags/master/variants/mellanox"+
				"/findings/CVE-2026-9999/components/libnl-3-200/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"Not compiled into that build."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding in the other product answered %d: %s",
				made.Code, made.Body.String())
		}
		var theirDecision struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &theirDecision); err != nil {
			t.Fatal(err)
		}

		// A decision that exists and one that does not, asked by somebody who may
		// see neither. The two answers have to be the same answer.
		invisible := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/reaffirmation", theirDecision.DecisionID),
			`{"reasoning":"Still true."}`)
		absent := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/decisions/999999/reaffirmation", `{"reasoning":"Still true."}`)
		if invisible.Code != absent.Code {
			t.Errorf("a decision elsewhere answered %d and a missing one %d",
				invisible.Code, absent.Code)
		}
		if invisible.Body.String() != absent.Body.String() {
			t.Errorf("a decision elsewhere answered %q and a missing one %q",
				invisible.Body.String(), absent.Body.String())
		}
	})
}

// A limit of zero answers how much is waiting without an entry.
func TestTheQueueAnswersItsTotalAloneForALimitOfZero(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)

		got := httpapitest.AsPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue?limit=0", "")
		if got.Code != http.StatusOK {
			t.Fatalf("reading the queue's total answered %d: %s", got.Code, got.Body.String())
		}
		var out struct {
			Items []json.RawMessage `json:"items"`
			Total int               `json:"total"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if out.Total != 1 || out.Items == nil || len(out.Items) != 0 {
			t.Errorf("asked alone the queue says %d with %d entries, want 1 and none", out.Total, len(out.Items))
		}
	})
}
