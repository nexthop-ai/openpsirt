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

func TestAFindingReportsItsDecisionsAndWhatMayCarryToIt(t *testing.T) {
	// The finding is the working screen after a decision as well as before
	// it : what stands, what stood, and what argued about a neighbor may
	// be carried here.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedTwoIssues(t)
		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom/findings/%s/components/linux-image"

		read := func(vulnerability string) (body []byte) {
			t.Helper()
			got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, fmt.Sprintf(at, vulnerability), "")
			if got.Code != http.StatusOK {
				t.Fatalf("reading the finding answered %d: %s", got.Code, got.Body.String())
			}
			return got.Body.Bytes()
		}
		type finding struct {
			Standing []struct {
				DecisionID  int64  `json:"decision_id"`
				State       string `json:"state"`
				ApprovedBy  string `json:"approved_by"`
				Occurrences int    `json:"occurrences"`
				Rows        struct {
					Proposed int `json:"proposed"`
					SentBack int `json:"sent_back"`
					Approved int `json:"approved"`
				} `json:"rows"`
				SentBackAt      string `json:"sent_back_at"`
				SentBackBecause string `json:"sent_back_because"`
			} `json:"standing"`
			Previous []struct {
				DecisionOccurrenceID int64  `json:"decision_occurrence_id"`
				Ended                string `json:"ended"`
				EndedAt              string `json:"ended_at"`
				Reasoning            string `json:"reasoning"`
			} `json:"previous"`
			Similar []struct {
				DecisionID int64  `json:"decision_id"`
				Reasoning  string `json:"reasoning"`
				Issues     int    `json:"issues"`
			} `json:"similar"`
		}
		var f finding
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Standing) != 0 || len(f.Previous) != 0 || len(f.Similar) != 0 {
			t.Fatalf("an undecided finding reports %+v", f)
		}

		// A decision about the neighbor, approved.
		neighbor, _ := r.Claimed(t, "triager", "CVE-2026-9999", "linux-image", httpapitest.Dismissal)
		r.Agreed(t, neighbor)
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Similar) != 1 || f.Similar[0].DecisionID != neighbor || f.Similar[0].Issues != 1 || f.Similar[0].Reasoning == "" {
			t.Fatalf("the approved decision about the neighbor is not offered: %+v", f.Similar)
		}

		// Carried here as an extension.
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, fmt.Sprintf(at, "CVE-2026-1000")+"/decision",
			fmt.Sprintf(`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"Same kernel config; still not built.","extends":%d}`, neighbor))
		if got.Code != http.StatusCreated {
			t.Fatalf("extending answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			DecisionID int64   `json:"decision_id"`
			IDs        []int64 `json:"ids"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		got = httpapitest.AsPerson(t, r, "reviewer", http.MethodGet, "/v1/review-queue", "")
		var queue struct {
			Items []struct {
				Decision struct {
					ID          int64  `json:"id"`
					Kind        string `json:"kind"`
					DerivedFrom int64  `json:"derived_from"`
				} `json:"decision"`
			} `json:"items"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &queue); err != nil || len(queue.Items) != 1 {
			t.Fatalf("the queue reads as %s (%v)", got.Body.String(), err)
		}
		if queue.Items[0].Decision.Kind != "extension" || queue.Items[0].Decision.DerivedFrom != neighbor {
			t.Errorf("the extension does not say what it carries: %+v", queue.Items[0].Decision)
		}

		// Standing, pending; then withdrawn, and offered back with a date.
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Standing) != 1 || f.Standing[0].DecisionID != made.DecisionID || f.Standing[0].State != "proposed" {
			t.Fatalf("the extension does not stand as pending: %+v", f.Standing)
		}
		if f.Standing[0].Rows.Proposed != 1 || f.Standing[0].Rows.SentBack != 0 || f.Standing[0].Rows.Approved != 0 {
			t.Errorf("a pending decision's rows read as %+v", f.Standing[0].Rows)
		}

		// Sent back, the finding says so and says why.
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/send-back", made.DecisionID),
			`{"because":"Name the kconfig option."}`); got.Code != http.StatusNoContent {
			t.Fatalf("sending the decision back answered %d: %s", got.Code, got.Body.String())
		}
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Standing) != 1 || f.Standing[0].Rows.SentBack != 1 || f.Standing[0].SentBackAt == "" ||
			f.Standing[0].SentBackBecause != "Name the kconfig option." {
			t.Errorf("a decision sent back does not say so on the finding: %+v", f.Standing)
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodDelete,
			fmt.Sprintf("/v1/decisions/%d", made.DecisionID), ""); got.Code != http.StatusNoContent {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body.String())
		}
		if err := json.Unmarshal(read("CVE-2026-1000"), &f); err != nil {
			t.Fatal(err)
		}
		if len(f.Standing) != 0 || len(f.Previous) != 1 {
			t.Fatalf("after withdrawing, the finding reports %+v", f)
		}
		if f.Previous[0].Ended != "withdrawn" || f.Previous[0].EndedAt == "" || f.Previous[0].Reasoning == "" {
			t.Errorf("what was decided before does not say how it ended, when, or what it argued: %+v", f.Previous[0])
		}

		// An extension that keeps neither outcome nor justification is refused.
		got = httpapitest.AsPerson(t, r, "triager", http.MethodPost, fmt.Sprintf(at, "CVE-2026-1000")+"/decision",
			fmt.Sprintf(`{"outcome":"wont-fix","reasoning":"Different decision.","extends":%d}`, neighbor))
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("an extension with a different outcome answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestAFindingsRowSaysHowFarItIsDecidedAndWhetherItCameBack(t *testing.T) {
	// The list carried no decision state, so the interface guessed from what
	// the build had argued away and showed "Undecided" over forty-four
	// proposed records. The row now says it, by the state filter's own
	// definition, and says when a decision is back with its author.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		const list = "/v1/products/mine/findings?branch_or_tag=master&variant=broadcom"
		row := func() (state string, sentBack bool) {
			t.Helper()
			got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, list, "")
			if got.Code != http.StatusOK {
				t.Fatalf("listing answered %d: %s", got.Code, got.Body.String())
			}
			var out struct {
				Items []struct {
					State    string `json:"state"`
					SentBack bool   `json:"sent_back"`
				} `json:"items"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil || len(out.Items) != 1 {
				t.Fatalf("the list reads as %s (%v)", got.Body.String(), err)
			}
			return out.Items[0].State, out.Items[0].SentBack
		}

		if state, back := row(); state != "undecided" || back {
			t.Errorf("an undecided finding reads as %q, sent back %v", state, back)
		}
		decision, _ := r.Claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)
		if state, back := row(); state != "waiting" || back {
			t.Errorf("a proposed decision reads as %q, sent back %v", state, back)
		}
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/send-back", decision), `{"because":"Which encoder?"}`); got.Code != http.StatusNoContent {
			t.Fatalf("sending back answered %d: %s", got.Code, got.Body.String())
		}
		if state, back := row(); state != "waiting" || !back {
			t.Errorf("a decision sent back reads as %q, sent back %v", state, back)
		}
		var ids struct {
			Standing []struct {
				DecisionOccurrenceID int64 `json:"decision_occurrence_id"`
				DecisionID           int64 `json:"decision_id"`
			} `json:"standing"`
		}
		// The finding itself is still a build's, and says so in its path.
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200", "")
		if err := json.Unmarshal(got.Body.Bytes(), &ids); err != nil || len(ids.Standing) != 1 {
			t.Fatalf("the finding reads as %s (%v)", got.Body.String(), err)
		}
		// Revised, it is waiting again; approved, it is agreed.
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPut,
			fmt.Sprintf("/v1/decisions/%d/reasoning", ids.Standing[0].DecisionID),
			`{"reasoning":"The encoder only. Re-checked the call sites."}`); got.Code != http.StatusOK {
			// 200 rather than 204: it answers which names in the text reached
			// nobody, so the author is told a mention did not land.
			t.Fatalf("revising answered %d: %s", got.Code, got.Body.String())
		}
		if state, back := row(); state != "waiting" || back {
			t.Errorf("a revised decision reads as %q, sent back %v", state, back)
		}
		r.Agreed(t, decision)
		if state, back := row(); state != "agreed" || back {
			t.Errorf("an approved decision reads as %q, sent back %v", state, back)
		}
	})
}

func TestADecisionAboutTheSameCodeInAnotherProductIsOffered(t *testing.T) {
	// An occurrence identity is a hash of a consumer and a component with no product
	// in it, deliberately, so that an occurrence is recognized across variants. The
	// same key recognizes it across products — two products shipping the same
	// library under the same consumer are the same code in the same position —
	// and without it no team is offered the decision another team has already
	// made about it. Deciding it again from scratch is the work the grouping
	// exists to avoid.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.Scanned(t)
		r.AlsoScannedInto(t, "theirs", "master", "mellanox")

		// Somebody who triages both products, which is what makes the other
		// team's decision reachable at all.
		theirs, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		for _, who := range []string{"triager", "reviewer"} {
			person, err := r.Rights.Ensure(ctx, who, "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Rights.GrantRole(ctx, person.ID, theirs.ID,
				access.PublicTriage); err != nil {
				t.Fatal(err)
			}
		}

		// The other team decides, and agrees.
		at := "/v1/products/theirs/branches-and-tags/master/variants/mellanox" +
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"
		decided := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"The affected protocol is not compiled into our build."}`)
		if decided.Code != http.StatusCreated {
			t.Fatalf("deciding in the other product answered %d: %s",
				decided.Code, decided.Body.String())
		}
		var made struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		r.Agreed(t, made.DecisionID)

		// And it is offered on this product's finding, as evidence.
		here := "/v1/products/mine/branches-and-tags/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200"
		var evidence struct {
			Elsewhere []struct {
				Product    string `json:"product"`
				Outcome    string `json:"outcome"`
				Reasoning  string `json:"reasoning"`
				ApprovedBy string `json:"approved_by"`
			} `json:"elsewhere"`
		}
		httpapitest.Read(t, r, "triager", here, &evidence)
		if len(evidence.Elsewhere) != 1 {
			t.Fatalf("this finding offers %d decisions from elsewhere, want the one: %+v",
				len(evidence.Elsewhere), evidence.Elsewhere)
		}
		one := evidence.Elsewhere[0]
		if one.Product != "theirs" || one.Outcome != "not-applicable" {
			t.Errorf("the decision offered is %+v", one)
		}
		if one.Reasoning == "" || one.ApprovedBy == "" {
			t.Errorf("the decision is offered with nothing to read: %+v", one)
		}

		// And only to somebody who may read it. An occurrence identity spans
		// products, so a join that did not carry the subject would hand
		// somebody the reasoning, the approver and the existence of a decision
		// in a product they cannot see at all.
		var blind struct {
			Elsewhere []struct {
				Product string `json:"product"`
			} `json:"elsewhere"`
		}
		httpapitest.Read(t, r, "reader", here, &blind)
		if len(blind.Elsewhere) != 0 {
			t.Errorf("somebody with no rights in the other product was shown %d of its "+
				"decisions: %+v", len(blind.Elsewhere), blind.Elsewhere)
		}
	})
}
