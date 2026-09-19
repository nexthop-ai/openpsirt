package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi"
)

// A deferral short enough to stand on nobody's say-so but the proposer's,
// which is the exception the rule carries and the pattern this report exists
// to make visible across a program.
const shortDeferral = `{"outcome":"deferred","deferred_until":"2026-09-20",` +
	`"reasoning":"Not this sprint; the release is next week."}`

func scrutiny(t *testing.T, r *reach, who, query string) struct {
	Alone  []httpapi.UnagreedBody       `json:"alone"`
	Bulk   []httpapi.BulkApprovalBody   `json:"bulk"`
	Pairs  []httpapi.PairingBody        `json:"pairs"`
	Lapsed []httpapi.LapsedApprovalBody `json:"lapsed"`
	Grew   []httpapi.GrownBody          `json:"grew"`
	Agreed int                          `json:"agreed"`
} {
	t.Helper()
	got := asPerson(t, r, who, http.MethodGet, "/v1/approvals/scrutiny"+query, "")
	if got.Code != http.StatusOK {
		t.Fatalf("%s asking how approvals are going answered %d: %s",
			who, got.Code, got.Body.String())
	}
	var out struct {
		Alone  []httpapi.UnagreedBody       `json:"alone"`
		Bulk   []httpapi.BulkApprovalBody   `json:"bulk"`
		Pairs  []httpapi.PairingBody        `json:"pairs"`
		Lapsed []httpapi.LapsedApprovalBody `json:"lapsed"`
		Grew   []httpapi.GrownBody          `json:"grew"`
		Agreed int                          `json:"agreed"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
		t.Fatalf("it is not JSON: %v (%s)", err, got.Body.String())
	}
	return out
}

func TestRiskStandingOnOnePersonIsReportedWithWhatItClaimed(t *testing.T) {
	// The whole point of the report. The control cannot be bypassed — the
	// proposer may never approve their own claim — so what is worth reporting
	// is where the rule did not apply. A short deferral is deliberately exempt
	// and is ordinary triage one at a time; it is the pattern across a program
	// that nothing else shows.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		if before := scrutiny(t, r, "private-triage", ""); len(before.Alone) != 0 {
			t.Fatalf("something stands alone before anything was decided: %+v", before.Alone)
		}

		r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", shortDeferral)

		after := scrutiny(t, r, "private-triage", "")
		if len(after.Alone) != 1 {
			t.Fatalf("%d kinds stand alone, want the deferral: %+v", len(after.Alone), after.Alone)
		}
		if after.Alone[0].Outcome != "deferred" {
			t.Errorf("what stands alone is %q, want the deferral", after.Alone[0].Outcome)
		}
		if after.Alone[0].Claims != 1 || after.Alone[0].Rows < 1 {
			t.Errorf("it stands alone as %d claims over %d rows",
				after.Alone[0].Claims, after.Alone[0].Rows)
		}
	})
}

func TestWhatTwoPeopleAgreedToIsNotReportedAsStandingAlone(t *testing.T) {
	// The other direction, which is what stops the report being a list of
	// everything. A dismissal needs a second person, gets one, and so has
	// nothing to answer for.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)

		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{"batch":"tuesday"}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		out := scrutiny(t, r, "private-triage", "")
		for _, row := range out.Alone {
			if row.Outcome == "not-applicable" {
				t.Errorf("a dismissal two people agreed to is reported as standing alone: %+v", row)
			}
		}

		// And it is reported as what it is: an agreement between two named
		// people, given as one act.
		if len(out.Pairs) != 1 {
			t.Fatalf("%d pairs agreed, want the one: %+v", len(out.Pairs), out.Pairs)
		}
		if out.Pairs[0].Proposer != "triager" || out.Pairs[0].Approver != "reviewer" {
			t.Errorf("the pair reads %q and %q", out.Pairs[0].Proposer, out.Pairs[0].Approver)
		}
		if out.Pairs[0].Share != 100 {
			t.Errorf("the only pair holds %d%% of what was agreed", out.Pairs[0].Share)
		}
		if len(out.Bulk) != 1 || out.Bulk[0].Batch != "tuesday" {
			t.Errorf("the batch it was agreed under is not reported: %+v", out.Bulk)
		}
		if out.Bulk[0].ApprovedBy != "reviewer" {
			t.Errorf("the batch names %q as the approver", out.Bulk[0].ApprovedBy)
		}
	})
}

func TestScrutinyRefusesAProductTheAskerMayNotRead(t *testing.T) {
	// Resolved against what the caller may see, and refused the same way a
	// name nobody ever declared is. Answering "no approvals there" for a real
	// product and 404 for an invented one would turn this into a way to ask
	// which products a deployment has, one guess at a time.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", shortDeferral)

		real := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/approvals/scrutiny?product=theirs", "")
		invented := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/approvals/scrutiny?product=no-such-product", "")
		if real.Code != http.StatusNotFound {
			t.Errorf("a product they may not read answered %d, want 404: %s",
				real.Code, real.Body.String())
		}
		if invented.Code != real.Code {
			t.Errorf("a real product answers %d and an invented one %d, which tells "+
				"somebody which names exist", real.Code, invented.Code)
		}
	})
}

func TestAClaimCoveringMoreThanWasAgreedToIsReported(t *testing.T) {
	// A claim reaches by matching, so a build appearing afterwards is covered
	// with nobody acting and nobody having agreed to the larger number. What
	// somebody consented to is recorded at the moment of consent precisely
	// because it cannot be recovered later; this is the section that reads the
	// two against each other.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, ids := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}

		// Nothing has appeared since, so nothing covers more than was agreed.
		if out := scrutiny(t, r, "private-triage", ""); len(out.Grew) != 0 {
			t.Fatalf("something already covers more than it was agreed to cover: %+v", out.Grew)
		}

		// The reach the approver actually agreed to, made smaller than what the
		// claim reaches. A second build would do this the way a deployment
		// does, and what is being pinned is the comparison rather than the
		// route by which the two came apart.
		if _, err := r.db.DB.NewUpdate().
			Table("claim_approval").
			Set("covered = ?", len(ids)-1).
			Where("claim_id = ?", claim).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		out := scrutiny(t, r, "private-triage", "")
		if len(out.Grew) != 1 {
			t.Fatalf("%d claims cover more than was agreed to, want the one: %+v",
				len(out.Grew), out.Grew)
		}
		grown := out.Grew[0]
		if grown.ClaimID != claim {
			t.Errorf("it names claim %d, want %d", grown.ClaimID, claim)
		}
		if grown.Covered != len(ids)-1 || grown.CoversNow != len(ids) {
			t.Errorf("it reads %d agreed against %d now, want %d against %d",
				grown.Covered, grown.CoversNow, len(ids)-1, len(ids))
		}
		if grown.ApprovedBy != "reviewer" {
			t.Errorf("it names %q as the approver", grown.ApprovedBy)
		}
	})
}
