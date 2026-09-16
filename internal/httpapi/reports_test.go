package httpapi_test

import (
	"fmt"
	"net/http"
	"testing"
)

func TestHowLongTriageIsTakingIsAddedUpSomewhere(t *testing.T) {
	// Every one of these was in the record and none was added up: how long
	// a finding sits before anybody says anything, how long a claim waits
	// for a second person, and what each person got through. A queue of
	// the same size is a different place depending on whether things sit
	// in it for a day or a quarter, and nothing here could tell you which.
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)

		// Read as a client reads it, off the published shape rather than
		// through the package's own type: what is being checked is that the
		// figures reach somebody outside.
		type worked struct {
			Person   string `json:"person"`
			Proposed int    `json:"proposed"`
			Approved int    `json:"approved"`
		}
		type measures struct {
			ToDecide []struct {
				Band  string `json:"band"`
				Count int    `json:"count"`
			} `json:"time_to_decide"`
			ToAgree []struct {
				Band  string `json:"band"`
				Count int    `json:"count"`
			} `json:"time_to_agree"`
			Worked  []worked `json:"throughput"`
			Sampled int      `json:"sampled"`
		}
		measured := func(t *testing.T, who string) measures {
			t.Helper()
			var body measures
			read(t, r, who, "/v1/measures?days=90", &body)
			return body
		}

		// Nothing proposed: the figures are empty rather than zero-shaped
		// numbers about nothing.
		if got := measured(t, "triager"); got.Sampled != 0 || len(got.ToDecide) != 0 {
			t.Errorf("a deployment nobody has triaged measures %+v", got)
		}

		_, claim := r.decidedAt(t, place)
		got := measured(t, "triager")
		if got.Sampled != 1 {
			t.Fatalf("one claim measures %d observations", got.Sampled)
		}
		// Proposed and not agreed to: there is a wait before the decision and
		// none before an agreement that has not happened.
		if len(got.ToDecide) != 1 {
			t.Errorf("time to decide is %+v, want the one band", got.ToDecide)
		}
		if len(got.ToAgree) != 0 {
			t.Errorf("a claim nobody agreed to has an agreement wait: %+v", got.ToAgree)
		}
		var proposed int
		for _, each := range got.Worked {
			if each.Person == "triager" {
				proposed = each.Proposed
			}
		}
		if proposed != 1 {
			t.Errorf("the proposer's throughput is %+v", got.Worked)
		}

		// Agreeing to it gives the second wait a value, and counts against the
		// approver rather than the proposer: an approver's week is the week
		// they approved in.
		if agreed := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); agreed.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", agreed.Code, agreed.Body.String())
		}
		after := measured(t, "triager")
		if len(after.ToAgree) != 1 {
			t.Errorf("an agreed claim has no agreement wait: %+v", after.ToAgree)
		}
		var approved int
		for _, each := range after.Worked {
			if each.Person == "reviewer" {
				approved = each.Approved
			}
		}
		if approved != 1 {
			t.Errorf("the approver's throughput is %+v", after.Worked)
		}

		// A count is a disclosure: somebody holding a capability and no
		// visibility measures nothing, rather than being told how much work
		// there is here.
		if got := measured(t, "approver"); got.Sampled != 0 || len(got.Worked) != 0 {
			t.Errorf("somebody who may read nothing measures %+v", got)
		}
	})
}

// TestWhatIsStillThereSaysWhetherAnybodyDecidedIt is the sign-off sheet.
//
// "Shipping anyway, and why" could not be produced: the still-present list
// came back with a name, a component and a severity, so an approved
// not-applicable and a row nobody has looked at read identically — and those
// are opposite answers to the question a release sign-off asks.
func TestWhatIsStillThereSaysWhetherAnybodyDecidedIt(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		// One of the two argued away and agreed to; the other untouched.
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}

		var out struct {
			Still []struct {
				Vulnerability string `json:"vulnerability"`
				State         string `json:"state"`
				Outcome       string `json:"outcome"`
				Justification string `json:"justification"`
			} `json:"still_present"`
		}
		read(t, r, "private-triage",
			"/v1/products/mine/comparison?from=master&from_variant=broadcom"+
				"&to=master&to_variant=broadcom&include_undisclosed=true", &out)

		stands := map[string]struct {
			State         string
			Outcome       string
			Justification string
		}{}
		for _, row := range out.Still {
			stands[row.Vulnerability] = struct {
				State         string
				Outcome       string
				Justification string
			}{row.State, row.Outcome, row.Justification}
		}
		if len(stands) != 2 {
			t.Fatalf("the comparison holds %d still-present rows, want both issues", len(stands))
		}

		// The one somebody argued away says so, and says why: that is the
		// "and why" half, and it is what somebody signs against.
		agreed := stands["CVE-2026-9999"]
		if agreed.State != "agreed" || agreed.Outcome != "not-applicable" ||
			agreed.Justification == "" {
			t.Errorf("an agreed dismissal reads as %+v", agreed)
		}
		// The one nobody has looked at is the coordinator's blocker, and it
		// has to be distinguishable from the one above.
		if open := stands["CVE-2026-1000"]; open.State != "undecided" || open.Outcome != "" {
			t.Errorf("a row nobody has decided reads as %+v", open)
		}
	})
}
