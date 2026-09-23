// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
	eachReach(t, func(t *testing.T, r *reach) {
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

// The sign-off sheet's agreement rule, from both sides.
//
// A component argued away at one place and deferred at another is two claims,
// and stating either over the row would be a claim nobody made — the rule the
// VEX document already publishes under, asked here of the same rows. Two
// claims that reach the same outcome in different words are not that: they
// agree, and what the row cannot state is which wording.
//
// Two tests because a place answered once cannot be answered again: a
// decision already stands there, which is the refusal working.
func TestARowDecidedTwoWaysStatesNeither(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		places := r.twoPlacesOf(t, "CVE-2026-9999")
		r.agreedAt(t, places[0], dismissal)
		r.agreedAt(t, places[1], `{"outcome":"deferred","deferred_until":"2030-01-01",`+
			`"reasoning":"Held until the next point release."}`)

		if outcome, why := r.standsOn(t, "CVE-2026-9999"); outcome != "" || why != "" {
			t.Errorf("a row argued away at one place and deferred at another states "+
				"%q with reason %q", outcome, why)
		}
	})
}

func TestTheComparisonFileSaysWhatTheScreenSays(t *testing.T) {
	// An export answering less than the screen it was taken from is a file
	// that quietly answers something else. The sign-off column is the whole
	// point of the still-present list, and downloaded it was nine columns in
	// which an approved not-applicable and a row nobody had looked at read
	// alike.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code >= 300 {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}

		file := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/products/mine/comparison.csv?from=master&from_variant=broadcom"+
				"&to=master&to_variant=broadcom&include_undisclosed=true", "")
		if file.Code != http.StatusOK {
			t.Fatalf("exporting answered %d: %s", file.Code, file.Body.String())
		}
		lines, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		body := rowsUnder(lines)
		at := map[string]int{}
		for i, column := range body[0] {
			at[column] = i
		}
		for _, wanted := range []string{"state", "outcome", "justification", "due"} {
			if _, held := at[wanted]; !held {
				t.Fatalf("the file has no %s column: %v", wanted, body[0])
			}
		}
		var agreed, undecided int
		for _, row := range body[1:] {
			switch row[at["issue"]] {
			case "CVE-2026-9999":
				agreed++
				if row[at["state"]] != "agreed" || row[at["outcome"]] != "not-applicable" {
					t.Errorf("the agreed row reads state %q outcome %q",
						row[at["state"]], row[at["outcome"]])
				}
			case "CVE-2026-1000":
				undecided++
				if row[at["state"]] != "undecided" || row[at["outcome"]] != "" {
					t.Errorf("the undecided row reads state %q outcome %q",
						row[at["state"]], row[at["outcome"]])
				}
			}
		}
		if agreed != 1 || undecided != 1 {
			t.Errorf("the file holds %d agreed and %d undecided rows", agreed, undecided)
		}
	})
}

func TestTwoClaimsAgreeingOnTheOutcomeStateItAndNoReason(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		places := r.twoPlacesOf(t, "CVE-2026-9999")
		r.agreedAt(t, places[0], dismissal)
		// The same outcome for a different recognized reason. Counted as
		// disagreement, the sign-off column went blank on a row every place
		// of which had been argued away — which is the opposite of what the
		// column is read for.
		r.agreedAt(t, places[1],
			`{"outcome":"not-applicable","justification":"component_not_present",`+
				`"reasoning":"The module is not shipped in this image at all."}`)

		outcome, why := r.standsOn(t, "CVE-2026-9999")
		if outcome != "not-applicable" {
			t.Errorf("two claims agreeing on the outcome state %q", outcome)
		}
		// And no reason, because the row cannot say which of the two.
		if why != "" {
			t.Errorf("a row answered by two claims states one of their reasons: %q", why)
		}
	})
}

// twoPlacesOf is the places one issue sits at in the seeded build.
func (r *reach) twoPlacesOf(t *testing.T, vulnerability string) []string {
	t.Helper()
	r.scannedAtTwoPlaces(t)
	var found struct {
		Places []struct {
			Place string `json:"place"`
		} `json:"places"`
	}
	read(t, r, "triager", findingAt(vulnerability), &found)
	if len(found.Places) < 2 {
		t.Fatalf("the fixture holds this issue at %d places, so there is nothing to prove",
			len(found.Places))
	}
	out := make([]string, 0, len(found.Places))
	for _, one := range found.Places {
		out = append(out, one.Place)
	}
	return out
}

// agreedAt records a judgment about one place and has a second person agree.
func (r *reach) agreedAt(t *testing.T, place, body string) {
	t.Helper()
	made := asPerson(t, r, "triager", http.MethodPost,
		"/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/"+place+"/decision", body)
	if made.Code != http.StatusCreated {
		t.Fatalf("deciding a place answered %d: %s", made.Code, made.Body.String())
	}
	var claim struct {
		ClaimID int64 `json:"claim_id"`
	}
	if err := json.Unmarshal(made.Body.Bytes(), &claim); err != nil {
		t.Fatal(err)
	}
	if ok := asPerson(t, r, "reviewer", http.MethodPost,
		fmt.Sprintf("/v1/claims/%d/approval", claim.ClaimID), `{}`); ok.Code != http.StatusOK {
		t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
	}
}

// standsOn is what the comparison says stands about one still-present row.
func (r *reach) standsOn(t *testing.T, vulnerability string) (string, string) {
	t.Helper()
	var out struct {
		Still []struct {
			Vulnerability string `json:"vulnerability"`
			Outcome       string `json:"outcome"`
			Justification string `json:"justification"`
		} `json:"still_present"`
	}
	read(t, r, "private-triage",
		"/v1/products/mine/comparison?from=master&from_variant=broadcom"+
			"&to=master&to_variant=broadcom&include_undisclosed=true", &out)
	for _, row := range out.Still {
		if row.Vulnerability == vulnerability {
			return row.Outcome, row.Justification
		}
	}
	t.Fatalf("%s is not in the comparison", vulnerability)
	return "", ""
}
