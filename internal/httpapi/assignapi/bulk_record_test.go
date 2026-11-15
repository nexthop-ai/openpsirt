// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

const libnlAt = "/v1/products/mine/branches-and-tags/master/variants/broadcom/components/libnl-3-200"

// The issues at a component, which a bulk decision is chosen from, carry what
// a person picks on: how bad each is, how much of the build it sits in, and
// whether there is anywhere to go.
func TestTheIssuesAtAComponentCarryWhatAPersonPicksOn(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		var issues struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Severity      string `json:"severity"`
				Occurrences   int    `json:"occurrences"`
				FixedIn       string `json:"fixed_in"`
			} `json:"items"`
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "triager", libnlAt+"/issues", &issues)
		if issues.Total != 1 || len(issues.Items) != 1 {
			t.Fatalf("%d issues at the component, want 1", issues.Total)
		}
		if issues.Items[0].Severity == "" || issues.Items[0].FixedIn == "" ||
			issues.Items[0].Occurrences == 0 {
			t.Errorf("the list to choose from says nothing to choose on: %+v", issues.Items[0])
		}
	})
}

// A bulk decision records one row per occurrence of each issue named, never
// one per name, and each row says how the set was chosen. A decision is keyed
// on an occurrence, so one row per name would silence one consumer and leave
// the rest open while reporting that it had covered them.
func TestABulkDecisionRecordsOneRowPerOccurrenceAndHowTheSetWasChosen(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		var issues struct {
			Items []struct {
				Occurrences int `json:"occurrences"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", libnlAt+"/issues", &issues)
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, libnlAt+"/bulk-decision",
			`{"vulnerabilities":["CVE-2026-9999"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_in_execute_path",`+
				`"selected_by":"searched the reports for \"driver\"",`+
				`"reasoning":"These are in drivers absent from our kernel config."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("deciding a set together answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Recorded int     `json:"recorded"`
			IDs      []int64 `json:"ids"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		var occurrences int
		for _, each := range issues.Items {
			occurrences += each.Occurrences
		}
		if occurrences == 0 || recorded.Recorded != occurrences || len(recorded.IDs) != occurrences {
			t.Fatalf("recorded %d rows (%d identifiers) for %d occurrences, want one each",
				recorded.Recorded, len(recorded.IDs), occurrences)
		}
		for _, id := range recorded.IDs {
			var made struct {
				DecisionOccurrence struct {
					SelectedBy string `json:"selected_by"`
				} `json:"decision_occurrence"`
			}
			httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decision-occurrences/%d", id), &made)
			if made.DecisionOccurrence.SelectedBy != `searched the reports for "driver"` {
				t.Errorf("row %d says the set was chosen by %q", id, made.DecisionOccurrence.SelectedBy)
			}
		}
	})
}

// A bulk deferral with no date is refused, never recorded as a postponement
// with no end.
func TestABulkDeferralWithNoDateIsRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, libnlAt+"/bulk-decision",
			`{"vulnerabilities":["CVE-2026-9999"],"outcome":"deferred",`+
				`"selected_by":"the same search","reasoning":"Not this release."}`,
		); got.Code != http.StatusUnprocessableEntity ||
			!strings.Contains(got.Body.String(), "deferring needs a date to defer until") {
			t.Errorf("deferring with no date answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// A bulk decision naming an issue nobody here knows is refused naming it, so
// a person who pasted a list can fix the list rather than bisect it.
func TestABulkDecisionNamesTheIssueItDoesNotKnow(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, libnlAt+"/bulk-decision",
			`{"vulnerabilities":["CVE-2026-9999","CVE-1999-0001"],"outcome":"wont-fix",`+
				`"selected_by":"a list somebody pasted","reasoning":"Not worth it."}`,
		); got.Code != http.StatusNotFound || !strings.Contains(got.Body.String(), "CVE-1999-0001") {
			t.Errorf("an unknown issue answered %d without naming it: %s", got.Code, got.Body.String())
		}
	})
}
