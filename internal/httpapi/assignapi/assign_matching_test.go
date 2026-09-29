// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// Assigning everything a narrowing of the findings list matches, in one act.

const matchingAt = "/v1/products/mine/findings/assignment"

// assignedMatching assigns through the narrowing and returns what the act
// reports.
func assignedMatching(t *testing.T, r *httpapitest.Reach, who, query, body string) (pieces int, moved int64) {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodPost, matchingAt+query, body)
	if got.Code != http.StatusOK {
		t.Fatalf("assigning by filter answered %d: %s", got.Code, got.Body.String())
	}
	var out struct {
		Pieces int   `json:"pieces"`
		Moved  int64 `json:"moved"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Pieces, out.Moved
}

// heldCount is how many rows of the list answer to one of the assigned words.
func heldCount(t *testing.T, r *httpapitest.Reach, assigned string) int {
	t.Helper()
	var list struct {
		Total int `json:"total"`
	}
	httpapitest.Read(t, r, "triager", "/v1/products/mine/findings?planned=either&assigned="+assigned, &list)
	return list.Total
}

func TestAssigningByFilterReachesEveryRowTheListCountsAndNoOther(t *testing.T) {
	// "Everything matching" means what the list counted rather than what one
	// page held, and nothing the filter kept out. The fold is two binaries of
	// one source, so a row counted as held has both of them assigned.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)

		var matched struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/findings?planned=either&severity=high", &matched)
		if matched.Total != 2 {
			t.Fatalf("the narrowing holds %d rows, want the critical and the high", matched.Total)
		}

		pieces, moved := assignedMatching(t, r, "assigner",
			"?planned=either&severity=high", `{"person":"reader"}`)
		if pieces != matched.Total {
			t.Errorf("the act reached %d rows where the list counts %d", pieces, matched.Total)
		}
		// The critical at both binaries of the fold, and the high at one.
		if moved != 3 {
			t.Errorf("%d findings changed hands, want 3", moved)
		}
		if got := heldCount(t, r, "somebody"); got != 2 {
			t.Errorf("%d rows are wholly held after the act, want 2", got)
		}
		if got := heldCount(t, r, "nobody"); got != 1 {
			t.Errorf("%d rows are held by nobody, want the low one the filter kept out", got)
		}
	})
}

func TestAssigningOnlyPickedRowsLeavesTheRestOfTheNarrowing(t *testing.T) {
	// A selection is made out of the list, and the act reaches it and nothing
	// else the filter admits.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		var list struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Fold          string `json:"fold"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/findings?planned=either&q=CURL2", &list)
		if len(list.Items) != 1 {
			t.Fatalf("searching for one issue found %d rows", len(list.Items))
		}
		picked := list.Items[0]

		pieces, moved := assignedMatching(t, r, "assigner", "?planned=either",
			`{"person":"reader","only":[{"vulnerability":"`+picked.Vulnerability+
				`","fold":"`+picked.Fold+`"}]}`)
		if pieces != 1 || moved != 2 {
			t.Errorf("the act reached %d rows and moved %d findings, want 1 and 2", pieces, moved)
		}
		if got := heldCount(t, r, "nobody"); got != 2 {
			t.Errorf("%d rows are held by nobody, want the two nobody picked", got)
		}

		// A picked row the filter no longer admits is not assigned.
		pieces, _ = assignedMatching(t, r, "assigner", "?planned=either&severity=critical",
			`{"person":"private","only":[{"vulnerability":"`+picked.Vulnerability+
				`","fold":"`+picked.Fold+`"}]}`)
		if pieces != 0 {
			t.Errorf("a picked row outside the narrowing was assigned")
		}
	})
}

func TestAssigningByFilterWithoutTheAssignerRightLeavesAColleaguesWorkWithThem(t *testing.T) {
	// Taking what nobody holds is triage, and taking what a colleague holds is
	// the assigner's act. One request over many rows is held to the rule one
	// row is.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		assignedMatching(t, r, "assigner", "?planned=either&q=CURL1", `{"person":"reader"}`)

		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, matchingAt+"?planned=either",
			`{"person":"triager"}`)
		var out struct {
			Pieces int   `json:"pieces"`
			Moved  int64 `json:"moved"`
			Left   []struct {
				Vulnerability string `json:"vulnerability"`
			} `json:"left"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil || got.Code != http.StatusOK {
			t.Fatalf("taking every row answered %d: %s", got.Code, got.Body.String())
		}
		if out.Pieces != 3 {
			t.Errorf("the act reached %d rows, want all 3", out.Pieces)
		}
		if out.Moved != 3 {
			t.Errorf("%d findings changed hands, want the 3 nobody held", out.Moved)
		}
		// The row a colleague holds is named, so a screen can keep it
		// selected rather than report it taken.
		if len(out.Left) != 1 || out.Left[0].Vulnerability != "CVE-2026-CURL1" {
			t.Errorf("the rows left behind read %+v, want the one a colleague holds", out.Left)
		}

		// And giving work to somebody else is refused outright.
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, matchingAt+"?planned=either",
			`{"person":"reader"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a triager giving work away answered %d: %s", got.Code, got.Body.String())
		}
	})
}

func TestAssigningByFilterIsRefusedWholeWhereAnyRowWouldBeDisclosedByIt(t *testing.T) {
	// One undisclosed row among many makes handing the set over the
	// disclosure, so the act is refused rather than cut down to the
	// disclosed part of it.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where("vulnerability_id IN (SELECT id FROM \"vulnerability\" WHERE identifier = ?)",
				"CVE-2026-CURL3").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		refused := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost,
			matchingAt+"?planned=either", `{"person":"reader"}`)
		if refused.Code != http.StatusUnprocessableEntity {
			t.Fatalf("handing undisclosed work to somebody who may not read it answered %d: %s",
				refused.Code, refused.Body.String())
		}
		var list struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "private-dispatcher",
			"/v1/products/mine/findings?planned=either&assigned=nobody", &list)
		if list.Total != 3 {
			t.Errorf("a refused act left %d of 3 rows unheld", list.Total)
		}

		if _, moved := assignedMatching(t, r, "private-dispatcher", "?planned=either",
			`{"person":"private"}`); moved != 5 {
			t.Errorf("somebody who reads undisclosed work was handed %d findings, want 5", moved)
		}
	})
}

func TestAssigningByFilterAnswersNothingAboutAProductNobodyShowedYou(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/theirs/findings/assignment", `{"person":"triager"}`)
		if got.Code != http.StatusNotFound {
			t.Errorf("assigning in a product nobody granted answered %d", got.Code)
		}
		got = httpapitest.AsPerson(t, r, "reader", http.MethodPost, matchingAt, `{"person":"reader"}`)
		if got.Code != http.StatusForbidden && got.Code != http.StatusNotFound {
			t.Errorf("a reader assigning answered %d", got.Code)
		}
	})
}

func TestAssigningByFilterToATeamNobodyOnWhichMayReadItIsRefused(t *testing.T) {
	// Routing to a team asks that one member may read the strictest row.
	// A team of public readers is handed disclosed work and refused
	// undisclosed work, whole.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"readers","display_name":"Readers","members":["reader"]}`); made.Code !=
			http.StatusCreated {
			t.Fatalf("recording a team answered %d: %s", made.Code, made.Body.String())
		}
		if _, moved := assignedMatching(t, r, "private-dispatcher", "?planned=either&q=CURL2",
			`{"team":"readers"}`); moved != 2 {
			t.Errorf("a team of readers was handed %d disclosed findings, want 2", moved)
		}
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set("visibility = ?", "private").
			Where("vulnerability_id IN (SELECT id FROM \"vulnerability\" WHERE identifier = ?)",
				"CVE-2026-CURL3").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		refused := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost,
			matchingAt+"?planned=either", `{"team":"readers"}`)
		if refused.Code != http.StatusUnprocessableEntity {
			t.Errorf("routing undisclosed work to a team nobody on which may read it "+
				"answered %d: %s", refused.Code, refused.Body.String())
		}
	})
}

func TestAnEmptySelectionIsRefusedRatherThanReadAsEverything(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		got := httpapitest.AsPerson(t, r, "assigner", http.MethodPost, matchingAt+"?planned=either",
			`{"person":"reader","only":[]}`)
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("an empty selection answered %d: %s", got.Code, got.Body.String())
		}
	})
}
