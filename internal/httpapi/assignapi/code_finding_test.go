// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// codeFindingAt is where the seeded code finding is addressed on the seeded build.
func codeFindingAt(occurrence string) string {
	return "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
}

// granted gives one of the cast another role on the seeded product.
func granted(t *testing.T, r *httpapitest.Reach, who string, role access.Role) {
	t.Helper()
	ctx := t.Context()
	person, err := r.Rights.Ensure(ctx, who, httpapitest.ShownAs(who), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	mine, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "mine")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Rights.GrantRole(ctx, person.ID, mine.ID, role); err != nil {
		t.Fatal(err)
	}
}

// heldCodeFinding is who the code finding page and the queue name as dealing with the code finding.
type heldCodeFinding struct {
	AssignedTo   string `json:"assigned_to"`
	AssignedTeam bool   `json:"assigned_team"`
}

// holderOf is who the code finding page says is dealing with the code finding, and who the
// queue's row for it says, as one reader reads both.
func holderOf(t *testing.T, r *httpapitest.Reach, who, occurrence string) (page, queue heldCodeFinding) {
	t.Helper()
	httpapitest.Read(t, r, who, codeFindingAt(occurrence), &page)
	var listed struct {
		Items []struct {
			Occurrence string `json:"occurrence"`
			heldCodeFinding
		} `json:"items"`
	}
	httpapitest.Read(t, r, who, "/v1/products/mine/code-findings?state=open", &listed)
	for _, row := range listed.Items {
		if row.Occurrence == occurrence {
			queue = row.heldCodeFinding
		}
	}
	return page, queue
}

// Assigning a code finding is triage at the code finding's visibility. Somebody who does not
// read it, and somebody who reads it and triages only another visibility, are
// answered as though it were not there, and giving it to somebody else asks
// for the assigner right as a finding's assignment does.
func TestACodeFindingIsAssignedByWhoeverTriagesItsVisibility(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		at := codeFindingAt(occurrence) + "/assignment"
		// Reading the code finding, and triaging disclosed work alone.
		granted(t, r, "internal-reviewer", access.PublicTriage)
		for _, c := range []struct {
			who, body string
			want      int
		}{
			{"reader", `{"person":"reader"}`, http.StatusNotFound},
			{"triager", `{"person":"triager"}`, http.StatusNotFound},
			{"private-triage", `{"person":"private-triage"}`, http.StatusNotFound},
			{"internal-reader", `{"person":"internal-reader"}`, http.StatusNotFound},
			{"internal-reviewer", `{"person":"internal-reviewer"}`, http.StatusNotFound},
			{"assigner-only", `{"person":"assigner-only"}`, http.StatusNotFound},
			{"internal-triager", `{"person":"internal-reader"}`, http.StatusUnprocessableEntity},
			{"internal-triager", `{"team":"anybody"}`, http.StatusUnprocessableEntity},
			{"internal-triager", `{"person":"internal-triager"}`, http.StatusNoContent},
		} {
			if got := httpapitest.AsPerson(t, r, c.who, http.MethodPut, at, c.body); got.Code != c.want {
				t.Errorf("%s sending %s answered %d, want %d: %s", c.who, c.body, got.Code, c.want, got.Body)
			}
		}
		page, queue := holderOf(t, r, "internal-reader", occurrence)
		if page.AssignedTo != "internal-triager" || queue.AssignedTo != "internal-triager" {
			t.Errorf("the code finding page names %+v and the queue %+v; want the triager who took it", page, queue)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at, `{}`); got.Code != http.StatusNoContent {
			t.Fatalf("handing it back answered %d: %s", got.Code, got.Body)
		}
		if page, queue := holderOf(t, r, "internal-reader", occurrence); page.AssignedTo != "" || queue.AssignedTo != "" {
			t.Errorf("a code finding handed back is named as held by %+v and %+v", page, queue)
		}
	})
}

// A code finding given to somebody is given only where they read it, and the line
// telling them is withheld as internal work: a reader of undisclosed work is
// refused the code finding and told nothing, and the holder losing internal reading
// loses the line with it, though they still read the product's undisclosed
// work.
func TestACodeFindingAssignedIsToldToItsHolderAsInternalWork(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		at := codeFindingAt(occurrence) + "/assignment"
		granted(t, r, "internal-triager", access.Assigner)
		granted(t, r, "internal-reader", access.PrivateRead)

		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at,
			`{"person":"private"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("handing a code finding to a reader of undisclosed work answered %d: %s", got.Code, got.Body)
		}
		// Asked of what was stored rather than of what they read: the area
		// narrows a line about internal work away from them, and a line
		// written for them at all is the defect.
		written, err := r.DB.DB.NewSelect().TableExpr(`"notification" AS "n"`).
			Join(`JOIN "person" AS "p" ON "p"."id" = "n"."person_id"`).
			Where(`"p"."identity" = ?`, "private").
			Where(`"n"."kind" = ?`, notify.Assigned).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if written != 0 {
			t.Error("a reader of undisclosed work was told about a code finding")
		}

		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at,
			`{"person":"internal-reader"}`); got.Code != http.StatusNoContent {
			t.Fatalf("handing the code finding to a reader of internal work answered %d: %s", got.Code, got.Body)
		}
		if !toldAbout(t, r, "internal-reader", "clang-tidy/leak at src/a.c:12") {
			t.Fatal("the reader handed the code finding was not told")
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/internal-reader/roles/mine/internal-read", ""); got.Code != http.StatusOK {
			t.Fatalf("withdrawing internal reading answered %d: %s", got.Code, got.Body)
		}
		if toldAbout(t, r, "internal-reader", "clang-tidy/leak") {
			t.Error("somebody who no longer reads internal work still reads the line about a code finding")
		}
	})
}

// Losing the last role on a product hands back the code findings it carried, as it
// hands back every finding.
func TestLosingTheLastRoleHandsBackTheCodeFindingsItCarried(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, codeFindingAt(occurrence)+"/assignment",
			`{"person":"internal-triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("taking the code finding answered %d: %s", got.Code, got.Body)
		}
		var withdrawn struct {
			Released int64 `json:"released"`
		}
		got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete,
			"/v1/people/internal-triager/roles/mine/internal-triage", "")
		if got.Code != http.StatusOK {
			t.Fatalf("withdrawing the role answered %d: %s", got.Code, got.Body)
		}
		if err := json.Unmarshal(got.Body.Bytes(), &withdrawn); err != nil {
			t.Fatal(err)
		}
		if withdrawn.Released == 0 {
			t.Error("the last role went and the code finding it carried was not handed back")
		}
		if page, _ := holderOf(t, r, "internal-reader", occurrence); page.AssignedTo != "" {
			t.Errorf("the code finding is still held by %q", page.AssignedTo)
		}
	})
}

// A team is handed a code finding when one of its members reads it, and its queue is
// named on the code finding.
func TestATeamHoldsACodeFindingOneOfItsMembersReads(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		at := codeFindingAt(occurrence) + "/assignment"
		granted(t, r, "internal-triager", access.Assigner)
		for _, team := range []string{
			`{"name":"private-desk","members":["private"]}`,
			`{"name":"analysis-desk","members":["internal-reader"]}`,
		} {
			if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams", team); made.Code != http.StatusCreated {
				t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
			}
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at,
			`{"team":"private-desk"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("a team nobody on which reads internal work was handed a code finding: %d %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at,
			`{"team":"analysis-desk"}`); got.Code != http.StatusNoContent {
			t.Fatalf("a team with a reader of internal work answered %d: %s", got.Code, got.Body)
		}
		page, queue := holderOf(t, r, "internal-reader", occurrence)
		if page.AssignedTo != "analysis-desk" || !page.AssignedTeam || !queue.AssignedTeam {
			t.Errorf("the code finding page names %+v and the queue %+v; want the team's queue", page, queue)
		}
	})
}

// The queue's file names a code finding's holder as the list does: who, their
// display name, and whether it is a team's queue, since a team and a person
// may share a name.
func TestTheCodeFindingFileNamesAHolderAsTheListDoes(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		granted(t, r, "internal-triager", access.Assigner)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"analysis-desk","members":["internal-reader"]}`); made.Code != http.StatusCreated {
			t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, codeFindingAt(occurrence)+"/assignment",
			`{"team":"analysis-desk"}`); got.Code != http.StatusNoContent {
			t.Fatalf("queueing the code finding with the team answered %d: %s", got.Code, got.Body)
		}
		file := httpapitest.AsPerson(t, r, "internal-reader", http.MethodGet, "/v1/products/mine/code-findings.csv?state=open", "")
		records, err := csv.NewReader(strings.NewReader(file.Body.String())).ReadAll()
		if err != nil {
			t.Fatalf("the file is not CSV a strict reader reads: %v\n%s", err, file.Body)
		}
		var header []string
		rows := 0
		for _, record := range records {
			switch {
			case strings.HasPrefix(record[0], "#"):
			case header == nil:
				header = record
			default:
				named := map[string]string{}
				for i, column := range header {
					named[column] = record[i]
				}
				if named["occurrence"] != occurrence {
					continue
				}
				rows++
				if named["assigned_to"] != "analysis-desk" || named["assigned_team"] != "true" {
					t.Errorf("the file names the holder %q, team %q; want the team's queue",
						named["assigned_to"], named["assigned_team"])
				}
				if _, ok := named["assigned_to_name"]; !ok {
					t.Error("the file has no column for the holder's display name")
				}
			}
		}
		if rows != 1 {
			t.Fatalf("the file holds %d rows for the code finding; want one\n%s", rows, file.Body)
		}
	})
}

// A code finding every release of which is past its end of life is kept as it stands.
func TestACodeFindingPastItsEndOfLifeIsNotAssigned(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		ended := time.Now().UTC().Add(-48 * time.Hour).Truncate(24 * time.Hour)
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"branch_or_tag"`).Set(`"eol_on" = ?`, ended).
			Where(`"name" = ?`, "master").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, codeFindingAt(occurrence)+"/assignment",
			`{"person":"internal-triager"}`); got.Code != http.StatusConflict {
			t.Errorf("taking a code finding past its end of life answered %d: %s", got.Code, got.Body)
		}
	})
}

// A code finding every release of which is past its end of life is one nobody may
// take, so the work nobody holds leaves it out, as the code finding queue narrowed to
// nobody does.
func TestTheUnassignedListLeavesOutACodeFindingPastItsEndOfLife(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		if got, _ := heldItems(t, r, "internal-reader", "/v1/unassigned"); len(got) != 1 || got[0] != occurrence {
			t.Fatalf("the unassigned list holds code findings %v; want the seeded code finding, or this checks nothing", got)
		}
		ended := time.Now().UTC().Add(-48 * time.Hour).Truncate(24 * time.Hour)
		if _, err := r.DB.DB.NewUpdate().TableExpr(`"branch_or_tag"`).Set(`"eol_on" = ?`, ended).
			Where(`"name" = ?`, "master").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got, _ := heldItems(t, r, "internal-reader", "/v1/unassigned"); len(got) != 0 {
			t.Errorf("the unassigned list holds code findings %v past their end of life", got)
		}
	})
}

// Handing everything one person holds to somebody else moves their code findings too,
// and is refused where the recipient may not read internal work.
func TestHandingOverSomebodysWorkMovesTheirCodeFindingsToAReaderOfThem(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, codeFindingAt(occurrence)+"/assignment",
			`{"person":"internal-triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("taking the code finding answered %d: %s", got.Code, got.Body)
		}
		at := "/v1/people/internal-triager/assignments/hand-back"
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, at, `{"to":"private"}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("handing a code finding to a reader of undisclosed work answered %d: %s", got.Code, got.Body)
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, at, `{"to":"internal-reader"}`); got.Code != http.StatusOK {
			t.Fatalf("handing a code finding to a reader of internal work answered %d: %s", got.Code, got.Body)
		}
		if page, _ := holderOf(t, r, "internal-reader", occurrence); page.AssignedTo != "internal-reader" {
			t.Errorf("the code finding is held by %q; want the reader it was handed to", page.AssignedTo)
		}
	})
}

// heldItems is the occurrences of the code findings a list of held work answers one reader,
// and how many items it holds in all.
func heldItems(t *testing.T, r *httpapitest.Reach, who, path string) (occurrences []string, items int) {
	t.Helper()
	var got struct {
		Items []struct {
			Vulnerability string `json:"vulnerability"`
			Occurrence    string `json:"occurrence"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, who, path, &got)
	for _, item := range got.Items {
		if item.Occurrence != "" {
			occurrences = append(occurrences, item.Occurrence)
		}
	}
	return occurrences, len(got.Items)
}

// The unassigned list, one person's work and the totals behind them list a
// code finding to whoever reads internal work, as one piece of work, and to nobody
// else.
func TestTheListsOfHeldWorkListACodeFindingToItsReadersAlone(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		if got, _ := heldItems(t, r, "internal-reader", "/v1/unassigned"); len(got) != 1 || got[0] != occurrence {
			t.Errorf("the unassigned list holds code findings %v; want the seeded code finding", got)
		}
		if got, _ := heldItems(t, r, "reader", "/v1/unassigned"); len(got) != 0 {
			t.Errorf("a reader of disclosed work was listed code findings %v", got)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, codeFindingAt(occurrence)+"/assignment",
			`{"person":"internal-triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("taking the code finding answered %d: %s", got.Code, got.Body)
		}
		if got, _ := heldItems(t, r, "internal-reader", "/v1/unassigned"); len(got) != 0 {
			t.Errorf("the unassigned list holds the code finding taken: %v", got)
		}
		const theirs = "/v1/people/internal-triager/assignments"
		if got, n := heldItems(t, r, "internal-reader", theirs); len(got) != 1 || got[0] != occurrence || n != 1 {
			t.Errorf("their work holds code findings %v of %d items; want the seeded code finding alone", got, n)
		}
		if got, _ := heldItems(t, r, "internal-triager", "/v1/people/me/assignments"); len(got) != 1 {
			t.Errorf("the holder's own work holds code findings %v; want the seeded code finding", got)
		}
		if got, n := heldItems(t, r, "reader", theirs); len(got) != 0 || n != 0 {
			t.Errorf("a reader of disclosed work was listed %d items of their work, code findings %v", n, got)
		}
		holding := func(who string) int {
			var got struct {
				Items []struct {
					Person string `json:"person"`
					Open   int    `json:"open"`
				} `json:"items"`
			}
			httpapitest.Read(t, r, who, "/v1/assignments", &got)
			for _, row := range got.Items {
				if row.Person == "internal-triager" {
					return row.Open
				}
			}
			return 0
		}
		if n := holding("internal-reader"); n != 1 {
			t.Errorf("the totals count %d pieces held by the code finding's holder; want one", n)
		}
		if n := holding("reader"); n != 0 {
			t.Errorf("a reader of disclosed work was counted %d pieces of the code finding's holder", n)
		}
	})
}

// A team's queue lists a code finding it holds to whoever reads internal work.
func TestATeamsQueueListsACodeFindingItHolds(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		granted(t, r, "internal-triager", access.Assigner)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"analysis-desk","members":["internal-reader"]}`); made.Code != http.StatusCreated {
			t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, codeFindingAt(occurrence)+"/assignment",
			`{"team":"analysis-desk"}`); got.Code != http.StatusNoContent {
			t.Fatalf("queueing the code finding with the team answered %d: %s", got.Code, got.Body)
		}
		const queue = "/v1/teams/analysis-desk/assignments"
		if got, _ := heldItems(t, r, "internal-reader", queue); len(got) != 1 || got[0] != occurrence {
			t.Errorf("the team's queue holds code findings %v; want the seeded code finding", got)
		}
		if got, n := heldItems(t, r, "reader", queue); len(got) != 0 || n != 0 {
			t.Errorf("a reader of disclosed work was listed %d items of the team's queue, code findings %v", n, got)
		}
	})
}

// A code finding recorded as a flaw leaves the lists of held work, internal only or included in disclosure:
// its flaw is held and listed as itself.
func TestAnInternalOnlyRecordedCodeFindingLeavesTheListsOfHeldWork(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) { recordedAsFlawUnlisted(t, r, false) })
}

func TestAnIncludedRecordedCodeFindingLeavesTheListsOfHeldWork(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) { recordedAsFlawUnlisted(t, r, true) })
}

// recordedAsFlawUnlisted hands the seeded code finding off, internal only or included in disclosure, and checks no
// reader of it is listed it as unassigned work, while its flaw is.
func recordedAsFlawUnlisted(t *testing.T, r *httpapitest.Reach, included bool) {
	t.Helper()
	occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, included)
	for _, who := range []string{"internal-reader", "embargo-reader", "code-finding-handler"} {
		if got, _ := heldItems(t, r, who, "/v1/unassigned"); len(got) != 0 {
			t.Errorf("%s is listed the code finding recorded as a flaw %v", who, got)
		}
	}
	var listed struct {
		Items []struct {
			Vulnerability string `json:"vulnerability"`
		} `json:"items"`
	}
	httpapitest.Read(t, r, "code-finding-handler", "/v1/unassigned", &listed)
	found := false
	for _, item := range listed.Items {
		found = found || item.Vulnerability == flaw
	}
	if !found {
		t.Errorf("the unassigned list holds %+v; want the flaw %s in place of code finding %s", listed.Items, flaw, occurrence)
	}
}

// A code finding its holder took and then recorded as a flaw, internal only or included in disclosure, leaves
// their work and the totals, is not assigned again, and stays where it is when
// their work is handed over: it is closed work for its holder.
func TestAnInternalOnlyRecordedCodeFindingLeavesItsHoldersWork(t *testing.T) {
	recordedAsFlawHeld(t, false)
}

func TestAnIncludedRecordedCodeFindingLeavesItsHoldersWork(t *testing.T) { recordedAsFlawHeld(t, true) }

// recordedAsFlawHeld records as a flaw a code finding its holder took first, included in disclosure or not.
func recordedAsFlawHeld(t *testing.T, included bool) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence, _ := httpapitest.RecordedCodeFindingHeldBy(t, r, included, "code-finding-handler")
		for _, path := range []string{"/v1/people/code-finding-handler/assignments", "/v1/people/me/assignments"} {
			if got, n := heldItems(t, r, "code-finding-handler", path); len(got) != 0 || n != 0 {
				t.Errorf("%s holds %d items, code findings %v; want the code finding recorded as a flaw gone", path, n, got)
			}
		}
		var totals struct {
			Items []struct {
				Person string `json:"person"`
				Open   int    `json:"open"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "code-finding-handler", "/v1/assignments", &totals)
		for _, row := range totals.Items {
			if row.Person == "code-finding-handler" && row.Open != 0 {
				t.Errorf("the totals count %d pieces held by the code finding's holder; want none", row.Open)
			}
		}
		if got := httpapitest.AsPerson(t, r, "code-finding-handler", http.MethodPut, codeFindingAt(occurrence)+"/assignment",
			`{"person":""}`); got.Code != http.StatusConflict {
			t.Errorf("handing back a code finding recorded as a flaw answered %d: %s", got.Code, got.Body)
		}
		holder := func() *int64 {
			var held struct {
				AssignedTo *int64 `bun:"assigned_to"`
			}
			if err := r.DB.DB.NewSelect().TableExpr(`"finding"`).Column("assigned_to").
				Where(`"occurrence_identity" = ?`, occurrence).Limit(1).Scan(t.Context(), &held); err != nil {
				t.Fatal(err)
			}
			return held.AssignedTo
		}
		before := holder()
		if before == nil {
			t.Fatal("the code finding's holder holds nothing, so this checks nothing")
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPost,
			"/v1/people/code-finding-handler/assignments/hand-back", `{"to":"reader"}`); got.Code != http.StatusOK {
			t.Errorf("handing over work holding only a code finding recorded as a flaw answered %d: %s", got.Code, got.Body)
		}
		if after := holder(); after == nil || *after != *before {
			t.Errorf("the hand-over moved the code finding recorded as a flaw away from its holder, %d", *before)
		}
	})
}

// Two code findings of one rule in one component are two pieces of work: a code finding is
// judged at its occurrence, and grouping them would hide the second behind the
// first.
func TestEachCodeFindingIsOnePieceOfHeldWork(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		httpapitest.ApplyRunIn(t, r, "cppcheck/default", time.Now().UTC().Add(-time.Hour),
			httpapitest.OtherToolRun("cppcheck", "overflow", "787", "src/c.c", 3, 40))
		if got, _ := heldItems(t, r, "internal-reader", "/v1/unassigned"); len(got) != 3 {
			t.Errorf("the unassigned list holds code findings %v; want the seeded code finding and both overflows", got)
		}
	})
}

// The queue narrowed to work nobody holds reads as the findings list's
// narrowing does: a code finding somebody holds leaves the rows and every count, and
// handed back it returns to both.
func TestTheQueueNarrowedToNobodyLeavesOutACodeFindingSomebodyHolds(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededCodeFinding(t, r)
		at := codeFindingAt(occurrence) + "/assignment"
		type narrowed struct {
			Items []struct {
				Occurrence string `json:"occurrence"`
			} `json:"items"`
			Total  int            `json:"total"`
			States map[string]int `json:"states"`
		}
		unheld := func() narrowed {
			var got narrowed
			httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/code-findings?assigned=nobody", &got)
			return got
		}
		if got := unheld(); len(got.Items) != 1 || got.Items[0].Occurrence != occurrence || got.Total != 1 || got.States["open"] != 1 {
			t.Fatalf("the unheld code findings are %+v; want the seeded code finding, listed and counted", got)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at, `{"person":"internal-triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("taking the code finding answered %d: %s", got.Code, got.Body)
		}
		if got := unheld(); len(got.Items) != 0 || got.Total != 0 || got.States["open"] != 0 {
			t.Errorf("a held code finding is in the unheld code findings as %+v", got)
		}
		var all narrowed
		httpapitest.Read(t, r, "internal-reader", "/v1/products/mine/code-findings", &all)
		if len(all.Items) != 1 {
			t.Errorf("the queue unnarrowed is %+v; want the held code finding in it", all)
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, at, `{}`); got.Code != http.StatusNoContent {
			t.Fatalf("handing it back answered %d: %s", got.Code, got.Body)
		}
		if got := unheld(); len(got.Items) != 1 || got.States["open"] != 1 {
			t.Errorf("a code finding handed back is missing from the unheld code findings: %+v", got)
		}
	})
}
