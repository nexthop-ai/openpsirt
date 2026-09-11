package httpapi_test

import (
	"fmt"
	"net/http"
	"testing"
)

func TestTheFiltersATriagerReachesFor(t *testing.T) {
	// Every filter the server offered was on the screen and the screen was
	// still not enough to assemble a day's work out of.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)

		const at = "/v1/products/mine/findings"
		count := func(t *testing.T, query string) int {
			t.Helper()
			var page struct {
				Items []struct{} `json:"items"`
				Total int        `json:"total"`
			}
			read(t, r, "triager", at+"?"+query, &page)
			if len(page.Items) != page.Total {
				t.Errorf("%q lists %d rows of %d, which do not agree",
					query, len(page.Items), page.Total)
			}
			return page.Total
		}

		if all := count(t, ""); all != 2 {
			t.Fatalf("the fixture lists %d rows, want its two", all)
		}
		// The high one is exploited and scored 8.1; the low one is neither.
		if got := count(t, "epss_at_least=0"); got != 2 {
			t.Errorf("a likelihood of zero excludes %d rows, and should exclude none", 2-got)
		}
		// Nothing in the fixture carries a published likelihood, so anything
		// above zero keeps nothing — which is the answer, not a failure.
		if got := count(t, "epss_at_least=0.5"); got != 0 {
			t.Errorf("a likelihood nothing reaches kept %d rows", got)
		}
		// Both opened just now, so nothing has been open a day.
		if got := count(t, "open_for=1"); got != 0 {
			t.Errorf("something opened this second has been open a day: %d rows", got)
		}
		// Neither is late yet, and both are due inside a year.
		if got := count(t, "overdue=true"); got != 0 {
			t.Errorf("%d rows are already late in a fixture written this second", got)
		}
		if got := count(t, "due_within=400"); got == 0 {
			t.Error("nothing is due within a year, so the deadline filter reaches nothing")
		}
		// What upstream did: one is fixed upstream, the other has no fix.
		if got := count(t, "fix_state=fixed"); got != 1 {
			t.Errorf("one issue is fixed upstream and the filter found %d", got)
		}
		if got := count(t, "fix_state=none"); got != 1 {
			t.Errorf("one issue has no fix and the filter found %d", got)
		}
		// And the two together, which is the question somebody
		// assembling a day's work actually asks: what needs a judgment
		// rather than a bump is "nothing released or upstream
		// declined", and one value could not ask it.
		if got := count(t, "fix_state=none&fix_state=wont-fix"); got != 1 {
			t.Errorf("nothing-released or declined found %d, want the one with no fix", got)
		}
		if got := count(t, "fix_state=fixed&fix_state=none"); got != 2 {
			t.Errorf("both fix statuses at once found %d, want both rows", got)
		}
		// The same for the package kind. Both rows are Debian packages, so a
		// kind they are not adds nothing and a list holding it keeps them.
		if got := count(t, "ecosystem=deb"); got != 2 {
			t.Errorf("the kind they are kept %d rows", got)
		}
		if got := count(t, "ecosystem=golang"); got != 0 {
			t.Errorf("a kind nothing is kept %d rows", got)
		}
		if got := count(t, "ecosystem=deb&ecosystem=golang"); got != 2 {
			t.Errorf("two kinds at once kept %d rows, want the two Debian packages", got)
		}
		// Who is dealing with it: nothing here is assigned, so "nobody" is
		// both rows and "somebody" is none — and the two together must be the
		// union rather than the intersection, which is what applying them one
		// at a time would have made it.
		if got := count(t, "assigned=nobody"); got != 2 {
			t.Errorf("nothing is assigned and unassigned kept %d rows", got)
		}
		if got := count(t, "assigned=somebody"); got != 0 {
			t.Errorf("nothing is assigned and assigned kept %d rows", got)
		}
		if got := count(t, "assigned=nobody&assigned=somebody"); got != 2 {
			t.Errorf("held or unheld kept %d rows, want both; the two answers "+
				"were required to hold at once rather than either", got)
		}
		// And a component named twice is either of them. Only one component
		// is here, so the pair is the same population as the one name — the
		// point being that naming a second does not narrow to nothing.
		if got := count(t, "component=linux-image"); got != 2 {
			t.Errorf("the one component here kept %d rows", got)
		}
		if got := count(t, "component=linux-image&component=openssl"); got != 2 {
			t.Errorf("either of two components kept %d rows, want the two here", got)
		}
		// Nothing has been sent back, and nothing differs in a single build.
		if got := count(t, "sent_back=true"); got != 0 {
			t.Errorf("%d rows are with their author in a fixture nobody decided", got)
		}
		if got := count(t, "differs=true"); got != 2 {
			t.Errorf("asked of one build, differs kept %d rather than being ignored", got)
		}
	})
}

func TestAWeaknessIsMatchedWholeAndNotAsAPrefix(t *testing.T) {
	// Asked as a membership test against the table that holds them, which is
	// what makes "whole and not as a prefix" true by construction rather than
	// by four escaped patterns: packed into one column, a bare LIKE answers
	// CWE-79 for a search for CWE-7.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		var issueID int64
		if err := r.db.DB.NewSelect().TableExpr("vulnerability").Column("id").
			Where(`identifier = ?`, "CVE-2026-9999").
			Scan(t.Context(), &issueID); err != nil {
			t.Fatal(err)
		}
		for _, cwe := range []string{"CWE-125", "CWE-787"} {
			row := map[string]any{"vulnerability_id": issueID, "cwe": cwe}
			if _, err := r.db.DB.NewInsert().Model(&row).
				TableExpr("vulnerability_weakness").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		for _, each := range []struct {
			cwe  string
			want int
		}{
			{"CWE-125", 1}, {"CWE-787", 1}, {"cwe-125", 1},
			{"CWE-12", 0}, {"CWE-78", 0}, {"CWE-1", 0},
		} {
			var page struct {
				Total int `json:"total"`
			}
			read(t, r, "triager",
				fmt.Sprintf("/v1/products/mine/findings?weakness=%s", each.cwe), &page)
			if page.Total != each.want {
				t.Errorf("%s kept %d rows, want %d", each.cwe, page.Total, each.want)
			}
		}
	})
}

func TestAssignedToMeMeansMineOrMyTeams(t *testing.T) {
	// on the list's own filter. The column holds a party, and a person's
	// is not their person identifier — so a filter comparing the wrong one
	// answers about somebody else, silently.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		// A team first, so the two numbers have certainly diverged.
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"kernel","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		assign := func(t *testing.T, issue, body string) {
			t.Helper()
			got := asPerson(t, r, "assigner", http.MethodPut,
				"/v1/products/mine/streams/master/variants/broadcom/findings/"+issue+
					"/components/linux-image/assignment", body)
			if got.Code != http.StatusNoContent {
				t.Fatalf("assigning %s answered %d: %s", issue, got.Code, got.Body.String())
			}
		}
		assign(t, "CVE-2026-9999", `{"person":"triager"}`)
		assign(t, "CVE-2026-1000", `{"team":"kernel"}`)

		var mine struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?assigned=me", &mine)
		if mine.Total != 2 {
			t.Errorf("mine or my team's found %d, want the one of each", mine.Total)
		}
		// Somebody not on the team counts neither.
		read(t, r, "assigner", "/v1/products/mine/findings?assigned=me", &mine)
		if mine.Total != 0 {
			t.Errorf("somebody holding neither counts %d as theirs", mine.Total)
		}
	})
}

func TestTheOutcomeFilterAnswersForWhatStandsNotWhatWasProposed(t *testing.T) {
	// Asking what has been dismissed is asking what this deployment's answer
	// is. A claim still waiting for a second person is not an answer yet, and
	// counting it as one lets a single person put their own proposal into the
	// number the question was asked about.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		dismissed := func(t *testing.T) int {
			t.Helper()
			var page struct {
				Total int `json:"total"`
			}
			read(t, r, "triager",
				"/v1/products/mine/findings?outcome=not-applicable", &page)
			return page.Total
		}

		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if got := dismissed(t); got != 0 {
			t.Errorf("a dismissal nobody has agreed to answers the outcome "+
				"filter with %d rows, want none", got)
		}

		if ok := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); ok.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
		}
		if got := dismissed(t); got != 1 {
			t.Errorf("an agreed dismissal answers the outcome filter with %d rows, want the one", got)
		}
	})
}

func TestAWithdrawnClaimLeavesTheFindingAsWorkAgain(t *testing.T) {
	// A claim that has been taken back says nothing about the place, so the
	// finding is undecided again — the state words have to partition the list
	// or a row falls out of every one of them and out of the count above it,
	// and nothing ever offers it as work again.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)

		buckets := func(t *testing.T) (undecided, waiting, agreed, lapsed, total int) {
			t.Helper()
			at := func(query string) int {
				var page struct {
					Total int `json:"total"`
				}
				read(t, r, "triager", "/v1/products/mine/findings?"+query, &page)
				return page.Total
			}
			return at("state=undecided"), at("state=waiting"), at("state=agreed"),
				at("state=lapsed"), at("")
		}

		if u, w, a, l, all := buckets(t); u+w+a+l != all {
			t.Fatalf("before anything is claimed the buckets are %d+%d+%d+%d of %d",
				u, w, a, l, all)
		}

		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if u, w, a, l, all := buckets(t); u+w+a+l != all {
			t.Errorf("with a claim waiting the buckets are %d+%d+%d+%d of %d",
				u, w, a, l, all)
		}

		if gone := asPerson(t, r, "triager", http.MethodDelete,
			fmt.Sprintf("/v1/claims/%d", claim), ""); gone.Code >= 300 {
			t.Fatalf("withdrawing answered %d: %s", gone.Code, gone.Body.String())
		}
		u, w, a, l, all := buckets(t)
		if u+w+a+l != all {
			t.Errorf("after the claim was taken back the buckets are %d+%d+%d+%d of %d",
				u, w, a, l, all)
		}
		if u != all {
			t.Errorf("a finding whose only claim was withdrawn reports %d undecided of %d",
				u, all)
		}
	})
}

func TestEveryRowIsReachableBySomeFixState(t *testing.T) {
	// A scanner that declines to say what upstream has done is its own answer,
	// and it was mapped to the empty string — a state no constant declared and
	// no filter value named, so those rows belonged to none of the buckets.
	//
	// And the list answers per issue and component *across* builds, so a group
	// whose places disagree has no single answer to give. Asked for one state
	// the question is unanimity; a group that is fixed in one build and not in
	// another answered neither, and was a row no value of this filter could
	// list — the same hole one level up.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		r.siblingsAlsoIn(t, "mellanox")

		// One issue reported with no answer at all, and one package fixed in
		// one build and not in the other.
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("fix_state = ?", "unknown").
			Where(`vulnerability_id = (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-CURL3").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("fix_state = ?", "wont-fix").
			Where(`vulnerability_id = (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-CURL1").
			Where(`target_id = (SELECT MAX(target_id) FROM finding)`).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		count := func(t *testing.T, query string) int {
			t.Helper()
			var page struct {
				Total int `json:"total"`
			}
			read(t, r, "triager", "/v1/products/mine/findings?"+query, &page)
			return page.Total
		}

		all := count(t, "")
		reached := 0
		for _, state := range []string{"fixed", "none", "wont-fix", "unknown", "mixed"} {
			reached += count(t, "fix_state="+state)
		}
		if reached != all {
			t.Errorf("the fix-state values reach %d rows of %d, so some row is in "+
				"none of them", reached, all)
		}
		if got := count(t, "fix_state=unknown"); got == 0 {
			t.Error("nothing is reachable as unknown, so this proves nothing")
		}
		if got := count(t, "fix_state=mixed"); got == 0 {
			t.Error("nothing is reachable as mixed, so the group whose places " +
				"disagree is not being exercised")
		}
	})
}
