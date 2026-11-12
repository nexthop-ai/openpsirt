// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestAMentionTellsOnlySomebodyWhoCouldAlreadyReadIt(t *testing.T) {
	// and the rule that makes it safe. On an undisclosed finding the
	// notification itself would say a finding exists, so whoever is told
	// is exactly whoever the editor would have offered — from the same
	// query, so the two cannot come to disagree.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := r.Scanned(t)

		// A decision to hang comments off.
		made := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-9999/occurrences/"+occurrence+"/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"The parser is never reached."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("proposing answered %d: %s", made.Code, made.Body.String())
		}
		var claimed struct {
			ID         int64 `json:"id"`
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &claimed); err != nil {
			t.Fatal(err)
		}

		// A comment naming a colleague who reads this product, and one naming
		// somebody who does not exist at all.
		said := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/decisions/"+httpapitest.Itoa(claimed.DecisionID)+"/comments",
			`{"body":"@reader could you look at this? @nobody-at-all too, and @triager wrote it."}`)
		if said.Code >= 400 {
			t.Fatalf("commenting answered %d: %s", said.Code, said.Body.String())
		}

		// The colleague hears about it.
		var theirs struct {
			Items []struct {
				Kind string `json:"kind"`
				Body string `json:"body"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reader", "/v1/notifications", &theirs)
		var named int
		for _, item := range theirs.Items {
			if item.Kind == "mentioned" {
				named++
			}
		}
		if named != 1 {
			t.Errorf("the person named was told %d times, want once: %+v", named, theirs.Items)
		}

		// Whoever wrote it named themselves and is not told about it: a tool
		// that reports back what you have just typed is one people stop
		// reading. A name nobody holds simply reaches nobody, with no error —
		// the comment is on record by then and refusing it helps nobody.
		var mine struct {
			Items []struct {
				Kind string `json:"kind"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", "/v1/notifications", &mine)
		for _, item := range mine.Items {
			if item.Kind == "mentioned" {
				t.Error("the author was told they named somebody")
			}
		}
	})
}

func TestAMentionOnUndisclosedWorkReachesNobodyWhoMayNotSeeIt(t *testing.T) {
	// The disclosure this rule exists to prevent: being told you were named on
	// a finding is being told the finding exists. Two people are named on a
	// decision about undisclosed work: one who reads it is told, and one who
	// reads only what is disclosed is told nothing.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		flaw := r.Embargoed(t)
		decision, _ := r.Claimed(t, "private-triage", flaw, "libnl-3-200", httpapitest.Dismissal)
		said := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/decisions/"+httpapitest.Itoa(decision)+"/comments",
			`{"body":"@reader and @private, could you look at the management socket?"}`)
		if said.Code >= 400 {
			t.Fatalf("commenting answered %d: %s", said.Code, said.Body.String())
		}

		mentioned := func(who string) int {
			var told struct {
				Items []struct {
					Kind string `json:"kind"`
				} `json:"items"`
			}
			httpapitest.Read(t, r, who, "/v1/notifications", &told)
			n := 0
			for _, item := range told.Items {
				if item.Kind == "mentioned" {
					n++
				}
			}
			return n
		}
		if n := mentioned("private"); n != 1 {
			t.Errorf("somebody who reads undisclosed work was told %d times, want once", n)
		}
		if n := mentioned("reader"); n != 0 {
			t.Errorf("somebody who may not read undisclosed work was told %d times", n)
		}
		// Not written for them at all, rather than written and then left out
		// of what they read: a row about undisclosed work held for somebody
		// who may not read it is one step from being shown.
		held, err := r.DB.DB.NewSelect().TableExpr(`"notification" AS "n"`).
			Join(`JOIN "person" AS "p" ON "p"."id" = "n"."person_id"`).
			Where(`"p"."identity" = ?`, "reader").Where(`"n"."kind" = ?`, "mentioned").Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if held != 0 {
			t.Errorf("%d mentions were written for somebody who may not read the work", held)
		}
	})
}

func TestAMentionOnADecisionSpanningVisibilitiesIsToldAsItsMostWithheld(t *testing.T) {
	// A bulk decision can cover a disclosed issue in one product and an
	// undisclosed one in another. A name in its text reaches only somebody who
	// reads every row, the notification is withheld as undisclosed work
	// whichever row was written first, and it is stored against the product
	// whose undisclosed work it is, so the person told reads it.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.ScannedWithEvidence(t)
		decision, _ := r.Claimed(t, "private-triage", "CVE-2026-9999", "libnl-3-200", httpapitest.Dismissal)
		flaw := r.Embargoed(t)

		// The undisclosed row, written beside the disclosed one the route
		// wrote first, as one bulk decision over both issues holds them.
		var first triage.DecisionOccurrence
		if err := r.DB.DB.NewSelect().Model(&first).
			Where(`"de"."decision_id" = ?`, decision).Limit(1).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if first.Visibility != access.Public {
			t.Fatalf("the route wrote a %s row, want the disclosed one first", first.Visibility)
		}
		var issue int64
		if err := r.DB.DB.NewSelect().TableExpr(`"vulnerability"`).Column("id").
			Where(`"identifier" = ?`, flaw).Scan(ctx, &issue); err != nil {
			t.Fatal(err)
		}
		undisclosed := first
		undisclosed.ID = 0
		undisclosed.Decision = nil
		// Who is told reads every row whether or not it stands, so the
		// row needs no live key of its own.
		undisclosed.LiveKey = nil
		undisclosed.VulnerabilityID = issue
		undisclosed.Visibility = access.Private
		// In the other product: a bulk decision reads across products.
		theirs, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, "theirs")
		if err != nil {
			t.Fatal(err)
		}
		undisclosed.ProductID = theirs.ID
		undisclosed.OccurrenceIdentity = strings.Repeat("0", len(first.OccurrenceIdentity))
		if _, err := r.DB.DB.NewInsert().Model(&undisclosed).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		// The reader reads disclosed work in the first product and undisclosed
		// work in the second, so they read both rows; the author reads both
		// as well. The person reading undisclosed work in the first product
		// alone reads only one row.
		for _, who := range []string{"reader", "private-triage"} {
			person, err := r.Rights.ByIdentity(ctx, who)
			if err != nil {
				t.Fatal(err)
			}
			for _, role := range []access.Role{access.PublicRead, access.PrivateRead, access.PrivateTriage} {
				if err := r.Rights.GrantRole(ctx, person.ID, theirs.ID, role); err != nil {
					t.Fatal(err)
				}
			}
		}
		said := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			"/v1/decisions/"+httpapitest.Itoa(decision)+"/comments",
			`{"body":"@reader and @private, could you look at both?"}`)
		if said.Code >= 400 {
			t.Fatalf("commenting answered %d: %s", said.Code, said.Body.String())
		}

		var told []struct {
			Identity        string `bun:"identity"`
			Private         bool   `bun:"private"`
			SecurityTesting bool   `bun:"security_testing"`
			VulnerabilityID *int64 `bun:"vulnerability_id"`
		}
		if err := r.DB.DB.NewSelect().TableExpr(`"notification" AS "n"`).
			Join(`JOIN "person" AS "p" ON "p"."id" = "n"."person_id"`).
			ColumnExpr(`"p"."identity"`).ColumnExpr(`"n"."private"`).
			ColumnExpr(`"n"."security_testing"`).ColumnExpr(`"n"."vulnerability_id"`).
			Where(`"n"."kind" = ?`, "mentioned").Scan(ctx, &told); err != nil {
			t.Fatal(err)
		}
		if len(told) != 1 || told[0].Identity != "reader" {
			t.Fatalf("the mention was written for %+v, want only the person reading both rows", told)
		}
		if !told[0].Private || told[0].SecurityTesting {
			t.Errorf("the mention was withheld as private=%t security-testing=%t, want private alone",
				told[0].Private, told[0].SecurityTesting)
		}
		if told[0].VulnerabilityID != nil {
			t.Errorf("a decision over two issues was told as about issue %d", *told[0].VulnerabilityID)
		}
		// Written is not read: the notice is stored against the product whose
		// undisclosed work its reader reads, so it reaches them.
		var theirsRead struct {
			Items []struct {
				Kind string `json:"kind"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reader", "/v1/notifications", &theirsRead)
		read := 0
		for _, item := range theirsRead.Items {
			if item.Kind == "mentioned" {
				read++
			}
		}
		if read != 1 {
			t.Errorf("the person named reads the mention %d times, want once", read)
		}
	})
}

func TestAMentionThatReachedNobodyIsReportedBack(t *testing.T) {
	// mentions reaching only readers says mentioning somebody who cannot
	// see the finding is refused while composing, and only the candidate
	// list enforced it. Writing the name anyway was accepted, nobody was
	// told, and the author had no way to know — so a question was asked of
	// somebody who never heard it.
	//
	// Reported rather than refused: the words are worth keeping either
	// way, and a comment rejected because one name in it was wrong loses
	// the paragraph to fix a word.
	//
	// And reported without saying why. A name nobody holds and a name
	// held by somebody who may not read this are one answer here, because
	// telling them apart would answer "can this person see undisclosed
	// work" one comment at a time.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := r.Scanned(t)
		_, decision := r.DecidedAt(t, occurrence)

		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/comments", decision),
			`{"body":"@private-triage and @nobody-is-called-this, what do you think?"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("commenting answered %d: %s", got.Code, got.Body.String())
		}
		var said struct {
			NotNotified []string `json:"not_notified"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &said); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		if len(said.NotNotified) != 1 || said.NotNotified[0] != "nobody-is-called-this" {
			t.Errorf("the answer says %v reached nobody, want the one unknown name",
				said.NotNotified)
		}

		// A comment naming only people who can read it says nothing, so the
		// report is a report rather than noise on every write.
		quiet := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/comments", decision),
			`{"body":"@private-triage one more thing."}`)
		if quiet.Code != http.StatusCreated {
			t.Fatalf("commenting answered %d: %s", quiet.Code, quiet.Body.String())
		}
		var second struct {
			NotNotified []string `json:"not_notified"`
		}
		_ = json.Unmarshal(quiet.Body.Bytes(), &second)
		if len(second.NotNotified) != 0 {
			t.Errorf("a comment naming only readers reported %v", second.NotNotified)
		}
	})
}

func TestNamesPastTheMentionCapAreReportedRatherThanDiscarded(t *testing.T) {
	// The cap is generous enough that nobody meets it writing normally, which
	// is what made the silence hard to notice: past it the tail of the list
	// was cut away before anything looked at it, so those names were told
	// nothing and did not appear among the ones that reached nobody. On a
	// finding nobody has announced, that notification is the only signal the
	// people named get that they were called into it.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := r.Scanned(t)
		_, decision := r.DecidedAt(t, occurrence)

		var named strings.Builder
		named.WriteString("@private-triage")
		for i := range 30 {
			fmt.Fprintf(&named, " @nobody-%d", i)
		}
		got := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
			fmt.Sprintf("/v1/decisions/%d/comments", decision),
			`{"body":"`+named.String()+` what do you think?"}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("commenting answered %d: %s", got.Code, got.Body.String())
		}
		var said struct {
			NotNotified []string `json:"not_notified"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &said); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}
		// Every name but the one person who could be told. The author asked
		// thirty people a question and none of them heard it.
		if len(said.NotNotified) != 30 {
			t.Errorf("%d names were reported as reaching nobody, want the thirty that did not",
				len(said.NotNotified))
		}
	})
}
