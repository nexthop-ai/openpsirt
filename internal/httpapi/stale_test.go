package httpapi_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// Each of these is wrong because nothing has happened, which is the
// one thing no message driven by an event can report — so each is derived by
// the sweep and each clears by the thing finally happening.

// aged moves a claim's rows back in time, which is how a threshold measured in
// days is tested without waiting days.
func (r *reach) aged(t *testing.T, claim int64, column string, when time.Time) {
	t.Helper()
	if _, err := r.db.DB.NewUpdate().Table("decision").
		Set(column+" = ?", when).
		Where("claim_id = ?", claim).Exec(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestAClaimNobodyApprovesIsSaidToWhoeverCouldApproveIt(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)

		// A claim proposed a moment ago is not waiting, it is new. Without
		// this the condition would fire on every claim the instant it is made,
		// which is the review queue said twice.
		if told := r.alerts(t, "reviewer", "claim-waiting"); len(told) != 0 {
			t.Fatalf("a claim proposed a moment ago is reported as stale: %v", told)
		}

		r.aged(t, claim, "proposed_at", time.Now().UTC().Add(-10*24*time.Hour))

		waiting := r.alerts(t, "reviewer", "claim-waiting")
		if len(waiting) != 1 {
			t.Fatalf("a claim waiting ten days raised %d notices: %v", len(waiting), waiting)
		}
		if !contains(waiting[0], "second person") {
			t.Errorf("the notice does not say what it is waiting for: %q", waiting[0])
		}

		// Never its proposer. Approving your own claim is refused, so
		// telling them it is waiting is telling them about work they
		// are not allowed to do.
		if told := r.alerts(t, "triager", "claim-waiting"); len(told) != 0 {
			t.Errorf("the proposer was told their own claim is waiting on them: %v", told)
		}
		// And never somebody who may read the product but cannot approve.
		if told := r.alerts(t, "reader", "claim-waiting"); len(told) != 0 {
			t.Errorf("somebody who cannot approve was told: %v", told)
		}
		// Nor somebody who may approve and may read nothing here — the
		// capability is bounded by what they may read.
		if told := r.alerts(t, "approver", "claim-waiting"); len(told) != 0 {
			t.Errorf("an approver who reaches nothing was told about it: %v", told)
		}

		// It clears by the thing happening, which nobody dismisses.
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		if told := r.alerts(t, "reviewer", "claim-waiting"); len(told) != 0 {
			t.Errorf("after approval the claim is still reported as waiting: %v", told)
		}
	})
}

func TestAClaimSentBackAndLeftIsSaidToItsAuthor(t *testing.T) {
	// The one that is invisible on every screen there is: the queue's tabs
	// both list pending work, and a sent-back claim is waiting on its author.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/send-back", claim),
			`{"because":"Name the kconfig option."}`); got.Code != http.StatusNoContent {
			t.Fatalf("sending it back answered %d: %s", got.Code, got.Body.String())
		}

		// Sent back a moment ago is somebody's turn, not somebody's oversight.
		if told := r.alerts(t, "triager", "sent-back-waiting"); len(told) != 0 {
			t.Fatalf("a claim sent back a moment ago is reported as ignored: %v", told)
		}
		r.aged(t, claim, "sent_back_at", time.Now().UTC().Add(-7*24*time.Hour))

		told := r.alerts(t, "triager", "sent-back-waiting")
		if len(told) != 1 {
			t.Fatalf("a claim sent back a week ago raised %d notices: %v", len(told), told)
		}
		if !contains(told[0], "applies to nothing") {
			t.Errorf("the notice does not say what leaving it costs: %q", told[0])
		}
		// It is not also reported as waiting on an approver: it is not.
		if waiting := r.alerts(t, "reviewer", "claim-waiting"); len(waiting) != 0 {
			t.Errorf("a sent-back claim is reported as waiting on the approver: %v", waiting)
		}

		// Revising it is the thing happening, and it clears.
		if got := asPerson(t, r, "triager", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/reasoning", claim),
			`{"reasoning":"CONFIG_NL is not set in this image."}`); got.Code != http.StatusOK {
			t.Fatalf("revising answered %d: %s", got.Code, got.Body.String())
		}
		if told := r.alerts(t, "triager", "sent-back-waiting"); len(told) != 0 {
			t.Errorf("after a revision it is still reported as untouched: %v", told)
		}
	})
}

func TestADeferralIsSaidBeforeItEndsRatherThanAfter(t *testing.T) {
	// The date is followed by the finding arriving back as work that is now
	// late, so the whole value of the warning is the time it leaves.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		soon := time.Now().UTC().AddDate(0, 0, 4).Format(time.DateOnly)
		far := time.Now().UTC().AddDate(0, 0, 300).Format(time.DateOnly)

		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200",
			fmt.Sprintf(`{"outcome":"deferred","deferred_until":%q,`+
				`"reasoning":"Waiting on the vendor's next image."}`, far))
		if told := r.alerts(t, "triager", "deferral-ending"); len(told) != 0 {
			t.Fatalf("a deferral with ten months to run is reported as ending: %v", told)
		}

		// Moved to inside the lead time. Written to the row rather than
		// proposed again, because what is being tested is the sweep's reading
		// of the date and not the form that sets it.
		if _, err := r.db.DB.NewUpdate().Table("claim").
			Set("deferred_until = ?", soon).
			Where("id = ?", claim).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		// Nothing is in force yet. Every clause of the notice would be false:
		// it names a date that covers nothing, and it would arrive beside the
		// message telling the same person the claim applies to nothing until
		// somebody agrees to it.
		if told := r.alerts(t, "triager", "deferral-ending"); len(told) != 0 {
			t.Fatalf("a deferral nobody has agreed to is reported as ending: %v", told)
		}
		if ok := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); ok.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
		}

		told := r.alerts(t, "triager", "deferral-ending")
		if len(told) != 1 {
			t.Fatalf("a deferral ending in four days raised %d notices: %v", len(told), told)
		}
		if !contains(told[0], soon) {
			t.Errorf("the notice does not say when it ends: %q", told[0])
		}

		// Past its date it is not "ending" any more — it has ended, and the
		// finding is back in the queue, which is a different thing to say.
		gone := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
		if _, err := r.db.DB.NewUpdate().Table("claim").
			Set("deferred_until = ?", gone).
			Where("id = ?", claim).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if told := r.alerts(t, "triager", "deferral-ending"); len(told) != 0 {
			t.Errorf("a deferral that has ended is still reported as ending: %v", told)
		}
	})
}

func TestWorkSittingInATeamQueueIsSaidToTheTeam(t *testing.T) {
	// The one that needed saying: a queue is neither owned nor unowned, so
	// it looks handled on every screen and is not.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"Kernel","display_name":"Kernel","members":["triager","reader"]}`,
		); made.Code != http.StatusCreated {
			t.Fatalf("recording a team answered %d: %s", made.Code, made.Body.String())
		}
		if got := asPerson(t, r, "assigner", http.MethodPut,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/components/libnl-3-200/assignment",
			`{"team":"kernel"}`); got.Code != http.StatusNoContent {
			t.Fatalf("routing to the team answered %d: %s", got.Code, got.Body.String())
		}

		// Just arrived is not sitting still.
		if told := r.alerts(t, "triager", "queue-untaken"); len(told) != 0 {
			t.Fatalf("work routed a moment ago is reported as sitting: %v", told)
		}
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("assigned_at = ?", time.Now().UTC().Add(-5*24*time.Hour)).
			Where("assigned_to IS NOT NULL").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		// Everybody on the team hears it, because a queue is addressed to
		// nobody in particular.
		for _, who := range []string{"triager", "reader"} {
			told := r.alerts(t, who, "queue-untaken")
			if len(told) != 1 {
				t.Fatalf("%s was told %d times about the queue: %v", who, len(told), told)
			}
			if !contains(told[0], "Kernel") {
				t.Errorf("the notice does not name the queue: %q", told[0])
			}
		}
		// Somebody not on it is not told: it is not their queue.
		if told := r.alerts(t, "assigner", "queue-untaken"); len(told) != 0 {
			t.Errorf("somebody not on the team was told about its queue: %v", told)
		}

		// A decision is the work being done, and it leaves the queue's
		// backlog whether or not anybody took it first.
		r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if told := r.alerts(t, "triager", "queue-untaken"); len(told) != 0 {
			t.Errorf("work that has been decided is still counted as sitting: %v", told)
		}
	})
}

func TestTheProposerSeesWhatBecameOfEachClaim(t *testing.T) {
	// Approval stays silent, and that only works if the view records
	// outcomes — the queue's own tab lists what is pending, so approved,
	// withdrawn, lapsed and undone all present there as the row
	// disappearing.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		agreed, _ := r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		sent, _ := r.claimed(t, "triager", "CVE-2026-1000", "linux-image", dismissal)

		// Both are waiting until somebody does something.
		for _, one := range r.became(t, "triager") {
			if one.Happened != "waiting" {
				t.Errorf("a claim nobody has answered reads as %q", one.Happened)
			}
			if one.When != "" || one.By != "" {
				t.Errorf("a claim nothing has happened to says when and by whom: %+v", one)
			}
		}

		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", agreed), `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/send-back", sent),
			`{"because":"Name the kconfig option."}`); got.Code != http.StatusNoContent {
			t.Fatalf("sending back answered %d: %s", got.Code, got.Body.String())
		}

		became := map[int64]string{}
		who := map[int64]string{}
		for _, one := range r.became(t, "triager") {
			became[one.Claim.ID] = one.Happened
			who[one.Claim.ID] = one.By
		}
		if became[agreed] != "approved" {
			t.Errorf("an approved claim reads as %q", became[agreed])
		}
		if who[agreed] != "reviewer" {
			t.Errorf("the view does not say who agreed: %q", who[agreed])
		}
		if became[sent] != "sent-back" {
			t.Errorf("a claim sent back reads as %q", became[sent])
		}

		// Somebody else's claims are not on their page.
		if mine := r.became(t, "reviewer"); len(mine) != 0 {
			t.Errorf("somebody who proposed nothing has %d claims of their own", len(mine))
		}
	})
}

func TestAnAgreementTakenBackIsSaidToWhoeverProposedIt(t *testing.T) {
	// One of the two outcomes that still notify: an undo reverses
	// something the proposer was relying on, which nobody expects.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim),
			`{"batch":"tuesday"}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		// Agreement itself says nothing, which is the rule this is the
		// exception to.
		if told := r.told(t, "triager", "approval-undone"); len(told) != 0 {
			t.Fatalf("an approval said something: %v", told)
		}

		if got := asPerson(t, r, "reviewer", http.MethodDelete,
			"/v1/approval-batches/tuesday", ""); got.Code != http.StatusOK {
			t.Fatalf("undoing answered %d: %s", got.Code, got.Body.String())
		}
		told := r.told(t, "triager", "approval-undone")
		if len(told) != 1 {
			t.Fatalf("undoing an agreement told the proposer %d times: %v", len(told), told)
		}
		if !contains(told[0], "taken back") {
			t.Errorf("the notice does not say what happened: %q", told[0])
		}
		// And the view says so too, apart from "waiting": somebody had agreed.
		for _, one := range r.became(t, "triager") {
			if one.Claim.ID == claim && one.Happened != "undone" {
				t.Errorf("a claim whose agreement was undone reads as %q", one.Happened)
			}
		}
	})
}

func TestARecordOfBeingExploitedIsSaidToWhoeverProposedTheDismissal(t *testing.T) {
	// The other cause of the same telling, and the one nobody is expecting: a
	// reviewer undoing their own batch is an exchange the proposer can see,
	// and this is somebody recording an incident somewhere else entirely.
	// Without it the claim simply reappears in their queue with nothing
	// saying why.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scanned(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim),
			`{"batch":"tuesday"}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		if told := r.told(t, "triager", "approval-undone"); len(told) != 0 {
			t.Fatalf("an approval said something: %v", told)
		}

		if got := asPerson(t, r, "private-triage", http.MethodPost,
			"/v1/products/mine/issues/CVE-2026-9999/exploited-here",
			`{"known_at":"2026-09-20T14:00:00Z",`+
				`"grounds":"A customer sent packet captures."}`,
		); got.Code != http.StatusCreated {
			t.Fatalf("recording answered %d: %s", got.Code, got.Body.String())
		}

		told := r.told(t, "triager", "approval-undone")
		if len(told) != 1 {
			t.Fatalf("recording told the proposer %d times: %v", len(told), told)
		}
		// Why, not only that. The proposer was not part of what caused this,
		// so a notice saying an agreement went away sends them looking.
		if !contains(told[0], "exploited") {
			t.Errorf("the notice does not say what caused it: %q", told[0])
		}
	})
}

// told is what somebody has been told, of one kind, without running the sweep.
//
// Apart from alerts because these two are events: they were written when
// somebody acted, and driving the condition pass to read them would say the
// sweep had something to do with it.
func (r *reach) told(t *testing.T, who, kind string) []string {
	t.Helper()
	var waiting struct {
		Items []struct {
			Kind string `json:"kind"`
			Body string `json:"body"`
		} `json:"items"`
	}
	read(t, r, who, "/v1/notifications", &waiting)
	var about []string
	for _, one := range waiting.Items {
		if one.Kind == kind {
			about = append(about, one.Body)
		}
	}
	return about
}

// became is what somebody's own page says happened to what they proposed.
func (r *reach) became(t *testing.T, who string) []becameRow {
	t.Helper()
	var out struct {
		Items []becameRow `json:"items"`
	}
	read(t, r, who, "/v1/my-claims", &out)
	return out.Items
}

type becameRow struct {
	Claim struct {
		ID int64 `json:"id"`
	} `json:"claim"`
	Happened string `json:"happened"`
	When     string `json:"when"`
	By       string `json:"by"`
}

func TestAStandingConditionSaysWhatIsTrueNow(t *testing.T) {
	// A condition's sentence is what it currently says — how many pieces of
	// work are sitting in a queue, how many places a deferral covers. The row
	// was written once and never touched again while the condition stayed
	// true, so it went on saying what was true the first time anybody looked.
	// A queue that grew overnight still reported the count it had when it
	// opened, standing beside the queue it is about.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"platform","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		hand := func(t *testing.T, issue string) {
			t.Helper()
			if got := asPerson(t, r, "assigner", http.MethodPut,
				"/v1/products/mine/streams/master/variants/broadcom"+
					"/findings/"+issue+"/components/linux-image/assignment",
				`{"team":"platform"}`); got.Code != http.StatusNoContent {
				t.Fatalf("handing work to the team answered %d: %s", got.Code, got.Body.String())
			}
		}

		hand(t, "CVE-2026-9999")
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("assigned_at = ?", time.Now().UTC().AddDate(0, 0, -30)).
			Where("assigned_to IS NOT NULL").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		first := r.alerts(t, "triager", "queue-untaken")
		if len(first) != 1 {
			t.Fatalf("work sitting in a queue raised %d notices: %v", len(first), first)
		}

		// A second piece arrives in the same queue and sits just as long.
		hand(t, "CVE-2026-1000")
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("assigned_at = ?", time.Now().UTC().AddDate(0, 0, -30)).
			Where("assigned_to IS NOT NULL").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		second := r.alerts(t, "triager", "queue-untaken")
		if len(second) != 1 {
			t.Fatalf("the queue raised %d notices, want the one: %v", len(second), second)
		}
		if second[0] == first[0] {
			t.Errorf("the notice still says what was true when it opened: %q", second[0])
		}
	})
}
