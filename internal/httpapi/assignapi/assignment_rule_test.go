// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func TestARuleRoutesWorkNobodyHoldsAndTakesNothingFromAnybody(t *testing.T) {
	// A rule places only work nobody holds: a human assignment always
	// wins, and turning a rule on never performs the act the assigner
	// right is named for on behalf of whoever wrote the rule.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}

		// One of the four is already somebody's, and stays theirs.
		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-CURL1/components/libcurl4t64/assignment",
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}

		// A rule naming the source package, which catches both binary
		// packages built from it — the whole point of keying on it.
		made := httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"curl to the curlers","team":"curlers","upstream":"curl"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("adding a rule answered %d: %s", made.Code, made.Body.String())
		}

		if placed := r.Swept(t); placed == 0 {
			t.Fatal("the sweep placed nothing")
		}

		var holding struct {
			Items []struct {
				Person string `json:"person"`
				Team   bool   `json:"team"`
				Open   int    `json:"open"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "assigner", "/v1/assignments", &holding)
		var queued, held int
		for _, one := range holding.Items {
			if one.Team {
				queued = one.Open
			} else {
				held = one.Open
			}
		}
		// Two issues across two packages is four findings; one was already
		// somebody's, so the rule placed the rest and took nothing.
		if held != 1 {
			t.Errorf("the person holds %d after the rule ran, want what they had", held)
		}
		if queued == 0 {
			t.Errorf("the team's queue holds nothing: %+v", holding.Items)
		}

		// And the finding says which rule placed it, which is what
		// makes a placement correctable rather than mysterious.
		var detail struct {
			AssignedTo     string `json:"assigned_to"`
			AssignedByRule string `json:"assigned_by_rule"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/branches-and-tags/master/variants/broadcom"+
			"/findings/CVE-2026-CURL2/components/libcurl3t64", &detail)
		if detail.AssignedByRule != "curl to the curlers" {
			t.Errorf("the finding says %q placed it", detail.AssignedByRule)
		}
		// The one a person took stays a person's, and names no rule.
		var byHand struct {
			AssignedByRule string `json:"assigned_by_rule"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/branches-and-tags/master/variants/broadcom"+
			"/findings/CVE-2026-CURL1/components/libcurl4t64", &byHand)
		if byHand.AssignedByRule != "" {
			t.Errorf("something a person took names the rule %q", byHand.AssignedByRule)
		}

		// A triager may see the rules but not write one: a rule hands work to
		// somebody, which is the act the assigner right names.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"mine","team":"curlers","upstream":"curl"}`), http.StatusForbidden)
		// Somebody who cannot see the product is told it is not there, for
		// the rules as for everything else about it.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "outsider", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"mine","team":"curlers","upstream":"curl"}`), http.StatusNotFound)
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "outsider", http.MethodGet,
			"/v1/products/mine/assignment-rules", ""), http.StatusNotFound)
		// And a rule that matches nothing is refused rather than recorded.
		if empty := httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"nothing","team":"curlers"}`); empty.Code != http.StatusUnprocessableEntity {
			t.Errorf("a rule matching nothing answered %d", empty.Code)
		}
	})
}

func TestRetiringARuleLeavesWhatItPlaced(t *testing.T) {
	// Changing a rule never takes something out of somebody's hands, and
	// that holds for a team's queue as much as for a person.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		// A member who reads the product, so the rule has somewhere to place
		// what it matches.
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["reader"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		made := httpapitest.AsPerson(t, r, "assigner", http.MethodPost, "/v1/products/mine/assignment-rules",
			`{"name":"curl","team":"curlers","upstream":"curl"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("adding answered %d: %s", made.Code, made.Body.String())
		}
		r.Swept(t)

		var rules struct {
			Items []struct {
				ID    int64  `json:"id"`
				Team  string `json:"team"`
				Order int    `json:"order"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "assigner", "/v1/products/mine/assignment-rules", &rules)
		if len(rules.Items) != 1 || rules.Items[0].Order != 1 {
			t.Fatalf("the rules read %+v", rules.Items)
		}

		var before struct {
			Items []struct {
				Open int `json:"open"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "assigner", "/v1/assignments", &before)
		if len(before.Items) != 1 {
			t.Fatalf("after the sweep %d parties hold work", len(before.Items))
		}
		placed := before.Items[0].Open

		if gone := httpapitest.AsPerson(t, r, "assigner", http.MethodDelete,
			"/v1/products/mine/assignment-rules/"+httpapitest.Itoa(rules.Items[0].ID),
			""); gone.Code != http.StatusNoContent {
			t.Fatalf("retiring answered %d: %s", gone.Code, gone.Body.String())
		}
		var after struct {
			Items []struct {
				Open int `json:"open"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "assigner", "/v1/assignments", &after)
		if len(after.Items) != 1 || after.Items[0].Open != placed {
			t.Errorf("retiring a rule took back what it placed: %+v", after.Items)
		}

		// A second click, and an identifier nothing here declared, are both a
		// rule not in use: the caller's to know, not a fault.
		for _, id := range []int64{rules.Items[0].ID, rules.Items[0].ID + 1000} {
			if again := httpapitest.AsPerson(t, r, "assigner", http.MethodDelete,
				"/v1/products/mine/assignment-rules/"+httpapitest.Itoa(id),
				""); again.Code != http.StatusNotFound {
				t.Errorf("retiring rule %d, not in use, answered %d: %s", id, again.Code,
					again.Body.String())
			}
		}
	})
}

// A rule whose team is retired still names the team, and says it is retired,
// so the list read is the list the sweep applies.
func TestARuleWhoseTeamIsRetiredStillNamesItAndSaysSo(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","display_name":"The Curlers"}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		if made := httpapitest.AsPerson(t, r, "assigner", http.MethodPost, "/v1/products/mine/assignment-rules",
			`{"name":"curl","team":"curlers","upstream":"curl"}`); made.Code != http.StatusCreated {
			t.Fatalf("adding answered %d: %s", made.Code, made.Body.String())
		}
		type listed struct {
			Items []struct {
				Team        string `json:"team"`
				TeamName    string `json:"team_name"`
				TeamRetired bool   `json:"team_retired"`
			} `json:"items"`
		}
		var live listed
		httpapitest.Read(t, r, "assigner", "/v1/products/mine/assignment-rules", &live)
		if len(live.Items) != 1 || live.Items[0].Team != "curlers" || live.Items[0].TeamRetired {
			t.Fatalf("before the team is retired the rules read %+v", live.Items)
		}

		if gone := httpapitest.AsPerson(t, r, "admin", http.MethodDelete, "/v1/teams/curlers",
			""); gone.Code >= 300 {
			t.Fatalf("retiring the team answered %d: %s", gone.Code, gone.Body.String())
		}
		var retired listed
		httpapitest.Read(t, r, "assigner", "/v1/products/mine/assignment-rules", &retired)
		if len(retired.Items) != 1 {
			t.Fatalf("after the team is retired the rules read %+v", retired.Items)
		}
		if got := retired.Items[0]; got.Team != "curlers" || got.TeamName != "The Curlers" || !got.TeamRetired {
			t.Errorf("a rule whose team is retired reads %+v, want it named and marked retired", got)
		}
	})
}

func TestARuleSaysWhatItWouldCatchBeforeItIsSaved(t *testing.T) {
	// A rule whose reach nobody can see before saving is a rule that sweeps
	// the estate on a guess, and one naming something nothing is called places
	// nothing — silently, which is the worst way for it to be wrong, because
	// it still looks like a rule.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)

		caught := r.Preview(t, "upstream=curl")
		if caught.Total != 2 || len(caught.Components) != 2 {
			t.Fatalf("the source package catches %d components: %+v", caught.Total, caught)
		}
		// One rule, both binary packages: the whole reason the key is the
		// source package.
		if !strings.Contains(caught.Components[0]+" "+caught.Components[1], "libcurl4t64") {
			t.Errorf("it does not name what it matches: %v", caught.Components)
		}
		if caught.Work == 0 || caught.Unheld != caught.Work {
			t.Errorf("nothing is held yet, so all of it should be unheld: %+v", caught)
		}

		// A name nothing is called catches nothing, and says so.
		if none := r.Preview(t, "upstream=libcurl"); none.Total != 0 || none.Work != 0 {
			t.Errorf("a name nothing is called catches %+v", none)
		}

		// A pattern catches what the exact name cannot: two binary packages
		// with no source package recorded between them would otherwise be two
		// rules.
		starred := r.Preview(t, "beneath=libcurl*")
		if starred.Total != 2 {
			t.Errorf("a pattern over the tree catches %d components: %+v",
				starred.Total, starred.Components)
		}

		// Nothing SQL treats as special leaks through. A pattern with no
		// star is matched exactly, so an underscore is an underscore.
		if literal := r.Preview(t, "beneath=libcurl_t64"); literal.Total != 0 {
			t.Errorf("an underscore matched as a wildcard: %+v", literal.Components)
		}

		// And the count of what nobody holds moves when somebody takes one.
		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-CURL1/components/libcurl4t64/assignment",
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		after := r.Preview(t, "upstream=curl")
		if after.Work != caught.Work || after.Unheld >= caught.Unheld {
			t.Errorf("taking one did not change what a rule may place: %+v then %+v",
				caught, after)
		}
	})
}

func TestASweepDoesNotStopBecauseSomebodyTookOneRow(t *testing.T) {
	// The batch is bounded on what it reads and the write re-checks the
	// holder, so one assignment made by a person inside the window leaves a
	// row of the batch already somebody's. A batch that writes fewer rows
	// than it read is not the end of the sweep; read as the end, it would stop
	// the sweep one human action in, with the rest of the estate unrouted and
	// the job reported successful.
	//
	// A batch of two against four matching findings, one of them held: the
	// first batch reads two and writes one, and the sweep goes on.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "assigner", http.MethodPut,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-CURL1/components/libcurl4t64/assignment",
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		if made := httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"curl to the curlers","team":"curlers","upstream":"curl"}`,
		); made.Code != http.StatusCreated {
			t.Fatalf("adding a rule answered %d: %s", made.Code, made.Body.String())
		}

		work := queue.New(r.DB, queue.DefaultOptions())
		if _, _, err := setting.NewStore(r.DB.DB).Change(t.Context(), setting.AssignmentBatch, "2"); err != nil {
			t.Fatal(err)
		}
		sweeper := finding.NewSweeper(r.DB, work,
			slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
		for range 20 {
			_, placed, err := sweeper.Once(t.Context())
			if err != nil {
				t.Fatalf("sweeping: %v", err)
			}
			if placed == 0 {
				break
			}
		}

		var left int
		if err := r.DB.DB.NewSelect().Table("finding").
			ColumnExpr("COUNT(*)").
			Where(`"assigned_to" IS NULL`).
			Where(`"closed_at" IS NULL`).
			Where(`"component_id" IN (SELECT "id" FROM "component" WHERE "upstream_name" = ?)`, "curl").
			Scan(t.Context(), &left); err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Errorf("%d findings the rule matches are still unrouted after the "+
				"sweep ran to the end", left)
		}
	})
}

// A full batch whose continuation cannot be queued is not a sweep that
// finished. Settled as done, the rest of the product stays unrouted until
// somebody saves another rule, and nothing says so.
func TestASweepThatCannotQueueTheRestIsNotReportedFinished(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.ScannedSiblings(t)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		if made := httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"curl to the curlers","team":"curlers","upstream":"curl"}`,
		); made.Code != http.StatusCreated {
			t.Fatalf("adding a rule answered %d: %s", made.Code, made.Body.String())
		}

		work := queue.New(r.DB, queue.DefaultOptions())
		// The rule's own sweep is waiting, and another beside it. With room
		// for one waiting assignment sweep, claiming the first leaves the second
		// filling the queue, so the rest of the first cannot be queued.
		if _, err := work.Add(ctx, queue.AssignmentSweep, "another product"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := setting.NewStore(r.DB.DB).Change(ctx, setting.QueueBacklog, "1"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := setting.NewStore(r.DB.DB).Change(t.Context(), setting.AssignmentBatch, "1"); err != nil {
			t.Fatal(err)
		}
		sweeper := finding.NewSweeper(r.DB, work,
			slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
		if _, _, err := sweeper.Once(ctx); err == nil {
			t.Fatal("a full batch whose continuation could not be queued reported success")
		}
		done, err := r.DB.DB.NewSelect().Table("job").
			Where(`"kind" = ?`, queue.AssignmentSweep).Where(`"state" = ?`, queue.Done).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if done != 0 {
			t.Error("the sweep was settled as done with the rest of the product unrouted")
		}
	})
}

// A rule and the sweep that applies it to what is open commit together. A
// rule recorded without its sweep leaves every open finding it covers unrouted
// until another rule is saved, so a full queue refuses the rule.
func TestARuleWhoseSweepCannotBeQueuedIsNotRecorded(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		if _, err := queue.New(r.DB, queue.DefaultOptions()).Add(ctx, queue.AssignmentSweep,
			"another product"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := setting.NewStore(r.DB.DB).Change(ctx, setting.QueueBacklog, "1"); err != nil {
			t.Fatal(err)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"curl to the curlers","team":"curlers","upstream":"curl"}`),
			http.StatusServiceUnavailable)
		rules, err := r.DB.DB.NewSelect().Table("assignment_rule").Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if rules != 0 {
			t.Error("a rule whose sweep could not be queued was recorded")
		}
	})
}

func TestMarkingAndAssigningResolveANameTheBuildHoldsTwice(t *testing.T) {
	// Marking and assigning carry no version to choose with, and the build
	// ships the name at two versions. Each is narrowed to the versions
	// carrying the issue first, exactly as the finding's own route is, since
	// most versions of a name carry nothing: the finding the caller just read
	// under the bare name is the one they mark and assign.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		r.ShipsTwice(t)

		at := "/v1/products/mine/branches-and-tags/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200"

		// The finding is readable under the bare name.
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodGet, at, ""); got.Code != http.StatusOK {
			t.Fatalf("reading the finding answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPut,
			at+"/labels/waiting-on-vendor", ""); got.Code >= 300 {
			t.Errorf("marking a finding the same name resolves to answered %d: %s",
				got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPut,
			at+"/assignment", `{"person":"triager"}`); got.Code >= 300 {
			t.Errorf("assigning a finding the same name resolves to answered %d: %s",
				got.Code, got.Body.String())
		}
	})
}

func TestTheSweeperWorksAWholeBacklogInOneWakeAndReturnsWhenCancelled(t *testing.T) {
	// Sweeper.Run is what cmd/openpsirt starts and what places work by rule.
	// The other tests here drive Once, one of them in a loop of twenty that
	// stands in for the loop being tested — and what only the loop does is
	// keep going while there is work, reset the timer and return on
	// cancellation. Once is correct whether or not any of the three is.
	//
	// The batch is two and there are more than two findings to place, so a
	// loop taking one batch per wake would leave some behind: the interval is
	// longer than this test runs for, and a second wake cannot be what
	// finishes it.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		if made := httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules",
			`{"name":"everything to the curlers","team":"curlers","upstream":"curl"}`,
		); made.Code != http.StatusCreated {
			t.Fatalf("adding a rule answered %d: %s", made.Code, made.Body.String())
		}

		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		work := queue.New(r.DB, queue.DefaultOptions())
		if _, _, err := setting.NewStore(r.DB.DB).Change(t.Context(), setting.AssignmentBatch, "2"); err != nil {
			t.Fatal(err)
		}
		sweeper := finding.NewSweeper(r.DB, work,
			slog.New(slog.NewTextHandler(io.Discard, nil)), "test")

		returned := make(chan struct{})
		go func() {
			defer close(returned)
			sweeper.Run(ctx, time.Hour)
		}()

		unplaced := func() int {
			var left int
			if err := r.DB.DB.NewSelect().Table("finding").
				ColumnExpr("COUNT(*)").
				Where(`"assigned_to" IS NULL`).
				Where(`"closed_at" IS NULL`).
				Where(`"component_id" IN (SELECT "id" FROM "component" WHERE "upstream_name" = ?)`, "curl").
				Scan(ctx, &left); err != nil {
				return -1
			}
			return left
		}
		waitFor(t, func() bool { return unplaced() == 0 }, "the whole backlog to be placed")

		stop()
		select {
		case <-returned:
		case <-time.After(10 * time.Second):
			t.Fatal("the loop did not return when its context ended")
		}
	})
}

// waitFor polls until done reports true, and fails saying what it was waiting
// for. A deadline rather than a sleep: the loops under test are driven by a
// timer, so how long the work takes is not something a test can name.
func waitFor(t *testing.T, done func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waited for %s and it did not happen", what)
}

// Somebody who triages only security testing work reads and previews the assignment rules,
// because a rule places code findings. Reading security testing work without triaging it is
// refused both.
func TestSomebodyWhoTriagesCodeFindingsAloneReadsAndPreviewsTheAssignmentRules(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		httpapitest.SeededCodeFinding(t, r)
		const at = "/v1/products/mine/assignment-rules"
		for who, want := range map[string]int{"security-testing-triager": http.StatusOK, "security-testing-reader": http.StatusForbidden} {
			for _, path := range []string{at, at + "/preview?beneath=mine"} {
				if got := httpapitest.AsPerson(t, r, who, http.MethodGet, path, ""); got.Code != want {
					t.Errorf("%s reading %s answered %d; want %d: %s", who, path, got.Code, want, got.Body)
				}
			}
		}
	})
}

// refusedSaying fails unless the answer is the status given and its body says
// the words given, so a refusal is told apart from another sharing its status.
func refusedSaying(t *testing.T, got *httptest.ResponseRecorder, status int, says string) {
	t.Helper()
	httpapitest.RefusedWith(t, got, status)
	if !strings.Contains(got.Body.String(), says) {
		t.Errorf("refused without saying %q: %s", says, got.Body.String())
	}
}

// A rule placing reports names no key, previews the reports nobody holds as
// the reader may read them, and places a report recorded before it on the
// next sweep.
func TestARulePlacingReportsPlacesTheReportsNobodyHolds(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		reference := r.Reported(t, "The management socket answers before anyone has authenticated.")
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"intake","members":["private-triage"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}

		before := r.PreviewAs(t, "private-dispatcher", "reports=true")
		if before.Work != 1 || before.Unheld != 1 || before.Total != 0 || len(before.Components) != 0 {
			t.Errorf("a rule placing reports would catch %+v, want the one report nobody holds", before)
		}
		if hidden := r.PreviewAs(t, "triager", "reports=true"); hidden.Work != 0 || hidden.Unheld != 0 {
			t.Errorf("somebody who reads no reports is shown %+v", hidden)
		}

		const preview = "/v1/products/mine/assignment-rules/preview"
		const keyed = "a rule placing reports names no package"
		for _, query := range []string{"?reports=true&upstream=curl", "?reports=true&beneath=libcurl4t64"} {
			refusedSaying(t, httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodGet,
				preview+query, ""), http.StatusUnprocessableEntity, keyed)
		}
		refusedSaying(t, httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodGet, preview, ""),
			http.StatusUnprocessableEntity, "a rule that matches nothing places nothing")

		const rules = "/v1/products/mine/assignment-rules"
		refusedSaying(t, httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, rules,
			`{"name":"reports","team":"intake","reports":true,"upstream":"curl"}`),
			http.StatusUnprocessableEntity, keyed)
		if made := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPost, rules,
			`{"name":"reports","team":"intake","reports":true}`); made.Code != http.StatusCreated {
			t.Fatalf("adding a rule placing reports answered %d: %s", made.Code, made.Body)
		}

		if placed := r.Swept(t); placed != 1 {
			t.Errorf("the sweep placed %d, want the one report", placed)
		}
		var queued heldReports
		httpapitest.Read(t, r, "private-triage", "/v1/teams/intake/assignments/reports", &queued)
		if queued.Total != 1 || len(queued.Items) != 1 || queued.Items[0].Reference != reference {
			t.Errorf("the team's queue reads as %+v, want report %s", queued, reference)
		}
		if after := r.PreviewAs(t, "private-dispatcher", "reports=true"); after.Work != 1 || after.Unheld != 0 {
			t.Errorf("after the sweep a rule placing reports would catch %+v, want it held", after)
		}
	})
}

// A pattern naming more places in one build than a rule may reach is refused
// by the preview and by adding the rule, in the same words.
func TestAPatternNamingMostOfABuildIsRefusedByThePreviewAndTheRule(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		padding := make([]graph.Described, 0, finding.AssignmentRuleReach+1)
		edges := make([]graph.Dependency, 0, cap(padding))
		for i := range cap(padding) {
			name := fmt.Sprintf("pad%04d", i)
			one := graph.Described{Purl: "pkg:deb/debian/" + name + "@1.0", Name: name, Version: "1.0"}
			padding = append(padding, one)
			edges = append(edges, graph.Dependency{Parent: httpapitest.SeededRoot, Child: one})
		}
		r.ScanAt(t, httpapitest.SeededBuild, "padded", graph.Snapshot{
			Root: httpapitest.SeededRoot, Components: padding, Dependencies: edges,
		}, nil)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"padders","members":["assigner"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}

		refusedSaying(t, httpapitest.AsPerson(t, r, "assigner", http.MethodGet,
			"/v1/products/mine/assignment-rules/preview?beneath=pad*", ""),
			http.StatusUnprocessableEntity, finding.ErrTooBroad.Error())
		refusedSaying(t, httpapitest.AsPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules", `{"name":"pads","team":"padders","beneath":"pad*"}`),
			http.StatusUnprocessableEntity, finding.ErrTooBroad.Error())
		// Half of them is within the reach, and answered.
		if narrower := httpapitest.AsPerson(t, r, "assigner", http.MethodGet,
			"/v1/products/mine/assignment-rules/preview?beneath=pad1*", ""); narrower.Code != http.StatusOK {
			t.Errorf("a pattern within the reach answered %d: %s", narrower.Code, narrower.Body)
		}
	})
}
