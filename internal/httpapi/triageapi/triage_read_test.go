// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestEverythingWrittenAboutADecisionCanBeReadBack(t *testing.T) {
	// A tool that lets somebody argue, agree and annotate and then offers no
	// way to read the result sends every reader to the review queue — which by
	// definition no longer holds what was agreed to.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		id, claim := r.DecidedAt(t, place)

		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/comments", claim),
			`{"body":"Re-checked against 3.7.0; still true."}`); got.Code != http.StatusCreated {
			t.Fatalf("commenting answered %d: %s", got.Code, got.Body.String())
		}
		r.Agreed(t, claim)

		// The decision itself, saying what it is about rather than by number.
		var detail struct {
			Decision struct {
				Outcome string `json:"outcome"`
				State   string `json:"state"`
			} `json:"decision"`
			Place struct {
				Product       string `json:"product"`
				ProductName   string `json:"product_name"`
				Vulnerability string `json:"vulnerability"`
				Place         string `json:"place"`
			} `json:"place"`
			Reasoning  string `json:"reasoning"`
			ProposedBy string `json:"proposed_by"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", id), &detail)
		if detail.Decision.State != "approved" {
			t.Errorf("the decision reads as %q after being approved", detail.Decision.State)
		}
		// The name that addresses the product, with the label beside it.
		if detail.Place.Product != "mine" || detail.Place.ProductName != httpapitest.ShownAs("mine") ||
			detail.Place.Vulnerability != "CVE-2026-9999" {
			t.Errorf("the decision does not say what it is about: %+v", detail.Place)
		}
		if detail.Reasoning == "" {
			t.Error("the decision came back with no reasoning to read")
		}
		if detail.ProposedBy != "triager" {
			t.Errorf("proposed by %q, want the person who made the claim", detail.ProposedBy)
		}

		// The reasoning, the agreement, and the discussion, each on its own.
		var revisions struct {
			Items []struct {
				ID        int64  `json:"id"`
				Body      string `json:"body"`
				WrittenBy string `json:"written_by"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/revisions", claim), &revisions)
		if len(revisions.Items) != 1 || revisions.Items[0].WrittenBy != "triager" {
			t.Errorf("the reasoning history reads as %+v", revisions.Items)
		}

		var approvals struct {
			Items []struct {
				RevisionID int64  `json:"revision_id"`
				ApprovedBy string `json:"approved_by"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/approvals", claim), &approvals)
		if len(approvals.Items) != 1 || approvals.Items[0].ApprovedBy != "reviewer" {
			t.Fatalf("who agreed reads as %+v", approvals.Items)
		}
		// The agreement names the words that were agreed to, which is the
		// whole point of keeping revisions.
		if approvals.Items[0].RevisionID != revisions.Items[0].ID {
			t.Error("the approval does not name a revision anybody can read")
		}

		var comments struct {
			Items []struct {
				Body      string `json:"body"`
				WrittenBy string `json:"written_by"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/comments", claim), &comments)
		if len(comments.Items) != 1 || comments.Items[0].WrittenBy != "triager" {
			t.Errorf("the discussion reads as %+v", comments.Items)
		}
	})
}

func TestWhatWasDismissedCanBeListed(t *testing.T) {
	// The question somebody auditing asks: what have we decided not to fix,
	// and on what grounds. Without it the only list of decisions is the review
	// queue, which holds exactly the ones nobody has agreed to yet.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		_, claim := r.DecidedAt(t, place)

		var listed struct {
			Items []struct {
				Decision struct {
					Outcome string `json:"outcome"`
				} `json:"decision"`
				Reasoning string `json:"reasoning"`
			} `json:"items"`
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "triager", "/v1/decisions?outcome=not-applicable", &listed)
		if listed.Total != 1 || len(listed.Items) != 1 {
			t.Fatalf("%d dismissals listed, want 1", listed.Total)
		}
		if listed.Items[0].Reasoning == "" {
			t.Error("a dismissal listed without the reason it was dismissed for")
		}

		// A filter that matches nothing says so rather than falling back to
		// everything, which is how a filtered list becomes dangerous.
		var none struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "triager", "/v1/decisions?outcome=wont-fix", &none)
		if none.Total != 0 {
			t.Errorf("filtering by an outcome nothing has returned %d", none.Total)
		}

		// The state filter separates what waits from what is agreed.
		var waiting, agreed struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "triager", "/v1/decisions?state=proposed", &waiting)
		httpapitest.Read(t, r, "triager", "/v1/decisions?state=approved", &agreed)
		if waiting.Total != 1 || agreed.Total != 0 {
			t.Errorf("before agreement %d wait and %d are agreed, want 1 and 0",
				waiting.Total, agreed.Total)
		}
		r.Agreed(t, claim)
		waiting.Total, agreed.Total = 0, 0
		httpapitest.Read(t, r, "triager", "/v1/decisions?state=proposed", &waiting)
		httpapitest.Read(t, r, "triager", "/v1/decisions?state=approved", &agreed)
		if waiting.Total != 0 || agreed.Total != 1 {
			t.Errorf("after agreement %d wait and %d are agreed, want 0 and 1",
				waiting.Total, agreed.Total)
		}
	})
}

func TestAClaimReadsWholeRatherThanThroughARow(t *testing.T) {
	// A claim is one argument however many rows it wrote, and the page people
	// act on is the claim. Read through a representative row, its state stood
	// in for the claim's — which is how one row approved beside forty-three
	// sent back read as approved.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		_, claim := r.DecidedAt(t, place)

		var whole struct {
			Claim struct {
				ID         int64  `json:"id"`
				Kind       string `json:"kind"`
				ProposedBy string `json:"proposed_by"`
			} `json:"claim"`
			Argument struct {
				ID            int64  `json:"id"`
				ClaimID       int64  `json:"claim_id"`
				Outcome       string `json:"outcome"`
				Justification string `json:"justification"`
				Reasoning     string `json:"reasoning"`
				State         string `json:"state"`
			} `json:"argument"`
			Place struct {
				Product       string `json:"product"`
				Vulnerability string `json:"vulnerability"`
			} `json:"place"`
			Happened           string   `json:"happened"`
			By                 string   `json:"by"`
			PreviouslyApproved bool     `json:"previously_approved"`
			Rows               int      `json:"rows"`
			Issues             int      `json:"issues"`
			Places             int      `json:"places"`
			Folds              int      `json:"folds"`
			Packages           int      `json:"packages"`
			Consumers          int      `json:"consumers"`
			Findings           int      `json:"findings"`
			Builds             []string `json:"builds"`
			Ended              []struct {
				State  string   `json:"state"`
				At     string   `json:"at"`
				Places int      `json:"places"`
				Builds []string `json:"builds"`
			} `json:"ended"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/claims/%d", claim), &whole)

		if whole.Claim.ID != claim || whole.Claim.Kind != "finding" {
			t.Errorf("the claim reads as %+v", whole.Claim)
		}
		if whole.Claim.ProposedBy != "triager" {
			t.Errorf("proposed by %q, want the person who made the claim", whole.Claim.ProposedBy)
		}
		if whole.Argument.Outcome != "not-applicable" ||
			whole.Argument.Justification != "vulnerable_code_not_in_execute_path" {
			t.Errorf("what the claim says reads as %+v", whole.Argument)
		}
		// The argument is the claim's, so it names no row and carries no row
		// state. Anything acting on one of those would be acting at the wrong
		// grain, and the claim page is where every act lives.
		if whole.Argument.ID != 0 || whole.Argument.State != "" {
			t.Errorf("the argument carries a row: %+v", whole.Argument)
		}
		if whole.Argument.ClaimID != claim {
			t.Errorf("the argument belongs to claim %d, want %d", whole.Argument.ClaimID, claim)
		}
		if whole.Place.Vulnerability != "CVE-2026-9999" || whole.Place.Product != "mine" {
			t.Errorf("the claim does not say what it is about: %+v", whole.Place)
		}
		if whole.Argument.Reasoning == "" {
			t.Error("the claim came back with no reasoning to read")
		}
		if whole.Happened != "waiting" || whole.By != "" {
			t.Errorf("a claim nobody has answered reads as %q by %q", whole.Happened, whole.By)
		}
		if whole.Rows != 1 || whole.Issues != 1 || whole.Places != 1 {
			t.Errorf("what the claim wrote reads as %d rows, %d issues, %d places",
				whole.Rows, whole.Issues, whole.Places)
		}
		// Its present reach, in the units somebody acts in. One judgment at
		// one fold, over the one package that fold holds here, under whatever
		// pulls it in — never a place count, which is a unit nobody acted in.
		if whole.Folds != 1 || whole.Packages != 1 || whole.Consumers != 1 ||
			whole.Findings != 1 {
			t.Errorf("what it covers reads as %d folds, %d packages, %d consumers, "+
				"%d findings", whole.Folds, whole.Packages, whole.Consumers, whole.Findings)
		}
		if len(whole.Builds) != 1 {
			t.Errorf("the builds it covers read as %v", whole.Builds)
		}

		// Agreed to, and the claim says so as a whole with who did it.
		r.Agreed(t, claim)
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/claims/%d", claim), &whole)
		if whole.Happened != "approved" || whole.By != "reviewer" {
			t.Errorf("an agreed claim reads as %q by %q", whole.Happened, whole.By)
		}
		// "Agreed to before and came back" is about a claim waiting again. A
		// claim standing on an agreement has an approval on record, and
		// reading that as having come back tells whoever opens it that they
		// are re-reading something nobody has answered.
		if whole.PreviouslyApproved {
			t.Error("a claim that was just agreed to reads as having come back")
		}
		if len(whole.Ended) != 0 {
			t.Errorf("a standing claim reports ended parts %+v", whole.Ended)
		}

		// Withdrawn, it reaches nothing now, and what it reached when it was
		// withdrawn is reported apart.
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodDelete,
			fmt.Sprintf("/v1/claims/%d", claim), ""); got.Code >= 300 {
			t.Fatalf("withdrawing answered %d: %s", got.Code, got.Body.String())
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/claims/%d", claim), &whole)
		if whole.Findings != 0 || len(whole.Builds) != 0 {
			t.Errorf("a withdrawn claim reaches %d findings in %v now", whole.Findings, whole.Builds)
		}
		if len(whole.Ended) != 1 || whole.Ended[0].State != "withdrawn" ||
			whole.Ended[0].Places != 1 || len(whole.Ended[0].Builds) != 1 || whole.Ended[0].At == "" {
			t.Errorf("what it reached when withdrawn reads as %+v", whole.Ended)
		}
	})
}

func TestTheRecordIsReadableAtTheFindingsVisibility(t *testing.T) {
	// Reading what was decided asked whether the reader may decide or
	// approve, which is narrower than disclosure opening the record: the
	// whole record — comments, decisions, actors — goes public when a
	// private issue is disclosed, and under the old rule that was true
	// only for people who could already see it. A reader saw "deferred"
	// with no way to see why or by whom.
	//
	// Every read is still narrowed. A decision on a product somebody may
	// not read answers as one that is not there, so guessing identifiers
	// says nothing, and acting on it is unchanged.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		id, claim := r.DecidedAt(t, place)

		// Holding the approver capability and nothing to read it against
		// reaches nothing, which is what makes a capability a capability.
		if got := httpapitest.AsPerson(t, r, "approver", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim), `{}`); got.Code != http.StatusNotFound {
			t.Errorf("an approver with no visibility approved: %d", got.Code)
		}
		for _, path := range []string{
			fmt.Sprintf("/v1/decisions/%d", id),
			fmt.Sprintf("/v1/claims/%d", claim),
			fmt.Sprintf("/v1/claims/%d/revisions", claim),
			fmt.Sprintf("/v1/claims/%d/approvals", claim),
			fmt.Sprintf("/v1/claims/%d/comments", claim),
		} {
			if got := httpapitest.AsPerson(t, r, "approver", http.MethodGet, path, ""); got.Code != http.StatusNotFound {
				t.Errorf("%s answered %d to somebody who reads nothing, want 404", path, got.Code)
			}
		}

		// Somebody who may read the finding reads its record, all four parts
		// of it, though they may argue about none of it.
		for _, path := range []string{
			fmt.Sprintf("/v1/decisions/%d", id),
			fmt.Sprintf("/v1/claims/%d", claim),
			fmt.Sprintf("/v1/claims/%d/revisions", claim),
			fmt.Sprintf("/v1/claims/%d/approvals", claim),
			fmt.Sprintf("/v1/claims/%d/comments", claim),
		} {
			got := httpapitest.AsPerson(t, r, "reader", http.MethodGet, path, "")
			if got.Code != http.StatusOK {
				t.Errorf("%s answered %d to somebody who may read the finding, want 200",
					path, got.Code)
			}
		}

		// And the list answers for them, rather than reporting that nothing
		// was ever decided.
		var listed struct {
			Total int `json:"total"`
		}
		httpapitest.Read(t, r, "reader", "/v1/decisions", &listed)
		if listed.Total == 0 {
			t.Error("a reader was told no decisions exist")
		}

		// Reading is not acting. Arguing still asks for triage, and the
		// refusal says nothing about whether the decision is there.
		// The decision's own sentence, so a route that moved and answers 404
		// for itself does not pass for the refusal.
		wrote := httpapitest.AsPerson(t, r, "reader", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/comments", claim),
			`{"body":"a reader should not be able to write this"}`)
		httpapitest.RefusedWith(t, wrote, http.StatusNotFound)
		if !strings.Contains(wrote.Body.String(), "no decision is recorded there") {
			t.Errorf("a reader writing on a decision was refused in other words: %s",
				wrote.Body.String())
		}

		// The finding's visibility is the whole of the rule, so an undisclosed
		// one closes the record again to somebody who reads only what has been
		// disclosed. This is the half a widening written as "anybody on the
		// product" leaks.
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set(`"visibility" = ?`, "private").
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.DB.DB.NewUpdate().Table("decision").
			Set(`"visibility" = ?`, "private").
			Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{
			fmt.Sprintf("/v1/decisions/%d", id),
			fmt.Sprintf("/v1/claims/%d", claim),
			fmt.Sprintf("/v1/claims/%d/revisions", claim),
			fmt.Sprintf("/v1/claims/%d/approvals", claim),
			fmt.Sprintf("/v1/claims/%d/comments", claim),
		} {
			if got := httpapitest.AsPerson(t, r, "reader", http.MethodGet, path, ""); got.Code != http.StatusNotFound {
				t.Errorf("%s answered %d on an undisclosed finding to somebody who reads "+
					"only disclosed ones, want 404", path, got.Code)
			}
		}
		httpapitest.Read(t, r, "reader", "/v1/decisions", &listed)
		if listed.Total != 0 {
			t.Errorf("a public reader was told %d undisclosed decisions exist", listed.Total)
		}
		// And somebody who reads undisclosed work still reads it.
		if got := httpapitest.AsPerson(t, r, "private", http.MethodGet,
			fmt.Sprintf("/v1/decisions/%d", id), ""); got.Code != http.StatusOK {
			t.Errorf("a private reader was refused an undisclosed decision: %d", got.Code)
		}
	})
}

func TestWhatAppliesToAFindingIsReadableWithItsHistory(t *testing.T) {
	// Somebody deciding needs to know what was decided here before. Making
	// them start from a blank page, having thrown away what was written last
	// time, is how a tool teaches people to stop writing reasoning at all.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		_, claim := r.DecidedAt(t, place)
		path := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/%s/decision", place)

		var before struct {
			Standing   *struct{} `json:"standing"`
			Previously []struct {
				Decision struct {
					State string `json:"state"`
				} `json:"decision"`
			} `json:"previously"`
		}
		httpapitest.Read(t, r, "triager", path, &before)
		// Nobody has agreed to it yet, so it suppresses nothing — but it is
		// there to be read.
		if before.Standing != nil {
			t.Error("a claim nobody agreed to reads as standing")
		}
		if len(before.Previously) != 1 {
			t.Fatalf("the history reads as %+v", before.Previously)
		}

		r.Agreed(t, claim)

		var after struct {
			Standing *struct {
				Decision struct {
					Outcome string `json:"outcome"`
					State   string `json:"state"`
				} `json:"decision"`
				Reasoning string `json:"reasoning"`
			} `json:"standing"`
			Previously []struct{} `json:"previously"`
		}
		httpapitest.Read(t, r, "triager", path, &after)
		if after.Standing == nil {
			t.Fatal("an agreed decision does not read as standing where it was made")
		}
		// The one claim now stands, so nothing was decided here before it.
		if len(after.Previously) != 0 {
			t.Errorf("the standing decision is listed again under previously: %d rows",
				len(after.Previously))
		}
		if after.Standing.Decision.Outcome != "not-applicable" || after.Standing.Reasoning == "" {
			t.Errorf("what stands here reads as %+v", after.Standing)
		}
	})
}

func TestTheAPIReturnsMarkdownAndNeverMarkup(t *testing.T) {
	// One representation, to every consumer. HTML assumes a browser, and in an
	// API-first tool most callers are not one — the adapters already on the
	// books want neither HTML nor markdown, and markdown is the form an
	// integrating application can most easily lay out and re-render.
	//
	// Our own interface renders in the browser, so it needs no server-rendered
	// half either, and a second renderer is the thing that eventually
	// disagrees with the first.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		id, _ := r.DecidedAt(t, place)

		var body map[string]any
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", id), &body)
		if body["reasoning"] == "" || body["reasoning"] == nil {
			t.Error("the answer carries no text at all")
		}
		for key := range body {
			if strings.HasSuffix(key, "_html") {
				t.Errorf("the answer carries a rendered field %q", key)
			}
		}

		// And there is no way to ask for markup: a request for it names a
		// parameter no operation takes, and is refused as that.
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			fmt.Sprintf("/v1/decisions/%d?html=true", id), ""), http.StatusBadRequest)
	})
}

func TestStoredTextComesBackExactlyAsWritten(t *testing.T) {
	// The counterpart to rendering in the browser: the server hands back the
	// source it holds, unaltered, so whatever renders it is rendering the
	// authoritative form rather than something already transformed.
	//
	// Sanitizing is the renderer's job and is tested where the renderer lives
	// (internal/markdown). What matters here is that nothing between the row
	// and the reader quietly rewrites the text — a reader that trusted a
	// half-cleaned string would be trusting the wrong control.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		id, _ := r.DecidedAt(t, place)

		// Straight into the row, the way text stored under an older rule would
		// already be sitting there.
		hostile := "Fine, then <img src=x onerror=alert(1)> and " +
			"[a link](javascript:alert(2))."
		if _, err := r.DB.DB.NewUpdate().
			Table("claim_revision").
			Set(`"body" = ?`, hostile).
			Where(`"claim_id" = (SELECT "claim_id" FROM "decision" WHERE "id" = ?)`, id).
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		var body struct {
			Reasoning string `json:"reasoning"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", id), &body)
		if body.Reasoning != hostile {
			t.Errorf("the source came back altered:\n got %q\nwant %q", body.Reasoning, hostile)
		}
	})
}

func TestAFindingCarriesEverythingNeededToActOnIt(t *testing.T) {
	// The measure this is built against: nothing here should send somebody to
	// a search engine. There may be thousands of findings and very few people,
	// so a finding that carries its own evidence and one that does not are the
	// difference between a queue that gets worked and one that does not.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)

		var detail struct {
			Vulnerability string  `json:"vulnerability"`
			Severity      string  `json:"severity"`
			Score         float64 `json:"score"`
			Vector        string  `json:"vector"`
			Exploited     bool    `json:"exploited"`
			Likelihood    float64 `json:"likelihood"`
			Weaknesses    []struct {
				ID    string `json:"id"`
				Name  string `json:"name"`
				Short string `json:"short"`
			} `json:"weaknesses"`
			Description string `json:"description"`
			Advisory    string `json:"advisory"`
			References  []struct {
				URL  string `json:"url"`
				Kind string `json:"kind"`
			} `json:"references"`
			Component string `json:"component"`
			FixState  string `json:"fix_state"`
			FixedIn   string `json:"fixed_in"`
			Places    []struct {
				Place    string `json:"place"`
				Consumer string `json:"consumer"`
			} `json:"places"`
		}
		httpapitest.Read(t, r, "reader", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &detail)

		for what, got := range map[string]string{
			"the issue":     detail.Vulnerability,
			"the component": detail.Component,
			"the write-up":  detail.Description,
			"the advisory":  detail.Advisory,
			"the vector":    detail.Vector,
			"the fix state": detail.FixState,
			"the fix":       detail.FixedIn,
		} {
			if got == "" {
				t.Errorf("%s is missing, so somebody has to go and look it up", what)
			}
		}
		if detail.Score == 0 || detail.Likelihood == 0 || !detail.Exploited {
			t.Errorf("what makes this urgent is missing: score=%v likelihood=%v exploited=%v",
				detail.Score, detail.Likelihood, detail.Exploited)
		}
		if len(detail.Weaknesses) == 0 {
			t.Error("what kind of flaw this is was not kept")
		} else if w := detail.Weaknesses[0]; w.ID != "CWE-125" || w.Name != "Out-of-bounds Read" ||
			w.Short != "Out-of-bounds read" {
			// Named in both lists, so nobody leaves to read what the number is.
			t.Errorf("the kind of flaw came back as %+v", w)
		}
		if len(detail.Places) == 0 || detail.Places[0].Place == "" {
			t.Fatalf("the answer does not say where it sits: %+v", detail.Places)
		}

		// The patch comes first. Somebody deciding whether to backport rather
		// than upgrade needs the change itself, and hunting for it among the
		// write-ups is the step that does not happen with a thousand waiting.
		if len(detail.References) < 2 {
			t.Fatalf("the references were not kept: %+v", detail.References)
		}
		if detail.References[0].Kind != "patch" {
			t.Errorf("the first reference is %q, not the change that fixes it",
				detail.References[0].Kind)
		}
	})
}

func TestABulkClaimCoversWhatTheClaimantCanSeeAndNoMore(t *testing.T) {
	// A public triager's judgment covers the places they can read. The
	// undisclosed ones stay open for whoever can read them — which is the
	// ordinary division of work, not a gap. Refusing the whole action because
	// something undisclosed sits at the same component would answer somebody
	// who picked from the list they were shown with a bare "not found".
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)

		// A second place for the same issue, so the component holds one the
		// public triager may read and one they may not.
		var rows []finding.Finding
		if err := r.DB.DB.NewSelect().Model(&rows).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("the fixture has %d findings, want 1", len(rows))
		}
		second := rows[0]
		second.ID = 0
		// A different identity of the same width. A place identity is a hash
		// stored in a fixed-width column, so appending to one overflows on
		// three of the four engines and is silently accepted on the fourth.
		second.PlaceIdentity = second.PlaceIdentity[:len(second.PlaceIdentity)-4] + "beef"
		if _, err := r.DB.DB.NewInsert().Model(&second).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set(`"visibility" = ?`, "private").
			Where(`"id" = ?`, rows[0].ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/libnl-3-200/decisions"
		body := `{"vulnerabilities":["CVE-2026-9999"],"outcome":"wont-fix",` +
			`"selected_by":"everything at this component","reasoning":"Not worth the churn."}`

		// One of the two places is theirs to argue about, and that is what the
		// claim covers.
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at, body)
		if got.Code != http.StatusCreated {
			t.Fatalf("a public triager answered %d: %s", got.Code, got.Body.String())
		}
		var recorded struct {
			Recorded int `json:"recorded"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &recorded); err != nil {
			t.Fatal(err)
		}
		if recorded.Recorded != 1 {
			t.Errorf("a public triager covered %d places, want only the disclosed one",
				recorded.Recorded)
		}

		// And the undisclosed one is still open, waiting for somebody who can
		// see it.
		standing, err := r.DB.DB.NewSelect().Table("decision").
			Where(`"place_identity" = ?`, rows[0].PlaceIdentity).
			Where(`"live_key" IS NOT NULL`).Count(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if standing != 0 {
			t.Errorf("%d claims stand against a place the claimant cannot read", standing)
		}
	})
}

func TestAPlaceNamesTheClaimStandingOnIt(t *testing.T) {
	// A claim shown on a finding says how many places it covers. That is how
	// big the judgment was and not which code it was about, and on a finding
	// only partly decided — some places answered and the rest never touched —
	// which ones is the whole question. The place carries the claim so the
	// screen can name them rather than only count them.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)

		var detail struct {
			Places []struct {
				Place    string `json:"place"`
				Consumer string `json:"consumer"`
				Decision int64  `json:"decision"`
				Claim    int64  `json:"claim"`
			} `json:"places"`
		}
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200"
		httpapitest.Read(t, r, "reader", at, &detail)
		if len(detail.Places) == 0 {
			t.Fatal("the finding sits nowhere")
		}
		for _, place := range detail.Places {
			if place.Claim != 0 {
				t.Errorf("a place nobody has decided names claim %d", place.Claim)
			}
		}

		made := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+detail.Places[0].Place+"/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
				`"reasoning":"The parser is never reached."}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("recording a decision answered %d: %s", made.Code, made.Body.String())
		}
		var recorded struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
			t.Fatalf("decode: %v", err)
		}

		httpapitest.Read(t, r, "reader", at, &detail)
		var named int
		for _, place := range detail.Places {
			if place.Decision == 0 {
				if place.Claim != 0 {
					t.Errorf("a place with no decision names claim %d", place.Claim)
				}
				continue
			}
			named++
			if place.Claim != recorded.ClaimID {
				t.Errorf("the decided place names claim %d, want %d", place.Claim, recorded.ClaimID)
			}
		}
		if named == 0 {
			t.Error("no place carries the decision that was just recorded")
		}
	})
}

// The bound is on what would be written, charged as each build resolves.
//
// Consulted after every named build is resolved and every place accumulated,
// the work one request does is bounded by the request array rather than by the
// limit: REQ-27's "a limit checked against the request lets a small request do
// a large amount of work", which is why each build costing a resolution is
// answered with a maxItems.
func TestTheBulkBoundIsChargedAsEachBuildResolves(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		// A second place of the same finding in the build the path names, so
		// that build alone is already past a cap of one.
		var rows []finding.Finding
		if err := r.DB.DB.NewSelect().Model(&rows).Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("the fixture has %d findings, want 1", len(rows))
		}
		second := rows[0]
		second.ID = 0
		second.PlaceIdentity = second.PlaceIdentity[:len(second.PlaceIdentity)-4] + "beef"
		if _, err := r.DB.DB.NewInsert().Model(&second).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.together-cap",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}

		// And a second build named that was never declared. Charged as each
		// build resolves, the act is refused on the bound before anything
		// tries to resolve that one; charged afterwards, every named build is
		// resolved first and the answer is about the build instead.
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
				`"reasoning":"The parser is never reached.",`+
				`"also":[{"stream":"never-declared","variant":"broadcom"}]}`)
		if got.Code != http.StatusUnprocessableEntity {
			t.Errorf("an act past the cap answered %d: %s", got.Code, got.Body.String())
		}
		if !strings.Contains(got.Body.String(), "one action may write") {
			t.Errorf("the refusal does not name the bound: %s", got.Body.String())
		}
	})
}

func TestADecisionReadBackSaysWhetherItWaitsForASecondPerson(t *testing.T) {
	// The finding screen reads a claim's state from the decision. Told nothing
	// about the wait, it shows a dismissal nobody has agreed to as in force,
	// which undoes the second person for anybody not reading the queue.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		dismissed, _ := r.DecidedAt(t, place)

		var detail struct {
			Decision struct {
				State         string `json:"state"`
				NeedsApproval *bool  `json:"needs_approval"`
			} `json:"decision"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", dismissed), &detail)
		if detail.Decision.State != "proposed" {
			t.Fatalf("the dismissal reads as %q, want proposed", detail.Decision.State)
		}
		if detail.Decision.NeedsApproval == nil || !*detail.Decision.NeedsApproval {
			t.Error("a proposed dismissal reads back without saying it waits for a second person")
		}

		// The review queue's rows are drawn the same way, and say the same.
		var queue struct {
			Items []struct {
				Decision struct {
					ID            int64 `json:"id"`
					NeedsApproval bool  `json:"needs_approval"`
				} `json:"decision"`
			} `json:"items"`
		}
		httpapitest.Read(t, r, "reviewer", "/v1/review-queue", &queue)
		if len(queue.Items) != 1 || queue.Items[0].Decision.ID != dismissed ||
			!queue.Items[0].Decision.NeedsApproval {
			t.Errorf("the review queue lists %+v, want the dismissal waiting", queue.Items)
		}
	})
}

func TestADecisionNeedingNobodyReadsBackWithoutAWait(t *testing.T) {
	// The wait is read off the row rather than assumed: an affected answer is
	// in force when made, and its decision says nothing waits on it.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		at := fmt.Sprintf("/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/places/%s/decision", place)
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"affected","reasoning":"We ship the vulnerable parser."}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("recording affected answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil {
			t.Fatalf("decode: %v (%s)", err, got.Body.String())
		}

		var detail struct {
			Decision struct {
				State         string `json:"state"`
				NeedsApproval bool   `json:"needs_approval"`
			} `json:"decision"`
		}
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/decisions/%d", made.ID), &detail)
		if detail.Decision.State != "proposed" || detail.Decision.NeedsApproval {
			t.Errorf("an affected answer reads back as %+v, want proposed and waiting on nobody",
				detail.Decision)
		}
	})
}

func TestABuildNamedTwiceInAnotherSpellingIsRefused(t *testing.T) {
	// A build name is matched without regard to capitals, so "Master" beside
	// the path's "master" is the same build named twice.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200/decision"
		got := httpapitest.AsPerson(t, r, "triager", http.MethodPost, at,
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
				`"reasoning":"The parser is never reached.",`+
				`"also":[{"stream":"Master","variant":" broadcom"}]}`)
		if got.Code != http.StatusUnprocessableEntity {
			t.Fatalf("a build named twice answered %d: %s", got.Code, got.Body.String())
		}
		if !strings.Contains(got.Body.String(), "named twice") {
			t.Errorf("the refusal does not say the build is named twice: %s", got.Body.String())
		}
	})
}

// approvalsListed is the approval list of a claim, as a reader decodes it.
type approvalsListed struct {
	Items []struct {
		ID          int64  `json:"id"`
		RevisionID  int64  `json:"revision_id"`
		ApprovedBy  string `json:"approved_by"`
		WithdrawnAt string `json:"withdrawn_at"`
		Batch       string `json:"batch"`
		CarriedFrom int64  `json:"carried_from"`
	} `json:"items"`
}

// An approval taken back is listed beside the one given after it, with the
// moment it stopped counting, and one given under a batch names the batch.
func TestTheApprovalListKeepsWhatWasTakenBackAndNamesTheBatch(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		_, claim := r.DecidedAt(t, place)
		r.Agreed(t, claim)

		// Revising the words withdraws the agreement to the old ones.
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/reasoning", claim),
			`{"reasoning":"Re-checked the call sites; still not reached."}`); got.Code != http.StatusOK {
			t.Fatalf("revising answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", claim),
			`{"batch":"october-review"}`); got.Code != http.StatusOK {
			t.Fatalf("approving under a batch answered %d: %s", got.Code, got.Body.String())
		}

		var listed approvalsListed
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/approvals", claim), &listed)
		if len(listed.Items) != 2 {
			t.Fatalf("the claim lists %d approvals, want the withdrawn one and the live one: %+v",
				len(listed.Items), listed.Items)
		}
		withdrawn, live := 0, 0
		for _, one := range listed.Items {
			switch {
			case one.WithdrawnAt != "" && one.Batch == "":
				withdrawn++
			case one.WithdrawnAt == "" && one.Batch == "october-review":
				live++
			default:
				t.Errorf("an approval reads as %+v", one)
			}
			if one.CarriedFrom != 0 {
				t.Errorf("an approval given to this claim reads as carried from %d", one.CarriedFrom)
			}
		}
		if withdrawn != 1 || live != 1 {
			t.Errorf("%d withdrawn and %d live under the batch, want one of each", withdrawn, live)
		}
	})
}

// A re-affirmation's approval names the agreement it stands on, which belongs
// to the claim it re-makes.
func TestAReaffirmedClaimsApprovalNamesTheOneItWasCarriedFrom(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		claimed := r.AgreedThenLapsed(t)

		var earlier approvalsListed
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/approvals", claimed), &earlier)
		if len(earlier.Items) != 1 {
			t.Fatalf("the lapsed claim lists %d approvals, want 1", len(earlier.Items))
		}

		again := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/reaffirmation", claimed),
			`{"reasoning":"Checked again at 8.6.0; the transfer path is still not reached."}`)
		if again.Code != http.StatusCreated {
			t.Fatalf("re-affirming answered %d: %s", again.Code, again.Body.String())
		}
		var restored struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(again.Body.Bytes(), &restored); err != nil {
			t.Fatal(err)
		}

		var carried approvalsListed
		httpapitest.Read(t, r, "triager", fmt.Sprintf("/v1/claims/%d/approvals", restored.ClaimID), &carried)
		if len(carried.Items) != 1 || carried.Items[0].CarriedFrom != earlier.Items[0].ID ||
			carried.Items[0].ApprovedBy != "reviewer" {
			t.Errorf("the re-affirmed claim's approvals read %+v, want one carried from %d",
				carried.Items, earlier.Items[0].ID)
		}
	})
}
