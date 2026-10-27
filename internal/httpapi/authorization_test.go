// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestWhoMayReachWhat(t *testing.T) {
	// The matrix rather than a few representative cases. What leaks is never
	// the endpoint somebody thought about.
	//
	// A product somebody cannot see answers as not declared, which is the same
	// answer a name nobody ever declared gets. That is what invisible means,
	// and it is why so many rows below expect 404 where 403 would look more
	// natural.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// A code finding recorded as a flaw and kept internal, so its collaborators
		// are a list to reach.
		occurrence, flaw := httpapitest.RecordedCodeFinding(t, r, false)
		var (
			codeFinding      = "/v1/products/mine/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
			flawCodeFinding  = "/v1/products/mine/issues/" + flaw + "/code-finding"
			theirCodeFinding = "/v1/products/theirs/branches-and-tags/master/variants/broadcom/code-findings/" + occurrence
		)
		const (
			codeFindings      = "/v1/products/mine/code-findings"
			codeFindingFile   = "/v1/products/mine/code-findings.csv"
			codeFindingSeries = "/v1/products/mine/code-finding-series"
			suppressionRules  = "/v1/products/mine/suppression-rules"
			theirCodeFindings = "/v1/products/theirs/code-findings"
			repos             = "/v1/products/mine/repositories"
			runs              = "/v1/products/mine/branches-and-tags/master/variants/broadcom/analyses"
			theirRuns         = "/v1/products/theirs/branches-and-tags/master/variants/broadcom/analyses"
		)
		const (
			products   = "/v1/products"
			mine       = "/v1/products/mine/branches-and-tags"
			mineVars   = "/v1/products/mine/variants"
			mineBuilt  = "/v1/products/mine/branches-and-tags/master/variants"
			theirs     = "/v1/products/theirs/branches-and-tags"
			theirsVars = "/v1/products/theirs/variants"
			absent     = "/v1/products/nosuch/branches-and-tags"
			version    = "/v1/version"

			mineFound           = "/v1/products/mine/findings?stream=master&variant=broadcom"
			mineMinimumSeverity = "/v1/products/mine/minimum-severity"
			mineEOL             = "/v1/products/mine/end-of-life"
			streamEOL           = "/v1/products/mine/branches-and-tags/master/end-of-life"
			mineScans           = "/v1/products/mine/branches-and-tags/master/variants/broadcom/sboms"
			// What one upload changed about the build's inventory. Reached
			// on the same terms the receipt carrying its counts is: they are
			// one answer read twice.
			mineMoved  = mineScans + "/1/changes"
			theirMoved = "/v1/products/theirs/branches-and-tags/master/variants/broadcom/sboms/1/changes"
			// What the scanner cannot match in one build, and its file.
			mineUnmatched   = "/v1/products/mine/branches-and-tags/master/variants/broadcom/unmatched-components"
			theirsUnmatched = "/v1/products/theirs/branches-and-tags/master/variants/broadcom/unmatched-components"
			theirFound      = "/v1/products/theirs/findings?stream=master&variant=broadcom"
			// The same list with the branch and the variant left
			// at "all". Widening the selection is exactly the
			// shape that leaves a check behind on the narrow path.
			mineWhole  = "/v1/products/mine/findings"
			theirWhole = "/v1/products/theirs/findings"
			// Recording that a product was exploited through an issue, which
			// refuses a dismissal somebody would otherwise be free to make
			// and moves where this product's findings sit.
			mineAttacked   = "/v1/products/mine/issues/CVE-2026-0001/incidents"
			theirsAttacked = "/v1/products/theirs/issues/CVE-2026-0001/incidents"
			people         = "/v1/people"
			keys           = "/v1/keys"
			tokens         = "/v1/tokens"
			queue          = "/v1/review-queue"
		)

		for _, c := range []struct {
			who    string
			method string
			path   string
			want   int
		}{
			// Nobody at all. Refused before anything about the request is
			// examined.
			{"", http.MethodGet, products, http.StatusUnauthorized},
			{"", http.MethodPost, products, http.StatusUnauthorized},
			{"", http.MethodGet, mine, http.StatusUnauthorized},
			{"", http.MethodGet, version, http.StatusUnauthorized},

			// Real but granted nothing, and not real at all. Same answer.
			{"nothing", http.MethodGet, products, http.StatusUnauthorized},
			{"ghost", http.MethodGet, products, http.StatusUnauthorized},

			// Reading what you hold, and not what you do not — where "not"
			// is indistinguishable from "does not exist".
			{"reader", http.MethodGet, products, http.StatusOK},
			{"reader", http.MethodGet, mine, http.StatusOK},
			{"reader", http.MethodGet, mineVars, http.StatusOK},
			{"reader", http.MethodGet, mineBuilt, http.StatusOK},
			{"reader", http.MethodGet, theirs, http.StatusNotFound},
			{"reader", http.MethodGet, theirsVars, http.StatusNotFound},
			{"reader", http.MethodGet, absent, http.StatusNotFound},
			{"reader", http.MethodGet, version, http.StatusOK},

			// Every read role reaches the catalog of what it holds.
			{"private", http.MethodGet, mine, http.StatusOK},
			{"private", http.MethodGet, mineVars, http.StatusOK},
			{"private", http.MethodGet, theirs, http.StatusNotFound},
			{"triager", http.MethodGet, mine, http.StatusOK},
			{"triager", http.MethodGet, mineBuilt, http.StatusOK},
			{"private-triage", http.MethodGet, mine, http.StatusOK},
			{"internal-reader", http.MethodGet, mine, http.StatusOK},
			{"internal-reader", http.MethodGet, theirs, http.StatusNotFound},
			{"internal-triager", http.MethodGet, mineBuilt, http.StatusOK},

			// A capability is not a way in. Holding one and nothing else
			// leaves the product invisible, exactly as if it had never been
			// declared.
			{"approver", http.MethodGet, products, http.StatusOK},
			{"approver", http.MethodGet, mine, http.StatusNotFound},
			{"approver", http.MethodGet, mineVars, http.StatusNotFound},
			{"approver", http.MethodGet, mineBuilt, http.StatusNotFound},
			{"assigner-only", http.MethodGet, mine, http.StatusNotFound},
			{"assigner-only", http.MethodGet, mineVars, http.StatusNotFound},

			// Declaring is administration, whoever else you are.
			{"reader", http.MethodPost, products, http.StatusForbidden},
			{"private", http.MethodPost, products, http.StatusForbidden},
			{"triager", http.MethodPost, products, http.StatusForbidden},
			{"private-triage", http.MethodPost, products, http.StatusForbidden},
			{"internal-triager", http.MethodPost, products, http.StatusForbidden},
			{"approver", http.MethodPost, products, http.StatusForbidden},
			{"assigner-only", http.MethodPost, products, http.StatusForbidden},
			{"reader", http.MethodPost, mine, http.StatusForbidden},
			{"reader", http.MethodPost, mineVars, http.StatusForbidden},

			// Recording that this product was exploited is triage on it.
			// Reading the product is not enough: the record refuses a
			// dismissal somebody there would otherwise be free to make.
			{"reader", http.MethodPost, mineAttacked, http.StatusForbidden},
			{"approver", http.MethodPost, mineAttacked, http.StatusNotFound},
			{"assigner-only", http.MethodPost, mineAttacked, http.StatusNotFound},
			// A product this asker cannot see answers as one nobody declared,
			// before the issue in the path is resolved.
			{"triager", http.MethodPost, theirsAttacked, http.StatusNotFound},
			{"private-triage", http.MethodPost, theirsAttacked, http.StatusNotFound},
			{"", http.MethodPost, mineAttacked, http.StatusUnauthorized},

			// A product's minimum severity hides findings, which
			// is the act every other part of this gates. No role granted per
			// product carries it, so it is the same authority that sets the
			// deployment's line.
			{"reader", http.MethodPut, mineMinimumSeverity, http.StatusForbidden},
			{"triager", http.MethodPut, mineMinimumSeverity, http.StatusForbidden},
			{"approver", http.MethodPut, mineMinimumSeverity, http.StatusForbidden},
			{"", http.MethodPut, mineMinimumSeverity, http.StatusUnauthorized},
			{"nothing", http.MethodPut, mineMinimumSeverity, http.StatusUnauthorized},
			{"admin", http.MethodPut, mineMinimumSeverity, http.StatusNoContent},

			// Going out of support decides what carries a
			// deadline and what a build going quiet means, so it is
			// administration for the same reason.
			{"reader", http.MethodPut, mineEOL, http.StatusForbidden},
			{"triager", http.MethodPut, streamEOL, http.StatusForbidden},
			{"", http.MethodPut, mineEOL, http.StatusUnauthorized},
			{"admin", http.MethodPut, mineEOL, http.StatusNoContent},
			{"admin", http.MethodPut, streamEOL, http.StatusNoContent},

			// An administrator reaches everything, including what nobody
			// else can see.
			{"admin", http.MethodGet, products, http.StatusOK},
			{"admin", http.MethodGet, theirs, http.StatusOK},
			{"admin", http.MethodGet, mineVars, http.StatusOK},
			{"admin", http.MethodGet, version, http.StatusOK},
			{"admin", http.MethodPost, products, http.StatusCreated},

			// Findings follow the same visibility as everything else, and a
			// build nobody may see is a build that was never declared.
			{"", http.MethodGet, mineFound, http.StatusUnauthorized},
			{"nothing", http.MethodGet, mineFound, http.StatusUnauthorized},
			{"reader", http.MethodGet, mineFound, http.StatusOK},
			{"private", http.MethodGet, mineFound, http.StatusOK},
			{"triager", http.MethodGet, mineFound, http.StatusOK},
			{"internal-reader", http.MethodGet, mineFound, http.StatusOK},
			{"internal-reader", http.MethodGet, theirFound, http.StatusNotFound},
			// An administrator holds no role on this product, so
			// they read nothing of it. Administering the catalog
			// is knowing the build exists, which is why this is
			// 403 rather than 404.
			{"admin", http.MethodGet, mineFound, http.StatusForbidden},
			{"admin-reader", http.MethodGet, mineFound, http.StatusOK},
			{"reader", http.MethodGet, theirFound, http.StatusNotFound},
			{"approver", http.MethodGet, mineFound, http.StatusNotFound},
			{"assigner-only", http.MethodGet, mineFound, http.StatusNotFound},
			{"", http.MethodGet, mineWhole, http.StatusUnauthorized},
			{"nothing", http.MethodGet, mineWhole, http.StatusUnauthorized},
			{"reader", http.MethodGet, mineWhole, http.StatusOK},
			{"private", http.MethodGet, mineWhole, http.StatusOK},
			{"triager", http.MethodGet, mineWhole, http.StatusOK},
			{"admin", http.MethodGet, mineWhole, http.StatusForbidden},
			{"admin-reader", http.MethodGet, mineWhole, http.StatusOK},
			{"reader", http.MethodGet, theirWhole, http.StatusNotFound},
			{"approver", http.MethodGet, mineWhole, http.StatusNotFound},
			{"assigner-only", http.MethodGet, mineWhole, http.StatusNotFound},

			// Receipts are read by whoever may read the build.
			{"reader", http.MethodGet, mineScans, http.StatusOK},
			{"approver", http.MethodGet, mineScans, http.StatusNotFound},
			{"", http.MethodGet, mineScans, http.StatusUnauthorized},

			// And so is what one of them changed about the inventory. The
			// same rule as the receipt carrying its counts, down to an
			// administrator reaching it: what a build sent is the catalog
			// rather than what is open against it, and an approver holds a
			// capability rather than a way in.
			{"reader", http.MethodGet, mineMoved, http.StatusOK},
			{"private", http.MethodGet, mineMoved, http.StatusOK},
			{"triager", http.MethodGet, mineMoved, http.StatusOK},
			{"admin", http.MethodGet, mineMoved, http.StatusOK},
			{"approver", http.MethodGet, mineMoved, http.StatusNotFound},
			{"reader", http.MethodGet, theirMoved, http.StatusNotFound},
			{"", http.MethodGet, mineMoved, http.StatusUnauthorized},
			{"reader", http.MethodGet, mineUnmatched, http.StatusOK},
			{"private", http.MethodGet, mineUnmatched, http.StatusOK},
			{"admin", http.MethodGet, mineUnmatched, http.StatusNotFound},
			{"reader", http.MethodGet, mineUnmatched + ".csv", http.StatusOK},
			{"approver", http.MethodGet, mineUnmatched, http.StatusNotFound},
			{"approver", http.MethodGet, mineUnmatched + ".json", http.StatusNotFound},
			{"reader", http.MethodGet, theirsUnmatched, http.StatusNotFound},
			{"reader", http.MethodGet, theirsUnmatched + ".csv", http.StatusNotFound},
			{"", http.MethodGet, mineUnmatched, http.StatusUnauthorized},

			// The code finding queue, its file, its counts by series and the standing
			// rules are internal work. The queue and its file answer a reader
			// of the product with what they may read of it, which for a
			// reader of no internal work is nothing.
			{"", http.MethodGet, codeFindings, http.StatusUnauthorized},
			{"internal-reader", http.MethodGet, codeFindings, http.StatusOK},
			{"internal-triager", http.MethodGet, codeFindings, http.StatusOK},
			{"reader", http.MethodGet, codeFindings, http.StatusOK},
			{"private", http.MethodGet, codeFindings, http.StatusOK},
			{"approver", http.MethodGet, codeFindings, http.StatusNotFound},
			{"outsider", http.MethodGet, codeFindings, http.StatusNotFound},
			{"internal-reader", http.MethodGet, theirCodeFindings, http.StatusNotFound},
			{"", http.MethodGet, codeFindingFile, http.StatusUnauthorized},
			{"internal-reader", http.MethodGet, codeFindingFile, http.StatusOK},
			{"approver", http.MethodGet, codeFindingFile, http.StatusNotFound},
			{"outsider", http.MethodGet, codeFindingFile, http.StatusNotFound},
			{"", http.MethodGet, codeFindingSeries, http.StatusUnauthorized},
			{"internal-reader", http.MethodGet, codeFindingSeries, http.StatusOK},
			{"reader", http.MethodGet, codeFindingSeries, http.StatusForbidden},
			{"private-triage", http.MethodGet, codeFindingSeries, http.StatusForbidden},
			{"approver", http.MethodGet, codeFindingSeries, http.StatusNotFound},
			{"", http.MethodGet, suppressionRules, http.StatusUnauthorized},
			{"internal-reader", http.MethodGet, suppressionRules, http.StatusOK},
			{"internal-triager", http.MethodGet, suppressionRules, http.StatusOK},
			{"reader", http.MethodGet, suppressionRules, http.StatusForbidden},
			{"approver", http.MethodGet, suppressionRules, http.StatusNotFound},
			{"reader", http.MethodPost, suppressionRules, http.StatusForbidden},
			{"internal-reader", http.MethodPost, suppressionRules, http.StatusForbidden},

			// One code finding's evidence is read where its visibility is, and a code finding
			// nobody may read there answers as an occurrence holding nothing.
			{"", http.MethodGet, codeFinding, http.StatusUnauthorized},
			{"internal-reader", http.MethodGet, codeFinding, http.StatusOK},
			{"internal-triager", http.MethodGet, codeFinding, http.StatusOK},
			{"code-finding-handler", http.MethodGet, codeFinding, http.StatusOK},
			{"reader", http.MethodGet, codeFinding, http.StatusNotFound},
			{"private", http.MethodGet, codeFinding, http.StatusNotFound},
			{"triager", http.MethodGet, codeFinding, http.StatusNotFound},
			{"private-triage", http.MethodGet, codeFinding, http.StatusNotFound},
			{"approver", http.MethodGet, codeFinding, http.StatusNotFound},
			{"outsider", http.MethodGet, codeFinding, http.StatusNotFound},
			{"admin", http.MethodGet, codeFinding, http.StatusNotFound},
			{"internal-reader", http.MethodGet, theirCodeFinding, http.StatusNotFound},
			// A code finding recorded as a flaw takes no decision, which its readers
			// are told, since its evidence says it was recorded as a flaw. Closing one
			// as fixed is internal triage, and a reader who does not hold it is
			// answered as though nothing were open to close.
			{"internal-reader", http.MethodPost, codeFinding + "/decision", http.StatusConflict},
			{"internal-triager", http.MethodPost, codeFinding + "/decision", http.StatusConflict},
			{"reader", http.MethodPost, codeFinding + "/decision", http.StatusNotFound},
			{"internal-reader", http.MethodPost, codeFinding + "/fixed", http.StatusNotFound},
			{"reader", http.MethodPost, codeFinding + "/fixed", http.StatusNotFound},
			// A flaw record takes triage of the internal code finding and of the private
			// flaw, asked before anything the request names is resolved.
			{"code-finding-handler", http.MethodGet, codeFinding + "/flaw", http.StatusOK},
			{"internal-triager", http.MethodGet, codeFinding + "/flaw", http.StatusForbidden},
			{"private-triage", http.MethodGet, codeFinding + "/flaw", http.StatusForbidden},
			{"internal-reader", http.MethodGet, codeFinding + "/flaw", http.StatusForbidden},
			{"internal-triager", http.MethodPost, codeFinding + "/flaw/withdrawal", http.StatusForbidden},
			{"private-triage", http.MethodPost, codeFinding + "/flaw/withdrawal", http.StatusForbidden},
			{"internal-reader", http.MethodPost, codeFinding + "/flaw/withdrawal", http.StatusForbidden},
			{"", http.MethodPost, codeFinding + "/flaw/withdrawal", http.StatusUnauthorized},
			// The code finding a flaw was recorded from is read by whoever reads both
			// the flaw and the code finding in full, and answers as no code finding elsewhere.
			{"code-finding-handler", http.MethodGet, flawCodeFinding, http.StatusOK},
			{"private-triage", http.MethodGet, flawCodeFinding, http.StatusNotFound},
			{"internal-reader", http.MethodGet, flawCodeFinding, http.StatusNotFound},
			{"outsider", http.MethodGet, flawCodeFinding, http.StatusNotFound},
			{"", http.MethodGet, flawCodeFinding, http.StatusUnauthorized},
			{"internal-triager", http.MethodPut, codeFinding + "/flaw/disclosure", http.StatusForbidden},
			{"internal-triager", http.MethodDelete, codeFinding + "/flaw/disclosure", http.StatusForbidden},
			// Who is granted an internal-only code finding is managed by whoever reads it at
			// internal visibility, and by nobody else.
			{"internal-reader", http.MethodGet, codeFinding + "/collaborators", http.StatusOK},
			{"internal-triager", http.MethodGet, codeFinding + "/collaborators", http.StatusOK},
			{"code-finding-handler", http.MethodGet, codeFinding + "/collaborators", http.StatusOK},
			{"private", http.MethodGet, codeFinding + "/collaborators", http.StatusNotFound},
			{"reader", http.MethodGet, codeFinding + "/collaborators", http.StatusNotFound},
			{"approver", http.MethodGet, codeFinding + "/collaborators", http.StatusNotFound},
			{"", http.MethodGet, codeFinding + "/collaborators", http.StatusUnauthorized},
			{"private", http.MethodPut, codeFinding + "/collaborators/reader", http.StatusNotFound},
			{"private", http.MethodDelete, codeFinding + "/collaborators/reader", http.StatusNotFound},

			// A product's repository settings are administration.
			{"", http.MethodGet, repos, http.StatusUnauthorized},
			{"admin", http.MethodGet, repos, http.StatusOK},
			{"reader", http.MethodGet, repos, http.StatusForbidden},
			{"internal-triager", http.MethodGet, repos, http.StatusForbidden},
			{"code-finding-handler", http.MethodGet, repos, http.StatusForbidden},
			{"reader", http.MethodPut, repos, http.StatusForbidden},
			{"internal-triager", http.MethodPut, repos, http.StatusForbidden},

			// A person reads a build's analyzer runs where they read internal
			// work in the product, since the counts are of internal findings,
			// and anybody else reads them as runs nobody sent.
			{"", http.MethodGet, runs, http.StatusUnauthorized},
			{"internal-reader", http.MethodGet, runs, http.StatusOK},
			{"internal-triager", http.MethodGet, runs, http.StatusOK},
			{"reader", http.MethodGet, runs, http.StatusNotFound},
			{"private", http.MethodGet, runs, http.StatusNotFound},
			{"approver", http.MethodGet, runs, http.StatusNotFound},
			{"outsider", http.MethodGet, runs, http.StatusNotFound},
			{"internal-reader", http.MethodGet, theirRuns, http.StatusNotFound},

			// Administration is administration. Holding every product role
			// there is does not amount to any of it.
			{"reader", http.MethodGet, people, http.StatusForbidden},
			{"private", http.MethodGet, people, http.StatusForbidden},
			{"triager", http.MethodGet, people, http.StatusForbidden},
			{"private-triage", http.MethodGet, people, http.StatusForbidden},
			{"internal-triager", http.MethodGet, people, http.StatusForbidden},
			{"approver", http.MethodGet, people, http.StatusForbidden},
			{"assigner-only", http.MethodGet, people, http.StatusForbidden},
			{"reader", http.MethodGet, keys, http.StatusForbidden},
			{"triager", http.MethodGet, keys, http.StatusForbidden},
			{"reader", http.MethodDelete, "/v1/keys/nightly", http.StatusForbidden},
			{"reader", http.MethodDelete, "/v1/people/admin/roles/mine/public-read", http.StatusForbidden},
			{"", http.MethodGet, people, http.StatusUnauthorized},
			{"nothing", http.MethodGet, keys, http.StatusUnauthorized},

			// Deciding is its own right. Somebody who may read a product
			// reaches its findings and may argue about none of them.
			{"reader", http.MethodGet, queue, http.StatusOK},
			{"triager", http.MethodGet, queue, http.StatusOK},
			{"", http.MethodGet, queue, http.StatusUnauthorized},
			{"nothing", http.MethodGet, queue, http.StatusUnauthorized},
			{"admin", http.MethodGet, people, http.StatusOK},
			{"admin", http.MethodGet, keys, http.StatusOK},

			// Your own lapsed decisions are a list anybody here may ask for, and
			// answers only what they may act on. Who may re-affirm them is
			// pinned with a real decision beside the act's own tests.
			{"reader", http.MethodGet, "/v1/to-reaffirm", http.StatusOK},
			{"triager", http.MethodGet, "/v1/to-reaffirm", http.StatusOK},
			{"", http.MethodGet, "/v1/to-reaffirm", http.StatusUnauthorized},
			{"", http.MethodPost, "/v1/reaffirmations", http.StatusUnauthorized},

			// The source of roles, and what each group grants, is
			// administration like everything else that decides access.
			{"reader", http.MethodGet, "/v1/roles/mode", http.StatusForbidden},
			{"triager", http.MethodGet, "/v1/roles/bindings", http.StatusForbidden},
			{"", http.MethodGet, "/v1/roles/mode", http.StatusUnauthorized},
			{"admin", http.MethodGet, "/v1/roles/mode", http.StatusOK},
			{"admin", http.MethodGet, "/v1/roles/bindings", http.StatusOK},

			// A person's own credentials are their own. Anybody who may be
			// here at all may hold one, and it reaches no further than they
			// do — so holding a read role is enough, and nothing more is.
			{"reader", http.MethodGet, tokens, http.StatusOK},
			{"approver", http.MethodGet, tokens, http.StatusOK},
			{"", http.MethodGet, tokens, http.StatusUnauthorized},
			{"nothing", http.MethodGet, tokens, http.StatusUnauthorized},
		} {
			if got := r.As(t, c.who, c.method, c.path); got != c.want {
				who := c.who
				if who == "" {
					who = "nobody"
				}
				t.Errorf("%s %s as %s = %d, want %d", c.method, c.path, who, got, c.want)
			}
		}
	})
}

func TestWhatSomebodyCannotSeeLooksExactlyLikeWhatIsNotThere(t *testing.T) {
	// The whole of what makes a product invisible, in one property. If these
	// two answers differ in any way — the code, the body, a header — then
	// somebody holding one product can enumerate every other by guessing names
	// and watching which guesses answer differently.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, pair := range [][2]string{
			{"/v1/products/theirs/branches-and-tags", "/v1/products/nosuch/branches-and-tags"},
			{"/v1/products/theirs/variants", "/v1/products/nosuch/variants"},
			{"/v1/products/theirs/branches-and-tags/master/variants", "/v1/products/nosuch/branches-and-tags/master/variants"},
		} {
			hidden := r.Body(t, "reader", http.MethodGet, pair[0])
			missing := r.Body(t, "reader", http.MethodGet, pair[1])
			if hidden.Code != missing.Code {
				t.Errorf("%s answered %d and %s answered %d", pair[0], hidden.Code, pair[1], missing.Code)
			}
			if hidden.Text == missing.Text {
				continue
			}
			// The bodies name the thing asked for, which is what the asker
			// already typed. What must not differ is anything else.
			if strings.ReplaceAll(hidden.Text, "theirs", "X") != strings.ReplaceAll(missing.Text, "nosuch", "X") {
				t.Errorf("bodies differ beyond the name asked for:\n  hidden:  %s\n  missing: %s", hidden.Text, missing.Text)
			}
		}
	})
}

func TestEveryRefusalOfAStrangerReadsTheSame(t *testing.T) {
	// Unknown, known but granted nothing, and holding a revoked credential.
	// Told apart, they say whether a name or a key is real.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		unknown := r.Body(t, "ghost", http.MethodGet, "/v1/products")
		ungranted := r.Body(t, "nothing", http.MethodGet, "/v1/products")
		revoked := r.WithKey(t, r.Revoked, http.MethodGet, "/v1/products")

		for _, got := range []httpapitest.Response{ungranted, revoked} {
			if got.Code != unknown.Code || got.Text != unknown.Text {
				t.Errorf("a refusal differs: %d %q against %d %q",
					got.Code, got.Text, unknown.Code, unknown.Text)
			}
		}
	})
}

func TestAPipelineCanReachNothingButSending(t *testing.T) {
	// A build server has no business holding a person's permissions, and this
	// is what keeps the visibility rules out of its reach entirely rather than
	// relying on them being applied to it correctly.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, path := range []string{
			"/v1/products",
			"/v1/products/mine/branches-and-tags",
			"/v1/products/mine/variants",
			"/v1/products/mine/branches-and-tags/master/variants",
			"/v1/products/mine/findings?stream=master&variant=broadcom",
			"/v1/people",
			"/v1/keys",
			// A pipeline has no owner for a token to be a live reference to.
			"/v1/tokens",
			// Nor anything to argue about: a build server makes no decision.
			"/v1/review-queue",
			// Nor when anything was last scanned. A key reads back what it
			// sent; when a build was last scanned by anybody is a fact about
			// the deployment, and the answer names every build there is.
			"/v1/last-uploads",
			// Nor a notification area. A key is not a person and has nobody to
			// tell; its identifier comes from another table and would collide
			// with a person's.
			"/v1/notifications",
			"/v1/roles/mode",
			"/v1/roles/bindings",
		} {
			if got := r.AsKey(t, http.MethodGet, path); got != http.StatusForbidden {
				t.Errorf("a pipeline reading %s answered %d, want 403", path, got)
			}
		}

		// The one exception, and it is not a reading role: a sender may read
		// back what became of what it sent. Without it an acceptance is
		// unverifiable by the only party that can act on a rejected file.
		if got := r.AsKey(t, http.MethodGet,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/sboms"); got != http.StatusOK {
			t.Errorf("a pipeline could not read its own receipts: %d", got)
		}
		if got := r.AsKey(t, http.MethodGet,
			"/v1/products/theirs/branches-and-tags/master/variants/broadcom/sboms"); got != http.StatusNotFound {
			t.Errorf("a pipeline reached receipts outside its scope: %d", got)
		}
		// And what one of its uploads changed, which is the detail behind the
		// counts on the receipt. A key holds no reading role, so this is
		// reached as the sender rather than as a reader — and outside its
		// scope it is the same refusal a receipt gets.
		sent := r.SentByTheKey(t)
		if got := r.AsKey(t, http.MethodGet,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom/sboms/"+
				strconv.FormatInt(sent, 10)+"/changes"); got != http.StatusOK {
			t.Errorf("a pipeline could not read what its own upload changed: %d", got)
		}
		if got := r.AsKey(t, http.MethodGet,
			"/v1/products/theirs/branches-and-tags/master/variants/broadcom/sboms/1/changes"); got != http.StatusNotFound {
			t.Errorf("a pipeline reached an inventory outside its scope: %d", got)
		}
		if got := r.AsKey(t, http.MethodGet, "/v1/version"); got != http.StatusForbidden {
			t.Errorf("a pipeline read the running version: %d", got)
		}
		if got := r.AsKey(t, http.MethodPost, "/v1/products"); got != http.StatusForbidden {
			t.Errorf("a pipeline declaring a product answered %d, want 403", got)
		}
	})
}

func TestAListShowsOnlyWhatTheAskerHolds(t *testing.T) {
	// Counting is reading. A list that quietly includes what somebody may not
	// see is the same disclosure as showing it, and the product list is itself
	// a statement about what an organization ships.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		req.Header.Set(httpapitest.TestHeader, "reader")
		rec := httptest.NewRecorder()
		r.Handler.ServeHTTP(rec, req)

		body := rec.Body.String()
		if !strings.Contains(body, "mine") {
			t.Errorf("the product they hold something on is missing: %s", body)
		}
		if strings.Contains(body, "theirs") {
			t.Errorf("a product they hold nothing on was listed: %s", body)
		}
	})
}

func TestScanningShowsOnlyTheBuildsTheAskerHolds(t *testing.T) {
	// Counting is reading, and this one names every build there is: a list
	// that included one somebody holds nothing on would disclose that the
	// product exists, which is the thing every other refusal here is careful
	// not to say.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		req := httptest.NewRequest(http.MethodGet, "/v1/last-uploads", nil)
		req.Header.Set(httpapitest.TestHeader, "reader")
		rec := httptest.NewRecorder()
		r.Handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("a reader could not ask what has been scanned: %d", rec.Code)
		}
		body := rec.Body.String()
		// Both directions. "Theirs is absent" is also what an endpoint
		// answering nothing to everybody looks like, and a fixture that builds
		// no builds at all satisfies both.
		if !strings.Contains(body, "mine") {
			t.Errorf("the build they hold something on is missing: %s", body)
		}
		if strings.Contains(body, "theirs") {
			t.Errorf("a product they hold nothing on was listed: %s", body)
		}
	})
}

func TestNothingButTheProbesAnswersWithoutACredential(t *testing.T) {
	// Guarding one prefix leaves everything outside it open by default, and
	// the framework registers routes of its own: the API document and the
	// schemas it references are served to anybody who asks, including the
	// running version the endpoint reporting it is authenticated to
	// withhold.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, path := range []string{
			"/openapi.json", "/openapi.yaml", "/openapi-3.0.json", "/openapi-3.0.yaml",
			"/schemas/VariantBody.json", "/docs",
			"/v1/version", "/v1/products", "/v1/last-uploads", "/v1/notifications",
		} {
			got := r.Body(t, "", http.MethodGet, path)
			if got.Code != http.StatusUnauthorized {
				t.Errorf("%s answered %d without a credential, want 401 (%d bytes)",
					path, got.Code, len(got.Text))
			}
		}

		// And the probes still answer, because a container cannot sign in.
		for _, path := range []string{"/healthz", "/readyz"} {
			if got := r.Body(t, "", http.MethodGet, path); got.Code != http.StatusOK {
				t.Errorf("%s answered %d", path, got.Code)
			}
		}

		// So does the list of ways in, which is what somebody sees before they
		// hold anything. It is the one reading endpoint outside the probes
		// that answers to a stranger, so what it discloses is asserted rather
		// than assumed: names an operator configured, and nothing about
		// whether any account exists.
		got := r.Body(t, "", http.MethodGet, "/v1/sign-in")
		if got.Code != http.StatusOK {
			t.Errorf("the sign-in providers answered %d to a stranger", got.Code)
		}
		for _, leaked := range []string{"reader", "triager", "admin", "identity", "person"} {
			if strings.Contains(strings.ToLower(got.Text), leaked) {
				t.Errorf("the providers list mentions %q: %s", leaked, got.Text)
			}
		}

		// And the subtree beneath it. What is down there redirects to a
		// provider or refuses; what it must never do is answer 200 with
		// anything in it, because a stranger is who reaches it. Sign-in reads
		// its own key, its own sessions and the account a first arrival
		// needs, so what is asserted here is the part that is checkable: no
		// domain data.
		for _, path := range []string{
			"/v1/sign-in/",
			"/v1/sign-in/stub",
			"/v1/sign-in/stub/callback",
			"/v1/sign-in/nothing-configured",
			"/v1/sign-in/../products",
			"/v1/sign-in/stub/../../products",
		} {
			got := r.Body(t, "", http.MethodGet, path)
			if got.Code == http.StatusOK && strings.TrimSpace(got.Text) != "" {
				t.Errorf("%s answered %d to a stranger with a body: %s",
					path, got.Code, got.Text)
			}
			// Whatever it answers, it names nothing this deployment holds.
			for _, leaked := range []string{"reader", "triager", "admin", "mine", "theirs"} {
				if strings.Contains(strings.ToLower(got.Text), leaked) {
					t.Errorf("%s mentioned %q to a stranger: %s", path, leaked, got.Text)
				}
			}
		}
	})
}

func TestTheApiDocumentIsServedToSomebodyRecognized(t *testing.T) {
	// Closing it to strangers must not close it to the client that is
	// generated from it.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if got := r.Body(t, "reader", http.MethodGet, "/openapi.json"); got.Code != http.StatusOK {
			t.Errorf("a recognized caller reading the API document got %d", got.Code)
		}
	})
}

func TestAKeyReachesOnlyTheTargetItIsScopedTo(t *testing.T) {
	// The scope is checked at the endpoint, not only in the model. A key
	// covering one product must be refused another, and refused in a way that
	// does not say whether that other product exists.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		// A real document, because the body is validated before the handler
		// runs: a request with nothing in it is refused for being empty and
		// never reaches the question being asked here.
		sent := func(path string) httpapitest.Response {
			req := httpapitest.Upload(t, path, httpapitest.Inventory(httpapitest.Nowish(), "libc6"))
			req.Header.Set("Authorization", "Bearer "+r.Key)
			rec := httptest.NewRecorder()
			r.Handler.ServeHTTP(rec, req)
			return httpapitest.Response{Code: rec.Code, Text: rec.Body.String()}
		}

		mine := sent("/v1/products/mine/branches-and-tags/master/variants/broadcom/sboms")
		if mine.Code != http.StatusAccepted {
			t.Errorf("a key sending to its own product answered %d: %s", mine.Code, mine.Text)
		}

		elsewhere := sent("/v1/products/theirs/branches-and-tags/master/variants/broadcom/sboms")
		absent := sent("/v1/products/nosuch/branches-and-tags/master/variants/broadcom/sboms")
		if elsewhere.Code != http.StatusNotFound {
			t.Errorf("a key reaching another product answered %d, want 404", elsewhere.Code)
		}
		if elsewhere.Code != absent.Code {
			t.Errorf("another product answered %d and an absent one %d", elsewhere.Code, absent.Code)
		}

		req := httpapitest.Upload(t, "/v1/products/mine/branches-and-tags/master/variants/broadcom/sboms",
			httpapitest.Inventory(httpapitest.Nowish(), "libc6"))
		req.Header.Set("Authorization", "Bearer "+r.Revoked)
		rec := httptest.NewRecorder()
		r.Handler.ServeHTTP(rec, req)
		revoked := httpapitest.Response{Code: rec.Code}
		if revoked.Code != http.StatusUnauthorized {
			t.Errorf("a revoked key answered %d, want 401", revoked.Code)
		}
	})
}

func TestACredentialWinsOverAHeader(t *testing.T) {
	// A request carrying both is a build server's credential arriving through
	// something that also sets a header. The credential is what it holds; the
	// header is what somebody in front of it claimed.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		req.Header.Set("Authorization", "Bearer "+r.Key)
		req.Header.Set(httpapitest.TestHeader, "admin")
		rec := httptest.NewRecorder()
		r.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("a request holding both answered %d; the key should decide and a key may not read", rec.Code)
		}
	})
}

func TestAMalformedCredentialIsRefused(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		for _, header := range []string{"", "Bearer", "Bearer ", "Basic " + r.Key, r.Key, "Bearer " + r.Key + "x"} {
			req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			rec := httptest.NewRecorder()
			r.Handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("Authorization %q answered %d, want 401", header, rec.Code)
			}
		}
	})
}

// TestWhatAnOperationSaysItNeedsIsWhatItEnforces walks the document the server
// builds and puts a pipeline key at every operation declaring a scope that
// excludes one.
//
// A declaration that writes a document and nothing else leaves this scope
// unenforced: an operation carrying it says "any recognized credential" and
// then refuses every credential that is not a person, so the generated
// reference, the extension a client generator reads and an access review all
// state a rule the code contradicts.
//
// Some operations do mean any credential — a key reads back what it sent, down
// to what one upload changed about the build — which is why the word cannot
// simply be redefined.
func TestWhatAnOperationSaysItNeedsIsWhatItEnforces(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		checked := 0
		for _, op := range r.API.OpenAPI().Paths {
			for method, operation := range map[string]*huma.Operation{
				http.MethodGet: op.Get, http.MethodPost: op.Post,
				http.MethodPut: op.Put, http.MethodDelete: op.Delete,
			} {
				if operation == nil || operation.Extensions == nil {
					continue
				}
				asks, stated := operation.Extensions["x-openpsirt-requires"]
				if !stated {
					continue
				}
				scope := httpapitest.DeclaredScope(t, asks)
				if scope != "person" && scope != "self" {
					continue
				}
				// A path with its parameters filled in with names the fixture
				// declares, so a refusal is about the credential rather than
				// about a name nothing matches.
				path := filled(operation.Path)
				if strings.Contains(path, "{") {
					continue
				}
				got := r.AsKey(t, method, path)
				if got != http.StatusForbidden && got != http.StatusUnauthorized {
					t.Errorf("%s %s says it needs a signed-in person and answered a "+
						"pipeline key %d", method, path, got)
				}
				checked++
			}
		}
		// A sweep that reached nothing looks exactly like a sweep that found
		// nothing wrong.
		if checked < 20 {
			t.Errorf("only %d operations were reached, so this proves little", checked)
		}
	})
}

// filled puts the fixture's own names into a templated path.
func filled(path string) string {
	for from, to := range map[string]string{
		"{product}": "mine", "{stream}": "master", "{variant}": "broadcom",
	} {
		path = strings.ReplaceAll(path, from, to)
	}
	return path
}
