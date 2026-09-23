// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

func TestOneIssueIsAnsweredAcrossEveryProductYouMaySee(t *testing.T) {
	// "A critical just landed in openssl — which of our products ship an
	// affected version" was a question asked one product at a time, which
	// at a dozen products is the first thing anybody complains about.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		var out struct {
			Vulnerability string `json:"vulnerability"`
			Products      int    `json:"products"`
			Total         int    `json:"total"`
			Items         []struct {
				Product   string `json:"product"`
				Stream    string `json:"stream"`
				Variant   string `json:"variant"`
				Component string `json:"component"`
				Places    int    `json:"places"`
				State     string `json:"state"`
			} `json:"items"`
		}
		read(t, r, "triager", "/v1/issues/CVE-2026-9999", &out)
		if len(out.Items) == 0 || out.Products != 1 {
			t.Fatalf("the issue reads as %+v", out)
		}
		one := out.Items[0]
		if one.Product != "mine" || one.Component != "libnl-3-200" || one.Places < 1 {
			t.Errorf("the row reads as %+v", one)
		}
		if one.State != "undecided" {
			t.Errorf("a finding nobody has decided reads as %q", one.State)
		}

		// A decision moves the state on this page too: it is the same
		// definition the findings list uses rather than a second one.
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		read(t, r, "triager", "/v1/issues/CVE-2026-9999", &out)
		if out.Items[0].State != "waiting" {
			t.Errorf("a claim nobody has agreed to reads as %q", out.Items[0].State)
		}
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			"/v1/claims/"+itoa(claim)+"/approval", `{}`); got.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", got.Code, got.Body.String())
		}
		read(t, r, "triager", "/v1/issues/CVE-2026-9999", &out)
		if out.Items[0].State != "agreed" {
			t.Errorf("an approved claim reads as %q", out.Items[0].State)
		}

		// Nothing affected is an answer, and it is the one a customer inquiry
		// asks for: the question of whether we are affected can otherwise be
		// answered yes and never no.
		//
		// And the two ways of not being affected answer identically. Somebody
		// who reaches no product, and somebody asking about an identifier
		// nobody here has seen, are told the same thing — told apart, the
		// pair says which issues this deployment holds, one guess at a time,
		// about products somebody may not read. (A subject granted nothing at
		// all is refused before this, at the door.)
		unaffected := func(t *testing.T, who, at string) {
			t.Helper()
			got := asPerson(t, r, who, http.MethodGet, at, "")
			if got.Code != http.StatusOK {
				t.Fatalf("%s asking %s answered %d", who, at, got.Code)
			}
			var said struct {
				Vulnerability string `json:"vulnerability"`
				Description   string `json:"description"`
				Severity      string `json:"severity"`
				Items         []struct {
					Product string `json:"product"`
				} `json:"items"`
				Total int `json:"total"`
			}
			if err := json.Unmarshal(got.Body.Bytes(), &said); err != nil {
				t.Fatal(err)
			}
			if said.Total != 0 || len(said.Items) != 0 {
				t.Errorf("%s asking %s was told about %d rows", who, at, said.Total)
			}
			// And nothing about the issue itself, which is what would tell
			// the two cases apart.
			if said.Description != "" || said.Severity != "" {
				t.Errorf("%s asking %s was told what the issue is: %+v", who, at, said)
			}
		}
		unaffected(t, "approver", "/v1/issues/CVE-2026-9999")
		unaffected(t, "triager", "/v1/issues/CVE-1999-0001")
	})
}

func TestAFailedReadIsNotAnAnswerAboutWhatYouAreAffectedBy(t *testing.T) {
	// "Nothing of yours is affected" is the answer an inquiry is usually
	// asking for, which is why it is a document rather than a refusal — and
	// exactly why a query that could not be made must not produce it. The
	// sentinel is what tells a name nobody has filed from a read that failed.
	//
	// The read is broken by taking the table the name is resolved against out
	// from under it, and put back before anything else runs: a server
	// database is shared by the whole package where SQLite hands out a copy,
	// so a test that left a hole in the schema would fail every later one and
	// look like an engine disagreement.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		ctx := t.Context()
		if _, err := r.db.ExecContext(ctx,
			`ALTER TABLE "vulnerability_alias" RENAME TO "vulnerability_alias_away"`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := r.db.ExecContext(context.WithoutCancel(ctx),
				`ALTER TABLE "vulnerability_alias_away" RENAME TO "vulnerability_alias"`); err != nil {
				t.Fatalf("the table was not put back, so every later test reads a "+
					"schema with a hole in it: %v", err)
			}
		})

		for _, at := range []string{
			"/v1/issues/CVE-2026-9999",
			"/v1/issues/CVE-2026-9999/document",
		} {
			got := asPerson(t, r, "triager", http.MethodGet, at, "")
			if got.Code != http.StatusInternalServerError {
				t.Errorf("%s answered %d to a read that could not be made", at, got.Code)
			}
			if strings.Contains(got.Body.String(), "Nothing you can see carries") {
				t.Errorf("%s told a customer they are not affected: %s", at, got.Body.String())
			}
		}
	})
}

// TestEverythingKnownAboutOneIssueIsADocument is the form a customer inquiry
// is answered in.
//
// The issue itself, the builds of ours carrying it, the decision about each
// and the argument behind it, were four screens and a copy-paste — so the
// answer was assembled differently every time and the half somebody forgot was
// the half that mattered.
func TestEverythingKnownAboutOneIssueIsADocument(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		claim, _ := r.claimed(t, "triager", "CVE-2026-9999", "libnl-3-200", dismissal)
		if got := asPerson(t, r, "reviewer", http.MethodPost,
			"/v1/claims/"+itoa(claim)+"/approval", `{}`); got.Code != http.StatusOK {
			t.Fatalf("agreeing answered %d: %s", got.Code, got.Body.String())
		}

		// An address from a feed that a reader's machine would act on, which
		// is the class this document has to keep out of somebody's hands.
		if _, err := finding.NewVulnerabilities(r.db.DB).Intern(t.Context(),
			[]finding.Named{{
				Identifier: "CVE-2026-9999",
				References: []finding.Reference{{URL: "ms-msdt:calc", Kind: finding.Report}},
			}}); err != nil {
			t.Fatal(err)
		}

		got := asPerson(t, r, "triager", http.MethodGet,
			"/v1/issues/CVE-2026-9999/document", "")
		if got.Code != http.StatusOK {
			t.Fatalf("the document answered %d: %s", got.Code, got.Body.String())
		}
		if kind := got.Header().Get("Content-Type"); !strings.HasPrefix(kind, "text/markdown") {
			t.Errorf("the document came back as %q", kind)
		}
		written := got.Body.String()

		// It says who it is for. A document that does not is one somebody
		// forwards, and this one carries our own argument.
		if !strings.Contains(written, "Internal") {
			t.Errorf("the document does not say it is internal:\n%s", written)
		}
		for _, wanted := range []string{
			"CVE-2026-9999",
			// The issue, its places, and the decisions.
			"read past the end of the buffer",
			"libnl-3-200",
			"not-applicable",
			// The argument the judgment rests on, which is the half a second
			// person is checking.
			"The driver is not built for this image.",
			// And who agreed, because a dismissal standing on one person is
			// the thing an inquiry is most likely to be about.
			"reviewer",
			// The write-up address, from what the report carried.
			"https://nvd.nist.gov/vuln/detail/CVE-2026-9999",
		} {
			if !strings.Contains(written, wanted) {
				t.Errorf("the document does not carry %q:\n%s", wanted, written)
			}
		}

		// An address a reader's machine would act on is not something to hand
		// somebody in a document they forward. The same rule an address
		// stored beside a claim goes through.
		if strings.Contains(written, "ms-msdt") {
			t.Errorf("a scheme a machine acts on reached the document:\n%s", written)
		}

		// Somebody who reaches no product is told what an issue nobody has
		// heard of gets, for the reason the issue's own route answers both
		// alike: told apart, the pair says which issues this deployment holds.
		hidden := asPerson(t, r, "approver", http.MethodGet,
			"/v1/issues/CVE-2026-9999/document", "")
		if hidden.Code != http.StatusOK {
			t.Fatalf("somebody who reaches no product answered %d", hidden.Code)
		}
		if !strings.Contains(hidden.Body.String(), "Nothing you can see carries this issue") ||
			strings.Contains(hidden.Body.String(), "libnl-3-200") {
			t.Errorf("somebody who reaches no product was told where it is:\n%s",
				hidden.Body.String())
		}

		// Nothing of yours affected is an answer rather than a refusal, which
		// is what the inquiry is usually asking.
		none := asPerson(t, r, "triager", http.MethodGet,
			"/v1/issues/CVE-1999-0001/document", "")
		if none.Code != http.StatusOK {
			t.Fatalf("an issue nothing carries answered %d", none.Code)
		}
		if !strings.Contains(none.Body.String(), "Nothing you can see carries this issue") {
			t.Errorf("the document does not answer the question:\n%s", none.Body.String())
		}
		// And says nothing about the issue itself, for the reason the issue's
		// own route says nothing: the two ways of not being affected answer
		// alike.
		if strings.Contains(none.Body.String(), "## The issue") {
			t.Errorf("an unaffected document describes the issue:\n%s", none.Body.String())
		}
	})
}
