// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestASupplierAdvisoryIsEvidenceAndNeverADecision(t *testing.T) {
	// REQ-31: a third party's judgment is shown as evidence and offered as a
	// prefill, and never decides anything by itself.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)

		// Only an administrator uploads one: it is a document about somebody
		// else's products, not a judgment anybody here triages.
		//
		// Two controls refuse, and either alone is enough: the scope the
		// operation declares, which the middleware enforces before any handler
		// runs, and the check inside the handler. Removing one leaves the test
		// green because the other covers it, which is what the declaration
		// exists for — a handler check somebody deletes does not quietly
		// widen an operation that still says it requires an administrator.
		httpapitest.RefusedWith(t, r.Advised(t, "triager", "exsa.json",
			httpapitest.SupplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0")),
			http.StatusForbidden)

		got := r.Advised(t, "admin", "exsa.json",
			httpapitest.SupplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0"))
		if got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		var taken struct {
			Publisher  string `json:"publisher"`
			Identifier string `json:"identifier"`
			Title      string `json:"title"`
			Recorded   int    `json:"recorded"`
			Superseded int    `json:"superseded"`
			Digest     string `json:"digest"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &taken); err != nil {
			t.Fatal(err)
		}
		// Who published it and what they called it are read from the document
		// rather than from the request: an advisory names both, and it is not
		// a conforming advisory without them.
		// As the document names itself: the response says "the publisher the
		// document names", and the folding is how the record matches rather
		// than how the publisher spells their own name.
		if taken.Publisher != "Example Distribution" || taken.Identifier != "EXSA-2026:1001" {
			t.Fatalf("the upload reports %+v", taken)
		}
		if taken.Recorded != 1 || taken.Digest == "" || taken.Title == "" {
			t.Fatalf("the upload reports %+v", taken)
		}

		detail := r.WhatPublishersSay(t)
		if len(detail.Said) != 1 {
			t.Fatalf("the finding shows %d claims", len(detail.Said))
		}
		one := detail.Said[0]
		if one.Source != "advisory" || one.Identifier != "EXSA-2026:1001" {
			t.Errorf("where it came from reads %+v, which is how a reader places it", one)
		}
		if one.Status != "fixed" || one.About != "3.7.0" {
			t.Errorf("what it says reads %+v", one)
		}
		if !strings.Contains(one.Statement, "Upgrade to libnl-3-200") {
			t.Errorf("the reasoning reads %q, and it is the part worth having", one.Statement)
		}
		// Offered, because the publisher spoke about the version shipped here.
		if one.Offers != "already-fixed" {
			t.Errorf("it offers %q", one.Offers)
		}
		// Never applied. Nothing was decided by uploading it.
		if len(detail.Standing) != 0 {
			t.Errorf("uploading an advisory decided %d things", len(detail.Standing))
		}
	})
}

func TestAnAdvisoryAboutAnotherVersionOffersNothing(t *testing.T) {
	// An advisory exists to name the version that carries the fix, which is
	// not the version shipped here. Offered anyway, the control comes
	// prefilled with a claim the publisher never made, with their name on it.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		got := r.Advised(t, "admin", "exsa.json",
			httpapitest.SupplierAdvisory("EXSA-2026:1002", "fixed", "3.9.0"))
		if got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		detail := r.WhatPublishersSay(t)
		if len(detail.Said) != 1 {
			t.Fatalf("the finding shows %d claims", len(detail.Said))
		}
		// Shown, because which versions a publisher spoke about is what a
		// triager reading the evidence wants.
		if detail.Said[0].About != "3.9.0" {
			t.Errorf("the version it spoke about reads %q", detail.Said[0].About)
		}
		if detail.Said[0].Offers != "" {
			t.Errorf("a claim about 3.9.0 offered %q against 3.7.0", detail.Said[0].Offers)
		}
	})
}

func TestUploadingOneAdvisoryLeavesTheOthersStanding(t *testing.T) {
	// A publisher issues hundreds. Replaced on the publisher alone, the
	// deployment holds exactly the last document anybody uploaded.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		if got := r.Advised(t, "admin", "one.json",
			httpapitest.SupplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0")); got.Code != http.StatusCreated {
			t.Fatalf("the first answered %d: %s", got.Code, got.Body.String())
		}
		second := r.Advised(t, "admin", "two.json",
			httpapitest.SupplierAdvisory("EXSA-2026:1002", "known_not_affected", "3.7.0"))
		if second.Code != http.StatusCreated {
			t.Fatalf("the second answered %d: %s", second.Code, second.Body.String())
		}
		var taken struct {
			Superseded int `json:"superseded"`
		}
		if err := json.Unmarshal(second.Body.Bytes(), &taken); err != nil {
			t.Fatal(err)
		}
		if taken.Superseded != 0 {
			t.Errorf("a second advisory set aside %d claims of the first", taken.Superseded)
		}
		if said := r.WhatPublishersSay(t).Said; len(said) != 2 {
			t.Errorf("%d claims stand, want both advisories", len(said))
		}

		// A revision of the first replaces its own claims and no others.
		revised := r.Advised(t, "admin", "one.json",
			httpapitest.SupplierAdvisory("EXSA-2026:1001", "known_not_affected", "3.7.0"))
		if revised.Code != http.StatusCreated {
			t.Fatalf("the revision answered %d: %s", revised.Code, revised.Body.String())
		}
		if err := json.Unmarshal(revised.Body.Bytes(), &taken); err != nil {
			t.Fatal(err)
		}
		if taken.Superseded != 1 {
			t.Errorf("a revision set aside %d claims, want its own one", taken.Superseded)
		}
		if said := r.WhatPublishersSay(t).Said; len(said) != 2 {
			t.Errorf("%d claims stand after a revision, want one per advisory", len(said))
		}
	})
}

func TestEachUploadRefusesTheOtherKindOfDocument(t *testing.T) {
	// The two are read into the same claims and mean different things around
	// them, so each refusal names the route that does take the document.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)

		asAdvisory := r.Advised(t, "admin", "vex.json",
			httpapitest.Said("not_affected", "vulnerable_code_not_present", ""))
		httpapitest.RefusedWith(t, asAdvisory, http.StatusUnprocessableEntity)
		asVex := r.Vexed(t, "admin", "example",
			httpapitest.SupplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0"))
		httpapitest.RefusedWith(t, asVex, http.StatusUnprocessableEntity)
		if !strings.Contains(asVex.Body.String(), "supplier advisory") {
			t.Errorf("the refusal does not say where it goes: %s", asVex.Body.String())
		}
	})
}

func TestAnAdvisorysPrefillIsSomethingAPersonStillHasToRecord(t *testing.T) {
	// The half of "evidence, never a decision" that an empty list cannot
	// show: the field that stays empty when an advisory is uploaded is the
	// one that fills when a person acts on it, so the assertion above is a
	// check rather than a sentence that cannot be false.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		if got := r.Advised(t, "admin", "exsa.json",
			httpapitest.SupplierAdvisory("EXSA-2026:1001", "known_not_affected",
				"3.7.0")); got.Code != http.StatusCreated {
			t.Fatalf("uploading answered %d: %s", got.Code, got.Body.String())
		}
		before := r.WhatPublishersSay(t)
		if len(before.Standing) != 0 {
			t.Fatalf("uploading decided %d things", len(before.Standing))
		}
		cited := before.Said
		if len(cited) != 1 {
			t.Fatalf("the finding offers %+v to cite", cited)
		}
		if cited[0].Offers != "not-applicable" {
			t.Fatalf("it offers %q", cited[0].Offers)
		}

		var said struct {
			Said []struct {
				ID int64 `json:"id"`
			} `json:"said"`
		}
		httpapitest.Read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-9999/components/libnl-3-200", &said)
		made := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-9999/places/"+place+"/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_present",`+
				`"reasoning":"The supplier says this build is not affected.",`+
				`"from_statement":`+httpapitest.Itoa(said.Said[0].ID)+`}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding answered %d: %s", made.Code, made.Body.String())
		}
		if after := r.WhatPublishersSay(t); len(after.Standing) != 1 {
			t.Errorf("after a person decided, %d things stand", len(after.Standing))
		}
	})
}

func TestANameLongerThanTheRecordIsRefusedRatherThanShortened(t *testing.T) {
	// Both names are part of the key a later upload replaces on, and both are
	// stored in a column of a fixed width. Shortened, two advisories agreeing
	// for the width of the column collapse into one, and a revision of one
	// sets aside claims it has nothing to do with.
	//
	// Two layers refuse and either alone is enough, the way the scope and the
	// handler check are: the endpoint, and the store behind it, which is
	// reachable from any other caller. Both have to go before this fails.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		tooLong := strings.Repeat("x", 200)

		named := r.Advised(t, "admin", "exsa.json",
			httpapitest.SupplierAdvisory(tooLong, "fixed", "3.7.0"))
		httpapitest.RefusedWith(t, named, http.StatusUnprocessableEntity)
		if !strings.Contains(named.Body.String(), "the name the publisher gave it") {
			t.Errorf("the refusal does not say which name is too long: %s", named.Body.String())
		}

		published := strings.Replace(httpapitest.SupplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0"),
			`"name": "Example Distribution"`, `"name": "`+tooLong+`"`, 1)
		who := r.Advised(t, "admin", "exsa.json", published)
		httpapitest.RefusedWith(t, who, http.StatusUnprocessableEntity)
		if !strings.Contains(who.Body.String(), "who published it") {
			t.Errorf("the refusal does not say which name is too long: %s", who.Body.String())
		}
	})
}
