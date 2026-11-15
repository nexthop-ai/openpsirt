// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// went is a row of the published list, read as a client reads it: the fields
// asserted here, by their names on the wire.
type went struct {
	Advisory string `json:"advisory"`
	Ordinal  int    `json:"ordinal"`
	Digest   string `json:"digest"`
}

func published(t *testing.T, r *httpapitest.Reach, who string) []went {
	t.Helper()
	return listedAt(t, r, who, "/v1/advisories/published")
}

// listedAt is the published list as somebody reads it at one address.
func listedAt(t *testing.T, r *httpapitest.Reach, who, path string) []went {
	t.Helper()
	got := httpapitest.AsPerson(t, r, who, http.MethodGet, path, "")
	if got.Code != http.StatusOK {
		t.Fatalf("%s asking what has been published answered %d: %s",
			who, got.Code, got.Body.String())
	}
	var out struct {
		Items []went `json:"items"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
		t.Fatalf("it is not JSON: %v (%s)", err, got.Body.String())
	}
	return out.Items
}

func TestAnAdvisoryAboutAnUndisclosedFlawIsNotListedToSomebodyWhoMayNotReadIt(t *testing.T) {
	// An issuance carries no visibility of its own, so the row has to be
	// narrowed by the flaw it was written about. Reading one as public
	// because it has no visibility column would announce an undisclosed flaw
	// in the report about announcements — and the row names the identifier,
	// which is the whole of what REQ-48 keeps out of anything leaving here.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		issued(t, r, false)

		if rows := published(t, r, "triager"); len(rows) != 0 {
			t.Errorf("somebody who may not read undisclosed work was told about it: %+v", rows)
		}
		// And somebody holding a different product entirely. The flaw's
		// visibility is the wrong question to ask them: asked alone it says
		// whether they read undisclosed work anywhere, and a public flaw in
		// a product they hold nothing on would pass it — carrying the
		// identifier, the title, the summary and the digest.
		if rows := published(t, r, "outsider"); len(rows) != 0 {
			t.Errorf("somebody holding another product was told what went out here: %+v", rows)
		}
		// And the other direction, which is what stops the narrowing being a
		// filter that hides everything from everybody.
		rows := published(t, r, "private-triage")
		if len(rows) != 1 {
			t.Fatalf("somebody who may read it saw %d advisories, want the one", len(rows))
		}
		if rows[0].Ordinal != 1 {
			t.Errorf("the first issuance reads as revision %d", rows[0].Ordinal)
		}
		if rows[0].Digest == "" {
			t.Error("no digest came back, so what was published cannot be compared")
		}
	})
}

// issued records a flaw in mine, disclosed or not, and publishes an advisory
// over it, holding that nothing was listed as published before it went out.
func issued(t *testing.T, r *httpapitest.Reach, disclosed bool) {
	t.Helper()
	r.ScannedWithEvidence(t)
	made := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
		"/v1/products/mine/findings",
		`{"builds":[{"branch_or_tag":"master","variant":"broadcom"}],`+
			`"summary":"The recovery console does not clear the previous session.",`+
			`"severity":"high","disclosed":`+strconv.FormatBool(disclosed)+`}`)
	if made.Code != http.StatusCreated {
		t.Fatalf("recording the flaw answered %d: %s", made.Code, made.Body.String())
	}
	var recorded struct {
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(made.Body.Bytes(), &recorded); err != nil {
		t.Fatal(err)
	}
	// Nothing has gone out yet, which is the half that makes the rest mean
	// something: a report answering the same before and after would pass
	// every assertion over it.
	if rows := published(t, r, "private-triage"); len(rows) != 0 {
		t.Fatalf("something was published before anything was: %+v", rows)
	}
	named := httpapitest.AdvisoryOver(t, r, "private-triage", "mine", recorded.Identifier)
	httpapitest.AgreedTo(t, r, "/v1/advisories/"+named)
	out := httpapitest.AsPerson(t, r, "private-triage", http.MethodPost,
		"/v1/advisories/"+named+"/issuance",
		`{"summary":"Sent to the coordinating body."}`)
	if out.Code != http.StatusCreated && out.Code != http.StatusOK {
		t.Fatalf("recording the issuance answered %d: %s", out.Code, out.Body.String())
	}
}

// TestThePublishedListNarrowsToTheProductAsked pins the product filter: an
// advisory is listed under the product it covers and under no other, and a
// product the reader cannot see is refused as one nobody declared.
func TestThePublishedListNarrowsToTheProductAsked(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		issued(t, r, true)
		if rows := listedAt(t, r, "estate-reader", "/v1/advisories/published?product=mine"); len(rows) != 1 {
			t.Errorf("the product the advisory covers lists %d advisories, want the one: %+v", len(rows), rows)
		}
		if rows := listedAt(t, r, "estate-reader", "/v1/advisories/published?product=theirs"); len(rows) != 0 {
			t.Errorf("a product the advisory does not cover lists %+v", rows)
		}
		httpapitest.RefusedWith(t, httpapitest.AsPerson(t, r, "reader", http.MethodGet,
			"/v1/advisories/published?product=theirs", ""), http.StatusNotFound)
	})
}
