// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// An administrator inspects an upstream that signs nothing and trusts it with
// no fingerprint; a fingerprint is refused, and stopping trusting it leaves the
// product trusting none.
func TestAnUpstreamThatSignsNothingIsTrustedWithNoFingerprint(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		address, roots := httpapitest.UpstreamAt(t)
		r = r.Rebuilt(func(d *core.Deps) { d.UpstreamRoots = roots })
		const path = "/v1/products/mine/upstream"

		got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, path+"/inspection", `{"url":"`+address+`"}`)
		if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), "Example Upstream") {
			t.Fatalf("inspecting the upstream answered %d: %s", got.Code, got.Body.String())
		}
		got = httpapitest.AsPerson(t, r, "admin", http.MethodPut, path,
			`{"url":"`+address+`","fingerprint":"ABCD"}`)
		if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "names no signing key") {
			t.Errorf("trusting a key the upstream does not name answered %d: %s", got.Code, got.Body.String())
		}
		got = httpapitest.AsPerson(t, r, "triager", http.MethodPut, path, `{"url":"`+address+`"}`)
		if got.Code != http.StatusForbidden {
			t.Errorf("somebody who only triages trusted an upstream: %d", got.Code)
		}
		got = httpapitest.AsPerson(t, r, "admin", http.MethodPut, path, `{"url":"`+address+`"}`)
		if got.Code != http.StatusOK {
			t.Fatalf("trusting the upstream answered %d: %s", got.Code, got.Body.String())
		}
		var held struct {
			URL       string `json:"url"`
			Publisher string `json:"publisher"`
		}
		got = httpapitest.AsPerson(t, r, "admin", http.MethodGet, path, "")
		if err := json.Unmarshal(got.Body.Bytes(), &held); err != nil || held.URL != address ||
			held.Publisher != "Example Upstream" {
			t.Errorf("the product trusts %+v (%d), want the upstream named", held, got.Code)
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete, path, ""); got.Code != http.StatusNoContent {
			t.Fatalf("stopping trusting the upstream answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodGet, path, ""); got.Code != http.StatusNotFound {
			t.Errorf("a product that stopped trusting its upstream answered %d", got.Code)
		}
	})
}

// upstreamHeld is what the API says a product trusts.
type upstreamHeld struct {
	URL         string `json:"url"`
	Fingerprint string `json:"fingerprint"`
	KeyOffered  string `json:"key_offered"`
}

// heldUpstream reads what mine trusts.
func heldUpstream(t *testing.T, r *httpapitest.Reach) upstreamHeld {
	t.Helper()
	got := httpapitest.AsPerson(t, r, "admin", http.MethodGet, "/v1/products/mine/upstream", "")
	var held upstreamHeld
	if got.Code != http.StatusOK {
		t.Fatalf("reading the upstream answered %d: %s", got.Code, got.Body.String())
	}
	if err := json.Unmarshal(got.Body.Bytes(), &held); err != nil {
		t.Fatal(err)
	}
	return held
}

// An upstream that signs is trusted only with the fingerprint of the key it
// serves; another is refused naming the one served, and nothing is trusted.
func TestASigningUpstreamIsTrustedOnlyWithTheKeyItServes(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		address, roots, fingerprint := httpapitest.SignedUpstreamAt(t)
		_, _, another := httpapitest.SignedUpstreamAt(t)
		r = r.Rebuilt(func(d *core.Deps) { d.UpstreamRoots = roots })
		const path = "/v1/products/mine/upstream"

		got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, path,
			`{"url":"`+address+`","fingerprint":"`+another+`"}`)
		if got.Code != http.StatusConflict || !strings.Contains(got.Body.String(), "signs with "+fingerprint) {
			t.Errorf("trusting a key other than the one served answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodGet, path, ""); got.Code != http.StatusNotFound {
			t.Errorf("a refused trust left the product trusting something: %d %s", got.Code, got.Body.String())
		}
		// The fingerprint as a person copies it, grouped and in lower case.
		said := strings.ToLower(fingerprint[:4] + " " + fingerprint[4:])
		got = httpapitest.AsPerson(t, r, "admin", http.MethodPut, path,
			`{"url":"`+address+`","fingerprint":"`+said+`"}`)
		if got.Code != http.StatusOK {
			t.Fatalf("trusting the key served answered %d: %s", got.Code, got.Body.String())
		}
		if held := heldUpstream(t, r); held.URL != address || held.Fingerprint != fingerprint {
			t.Errorf("the product trusts %+v, want %s with key %s", held, address, fingerprint)
		}
	})
}

// Another address is the same upstream moved: no fingerprint is asked for,
// the key already trusted stays trusted, a different key the new address
// names is offered rather than trusted, and the trail says what was trusted
// before.
func TestAnUpstreamMovedToAnotherAddressKeepsTheKeyItTrusted(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		address, roots, fingerprint := httpapitest.SignedUpstreamAt(t)
		moved, movedRoots, offered := httpapitest.SignedUpstreamAt(t)
		r = r.Rebuilt(func(d *core.Deps) { d.UpstreamRoots = roots })
		const path = "/v1/products/mine/upstream"
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, path,
			`{"url":"`+address+`","fingerprint":"`+fingerprint+`"}`); got.Code != http.StatusOK {
			t.Fatalf("trusting the upstream answered %d: %s", got.Code, got.Body.String())
		}

		r = r.Rebuilt(func(d *core.Deps) { d.UpstreamRoots = movedRoots })
		got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, path, `{"url":"`+moved+`"}`)
		if got.Code != http.StatusOK {
			t.Fatalf("moving the upstream answered %d: %s", got.Code, got.Body.String())
		}
		held := heldUpstream(t, r)
		if held.URL != moved || held.Fingerprint != fingerprint || held.KeyOffered != offered {
			t.Errorf("after the move the product trusts %+v, want %s still checked against %s with %s offered",
				held, moved, fingerprint, offered)
		}

		var rows []trail.Change
		if err := r.DB.DB.NewSelect().Model(&rows).Where(`"kind" = ?`, trail.Upstream).
			Order("id").Scan(t.Context()); err != nil {
			t.Fatal(err)
		}
		want := address + " (key " + fingerprint + ")"
		if len(rows) != 2 || rows[1].Was == nil || *rows[1].Was != want {
			t.Errorf("the trail holds %+v, want the move recorded with %q before it", rows, want)
		}
	})
}

// Somebody who triages the product declines one of its upstream's
// statements; to somebody who only reads it, the statement does not exist.
func TestAnUpstreamsStatementIsDeclinedBySomebodyWhoTriages(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		path := "/v1/statements/" + httpapitest.Itoa(r.UpstreamStatement(t)) + "/declined"
		if got := httpapitest.AsPerson(t, r, "reader", http.MethodPut, path, ""); got.Code != http.StatusForbidden &&
			got.Code != http.StatusNotFound {
			t.Errorf("somebody who only reads the product declined a statement: %d", got.Code)
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPut, path, ""); got.Code != http.StatusNoContent {
			t.Fatalf("declining a statement answered %d: %s", got.Code, got.Body.String())
		}
		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			"/v1/products/mine/components/zlib/upstream-statements", "")
		if got.Code != http.StatusOK || !strings.Contains(got.Body.String(), `"declined":true`) {
			t.Errorf("the component's upstream statements answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodDelete, path, ""); got.Code != http.StatusNoContent {
			t.Errorf("restoring a statement answered %d: %s", got.Code, got.Body.String())
		}
	})
}

// Declining, restoring and stopping trusting each change what closes the
// product's findings, so each queues the product's scanned builds to be
// scanned again in the act itself.
func TestEachUpstreamReversalQueuesTheProductsBuilds(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		address, roots := httpapitest.UpstreamAt(t)
		r = r.Rebuilt(func(d *core.Deps) { d.UpstreamRoots = roots })
		r.Scanned(t)
		statement := "/v1/statements/" + httpapitest.Itoa(r.UpstreamStatement(t)) + "/declined"
		queued := func(what string) {
			t.Helper()
			var waiting []string
			if err := r.DB.DB.NewSelect().Model((*queue.Job)(nil)).Column("reference").
				Where(`"kind" = ?`, queue.Scan).Where(`"state" = ?`, queue.Pending).
				Scan(t.Context(), &waiting); err != nil {
				t.Fatal(err)
			}
			if len(waiting) == 0 {
				t.Errorf("%s queued no scan of the product's build", what)
			}
			if _, err := r.DB.DB.NewDelete().Model((*queue.Job)(nil)).Where("1 = 1").Exec(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.DB.DB.NewDelete().Model((*queue.Job)(nil)).Where("1 = 1").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodPut, statement, ""); got.Code != http.StatusNoContent {
			t.Fatalf("declining answered %d", got.Code)
		}
		queued("declining a statement")
		if got := httpapitest.AsPerson(t, r, "triager", http.MethodDelete, statement, ""); got.Code != http.StatusNoContent {
			t.Fatalf("restoring answered %d", got.Code)
		}
		queued("restoring a statement")
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPut, "/v1/products/mine/upstream",
			`{"url":"`+address+`"}`); got.Code != http.StatusOK {
			t.Fatalf("trusting answered %d: %s", got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodDelete, "/v1/products/mine/upstream", ""); got.Code != http.StatusNoContent {
			t.Fatalf("stopping trusting answered %d", got.Code)
		}
		queued("stopping trusting the upstream")
	})
}
