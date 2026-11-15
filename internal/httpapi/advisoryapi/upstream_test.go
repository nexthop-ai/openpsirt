// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/advisoryapi"
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

// offered records an upstream statement in product, held by no placement, about
// the issue at the component and version named, which is what an offer is.
func offered(t *testing.T, r *httpapitest.Reach, product, vulnerability, component, version string) {
	t.Helper()
	ctx := t.Context()
	held, err := catalog.NewStore(r.DB.DB).ProductByName(ctx, product)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := r.Rights.ByIdentity(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := finding.NewStore(r.DB.DB).RecordStatements(ctx,
		access.Subject{Kind: access.Person, ID: admin.ID}, held.ID, finding.Supplied{
			Source: finding.FromUpstream, Identifier: "VEX-upstream-" + product,
			Publisher: "Example Upstream", Document: "https://upstream.example.test/" + product + ".json",
			Digest: strings.Repeat("b", 64),
		}, []finding.Statement{{
			Vulnerability: vulnerability, Purl: "pkg:deb/debian/" + component + "@" + version,
			Component: component, About: version, Status: "not_affected",
			Justification: "vulnerable_code_not_present",
		}}); err != nil {
		t.Fatal(err)
	}
}

// What upstreams offer is listed only in the products the reader sees, named
// by product: across the estate, in one product, or in the other alone. A
// product named that the reader cannot see is refused as one nobody declared,
// and a pipeline key reads none of it.
func TestUpstreamOffersAreListedOnlyWhereTheReaderSees(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.Scanned(t)
		disclosed, _ := httpapitest.SeedTheirs(t, r)
		offered(t, r, "mine", "CVE-2026-9999", "libnl-3-200", "3.7.0")
		offered(t, r, "theirs", disclosed, "libestate", "2.1")

		listed := func(who, query string) []string {
			t.Helper()
			var out struct {
				Items []advisoryapi.OfferBody `json:"items"`
			}
			httpapitest.Read(t, r, who, "/v1/upstream-offers"+query, &out)
			var offers []string
			for _, one := range out.Items {
				offers = append(offers, one.Product+"/"+one.Issue+"/"+one.Component)
			}
			sort.Strings(offers)
			return offers
		}
		for _, c := range []struct{ who, query, want string }{
			{"estate-reader", "", "mine/CVE-2026-9999/libnl-3-200 theirs/" + disclosed + "/libestate"},
			{"estate-reader", "?product=theirs", "theirs/" + disclosed + "/libestate"},
			{"triager", "", "mine/CVE-2026-9999/libnl-3-200"},
			{"triager", "?product=mine", "mine/CVE-2026-9999/libnl-3-200"},
			{"outsider", "", "theirs/" + disclosed + "/libestate"},
		} {
			if got := strings.Join(listed(c.who, c.query), " "); got != c.want {
				t.Errorf("%s reading %q is offered %q, want %q", c.who, c.query, got, c.want)
			}
		}

		hidden := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/upstream-offers?product=theirs", "")
		undeclared := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/upstream-offers?product=nosuch", "")
		httpapitest.RefusedWith(t, hidden, http.StatusNotFound)
		if hidden.Body.String() != undeclared.Body.String() {
			t.Errorf("a hidden product answers %s, and one nobody declared %s", hidden.Body, undeclared.Body)
		}
		if got := r.AsKey(t, http.MethodGet, "/v1/upstream-offers"); got != http.StatusForbidden {
			t.Errorf("a pipeline key reading the offers answered %d, want 403", got)
		}
	})
}

// A component's upstream statements in a product the reader cannot see
// answer as a product nobody declared.
func TestUpstreamStatementsOfAHiddenProductAnswerLikeAnUndeclaredOne(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		disclosed, _ := httpapitest.SeedTheirs(t, r)
		offered(t, r, "theirs", disclosed, "libestate", "2.1")
		const at = "/components/libestate/upstream-statements"
		if got := httpapitest.AsPerson(t, r, "estate-reader", http.MethodGet, "/v1/products/theirs"+at, ""); got.Code != http.StatusOK ||
			!strings.Contains(got.Body.String(), strings.ToLower(disclosed)) {
			t.Fatalf("somebody who sees the product read its statements as %d: %s", got.Code, got.Body)
		}
		hidden := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/products/theirs"+at, "")
		undeclared := httpapitest.AsPerson(t, r, "triager", http.MethodGet, "/v1/products/nosuch"+at, "")
		httpapitest.RefusedWith(t, hidden, http.StatusNotFound)
		if hidden.Body.String() != undeclared.Body.String() {
			t.Errorf("a hidden product answers %s, and one nobody declared %s", hidden.Body, undeclared.Body)
		}
	})
}
