package httpapi_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Routes nothing reached.
//
// Eighteen registered operations sat at the coverage their `huma.Register`
// call gets for running at suite start, and nothing else: the registration was
// exercised and the handler never was. Two of them write, one produces a
// document meant to be pasted into a customer release note, one deliberately
// bypasses the visibility check, and one stores a shared signing secret.
//
// What each needs is the same pair — the success shape, and a subject holding
// none of the declared roles refused with the exact status — so they are one
// table, with the cases that are particular to a route written out beneath it.

// reached is one operation driven through the real router.
type reached struct {
	what string
	// who asks, and what they get.
	who  string
	want int
	// refusedFor is somebody holding none of what the operation declares.
	refusedFor string
	refusal    int
	method     string
	path       string
	body       string
}

func TestTheRoutesNothingReachedAnswerAndRefuse(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		const build = "/v1/products/mine/streams/master/variants/broadcom"
		for _, c := range []reached{
			{
				what: "what is ready to ship", method: http.MethodGet,
				path: build + "/readiness",
				who:  "reader", want: http.StatusOK,
				refusedFor: "outsider", refusal: http.StatusNotFound,
			},
			{
				what: "what a build ships of one component", method: http.MethodGet,
				path: "/v1/products/mine/components/libnl-3-200",
				who:  "reader", want: http.StatusOK,
				refusedFor: "outsider", refusal: http.StatusNotFound,
			},
			{
				what: "where an issue reaches from a component", method: http.MethodGet,
				path: build + "/findings/CVE-2026-9999/components/libnl-3-200/reach",
				who:  "triager", want: http.StatusOK,
				refusedFor: "outsider", refusal: http.StatusNotFound,
			},
			{
				what: "what is owed and when", method: http.MethodGet,
				path: "/v1/remediation",
				who:  "reader", want: http.StatusOK,
				refusedFor: "", refusal: http.StatusUnauthorized,
			},
			{
				what: "what keeps being deferred", method: http.MethodGet,
				path: "/v1/deferrals/repeated",
				who:  "reader", want: http.StatusOK,
				refusedFor: "", refusal: http.StatusUnauthorized,
			},
			{
				// Named, because release over release is a question about one
				// product's line of releases: two products' tags interleave
				// by date and mean nothing side by side. Unnamed it is
				// refused rather than answered with an empty list, which is
				// what a product with no releases looks like.
				what: "how releases are trending", method: http.MethodGet,
				path: "/v1/trend/releases?product=mine",
				who:  "reader", want: http.StatusOK,
				refusedFor: "", refusal: http.StatusUnauthorized,
			},
			{
				what: "the chains somebody's own work sits on", method: http.MethodGet,
				path: build + "/components/mine",
				who:  "triager", want: http.StatusOK,
				refusedFor: "outsider", refusal: http.StatusNotFound,
			},
			{
				what: "what one release changed against another", method: http.MethodGet,
				path: "/v1/products/mine/comparison?from=master&from_variant=broadcom" +
					"&to=master&to_variant=broadcom",
				who: "reader", want: http.StatusOK,
				refusedFor: "outsider", refusal: http.StatusNotFound,
			},
			{
				what: "what to carry from another build", method: http.MethodGet,
				path: build + "/carried?from=master&from_variant=broadcom",
				who:  "triager", want: http.StatusOK,
				refusedFor: "outsider", refusal: http.StatusNotFound,
			},
			{
				what: "what somebody asks to be sent", method: http.MethodPut,
				path: "/v1/session/me/digest", body: `{"digest":true}`,
				who: "reader", want: http.StatusNoContent,
				refusedFor: "", refusal: http.StatusUnauthorized,
			},
		} {
			if got := asPerson(t, r, c.who, c.method, c.path, c.body); got.Code != c.want {
				t.Errorf("%s answered %s %d, want %d: %s",
					c.what, c.who, got.Code, c.want, got.Body.String())
			}
			if got := asPerson(t, r, c.refusedFor, c.method, c.path, c.body); got.Code != c.refusal {
				who := c.refusedFor
				if who == "" {
					who = "nobody"
				}
				t.Errorf("%s answered %s %d, want %d: %s",
					c.what, who, got.Code, c.refusal, got.Body.String())
			}
		}
	})
}

// TestADestinationIsNeverHandedBackWhatItIsSignedWith is the outbound trio.
//
// `add-outbound` is the only place the https-only and no-userinfo rules on a
// destination are enforced, and it stores a shared signing secret; the two
// store methods behind the listing and the retirement take no subject, so the
// only thing narrowing them is a check in the handler. No test named
// `/v1/outbound` at all.
func TestADestinationIsNeverHandedBackWhatItIsSignedWith(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		const secret = "sixteen-characters-at-least"
		const at = "/v1/outbound"

		// A plain reader and a product triager reach none of the three.
		for _, who := range []string{"reader", "triager"} {
			for _, c := range []struct {
				method, path, body string
			}{
				{http.MethodGet, at, ""},
				{http.MethodPost, at, `{"name":"theirs","kind":"*",` +
					`"url":"https://hooks.example.test/t/abc","secret":"` + secret + `"}`},
				{http.MethodDelete, at + "/theirs/*", ""},
			} {
				if got := asPerson(t, r, who, c.method, c.path, c.body); got.Code != http.StatusForbidden {
					t.Errorf("%s reached %s %s, answering %d", who, c.method, c.path, got.Code)
				}
			}
		}

		if got := asPerson(t, r, "admin", http.MethodPost, at,
			`{"name":"ops","kind":"*","url":"https://hooks.example.test/t/s3cr3t-path",`+
				`"secret":"`+secret+`"}`); got.Code != http.StatusCreated {
			t.Fatalf("recording a destination answered %d: %s", got.Code, got.Body.String())
		}

		// Never what it is signed with. For Slack and for Teams the
		// address is itself the credential — the path carries the token and
		// there is no other authentication — so neither may come back.
		listed := asPerson(t, r, "admin", http.MethodGet, at, "")
		if listed.Code != http.StatusOK {
			t.Fatalf("listing answered %d: %s", listed.Code, listed.Body.String())
		}
		if body := listed.Body.String(); strings.Contains(body, secret) {
			t.Errorf("the listing hands back the signing secret: %s", body)
		}
		// The secret, and not the address. For Slack and for Teams the
		// path carries the token and there is no other authentication, which
		// is why the trail row beside the create records the host alone — and
		// the listing hands the whole URL back regardless. That is not
		// asserted here because it is not true: `outbound.go` predates this
		// branch, and a test claiming a redaction nothing does would be worse
		// than none. `TODO.md` carries it.

		// And the rules on a destination are enforced here and nowhere else.
		for _, c := range []struct {
			what, url string
		}{
			{"a plain http address", "http://hooks.example.test/t/abc"},
			{"a name and password in the address",
				"https://hooks.slack.com@127.0.0.1/services/x"},
			{"an address that is not one", "not-an-address"},
		} {
			refusedWith(t, asPerson(t, r, "admin", http.MethodPost, at,
				`{"name":"bad","kind":"*","url":"`+c.url+`","secret":"`+secret+`"}`),
				http.StatusUnprocessableEntity)
		}
	})
}

// TestReleaseNotesNameNothingNobodyHasAnnounced drives the one route whose
// output is meant to be pasted into a customer release note.
//
// It writes text/markdown and nothing reached it. An undisclosed finding is
// counted there and never named: the document is the thing that leaves this
// deployment, so the rule that governs it is the one that governs an advisory.
func TestReleaseNotesNameNothingNobodyHasAnnounced(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		embargoed := r.embargoed(t)

		const notes = "/v1/products/mine/comparison/notes" +
			"?from=master&from_variant=broadcom&to=master&to_variant=broadcom"

		got := asPerson(t, r, "private-triage", http.MethodGet, notes, "")
		if got.Code != http.StatusOK {
			t.Fatalf("release notes answered %d: %s", got.Code, got.Body.String())
		}
		if kind := got.Header().Get("Content-Type"); !strings.HasPrefix(kind, "text/markdown") {
			t.Errorf("release notes came back as %q, want text/markdown", kind)
		}
		// An undisclosed fix is counted and never named. That is the whole
		// rule this document is under: it is the thing that leaves the
		// deployment, so what governs it is what governs an advisory.
		if strings.Contains(got.Body.String(), embargoed) {
			t.Errorf("release notes name an undisclosed issue: %s", got.Body.String())
		}

		// And somebody holding nothing on the product does not get them.
		if refusedFor := asPerson(t, r, "outsider", http.MethodGet, notes,
			""); refusedFor.Code != http.StatusNotFound {
			t.Errorf("somebody holding nothing on the product read its release notes: %d",
				refusedFor.Code)
		}
	})
}

// TestClosingAFindingByHandGoesThroughTheRouteAndIsRefusedWithoutTheRight
// reaches `resolve-finding`, the act that closes findings, which was pinned
// nowhere through the router.
func TestClosingAFindingByHandGoesThroughTheRouteAndIsRefusedWithoutTheRight(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)

		// A flaw somebody recorded, because a scan is the authority on what it
		// found: only a hand-recorded one is closed this way. Disclosed, so
		// that the refusal below is about the right to close rather than about
		// the right to see it at all.
		recorded := asPerson(t, r, "triager", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+
				`"summary":"The management socket answers before anyone has authenticated.",`+
				`"severity":"high","component":"libnl-3-200","disclosed":true}`)
		if recorded.Code != http.StatusCreated {
			t.Fatalf("recording a flaw answered %d: %s", recorded.Code, recorded.Body.String())
		}
		var flaw struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(recorded.Body.Bytes(), &flaw); err != nil {
			t.Fatal(err)
		}

		at := "/v1/products/mine/streams/master/variants/broadcom/findings/" +
			flaw.Identifier + "/resolve"
		const body = `{"because":"The advisory was retracted."}`

		// Answered as a finding that is not there rather than as a refusal:
		// the per-product half of a requirement is resolved in the handler,
		// and it refuses the way every other read of one does.
		if got := asPerson(t, r, "reader", http.MethodPost, at, body); got.Code != http.StatusNotFound {
			t.Errorf("somebody who may not triage closed a finding, answering %d", got.Code)
		}

		got := asPerson(t, r, "triager", http.MethodPost, at, body)
		if got.Code != http.StatusOK {
			t.Fatalf("closing a finding answered %d: %s", got.Code, got.Body.String())
		}
		var closed struct {
			Closed int `json:"closed"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &closed); err != nil {
			t.Fatal(err)
		}
		if closed.Closed == 0 {
			t.Errorf("closing a finding reported %d closed: %s", closed.Closed, got.Body.String())
		}
	})
}

// TestNarrowingWhichBuildsAFlawAffectsClosesTheOnesDropped reaches the write
// whose counts nothing read back.
//
// The build-resolution loop decides which findings get closed as invalid, and
// the only test that reached the route asserted a refusal — so the success
// path, and both counts it publishes, were unpinned.
func TestNarrowingWhichBuildsAFlawAffectsClosesTheOnesDropped(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		r.scannedAlso(t, "mellanox", "3.7.0")

		// Recorded against two builds, then narrowed to one.
		recorded := asPerson(t, r, "triager", http.MethodPost, "/v1/products/mine/findings",
			`{"builds":[{"stream":"master","variant":"broadcom"},`+
				`{"stream":"master","variant":"mellanox"}],`+
				`"summary":"The management socket answers before anyone has authenticated.",`+
				`"severity":"high","component":"libnl-3-200","disclosed":true}`)
		if recorded.Code != http.StatusCreated {
			t.Fatalf("recording a flaw answered %d: %s", recorded.Code, recorded.Body.String())
		}
		var flaw struct {
			Identifier string `json:"identifier"`
		}
		if err := json.Unmarshal(recorded.Body.Bytes(), &flaw); err != nil {
			t.Fatal(err)
		}

		at := "/v1/products/mine/issues/" + flaw.Identifier + "/builds"
		got := asPerson(t, r, "triager", http.MethodPut, at,
			`{"builds":[{"stream":"master","variant":"broadcom"}],`+
				`"reason":"The mellanox build never shipped the component."}`)
		if got.Code != http.StatusOK {
			t.Fatalf("narrowing the builds answered %d: %s", got.Code, got.Body.String())
		}
		var affects struct {
			Added  int `json:"added"`
			Closed int `json:"closed"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &affects); err != nil {
			t.Fatal(err)
		}
		// Nothing added, and the dropped build's places closed. The counts are
		// what a caller acts on, and both came back from a handler nothing
		// had ever run.
		if affects.Added != 0 {
			t.Errorf("narrowing added %d builds, want none", affects.Added)
		}
		if affects.Closed == 0 {
			t.Errorf("narrowing closed %d, want the dropped build's places", affects.Closed)
		}

		// Taking a build out with no reason is refused: closing a finding as
		// never-affected is a judgment, and one with no reason is not.
		refusedWith(t, asPerson(t, r, "triager", http.MethodPut, at,
			`{"builds":[{"stream":"master","variant":"mellanox"}]}`),
			http.StatusUnprocessableEntity)
	})
}
