// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// declaredBody builds a body the endpoint would accept, so that what a test
// measures is the decision about the asker rather than a complaint about the
// request. A refusal that arrives because the body was wrong proves nothing
// about who may do what.
func declaredBody(method, path, name string) io.Reader {
	if method == http.MethodPut && strings.HasSuffix(path, "/triage-floor") {
		return strings.NewReader(`{"floor": "high"}`)
	}
	if method == http.MethodPut && strings.HasSuffix(path, "/pair-thresholds") {
		return strings.NewReader(`{"share": 90, "approvers": 4}`)
	}
	if method == http.MethodPut && strings.HasSuffix(path, "/end-of-life") {
		return strings.NewReader(`{"on": "2030-01-01"}`)
	}
	if method == http.MethodPut && strings.HasSuffix(path, "/issue") {
		return strings.NewReader(`{"vulnerability": "CVE-2026-9999"}`)
	}
	if method != http.MethodPost {
		return nil
	}
	if strings.HasSuffix(path, "/reports") {
		return strings.NewReader(`{"summary": "` + name + `"}`)
	}
	if strings.HasSuffix(path, "/streams") {
		return strings.NewReader(`{"name": "` + name + `", "kind": "branch"}`)
	}
	if strings.HasSuffix(path, "/exploited-here") {
		return strings.NewReader(
			`{"known_at": "2026-09-20T14:00:00Z", "grounds": "A customer sent captures."}`)
	}
	if strings.HasSuffix(path, "/roles/bindings") {
		// A body the schema accepts, so that a refusal is about the asker
		// rather than about the request. Validation runs before the handler,
		// so an invalid body answers 422 whoever sends it — which measures
		// nothing about who may bind a group to a role.
		return strings.NewReader(`{"group": "` + name + `", "product": "mine", "role": "public-read"}`)
	}
	return strings.NewReader(`{"name": "` + name + `"}`)
}

// fromOurOwnPage makes a request look like one a browser made from a page this
// deployment served, which is what every ordinary request is.
//
// A browser states the origin of the page that caused a state-changing
// request, and will not let a page lie about it — so a request that states
// none is not one a browser made from our own page, and is refused. Tests that
// authenticate through the proxy header have to say so, or every write they
// make is measuring the forgery guard instead of the thing under test.
func fromOurOwnPage(req *http.Request) {
	req.Header.Set("Origin", "http://"+req.Host)
}

// reach is a server with two products and people holding various things, so
// that every combination of who-asks and what-they-ask-for can be checked
// rather than a representative few.
type reach struct {
	handler http.Handler
	key     string
	revoked string
	// rights is the store behind the handler, so a test can sign somebody in
	// without a provider to sign in through.
	rights *access.Store
	// db is the same database the handler reads, so a test can put a scanned
	// build behind it. Reading what has been decided is only testable against
	// something that was found.
	db *database.DB
	// api is the document the server builds from its own registrations, so a
	// test can walk every operation rather than a list somebody maintains.
	api huma.API
}

// response is what came back, for the tests that compare answers rather than
// just status codes.
type response struct {
	code int
	text string
}

// body makes a request as somebody and keeps what came back.
func (r *reach) body(t *testing.T, who, method, path string) response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if who != "" {
		req.Header.Set(testHeader, who)
	}
	fromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return response{code: rec.Code, text: rec.Body.String()}
}

// withKey makes a request presenting a credential.
func (r *reach) withKey(t *testing.T, secret, method, path string) response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return response{code: rec.Code, text: rec.Body.String()}
}

func (r *reach) as(t *testing.T, who, method, path string) int {
	t.Helper()
	// A well-formed body, so that what is being measured is the decision about
	// the asker rather than a complaint about the request.
	req := httptest.NewRequest(method, path, declaredBody(method, path, "declared-by-the-test"))
	if method == http.MethodPost || method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}
	if who != "" {
		req.Header.Set(testHeader, who)
	}
	fromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec.Code
}

func (r *reach) asKey(t *testing.T, method, path string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, declaredBody(method, path, "declared-by-a-pipeline"))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+r.key)
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec.Code
}

// engines is dbtest.Each or dbtest.Two.
type engines = func(t *testing.T, fn func(t *testing.T, db *database.DB))

// withCast is castSeed.Each or castSeed.Two: engines, from the seeded world.
type withCast = func(t *testing.T, fn func(t *testing.T, db *database.DB, made cast))

// The four-engine form and the two-engine form of the same fixture. Which
// one a test uses is decided by the rule at dbtest.Two: a test that pins what
// a query does — what a list contains, what a filter hides, what a conflict
// looks like, what text comes back — runs on every engine, and a test that
// pins routing, who may reach what, or the shape of a response runs on two.
func eachReach(t *testing.T, fn func(t *testing.T, r *reach)) {
	t.Helper()
	reachOn(t, castSeed.Each, fn)
}

func twoReach(t *testing.T, fn func(t *testing.T, r *reach)) {
	t.Helper()
	reachOn(t, castSeed.Two, fn)
}

func reachOn(t *testing.T, on withCast, fn func(t *testing.T, r *reach)) {
	t.Helper()
	reachAs(t, on, publisher.Named{
		Name: "Example Networks", Namespace: "https://example.test",
		// The prefix a minted advisory identifier opens with. A deployment
		// that has not been told cannot start one, which is a case of its own
		// and has its own test.
		Prefix: "EXNET",
	}, fn)
}

// cast is what the seeded world hands a test: the secrets of the two API
// keys it minted, which are shown once and so travel with the rows.
type cast struct {
	key, revoked string
}

// castSeed is the world every test here reaches into — two products, one of
// them built, and one person per way of holding rights — seeded once per
// binary on SQLite and per test on a server.
var castSeed = dbtest.Seed(seedCast)

func seedCast(ctx context.Context, db *database.DB) (cast, error) {
	cat := catalog.NewStore(db.DB)
	mine, err := cat.DeclareProduct(ctx, "mine", shownAs("mine"))
	if err != nil {
		return cast{}, err
	}
	if _, err := cat.DeclareStream(ctx, mine.ID, "master", catalog.Branch, nil); err != nil {
		return cast{}, err
	}
	if _, err := cat.DeclareVariant(ctx, mine.ID, "broadcom", true); err != nil {
		return cast{}, err
	}
	theirs, err := cat.DeclareProduct(ctx, "theirs", shownAs("theirs"))
	if err != nil {
		return cast{}, err
	}
	theirBranch, err := cat.DeclareStream(ctx, theirs.ID, "master", catalog.Branch, nil)
	if err != nil {
		return cast{}, err
	}
	theirVariant, err := cat.DeclareVariant(ctx, theirs.ID, "mellanox", true)
	if err != nil {
		return cast{}, err
	}

	// A build under each product, so that anything answering "what exists
	// here" has something to answer with. Without these the catalog has
	// products and no builds, and every test of what a reader may see is
	// satisfied by an empty list — which is also what a missing visibility
	// filter looks like.
	mineBranch, err := cat.StreamByName(ctx, mine.ID, "master")
	if err != nil {
		return cast{}, err
	}
	mineVariant, err := cat.VariantByName(ctx, mine.ID, "broadcom")
	if err != nil {
		return cast{}, err
	}
	if _, err := cat.TargetFor(ctx, mineBranch.ID, mineVariant.ID); err != nil {
		return cast{}, err
	}
	if _, err := cat.TargetFor(ctx, theirBranch.ID, theirVariant.ID); err != nil {
		return cast{}, err
	}

	// Everybody here is seeded with a display name that is not their
	// identity. access.Store.Names answers the display name, so a field
	// publishing the label where the identity belongs reads differently
	// from one publishing the identity, and a route that resolves the
	// field it listed fails to find the label.
	rights := access.NewStore(db.DB)
	administrator, err := rights.Ensure(ctx, "admin", shownAs("admin"), access.Stated(true), nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.Claim(ctx, administrator.ID, "admin"); err != nil {
		return cast{}, err
	}
	// An administrator who granted themselves reading, which is
	// how one reaches findings since an administrator stopped
	// reading by administering — and the point of the pair is that
	// the grant is visible in the same record as everybody else's
	// rather than implied by the flag.
	adminReader, err := rights.Ensure(ctx, "admin-reader", shownAs("admin-reader"), access.Stated(true), nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.Claim(ctx, adminReader.ID, "admin-reader"); err != nil {
		return cast{}, err
	}
	for _, role := range []access.Role{access.PublicRead, access.PrivateRead} {
		if err := rights.GrantRole(ctx, adminReader.ID, mine.ID, role); err != nil {
			return cast{}, err
		}
	}
	// Somebody holding the audit permission and no role at all: the
	// whole of what it is for is a reader of the deployment's own records
	// who reaches no product, so the identity that tests it holds nothing
	// else.
	auditor, err := rights.Ensure(ctx, "auditor", shownAs("auditor"), nil, access.Stated(true))
	if err != nil {
		return cast{}, err
	}
	if err := rights.Claim(ctx, auditor.ID, "auditor"); err != nil {
		return cast{}, err
	}
	// One entry per identity, and more than one role where the
	// point of the identity is what holding both allows. "triager"
	// deliberately holds triage alone: taking unowned work is
	// theirs and giving work to somebody else is not, and a cast
	// where everybody could do both would test neither.
	for who, roles := range map[string][]access.Role{
		"reader": {access.PublicRead},
		// Reading at both visibilities. Each is its own grant, and the
		// identities named for undisclosed work are the ones that hold
		// all of it; the ones holding the undisclosed half alone are
		// named for that.
		"private":  {access.PublicRead, access.PrivateRead},
		"triager":  {access.PublicTriage},
		"assigner": {access.PublicTriage, access.Assigner},
		// The capability without the triage right it sits on, plus enough
		// to see the product — otherwise the conjunction is untestable,
		// since a subject who reaches nothing is refused before any role
		// is consulted. Assigning is triage *and* assigner, and this is
		// the identity that shows it.
		"dispatcher":     {access.PublicRead, access.Assigner},
		"private-triage": {access.PublicTriage, access.PrivateTriage},
		// Triage at both visibilities plus the right to hand work to
		// somebody else, for the tests about what a recipient is told.
		"private-dispatcher": {access.PublicTriage, access.PrivateTriage, access.Assigner},
		// The undisclosed half alone: somebody working private reports
		// who is not handed the disclosed stream.
		"embargo-reader":  {access.PrivateRead},
		"embargo-triager": {access.PrivateTriage},
		// Reading the disclosed half and triaging the undisclosed one:
		// a right asked at one visibility is answered at that one, and
		// this is the identity where the two answers differ.
		"split-triager": {access.PublicRead, access.PrivateTriage},
		"approver":      {access.Approver},
		// Assigning is the other capability that grants
		// nothing on its own, and the dispatcher above holds
		// it alongside a read role, so this is the identity
		// that holds it bare.
		"assigner-only": {access.Assigner},
	} {
		person, err := rights.Ensure(ctx, who, shownAs(who), nil, nil)
		if err != nil {
			return cast{}, err
		}
		// Recording somebody is not the same as recording how they sign
		// in. The proxy path matches on what the proxy asserts, so that
		// has to be claimed for them or they are somebody with access and
		// no door to come through.
		if err := rights.Claim(ctx, person.ID, who); err != nil {
			return cast{}, err
		}
		for _, role := range roles {
			if err := rights.GrantRole(ctx, person.ID, mine.ID, role); err != nil {
				return cast{}, err
			}
		}
	}
	// A capability plus the visibility it acts on, which is what an
	// approver is actually granted in a deployment. The approver above
	// holds the capability alone, and reaches nothing — that is the rule
	// being pinned, not an oversight.
	reviewer, err := rights.Ensure(ctx, "reviewer", shownAs("reviewer"), nil, nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.Claim(ctx, reviewer.ID, "reviewer"); err != nil {
		return cast{}, err
	}
	for _, role := range []access.Role{access.PublicRead, access.Approver} {
		if err := rights.GrantRole(ctx, reviewer.ID, mine.ID, role); err != nil {
			return cast{}, err
		}
	}

	// A role held across every product rather than against one, which is
	// how a security team holds the estate. Granted disclosed reading
	// deliberately: the hazard is that "every product" is read as "no
	// narrowing at all", which would hand this identity the undisclosed
	// findings in both products (REQ-42 and REQ-43).
	estate, err := rights.Ensure(ctx, "estate-reader", shownAs("estate-reader"), nil, nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.Claim(ctx, estate.ID, "estate-reader"); err != nil {
		return cast{}, err
	}
	if err := rights.GrantEstateRole(ctx, estate.ID, access.PublicRead); err != nil {
		return cast{}, err
	}

	// The same shape holding triage rather than reading, so that "holds
	// the role everywhere" and "may act on this issue here" can be told
	// apart: an issue a product does not carry is not one anybody rates
	// through it, however widely they are trusted.
	estateTriage, err := rights.Ensure(ctx, "wide-triager", shownAs("wide-triager"), nil, nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.Claim(ctx, estateTriage.ID, "wide-triager"); err != nil {
		return cast{}, err
	}
	if err := rights.GrantEstateRole(ctx, estateTriage.ID, access.PublicTriage); err != nil {
		return cast{}, err
	}

	// Somebody holding a role on the other product and nothing on this
	// one. Not "nothing": a subject granted nothing anywhere is refused at
	// the door, so a case grant is untestable through them — and a case is
	// exactly what somebody outside a product is brought into.
	outsider, err := rights.Ensure(ctx, "outsider", shownAs("outsider"), nil, nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.Claim(ctx, outsider.ID, "outsider"); err != nil {
		return cast{}, err
	}
	if err := rights.GrantRole(ctx, outsider.ID, theirs.ID, access.PublicRead); err != nil {
		return cast{}, err
	}

	// Somebody who exists and was granted nothing at all.
	ungranted, err := rights.Ensure(ctx, "nothing", shownAs("nothing"), nil, nil)
	if err != nil {
		return cast{}, err
	}
	if err := rights.Claim(ctx, ungranted.ID, "nothing"); err != nil {
		return cast{}, err
	}
	_, secret, err := rights.NewKey(ctx, "nightly", access.Scope{ProductID: mine.ID})
	if err != nil {
		return cast{}, err
	}
	withdrawn, revokedSecret, err := rights.NewKey(ctx, "retired", access.Scope{ProductID: mine.ID})
	if err != nil {
		return cast{}, err
	}
	if err := rights.Revoke(ctx, withdrawn.ID); err != nil {
		return cast{}, err
	}
	return cast{key: secret, revoked: revokedSecret}, nil
}

// reachAs is reachOn for a test that needs the deployment configured
// differently — the one that has not been told who it publishes as.
func reachAs(t *testing.T, on withCast, as publisher.Named, fn func(t *testing.T, r *reach)) {
	t.Helper()
	on(t, func(t *testing.T, db *database.DB, made cast) {
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		rights := access.NewStore(db.DB)
		sources, err := access.ParseSources("192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		// A place for attachments, so the operations that carry REQ-70's
		// control answer rather than saying the deployment holds none.
		files, err := attach.NewFiles(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		handler, api := httpapi.New(quiet, nil, httpapi.Ingest{
			DB: db, Queue: queue.New(db, queue.DefaultOptions()), Files: files,
			Access: access.NewResolver(rights, access.Trust{Header: testHeader, From: sources}),
			// The identity this deployment publishes as, which an advisory
			// and a VEX document both need. Passed in, because the deployment
			// that has not been told is a case of its own.
			Publisher: as,
			// The names this deployment calls its own, derived from the
			// namespace it publishes under exactly as the binary derives it.
			// Restated here it is a second boundary that agrees until one
			// moves.
			Ours: currency.Ourselves(as.Namespace, nil),
		})
		fn(t, &reach{handler: handler, key: made.key, revoked: made.revoked,
			rights: rights, db: db, api: api})
	})
}

func TestWhoMayReachWhat(t *testing.T) {
	// The matrix rather than a few representative cases. What leaks is never
	// the endpoint somebody thought about.
	//
	// A product somebody cannot see answers as not declared, which is the same
	// answer a name nobody ever declared gets. That is what invisible means,
	// and it is why so many rows below expect 404 where 403 would look more
	// natural.
	eachReach(t, func(t *testing.T, r *reach) {
		const (
			products   = "/v1/products"
			mine       = "/v1/products/mine/streams"
			mineVars   = "/v1/products/mine/variants"
			mineBuilt  = "/v1/products/mine/streams/master/variants"
			theirs     = "/v1/products/theirs/streams"
			theirsVars = "/v1/products/theirs/variants"
			absent     = "/v1/products/nosuch/streams"
			version    = "/v1/version"

			mineFound = "/v1/products/mine/findings?stream=master&variant=broadcom"
			mineFloor = "/v1/products/mine/triage-floor"
			mineEOL   = "/v1/products/mine/end-of-life"
			streamEOL = "/v1/products/mine/streams/master/end-of-life"
			mineScans = "/v1/products/mine/streams/master/variants/broadcom/scans"
			// What one upload changed about the build's inventory. Reached
			// on the same terms the receipt carrying its counts is: they are
			// one answer read twice.
			mineMoved  = mineScans + "/1/changes"
			theirMoved = "/v1/products/theirs/streams/master/variants/broadcom/scans/1/changes"
			theirFound = "/v1/products/theirs/findings?stream=master&variant=broadcom"
			// The same list with the branch and the variant left
			// at "all". Widening the selection is exactly the
			// shape that leaves a check behind on the narrow path.
			mineWhole  = "/v1/products/mine/findings"
			theirWhole = "/v1/products/theirs/findings"
			// Recording that a product was exploited through an issue, which
			// refuses a dismissal somebody would otherwise be free to make
			// and moves where this product's findings sit.
			mineAttacked   = "/v1/products/mine/issues/CVE-2026-0001/exploited-here"
			theirsAttacked = "/v1/products/theirs/issues/CVE-2026-0001/exploited-here"
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

			// A product's triage line hides findings, which
			// is the act every other part of this gates. No role granted per
			// product carries it, so it is the same authority that sets the
			// deployment's line.
			{"reader", http.MethodPut, mineFloor, http.StatusForbidden},
			{"triager", http.MethodPut, mineFloor, http.StatusForbidden},
			{"approver", http.MethodPut, mineFloor, http.StatusForbidden},
			{"", http.MethodPut, mineFloor, http.StatusUnauthorized},
			{"nothing", http.MethodPut, mineFloor, http.StatusUnauthorized},
			{"admin", http.MethodPut, mineFloor, http.StatusNoContent},

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

			// Administration is administration. Holding every product role
			// there is does not amount to any of it.
			{"reader", http.MethodGet, people, http.StatusForbidden},
			{"private", http.MethodGet, people, http.StatusForbidden},
			{"triager", http.MethodGet, people, http.StatusForbidden},
			{"private-triage", http.MethodGet, people, http.StatusForbidden},
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

			// The source of roles, and what each group grants, is
			// administration like everything else that decides access.
			{"reader", http.MethodGet, "/v1/roles/mode", http.StatusForbidden},
			{"triager", http.MethodGet, "/v1/roles/bindings", http.StatusForbidden},
			{"approver", http.MethodPost, "/v1/roles/bindings", http.StatusForbidden},
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
			if got := r.as(t, c.who, c.method, c.path); got != c.want {
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
	eachReach(t, func(t *testing.T, r *reach) {
		for _, pair := range [][2]string{
			{"/v1/products/theirs/streams", "/v1/products/nosuch/streams"},
			{"/v1/products/theirs/variants", "/v1/products/nosuch/variants"},
			{"/v1/products/theirs/streams/master/variants", "/v1/products/nosuch/streams/master/variants"},
		} {
			hidden := r.body(t, "reader", http.MethodGet, pair[0])
			missing := r.body(t, "reader", http.MethodGet, pair[1])
			if hidden.code != missing.code {
				t.Errorf("%s answered %d and %s answered %d", pair[0], hidden.code, pair[1], missing.code)
			}
			if hidden.text == missing.text {
				continue
			}
			// The bodies name the thing asked for, which is what the asker
			// already typed. What must not differ is anything else.
			if strings.ReplaceAll(hidden.text, "theirs", "X") != strings.ReplaceAll(missing.text, "nosuch", "X") {
				t.Errorf("bodies differ beyond the name asked for:\n  hidden:  %s\n  missing: %s", hidden.text, missing.text)
			}
		}
	})
}

func TestEveryRefusalOfAStrangerReadsTheSame(t *testing.T) {
	// Unknown, known but granted nothing, and holding a revoked credential.
	// Told apart, they say whether a name or a key is real.
	twoReach(t, func(t *testing.T, r *reach) {
		unknown := r.body(t, "ghost", http.MethodGet, "/v1/products")
		ungranted := r.body(t, "nothing", http.MethodGet, "/v1/products")
		revoked := r.withKey(t, r.revoked, http.MethodGet, "/v1/products")

		for _, got := range []response{ungranted, revoked} {
			if got.code != unknown.code || got.text != unknown.text {
				t.Errorf("a refusal differs: %d %q against %d %q",
					got.code, got.text, unknown.code, unknown.text)
			}
		}
	})
}

func TestAPipelineCanReachNothingButSending(t *testing.T) {
	// A build server has no business holding a person's permissions, and this
	// is what keeps the visibility rules out of its reach entirely rather than
	// relying on them being applied to it correctly.
	twoReach(t, func(t *testing.T, r *reach) {
		for _, path := range []string{
			"/v1/products",
			"/v1/products/mine/streams",
			"/v1/products/mine/variants",
			"/v1/products/mine/streams/master/variants",
			"/v1/products/mine/findings?stream=master&variant=broadcom",
			"/v1/people",
			"/v1/keys",
			// A pipeline has no owner for a token to be a live reference to.
			"/v1/tokens",
			// Nor anything to argue about: a build server has no judgment.
			"/v1/review-queue",
			// Nor when anything was last scanned. A key reads back what it
			// sent; when a build was last scanned by anybody is a fact about
			// the deployment, and the answer names every build there is.
			"/v1/scanning",
			// Nor a notification area. A key is not a person and has nobody to
			// tell; its identifier comes from another table and would collide
			// with a person's.
			"/v1/notifications",
			"/v1/roles/mode",
			"/v1/roles/bindings",
		} {
			if got := r.asKey(t, http.MethodGet, path); got != http.StatusForbidden {
				t.Errorf("a pipeline reading %s answered %d, want 403", path, got)
			}
		}

		// The one exception, and it is not a reading role: a sender may read
		// back what became of what it sent. Without it an acceptance is
		// unverifiable by the only party that can act on a rejected file.
		if got := r.asKey(t, http.MethodGet,
			"/v1/products/mine/streams/master/variants/broadcom/scans"); got != http.StatusOK {
			t.Errorf("a pipeline could not read its own receipts: %d", got)
		}
		if got := r.asKey(t, http.MethodGet,
			"/v1/products/theirs/streams/master/variants/broadcom/scans"); got != http.StatusNotFound {
			t.Errorf("a pipeline reached receipts outside its scope: %d", got)
		}
		// And what one of its uploads changed, which is the detail behind the
		// counts on the receipt. A key holds no reading role, so this is
		// reached as the sender rather than as a reader — and outside its
		// scope it is the same refusal a receipt gets.
		if got := r.asKey(t, http.MethodGet,
			"/v1/products/mine/streams/master/variants/broadcom/scans/1/changes"); got != http.StatusOK {
			t.Errorf("a pipeline could not read what its own upload changed: %d", got)
		}
		if got := r.asKey(t, http.MethodGet,
			"/v1/products/theirs/streams/master/variants/broadcom/scans/1/changes"); got != http.StatusNotFound {
			t.Errorf("a pipeline reached an inventory outside its scope: %d", got)
		}
		if got := r.asKey(t, http.MethodGet, "/v1/version"); got != http.StatusForbidden {
			t.Errorf("a pipeline read the running version: %d", got)
		}
		if got := r.asKey(t, http.MethodPost, "/v1/products"); got == http.StatusCreated {
			t.Error("a pipeline declared a product")
		}
	})
}

func TestAListShowsOnlyWhatTheAskerHolds(t *testing.T) {
	// Counting is reading. A list that quietly includes what somebody may not
	// see is the same disclosure as showing it, and the product list is itself
	// a statement about what an organization ships.
	eachReach(t, func(t *testing.T, r *reach) {
		req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		req.Header.Set(testHeader, "reader")
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)

		body := rec.Body.String()
		if !contains(body, "mine") {
			t.Errorf("the product they hold something on is missing: %s", body)
		}
		if contains(body, "theirs") {
			t.Errorf("a product they hold nothing on was listed: %s", body)
		}
	})
}

func TestScanningShowsOnlyTheBuildsTheAskerHolds(t *testing.T) {
	// Counting is reading, and this one names every build there is: a list
	// that included one somebody holds nothing on would disclose that the
	// product exists, which is the thing every other refusal here is careful
	// not to say.
	eachReach(t, func(t *testing.T, r *reach) {
		req := httptest.NewRequest(http.MethodGet, "/v1/scanning", nil)
		req.Header.Set(testHeader, "reader")
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("a reader could not ask what has been scanned: %d", rec.Code)
		}
		body := rec.Body.String()
		// Both directions. "Theirs is absent" is also what an endpoint
		// answering nothing to everybody looks like, and a fixture that builds
		// no builds at all satisfies both.
		if !contains(body, "mine") {
			t.Errorf("the build they hold something on is missing: %s", body)
		}
		if contains(body, "theirs") {
			t.Errorf("a product they hold nothing on was listed: %s", body)
		}
	})
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

func TestNothingButTheProbesAnswersWithoutACredential(t *testing.T) {
	// Guarding one prefix leaves everything outside it open by default, and
	// the framework registers routes of its own: the API document and the
	// schemas it references are served to anybody who asks, including the
	// running version the endpoint reporting it is authenticated to
	// withhold.
	twoReach(t, func(t *testing.T, r *reach) {
		for _, path := range []string{
			"/openapi.json", "/openapi.yaml", "/openapi-3.0.json", "/openapi-3.0.yaml",
			"/schemas/VariantBody.json", "/docs",
			"/v1/version", "/v1/products", "/v1/scanning", "/v1/notifications",
		} {
			got := r.body(t, "", http.MethodGet, path)
			if got.code == http.StatusOK {
				t.Errorf("%s answered %d without a credential (%d bytes)", path, got.code, len(got.text))
			}
		}

		// And the probes still answer, because a container cannot sign in.
		for _, path := range []string{"/healthz", "/readyz"} {
			if got := r.body(t, "", http.MethodGet, path); got.code != http.StatusOK {
				t.Errorf("%s answered %d", path, got.code)
			}
		}

		// So does the list of ways in, which is what somebody sees before they
		// hold anything. It is the one reading endpoint outside the probes
		// that answers to a stranger, so what it discloses is asserted rather
		// than assumed: names an operator configured, and nothing about
		// whether any account exists.
		got := r.body(t, "", http.MethodGet, "/v1/sign-in")
		if got.code != http.StatusOK {
			t.Errorf("the sign-in providers answered %d to a stranger", got.code)
		}
		for _, leaked := range []string{"reader", "triager", "admin", "identity", "person"} {
			if strings.Contains(strings.ToLower(got.text), leaked) {
				t.Errorf("the providers list mentions %q: %s", leaked, got.text)
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
			got := r.body(t, "", http.MethodGet, path)
			if got.code == http.StatusOK && strings.TrimSpace(got.text) != "" {
				t.Errorf("%s answered %d to a stranger with a body: %s",
					path, got.code, got.text)
			}
			// Whatever it answers, it names nothing this deployment holds.
			for _, leaked := range []string{"reader", "triager", "admin", "mine", "theirs"} {
				if strings.Contains(strings.ToLower(got.text), leaked) {
					t.Errorf("%s mentioned %q to a stranger: %s", path, leaked, got.text)
				}
			}
		}
	})
}

func TestTheApiDocumentIsServedToSomebodyRecognized(t *testing.T) {
	// Closing it to strangers must not close it to the client that is
	// generated from it.
	twoReach(t, func(t *testing.T, r *reach) {
		if got := r.body(t, "reader", http.MethodGet, "/openapi.json"); got.code != http.StatusOK {
			t.Errorf("a recognized caller reading the API document got %d", got.code)
		}
	})
}

func TestAKeyReachesOnlyTheTargetItIsScopedTo(t *testing.T) {
	// The scope is checked at the endpoint, not only in the model. A key
	// covering one product must be refused another, and refused in a way that
	// does not say whether that other product exists.
	eachReach(t, func(t *testing.T, r *reach) {
		// A real document, because the body is validated before the handler
		// runs: a request with nothing in it is refused for being empty and
		// never reaches the question being asked here.
		sent := func(path string) response {
			req := upload(t, path, inventory(nowish(), "libc6"))
			req.Header.Set("Authorization", "Bearer "+r.key)
			rec := httptest.NewRecorder()
			r.handler.ServeHTTP(rec, req)
			return response{code: rec.Code, text: rec.Body.String()}
		}

		mine := sent("/v1/products/mine/streams/master/variants/broadcom/scans")
		if mine.code != http.StatusAccepted {
			t.Errorf("a key sending to its own product answered %d: %s", mine.code, mine.text)
		}

		elsewhere := sent("/v1/products/theirs/streams/master/variants/broadcom/scans")
		absent := sent("/v1/products/nosuch/streams/master/variants/broadcom/scans")
		if elsewhere.code != http.StatusNotFound {
			t.Errorf("a key reaching another product answered %d, want 404", elsewhere.code)
		}
		if elsewhere.code != absent.code {
			t.Errorf("another product answered %d and an absent one %d", elsewhere.code, absent.code)
		}

		req := upload(t, "/v1/products/mine/streams/master/variants/broadcom/scans",
			inventory(nowish(), "libc6"))
		req.Header.Set("Authorization", "Bearer "+r.revoked)
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		revoked := response{code: rec.Code}
		if revoked.code != http.StatusUnauthorized {
			t.Errorf("a revoked key answered %d, want 401", revoked.code)
		}
	})
}

func TestACredentialWinsOverAHeader(t *testing.T) {
	// A request carrying both is a build server's credential arriving through
	// something that also sets a header. The credential is what it holds; the
	// header is what somebody in front of it claimed.
	twoReach(t, func(t *testing.T, r *reach) {
		req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
		req.Header.Set("Authorization", "Bearer "+r.key)
		req.Header.Set(testHeader, "admin")
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("a request holding both answered %d; the key should decide and a key may not read", rec.Code)
		}
	})
}

func TestAMalformedCredentialIsRefused(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		for _, header := range []string{"", "Bearer", "Bearer ", "Basic " + r.key, r.key, "Bearer " + r.key + "x"} {
			req := httptest.NewRequest(http.MethodGet, "/v1/products", nil)
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			rec := httptest.NewRecorder()
			r.handler.ServeHTTP(rec, req)
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
	twoReach(t, func(t *testing.T, r *reach) {
		checked := 0
		for _, op := range r.api.OpenAPI().Paths {
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
				scope := declaredScope(t, asks)
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
				got := r.asKey(t, method, path)
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

// declaredScope reads the scope off an operation's declaration, whichever
// shape the document put it in.
func declaredScope(t *testing.T, asks any) string {
	t.Helper()
	encoded, err := json.Marshal(asks)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	return out.Scope
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

// saying is a provider that reports whether it has a source of groups, and
// nothing else. What is under test is the answer to that one question.
type saying struct {
	*stubProvider
	groups bool
}

func (s *saying) GroupsSource() bool { return s.groups }

func TestRolesCannotBeBoundToGroupsNothingCanReport(t *testing.T) {
	// The other door to the lockout the mode switch already guards. A provider
	// configured without a source of groups reports every arrival as belonging
	// to nothing, so in group-bound mode nobody derives any role — and the
	// deployment looks like a working one that admits nobody, including
	// whoever made the change.
	//
	// The OIDC adapter supplies a default for the username claim and none for
	// the groups claim, so this is the default configuration rather than an
	// exotic one.
	twoReach(t, func(t *testing.T, r *reach) {
		// Something has to administer in the new mode, or the check beside
		// this one refuses first and this would prove nothing.
		if err := r.rights.BindOver(t.Context(), "admins", access.Administers); err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			what   string
			groups bool
			want   int
		}{
			{"a provider that reports no groups", false, http.StatusConflict},
			{"a provider that does", true, http.StatusOK},
		} {
			handler := withProvider(t, r, c.groups)
			req := httptest.NewRequest(http.MethodPut, "/v1/roles/mode",
				strings.NewReader(`{"mode":"group-bound"}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(testHeader, "admin")
			fromOurOwnPage(req)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != c.want {
				t.Errorf("%s: switching answered %d, want %d: %s",
					c.what, rec.Code, c.want, rec.Body.String())
			}
			if c.want == http.StatusConflict && !contains(rec.Body.String(), "groups") {
				t.Errorf("%s: the refusal does not say what is missing: %s",
					c.what, rec.Body.String())
			}
		}
	})
}

// deriving is r with the role-assignment mode wired, answering group-bound or
// direct.
//
// A running deployment always sets it. Left nil, the guard reading it
// short-circuits and neither of its arms is ever executed.
func deriving(t *testing.T, r *reach, groups bool) *reach {
	t.Helper()
	files, err := attach.NewFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sources, err := access.ParseSources("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	settings := setting.NewStore(r.db)
	if groups {
		if _, _, err := settings.Change(t.Context(), setting.RoleMode,
			string(access.GroupBound)); err != nil {
			t.Fatal(err)
		}
	}
	// Wired the way the process wires it — a read of the stored mode, through
	// a store holding the root database handle — rather than a closure over a
	// constant. A constant exercises both arms of the guard and neither can
	// deadlock, which is the difference between testing what the guard decides
	// and testing where it reads from.
	handler, _ := httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil,
		httpapi.Ingest{
			DB: r.db, Queue: queue.New(r.db, queue.DefaultOptions()), Files: files,
			Access: access.NewResolver(r.rights,
				access.Trust{Header: testHeader, From: sources}),
			Mode: func(ctx context.Context) access.Mode {
				stored, _, err := settings.Get(ctx, setting.RoleMode)
				if err != nil {
					return access.Direct
				}
				return access.AsMode(stored)
			},
		})
	with := *r
	with.handler = handler
	return &with
}

// withProvider is the server again, with one sign-in provider that either has
// a source of groups or has not.
func withProvider(t *testing.T, r *reach, groups bool) http.Handler {
	t.Helper()
	files, err := attach.NewFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sources, err := access.ParseSources("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil,
		httpapi.Ingest{
			DB: r.db, Queue: queue.New(r.db, queue.DefaultOptions()), Files: files,
			Access: access.NewResolver(r.rights,
				access.Trust{Header: testHeader, From: sources}),
			Providers: map[string]signin.Provider{
				"one": &saying{stubProvider: &stubProvider{}, groups: groups},
			},
		})
	return handler
}

// shownAs is the display name the cast is seeded with: never a
// recapitalization of the identity, because folding would then match the
// label against the identity and hide a field carrying the wrong one.
func shownAs(identity string) string {
	return "Shown as " + identity
}
