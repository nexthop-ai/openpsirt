// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package httpapitest is the harness the API's tests share: a server over a
// seeded cast of people, the requests they make, and the builds, claims and
// documents a test sets up.
package httpapitest

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
)

// DeclaredBody builds a body the endpoint would accept, so that what a test
// measures is the decision about the asker rather than a complaint about the
// request. A refusal that arrives because the body was wrong proves nothing
// about who may do what.
func DeclaredBody(method, path, name string) io.Reader {
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

// FromOurOwnPage makes a request look like one a browser made from a page this
// deployment served, which is what every ordinary request is.
//
// A browser states the origin of the page that caused a state-changing
// request, and will not let a page lie about it — so a request that states
// none is not one a browser made from our own page, and is refused. Tests that
// authenticate through the proxy header have to say so, or every write they
// make is measuring the forgery guard instead of the thing under test.
func FromOurOwnPage(req *http.Request) {
	req.Header.Set("Origin", "http://"+req.Host)
}

// Reach is a server with two products and people holding various things, so
// that every combination of who-asks and what-they-ask-for can be checked
// rather than a representative few.
type Reach struct {
	Handler http.Handler
	Key     string
	Revoked string
	// Rights is the store behind the handler, so a test can sign somebody in
	// without a provider to sign in through.
	Rights *access.Store
	// DB is the same database the handler reads, so a test can put a scanned
	// build behind it. Reading what has been decided is only testable against
	// something that was found.
	DB *database.DB
	// API is the document the server builds from its own registrations, so a
	// test can walk every operation rather than a list somebody maintains.
	API huma.API
}

// Response is what came back, for the tests that compare answers rather than
// just status codes.
type Response struct {
	Code int
	Text string
}

// Body makes a request as somebody and keeps what came back.
func (r *Reach) Body(t *testing.T, who, method, path string) Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if who != "" {
		req.Header.Set(TestHeader, who)
	}
	FromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return Response{Code: rec.Code, Text: rec.Body.String()}
}

// WithKey makes a request presenting a credential.
func (r *Reach) WithKey(t *testing.T, secret, method, path string) Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return Response{Code: rec.Code, Text: rec.Body.String()}
}

func (r *Reach) As(t *testing.T, who, method, path string) int {
	t.Helper()
	// A well-formed body, so that what is being measured is the decision about
	// the asker rather than a complaint about the request.
	req := httptest.NewRequest(method, path, DeclaredBody(method, path, "declared-by-the-test"))
	if method == http.MethodPost || method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}
	if who != "" {
		req.Header.Set(TestHeader, who)
	}
	FromOurOwnPage(req)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return rec.Code
}

// SentByTheKey files an upload against the built product as the cast's key,
// and answers which scan it is.
func (r *Reach) SentByTheKey(t *testing.T) int64 {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(ctx, "mine", "master", "broadcom")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	key, err := r.Rights.ResolveKey(ctx, r.Key)
	if err != nil {
		t.Fatal(err)
	}
	made, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "sent-by-the-key", BuiltAt: time.Now().UTC(),
		ParserVersion: "test", Credential: ingest.Sender(key),
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	return made.ID
}

func (r *Reach) AsKey(t *testing.T, method, path string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, DeclaredBody(method, path, "declared-by-a-pipeline"))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+r.Key)
	rec := httptest.NewRecorder()
	r.Handler.ServeHTTP(rec, req)
	return rec.Code
}

// Engines is dbtest.Each or dbtest.Two.
type Engines = func(t *testing.T, fn func(t *testing.T, db *database.DB))

// withCast is CastSeed.Each or CastSeed.Two: engines, from the seeded world.
type withCast = func(t *testing.T, fn func(t *testing.T, db *database.DB, made cast))

// The four-engine form and the two-engine form of the same fixture. Which
// one a test uses is decided by the rule at dbtest.Two: a test that pins what
// a query does — what a list contains, what a filter hides, what a conflict
// looks like, what text comes back — runs on every engine, and a test that
// pins routing, who may reach what, or the shape of a response runs on two.
func EachReach(t *testing.T, fn func(t *testing.T, r *Reach)) {
	t.Helper()
	ReachOn(t, CastSeed.Each, fn)
}

func TwoReach(t *testing.T, fn func(t *testing.T, r *Reach)) {
	t.Helper()
	ReachOn(t, CastSeed.Two, fn)
}

func ReachOn(t *testing.T, on withCast, fn func(t *testing.T, r *Reach)) {
	t.Helper()
	ReachAs(t, on, publisher.Named{
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

// CastSeed is the world every test here reaches into — two products, one of
// them built, and one person per way of holding rights — seeded once per
// binary on SQLite and per test on a server.
var CastSeed = dbtest.Seed(seedCast)

func seedCast(ctx context.Context, db *database.DB) (cast, error) {
	cat := catalog.NewStore(db.DB)
	mine, err := cat.DeclareProduct(ctx, "mine", ShownAs("mine"))
	if err != nil {
		return cast{}, err
	}
	// The streams and variants are declared with a capital, so each is spelled
	// differently from the name a path addresses it by and a test can tell
	// which of the two a field carries.
	if _, err := cat.DeclareStream(ctx, mine.ID, "Master", catalog.Branch, nil); err != nil {
		return cast{}, err
	}
	if _, err := cat.DeclareVariant(ctx, mine.ID, "Broadcom", true); err != nil {
		return cast{}, err
	}
	theirs, err := cat.DeclareProduct(ctx, "theirs", ShownAs("theirs"))
	if err != nil {
		return cast{}, err
	}
	theirBranch, err := cat.DeclareStream(ctx, theirs.ID, "Master", catalog.Branch, nil)
	if err != nil {
		return cast{}, err
	}
	theirVariant, err := cat.DeclareVariant(ctx, theirs.ID, "Mellanox", true)
	if err != nil {
		return cast{}, err
	}
	// The other product builds the same variant name as this one, so a path
	// naming theirs/master/broadcom addresses a build that exists: a refusal
	// there is the scope or visibility check answering, and not the build
	// being absent. With the visibility test in catalog.LocateVisible removed,
	// the pipeline tests reaching theirs/master/broadcom fail; with this
	// variant undeclared they passed either way.
	theirBroadcom, err := cat.DeclareVariant(ctx, theirs.ID, "Broadcom", true)
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
	for _, variant := range []*catalog.Variant{theirVariant, theirBroadcom} {
		if _, err := cat.TargetFor(ctx, theirBranch.ID, variant.ID); err != nil {
			return cast{}, err
		}
	}

	// Everybody here is seeded with a display name that is not their
	// identity. access.Store.Names answers the display name, so a field
	// publishing the label where the identity belongs reads differently
	// from one publishing the identity, and a route that resolves the
	// field it listed fails to find the label.
	rights := access.NewStore(db.DB)
	administrator, err := rights.Ensure(ctx, "admin", ShownAs("admin"), access.Stated(true), nil)
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
	adminReader, err := rights.Ensure(ctx, "admin-reader", ShownAs("admin-reader"), access.Stated(true), nil)
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
	auditor, err := rights.Ensure(ctx, "auditor", ShownAs("auditor"), nil, access.Stated(true))
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
		person, err := rights.Ensure(ctx, who, ShownAs(who), nil, nil)
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
	reviewer, err := rights.Ensure(ctx, "reviewer", ShownAs("reviewer"), nil, nil)
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
	estate, err := rights.Ensure(ctx, "estate-reader", ShownAs("estate-reader"), nil, nil)
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
	estateTriage, err := rights.Ensure(ctx, "wide-triager", ShownAs("wide-triager"), nil, nil)
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
	outsider, err := rights.Ensure(ctx, "outsider", ShownAs("outsider"), nil, nil)
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
	ungranted, err := rights.Ensure(ctx, "nothing", ShownAs("nothing"), nil, nil)
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

// ReachAs is ReachOn for a test that needs the deployment configured
// differently — the one that has not been told who it publishes as.
func ReachAs(t *testing.T, on withCast, as publisher.Named, fn func(t *testing.T, r *Reach)) {
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
		handler, api := httpapi.New(quiet, nil, core.Deps{
			DB: db, Queue: queue.New(db, queue.DefaultOptions()), Files: files,
			Access: access.NewResolver(rights, access.Trust{Header: TestHeader, From: sources}),
			// The identity this deployment publishes as, which an advisory
			// and a VEX document both need. Passed in, because the deployment
			// that has not been told is a case of its own.
			Publisher: as,
			// The names this deployment calls its own, derived from the
			// namespace it publishes under exactly as the binary derives it.
			// Restated here it is a second boundary that agrees until one
			// moves.
			Ours: currency.Ourselves(as.Namespace, nil),
			// A chat platform, so a chat channel and a person's own chat
			// settings answer rather than saying the deployment offers none.
			Chats: []string{notify.Slack},
		})
		fn(t, &Reach{Handler: handler, Key: made.key, Revoked: made.revoked,
			Rights: rights, DB: db, API: api})
	})
}

func Contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// DeclaredScope reads the scope off an operation's declaration, whichever
// shape the document put it in.
func DeclaredScope(t *testing.T, asks any) string {
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

// saying is a provider that reports whether it has a source of groups, and
// nothing else. What is under test is the answer to that one question.
type saying struct {
	*StubProvider
	groups bool
}

func (s *saying) GroupsSource() bool { return s.groups }

// Deriving is r with the role-assignment mode wired, answering group-bound or
// direct.
//
// A running deployment always sets it. Left nil, the guard reading it
// short-circuits and neither of its arms is ever executed.
func Deriving(t *testing.T, r *Reach, groups bool) *Reach {
	t.Helper()
	files, err := attach.NewFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sources, err := access.ParseSources("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	settings := setting.NewStore(r.DB)
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
		core.Deps{
			DB: r.DB, Queue: queue.New(r.DB, queue.DefaultOptions()), Files: files,
			Access: access.NewResolver(r.Rights,
				access.Trust{Header: TestHeader, From: sources}),
			Mode: func(ctx context.Context) access.Mode {
				stored, _, err := settings.Get(ctx, setting.RoleMode)
				if err != nil {
					return access.Direct
				}
				return access.AsMode(stored)
			},
		})
	with := *r
	with.Handler = handler
	return &with
}

// WithProvider is the server again, with one sign-in provider that either has
// a source of groups or has not.
func WithProvider(t *testing.T, r *Reach, groups bool) http.Handler {
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
		core.Deps{
			DB: r.DB, Queue: queue.New(r.DB, queue.DefaultOptions()), Files: files,
			Access: access.NewResolver(r.Rights,
				access.Trust{Header: TestHeader, From: sources}),
			Providers: map[string]signin.Provider{
				"one": &saying{StubProvider: &StubProvider{}, groups: groups},
			},
		})
	return handler
}

// ShownAs is the display name the cast is seeded with: never a
// recapitalization of the identity, because folding would then match the
// label against the identity and hide a field carrying the wrong one.
func ShownAs(identity string) string {
	return "Shown as " + identity
}

// TestHeader is what the fixture's proxy would set. Requests from the test
// client arrive from the address httptest uses, which the fixture trusts.
const TestHeader = "X-Test-User"

// Operations is the methods one path answers, in a fixed order so a failure
// reads the same twice.
func Operations(item *huma.PathItem) map[string]*huma.Operation {
	all := map[string]*huma.Operation{
		http.MethodGet: item.Get, http.MethodPost: item.Post,
		http.MethodPut: item.Put, http.MethodPatch: item.Patch,
		http.MethodDelete: item.Delete,
	}
	out := map[string]*huma.Operation{}
	names := make([]string, 0, len(all))
	for method := range all {
		names = append(names, method)
	}
	sort.Strings(names)
	for _, method := range names {
		if all[method] != nil {
			out[method] = all[method]
		}
	}
	return out
}

// SeedTheirs puts one disclosed and one undisclosed finding behind "theirs",
// the product nobody names in a per-product grant.
//
// An export over an empty result set is 200 whether the narrowing ran or not,
// so a test that only reads status codes passes against an estate grant that
// dropped the visibility predicate entirely — which is the disclosure this
// whole shape is written around.
//
// The undisclosed one is written straight to the column. Recording a flaw by
// hand is the path that mints one in a deployment, and standing it up here
// would test that path rather than this one.
func SeedTheirs(t *testing.T, r *Reach) (disclosed, undisclosed string) {
	t.Helper()
	ctx := t.Context()
	names := catalog.NewStore(r.DB.DB)
	located, err := names.Locate(ctx, "theirs", "master", "mellanox")
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "estate-theirs",
		BuiltAt: time.Now().UTC(), ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	root := graph.Described{Purl: "pkg:deb/debian/theirs@1.0", Name: "theirs", Version: "1.0"}
	lib := graph.Described{Purl: "pkg:deb/debian/libestate@2.1", Name: "libestate", Version: "2.1"}
	if _, err := graph.NewStore(r.DB.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{lib},
		Dependencies: []graph.Dependency{{Parent: root, Child: lib}},
	}); err != nil {
		t.Fatal(err)
	}
	findings := finding.NewStore(r.DB.DB)
	run, err := findings.Begin(ctx, finding.Run{
		TargetID: target.ID, Scanner: "grype", ScannerVersion: "0.112.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	disclosed, undisclosed = "CVE-2026-9001", "CVE-2026-9002"
	if _, err := findings.Apply(ctx, target.ID, run.ID, []finding.Reported{
		{Issue: finding.Named{Identifier: disclosed, Severity: "high"},
			Component: lib, FixState: finding.NoFix},
		{Issue: finding.Named{Identifier: undisclosed, Severity: "high"},
			Component: lib, FixState: finding.NoFix},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.DB.DB.NewUpdate().Table("finding").
		Set("visibility = ?", access.Private).
		Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
			undisclosed).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	return disclosed, undisclosed
}
