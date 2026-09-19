package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/danielgtaylor/huma/v2"
)

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	h, _ := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, Ingest{})
	return h
}

func TestProbesAnswerWithoutAuthentication(t *testing.T) {
	// Container probes cannot sign in. If these ever start requiring
	// credentials, every deployment fails its health check.
	h := newTestHandler(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, rec.Code)
		}
	}
}

func TestTheVersionIsNotToldToStrangers(t *testing.T) {
	// The running build is small reconnaissance, but it is
	// reconnaissance: it says which published issues might apply here. Every
	// documented route is authenticated, and this one is not an exception
	// because it looks harmless.
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/version", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/version unauthenticated = %d, want 401", rec.Code)
	}
}

func TestAProcessThatCannotTellWhoIsAskingAnswersNobody(t *testing.T) {
	// Failing closed. A deployment whose sign-in is not configured serves
	// nothing rather than serving everybody, and the probes still answer so
	// that the failure is visible as a service that is up and refusing.
	h := newTestHandler(t)
	for _, path := range []string{"/v1/version", "/v1/products"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s = %d, want 401", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("the liveness probe answered %d", rec.Code)
	}
}

func TestOpenAPIDocumentDescribesTheRegisteredRoutes(t *testing.T) {
	// This is the check that keeps the published specification honest: it is
	// generated from the same registrations the server routes on, so a route
	// that exists but is undocumented cannot happen.
	_, api := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, Ingest{})
	doc := api.OpenAPI()
	if doc.Paths["/v1/version"] == nil {
		t.Fatal("/v1/version missing from the generated document")
	}
	spec, err := doc.YAML()
	if err != nil {
		t.Fatalf("render document: %v", err)
	}
	if len(spec) == 0 {
		t.Fatal("generated document is empty")
	}
}

func TestDocumentationIsNotServed(t *testing.T) {
	// Documentation is published separately. Serving it here would be the only
	// unauthenticated route in the application.
	h := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if rec.Code == http.StatusOK {
		t.Error("GET /docs served something; documentation should not be served")
	}
}

func TestReadinessFailsWhenTheServiceCannotWork(t *testing.T) {
	// A process that is up but cannot reach its database should not be sent
	// traffic. Answering "ok" regardless would make the probe decorative.
	h, _ := New(slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(context.Context) error { return errUnavailable }, Ingest{})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz = %d, want 503", rec.Code)
	}

	// Liveness is a different question: the process is running, so restarting
	// it would not help.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz = %d, want 200 even when not ready", rec.Code)
	}
}

var errUnavailable = errStub("database is unreachable")

type errStub string

func (e errStub) Error() string { return string(e) }

func TestEveryOperationSaysWhatItAsksFor(t *testing.T) {
	// The rights an endpoint needs were written nowhere and lived only in the
	// handlers, so the only way to answer "who may call this" was to read the
	// code. Now every operation carries it — structured for a client generator
	// or an access review, and rendered into the description for somebody
	// reading the reference.
	//
	// Checked rather than trusted, because the failure is silent: an endpoint
	// added without one is not broken, it is undocumented, and nobody notices
	// until they need the answer.
	_, api := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, Ingest{})
	spec := api.OpenAPI()

	var missing []string
	var operations int
	for path, item := range spec.Paths {
		for method, op := range map[string]*huma.Operation{
			"GET": item.Get, "PUT": item.Put, "POST": item.Post,
			"DELETE": item.Delete, "PATCH": item.Patch,
		} {
			if op == nil || op.OperationID == "" {
				continue
			}
			operations++
			if _, ok := op.Extensions["x-openpsirt-requires"]; !ok {
				missing = append(missing, method+" "+path+" ("+op.OperationID+")")
				continue
			}
			if !strings.Contains(op.Description, "Requires: ") {
				missing = append(missing, op.OperationID+" states it in the document and not in the reference")
			}
		}
	}
	if operations == 0 {
		t.Fatal("no operations were registered, so this checked nothing")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d of %d operations do not say what they ask for:\n  %s",
			len(missing), operations, strings.Join(missing, "\n  "))
	}
}

func TestThePagesOwnInlineScriptIsAllowedByHashAndNothingWider(t *testing.T) {
	// The policy said "the interface has no inline script", which was true when
	// it was written and stopped being true when the page grew one: the snippet
	// that reads the chosen theme before the first paint. Nothing said so —
	// the browser refused it silently, the bundle applied the theme a moment
	// later, and the flash the snippet exists to prevent happened every load.
	//
	// The hash is taken from what is actually served, so a build step that
	// changes the snippet cannot leave the policy behind.
	page := []byte(`<!doctype html><html><head>` +
		`<script>document.documentElement.setAttribute("data-look","dark");</script>` +
		`<script type="module" src="/assets/index.js"></script>` +
		`</head><body></body></html>`)
	files := fstest.MapFS{"index.html": &fstest.MapFile{Data: page}}

	handler, _ := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, Ingest{
		Interface: Interface{Files: files},
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/version", nil))
	policy := rec.Header().Get("Content-Security-Policy")

	sum := sha256.Sum256([]byte(`document.documentElement.setAttribute("data-look","dark");`))
	want := "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if !strings.Contains(policy, want) {
		t.Errorf("the policy does not allow the page's own script: %s", policy)
	}
	// The hash and nothing wider: unsafe-inline would allow every inline
	// script, including one somebody smuggled past the sanitizer, which is
	// what this policy is a second line against.
	if strings.Contains(policy, "unsafe-inline") &&
		!strings.Contains(policy, "style-src 'self' 'unsafe-inline'") {
		t.Errorf("the policy allows inline scripts wholesale: %s", policy)
	}
	if strings.Count(policy, "'sha256-") != 1 {
		t.Errorf("%d hashes for one inline script: %s", strings.Count(policy, "'sha256-"), policy)
	}

	// A deployment serving no page has no inline script to allow, and its
	// policy says so rather than carrying a hash of nothing.
	api, _ := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, Ingest{})
	bare := httptest.NewRecorder()
	api.ServeHTTP(bare, httptest.NewRequest(http.MethodGet, "/v1/version", nil))
	if strings.Contains(bare.Header().Get("Content-Security-Policy"), "sha256-") {
		t.Errorf("an API-only deployment carries a script hash: %s",
			bare.Header().Get("Content-Security-Policy"))
	}
}
