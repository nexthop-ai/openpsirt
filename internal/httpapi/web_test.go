package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/nexthop-ai/openpsirt/internal/httpapi"
)

// built stands in for the frontend's output: a page, a hashed asset beside it,
// and nothing else.
func built() fstest.MapFS {
	return fstest.MapFS{
		"index.html":             {Data: []byte("<!doctype html><div id=root></div>")},
		"assets/index-abc123.js": {Data: []byte("console.log(1)")},
	}
}

func serving(t *testing.T, files fstest.MapFS) http.Handler {
	t.Helper()
	handler, _ := httpapi.New(nil, nil, httpapi.Ingest{
		Interface: httpapi.Interface{Files: files},
	})
	return handler
}

func fetch(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestAPathThePageOwnsIsAnsweredWithThePage(t *testing.T) {
	// A single-page application does its own routing, so a path this server
	// has never heard of is not a mistake — it is a route the page knows.
	// Answering 404 would make every deep link fail on reload while working
	// perfectly when navigated to.
	handler := serving(t, built())
	for _, path := range []string{"/", "/products", "/products/sonic/streams/master/variants/x/findings"} {
		got := fetch(t, handler, http.MethodGet, path)
		if got.Code != http.StatusOK {
			t.Errorf("GET %s answered %d, want the page", path, got.Code)
		}
		if body := got.Body.String(); body != "<!doctype html><div id=root></div>" {
			t.Errorf("GET %s answered %q", path, body)
		}
	}
}

func TestARealFileIsServedAsItself(t *testing.T) {
	handler := serving(t, built())
	got := fetch(t, handler, http.MethodGet, "/assets/index-abc123.js")
	if got.Code != http.StatusOK || got.Body.String() != "console.log(1)" {
		t.Errorf("the asset answered %d: %q", got.Code, got.Body.String())
	}
}

func TestAnUnknownEndpointStaysAnEndpoint(t *testing.T) {
	// The API answers for itself, including for paths it does not have.
	// Handing back a page here reports a mistyped endpoint to a client parsing
	// JSON as a parse failure rather than as the 404 it is — which is a long
	// way from the mistake that caused it.
	handler := serving(t, built())
	for _, path := range []string{
		"/v1/nonesuch", "/v1",
		// The same paths spelled the two ways the test on the raw path
		// missed: a dot segment, and different capitals. Both named
		// something the API owns and both were answered with the page.
		"/v1/./nonesuch", "/v1/findings/../nonesuch", "/V1/nonesuch",
		"/Docs", "/OpenAPI.json",
	} {
		got := fetch(t, handler, http.MethodGet, path)
		if got.Code == http.StatusOK {
			t.Errorf("GET %s answered %d with %q", path, got.Code, got.Body.String())
		}
		if body := got.Body.String(); len(body) > 0 && body[0] == '<' {
			t.Errorf("GET %s answered with a page: %q", path, body)
		}
	}
}

func TestThePageIsNeverCached(t *testing.T) {
	// The assets carry a content hash and may be cached forever. index.html is
	// the one file that names them, so a cached copy pins a browser to the
	// previous deployment's assets — which are gone.
	handler := serving(t, built())
	got := fetch(t, handler, http.MethodGet, "/products")
	if got.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("the page is served with Cache-Control %q", got.Header().Get("Cache-Control"))
	}
}

func TestABinaryBuiltWithoutTheInterfaceServesTheAPIAlone(t *testing.T) {
	// A checkout with no node toolchain still has to build and serve. What it
	// must not do is answer as though a page were there.
	handler, _ := httpapi.New(nil, nil, httpapi.Ingest{})
	got := fetch(t, handler, http.MethodGet, "/products")
	if got.Code == http.StatusOK {
		t.Errorf("a binary with no interface served %q", got.Body.String())
	}
}

func TestServingAPageDoesNotOpenAnythingElse(t *testing.T) {
	// The failure this guards against. Serving the interface means answering
	// paths this server has no route for — and the tempting way to express
	// that is "anything outside /v1", which hands a stranger the framework's
	// own document and schema routes along with the page.
	//
	// So the question asked is whether the router has a route, not what the
	// path looks like. Anything registered still goes through the credential
	// check, whether or not an interface is mounted beside it.
	handler := serving(t, built())
	for _, path := range []string{
		"/openapi.json", "/openapi.yaml", "/openapi-3.0.json", "/openapi-3.0.yaml",
		"/schemas/VariantBody.json", "/docs",
		"/v1/version", "/v1/products", "/v1/session/me",
	} {
		got := fetch(t, handler, http.MethodGet, path)
		if got.Code == http.StatusOK {
			t.Errorf("%s answered %d with an interface mounted (%d bytes)",
				path, got.Code, got.Body.Len())
		}
	}

	// And the one thing that is public stays public, so this has not simply
	// closed everything.
	if got := fetch(t, handler, http.MethodGet, "/healthz"); got.Code != http.StatusOK {
		t.Errorf("the probe answered %d", got.Code)
	}
}
