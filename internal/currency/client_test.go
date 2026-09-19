package currency_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/currency"
)

// answering is a stand-in for one public index.
//
// Without one, the HTTP half of this package is exercised only by a manual
// test that talks to the real services, skipped unless an environment variable
// is set. A request built wrongly then reaches nobody's attention until
// somebody reads it.
type answering struct {
	*httptest.Server
	// asked records every path requested, which is the point: what this code
	// gets wrong is the URL it builds, and only the server sees that.
	asked []string
	body  string
	code  int
}

func serving(t *testing.T, body string) *answering {
	t.Helper()
	a := &answering{body: body, code: http.StatusOK}
	a.Server = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			a.asked = append(a.asked, r.URL.RequestURI())
			w.WriteHeader(a.code)
			_, _ = w.Write([]byte(a.body))
		}))
	t.Cleanup(a.Close)
	return a
}

func client(a *answering) *currency.Client {
	c := currency.New()
	c.GoProxy, c.NPM, c.PyPI, c.Crates = a.URL, a.URL, a.URL, a.URL
	// The guard the real client carries pins the public index hosts, refuses
	// plain HTTP and refuses to connect inside this network — all three of
	// which describe a test server exactly. It is stood down here so that what
	// these tests measure is the request this package builds; the guard has
	// its own tests, against the layers rather than through them.
	c.HTTP = &http.Client{Timeout: 5 * time.Second}
	return c
}

// A package identifier is somebody else's input, and the Go proxy was the one
// asker interpolating the name into the URL unescaped. `pkg:golang/foo%3Fx=1`
// decodes to a name carrying a `?`, which turned the rest of the path into a
// query string — an uploaded document choosing part of our request.
func TestAnIdentifierCannotSteerTheRequest(t *testing.T) {
	for _, c := range []struct {
		what string
		purl string
		want string
	}{
		{"an ordinary module", "pkg:golang/golang.org/x/net@v0.17.0",
			"/golang.org/x/net/@latest"},
		{"a question mark in the name", "pkg:golang/foo%3Fx=1@v1",
			"/foo%3Fx=1/@latest"},
		{"a fragment in the name", "pkg:golang/foo%23frag@v1",
			"/foo%23frag/@latest"},
		{"an upper-case letter, which the proxy spells with a bang",
			"pkg:golang/github.com/Sirupsen/logrus@v1", "/github.com/%21sirupsen/logrus/@latest"},
	} {
		a := serving(t, `{"Version":"v1.0.0","Time":"2026-01-02T03:04:05Z"}`)
		ecosystem, name, ok := currency.Asked(c.purl)
		if !ok {
			t.Fatalf("%s: %q could not be read at all", c.what, c.purl)
		}
		if _, err := client(a).For(ecosystem).Latest(t.Context(), name); err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		if len(a.asked) != 1 || a.asked[0] != c.want {
			t.Errorf("%s: requested %v, expected [%q]", c.what, a.asked, c.want)
		}
	}
}

func TestTheVersionAndItsDateAreRead(t *testing.T) {
	a := serving(t, `{"Version":"v0.38.0","Time":"2026-03-01T12:00:00Z"}`)
	latest, err := client(a).For("golang").Latest(t.Context(), "golang.org/x/net")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Version != "v0.38.0" {
		t.Errorf("version %q, expected v0.38.0", latest.Version)
	}
	if want := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC); !latest.Released.Equal(want) {
		t.Errorf("released %v, expected %v", latest.Released, want)
	}
}

// A package the index has never heard of is not a failure — a private module
// and a vendored fork both look like this — and the caller tells the two
// apart to decide whether to ask again.
func TestAPackageTheIndexDoesNotKnowIsNotAFailure(t *testing.T) {
	a := serving(t, `{}`)
	a.code = http.StatusNotFound
	_, err := client(a).For("pypi").Latest(t.Context(), "nothing-here")
	if !errors.Is(err, currency.ErrUnknown) {
		t.Errorf("got %v, expected ErrUnknown", err)
	}
}

// npm's full document is the only one dating each version, and for a heavily
// published package it is tens of megabytes; where it will not come back the
// abbreviated one still says which version is current. But a definite 404 is
// already the answer, and asking again for the same name doubles the load on a
// free service for nothing.
func TestNpmDoesNotAskTwiceForAPackageThatIsNotThere(t *testing.T) {
	a := serving(t, `{}`)
	a.code = http.StatusNotFound
	_, err := client(a).For("npm").Latest(t.Context(), "@scope/nothing")
	if !errors.Is(err, currency.ErrUnknown) {
		t.Fatalf("got %v, expected ErrUnknown", err)
	}
	if len(a.asked) != 1 {
		t.Errorf("made %d requests for one unknown package: %v", len(a.asked), a.asked)
	}
	// And the scope stays one name rather than becoming a directory.
	if a.asked[0] != "/@scope%2Fnothing" {
		t.Errorf("requested %q, expected the scoped name escaped whole", a.asked[0])
	}
}

// A date the index does not give is not a date of zero. The caller stores
// nothing rather than the beginning of time, which would make an abandoned
// package look freshly released.
func TestAVersionWithNoDateIsStoredWithNoDate(t *testing.T) {
	a := serving(t, `{"crate":{"max_stable_version":"1.0.230"},"versions":[]}`)
	latest, err := client(a).For("cargo").Latest(t.Context(), "serde")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Version != "1.0.230" {
		t.Errorf("version %q, expected 1.0.230", latest.Version)
	}
	if !latest.Released.IsZero() {
		t.Errorf("invented a release date: %v", latest.Released)
	}
}

// A pre-release is not something to tell somebody they are behind by.
func TestAStableReleaseWinsOverAPreRelease(t *testing.T) {
	a := serving(t, `{"crate":{"max_stable_version":"1.0.0","max_version":"2.0.0-rc1"},
		"versions":[{"num":"1.0.0","created_at":"2026-01-01T00:00:00Z"}]}`)
	latest, err := client(a).For("cargo").Latest(t.Context(), "serde")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Version != "1.0.0" {
		t.Errorf("version %q, expected the stable one", latest.Version)
	}
}

// PyPI dates a release by when it appeared, not by when somebody added another
// wheel to it.
func TestAPythonReleaseIsDatedByItsEarliestFile(t *testing.T) {
	a := serving(t, `{"info":{"version":"4.2"},"urls":[
		{"upload_time_iso_8601":"2026-05-02T00:00:00Z"},
		{"upload_time_iso_8601":"2026-05-01T00:00:00Z"}]}`)
	latest, err := client(a).For("pypi").Latest(t.Context(), "django")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if want := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC); !latest.Released.Equal(want) {
		t.Errorf("released %v, expected the earliest file's date %v", latest.Released, want)
	}
}

// An ecosystem with no index is not a failure and not an error; there is
// simply nothing to ask.
func TestAnEcosystemWithNoIndexIsNotAsked(t *testing.T) {
	c := currency.New()
	for _, ecosystem := range []string{"generic", "oci", "github", "maven", "deb", ""} {
		if c.For(ecosystem) != nil {
			t.Errorf("%q reports an index it does not have", ecosystem)
		}
	}
	for _, ecosystem := range []string{"golang", "npm", "pypi", "cargo"} {
		if c.For(ecosystem) == nil {
			t.Errorf("%q has no index", ecosystem)
		}
	}
}

func TestThePublicIndexesAreReachedThroughTheGuardedClient(t *testing.T) {
	// one configured host names this feed as the case it was written for,
	// and this was the one client in the process that had none of it: no
	// host pin, no refusal to follow a redirect, nothing stopping a
	// connection inside this network. A background pass nobody watches
	// followed whatever an index answered with, ten hops deep, downgrading
	// to plain HTTP if it was told to.
	//
	// Asserted on the reason rather than on the failure. Every address
	// below fails one way or another without a guard — a name that does
	// not resolve, a route that does not exist — so a test that only
	// wanted an error would pass against a client with no guard at all.
	c := currency.New()
	for _, each := range []struct{ at, because string }{
		{"https://attacker.test/@latest", "not a configured provider host"},
		{"http://proxy.golang.org/@latest", "reached over https"},
	} {
		request, err := http.NewRequest(http.MethodGet, each.at, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.HTTP.Transport.RoundTrip(request)
		if err == nil {
			t.Errorf("%s was allowed", each.at)
			continue
		}
		if !strings.Contains(err.Error(), each.because) {
			t.Errorf("%s was refused for the wrong reason: %v", each.at, err)
		}
	}
	if c.HTTP.CheckRedirect == nil {
		t.Error("the client follows redirects, which is what a public index is not trusted to choose")
	}
	if c.HTTP.Timeout == 0 {
		t.Error("the client has no timeout")
	}
}

// Each index's description of a package, and where it lives. A bare name is not
// enough for a dependency of a dependency somebody has never heard of, and the
// indexes already carry the answer.
func TestWhatEachIndexSaysThePackageIsAndWhereItLives(t *testing.T) {
	for _, each := range []struct {
		ecosystem, name, body, summary, project string
	}{
		{
			// The module protocol has no description anywhere, but the proxy
			// states the origin — so a Go module carries an address and no
			// summary, which is not a gap in the row.
			"golang", "github.com/anchore/grype",
			`{"Version":"v0.118.0","Time":"2026-08-27T18:40:29Z",
			  "Origin":{"VCS":"git","URL":"https://github.com/anchore/grype"}}`,
			"", "https://github.com/anchore/grype",
		},
		{
			"npm", "lodash",
			`{"dist-tags":{"latest":"4.17.21"},"time":{"4.17.21":"2026-02-20T00:00:00Z"},
			  "description":"Lodash modular utilities.","homepage":"https://lodash.com/"}`,
			"Lodash modular utilities.", "https://lodash.com/",
		},
		{
			// The summary, never the description: in this index the second is
			// the package's whole README.
			"pypi", "requests",
			`{"info":{"version":"2.32.3","summary":"Python HTTP for Humans.",
			  "description":"a readme thousands of characters long",
			  "project_urls":{"Source":"https://github.com/psf/requests"}},
			  "urls":[{"upload_time_iso_8601":"2026-05-29T15:37:49.000000Z"}]}`,
			"Python HTTP for Humans.", "https://github.com/psf/requests",
		},
		{
			"cargo", "serde",
			`{"crate":{"max_stable_version":"1.0.219","description":"A generic serialization framework",
			  "homepage":"https://serde.rs","repository":"https://github.com/serde-rs/serde"},
			  "versions":[{"num":"1.0.219","created_at":"2026-03-09T00:00:00Z"}]}`,
			"A generic serialization framework", "https://serde.rs",
		},
	} {
		a := serving(t, each.body)
		latest, err := client(a).For(each.ecosystem).Latest(t.Context(), each.name)
		if err != nil {
			t.Errorf("%s: latest: %v", each.ecosystem, err)
			continue
		}
		if latest.Summary != each.summary {
			t.Errorf("%s said %q is %q, want %q", each.ecosystem, each.name,
				latest.Summary, each.summary)
		}
		if latest.Project != each.project {
			t.Errorf("%s put %q at %q, want %q", each.ecosystem, each.name,
				latest.Project, each.project)
		}
	}
}

// A publisher filling in more than one address gives the one a reader wants
// leads: a project's own pages before its repository.
func TestTheProjectsOwnPagesAreOfferedBeforeItsRepository(t *testing.T) {
	a := serving(t, `{"crate":{"max_stable_version":"1.0.0",
		"homepage":"https://serde.rs","repository":"https://github.com/serde-rs/serde"},
		"versions":[{"num":"1.0.0","created_at":"2026-01-01T00:00:00Z"}]}`)
	latest, err := client(a).For("cargo").Latest(t.Context(), "serde")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Project != "https://serde.rs" {
		t.Errorf("project %q, want the homepage rather than the repository", latest.Project)
	}

	// And where only the repository is filled in, that is the answer rather
	// than nothing.
	b := serving(t, `{"crate":{"max_stable_version":"1.0.0",
		"repository":"https://github.com/serde-rs/serde"},
		"versions":[{"num":"1.0.0","created_at":"2026-01-01T00:00:00Z"}]}`)
	only, err := client(b).For("cargo").Latest(t.Context(), "serde")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if only.Project != "https://github.com/serde-rs/serde" {
		t.Errorf("project %q, want the repository", only.Project)
	}
}

func TestEveryAskableEcosystemHasAnAsker(t *testing.T) {
	// The list and the switch were separate spellings of one fact, with
	// nothing joining them: a fifth index added to one and forgotten in the
	// other is either components selected and never asked, or asked about
	// and never selected, and neither says anything. Derived from one table
	// now, and this is what says the derivation is still a derivation.
	client := currency.New()
	askable := currency.Askable()
	if len(askable) == 0 {
		t.Fatal("nothing is askable, so this checked nothing")
	}
	for _, each := range askable {
		if client.For(each) == nil {
			t.Errorf("%q is selected by the pass and has no index to ask", each)
		}
		if each != strings.ToLower(each) {
			t.Errorf("%q is compared against a package identifier's type, which is folded", each)
		}
	}
	if client.For("deb") != nil {
		t.Error("a distribution package has an asker, and the distribution is the maintainer")
	}
}
