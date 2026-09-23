// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package currency_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/currency"
)

// routed is a stand-in for an index that answers several documents, which is
// what Maven Central and nuget.org both take for one package.
type routed struct {
	*httptest.Server
	asked []string
	// served is the body for each path. A path it does not name answers 404.
	served map[string]string
	header map[string]http.Header
}

func routing(t *testing.T, served map[string]string) *routed {
	t.Helper()
	r := &routed{served: served, header: map[string]http.Header{}}
	r.Server = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			r.asked = append(r.asked, req.URL.RequestURI())
			body, found := r.served[req.URL.Path]
			if !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			for key, values := range r.header[req.URL.Path] {
				w.Header()[key] = values
			}
			_, _ = w.Write([]byte(strings.ReplaceAll(body, "{{base}}", r.URL)))
		}))
	t.Cleanup(r.Close)
	return r
}

func routedClient(r *routed) *currency.Client {
	c := currency.New()
	c.Maven, c.NuGet = r.URL, r.URL
	c.HTTP = &http.Client{Timeout: 5 * time.Second}
	return c
}

const log4jMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <versioning>
    <latest>3.0.0-beta3</latest>
    <release>3.0.0-beta3</release>
    <versions>
      <version>2.0-beta9</version>
      <version>2.9.1</version>
      <version>2.25.1</version>
      <version>2.17.1</version>
      <version>3.0.0-beta3</version>
      <version>not a version</version>
    </versions>
  </versioning>
</metadata>`

const log4jProject = `<project>
  <name>Apache Log4j Core</name>
  <description>
    The Apache Log4j Core implementation.
    Spread over two lines.

    And a second paragraph nobody wanted in a table.
  </description>
  <url>https://logging.apache.org/log4j/2.x/</url>
  <scm><url>https://github.com/apache/logging-log4j2</url></scm>
</project>`

func TestMavenCentralAnswersTheNewestReleaseRatherThanItsOwnReleaseField(t *testing.T) {
	// The metadata document's "release" names whatever was published last,
	// which here is a beta — as it is on the real repository for this
	// artifact. The newest release is found by ordering the versions the
	// document lists, and 2.25.1 is after 2.9.1 only under an ordering.
	pom := "/maven2/org/apache/logging/log4j/log4j-core/2.25.1/log4j-core-2.25.1.pom"
	r := routing(t, map[string]string{
		"/maven2/org/apache/logging/log4j/log4j-core/maven-metadata.xml": log4jMetadata,
		pom: log4jProject,
	})
	r.header[pom] = http.Header{"Last-Modified": {"Sat, 05 Jul 2025 20:22:35 GMT"}}
	ecosystem, name, ok := currency.Asked("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1")
	if !ok {
		t.Fatal("the identifier could not be read")
	}
	latest, err := routedClient(r).For(ecosystem).Latest(t.Context(), name)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Version != "2.25.1" {
		t.Errorf("version %q, want 2.25.1", latest.Version)
	}
	if want := time.Date(2025, 7, 5, 20, 22, 35, 0, time.UTC); !latest.Released.Equal(want) {
		t.Errorf("released %v, want %v", latest.Released, want)
	}
	if latest.Summary != "The Apache Log4j Core implementation. Spread over two lines." {
		t.Errorf("summary %q, want the first paragraph on one line", latest.Summary)
	}
	if latest.Project != "https://logging.apache.org/log4j/2.x/" {
		t.Errorf("project %q, want the project's own pages", latest.Project)
	}
}

func TestMavenCentralOffersAPreReleaseOnlyWhereThereIsNoRelease(t *testing.T) {
	r := routing(t, map[string]string{
		"/maven2/org/example/thing/maven-metadata.xml": `<metadata><versioning><versions>
			<version>1.0-alpha-1</version><version>1.0-beta-2</version>
		</versions></versioning></metadata>`,
	})
	latest, err := routedClient(r).For("maven").Latest(t.Context(), "org.example/thing")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Version != "1.0-beta-2" {
		t.Errorf("version %q, want the furthest pre-release", latest.Version)
	}
	// The project document is missing, and the version stands without it.
	if !latest.Released.IsZero() || latest.Summary != "" {
		t.Errorf("invented what a missing document would have said: %+v", latest)
	}
}

func TestAMavenNameThatWouldMoveTheRequestIsNotAsked(t *testing.T) {
	r := routing(t, map[string]string{})
	for _, name := range []string{
		"no-group",
		"../../etc/thing",
		"org..example/thing",
		"org.example/..",
		"org.example/",
		`org.example\evil/thing`,
	} {
		_, err := routedClient(r).For("maven").Latest(t.Context(), name)
		if !errors.Is(err, currency.ErrUnaskable) {
			t.Errorf("%q: got %v, want it refused as unaskable", name, err)
		}
	}
	if len(r.asked) != 0 {
		t.Errorf("requests were made: %v", r.asked)
	}
}

func TestAMavenArtifactTheRepositoryDoesNotHoldIsUnknown(t *testing.T) {
	r := routing(t, map[string]string{})
	_, err := routedClient(r).For("maven").Latest(t.Context(), "org.example/private")
	if !errors.Is(err, currency.ErrUnknown) {
		t.Errorf("got %v, want ErrUnknown", err)
	}
	// And one listing nothing it can read is unknown too, rather than an
	// empty version recorded as an answer.
	r.served["/maven2/org/example/odd/maven-metadata.xml"] =
		`<metadata><versioning><versions><version>latest</version></versions></versioning></metadata>`
	if _, err := routedClient(r).For("maven").Latest(t.Context(), "org.example/odd"); !errors.Is(err, currency.ErrUnknown) {
		t.Errorf("got %v, want ErrUnknown", err)
	}
}

func TestAMavenDocumentUsingAnEntityItDoesNotDefineIsRefused(t *testing.T) {
	r := routing(t, map[string]string{
		"/maven2/org/example/thing/maven-metadata.xml": `<!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]>
			<metadata><versioning><versions><version>&x;</version></versions></versioning></metadata>`,
	})
	_, err := routedClient(r).For("maven").Latest(t.Context(), "org.example/thing")
	if !errors.Is(err, currency.ErrUnaskable) {
		t.Errorf("got %v, want the document refused as unreadable", err)
	}
}

const nugetInline = `{"items":[
  {"@id":"{{base}}/v3/registration5-gz-semver2/newtonsoft.json/index.json#page/3.5.8/12.0.1","items":[
    {"catalogEntry":{"version":"12.0.1","published":"2019-01-01T00:00:00+00:00","listed":true}}
  ]},
  {"@id":"{{base}}/v3/registration5-gz-semver2/newtonsoft.json/index.json#page/12.0.2/14.0.1-beta2","items":[
    {"catalogEntry":{"version":"13.0.4","published":"2025-09-16T08:13:09.313+00:00","listed":true,
      "summary":"","description":"Json.NET is a popular high-performance JSON framework for .NET",
      "projectUrl":"https://www.newtonsoft.com/json"}},
    {"catalogEntry":{"version":"13.0.10","published":"1900-01-01T00:00:00+00:00","listed":false}},
    {"catalogEntry":{"version":"13.0.5-beta1","published":"1900-01-01T00:00:00+00:00","listed":false}},
    {"catalogEntry":{"version":"14.0.1-beta2","published":"2026-09-21T10:12:19.923+00:00","listed":true}}
  ]}
]}`

func TestNuGetAnswersTheNewestListedRelease(t *testing.T) {
	// 13.0.10 is further along and unlisted, so nobody choosing a version is
	// offered it; 14.0.1-beta2 is further along and a pre-release.
	r := routing(t, map[string]string{
		"/v3/registration5-gz-semver2/newtonsoft.json/index.json": nugetInline,
	})
	ecosystem, name, ok := currency.Asked("pkg:nuget/Newtonsoft.Json@13.0.3")
	if !ok {
		t.Fatal("the identifier could not be read")
	}
	latest, err := routedClient(r).For(ecosystem).Latest(t.Context(), name)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Version != "13.0.4" {
		t.Errorf("version %q, want 13.0.4", latest.Version)
	}
	if want := time.Date(2025, 9, 16, 8, 13, 9, 313e6, time.UTC); !latest.Released.Equal(want) {
		t.Errorf("released %v, want %v", latest.Released, want)
	}
	if latest.Summary != "Json.NET is a popular high-performance JSON framework for .NET" {
		t.Errorf("summary %q, want the description where there is no summary", latest.Summary)
	}
	if latest.Project != "https://www.newtonsoft.com/json" {
		t.Errorf("project %q", latest.Project)
	}
	// The name is asked in lower case, which is how nuget.org serves it.
	if len(r.asked) != 1 || r.asked[0] != "/v3/registration5-gz-semver2/newtonsoft.json/index.json" {
		t.Errorf("requested %v", r.asked)
	}
}

func TestAPagedNuGetRegistrationIsReadFromItsNewestPage(t *testing.T) {
	// The newest page holds only a pre-release, so the page before it is read
	// as well — and the oldest never is.
	prefix := "/v3/registration5-gz-semver2/microsoft.extensions.logging/"
	r := routing(t, map[string]string{
		prefix + "index.json": `{"items":[
			{"@id":"{{base}}` + prefix + `page/1.json"},
			{"@id":"{{base}}` + prefix + `page/2.json"},
			{"@id":"{{base}}` + prefix + `page/3.json"}]}`,
		prefix + "page/2.json": `{"items":[
			{"catalogEntry":{"version":"9.0.0","published":"2024-11-12T00:00:00Z"}},
			{"catalogEntry":{"version":"10.0.0","published":"2025-11-11T00:00:00Z","summary":"Logging."}}]}`,
		prefix + "page/3.json": `{"items":[
			{"catalogEntry":{"version":"11.0.0-rc.1.26425.128","published":"2026-09-01T00:00:00Z"}}]}`,
	})
	latest, err := routedClient(r).For("nuget").Latest(t.Context(), "Microsoft.Extensions.Logging")
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if latest.Version != "10.0.0" {
		t.Errorf("version %q, want 10.0.0", latest.Version)
	}
	if latest.Summary != "Logging." {
		t.Errorf("summary %q, want the stated summary", latest.Summary)
	}
	for _, each := range r.asked {
		if strings.HasSuffix(each, "page/1.json") {
			t.Errorf("read the oldest page after the answer was in hand: %v", r.asked)
		}
	}
}

func TestANuGetPageIsReadOnlyFromTheRegistrationItCameFrom(t *testing.T) {
	// Another host, and on the same host another package's registration —
	// including one whose name begins with this one's.
	for _, elsewhere := range []string{
		"http://169.254.169.254/latest",
		"{{base}}/v3/registration5-gz-semver2/thingelse/page/1.json",
		"{{base}}/v3/registration5-gz-semver2/other/page/1.json",
	} {
		r := routing(t, map[string]string{
			"/v3/registration5-gz-semver2/thing/index.json":      `{"items":[{"@id":"` + elsewhere + `"}]}`,
			"/v3/registration5-gz-semver2/thingelse/page/1.json": `{"items":[{"catalogEntry":{"version":"9.9.9"}}]}`,
			"/v3/registration5-gz-semver2/other/page/1.json":     `{"items":[{"catalogEntry":{"version":"9.9.9"}}]}`,
		})
		_, err := routedClient(r).For("nuget").Latest(t.Context(), "thing")
		if !errors.Is(err, currency.ErrUnaskable) {
			t.Errorf("%s: got %v, want the page refused", elsewhere, err)
		}
		if len(r.asked) != 1 {
			t.Errorf("%s: followed a page elsewhere: %v", elsewhere, r.asked)
		}
	}
}

func TestAMavenOrNuGetNameCannotSteerTheRequest(t *testing.T) {
	// A package identifier is somebody else's input. Unescaped, a name
	// carrying a "?" or a "#" turns the rest of the path into a query or a
	// fragment, and an uploaded document picks part of the request.
	r := routing(t, map[string]string{})
	_, _ = routedClient(r).For("nuget").Latest(t.Context(), "thing?x=1")
	_, _ = routedClient(r).For("maven").Latest(t.Context(), "org.example/thing#frag")
	_, _ = routedClient(r).For("maven").Latest(t.Context(), "org.ex?ample/thing")
	want := []string{
		"/v3/registration5-gz-semver2/thing%3Fx=1/index.json",
		"/maven2/org/example/thing%23frag/maven-metadata.xml",
		"/maven2/org/ex%3Fample/thing/maven-metadata.xml",
	}
	if !slices.Equal(r.asked, want) {
		t.Errorf("requested %v, want %v", r.asked, want)
	}
}

func TestANuGetPackageOfOnlyPreReleasesIsReadABoundedDistance(t *testing.T) {
	// Every page a pre-release, so nothing stops the walk but the bound.
	prefix := "/v3/registration5-gz-semver2/beta.only/"
	served := map[string]string{}
	var pages []string
	for _, each := range []string{"1", "2", "3", "4", "5", "6"} {
		pages = append(pages, `{"@id":"{{base}}`+prefix+`page/`+each+`.json"}`)
		served[prefix+"page/"+each+".json"] =
			`{"items":[{"catalogEntry":{"version":"0.` + each + `.0-beta"}}]}`
	}
	served[prefix+"index.json"] = `{"items":[` + strings.Join(pages, ",") + `]}`
	r := routing(t, served)
	// Stopped short, a release may sit on a page that was not read, so the
	// newest pre-release is not offered.
	if _, err := routedClient(r).For("nuget").Latest(t.Context(), "Beta.Only"); !errors.Is(err, currency.ErrUnknown) {
		t.Errorf("got %v, want no answer where the walk stopped short", err)
	}
	// The registration, and then no more pages than the bound.
	if len(r.asked) != 1+4 {
		t.Errorf("made %d requests, want the registration and four pages: %v", len(r.asked), r.asked)
	}
}

func TestANuGetPackageWithNothingListedIsUnknown(t *testing.T) {
	r := routing(t, map[string]string{
		"/v3/registration5-gz-semver2/gone/index.json": `{"items":[{"@id":"x","items":[
			{"catalogEntry":{"version":"1.0.0","listed":false}}]}]}`,
	})
	if _, err := routedClient(r).For("nuget").Latest(t.Context(), "Gone"); !errors.Is(err, currency.ErrUnknown) {
		t.Errorf("got %v, want ErrUnknown", err)
	}
	if _, err := routedClient(r).For("nuget").Latest(t.Context(), ".."); !errors.Is(err, currency.ErrUnaskable) {
		t.Errorf("got %v, want a name that moves the request refused", err)
	}
}
