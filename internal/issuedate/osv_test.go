// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package issuedate_test

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/issuedate"
)

// full is a commit's name in full.
const full = "3439c15ae91a517cf3c650ea15a8987699416ad9"

// Each answer OSV gives is read as the pass needs it read, and a name that is
// not an advisory identifier is never sent.
func TestOSVAnswersAreClassified(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		switch r.URL.Path {
		case "/v1/vulns/CVE-2024-3094":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write([]byte(`{"id":"CVE-2024-3094","published":"2024-03-29T16:51:12.588Z",` +
				`"modified":"2026-11-05T10:31:12.351990229Z"}`))
		case "/v1/vulns/CVE-2026-0500":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/v1/vulns/CVE-2026-0403":
			w.WriteHeader(http.StatusForbidden)
		case "/v1/vulns/CVE-2026-0400":
			w.WriteHeader(http.StatusBadRequest)
		case "/v1/vulns/CVE-2026-0501":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"CVE-2026-0501"}`))
		case "/v1/vulns/GHSA-jfh8-c2jp-5v3q":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"GHSA-jfh8-c2jp-5v3q","published":"2024-03-29T16:51:12Z"}`))
		case "/v1/vulns/CVE-2026-0502":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":`))
		case "/v1/vulns/CVE-2026-0503":
			w.Header().Set("Content-Type", "application/json")
			// Whole once cut at the bound, so only the bound refuses it.
			_, _ = w.Write([]byte(`{"id":"CVE-2026-0503"}` + strings.Repeat(" ", 8<<20)))
		case "/v1/vulns/CVE-2026-0200":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html>Sign in to continue</html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":5,"message":"Vulnerability not found"}`))
		}
	}))
	defer server.Close()
	client := &issuedate.OSV{HTTP: server.Client(), Base: server.URL}
	ctx := t.Context()

	dates, err := client.Ask(ctx, "CVE-2024-3094")
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2024, 3, 29, 16, 51, 12, 588_000_000, time.UTC); !dates.Published.Equal(want) {
		t.Errorf("published %v, want %v", dates.Published, want)
	}
	if dates.Modified.IsZero() {
		t.Error("the modified date was not read")
	}
	// Stored in capitals, and asked as OSV spells it.
	if _, err := client.Ask(ctx, "GHSA-JFH8-C2JP-5V3Q"); err != nil {
		t.Errorf("a GitHub advisory stored in capitals answered %v", err)
	}
	for name, want := range map[string]error{
		"CVE-2026-0502":  issuedate.ErrUnaskable,
		"CVE-2026-0503":  issuedate.ErrUnaskable,
		"CVE-1999-99999": issuedate.ErrUnknown,
		"CVE-2026-0500":  issuedate.ErrNotAnswering,
		"CVE-2026-0403":  issuedate.ErrNotAnswering,
		"CVE-2026-0400":  issuedate.ErrUnaskable,
		"CVE-2026-0200":  issuedate.ErrNotAnswering,
		"CVE-2026-0501":  issuedate.ErrUnknown,
		"../admin":       issuedate.ErrUnaskable,
		"CVE-1 2":        issuedate.ErrUnaskable,
	} {
		if _, err := client.Ask(ctx, name); !errors.Is(err, want) {
			t.Errorf("%q answered %v, want %v", name, err, want)
		}
	}
	for _, path := range paths {
		if path == "/v1/vulns/..%2Fadmin" || path == "/admin" {
			t.Errorf("a name that is no identifier was sent: %s", path)
		}
	}
}

// A not-found answer naming the records that hold the name as an alias names
// them, shaped as identifiers and bounded; it still reads as unknown to a
// caller that does not follow them.
func TestOSVNamesTheRecordsHoldingANameAsAnAlias(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		switch r.URL.Path {
		case "/v1/vulns/CVE-2026-86409":
			// Recorded from api.osv.dev.
			_, _ = w.Write([]byte(`{"code":5,"message":"Vulnerability not found, but the following aliases were: CURL-CVE-2026-86409"}`))
		case "/v1/vulns/CVE-2026-0404":
			_, _ = w.Write([]byte(`{"code":5,"message":"Vulnerability not found, but the following aliases were: ` +
				`../admin, A-1, B 2, C-3, D-4, E-5"}`))
		default:
			_, _ = w.Write([]byte(`{"code":5,"message":"Vulnerability not found"}`))
		}
	}))
	defer server.Close()
	client := &issuedate.OSV{HTTP: server.Client(), Base: server.URL}
	for name, want := range map[string][]string{
		"CVE-2026-86409": {"CURL-CVE-2026-86409"},
		"CVE-2026-0404":  {"A-1", "C-3", "D-4"},
		"CVE-2026-0405":  nil,
	} {
		_, err := client.Ask(t.Context(), name)
		if !errors.Is(err, issuedate.ErrUnknown) {
			t.Errorf("%s answered %v, want it unknown to a caller not following aliases", name, err)
		}
		var aliased *issuedate.Aliased
		var got []string
		if errors.As(err, &aliased) {
			got = aliased.Names
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s names %q, want %q", name, got, want)
		}
	}
}

// Two records as api.osv.dev answers them, cut to the fields read here.
const (
	curlRecord   = `{"id":"CURL-CVE-2026-86409","aliases":["CVE-2026-86409"],"modified":"2026-10-25T01:16:47.956837797Z","published":"2026-10-14T08:00:00Z","affected":[{"ranges":[{"type":"GIT","repo":"https://github.com/curl/curl.git","events":[{"introduced":"08e8455dddc5e48e58a12ade3815c01ae3da3b64"},{"fixed":"c3c70440e8d9938c0bb732595751e8aebc614f24"}]}]}]}`
	kernelRecord = `{"id":"CVE-2024-26581","modified":"2026-11-17T07:01:44.153486639Z","published":"2024-02-20T12:52:57.398Z","affected":[{"ranges":[{"type":"GIT","repo":"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git","events":[{"introduced":"8284a79136c384059e85e278da2210b809730287"},{"fixed":"c60d252949caf9aba537525195edae6bbabc35eb"}]},{"type":"GIT","repo":"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git","events":[{"introduced":"acaee227cf79c45a5d2d49c3e9a66333a462802c"},{"fixed":"10e9cb39313627f2eae4cd70c4b742074e998fd8"}]},{"type":"GIT","repo":"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git","events":[{"introduced":"893cb3c3513cf661a0ff45fe0cfa83fe27131f76"},{"fixed":"4cee42fcf54fec46b344681e7cc4f234bb22f85a"}]},{"type":"GIT","repo":"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git","events":[{"introduced":"50cbb9d195c197af671869c8cadce3bd483735a0"},{"fixed":"2bab493a5624444ec6e648ad0d55a362bcb4c003"}]},{"type":"GIT","repo":"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git","events":[{"introduced":"89a4d1a89751a0fbd520e64091873e19cc0979e8"},{"fixed":"1296c110c5a0b45a8fcf58e7d18bc5da61a565cb"}]},{"type":"GIT","repo":"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git","events":[{"introduced":"f718863aca469a109895cb855e6b81fff4827d71"},{"fixed":"b734f7a47aeb32a5ba298e4ccc16bb0c52b6dbf7"},{"fixed":"6eb14441f10602fa1cf691da9d685718b68b78a9"},{"fixed":"60c0c230c6f046da536d3df8b39a20b9a9fd6af0"}]},{"type":"GIT","repo":"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git","events":[{"introduced":"cd66733932399475fe933cb3ec03e687ed401462"}]}]},{"ranges":[]}]}`
)

// recorded serves written bodies by name.
func recorded(t *testing.T, bodies map[string]string) *issuedate.OSV {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[strings.TrimPrefix(r.URL.Path, "/v1/vulns/")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	return &issuedate.OSV{HTTP: server.Client(), Base: server.URL}
}

// A record's fix references, and each fixed commit of a git range on a host
// with a known commit page, are its patch links.
func TestARecordsFixesAreItsPatchLinks(t *testing.T) {
	client := recorded(t, map[string]string{
		"CURL-CVE-2026-86409": curlRecord,
		"CVE-2024-26581":      kernelRecord,
		"CVE-2026-0600": `{"published":"2026-01-01T00:00:00Z","references":[
			{"type":"FIX","url":"https://example.org/fix/1"},
			{"type":"WEB","url":"https://example.org/page"},
			{"type":"FIX","url":"javascript:alert(1)"},
			{"type":"FIX","url":"javascript://example.org/%0Aalert(1)"},
			{"type":"FIX","url":"ftp://example.org/fix"},
			{"type":"FIX","url":"data:text/html,<script>x</script>"},
			{"type":"FIX","url":"/relative/commit/` + full + `"},
			{"type":"FIX","url":"https://user:pass@example.org/fix"},
			{"type":"FIX","url":"https://example.org/a b"},
			{"type":"FIX","url":"https://example.org/` + strings.Repeat("a", 2048) + `"},
			{"type":"FIX","url":"https://github.com/curl/curl/commit/` + full + `"}],
			"affected":[{"ranges":[
			{"type":"GIT","repo":"https://github.com/curl/curl.git","events":[{"introduced":"0"},{"fixed":"` + full + `"}]},
			{"type":"GIT","repo":"https://git.example.org/curl.git","events":[{"fixed":"` + full + `"}]},
			{"type":"ECOSYSTEM","repo":"https://github.com/o/r","events":[{"fixed":"` + strings.Repeat("a", 40) + `"}]},
			{"type":"SEMVER","events":[{"fixed":"8.14.3"}]}]}]}`,
	})
	for name, want := range map[string][]string{
		// One fixed commit on GitHub.
		"CURL-CVE-2026-86409": {"https://github.com/curl/curl/commit/c3c70440e8d9938c0bb732595751e8aebc614f24"},
		// A fixed commit per stable branch the fix reached.
		"CVE-2024-26581": {
			"https://git.kernel.org/stable/c/c60d252949caf9aba537525195edae6bbabc35eb",
			"https://git.kernel.org/stable/c/10e9cb39313627f2eae4cd70c4b742074e998fd8",
			"https://git.kernel.org/stable/c/4cee42fcf54fec46b344681e7cc4f234bb22f85a",
			"https://git.kernel.org/stable/c/2bab493a5624444ec6e648ad0d55a362bcb4c003",
			"https://git.kernel.org/stable/c/1296c110c5a0b45a8fcf58e7d18bc5da61a565cb",
			"https://git.kernel.org/stable/c/b734f7a47aeb32a5ba298e4ccc16bb0c52b6dbf7",
			"https://git.kernel.org/stable/c/6eb14441f10602fa1cf691da9d685718b68b78a9",
			"https://git.kernel.org/stable/c/60c0c230c6f046da536d3df8b39a20b9a9fd6af0",
		},
		// Fix references that are links, then commits not already linked;
		// a host with no known commit page gives none.
		"CVE-2026-0600": {"https://example.org/fix/1", "https://github.com/curl/curl/commit/" + full},
	} {
		got, err := client.Ask(t.Context(), name)
		if err != nil {
			t.Fatalf("%s answered %v", name, err)
		}
		if !slices.Equal(got.Patches, want) {
			t.Errorf("%s has patch links\n%q\nwant\n%q", name, got.Patches, want)
		}
	}
}

// One record gives at most a hundred patch links.
func TestARecordsPatchLinksAreBounded(t *testing.T) {
	var events []string
	for i := range 150 {
		events = append(events, fmt.Sprintf(`{"fixed":"%040x"}`, i+1))
	}
	client := recorded(t, map[string]string{
		"CVE-2026-0601": `{"published":"2026-01-01T00:00:00Z","affected":[{"ranges":[` +
			`{"type":"GIT","repo":"https://github.com/o/r","events":[` + strings.Join(events, ",") + `]}]}]}`,
	})
	got, err := client.Ask(t.Context(), "CVE-2026-0601")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Patches) != 100 {
		t.Errorf("a record of 150 fixed commits gave %d patch links, want 100", len(got.Patches))
	}
}

// A stored name is sent as OSV spells it.
func TestNamesAreSentAsOSVSpellsThem(t *testing.T) {
	for stored, sent := range map[string]string{
		"GHSA-JFH8-C2JP-5V3Q":      "GHSA-jfh8-c2jp-5v3q",
		"OPENSUSE-SU-2024:14017-1": "openSUSE-SU-2024:14017-1",
		"CVE-2024-3094":            "CVE-2024-3094",
		"DEBIAN-CVE-2024-3094":     "DEBIAN-CVE-2024-3094",
	} {
		if got := issuedate.Spelled(stored); got != sent {
			t.Errorf("%s is sent as %s, want %s", stored, got, sent)
		}
	}
}

// The client reaches OSV's host alone.
func TestTheOSVClientReachesNoOtherHost(t *testing.T) {
	client := issuedate.NewOSV()
	client.Base = "https://example.com"
	// Refused, and left due: the network refused it, not the name.
	if _, err := client.Ask(t.Context(), "CVE-2024-3094"); !errors.Is(err, issuedate.ErrNotAnswering) {
		t.Fatalf("a request to another host answered %v, want it refused as not answering", err)
	}
}
