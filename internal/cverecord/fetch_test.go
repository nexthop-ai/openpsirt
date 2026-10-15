// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package cverecord_test

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/outward"
)

// list stands in for the repository host: a latest release that redirects to
// its tag, and downloads that redirect to the host storing them.
type list struct {
	mu        sync.Mutex
	tag       string
	archives  map[string]string
	downloads []string
}

func (l *list) serve(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.mu.Lock()
		defer l.mu.Unlock()
		switch {
		case r.URL.Path == "/releases/latest":
			http.Redirect(w, r, "/releases/tag/"+l.tag, http.StatusFound)
		case len(r.URL.Path) > len("/stored/") && r.URL.Path[:len("/stored/")] == "/stored/":
			name := r.URL.Path[len("/stored/"):]
			l.downloads = append(l.downloads, name)
			body, err := os.ReadFile(l.archives[name])
			if err != nil {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		default:
			name := r.URL.Path[len("/releases/download/"+l.tag+"/"):]
			if _, ok := l.archives[name]; !ok {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, "/stored/"+name, http.StatusFound) //nolint:gosec // G710: a stand-in redirecting to itself
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// fetcherFor is a fetcher reaching a stand-in, refusing redirects the way the
// guarded client does so the hop is the fetcher's own.
func fetcherFor(t *testing.T, server *httptest.Server, dir string) *cverecord.Fetcher {
	t.Helper()
	f := cverecord.NewFetcher(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("%w a redirect to %s", outward.ErrRefused, req.URL.Host)
	}
	f.Client = client
	f.Repository = server.URL
	return f
}

func TestTheMidnightReleaseCarriesTheDayBeforesArchive(t *testing.T) {
	yesterday := listArchive(t, map[string][]byte{
		"CVE-2026-31589.json": published("CVE-2026-31589", "PUBLISHED", "2026-10-06T21:58:40Z", kernelEntry),
	})
	l := &list{tag: "cve_2026-10-07_0000Z", archives: map[string]string{
		"2026-10-06_all_CVEs_at_midnight.zip.zip": yesterday,
	}}
	dir := t.TempDir()
	fetcher := fetcherFor(t, l.serve(t), dir)

	replaced, err := fetcher.Once(t.Context())
	if err != nil || !replaced {
		t.Fatalf("replaced %v, %v; want the day before's archive read", replaced, err)
	}
	if snapshot, err := cverecord.NewHeld(dir).Current(); err != nil || snapshot.Len() != 1 {
		t.Fatalf("held %v records, %v", snapshot.Len(), err)
	}

	// Asked again with nothing new published, it downloads nothing.
	if replaced, err := fetcher.Once(t.Context()); err != nil || replaced {
		t.Errorf("asked again, replaced %v, %v; want nothing done", replaced, err)
	}
	if len(l.downloads) != 1 {
		t.Errorf("downloaded %v, want the one archive once", l.downloads)
	}

	// The next hour's release carries the day's own, which replaces it.
	today := listArchive(t, map[string][]byte{
		"CVE-2026-31589.json": published("CVE-2026-31589", "PUBLISHED", "2026-10-07T00:30:00Z", kernelEntry),
		"CVE-2026-43465.json": published("CVE-2026-43465", "PUBLISHED", "2026-10-07T00:40:00Z", kernelEntry),
	})
	l.mu.Lock()
	l.tag = "cve_2026-10-07_0100Z"
	l.archives["2026-10-07_all_CVEs_at_midnight.zip.zip"] = today
	l.mu.Unlock()
	if replaced, err := fetcher.Once(t.Context()); err != nil || !replaced {
		t.Fatalf("with the day's archive out, replaced %v, %v", replaced, err)
	}
	snapshot, err := cverecord.NewHeld(dir).Current()
	if err != nil || snapshot.Len() != 2 || snapshot.Version() != "2026-10-07T00:40:00Z" {
		t.Errorf("held %d records taken %s, %v; want the day's two", snapshot.Len(), snapshot.Version(), err)
	}
}

// redirecting stands in for a repository host whose download reaches its
// archive through a chain of redirects, the given number long.
func redirecting(t *testing.T, tag, name, archive string, redirects int) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var stored atomic.Bool
	body, err := os.ReadFile(filepath.Clean(archive))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hop, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
		switch {
		case r.URL.Path == "/releases/latest":
			http.Redirect(w, r, "/releases/tag/"+tag, http.StatusFound)
		case r.URL.Path == "/releases/download/"+tag+"/"+name:
			http.Redirect(w, r, "/hop/1", http.StatusFound)
		case hop > 0 && hop < redirects-1:
			http.Redirect(w, r, "/hop/"+strconv.Itoa(hop+1), http.StatusFound)
		case hop > 0:
			http.Redirect(w, r, "/stored", http.StatusFound)
		case r.URL.Path == "/stored":
			stored.Store(true)
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server, &stored
}

// A download is followed through three redirects and no further, so a host
// answering with an endless chain does not hold the fetch.
func TestADownloadFollowsThreeRedirectsAndNoMore(t *testing.T) {
	const tag, name = "cve_2026-10-07_0000Z", "2026-10-06_all_CVEs_at_midnight.zip.zip"
	archive := listArchive(t, map[string][]byte{
		"CVE-2026-31589.json": published("CVE-2026-31589", "PUBLISHED", "2026-10-06T21:58:40Z", kernelEntry),
	})
	for _, c := range []struct {
		redirects int
		reached   bool
	}{{3, true}, {4, false}} {
		server, stored := redirecting(t, tag, name, archive, c.redirects)
		dir := t.TempDir()
		replaced, err := fetcherFor(t, server, dir).Once(t.Context())
		if c.reached && (err != nil || !replaced) {
			t.Errorf("an archive %d redirects away: replaced %v, %v; want it read", c.redirects, replaced, err)
		}
		if !c.reached && err == nil {
			t.Errorf("an archive %d redirects away was fetched with no error", c.redirects)
		}
		if stored.Load() != c.reached {
			t.Errorf("an archive %d redirects away was reached: %v, want %v", c.redirects, stored.Load(), c.reached)
		}
	}
}

func TestAReleaseCarryingNoArchiveIsAnError(t *testing.T) {
	l := &list{tag: "cve_2026-10-07_0500Z", archives: map[string]string{}}
	dir := t.TempDir()
	if _, err := fetcherFor(t, l.serve(t), dir).Once(t.Context()); err == nil {
		t.Error("a release with no archive fetched nothing and reported no error")
	}
	if held, err := cverecord.NewHeld(dir).Current(); held != nil || err != nil {
		t.Errorf("a failed fetch left %v, %v", held, err)
	}
}

func TestTheFetcherReachesOnlyTheListsHosts(t *testing.T) {
	// The redirect a download takes is followed by hand, so the client is what
	// keeps it on the hosts named. A stand-in on any other host is refused
	// before anything is asked of it.
	f := cverecord.NewFetcher(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := f.Client.Get("https://downloads.example.test/archive.zip")
	if !errors.Is(err, outward.ErrRefused) {
		t.Errorf("a host not named answered %v, want a refusal", err)
	}
}

func TestAFetchRemovesWhatAKilledOneLeftBehind(t *testing.T) {
	// A fetch killed part way leaves hundreds of megabytes on the scanner's
	// volume. One still being written, by an import beside the fetcher, is
	// left alone.
	dir := t.TempDir()
	abandoned := filepath.Join(dir, ".archive-1.zip")
	fresh := filepath.Join(dir, ".cves-2.zip")
	for _, path := range []string{abandoned, fresh} {
		if err := os.WriteFile(path, []byte("part"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-3 * time.Hour)
	if err := os.Chtimes(abandoned, old, old); err != nil {
		t.Fatal(err)
	}
	l := &list{tag: "cve_2026-10-07_0500Z", archives: map[string]string{}}
	_, _ = fetcherFor(t, l.serve(t), dir).Once(t.Context())
	if _, err := os.Stat(abandoned); !errors.Is(err, os.ErrNotExist) {
		t.Error("an abandoned download was left on the volume")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a file still being written was removed")
	}
}
