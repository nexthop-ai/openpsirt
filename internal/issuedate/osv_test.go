// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package issuedate_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/issuedate"
)

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

	dates, err := client.Dates(ctx, "CVE-2024-3094")
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
	if _, err := client.Dates(ctx, "GHSA-JFH8-C2JP-5V3Q"); err != nil {
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
		if _, err := client.Dates(ctx, name); !errors.Is(err, want) {
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
		_, err := client.Dates(t.Context(), name)
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
	if _, err := client.Dates(t.Context(), "CVE-2024-3094"); !errors.Is(err, issuedate.ErrNotAnswering) {
		t.Fatalf("a request to another host answered %v, want it refused as not answering", err)
	}
}
