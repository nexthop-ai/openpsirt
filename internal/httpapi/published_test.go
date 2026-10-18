// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// The published documents take no credential and look at none: a request
// carrying a session, a key or a proxy's header reaches them exactly as one
// carrying nothing, and no subject is resolved on the way.
func TestThePublishedDocumentsTakeNoCredential(t *testing.T) {
	reached := 0
	deps := unreached(t)
	deps.Published = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		if _, err := access.From(r.Context()); err == nil {
			t.Errorf("%s reached the published documents with a subject resolved", r.URL.Path)
		}
		w.WriteHeader(http.StatusTeapot)
	})
	h, _ := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, deps)
	for _, path := range []string{"/.well-known/csaf/provider-metadata.json", "/openvex/index.txt"} {
		for name, dress := range map[string]func(*http.Request){
			"nothing":   func(*http.Request) {},
			"a session": func(r *http.Request) { r.Header.Set("Cookie", "openpsirt_session=x") },
			"a key":     func(r *http.Request) { r.Header.Set("Authorization", "Bearer opk_nothing") },
		} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			dress(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusTeapot {
				t.Errorf("GET %s carrying %s = %d, want it answered by the published surface",
					path, name, rec.Code)
			}
		}
	}
	if reached == 0 {
		t.Fatal("nothing reached the published surface, so this checked nothing")
	}
}

// A deployment publishing nothing answers below the published paths as a path
// nothing is published at: not with the interface's page, and not by asking
// who is there.
func TestADeploymentPublishingNothingAnswersThereWithNothing(t *testing.T) {
	deps := unreached(t)
	deps.Interface = core.Interface{Files: fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")}}}
	h, _ := New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, deps)
	for _, path := range []string{"/.well-known/csaf/provider-metadata.json",
		"/.well-known/csaf/white/index.txt", "/openvex/sonic/master.json"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound || rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("GET %s = %d %s, want a 404 problem", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
}
