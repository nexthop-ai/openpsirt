// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// The bounds an upload is refused by are the ones the configuration states. A
// scan past twice the configured size is refused before it is read, and an
// analyzer's document past it is refused by the bound as sent, which follows
// the configured one where nothing sets it.
func TestTheUploadBoundsTheServerRefusesByAreTheConfiguredOnes(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		product := fixture.New(t, db).Product
		_, secret, err := access.NewStore(db.DB).NewKey(ctx, "nightly", access.Scope{ProductID: product.ID})
		if err != nil {
			t.Fatal(err)
		}
		cfg := started()
		cfg.IngestMaxBytes, cfg.AnalysisMaxBytes = 4096, 4096
		handler, _, err := prepare(ctx, cfg, discard(), db)
		if err != nil {
			t.Fatal(err)
		}
		build := "/v1/products/" + fixture.ProductName + "/streams/" + fixture.BranchName +
			"/variants/" + fixture.CustomerVariant
		padded := `{"version":"2.1.0",` + strings.Repeat(" ", 3*4096) + `"runs":[]}`
		for path, c := range map[string]struct {
			field string
			code  int
			says  string
		}{
			build + "/scans":    {"inventory", http.StatusRequestEntityTooLarge, "8192 bytes"},
			build + "/analyses": {"sarif", http.StatusUnprocessableEntity, "the configured limit of 4096"},
		} {
			body, form := httpapitest.Form(t, httpapitest.Part{Field: c.field, Filename: "doc.json", Content: padded})
			req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, body)
			req.Header.Set("Content-Type", form)
			req.Header.Set("Authorization", "Bearer "+secret)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.says) {
				t.Errorf("%s answered %d to a request past the configured bound, want %d: %s",
					path, rec.Code, c.code, rec.Body.String())
			}
		}
	})
}

// An analyzer upload is bounded as it is sent, the whole request and each
// document, by the settings for those bounds, apart from the bound on what
// its documents hold once decompressed.
func TestAnAnalyzerUploadIsBoundedAsItIsSent(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		product := fixture.New(t, db).Product
		_, secret, err := access.NewStore(db.DB).NewKey(ctx, "nightly", access.Scope{ProductID: product.ID})
		if err != nil {
			t.Fatal(err)
		}
		path := "/v1/products/" + fixture.ProductName + "/streams/" + fixture.BranchName +
			"/variants/" + fixture.CustomerVariant + "/analyses"
		// The request's bound leaves room for the form around the documents,
		// so the request past it is padded past that room as well.
		padded := func(n int) string { return `{"version":"2.1.0",` + strings.Repeat(" ", n) + `"runs":[]}` }
		for name, c := range map[string]struct {
			set  func(*config.Config)
			doc  string
			code int
			says string
		}{
			"the request": {func(c *config.Config) { c.AnalysisMaxCompressed = 4096 }, padded(3 << 20),
				http.StatusRequestEntityTooLarge, "bytes"},
			"one document": {func(c *config.Config) { c.AnalysisMaxPartCompressed = 4096 }, padded(3 * 4096),
				http.StatusUnprocessableEntity, "one document as it was sent"},
		} {
			t.Run(name, func(t *testing.T) {
				cfg := started()
				c.set(&cfg)
				handler, _, err := prepare(ctx, cfg, discard(), db)
				if err != nil {
					t.Fatal(err)
				}
				body, form := httpapitest.Form(t, httpapitest.Part{Field: "sarif", Filename: "doc.json", Content: c.doc})
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, body)
				req.Header.Set("Content-Type", form)
				req.Header.Set("Authorization", "Bearer "+secret)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.says) {
					t.Errorf("answered %d past the bound, want %d holding %q: %s",
						rec.Code, c.code, c.says, rec.Body.String())
				}
			})
		}
	})
}
