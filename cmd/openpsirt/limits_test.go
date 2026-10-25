// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// The bounds an upload is refused by are the ones the configuration states. A
// scan past twice the configured size is refused before it is read, and an
// analyzer's document past it is refused as it is read.
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
			build + "/analyses": {"sarif", http.StatusUnprocessableEntity, "larger than the configured limit"},
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
