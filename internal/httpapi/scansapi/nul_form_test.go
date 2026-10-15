// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// A form field holding a NUL is refused naming the field, before anything is
// stored. The file beside it is not typed input and is not what refuses it.
func TestAFormFieldHoldingANULIsRefusedNamingTheField(t *testing.T) {
	twoIngest(t, queue.Options{}, func(t *testing.T, f *httpapitest.IngestFixture) {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		part, err := form.CreateFormFile("inventory", "sonic.cdx.json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, httpapitest.Inventory(httpapitest.Nowish(), "libc6")); err != nil {
			t.Fatal(err)
		}
		if err := form.WriteField("note", "night\x00ly"); err != nil {
			t.Fatal(err)
		}
		if err := form.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, f.Path, &body)
		req.Header.Set("Content-Type", form.FormDataContentType())
		rec := httptest.NewRecorder()
		f.Handler.ServeHTTP(rec, f.Sending(req))
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "form field note holds a NUL character") {
			t.Errorf("a form field holding a NUL answered %d: %s", rec.Code, rec.Body.String())
		}
		var scans int
		if err := f.DB.DB.NewRaw(`SELECT COUNT(*) FROM "scan"`).Scan(t.Context(), &scans); err != nil {
			t.Fatal(err)
		}
		if scans != 0 {
			t.Errorf("%d scans were recorded from a refused upload", scans)
		}
	})
}
