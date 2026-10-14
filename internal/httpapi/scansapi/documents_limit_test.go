// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scansapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/bound/boundtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// answered is a response status taken as an error.
type answered int

func (a answered) Error() string { return http.StatusText(int(a)) }

func TestAScanCarryingMoreSuppressionDocumentsThanTheLimitIsRefused(t *testing.T) {
	const most = 2
	limitedIngest(t, sbom.Limits{MaxDocuments: most}, func(t *testing.T, f *httpapitest.IngestFixture) {
		statement := `{"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}`
		var refused *httptest.ResponseRecorder
		boundtest.Edges(t, most, func(n int) error {
			documents := make([]string, n)
			for i := range documents {
				documents[i] = statement
			}
			inventory := httpapitest.Inventory(httpapitest.Nowish(), "libc6")
			rec := httptest.NewRecorder()
			f.Handler.ServeHTTP(rec, f.Sending(httpapitest.Upload(t, f.Path, inventory, documents...)))
			if rec.Code < 300 {
				return nil
			}
			refused = rec
			return answered(rec.Code)
		}, func(err error) bool {
			return err == answered(http.StatusUnprocessableEntity) &&
				strings.Contains(refused.Body.String(), "suppression documents")
		})

		var scans int
		if err := f.DB.DB.NewRaw(`SELECT COUNT(*) FROM "scan"`).Scan(t.Context(), &scans); err != nil {
			t.Fatal(err)
		}
		if scans != 1 {
			t.Errorf("%d scans were recorded, want the one at the limit", scans)
		}
		depth, err := f.Queue.Depth(t.Context(), queue.Parse)
		if err != nil {
			t.Fatal(err)
		}
		if depth != 1 {
			t.Errorf("%d parse jobs are queued, want the one at the limit", depth)
		}
	})
}
