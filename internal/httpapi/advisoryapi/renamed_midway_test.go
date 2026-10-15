// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// A write naming a product resolves it inside the transaction that writes.
// Renamed between a refused commit and its retry, the product the request
// named is gone, and the retry answers that rather than writing against the
// row the first attempt read.
func TestAProductRenamedBeforeARetryIsWhatTheRetryReads(t *testing.T) {
	for _, c := range []struct {
		name string
		// first is what stands before the request, and send makes it.
		first func(t *testing.T, r *httpapitest.Reach)
		send  func(t *testing.T, r *httpapitest.Reach) *httptest.ResponseRecorder
	}{
		{"adding a supplier", nil, func(t *testing.T, r *httpapitest.Reach) *httptest.ResponseRecorder {
			return r.Named(t, "admin", http.MethodPost, "/v1/products/mine/advisory-sources", publishedAt)
		}},
		{"withdrawing a supplier", func(t *testing.T, r *httpapitest.Reach) {
			if got := r.Named(t, "admin", http.MethodPost, "/v1/products/mine/advisory-sources",
				publishedAt); got.Code != http.StatusCreated {
				t.Fatalf("naming a supplier answered %d: %s", got.Code, got.Body.String())
			}
		}, func(t *testing.T, r *httpapitest.Reach) *httptest.ResponseRecorder {
			return r.Named(t, "admin", http.MethodDelete,
				"/v1/products/mine/advisory-sources/ExampleDistribution", "")
		}},
		{"uploading VEX statements", nil, func(t *testing.T, r *httpapitest.Reach) *httptest.ResponseRecorder {
			return r.Vexed(t, "admin", "debian", httpapitest.Said("not_affected",
				"vulnerable_code_not_present", "The affected routine is not built."))
		}},
		{"uploading a supplier advisory", nil, func(t *testing.T, r *httpapitest.Reach) *httptest.ResponseRecorder {
			return r.Advised(t, "admin", "exsa.json",
				httpapitest.SupplierAdvisory("EXSA-2026:1001", "fixed", "3.7.0"))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := t.Context()
			var renamed func()
			handle, race := dbtest.Racing(t, func() { renamed() })
			names := catalog.NewStore(handle.DB)
			product, err := names.DeclareProduct(ctx, "mine", "mine")
			if err != nil {
				t.Fatal(err)
			}
			renamed = func() {
				if err := names.RenameProduct(ctx, product.ID, "ours"); err != nil {
					t.Errorf("renaming between the attempts: %v", err)
				}
			}
			rights := access.NewStore(handle.DB)
			admin, err := rights.Ensure(ctx, "admin", "", new(true), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := rights.Claim(ctx, admin.ID, "admin"); err != nil {
				t.Fatal(err)
			}
			handler, _ := httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, core.Deps{
				DB: handle, Queue: queue.New(handle, queue.DefaultOptions()),
				Access: httpapitest.Trusting(t, rights),
			})
			r := &httpapitest.Reach{Handler: handler, DB: handle}
			if c.first != nil {
				c.first(t, r)
			}

			race.Arm(1)
			got := c.send(t, r)
			if race.Unspent() != 0 {
				t.Fatal("no commit was refused, so nothing ran between the attempts")
			}
			httpapitest.RefusedWith(t, got, http.StatusNotFound)
		})
	}
}
