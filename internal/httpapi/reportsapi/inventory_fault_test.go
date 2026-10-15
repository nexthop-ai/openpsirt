// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// A build whose filings could not be read is a fault. Answered as an empty
// list, an outage reads as an upload that changed nothing.
func TestAnInventoryChangeWhoseBuildCouldNotBeReadIsAFault(t *testing.T) {
	ctx := t.Context()
	handle := dbtest.Without(t, "target")
	names := catalog.NewStore(handle.DB)
	product, err := names.DeclareProduct(ctx, "mine", "mine")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := names.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := names.DeclareVariant(ctx, product.ID, "broadcom", true); err != nil {
		t.Fatal(err)
	}
	rights := access.NewStore(handle.DB)
	reader, err := rights.Ensure(ctx, "reader", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rights.Claim(ctx, reader.ID, "reader"); err != nil {
		t.Fatal(err)
	}
	if err := rights.GrantRole(ctx, reader.ID, product.ID, access.PublicRead); err != nil {
		t.Fatal(err)
	}
	handler, _ := httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, core.Deps{
		DB: handle, Queue: queue.New(handle, queue.DefaultOptions()),
		Access: httpapitest.Trusting(t, rights),
	})
	got := httpapitest.AsPerson(t, &httpapitest.Reach{Handler: handler}, "reader", http.MethodGet,
		"/v1/products/mine/streams/master/variants/broadcom/scans/1/changes", "")
	if got.Code != http.StatusInternalServerError {
		t.Errorf("an inventory change over a build that could not be read answered %d: %s",
			got.Code, got.Body.String())
	}
}
