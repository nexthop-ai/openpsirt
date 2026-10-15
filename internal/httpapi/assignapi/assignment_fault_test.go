// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

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

// Somebody's work whose holder could not be looked up is a fault. Answered as
// a name nobody holds, an outage reads as somebody holding nothing.
//
// The caller is recognized from a database of its own, so the first read the
// route makes of its own handle is the lookup of the name it was asked about.
func TestAPersonsWorkWhoseHolderCouldNotBeLookedUpIsAFault(t *testing.T) {
	ctx := t.Context()
	recognizing, _ := dbtest.Racing(t, nil)
	rights := access.NewStore(recognizing.DB)
	caller, err := rights.Ensure(ctx, "caller", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rights.Claim(ctx, caller.ID, "caller"); err != nil {
		t.Fatal(err)
	}
	product, err := catalog.NewStore(recognizing.DB).DeclareProduct(ctx, "mine", "mine")
	if err != nil {
		t.Fatal(err)
	}
	if err := rights.GrantRole(ctx, caller.ID, product.ID, access.PublicRead); err != nil {
		t.Fatal(err)
	}
	handle := dbtest.Without(t, "person")
	handler, _ := httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, core.Deps{
		DB: handle, Queue: queue.New(handle, queue.DefaultOptions()),
		Access: httpapitest.Trusting(t, rights),
	})
	got := httpapitest.AsPerson(t, &httpapitest.Reach{Handler: handler}, "caller", http.MethodGet,
		"/v1/people/somebody/assignments", "")
	if got.Code != http.StatusInternalServerError {
		t.Errorf("a person's work over a lookup that failed answered %d: %s",
			got.Code, got.Body.String())
	}
}
