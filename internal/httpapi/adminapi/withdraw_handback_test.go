// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

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

// Withdrawing somebody's last role on a product and handing back their work
// there commit together. Over a database where the hand-back cannot be
// written, the withdrawal fails with it and the role is still held: committed
// alone, the role is gone and the work stays with somebody who can no longer
// open it, and asking again answers that there is no such grant.
func TestALastRoleAndTheWorkHandedBackAreWithdrawnTogether(t *testing.T) {
	ctx := t.Context()
	handle := dbtest.Without(t, "finding")
	mine, err := catalog.NewStore(handle.DB).DeclareProduct(ctx, "mine", "mine")
	if err != nil {
		t.Fatal(err)
	}
	rights := access.NewStore(handle.DB)
	admin, err := rights.Ensure(ctx, "admin", "", access.Stated(true), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rights.Claim(ctx, admin.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	triager, err := rights.Ensure(ctx, "triager", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := rights.GrantRole(ctx, triager.ID, mine.ID, access.PublicRead); err != nil {
		t.Fatal(err)
	}
	sources, err := access.ParseSources("192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := httpapi.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, core.Deps{
		DB: handle, Queue: queue.New(handle, queue.DefaultOptions()),
		Access: access.NewResolver(rights,
			access.Trust{Header: httpapitest.TestHeader, From: sources}),
	})

	got := httpapitest.AsPerson(t, &httpapitest.Reach{Handler: handler}, "admin",
		http.MethodDelete, "/v1/people/triager/roles/mine/public-read", "")
	if got.Code != http.StatusInternalServerError {
		t.Errorf("a withdrawal whose hand-back could not be written answered %d: %s",
			got.Code, got.Body.String())
	}
	held, err := rights.HoldsAnythingIn(ctx, triager.ID, mine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Error("the role was withdrawn although the work it held could not be handed back")
	}
}
