// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// The product a token is narrowed to is resolved where the token is minted. A
// product renamed after the early refusal read it is looked for by the name
// asked for and not found, rather than narrowing the token to a product by a
// name it no longer has.
func TestATokenIsNarrowedToTheProductAsItIsWhenMinted(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		hooked, rival := dbtest.RivalAfterSelect(t, r.DB, "product", 3*time.Second, func() error {
			_, err := r.DB.NewRaw(`UPDATE "product" SET "name" = ? WHERE "name" = ?`, "renamed", "mine").
				Exec(t.Context())
			return err
		})
		watched := *r.DB
		watched.DB = hooked
		made := httpapitest.AsPerson(t, r.Over(&watched), "private", http.MethodPost, "/v1/tokens",
			`{"name":"nightly","lifetime":"24h","product":"mine"}`)
		if err := rival(); err != nil {
			t.Fatal(err)
		}
		httpapitest.RefusedWith(t, made, http.StatusNotFound)
	})
}
