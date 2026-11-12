// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// The product a rule is written against is resolved inside the act. A product
// renamed after the early refusal read it is looked for by the name asked for
// and not found, rather than given a rule under a name it no longer has.
func TestARuleIsWrittenAgainstTheProductAsItIsWhenRecorded(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		hooked, rival := dbtest.RivalAfterSelect(t, r.DB, "product", 3*time.Second, func() error {
			_, err := r.DB.NewRaw(`UPDATE "product" SET "name" = ? WHERE "name" = ?`, "renamed", "mine").
				Exec(t.Context())
			return err
		})
		watched := *r.DB
		watched.DB = hooked
		made := httpapitest.AsPerson(t, r.Over(&watched), "assigner", http.MethodPost,
			"/v1/products/mine/assignment-rules", `{"name":"curl to the curlers","team":"curlers","upstream":"curl"}`)
		if err := rival(); err != nil {
			t.Fatal(err)
		}
		httpapitest.RefusedWith(t, made, http.StatusNotFound)
	})
}
