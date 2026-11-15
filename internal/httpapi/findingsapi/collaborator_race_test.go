// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// Whether the issue is in the product is asked again where a collaborator's
// grant is written, and that answer decides. An issue whose findings left the
// product after the early refusal read them is refused as absent, never
// granted.
func TestACollaboratorIsBroughtInOnlyWhileTheIssueIsInTheProduct(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedWithEvidence(t)
		embargoed := r.Embargoed(t)
		hooked, rival := dbtest.RivalAfterSelect(t, r.DB, "finding", 3*time.Second, func() error {
			_, err := r.DB.NewRaw(`UPDATE "finding" SET "kind" = 'analysis' WHERE "vulnerability_id" IN `+
				`(SELECT "id" FROM "vulnerability" WHERE "identifier" = ?)`, embargoed).Exec(t.Context())
			return err
		})
		watched := *r.DB
		watched.DB = hooked
		got := httpapitest.AsPerson(t, r.Over(&watched), "private-triage", http.MethodPut,
			fmt.Sprintf("/v1/products/mine/issues/%s/collaborators/%s", embargoed, "triager"), "")
		if err := rival(); err != nil {
			t.Fatal(err)
		}
		httpapitest.RefusedWith(t, got, http.StatusNotFound)
	})
}
