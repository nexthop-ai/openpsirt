// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestTimeToFixFromPublicationAnswersOnlyAtTheVisibilitiesTheReaderHolds(t *testing.T) {
	// One fixed issue, dated, at each visibility in turn. Each role is told
	// the publication figure and the undated count only where it reads the
	// occurrence, and the undated count follows the same rule once the date
	// is gone.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		ctx := t.Context()
		r.Scanned(t)
		now := time.Now().UTC()
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set(`"opened_at" = ?`, now.Add(-10*24*time.Hour)).
			Set(`"closed_at" = ?`, now.Add(-time.Hour)).
			Set(`"closed_because" = ?`, "upgraded").
			Where("1 = 1").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		dated := func(t *testing.T, at *time.Time) {
			t.Helper()
			if _, err := r.DB.DB.NewUpdate().Table("vulnerability").
				Set(`"published_at" = ?`, at).Where("1 = 1").Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		shown := func(t *testing.T, visibility access.Visibility) {
			t.Helper()
			if _, err := r.DB.DB.NewUpdate().Table("finding").
				Set(`"visibility" = ?`, visibility).Where("1 = 1").Exec(ctx); err != nil {
				t.Fatal(err)
			}
		}
		type figures struct {
			Fixed     int                `json:"fixed"`
			Published map[string]float64 `json:"time_to_fix_from_publication"`
			Undated   map[string]int     `json:"time_to_fix_undated"`
		}
		read := func(t *testing.T, who string) figures {
			t.Helper()
			var out figures
			httpapitest.Read(t, r, who, "/v1/remediation?days=30", &out)
			return out
		}
		published := now.Add(-30 * 24 * time.Hour)
		for _, visibility := range []access.Visibility{access.Public, access.Private} {
			shown(t, visibility)
			for who, reads := range map[string]bool{
				"reader":                  visibility == access.Public,
				"private":                 true,
				"embargo-reader":          visibility == access.Private,
				"security-testing-reader": false,
			} {
				dated(t, &published)
				got := read(t, who)
				if reads != (got.Published["high"] > 0) {
					t.Errorf("%s at %s: told %v from publication, want told: %v",
						who, visibility, got.Published, reads)
				}
				dated(t, nil)
				got = read(t, who)
				if reads != (got.Undated["high"] == 1) || len(got.Published) != 0 {
					t.Errorf("%s at %s undated: told %v undated and %v from publication, want told: %v",
						who, visibility, got.Undated, got.Published, reads)
				}
			}
		}
	})
}
