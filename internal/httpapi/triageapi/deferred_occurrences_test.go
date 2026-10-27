// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triageapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAFindingSaysHowLongEachOccurrenceWasPutOff(t *testing.T) {
	// The decision form says whether a deferral stands on its own before it is
	// sent, and the server measures one against everything the occurrence was put
	// off for before. Without the total the form promises a repeat deferral
	// that it stands alone, and it is then gated.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := r.Scanned(t)
		const finding = "/v1/products/mine/branches-and-tags/master/variants/broadcom" +
			"/findings/CVE-2026-9999"

		type occurrences struct {
			Occurrences []struct {
				Occurrence   string  `json:"occurrence"`
				DeferredDays float64 `json:"deferred_days"`
			} `json:"occurrences"`
		}
		putOff := func(t *testing.T) float64 {
			t.Helper()
			var got occurrences
			httpapitest.Read(t, r, "triager", finding+"/components/libnl-3-200", &got)
			for _, each := range got.Occurrences {
				if each.Occurrence == occurrence {
					return each.DeferredDays
				}
			}
			t.Fatalf("the finding does not list the occurrence it was scanned at: %+v", got.Occurrences)
			return 0
		}

		if days := putOff(t); days != 0 {
			t.Fatalf("an occurrence nobody deferred reads %g days put off", days)
		}
		until := time.Now().UTC().AddDate(0, 0, 10).Format(time.DateOnly)
		if made := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			finding+"/occurrences/"+occurrence+"/decision",
			`{"outcome":"deferred","deferred_until":"`+until+
				`","reasoning":"Not this sprint."}`); made.Code != http.StatusCreated {
			t.Fatalf("deferring answered %d: %s", made.Code, made.Body.String())
		}
		// Measured to the moment rather than in whole days, because the
		// threshold is: a deferral to a date ten days out, asked after
		// midnight, is short of ten days by the part of today already gone.
		days := putOff(t)
		if days <= 9 || days >= 10 {
			t.Errorf("an occurrence deferred to a date ten days out reads %g days put off", days)
		}
	})
}
