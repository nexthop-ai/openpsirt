// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"testing"
	"time"
)

func TestAFindingSaysHowLongEachPlaceWasPutOff(t *testing.T) {
	// The decision form says whether a deferral stands on its own before it is
	// sent, and the server measures one against everything the place was put
	// off for before. Without the total the form promises a repeat deferral
	// that it stands alone, and it is then gated.
	twoReach(t, func(t *testing.T, r *reach) {
		place := r.scanned(t)
		const finding = "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999"

		type places struct {
			Places []struct {
				Place        string `json:"place"`
				DeferredDays int    `json:"deferred_days"`
			} `json:"places"`
		}
		putOff := func(t *testing.T) int {
			t.Helper()
			var got places
			read(t, r, "triager", finding+"/components/libnl-3-200", &got)
			for _, each := range got.Places {
				if each.Place == place {
					return each.DeferredDays
				}
			}
			t.Fatalf("the finding does not list the place it was scanned at: %+v", got.Places)
			return 0
		}

		if days := putOff(t); days != 0 {
			t.Fatalf("a place nobody deferred reads %d days put off", days)
		}
		until := time.Now().UTC().AddDate(0, 0, 10).Format(time.DateOnly)
		if made := asPerson(t, r, "triager", http.MethodPost,
			finding+"/places/"+place+"/decision",
			`{"outcome":"deferred","deferred_until":"`+until+
				`","reasoning":"Not this sprint."}`); made.Code != http.StatusCreated {
			t.Fatalf("deferring answered %d: %s", made.Code, made.Body.String())
		}
		if days := putOff(t); days < 9 || days > 10 {
			t.Errorf("a place deferred for ten days reads %d days put off", days)
		}
	})
}
