// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"fmt"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// The state filter selects a group exactly where its row reads that state, for
// every way a group's occurrences can be decided, a group both agreed and
// waiting included.
func TestTheStateFilterSelectsWhatTheRowSays(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		states := []DecisionStanding{StandingAgreed, StandingWaiting, StandingLapsed, StandingUndecided}
		checked := 0
		for n := 1; n <= 2; n++ {
			for waiting := 0; waiting <= n; waiting++ {
				for approved := 0; approved <= n; approved++ {
					for lapsed := 0; lapsed <= n; lapsed++ {
						word := stateWord(n, waiting, approved, lapsed)
						for _, state := range states {
							// One partial group under "f", as the grouped list reads them.
							var hit int
							err := db.DB.NewRaw(fmt.Sprintf(`SELECT COUNT(*) FROM (SELECT 1 AS "one" FROM
								(SELECT %d AS "n", %d AS "waiting", %d AS "approved", %d AS "lapsed") AS "f"
								GROUP BY "f"."n" HAVING %s) AS "matched"`, n, waiting, approved, lapsed,
								stateHaving(state, overParts))).Scan(ctx, &hit)
							if err != nil {
								t.Fatal(err)
							}
							checked++
							if (hit == 1) != (word == state) {
								t.Errorf("%d occurrences, %d waiting, %d agreed, %d lapsed: the row reads %q "+
									"and the %s filter selects it: %v", n, waiting, approved, lapsed, word, state, hit == 1)
							}
						}
					}
				}
			}
		}
		if checked == 0 {
			t.Fatal("no state was asked about, so this checked nothing")
		}
	})
}
