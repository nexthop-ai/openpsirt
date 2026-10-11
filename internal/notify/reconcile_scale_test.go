// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build measure

package notify_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// The shape of a sweep that opens every waiting claim at once: the triage
// bench holds 430 claims waiting on a second person in one product, and 200
// approvers there each hear about all of them, which is 86,000 conditions.
const (
	sweepPeople = 200
	sweepClaims = 430
)

// counted is a query hook that counts statements.
type counted struct{ n int }

func (c *counted) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context { return ctx }
func (c *counted) AfterQuery(context.Context, *bun.QueryEvent)                        { c.n++ }

func TestMeasureASweepOpeningEveryWaitingClaim(t *testing.T) {
	// Every approver reconciled once per phase, as a sweep does: opening
	// every condition, a sweep where nothing moved, every sentence moving,
	// and every condition clearing. Measured as statements and wall time,
	// against the sweep where nothing moved.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		people := make([]int64, sweepPeople)
		for i := range people {
			who, err := access.NewStore(db.DB).Ensure(ctx,
				fmt.Sprintf("approver%d@example.com", i), "Approver", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			people[i] = who.ID
		}
		held := func(waiting string) []notify.Holds {
			out := make([]notify.Holds, sweepClaims)
			for i := range out {
				out[i] = notify.Holds{
					About: fmt.Sprintf("claim-waiting %d", i),
					Body: fmt.Sprintf("A claim in sonic has been waiting %s for a second person. "+
						"It covers %d places and takes effect only once somebody agrees to it.",
						waiting, i+1),
					Link: "/review-queue",
				}
			}
			return out
		}
		store := notify.NewStore(db.DB)
		sent := &counted{}
		db.AddQueryHook(sent)
		phase := func(name string, holds []notify.Holds) time.Duration {
			t.Helper()
			sent.n = 0
			opened, cleared := 0, 0
			start := time.Now()
			for _, person := range people {
				o, c, err := store.Reconcile(ctx, person, notify.ClaimWaiting, holds)
				if err != nil {
					t.Fatal(err)
				}
				opened, cleared = opened+o, cleared+c
			}
			took := time.Since(start)
			t.Logf("%-8s %8s  %6d statements  opened %d cleared %d",
				name, took.Round(time.Millisecond), sent.n, opened, cleared)
			return took
		}
		opening := phase("open", held("3 weeks"))
		steady := phase("steady", held("3 weeks"))
		restating := phase("restate", held("4 weeks"))
		clearing := phase("clear", nil)
		t.Logf("%d conditions: opening %.1fx, restating %.1fx, clearing %.1fx the steady sweep",
			sweepPeople*sweepClaims, opening.Seconds()/steady.Seconds(),
			restating.Seconds()/steady.Seconds(), clearing.Seconds()/steady.Seconds())
	})
}
