// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// A replica whose clock stands past the bound from the database's is refused,
// ahead or behind, and one in step is not.
func TestAClockApartFromTheDatabasesIsRefused(t *testing.T) {
	each(t, queue.DefaultOptions(), func(t *testing.T, _ *database.DB, q *queue.Queue) {
		ctx := t.Context()
		if err := q.CheckClock(ctx); err != nil {
			t.Fatalf("a clock in step was refused: %v", err)
		}
		for _, off := range []time.Duration{2 * queue.MostSkew, -2 * queue.MostSkew} {
			queue.SetClock(q, func() time.Time { return time.Now().UTC().Add(off) })
			if err := q.CheckClock(ctx); err == nil {
				t.Errorf("a clock %s off the database's was accepted", off)
			}
		}
	})
}
