// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue_test

import (
	"context"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// A turn whose row was never made serializes nothing, so taking it is
// refused rather than passing as though it had waited.
func TestATurnWithNoRowIsRefused(t *testing.T) {
	each(t, queue.DefaultOptions(), func(t *testing.T, db *database.DB, _ *queue.Queue) {
		ctx := t.Context()
		take := func(name string) error {
			return database.InTransaction(ctx, db.DB, func(ctx context.Context, tx bun.Tx) error {
				return queue.TakeTurn(ctx, tx, name)
			})
		}
		if err := take("never made"); err == nil {
			t.Error("a turn with no row was taken")
		}
		if err := queue.EnsureTurn(ctx, db.DB, "made"); err != nil {
			t.Fatal(err)
		}
		if err := take("made"); err != nil {
			t.Errorf("a turn whose row was made was refused: %v", err)
		}
		// Taken twice in a row, the second write still matches its row.
		if err := take("made"); err != nil {
			t.Errorf("a turn taken again was refused: %v", err)
		}
	})
}
