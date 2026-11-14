// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// Exports holding a connection past the slots are refused rather than queued for a
// connection.
func TestStreamedExportsPastTheSlotsAreRefused(t *testing.T) {
	slots := make(streamSlots, 1)
	release, err := slots.take()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := slots.take(); err == nil {
		t.Error("a second stream was let through a single slot")
	}
	release()
	again, err := slots.take()
	if err != nil {
		t.Errorf("a released slot was not given back: %v", err)
	} else {
		again()
	}
}

// A pool of one connection gives exports holding a connection one slot: a second would
// wait for the connection the first holds. The harness holds SQLite to one.
func TestAPoolOfOneConnectionGivesStreamedExportsOneSlot(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		if open := db.Stats().MaxOpenConnections; open != 1 {
			t.Fatalf("the harness gave SQLite %d connections, where this needs one", open)
		}
		if got := cap(newStreamSlots(db)); got != 1 {
			t.Errorf("one connection is shared by %d exports", got)
		}
	})
}

// A file read whole before its first byte holds no connection while it is
// written, so it is answered when every place is taken; one reading as it
// writes is refused.
func TestAFileReadWholeTakesNoPlaceAmongExportsHoldingAConnection(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		in := Deps{DB: db}
		slots := streamSlotsFor(db)
		held := make([]func(), 0, cap(slots))
		for range cap(slots) {
			release, err := slots.take()
			if err != nil {
				t.Fatal(err)
			}
			held = append(held, release)
		}
		defer func() {
			for _, release := range held {
				release()
			}
		}()
		if _, err := Export(in, "csv", "whole", Exporting{Header: []string{"n"}, Held: [][]string{{"1"}}}); err != nil {
			t.Errorf("a file read whole was refused while every place was taken: %v", err)
		}
		paged := Exporting{Header: []string{"n"},
			Rows: func(context.Context, bun.IDB, time.Time, int, int) ([][]string, error) { return nil, nil }}
		if _, err := Export(in, "csv", "paged", paged); err == nil {
			t.Error("a paged file was let through with every place taken")
		}
	})
}
