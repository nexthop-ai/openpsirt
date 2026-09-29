// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// Streamed exports past the slots are refused rather than queued for a
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

// SQLite's pool is one connection, so a streamed export is given one slot
// there: a second would wait for the connection the first holds.
func TestSQLiteGivesStreamedExportsOneSlot(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		if got := cap(newStreamSlots(db)); got != 1 {
			t.Errorf("SQLite's one connection is shared by %d streamed exports", got)
		}
	})
}
