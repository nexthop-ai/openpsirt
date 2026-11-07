// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package incident_test

import (
	"testing"

	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/incident"
)

// takenBy is the value a row was last taken with.
func (f *fixture) takenBy(t *testing.T, table string, id int64) string {
	t.Helper()
	var by *string
	if err := f.db.DB.NewSelect().Table(table).Column("taken_by").Where(`"id" = ?`, id).
		Scan(t.Context(), &by); err != nil {
		t.Fatal(err)
	}
	if by == nil {
		return ""
	}
	return *by
}

// freshEachTime fails unless both values are set and differ.
func freshEachTime(t *testing.T, what string, values []string) {
	t.Helper()
	if values[0] == "" || values[0] == values[1] {
		t.Errorf("%s was taken with %q then %q, want a fresh value each time", what, values[0], values[1])
	}
}

// A take writing the value a row already holds is skipped on MySQL and
// MariaDB, and a cluster never certifies it, so two changes of windows on two
// nodes would not wait for each other.
func TestEveryChangeOfAWindowTakesTheWindowsInForceWithAFreshValue(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		window := f.window(t, "Notification", 72)
		var seen []string
		for _, hours := range []int{48, 24} {
			if _, err := f.store.ChangeWindow(t.Context(), f.admin, window.ID,
				incident.WindowSaid{Name: "Notification", Hours: hours}); err != nil {
				t.Fatal(err)
			}
			seen = append(seen, f.takenBy(t, "response_window", window.ID))
		}
		freshEachTime(t, "the window", seen)
	})
}

// A take writing the value a row already holds is skipped on MySQL and
// MariaDB, and a cluster never certifies it, so a naming of a fix and a
// clearing on two nodes would not wait for each other.
func TestEveryActOnAFixTakesTheRecordWithAFreshValue(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		record := f.attacked(t)
		named, err := f.store.NameFix(t.Context(), f.triager, record.ID, world.TagName)
		if err != nil {
			t.Fatal(err)
		}
		seen := []string{f.takenBy(t, "incident", record.ID)}
		if err := f.store.WithdrawFix(t.Context(), f.triager, record.ID, named.ID); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, f.takenBy(t, "incident", record.ID))
		freshEachTime(t, "the record", seen)
	})
}
