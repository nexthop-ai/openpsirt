// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// A mention whose notification failed is reported as reaching nobody, along
// with every name after it, which the walk never reached.
//
// The author reads the list of names that did not land and believes the rest
// were told. A failure answered with the names gathered so far tells them
// somebody was notified who was not.
func TestAMentionThatWasNotToldIsReportedAsNotTold(t *testing.T) {
	byName := map[string]int64{"alice": 1, "bob": 2, "carol": 3}
	failOn := int64(2)
	tell := func(who int64) error {
		if who == failOn {
			return errors.New("the notification could not be stored")
		}
		return nil
	}

	dropped, err := tellEach([]string{"alice", "Bob", "carol", "ghost"}, byName, 9, nil, tell)
	if err == nil {
		t.Error("a failed notification was reported as none failing")
	}
	if want := []string{"Bob", "carol", "ghost"}; !slices.Equal(dropped, want) {
		t.Errorf("reported %v as not told, want %v", dropped, want)
	}

	// A name repeated after it was told is not reported for the failure that
	// came later.
	dropped, _ = tellEach([]string{"alice", "bob", "alice"}, byName, 9, nil, tell)
	if want := []string{"bob"}; !slices.Equal(dropped, want) {
		t.Errorf("reported %v as not told, want %v", dropped, want)
	}

	// Nothing failing: only the name nobody holds, and never the author.
	failOn = 0
	dropped, err = tellEach([]string{"alice", "ghost", "me"}, map[string]int64{"alice": 1, "me": 9},
		9, nil, tell)
	if err != nil || !slices.Equal(dropped, []string{"ghost"}) {
		t.Errorf("reported %v, %v as not told, want only the name nobody holds", dropped, err)
	}
}

// Who may be told could not be read, so every name is reported as not told.
func TestMentionsAreAllNotToldWhenTheReadersCannotBeRead(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		if err := db.DB.DB.Close(); err != nil {
			t.Fatal(err)
		}
		dropped, err := mentioned(t.Context(), Deps{DB: db},
			access.Everything("a test asking who may be told"),
			mentionTarget{ProductID: 1, VulnerabilityID: 1, Visibility: access.Public},
			"@alice and @bob, look", "/claims/1")
		if err == nil {
			t.Error("a failed read of who may be told was reported as none failing")
		}
		if want := []string{"alice", "bob"}; !slices.Equal(dropped, want) {
			t.Errorf("reported %v as not told, want %v", dropped, want)
		}
	})
}
