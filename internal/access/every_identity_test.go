// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// Read for everybody at once, how each person signs in is what reading them
// one at a time answers, and a person with no way in yet is absent.
func TestEveryIdentityIsWhatEachPersonsOwnReadAnswers(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		var people []int64
		for _, identity := range []string{"zed", "amy", "kim"} {
			person, err := rights.Ensure(ctx, identity, "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			people = append(people, person.ID)
			if identity != "kim" {
				if err := rights.Claim(ctx, person.ID, identity); err != nil {
					t.Fatal(err)
				}
			}
		}

		// A second way in for zed, claimed later and sorting first, so the
		// order the two are read in is the order of their names.
		if err := rights.Claim(ctx, people[0], "aaa-zed"); err != nil {
			t.Fatal(err)
		}

		every, err := rights.EveryIdentity(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(every) == 0 {
			t.Fatal("nobody signs in any way, so this compared nothing")
		}
		for _, id := range people {
			one, err := rights.Identities(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.EqualFunc(every[id], one, func(a, b access.Identity) bool {
				return a.ID == b.ID && a.Username == b.Username
			}) {
				t.Errorf("person %d signs in by %+v read together and %+v read alone", id, every[id], one)
			}
		}
		if len(every[people[0]]) != 2 {
			t.Errorf("zed signs in by %+v, want both ways in", every[people[0]])
		}
		if got, held := every[people[2]]; held {
			t.Errorf("somebody with no way in signs in by %+v", got)
		}
	})
}
