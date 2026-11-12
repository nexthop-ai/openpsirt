// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"fmt"
	"sync"
	"testing"
)

// atOnce runs fn from several callers together and returns what each
// answered.
func atOnce(callers int, fn func(caller int) error) []error {
	failures := make([]error, callers)
	var wait sync.WaitGroup
	start := make(chan struct{})
	for i := range failures {
		wait.Go(func() {
			<-start
			failures[i] = fn(i)
		})
	}
	close(start)
	wait.Wait()
	return failures
}

// TestDeclaringATeamOrAMembershipTwiceAtOnceSucceedsBothTimes holds that a
// second declarer losing the race to the unique index is answered as though it
// came second. Every engine, because each refuses the losing insert in its own
// way and at its own moment.
func TestDeclaringATeamOrAMembershipTwiceAtOnceSucceedsBothTimes(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		const callers, rounds = 4, 8
		admin, err := f.store.Ensure(ctx, "admin", "Admin", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		member, err := f.store.Ensure(ctx, "member", "Member", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for round := range rounds {
			name := fmt.Sprintf("team-%d", round)
			ids := make([]int64, callers)
			for i, err := range atOnce(callers, func(caller int) error {
				team, err := f.store.DeclareTeam(ctx, name, name)
				if err == nil {
					ids[caller] = team.ID
				}
				return err
			}) {
				if err != nil {
					t.Fatalf("declaring team %s at once: caller %d was refused: %v", name, i+1, err)
				}
			}
			for i, id := range ids {
				if id != ids[0] {
					t.Fatalf("declaring team %s at once made teams %d and %d", name, ids[0], ids[i])
				}
			}

			added := make([]bool, callers)
			for i, err := range atOnce(callers, func(caller int) error {
				var err error
				added[caller], err = f.store.AddToTeam(ctx, ids[0], member.ID, admin.ID)
				return err
			}) {
				if err != nil {
					t.Fatalf("putting somebody on team %s at once: caller %d was refused: %v", name, i+1, err)
				}
			}
			adding := 0
			for _, a := range added {
				if a {
					adding++
				}
			}
			if adding != 1 {
				t.Errorf("putting somebody on team %s at once was reported as adding them %d times, want once", name, adding)
			}
		}
	})
}
