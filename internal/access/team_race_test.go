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
		admin := admin(t, f)
		member, err := f.store.Ensure(ctx, "member", "Member", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		for round := range rounds {
			name := fmt.Sprintf("team-%d", round)
			ids := declaredOnce(t, f, name, callers)

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

// declaredOnce declares one team from several callers at once and returns the
// team each was answered with, failing unless they share one team and exactly
// one caller was told it declared it.
func declaredOnce(t *testing.T, f *fixture, name string, callers int) []int64 {
	t.Helper()
	ids := make([]int64, callers)
	declared := make([]bool, callers)
	for i, err := range atOnce(callers, func(caller int) error {
		team, made, err := f.store.DeclareTeam(t.Context(), name, name)
		if err == nil {
			ids[caller], declared[caller] = team.ID, made
		}
		return err
	}) {
		if err != nil {
			t.Fatalf("declaring team %s at once: caller %d was refused: %v", name, i+1, err)
		}
	}
	declaring := 0
	for i, id := range ids {
		if id != ids[0] {
			t.Fatalf("declaring team %s at once made teams %d and %d", name, ids[0], ids[i])
		}
		if declared[i] {
			declaring++
		}
	}
	if declaring != 1 {
		t.Errorf("declaring team %s at once was reported as declaring it %d times, want once", name, declaring)
	}
	return ids
}

// TestReinstatingATeamTwiceAtOnceIsOneDeclaration holds that a retired team
// declared again from several callers at once is reinstated by one of them,
// and the others are told it was already in use. Every engine, because each
// orders the two conditional writes in its own way.
func TestReinstatingATeamTwiceAtOnceIsOneDeclaration(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		const callers, rounds = 4, 8
		for round := range rounds {
			name := fmt.Sprintf("retired-%d", round)
			team, _, err := f.store.DeclareTeam(t.Context(), name, name)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.store.RetireTeam(t.Context(), team.ID); err != nil {
				t.Fatal(err)
			}
			if ids := declaredOnce(t, f, name, callers); ids[0] != team.ID {
				t.Errorf("reinstating team %s made team %d, want %d", name, ids[0], team.ID)
			}
			if _, err := f.store.TeamByName(t.Context(), name); err != nil {
				t.Errorf("team %s is not in use after it was reinstated: %v", name, err)
			}
		}
	})
}
