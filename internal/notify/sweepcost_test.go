// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// sentQueries records every statement sent, with identifiers in double
// quotes whichever quote the engine's dialect writes them in.
type sentQueries struct {
	mu   sync.Mutex
	sent []string
}

func (s *sentQueries) BeforeQuery(ctx context.Context, _ *bun.QueryEvent) context.Context {
	return ctx
}

func (s *sentQueries) AfterQuery(_ context.Context, event *bun.QueryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, strings.ReplaceAll(event.Query, "`", `"`))
}

// containing is how many statements sent contain every one of parts.
func (s *sentQueries) containing(parts ...string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, query := range s.sent {
		all := true
		for _, part := range parts {
			all = all && strings.Contains(query, part)
		}
		if all {
			n++
		}
	}
	return n
}

func TestASweepLeavesAloneWhoeverHasNothingToHearOrClear(t *testing.T) {
	// Every person who may act on a product is a possible recipient of every
	// kind of condition, and almost all of them hold none of almost all
	// kinds. Reconciling an empty list against nothing open does nothing, so
	// a sweep asks only about the people a condition found or one is open
	// for — and reads who may act once rather than once per condition.
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		ctx := t.Context()
		tm := aTeam(t, w, "ana", "ben", "cy")
		// Something the administrator was told that is no longer true, so
		// the sweep has one person to reconcile.
		if _, _, err := notify.NewStore(w.DB.DB).Reconcile(ctx, tm.admin.ID, notify.BuildQuiet,
			[]notify.Holds{{About: "gone", Body: "A build that is no longer quiet."}}); err != nil {
			t.Fatal(err)
		}
		asked := &sentQueries{}
		w.DB.AddQueryHook(asked)
		if _, _, err := notify.NewWatch(w.DB.DB, slog.New(slog.NewTextHandler(io.Discard, nil))).
			Once(ctx); err != nil {
			t.Fatal(err)
		}
		if n := asked.containing(`FROM "notification" AS "nt"`,
			fmt.Sprintf("(person_id = %d)", tm.admin.ID)); n == 0 {
			t.Fatal("the sweep did not reconcile the administrator, so this checked nothing")
		}
		for name, person := range tm.people {
			if n := asked.containing(`FROM "notification" AS "nt"`,
				fmt.Sprintf("(person_id = %d)", person.ID)); n != 0 {
				t.Errorf("%s holds nothing and was reconciled %d times", name, n)
			}
		}
		if n := asked.containing(`FROM "role_grant" AS "rg" ORDER BY`); n != 1 {
			t.Errorf("who may act was read %d times in one sweep, want once", n)
		}
	})
}
