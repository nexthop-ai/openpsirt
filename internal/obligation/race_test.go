// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package obligation_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uptrace/bun"

	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/obligation"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// rivalDuring returns a store whose first statement starting with verb on
// table starts rival on another connection and waits a moment before the
// statement goes on, without waiting for rival to finish.
//
// For a rival that has to wait on what this transaction holds: run in line,
// it would wait on a transaction that waits on it.
func rivalDuring(t *testing.T, f *fixture, verb, table string, rival func() error) (
	*obligation.Store, func() error) {
	t.Helper()
	if f.db.Stats().MaxOpenConnections == 1 {
		t.Skip("one connection: nothing lands between a read and a write")
	}
	hooked := bun.NewDB(f.db.DB.DB, f.db.Dialect())
	hook := &during{verb: verb, table: table, rival: rival, done: make(chan error, 1)}
	hooked.AddQueryHook(hook)
	return obligation.NewStore(hooked), func() error {
		if !hook.ran {
			t.Fatal("the rival never ran, so nothing landed between the read and the write")
		}
		return <-hook.done
	}
}

type during struct {
	once        sync.Once
	verb, table string
	rival       func() error
	ran         bool
	done        chan error
}

func (h *during) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	named := strings.Contains(e.Query, h.table+"`") || strings.Contains(e.Query, h.table+`"`)
	if strings.HasPrefix(e.Query, h.verb+" ") && named {
		h.once.Do(func() {
			h.ran = true
			go func() { h.done <- h.rival() }()
			// Long enough for the rival to reach whatever it waits on.
			time.Sleep(300 * time.Millisecond)
		})
	}
	return ctx
}

func (h *during) AfterQuery(context.Context, *bun.QueryEvent) {}

// A window declared to count from another while that one is being retired
// leaves one of the two acts refused, never a window counting from a retired
// one, which would wait on a notice nobody can record.
func TestAWindowIsNotDeclaredFromOneRetiredAtTheSameTime(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		notification := f.window(t, "Notification", 72)
		racing, rival := rivalDuring(t, f, "INSERT", "obligation_window", func() error {
			return f.store.RetireWindow(context.Background(), f.admin, notification.ID)
		})
		_, declared := racing.DeclareWindow(t.Context(), f.admin, obligation.WindowSaid{
			Name: "Final report", Hours: 720, From: &notification.ID,
		})
		retired := rival()
		if declared == nil && retired == nil {
			t.Fatal("a window was declared counting from one retired at the same time")
		}
		if declared == nil && !errors.Is(retired, obligation.ErrCountedFrom) {
			t.Errorf("retiring a window another came to count from answered %v", retired)
		}
	})
}

// Two changes at once that would close a loop between them leave one refused.
func TestTwoChangesAtOnceCloseNoLoop(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		a := f.window(t, "A", 24)
		b := f.window(t, "B", 24)
		racing, rival := rivalDuring(t, f, "UPDATE", "obligation_window", func() error {
			_, err := f.store.ChangeWindow(context.Background(), f.admin, b.ID, obligation.WindowSaid{
				Name: "B", Hours: 24, From: &a.ID,
			})
			return err
		})
		_, first := racing.ChangeWindow(t.Context(), f.admin, a.ID, obligation.WindowSaid{
			Name: "A", Hours: 24, From: &b.ID,
		})
		second := rival()
		if first == nil && second == nil {
			t.Fatal("two windows came to count from each other")
		}
	})
}

// A fix release named while the record is being cleared lands before the
// clearing or not at all: the clearing waits for the naming, so no naming
// arrives on a record already cleared.
func TestAFixIsNotNamedOnARecordClearedAtTheSameTime(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		record := f.attacked(t)
		var cleared time.Time
		racing, rival := rivalDuring(t, f, "INSERT", "exploited_fix", func() error {
			err := triage.NewStore(f.db.DB).ClearExploitedHere(context.Background(), f.triager,
				record.ID, "It was a test harness.")
			cleared = time.Now()
			return err
		})
		_, named := racing.NameFix(t.Context(), f.triager, record.ID, world.TagName)
		returned := time.Now()
		if err := rival(); err != nil {
			t.Fatalf("the rival clearing: %v", err)
		}
		if named == nil && cleared.Before(returned) {
			t.Error("a fix release was named on a record cleared before the naming committed")
		}
	})
}
