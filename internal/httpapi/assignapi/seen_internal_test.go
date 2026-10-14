// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"context"
	"log/slog"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// counted is a log handler that keeps how many error lines were written.
type counted struct{ errors int }

func (c *counted) Enabled(context.Context, slog.Level) bool { return true }
func (c *counted) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		c.errors++
	}
	return nil
}
func (c *counted) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *counted) WithGroup(string) slog.Handler      { return c }

// A notice dropped because who would receive it could not be read is logged,
// as every notification that could not be sent is. Dropped silently, nobody
// learns that somebody was handed work and never told.
func TestANoticeDroppedOnAFailedReadIsLogged(t *testing.T) {
	logged := &counted{}
	in := core.Deps{DB: dbtest.Without(t, "person"), Logger: slog.New(logged)}
	if seenBy(t.Context(), in, "triager", 1, false) {
		t.Fatal("somebody whose record could not be read was told")
	}
	if logged.errors == 0 {
		t.Error("the notice was dropped and nothing said so")
	}
}

// Somebody nobody knows is not a failure, and nothing is logged.
func TestANoticeForNobodyIsDroppedQuietly(t *testing.T) {
	logged := &counted{}
	handle, _ := dbtest.Racing(t, nil)
	in := core.Deps{DB: handle, Logger: slog.New(logged)}
	if seenBy(t.Context(), in, "nobody-here", 1, false) {
		t.Fatal("somebody nobody knows was told")
	}
	if logged.errors != 0 {
		t.Errorf("a notice for nobody logged %d errors", logged.errors)
	}
}
