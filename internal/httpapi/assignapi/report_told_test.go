// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// errorsLogged is a log handler that keeps how many error lines were written.
type errorsLogged struct {
	mu sync.Mutex
	n  int
}

func (c *errorsLogged) Enabled(context.Context, slog.Level) bool { return true }
func (c *errorsLogged) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		c.mu.Lock()
		c.n++
		c.mu.Unlock()
	}
	return nil
}
func (c *errorsLogged) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *errorsLogged) WithGroup(string) slog.Handler      { return c }

func (c *errorsLogged) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// failsAfterHolding makes the first read of a person after a report changes
// hands fail: the reads that authorize the request and resolve its recipient
// succeed, and the read deciding whether the recipient is told does not.
type failsAfterHolding struct{ fault *dbtest.Fault }

func (h failsAfterHolding) BeforeQuery(ctx context.Context, e *bun.QueryEvent) context.Context {
	return h.fault.BeforeQuery(ctx, e)
}

func (h failsAfterHolding) AfterQuery(_ context.Context, e *bun.QueryEvent) {
	if strings.HasPrefix(strings.TrimSpace(e.Query), "UPDATE") && strings.Contains(e.Query, "flaw_report") {
		h.fault.Arm("SELECT", "person")
	}
}

// A report given to somebody whose record could not then be read is given, the
// notice is dropped, and the dropped notice is logged, as every notification
// that could not be sent is.
func TestAReportsNoticeDroppedOnAFailedReadIsLogged(t *testing.T) {
	logged := &errorsLogged{}
	fault := &dbtest.Fault{}
	httpapitest.ReachAdjusted(t, httpapitest.CastSeed.Two, func(deps *core.Deps) {
		deps.DB = dbtest.Hooked(deps.DB, failsAfterHolding{fault})
		deps.Logger = slog.New(logged)
	}, func(t *testing.T, r *httpapitest.Reach) {
		at := recordReport(t, r)
		before := logged.count()
		if got := httpapitest.AsPerson(t, r, "private-dispatcher", http.MethodPut, at+"/assignment",
			`{"person":"private"}`); got.Code != http.StatusNoContent {
			t.Fatalf("giving a report answered %d: %s", got.Code, got.Body)
		}
		if !fault.Disarm() {
			t.Fatal("no read of the recipient followed the report changing hands, so this tested nothing")
		}
		if n := told(t, r, "private", notify.Assigned); n != 0 {
			t.Errorf("somebody whose record could not be read was told %d times", n)
		}
		if logged.count() == before {
			t.Error("the notice was dropped and nothing said so")
		}
	})
}
