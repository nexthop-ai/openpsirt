// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
)

// What a register was measured with, when it could not be read, fails the
// register. An absent block says nothing has been uploaded to the build, and a
// fault is not that.
func TestARegisterWhoseProvenanceCouldNotBeReadIsAFault(t *testing.T) {
	gone := dbtest.Closed(t)
	logged := &tally{}
	in := core.Deps{DB: gone, Logger: slog.New(logged)}
	measured, err := measuredWith(t.Context(), in, access.Everything("a test"), 1,
		"mine", "master", "broadcom")
	if err == nil {
		t.Fatalf("a database nobody can reach answered the register's provenance as %+v", measured)
	}
	if core.Answered(err) != http.StatusInternalServerError {
		t.Errorf("a provenance read that failed answered %d", core.Answered(err))
	}
	if logged.n == 0 {
		t.Error("a provenance read that failed was not logged")
	}
}

// tally is a log handler that keeps how many lines were written.
type tally struct{ n int }

func (c *tally) Enabled(context.Context, slog.Level) bool { return true }
func (c *tally) Handle(context.Context, slog.Record) error {
	c.n++
	return nil
}
func (c *tally) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *tally) WithGroup(string) slog.Handler      { return c }
