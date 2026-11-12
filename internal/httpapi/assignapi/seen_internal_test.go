// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"context"
	"log/slog"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
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
	if seenBy(t.Context(), in, "triager", 1, nil) {
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
	if seenBy(t.Context(), in, "nobody-here", 1, nil) {
		t.Fatal("somebody nobody knows was told")
	}
	if logged.errors != 0 {
		t.Errorf("a notice for nobody logged %d errors", logged.errors)
	}
}

// Whether a receiver is told goes through the one logged drop, a report's
// included: a receiver whose record cannot be read is not told, and the
// failed read is logged.
func TestAReceiverWhoseRecordCouldNotBeReadIsNotToldAndItIsLogged(t *testing.T) {
	logged := &counted{}
	in := core.Deps{DB: dbtest.Without(t, "person"), Logger: slog.New(logged)}
	caller := access.NewPerson(1, "assigner", false, nil, 10)
	party := int64(20)
	to := receiver{to: &party, tell: 2, identity: "triager"}
	if to.told(t.Context(), in, caller, 1, []access.Visibility{access.Private}) {
		t.Fatal("somebody whose record could not be read was told")
	}
	if logged.errors == 0 {
		t.Error("the notice was dropped and nothing said so")
	}
}

// Nobody is told of work handed back, of work put in a team's queue, or of
// work they took themselves, and none of those asks the database anything.
func TestNobodyIsToldOfHandingBackATeamQueueOrTheirOwnTaking(t *testing.T) {
	logged := &counted{}
	in := core.Deps{DB: dbtest.Without(t, "person"), Logger: slog.New(logged)}
	caller := access.NewPerson(1, "assigner", false, nil, 10)
	own, team := int64(10), int64(30)
	for what, to := range map[string]receiver{
		"handing back":         {},
		"a team's queue":       {to: &team},
		"taking it themselves": {to: &own, tell: 1, identity: "assigner"},
	} {
		if to.told(t.Context(), in, caller, 1, nil) {
			t.Errorf("%s told somebody", what)
		}
	}
	if logged.errors != 0 {
		t.Errorf("deciding to tell nobody read the database and logged %d errors", logged.errors)
	}
}
