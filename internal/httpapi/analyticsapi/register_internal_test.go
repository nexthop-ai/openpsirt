// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analyticsapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
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

// A release note whose builds could not be named fails, rather than heading a
// document going to a customer with the names this deployment files them by.
func TestAReleaseNoteWhoseBuildsCouldNotBeNamedIsAFault(t *testing.T) {
	gone := dbtest.Closed(t)
	logged := &tally{}
	in := core.Deps{DB: gone, Logger: slog.New(logged)}
	named, err := describing(t.Context(), in, 1, "master", "broadcom")
	if err == nil {
		t.Fatalf("a database nobody can reach named the build %q", named)
	}
	if core.Answered(err) != http.StatusInternalServerError {
		t.Errorf("a build lookup that failed answered %d", core.Answered(err))
	}
	if logged.n == 0 {
		t.Error("a build lookup that failed was not logged")
	}
}

// A closed row whose record lines cannot be read says so, in the row and in
// the file's cell, and the fault is logged; lines that read are carried as
// they were stated.
func TestARegisterRowWhoseRecordLinesCannotBeReadSaysSo(t *testing.T) {
	closed := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	stated, err := json.Marshal([]cverecord.Stated{{Entry: "libnl",
		Line: cverecord.Line{Version: "3.7.0", Status: "unaffected"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, lines string
		unreadable  bool
	}{
		{"unreadable", "[{not json", true},
		{"readable", string(stated), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			logged := &tally{}
			in := core.Deps{Logger: slog.New(logged)}
			body := disposedBody(t.Context(), in, finding.Disposed{
				Vulnerability: "CVE-2026-9999", Component: "libnl-3-200",
				ClosedAt: &closed, UnaffectedBy: c.lines,
			})
			if body.UnaffectedUnreadable != c.unreadable {
				t.Errorf("the row says its lines are unreadable: %v, want %v",
					body.UnaffectedUnreadable, c.unreadable)
			}
			if logged.n > 0 != c.unreadable {
				t.Errorf("%d lines were logged, want a line only where the record lines do not read", logged.n)
			}
			cell := saidLines(body)
			if c.unreadable && cell != core.UnreadableLines {
				t.Errorf("the file's cell says %q, want %q", cell, core.UnreadableLines)
			}
			if !c.unreadable && (len(body.Unaffected) != 1 || body.Unaffected[0].Version != "3.7.0" ||
				body.Unaffected[0].Status != "unaffected") {
				t.Errorf("the row carries %+v, want the one line stated", body.Unaffected)
			}
		})
	}
}
