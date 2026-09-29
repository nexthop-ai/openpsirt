// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// A component lookup that could not be made is a fault. Only the lookup's own
// "no component by that name" is an absence, and a name matching several is
// the caller's to narrow.
func TestAComponentLookupThatFailedIsAFaultAndNotAnAbsence(t *testing.T) {
	logged := &tally{}
	logger := slog.New(logged)
	for _, c := range []struct {
		what string
		err  error
		want int
	}{
		{"a name the build does not hold",
			fmt.Errorf("%w: %q", graph.ErrNoComponent, "libfoo"), http.StatusNotFound},
		{"a name the build holds twice",
			&graph.Ambiguous{Name: "libfoo", Choices: []graph.Choice{{Version: "1"}, {Version: "2"}}},
			http.StatusConflict},
		{"a read that could not be made",
			errors.New("look up component: the database is closed"),
			http.StatusInternalServerError},
	} {
		before := logged.n
		if got := Answered(AmbiguousOrMissing(logger, c.err)); got != c.want {
			t.Errorf("%s answered %d, want %d", c.what, got, c.want)
		}
		if c.want == http.StatusInternalServerError && logged.n == before {
			t.Errorf("%s was not logged", c.what)
		}
	}
}

// Writing the policy refused is answered with a detail per fault, whichever
// helper the route answers a store's refusal through.
func TestRefusedWritingIsAnsweredFaultByFault(t *testing.T) {
	refused := fmt.Errorf("record the assessment: %w", markdown.Faults{
		{Line: 2, Offending: "<b>", Reason: "raw markup is not stored"},
		{Line: 5, Offending: "javascript:x", Reason: "that link scheme is not allowed"},
	})
	got := Asked(nil, refused)
	var model *huma.ErrorModel
	if !errors.As(got, &model) {
		t.Fatalf("refused writing answered %v", got)
	}
	if model.Status != http.StatusUnprocessableEntity {
		t.Errorf("refused writing answered %d", model.Status)
	}
	if len(model.Errors) != 2 {
		t.Fatalf("two faults came back as %d details: %+v", len(model.Errors), model.Errors)
	}
	if model.Errors[0].Location != "line 2" || model.Errors[1].Location != "line 5" {
		t.Errorf("the details do not name their lines: %+v", model.Errors)
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
