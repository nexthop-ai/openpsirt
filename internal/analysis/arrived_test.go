// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"io"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

func TestARunOpeningCodeFindingsUnderARuleQueuesItsSweep(t *testing.T) {
	// A rule places code findings matched by component, as it places
	// vulnerability findings, so a run opening some beneath it asks for its
	// product's sweep in the run's own transaction.
	eachWorld(t, func(t *testing.T, w *world) {
		ctx := t.Context()
		w.inventory(t, w.Build.ID)
		rights := access.NewStore(w.DB.DB)
		team, err := rights.DeclareTeam(ctx, "routing", "routing")
		if err != nil {
			t.Fatal(err)
		}
		who := w.holding(t, "planner", access.Assigner)
		if err := rights.GrantRole(ctx, who.ID, w.Product.ID, access.PublicTriage); err != nil {
			t.Fatal(err)
		}
		who, err = rights.Resolve(ctx, "planner")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := finding.NewStore(w.DB.DB).AddRule(ctx, who, w.Product.ID, team.ID,
			"frr to routing", "", "frr"); err != nil {
			t.Fatal(err)
		}

		// Applied by the worker a deployment runs, which queues sweeps on the
		// queue its runs come from.
		work := queue.New(w.DB, queue.DefaultOptions())
		run := w.receive(t, w.Build.ID, time.Now().UTC().Add(-time.Hour), document([]sent{inFRR}, 10))
		if _, err := work.Add(ctx, queue.Analyze, strconv.FormatInt(run.ID, 10)); err != nil {
			t.Fatal(err)
		}
		applied, err := NewWorker(w.applier, work, slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if applied == nil || applied.Status != series.Applied {
			t.Fatalf("the worker applied %+v; want the run applied", applied)
		}

		n, err := w.DB.DB.NewSelect().Model((*queue.Job)(nil)).
			Where(`"kind" = ?`, queue.AssignmentSweep).
			Where(`"reference" = ?`, strconv.FormatInt(w.Product.ID, 10)).
			Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("a run opening a code finding beneath a rule queued %d sweeps, want one", n)
		}
	})
}
