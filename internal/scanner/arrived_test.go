// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"strconv"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

func TestAScanOpeningWorkUnderARuleQueuesItsSweep(t *testing.T) {
	// The runner hands the scan's writer its queue. A writer handed none
	// queues nothing, so this is the one place a scan's arrivals are placed.
	eachRun(t, func(t *testing.T, f *runFixture) {
		ctx := t.Context()
		product, err := catalog.NewStore(f.db.DB).ProductByName(ctx, "sonic")
		if err != nil {
			t.Fatal(err)
		}
		rights := access.NewStore(f.db.DB)
		team, err := rights.DeclareTeam(ctx, "platform", "platform")
		if err != nil {
			t.Fatal(err)
		}
		person, err := rights.Ensure(ctx, "planner@example.com", "Planner", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		who := access.NewPerson(person.ID, "planner@example.com", false,
			map[int64][]access.Role{product.ID: {access.PublicTriage, access.Assigner}}, 0)
		if _, err := finding.NewStore(f.db.DB).AddRule(ctx, who, product.ID, team.ID,
			"libnl to platform", "", "libnl-3-*"); err != nil {
			t.Fatal(err)
		}

		f.reporting(t, finding.Reported{
			Issue:     finding.Named{Identifier: "CVE-2026-1", Severity: "high"},
			Component: libnl, FixState: finding.NoFix,
		})

		n, err := f.db.DB.NewSelect().Model((*queue.Job)(nil)).
			Where(`"kind" = ?`, queue.AssignmentSweep).
			Where(`"reference" = ?`, strconv.FormatInt(product.ID, 10)).
			Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("a scan opening work beneath a rule queued %d sweeps, want one", n)
		}
	})
}
