// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"

	"github.com/pressly/goose/v3"
	"github.com/uptrace/bun"
)

func init() {
	goose.AddMigrationNoTxContext(upV0110, nil)
}

// The v0.10.0 release's schema changed into v0.11.0's.
//
// Run in one transaction of its own, the way migration 42 is.
func upV0110(ctx context.Context, sqldb *sql.DB) error {
	return inV020(ctx, sqldb, upgradeV0110)
}

// upgradeV0110 changes the schema v0.10.0 built into v0.11.0's.
//
// The v0110 files beside this one hold v0.11.0's declaration of every table
// this changes.
//
//   - The triage records take the names the interface gives them: a claim is
//     a decision, a decision's row at one place is a decision occurrence, and
//     a place is an occurrence. Renamed first, so everything after is
//     written against the new names.
//   - The stored words those renames reach follow them, in a step of their
//     own after the renames: a bulk decision's kind, the kinds of
//     notification a decision waiting or lapsed raises, the address a kept
//     filter opens, and the bulk action limit's setting name.
//   - An issue records what sort of issue it is: a published vulnerability, a
//     flaw minted here, or an analyzer's rule.
//   - The finding indexes a read answers from without the table carry the
//     finding's kind.
//   - Results a producer sends per series arrive as runs of a series against
//     a build, and a finding they report records the runs that saw it.
//   - An analyzer's result records where it is and what it said.
//   - A product records the repository hosts its links may point at, and
//     what it says about the code under a path prefix.
//   - A build's node records the repository the build stated a component is
//     built from.
//   - A product records the standing rules that dismiss leads.
//   - An analyzer's rule records the tool's own rating of its results and
//     the weakness families it finds, and a result the last place it names.
//   - A notification records whether what it withholds is internal work.
//   - A decision has a stamp, in a table of its own, that a hand-off resting
//     on it and the writes that could take that support away change.
//   - A product records each VEX document and supplier advisory that arrived
//     for it: who sent it or which feed fetched it, when, and what became of
//     it.
//   - A vulnerability report is a case: it has a title, a holder, revisions,
//     notes, a log of correspondence with its reporter and a record of who
//     held it, and the acknowledgement is the first message sent. A routing
//     rule may place reports. The report beside a flaw recorded by hand
//     carries the flaw's summary as its reported problem.
func upgradeV0110(ctx context.Context, tx bun.Tx) error {
	if err := renameV0110(ctx, tx); err != nil {
		return err
	}
	if err := valuesV0110(ctx, tx); err != nil {
		return err
	}
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if err := u.index(findingV0110(u.t), "finding",
		"finding_group_idx", "finding_opened_run_idx", "finding_closed_run_idx"); err != nil {
		return err
	}
	for _, step := range []func(context.Context, bun.Tx) error{
		issueKindV0110, createSeriesV0110, createRepositoryV0110, graphNodeRepositoryV0110, createLeadV0110,
		notificationInternalV0110, createDecisionStampV0110, createDocumentUploadV0110,
		reportCaseV0110, claimFromFlawV0110,
	} {
		if err := step(ctx, tx); err != nil {
			return err
		}
	}
	return nil
}
