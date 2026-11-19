// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// RunV0130Unrecorded runs the v0.13.0 upgrade and leaves its version
// unrecorded: a process killed after the upgrade committed and before the
// migration library recorded the version.
func RunV0130Unrecorded(ctx context.Context, db *database.DB) error {
	return upV0130(migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler)), db.DB.DB)
}

// StatementsV0130 is v0.13.0's declaration of each table it changes.
func StatementsV0130(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	return map[string][]string{
		"advisory_issue":         advisoryIssueV0130(t),
		"advisory_override":      advisoryOverrideV0130(t),
		"component":              componentV0130(t),
		"decision_occurrence":    decisionOccurrenceV0130(t),
		"graph_node":             graphNodeV0130(t),
		"person":                 personV0130(t),
		"received_vex_statement": receivedStatementV0130(t),
		"schema_change":          schemaChangeV0130(t),
	}
}

// StatementsV0140 is v0.14.0's declaration of each table it changes.
func StatementsV0140(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	return map[string][]string{
		"component":              componentV0140(t),
		"component_name":         componentNameV0140(t),
		"finding":                findingV0140(t),
		"received_vex_statement": receivedStatementV0140(t),
		"source_answer":          sourceAnswerV0140(t),
		"source_correction":      sourceCorrectionV0140(t),
		"suppression":            suppressionV0140(t),
		"vulnerability":          vulnerabilityV0140(t),
	}
}

// StopV0130AfterLiveColumn adds the column marking an issue on an advisory
// and nothing else: a start of the v0.13.0 upgrade on MySQL or MariaDB that
// stopped after the column committed.
func StopV0130AfterLiveColumn(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return u.change(advisoryIssueV0130(u.t), change{table: "advisory_issue",
			add: []added{{column: "live"}}})
	})
}

// StopV0130AfterLiveRule runs the v0.13.0 upgrade up to the uniqueness rule
// holding the mark, and stops before the rule it replaces is dropped.
func StopV0130AfterLiveRule(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return u.change(advisoryIssueV0130(u.t), change{table: "advisory_issue",
			add: []added{{column: "live"}}, constraints: []string{"advisory_issue_live_once"}})
	})
}

// StopV0130AfterOverrideLiveColumn adds the column marking a release an
// advisory marks affected and nothing else: a start of the v0.13.0 upgrade on
// MySQL or MariaDB that stopped after the column committed.
func StopV0130AfterOverrideLiveColumn(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return u.change(advisoryOverrideV0130(u.t), change{table: "advisory_override",
			add: []added{{column: "live"}}})
	})
}

// StopV0130AfterOverrideLiveRule runs the v0.13.0 upgrade of the release
// marks up to the uniqueness rule holding the mark, and stops before the rule
// it replaces is dropped.
func StopV0130AfterOverrideLiveRule(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		mark := func() error {
			_, err := tx.NewUpdate().TableExpr(`"advisory_override"`).Set(`"live" = ?`, true).
				Where(`"removed_at" IS NULL`).Where(`"live" IS NULL`).Exec(ctx)
			return err
		}
		return u.change(advisoryOverrideV0130(u.t), change{table: "advisory_override",
			add: []added{{column: "live"}}, then: mark, constraints: []string{"advisory_override_live_once"}})
	})
}

// StopV0130AfterNodeName adds the name a build stated to each graph node and
// nothing else: a start of the v0.13.0 upgrade on MySQL or MariaDB that
// stopped after the first column committed.
func StopV0130AfterNodeName(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return u.change(graphNodeV0130(u.t), change{table: "graph_node",
			add: []added{{column: "name"}}})
	})
}

// StopV0130BeforeNodeIndex adds every v0.13.0 node column and not the index of
// the folded name: a start on MySQL or MariaDB that stopped after the last
// column committed.
func StopV0130BeforeNodeIndex(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return graphNodeColumnsV0130(u)
	})
}

// StopV0130AfterStatementTime adds when each received statement was made and
// nothing else: a start of the v0.13.0 upgrade on MySQL or MariaDB that
// stopped after that column committed.
func StopV0130AfterStatementTime(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return u.change(receivedStatementV0130(u.t), change{table: "received_vex_statement",
			add: []added{{column: "said_at"}}})
	})
}

// StopV0130AfterEndedByColumn adds the column naming who withdrew a decision
// occurrence and nothing else: a start of the v0.13.0 upgrade on MySQL or
// MariaDB that stopped after the column committed.
func StopV0130AfterEndedByColumn(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return u.change(decisionOccurrenceV0130(u.t), change{table: "decision_occurrence",
			add: []added{{column: "ended_by"}}})
	})
}

// PurlPhasesV0130 is how many phases the v0.13.0 credential step runs in.
var PurlPhasesV0130 = len(purlPhasesV0130)

// StopV0130AfterPurlPhase runs the first phases of the v0.13.0 credential
// step and nothing else, committed: a start that stopped there on MySQL or
// MariaDB, where each of the step's writes lands on its own.
func StopV0130AfterPurlPhase(ctx context.Context, db *database.DB, phases int) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		var pass purlPassV0130
		for _, phase := range purlPhasesV0130[:phases] {
			if err := phase(ctx, tx, &pass); err != nil {
				return err
			}
		}
		return nil
	})
}

// PublishedBatchV0130 is how many published documents one read of the
// v0.13.0 upgrade takes.
const PublishedBatchV0130 = publishedBatchV0130

// ShortLockWaits is ctx with a migration's attempts at a lock one second
// long, and the pauses between them a tenth of a second, doubling to a fifth.
func ShortLockWaits(ctx context.Context) context.Context {
	return context.WithValue(ctx, waitsKey{}, lockWaits{attemptSeconds: 1,
		pause: 100 * time.Millisecond, most: 200 * time.Millisecond})
}

// IdentifyingNameV0130 is the name v0.13.0's upgrade identifies a component
// by, for a test holding it to the name the application reads.
func IdentifyingNameV0130(name, version, purl string) string {
	return identifyingNameV0130(name, version, purl)
}

// SettledDigestV0130 is the settled digest v0.13.0's upgrade stores for an
// advisory it rewrites, for a test holding it to the application's.
func SettledDigestV0130(body []byte) (string, error) {
	return settledDigestV0130(body)
}

// StopV0140AfterClaimNotes adds the status notes column to a build's own claims
// and nothing else: a start of the v0.14.0 upgrade on MySQL or MariaDB that
// stopped after that column committed.
func StopV0140AfterClaimNotes(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return u.change(suppressionV0140(u.t), change{table: "suppression",
			add: []added{{column: "notes_id"}}})
	})
}

// PackageFoldedV0140 is the name v0.14.0's upgrade stores for a component's
// package identifier.
func PackageFoldedV0140(purl string) string { return foldedV0130(packageNameV0140(purl)) }
