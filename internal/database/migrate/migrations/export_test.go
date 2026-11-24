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

// RunV0140Unrecorded runs the v0.14.0 upgrade and leaves its version
// unrecorded: a process killed after the upgrade committed and before the
// migration library recorded the version.
func RunV0140Unrecorded(ctx context.Context, db *database.DB) error {
	return upV0140(migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler)), db.DB.DB)
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

// StatementsV0150 is v0.15.0's declaration of each table it changes.
func StatementsV0150(engine database.Engine) map[string][]string {
	return map[string][]string{"scan_run": scanRunV0150(typesFor(engine))}
}

// ShortLockWaits is ctx with a migration's attempts at a lock one second
// long, and the pauses between them a tenth of a second, doubling to a fifth.
func ShortLockWaits(ctx context.Context) context.Context {
	return context.WithValue(ctx, waitsKey{}, lockWaits{attemptSeconds: 1,
		pause: 100 * time.Millisecond, most: 200 * time.Millisecond})
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
