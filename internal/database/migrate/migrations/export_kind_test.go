// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"errors"
	"log/slog"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// errKindStopped is what the v0.11.0 upgrade stopped after adding the issue
// kind returns.
var errKindStopped = errors.New("the v0.11.0 upgrade was stopped after adding the issue kind")

// StopV0110AfterAddingIssueKind runs the v0.11.0 upgrade's renames and stored
// words, adds the issue kind with the default that fills it, and stops before
// the default is dropped: a start that stopped there. MySQL and MariaDB commit
// each statement as it runs, so there the stop keeps all of it; PostgreSQL and
// SQLite keep none.
func StopV0110AfterAddingIssueKind(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	err := inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
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
		made, _, err := pick(vulnerabilityV0110(u.t), "vulnerability")
		if err != nil {
			return err
		}
		items, err := declared(made)
		if err != nil {
			return err
		}
		def, err := items.column("kind")
		if err != nil {
			return err
		}
		if err := u.run([]string{`ALTER TABLE "vulnerability" ADD COLUMN ` + def +
			` DEFAULT 'vulnerability'`}); err != nil {
			return err
		}
		return errKindStopped
	})
	if errors.Is(err, errKindStopped) {
		return nil
	}
	return err
}
