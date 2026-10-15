// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// runRecords keeps the CVE record snapshot by hand.
//
// What an air-gapped deployment uses instead of the fetcher: `fetch` on a
// machine that reaches the CVE List writes the snapshot, which is carried
// across and placed in the deployment's directory; `import` builds it from an
// archive of the List somebody downloaded; `status` says what is held. None of
// them needs a database.
func runRecords(ctx context.Context, cfg config.Config, logger *slog.Logger, stdout *os.File,
	action, archive string) error {

	switch action {
	case "fetch":
		if _, err := cverecord.NewFetcher(cfg.RecordsDir, logger).Once(ctx); err != nil {
			return err
		}
	case "import":
		if archive == "" {
			return errors.New("openpsirt records import: name the CVE List archive to read")
		}
		skipped, err := cverecord.Build(archive, cfg.RecordsDir, "")
		if err != nil {
			return err
		}
		cverecord.Report(logger, skipped)
	case "status", "":
	default:
		return fmt.Errorf("openpsirt records: unknown action %q: the actions are \"fetch\", \"import\" and \"status\"", action)
	}
	held, err := cverecord.NewHeld(cfg.RecordsDir).Current()
	if err != nil {
		return err
	}
	if held == nil {
		_, err = fmt.Fprintf(stdout, "No CVE record snapshot in %s\n", cfg.RecordsDir)
		return err
	}
	_, err = fmt.Fprintf(stdout, "CVE record snapshot taken %s, %d records, in %s\n",
		held.Version(), held.Len(), cfg.RecordsDir)
	return err
}

// runMigrate applies schema changes on their own, so an operator can run them
// under different credentials and at a time they choose. There is no way back
// down: a database is only ever upgraded.
func runMigrate(ctx context.Context, cfg config.Config, logger *slog.Logger, stdout *os.File, action string) error {
	if action == "" {
		action = "up"
	}
	// Refused before anything is contacted, so a typo is named as one rather
	// than as whatever the connection said.
	if action != "up" && action != "status" {
		return fmt.Errorf("unknown migrate action %q: want up or status", action)
	}

	// Connecting is bounded the way a server's start is, and migrating is
	// not: a schema change on a large table legitimately takes longer than a
	// start, and an endpoint that accepts the connection and never answers
	// does not.
	logger.Info("connecting to the database", "timeout", cfg.StartupTimeout)
	connecting, connected := context.WithTimeout(ctx, cfg.StartupTimeout)
	db, err := openDatabase(connecting, cfg, logger)
	connected()
	if err != nil {
		return startupFailed(err, "connecting to the database", cfg)
	}
	defer closeQuietly(db, logger)

	switch action {
	case "up":
		return schema.Up(ctx, db, logger)
	default:
		applied, err := schema.Version(ctx, db)
		if err != nil {
			return err
		}
		// Both numbers, because one of them answers nothing. "Schema version
		// 34" is only useful beside what this build was written against.
		wanted, err := schema.Expected()
		if err != nil {
			return err
		}
		state := "the version this build expects"
		switch {
		case schema.BeforeTheBaseline(applied):
			state = "before the baseline: upgrade it with v0.6.0 first"
		case applied < wanted:
			state = fmt.Sprintf("behind by %d", wanted-applied)
		case applied > wanted:
			state = "ahead of this build"
		}
		_, err = fmt.Fprintf(stdout, "%s %s, schema version %d of %d (%s)\n",
			db.Server.Engine, db.Server.Version, applied, wanted, state)
		return err
	}
}
