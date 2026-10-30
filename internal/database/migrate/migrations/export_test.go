// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// StatementsV0100 is v0.10.0's declaration of each table it changes.
func StatementsV0100(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	return map[string][]string{
		"finding":            findingV0100(t),
		"product":            productV0100(t),
		"claim":              claimV0100(t),
		"published_document": publishedDocumentV0100(t),
		"upstream":           upstreamV0100(t),
		"upstream_document":  upstreamDocumentV0100(t),
		"vex_statement":      vexStatementV0100(t),
	}
}

// StatementsV0110 is v0.11.0's declaration of each table it changes.
func StatementsV0110(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	out := map[string][]string{}
	for table := range keptV0110 {
		out[table] = declaredV0110(t, table)
	}
	for _, r := range tablesRenamedV0110 {
		out[r.to] = declaredV0110(t, r.to)
	}
	// The tables v0.11.0 changes after renaming them are declared as the
	// change leaves them.
	for table, declared := range map[string][]string{
		"vulnerability":  vulnerabilityV0110(t),
		"finding":        findingV0110(t),
		"graph_node":     graphNodeV0110(t),
		"notification":   notificationV0110(t),
		"decision_stamp": decisionStampV0110(t),
	} {
		out[table] = declared
	}
	for table, declared := range map[string][]string{
		"series": seriesV0110(t), "series_run": seriesV0110(t), "series_document": seriesV0110(t),
		"series_document_chunk": seriesV0110(t), "series_module": seriesV0110(t),
		"sighting": seriesV0110(t), "series_refusal": seriesV0110(t), "analysis_result": analysisV0110(t),
		"analysis_location": analysisV0110(t),
		"suppression_rule":  codeFindingV0110(t), "rule_rating": codeFindingV0110(t), "rule_family": codeFindingV0110(t),
		"code_finding_flaw": codeFindingV0110(t), "flaw_code_finding": codeFindingV0110(t),
		"flaw_code_finding_build": codeFindingV0110(t), "code_finding_component": codeFindingV0110(t),
		"code_finding_collaborator": codeFindingV0110(t),
		"document_upload":           documentUploadV0110(t),
		"flaw_report":               flawReportV0110(t), "flaw_report_revision": flawReportV0110(t),
		"report_note": flawReportV0110(t), "report_note_revision": flawReportV0110(t),
		"report_message": flawReportV0110(t), "report_assignment": flawReportV0110(t),
		"assignment_rule": assignmentRuleV0110(t),
		"role_grant":      roleV0110(t), "role_grant_all": roleV0110(t),
		"group_role": roleV0110(t), "group_role_all": roleV0110(t),
	} {
		made, indexes, err := pick(declared, table)
		if err != nil {
			panic(err)
		}
		out[table] = append([]string{made}, indexes...)
	}
	return out
}

// RunV0110ReportStep runs the v0.11.0 upgrade's report step alone, in a
// transaction of its own as on MySQL and MariaDB: a start that stopped after
// it, at a later step.
func RunV0110ReportStep(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		return renamedForV0110(ctx, tx, reportCaseV0110)
	})
}

// renamedForV0110 runs a step of the v0.11.0 upgrade against the names it is
// written for, as a start that stopped after that step left them. MySQL and
// MariaDB commit each rename as it runs, so such a start had made every one.
// PostgreSQL and SQLite keep nothing a stopped start did, so the tables the
// step names are given their new names for it and their former ones after,
// and a later start makes every rename.
func renamedForV0110(ctx context.Context, tx bun.Tx, step func(context.Context, bun.Tx) error) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	if u.engine == database.MySQL || u.engine == database.MariaDB {
		if err := renameV0110(ctx, tx); err != nil {
			return err
		}
		return step(ctx, tx)
	}
	named := []tableRename{{"routing_rule", "assignment_rule"}}
	for _, r := range named {
		if err := u.run([]string{`ALTER TABLE "` + r.from + `" RENAME TO "` + r.to + `"`}); err != nil {
			return err
		}
	}
	if err := step(ctx, tx); err != nil {
		return err
	}
	for _, r := range named {
		if err := u.run([]string{`ALTER TABLE "` + r.to + `" RENAME TO "` + r.from + `"`}); err != nil {
			return err
		}
	}
	return nil
}

// StopV0110AfterAcknowledgements makes the report step's tables and writes
// each acknowledgement as the first message sent, in a transaction of its
// own, and stops before the acknowledged stamp is dropped: a start that
// stopped there, as one on MySQL and MariaDB can.
func StopV0110AfterAcknowledgements(ctx context.Context, db *database.DB) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	return inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		u, err := upgraderIn(ctx, tx)
		if err != nil {
			return err
		}
		return renamedForV0110(ctx, tx, func(ctx context.Context, tx bun.Tx) error {
			declared := flawReportV0110(u.t)
			for _, table := range []string{"report_message", "flaw_report_revision", "report_note",
				"report_note_revision", "report_assignment"} {
				if err := u.create(declared, table); err != nil {
					return err
				}
			}
			return acknowledgedAsSentV0110(ctx, tx)
		})
	})
}

// StopV0110RenamingAfter runs the v0.11.0 upgrade and stops it once the first
// statement renaming the named table, column, index or constraint has run: a
// start that stopped there. It reports whether it stopped, which it does not
// on an engine where nothing renames that name.
func StopV0110RenamingAfter(ctx context.Context, db *database.DB, name string) (bool, error) {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	err := inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		return renameV0110Stopping(ctx, tx, name)
	})
	if errors.Is(err, errRenameStopped) {
		return true, nil
	}
	return false, err
}

// RenameOrderV0110 is the position, in the order the v0.11.0 upgrade runs its
// renames, of the first statement renaming the named table, column, index or
// constraint, and -1 where nothing renames that name.
func RenameOrderV0110(name string) int {
	var froms []string
	for _, t := range tablesRenamedV0110 {
		froms = append(froms, t.from)
	}
	for _, c := range columnsRenamedV0110 {
		froms = append(froms, c.from)
	}
	for _, n := range namesRenamedV0110 {
		froms = append(froms, n.from)
	}
	return slices.Index(froms, name)
}

// StopV0110RewritingAfter runs the v0.11.0 renames and the stored words after
// them, and stops once the named step of the words has run: a start that
// stopped there. It reports whether it stopped.
func StopV0110RewritingAfter(ctx context.Context, db *database.DB, step string) (bool, error) {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	err := inV020(ctx, db.DB.DB, func(ctx context.Context, tx bun.Tx) error {
		if err := renameV0110(ctx, tx); err != nil {
			return err
		}
		return valuesV0110Stopping(ctx, tx, step)
	})
	if errors.Is(err, errValuesStopped) {
		return true, nil
	}
	return false, err
}

// SavedQueryV0110 is a kept filter's query string in v0.11.0's words.
func SavedQueryV0110(query string) string { return savedQueryV0110(query) }
