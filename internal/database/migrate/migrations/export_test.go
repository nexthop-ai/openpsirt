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

// StatementsV080 is v0.8.0's declaration of each table it changes.
func StatementsV080(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	return map[string][]string{
		"finding":      findingV080(t),
		"decision":     decisionV080(t),
		"notification": notificationV080(t),
	}
}

// StatementsV090 is v0.9.0's declaration of each table it creates or changes.
func StatementsV090(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	return map[string][]string{
		"finding":           findingV090(t),
		"graph_node":        graphNodeV090(t),
		"image_version":     imageVersionV090(t),
		"outbound":          outboundV090(t),
		"outbound_delivery": outboundDeliveryV090(t),
		"statement_text":    statementTextV090(t),
		"suppression":       suppressionV090(t),
		"vex_statement":     vexStatementsV090(t),
	}
}

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

// StopV090AfterDropping runs the v0.9.0 upgrade's steps, each in a
// transaction of its own as on MySQL and MariaDB, and stops once the named
// claim tables have lost their copy of the reasoning: a start that died
// between the drops, or after them.
func StopV090AfterDropping(ctx context.Context, db *database.DB, tables ...string) error {
	ctx = migrate.WithEngine(ctx, db.Server.Engine, slog.New(slog.DiscardHandler))
	drop := func(ctx context.Context, tx bun.Tx) error {
		t, err := types(ctx)
		if err != nil {
			return err
		}
		u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
		declared := map[string][]string{"suppression": suppressionV090(t), "vex_statement": vexStatementsV090(t)}
		for _, table := range tables {
			if err := u.change(declared[table], change{table: table, drop: []string{"statement"}}); err != nil {
				return err
			}
		}
		return nil
	}
	for _, step := range []func(context.Context, bun.Tx) error{
		createImageVersionV090, foldDestinationsV090, attemptDeliveriesV090, mergeImagesV090,
		shapeWordsV090, moveWordsV090, drop,
	} {
		if err := inV020(ctx, db.DB.DB, step); err != nil {
			return err
		}
	}
	return nil
}

// StatementsV0110 is v0.11.0's declaration of each table it changes.
func StatementsV0110(engine database.Engine) map[string][]string {
	t := typesFor(engine)
	out := map[string][]string{
		"vulnerability":  vulnerabilityV0110(t),
		"finding":        findingV0110(t),
		"graph_node":     graphNodeV0110(t),
		"notification":   notificationV0110(t),
		"decision_stamp": decisionStampV0110(t),
	}
	for _, table := range []string{"upgrade"} {
		out[table] = declaredV0110(t, table)
	}
	for _, r := range tablesRenamedV0110 {
		out[r.to] = declaredV0110(t, r.to)
	}
	for table, declared := range map[string][]string{
		"series": seriesV0110(t), "series_run": seriesV0110(t), "series_document": seriesV0110(t),
		"series_document_chunk": seriesV0110(t), "series_module": seriesV0110(t),
		"sighting": seriesV0110(t), "series_refusal": seriesV0110(t), "analysis_result": analysisV0110(t),
		"analysis_location": analysisV0110(t),
		"lead_rule":         leadV0110(t), "rule_rating": leadV0110(t), "rule_family": leadV0110(t),
		"document_upload": documentUploadV0110(t),
		"flaw_report":     flawReportV0110(t), "flaw_report_revision": flawReportV0110(t),
		"report_note": flawReportV0110(t), "report_note_revision": flawReportV0110(t),
		"report_message": flawReportV0110(t), "report_assignment": flawReportV0110(t),
		"routing_rule": routingRuleV0110(t),
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
	return inV020(ctx, db.DB.DB, reportCaseV0110)
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
		declared := flawReportV0110(u.t)
		for _, table := range []string{"report_message", "flaw_report_revision", "report_note",
			"report_note_revision", "report_assignment"} {
			if err := u.create(declared, table); err != nil {
				return err
			}
		}
		return acknowledgedAsSentV0110(ctx, tx)
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
