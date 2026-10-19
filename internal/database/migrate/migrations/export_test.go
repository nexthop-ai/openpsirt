// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
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
