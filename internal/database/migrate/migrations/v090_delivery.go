// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// outboundDeliveryV090 is v0.9.0's declaration of the table recording what has
// gone where.
//
// A delivery records when its latest attempt began, so a sweep can tell an
// attempt still in flight from one that failed or whose sender stopped.
func outboundDeliveryV090(t *columnTypes) []string {
	statements := outboundDeliveryBaseline(t)
	statements[0] = withColumn(statements[0], `"attempts"    `+t.ref+` NOT NULL,`,
		`-- When the latest attempt began. An attempt that began a moment
			-- ago and has neither gone nor failed is in flight, and is not
			-- taken again beside it.
			"attempted_at" `+t.timestamp+` NULL,`)
	return statements
}

// attemptDeliveriesV090 adds when each delivery's latest attempt began. A
// delivery v0.8.0 recorded holds none, which reads as no attempt in flight.
//
// Asked first whether the column is there, so a run stopped part way on MySQL
// or MariaDB, where adding a column commits as it runs, steps over it on the
// next start.
func attemptDeliveriesV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	if has, err := u.hasColumn("outbound_delivery", "attempted_at"); err != nil || has {
		return err
	}
	return u.change(outboundDeliveryV090(t), change{table: "outbound_delivery",
		add: []added{{column: "attempted_at"}}})
}
