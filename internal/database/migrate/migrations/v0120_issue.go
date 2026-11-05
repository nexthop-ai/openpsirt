// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"strings"

	"github.com/uptrace/bun"
)

// vulnerabilityV0120 is v0.12.0's declaration of the vulnerability table.
//
// v0.11.0's, with the dates a public vulnerability database states for the
// issue and when it was last asked.
func vulnerabilityV0120(t *columnTypes) []string {
	statements := vulnerabilityV0110(t)
	statements[0] = withColumn(statements[0], `"first_seen_at" `+t.timestamp+` NOT NULL,`,
		`-- When the issue was published and last modified, as a public
			-- vulnerability database states. Null where it was never asked or
			-- does not know the issue; the moment of asking tells the two
			-- apart.
			"published_at"   `+t.timestamp+` NULL,
			"modified_at"    `+t.timestamp+` NULL,
			"dates_asked_at" `+t.timestamp+` NULL,`)
	return statements
}

// scanRunV0120 is v0.12.0's declaration of the scan run table.
//
// v0.11.0's, with the replaced inventory a run checked. Null on every run
// over what a build holds now.
func scanRunV0120(t *columnTypes) []string {
	statements := declaredV0110(t, "scan_run")
	statements[0] = withColumn(statements[0], `"records_version"  `+t.free+` NULL,`,
		`-- The replaced inventory this run checked against issues published
			-- while it was current. Null on a run over what the build holds.
			"checked_scan_id"  `+t.refNull+` NULL,`)
	statements[0] = strings.Replace(statements[0], `REFERENCES "build"("id")`,
		`REFERENCES "build"("id"),
			CONSTRAINT "scan_run_checked_scan_fk" FOREIGN KEY ("checked_scan_id") REFERENCES "scan"("id")`, 1)
	return append(statements,
		// Whether an inventory's check is done, asked of every replaced
		// inventory by the pass that queues them.
		`CREATE INDEX "scan_run_checked_idx" ON "scan_run" ("checked_scan_id")`)
}

// issueDatesV0120 adds an issue's published and modified dates. v0.11.0 held
// none, so every issue starts unasked.
func issueDatesV0120(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("vulnerability", "dates_asked_at")
	if err != nil || present {
		return err
	}
	return u.change(vulnerabilityV0120(u.t), change{table: "vulnerability",
		add: []added{{column: "published_at"}, {column: "modified_at"}, {column: "dates_asked_at"}}})
}

// checkedScanV0120 adds the replaced inventory a run checked, and its index.
// Every run v0.11.0 recorded was over what its build held.
func checkedScanV0120(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("scan_run", "checked_scan_id")
	if err != nil {
		return err
	}
	if !present {
		if err := u.change(scanRunV0120(u.t), change{table: "scan_run",
			add:         []added{{column: "checked_scan_id"}},
			constraints: []string{"scan_run_checked_scan_fk"}}); err != nil {
			return err
		}
	}
	return u.index(scanRunV0120(u.t), "scan_run", "scan_run_checked_idx")
}

// scanV0120 is v0.12.0's declaration of the scan table.
//
// v0.11.0's, with whether a branch inventory was replaced before replaced
// inventories were checked, which owes no check.
func scanV0120(t *columnTypes) []string {
	statements := declaredV0110(t, "scan")
	statements[0] = withColumn(statements[0], `"placed"         INTEGER NULL,`,
		`-- True on an inventory already replaced when this deployment began
			-- checking replaced inventories: it owes no check, since its
			-- history would be checked only against today's data.
			"replaced_unchecked" `+t.boolean+` DEFAULT FALSE NOT NULL,`)
	return statements
}

// uncheckedV0120 marks every branch inventory v0.11.0 left replaced as owing
// no check. An inventory replaced after the upgrade owes one, and a fresh
// install holds none to mark.
func uncheckedV0120(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("scan", "replaced_unchecked")
	if err != nil || present {
		return err
	}
	if err := u.change(scanV0120(u.t), change{table: "scan",
		add: []added{{column: "replaced_unchecked"}}}); err != nil {
		return err
	}
	// Every applied scan with a later applied scan of its build: what was
	// replaced by the moment of the upgrade. A tag is marked too, and is
	// never checked either way. Read first and written by identifier, since
	// MySQL refuses an update naming its own table in a subquery.
	var replaced []int64
	if err := tx.NewSelect().TableExpr(`"scan" AS "sc"`).ColumnExpr(`"sc"."id"`).
		Where(`"sc"."status" = ? AND "sc"."components" IS NOT NULL`, "accepted").
		Where(`EXISTS (SELECT 1 FROM "scan" AS "nx" WHERE "nx"."build_id" = "sc"."build_id"
			AND "nx"."id" > "sc"."id" AND "nx"."status" = ? AND "nx"."components" IS NOT NULL)`, "accepted").
		Scan(ctx, &replaced); err != nil {
		return err
	}
	const batch = 500
	for from := 0; from < len(replaced); from += batch {
		if _, err := tx.NewUpdate().Table("scan").
			Set(`"replaced_unchecked" = ?`, true).
			Where(`"id" IN (?)`, bun.List(replaced[from:min(from+batch, len(replaced))])).
			Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}
