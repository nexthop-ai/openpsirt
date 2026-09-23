// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package v010

import (
	"context"
	"database/sql"
)

func init() {
	register(upScanRecency, downScanRecency)
}

// When a build was last scanned, answerable without reading its whole history.
//
// "Has anything arrived for this lately" is asked for every declared build at
// once — by the front page, by the scans screen, by the pass that decides
// whether to say a build has gone quiet, and by the product list, which reads
// it for the whole estate. The answer is one row per build: the newest arrival.
//
// The only index on a scan led with the target and its status and then the
// build time, so the newest *arrival* was not reachable through it: every scan
// ever filed against a build had to be fetched to find the latest. A year of
// nightly scans is 365 of those per build per request, and that measurement is
// not hypothetical — it is in `DESIGN-findings.md`.
//
// Leading with the target and ordering by arrival makes it one seek to the end
// of the range.
func upScanRecency(ctx context.Context, tx *sql.Tx) error {
	return apply(ctx, tx, []string{
		`CREATE INDEX "scan_recency_idx" ON "scan" ("target_id", "received_at")`,
	})
}

func downScanRecency(ctx context.Context, tx *sql.Tx) error {
	return dropIndex(ctx, tx, "scan", "scan_recency_idx")
}
