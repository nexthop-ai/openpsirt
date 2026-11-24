// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// scanRunV0150 is v0.15.0's declaration of the scan run table.
//
// The baseline's, with whether the run recorded the source package each
// finding it applied was matched through.
func scanRunV0150(t *columnTypes) []string {
	made, indexes, err := pick(issueBaseline(t), "scan_run")
	if err != nil {
		panic(err)
	}
	made = withColumn(made, `"checked_scan_id"  `+t.refNull+` NULL,`,
		`-- Whether the run recorded the source package each finding it
			-- applied was matched through. False on a run stored before the
			-- column existed: a finding such a run last applied is not known
			-- to hold its source, so its match is unknown. A default rather
			-- than a fill: a run that does not say it recorded them did not.
			"sources_recorded" `+t.boolean+` DEFAULT FALSE NOT NULL,`)
	return append([]string{made}, indexes...)
}

// scanRunSourcesV0150 adds whether a run recorded match sources. No run
// before v0.15.0 is counted as having recorded them: v0.13.0's recorded none,
// and nothing held tells a v0.14.0 run from one of v0.13.0's. A build's next
// scheduled scan records them.
func scanRunSourcesV0150(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("scan_run", "sources_recorded")
	if err != nil || present {
		return err
	}
	return u.change(scanRunV0150(u.t), change{table: "scan_run", add: []added{{column: "sources_recorded"}}})
}
