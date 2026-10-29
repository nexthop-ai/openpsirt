// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"

	"github.com/uptrace/bun"
)

// notificationV0110 is v0.11.0's declaration of the notification table.
//
// v0.8.0's, with whether a withheld notification is about security testing
// work.
// Derived from v0.8.0's declaration; no release between changed it.
func notificationV0110(t *columnTypes) []string {
	statements := notificationV080(t)
	statements[0] = withColumn(statements[0], `"private"   `+t.boolean+` NOT NULL,`,
		`-- Whether a withheld notification is about security testing work,
			-- an analyzer's code findings, which a reader of security testing
			-- findings reads and a reader of undisclosed work does not.
			"security_testing" `+t.boolean+` DEFAULT FALSE NOT NULL,`)
	return statements
}

// notificationSecurityTestingV0110 adds whether each notification is about
// security testing work. v0.10.0 told nobody about any, so every row is not.
func notificationSecurityTestingV0110(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("notification", "security_testing")
	if err != nil || present {
		return err
	}
	return u.change(notificationV0110(u.t), change{table: "notification",
		add: []added{{column: "security_testing"}}})
}
