// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

// Settings an administrator can change at runtime — thresholds, precedence
// orders, modes. Configuration files hold what an operator sets at deploy time;
// this holds what an administrator sets from inside the application.
//
// The value is TEXT on every engine, the smaller type on MySQL and MariaDB,
// because every setting is a short value the application writes.
func settingsBaseline(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "application_setting" (
			"name"       ` + t.name + ` NOT NULL PRIMARY KEY,
			"value"      TEXT NOT NULL,
			"updated_at" ` + t.timestamp + ` NOT NULL
		)` + t.suffix,
	}
}
