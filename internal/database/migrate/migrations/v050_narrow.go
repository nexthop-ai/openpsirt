// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import "github.com/nexthop-ai/openpsirt/internal/database"

// narrowRequiring gives a table back as narrow does, and makes the columns
// named refuse a null again, spelling each from the release's declaration of
// the table.
//
// narrow's own requirement reads v0.2.0's declarations, which hold none of the
// tables v0.5.0 relaxes. SQLite rebuilds the table from the statement it holds,
// which narrow already reads; PostgreSQL needs no spelling; MySQL and MariaDB
// restate the column as the declaration spells it.
func (u *upgrader) narrowRequiring(n narrowing, declaration []string, require ...string) error {
	if u.engine == database.SQLite {
		n.require = require
		return u.narrow(n)
	}
	if err := u.narrow(n); err != nil {
		return err
	}
	var stmts []string
	if u.engine == database.Postgres {
		for _, column := range require {
			stmts = append(stmts, `ALTER TABLE "`+n.table+`" ALTER COLUMN "`+column+`" SET NOT NULL`)
		}
		return u.run(stmts)
	}
	made, _, err := pick(declaration, n.table)
	if err != nil {
		return err
	}
	items, err := declared(made)
	if err != nil {
		return err
	}
	for _, column := range require {
		def, err := items.column(column)
		if err != nil {
			return err
		}
		stmts = append(stmts, `ALTER TABLE "`+n.table+`" MODIFY COLUMN `+refusingNull(def))
	}
	return u.run(stmts)
}
