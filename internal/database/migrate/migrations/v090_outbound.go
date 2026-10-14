// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// outboundV090 is v0.9.0's declaration of the destination table.
//
// A destination's name is typed by an administrator, so it is matched without
// regard to capitals: the name column holds the folded key the uniqueness rule
// and every match read, and the display name holds the spelling typed.
func outboundV090(t *columnTypes) []string {
	statements := outboundBaseline(t)
	statements[0] = withColumn(statements[0], `"name"       `+t.name+` NOT NULL,`,
		`-- The name as it was typed, for a screen and a log line. The
			-- name above is it folded to lower case, which is what is unique
			-- and what a retirement matches.
			"display_name" `+t.name+` NOT NULL,`)
	return statements
}

// foldDestinationsV090 adds the display name and folds each destination's name
// into the key the release matches on.
//
// Asked first whether the column is there, so a run stopped part way on MySQL
// or MariaDB, where adding a column commits as it runs, folds on the next
// start rather than failing on the column. The fold itself changes nothing it
// has already changed.
func foldDestinationsV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	has, err := u.hasColumn("outbound", "display_name")
	if err != nil {
		return err
	}
	fold := func() error { return foldOutboundV090(ctx, tx) }
	if has {
		return fold()
	}
	return u.change(outboundV090(t), change{table: "outbound",
		add:  []added{{column: "display_name", fill: `"name"`, serverFill: "''"}},
		then: fold})
}

// outboundRowV090 is one destination as the fold reads it.
type outboundRowV090 struct {
	ID          int64  `bun:"id"`
	Name        string `bun:"name"`
	Kind        string `bun:"kind"`
	DisplayName string `bun:"display_name"`
	Live        bool   `bun:"live"`
}

// foldOutboundV090 writes each destination's name as its folded key, and its
// display name as typed where none is held yet.
//
// Two names one kind holds that fold to one key keep one destination each. The
// key goes to a destination still in use before a retired one, then to the one
// already spelled as the key, then to the earliest; every other takes the key
// and its own number. Both stay configured. A destination given a numbered key
// is listed under that key, because what the listing shows is what retiring
// matches.
//
// The fold is copied rather than called, so a later change to the
// application's rule does not change what this upgrade wrote.
func foldOutboundV090(ctx context.Context, tx bun.Tx) error {
	var rows []outboundRowV090
	if err := tx.NewSelect().TableExpr(`"outbound"`).
		ColumnExpr(`"id", "name", "kind", "display_name"`).
		ColumnExpr(`CASE WHEN "retired_at" IS NULL THEN 1 ELSE 0 END AS "live"`).
		OrderExpr(`"id"`).Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read the destinations: %w", err)
	}
	taken := map[string]bool{}
	byKey := map[string][]int{}
	for i, row := range rows {
		key := strings.ToLower(strings.TrimSpace(row.Name))
		byKey[key+"\x00"+row.Kind] = append(byKey[key+"\x00"+row.Kind], i)
		taken[row.Name+"\x00"+row.Kind] = true
		taken[key+"\x00"+row.Kind] = true
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	named := make([]string, len(rows))
	var keepers []int
	for _, group := range keys {
		members := byKey[group]
		key, _, _ := strings.Cut(group, "\x00")
		keeper := members[0]
		rank := func(i int) int {
			r := 0
			if rows[i].Live {
				r += 2
			}
			if rows[i].Name == key {
				r++
			}
			return r
		}
		for _, i := range members {
			if rank(i) > rank(keeper) {
				keeper = i
			}
		}
		named[keeper] = key
		keepers = append(keepers, keeper)
		for _, i := range members {
			if i == keeper {
				continue
			}
			named[i] = numberedKeyV090(key, rows[i].ID, rows[i].Kind, taken)
			taken[named[i]+"\x00"+rows[i].Kind] = true
		}
	}

	// The numbered ones first, so a keeper's key is free when it is written.
	write := func(i int) error {
		row := rows[i]
		display := strings.TrimSpace(row.DisplayName)
		if display == "" {
			display = strings.TrimSpace(row.Name)
		}
		if named[i] != strings.ToLower(strings.TrimSpace(row.Name)) {
			display = named[i]
		}
		if named[i] == row.Name && display == row.DisplayName {
			return nil
		}
		if _, err := tx.NewUpdate().TableExpr(`"outbound"`).
			Set(`"name" = ?`, named[i]).
			Set(`"display_name" = ?`, display).
			Where(`"id" = ?`, row.ID).Exec(ctx); err != nil {
			return fmt.Errorf("fold the name of destination %d: %w", row.ID, err)
		}
		return nil
	}
	isKeeper := map[int]bool{}
	for _, i := range keepers {
		isKeeper[i] = true
	}
	for i := range rows {
		if !isKeeper[i] {
			if err := write(i); err != nil {
				return err
			}
		}
	}
	for _, i := range keepers {
		if err := write(i); err != nil {
			return err
		}
	}
	return nil
}

// numberedKeyV090 is a folded key with a destination's number after it, cut to
// the column's width, and numbered again while another row of the kind holds
// it.
func numberedKeyV090(key string, id int64, kind string, taken map[string]bool) string {
	for n := 0; ; n++ {
		suffix := "-" + strconv.FormatInt(id, 10)
		if n > 0 {
			suffix += "-" + strconv.Itoa(n)
		}
		head := key
		for len(head)+len(suffix) > database.NameWidth {
			_, size := utf8.DecodeLastRuneInString(head)
			head = head[:len(head)-size]
		}
		if candidate := head + suffix; !taken[candidate+"\x00"+kind] {
			return candidate
		}
	}
}

// hasColumn reports whether a table already holds a column of this name.
func (u *upgrader) hasColumn(table, column string) (bool, error) {
	if u.engine == database.SQLite {
		columns, err := u.sqliteColumns(table)
		return columns[column], err
	}
	query := `SELECT 1 FROM "information_schema"."columns"
		WHERE "table_schema" = CURRENT_SCHEMA() AND "table_name" = ? AND "column_name" = ?`
	if u.engine != database.Postgres {
		query = `SELECT 1 FROM "information_schema"."COLUMNS"
			WHERE "TABLE_SCHEMA" = DATABASE() AND "TABLE_NAME" = ? AND "COLUMN_NAME" = ? LIMIT 1`
	}
	var probe int
	err := u.tx.QueryRowContext(u.ctx, query, table, column).Scan(&probe)
	if database.IsNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("ask whether %s has column %s: %w", table, column, err)
	}
	return true, nil
}
