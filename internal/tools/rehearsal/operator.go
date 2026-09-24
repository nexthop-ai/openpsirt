// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Implied is the disclosed role an undisclosed role reached as well in a
// release before v0.2.0. The upgrade note in docs/configuration.md asks an
// operator to grant it beside the undisclosed one; nothing grants it on
// upgrade.
var Implied = map[string]string{
	"private-read":   "public-read",
	"private-triage": "public-triage",
}

// grantImplied does what the upgrade note asks of an operator coming from a
// release whose undisclosed roles reached disclosed work: every grant of an
// undisclosed role, per product, across the estate, in a group binding and in
// a personal token's holds, gains the disclosed role beside it where it is not
// already held. It returns how many rows it wrote.
func (r *run) grantImplied(ctx context.Context) (int, error) {
	target, err := database.ParseURL(r.hostURL)
	if err != nil {
		return 0, err
	}
	db, err := database.Open(ctx, target)
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()
	now := time.Now().UTC().Truncate(time.Second)

	written := 0
	for _, table := range []struct {
		name, key string
		carried   []string
	}{
		{"role_grant", `"person_id", "product_id", "source"`, []string{"active"}},
		{"role_grant_all", `"person_id", "source"`, []string{"active"}},
		{"group_role", `"group_name", "product_id"`, nil},
	} {
		n, err := implyIn(ctx, db, table.name, table.key, table.carried, now)
		if err != nil {
			return written, fmt.Errorf("%s: %w", table.name, err)
		}
		written += n
	}
	n, err := implyInTokens(ctx, db)
	if err != nil {
		return written, fmt.Errorf("personal_token: %w", err)
	}
	return written + n, nil
}

// impliedHolds is a token's holds with the disclosed role added beside every
// undisclosed one, in the order a token writes its roles. A token that names
// no undisclosed role comes back as it was.
func impliedHolds(holds string) string {
	named := map[string]bool{}
	for _, word := range strings.Split(holds, ",") {
		if word = strings.TrimSpace(word); word != "" {
			named[word] = true
		}
	}
	for held, implied := range Implied {
		if named[held] {
			named[implied] = true
		}
	}
	var kept []string
	for _, role := range access.Roles() {
		if named[string(role)] {
			kept = append(kept, string(role))
		}
	}
	return strings.Join(kept, ",")
}

// implyInTokens rewrites the holds of every personal token narrowed to an
// undisclosed role. A token that names no role reaches what its owner holds,
// so the owner's grants above already carry it.
func implyInTokens(ctx context.Context, db *database.DB) (int, error) {
	var tokens []struct {
		ID    int64  `bun:"id"`
		Holds string `bun:"holds"`
	}
	if err := db.NewSelect().TableExpr(`"personal_token"`).Column("id", "holds").
		Where(`"holds" IS NOT NULL`).Scan(ctx, &tokens); err != nil {
		return 0, err
	}
	written := 0
	for _, token := range tokens {
		after := impliedHolds(token.Holds)
		if after == token.Holds {
			continue
		}
		if _, err := db.ExecContext(ctx, `UPDATE "personal_token" SET "holds" = ? WHERE "id" = ?`,
			after, token.ID); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// implyIn adds the implied role beside every undisclosed role in one grant
// table. Read first and written one row at a time, because two undisclosed
// roles can imply rows that collide, and each engine answers a duplicate in an
// INSERT ... SELECT differently.
func implyIn(ctx context.Context, db *database.DB, table, key string, carried []string,
	now time.Time) (int, error) {

	columns := key
	for _, c := range carried {
		columns += `, "` + c + `"`
	}
	rows, err := db.QueryContext(ctx, `SELECT `+columns+`, "role" FROM "`+table+`"`)
	if err != nil {
		return 0, err
	}
	type grant struct {
		values []any
		role   string
	}
	var held []grant
	has := map[string]bool{}
	width := len(splitColumns(columns))
	for rows.Next() {
		values := make([]any, width)
		ptrs := make([]any, width+1)
		for i := range values {
			ptrs[i] = &values[i]
		}
		var role string
		ptrs[width] = &role
		if err := rows.Scan(ptrs...); err != nil {
			_ = rows.Close()
			return 0, err
		}
		// A driver hands text back as bytes, which the query formatter would
		// write as a binary literal rather than text.
		for i, v := range values {
			if b, ok := v.([]byte); ok {
				values[i] = string(b)
			}
		}
		held = append(held, grant{values: values, role: role})
		has[fmt.Sprint(values[:len(splitColumns(key))], role)] = true
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}

	written := 0
	for _, g := range held {
		implied, ok := Implied[g.role]
		if !ok {
			continue
		}
		id := fmt.Sprint(g.values[:len(splitColumns(key))], implied)
		if has[id] {
			continue
		}
		args := append(append([]any{}, g.values...), implied, now)
		marks := ""
		for range args {
			if marks != "" {
				marks += ", "
			}
			marks += "?"
		}
		query := `INSERT INTO "` + table + `" (` + columns + `, "role", "created_at") VALUES (` + marks + `)`
		if _, err := db.ExecContext(ctx, query, args...); err != nil {
			return written, err
		}
		has[id] = true
		written++
	}
	return written, nil
}

// splitColumns counts the quoted names in a column list.
func splitColumns(list string) []string {
	var out []string
	start := -1
	for i, c := range list {
		if c == '"' {
			if start < 0 {
				start = i + 1
			} else {
				out = append(out, list[start:i])
				start = -1
			}
		}
	}
	return out
}
