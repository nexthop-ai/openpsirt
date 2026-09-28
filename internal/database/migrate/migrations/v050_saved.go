// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/uptrace/bun"
)

// savedFiltersRespelled rewrites each kept findings-list query into the words
// v0.5.0's list reads.
//
// The list reads "exploited" and "fixable" as flags of their own and takes a
// hidden component as one repeated parameter. A query kept by an earlier
// release can carry the single word "only" for either flag, or several hidden
// components joined by commas in one value, and v0.5.0 reads neither.
//
// A query is text the list reads rather than a column per filter, so it is
// rewritten one parameter at a time and every parameter this does not name is
// kept exactly as it was written.
func savedFiltersRespelled(ctx context.Context, tx bun.Tx) error {
	var kept []struct {
		ID    int64  `bun:"id"`
		Query string `bun:"query"`
	}
	if err := tx.NewSelect().TableExpr(`"saved_filter"`).
		ColumnExpr(`"id", "query"`).
		Scan(ctx, &kept); err != nil {
		return fmt.Errorf("read the kept filters: %w", err)
	}
	for _, each := range kept {
		now := respelled(each.Query)
		if now == each.Query {
			continue
		}
		if _, err := tx.NewRaw(`UPDATE "saved_filter" SET "query" = ? WHERE "id" = ?`,
			now, each.ID).Exec(ctx); err != nil {
			return fmt.Errorf("rewrite kept filter %d: %w", each.ID, err)
		}
	}
	return nil
}

// respelled is one kept query in v0.5.0's words.
//
//   - "only=exploited" is "exploited=1", and "only=hasFix" is "fixable=1".
//     Any other value of "only" narrowed nothing and is dropped.
//   - A "hide" value holding commas is one "hide" per name, each trimmed, with
//     empty names dropped.
//   - A parameter the rewrite produces that the query already carries is not
//     written twice. A parameter the query carried is kept as written.
func respelled(query string) string {
	if query == "" {
		return query
	}
	pairs := strings.Split(query, "&")
	seen := make(map[string]bool, len(pairs))
	for _, pair := range pairs {
		seen[pair] = true
	}
	var out []string
	keep := func(pair string) { out = append(out, pair) }
	add := func(pair string) {
		if seen[pair] {
			return
		}
		seen[pair] = true
		out = append(out, pair)
	}
	for _, pair := range pairs {
		rawKey, rawValue, _ := strings.Cut(pair, "=")
		key, errKey := url.QueryUnescape(rawKey)
		value, errValue := url.QueryUnescape(rawValue)
		switch {
		case errKey != nil || errValue != nil:
			keep(pair)
		case key == "only":
			switch value {
			case "exploited":
				add("exploited=1")
			case "hasFix":
				add("fixable=1")
			}
		case key == "hide" && strings.Contains(value, ","):
			for _, name := range strings.Split(value, ",") {
				if name = strings.TrimSpace(name); name != "" {
					add("hide=" + url.QueryEscape(name))
				}
			}
		default:
			keep(pair)
		}
	}
	return strings.Join(out, "&")
}
