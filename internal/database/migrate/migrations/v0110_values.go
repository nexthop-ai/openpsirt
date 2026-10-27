// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/uptrace/bun"
)

// valueRewrite is one stored word changed in place: every row of a table
// holding the word in a column is given its v0.11.0 spelling.
type valueRewrite struct{ table, column, from, to string }

// valuesRewrittenV0110 is every stored word v0.11.0 renames, by the tables as
// v0.11.0 names them. A notification destination names a kind as a
// notification does, so both are rewritten. The trail's kind of change is
// one of a fixed list the API filters on and returns, so it is rewritten
// too; what a change was about is kept as written.
var valuesRewrittenV0110 = []valueRewrite{
	{"decision", "kind", "together", "bulk"},
	{"notification", "kind", "claim-waiting", "decision-waiting"},
	{"notification", "kind", "claim-lapsed", "decision-lapsed"},
	{"outbound", "kind", "claim-waiting", "decision-waiting"},
	{"outbound", "kind", "claim-lapsed", "decision-lapsed"},
	{"notification", "kind", "obligation-open", "response-window-open"},
	{"notification", "kind", "obligation-near", "response-window-near"},
	{"notification", "kind", "obligation-passed", "response-window-passed"},
	{"outbound", "kind", "obligation-open", "response-window-open"},
	{"outbound", "kind", "obligation-near", "response-window-near"},
	{"outbound", "kind", "obligation-passed", "response-window-passed"},
	{"admin_change", "kind", "exploited-here", "incident"},
}

// settingRenamedV0110 is the setting v0.11.0 renames, from its v0.10.0 name.
var settingRenamedV0110 = struct{ from, to string }{"triage.together-cap", "triage.bulk-decision-cap"}

// savedWordsV0110 is each word of the findings list's address v0.11.0
// renames, and savedSortsV0110 each order it renames.
var (
	savedWordsV0110 = map[string]string{"claim": "decision", "claim_state": "decision_state"}
	savedSortsV0110 = map[string]string{"places": "occurrences"}
)

// errValuesStopped is what a rewrite stopped on purpose returns.
var errValuesStopped = errors.New("the stored words were stopped part way")

// valuesV0110 gives every stored word the renames reach its v0.11.0
// spelling: a decision's kind, the kinds of notification and destination,
// the link a notification holds to a decision's row, the address a kept
// filter opens and a setting's name. It runs after the
// renames, against the tables as v0.11.0 names them.
//
// Every step changes only rows still holding a v0.10.0 word, so a start that
// stopped part way changes on its second start what the first did not reach.
// That matters on MySQL and MariaDB, where the renames before this committed
// the upgrade's transaction and each statement here commits as it runs.
// PostgreSQL and SQLite run all of it in the upgrade's one transaction.
func valuesV0110(ctx context.Context, tx bun.Tx) error {
	return valuesV0110Stopping(ctx, tx, "")
}

// valuesV0110Stopping rewrites as valuesV0110 does, and stops once the step
// named stopAfter has run: an upgrade that stopped there. A step is named by
// the word it writes, by "notification.link", by "saved_filter" or by
// "application_setting".
func valuesV0110Stopping(ctx context.Context, tx bun.Tx, stopAfter string) error {
	for _, v := range valuesRewrittenV0110 {
		column := `"` + v.column + `"`
		if _, err := tx.ExecContext(ctx, `UPDATE "`+v.table+`" SET `+column+` = ? WHERE `+column+` = ?`,
			v.to, v.from); err != nil {
			return fmt.Errorf("rename %s %s %q: %w", v.table, v.column, v.from, err)
		}
		if stopAfter == v.table+"."+v.to {
			return errValuesStopped
		}
	}
	if err := notificationLinksV0110(ctx, tx); err != nil {
		return err
	}
	if stopAfter == "notification.link" {
		return errValuesStopped
	}
	if err := savedFiltersV0110(ctx, tx); err != nil {
		return err
	}
	if stopAfter == "saved_filter" {
		return errValuesStopped
	}
	if err := settingV0110(ctx, tx); err != nil {
		return err
	}
	if stopAfter == "application_setting" {
		return errValuesStopped
	}
	return nil
}

// notificationLinksV0110 points each notification linking a decision's row at
// one occurrence at that row's v0.11.0 address. v0.10.0 linked the row at
// /decisions/{id}, which v0.11.0 gives the decision, so the link would open a
// different record. A link to /claims/{id} is left to the interface, which
// forwards it. Only the v0.10.0 address is matched, so a start after one that
// stopped part way rewrites no link twice.
func notificationLinksV0110(ctx context.Context, tx bun.Tx) error {
	var rows []struct {
		ID   int64  `bun:"id"`
		Link string `bun:"link"`
	}
	if err := tx.NewRaw(`SELECT "id", "link" FROM "notification" WHERE "link" LIKE '/decisions/%' ORDER BY "id"`).
		Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read the notifications linking a decision's row: %w", err)
	}
	for _, row := range rows {
		link := "/decision-occurrences/" + strings.TrimPrefix(row.Link, "/decisions/")
		if _, err := tx.ExecContext(ctx, `UPDATE "notification" SET "link" = ? WHERE "id" = ?`,
			link, row.ID); err != nil {
			return fmt.Errorf("rewrite notification %d's link: %w", row.ID, err)
		}
	}
	return nil
}

// savedFiltersV0110 rewrites each kept filter whose address names a renamed
// word. Read and written in Go, because a word is one part of a query string,
// and matching one portably in SQL would also match it inside a value.
func savedFiltersV0110(ctx context.Context, tx bun.Tx) error {
	var rows []struct {
		ID    int64  `bun:"id"`
		Query string `bun:"query"`
	}
	if err := tx.NewRaw(`SELECT "id", "query" FROM "saved_filter"
		WHERE "query" LIKE '%claim%' OR "query" LIKE '%places%' ORDER BY "id"`).Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read the kept filters: %w", err)
	}
	for _, row := range rows {
		rewritten := savedQueryV0110(row.Query)
		if rewritten == row.Query {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE "saved_filter" SET "query" = ? WHERE "id" = ?`,
			rewritten, row.ID); err != nil {
			return fmt.Errorf("rewrite kept filter %d: %w", row.ID, err)
		}
	}
	return nil
}

// savedQueryV0110 is a kept filter's query string in v0.11.0's words. Every
// other part is kept byte for byte, because the list recognizes a kept filter
// as open by comparing its query with the address.
func savedQueryV0110(query string) string {
	if query == "" {
		return query
	}
	pairs := strings.Split(query, "&")
	for i, pair := range pairs {
		key, value, valued := strings.Cut(pair, "=")
		if to, ok := savedWordsV0110[key]; ok {
			key = to
		}
		if to, ok := savedSortsV0110[value]; ok && key == "sort" {
			value = to
		}
		if valued {
			pairs[i] = key + "=" + value
		} else {
			pairs[i] = key
		}
	}
	return strings.Join(pairs, "&")
}

// settingV0110 moves the renamed setting's row to its new name. A row already
// under the new name is left beside the old one, which the new one outranks.
func settingV0110(ctx context.Context, tx bun.Tx) error {
	var held int
	if err := tx.NewRaw(`SELECT COUNT(*) FROM "application_setting" WHERE "name" = ?`,
		settingRenamedV0110.to).Scan(ctx, &held); err != nil {
		return fmt.Errorf("read the %q setting: %w", settingRenamedV0110.to, err)
	}
	if held > 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE "application_setting" SET "name" = ? WHERE "name" = ?`,
		settingRenamedV0110.to, settingRenamedV0110.from); err != nil {
		return fmt.Errorf("rename the %q setting: %w", settingRenamedV0110.from, err)
	}
	return nil
}
