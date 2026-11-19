// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
)

// sayingIt keeps only what a VEX publisher has a standing statement about,
// and only where that statement says what was asked.
//
// Apart from narrow, so that the rest of it reads as independent narrowings.
// The statements are resolved into the (component, issue) pairs they name,
// once, and the list is joined to that.
//
// A statement naming the product a component ships inside, where this product
// ships that product, is about the component where it sits inside it, which a
// pair cannot say. It reaches the list through the finding the run answered
// with it, and through nothing else (REQ-31). A product this product does not
// ship, such as the platform a distribution composes its packages into, places
// nothing, and its statement is matched by package. Asked once per statement
// rather than per finding.
//
// A component is matched by every name it goes by, which is what a statement
// may be stored under: its own, and the name its package identifier gives,
// each a row of its own so each match is one indexed equality. Matched by
// either of two columns of the component instead, the reads took twice as
// long and more (design-docs/findings-measurements.md § Statements matched by
// name).
func (f Filter) sayingIt(q *bun.SelectQuery) *bun.SelectQuery {
	publishers, saidIt := trimmed(f.Publishers), trimmed(f.VexStatus)
	if len(publishers) > 0 || len(saidIt) > 0 {
		// The statements being asked about, written once and used for
		// both arms of the union below.
		asked := []string{`"ss"."superseded_at" IS NULL`}
		var about []any
		if len(publishers) > 0 {
			lowered := make([]string, 0, len(publishers))
			for _, name := range publishers {
				lowered = append(lowered, typedname.Matching(name))
			}
			asked = append(asked, `"ss"."publisher" IN (?)`)
			about = append(about, bun.List(lowered))
		}
		if len(saidIt) > 0 {
			asked = append(asked, `"ss"."status" IN (?)`)
			about = append(about, bun.List(saidIt))
		}
		narrowing := strings.Join(asked, " AND ")
		alone := narrowing + ` AND ("ss"."within" IS NULL OR NOT EXISTS (SELECT 1
			FROM "component_name" AS "pc"
			JOIN "graph_node" AS "pn" ON "pn"."component_id" = "pc"."component_id"
			JOIN "build" AS "pt" ON "pt"."id" = "pn"."build_id"
			JOIN "branch_or_tag" AS "ps" ON "ps"."id" = "pt"."branch_or_tag_id"
			WHERE "ps"."product_id" = "ss"."product_id" AND "pn"."closed_scan_id" IS NULL
			  AND "pc"."name_folded" = "ss"."within"))`

		// The issue under its own name, and under every other name it
		// goes by: which identifier a publisher chose says nothing
		// about which issue they meant. Two arms rather than an OR
		// across two left joins, because one statement can match one
		// issue by name and another by alias, and folding those
		// together would drop one of them.
		//
		// Both sides of every comparison are folded on the way in, so
		// these are equalities the indexes can be used for rather than
		// functions of a column. That is not a tidiness point: with
		// LOWERon the issue's side the plan scanned the whole
		// vulnerability table, and the whole alias table, once per
		// statement.
		pairs := `(SELECT "ss"."product_id" AS "product_id", "vc"."component_id" AS "component_id",
			"vv"."issue_id" AS "vulnerability_id"
			FROM "received_vex_statement" AS "ss"
			JOIN "component_name" AS "vc" ON "vc"."name_folded" = "ss"."component"
			JOIN "vulnerability" AS "vv" ON "vv"."identifier_folded" = "ss"."vulnerability"
			WHERE ` + alone + `
			UNION
			SELECT "ss"."product_id", "vc"."component_id", "vl"."vulnerability_id"
			FROM "received_vex_statement" AS "ss"
			JOIN "component_name" AS "vc" ON "vc"."name_folded" = "ss"."component"
			JOIN "vulnerability_alias" AS "vl" ON "vl"."identifier_folded" = "ss"."vulnerability"
			WHERE ` + alone + `)`

		where, args := f.product()
		joined := make([]any, 0, 2*len(about)+len(args))
		joined = append(joined, about...)
		joined = append(joined, about...)
		joined = append(joined, args...)
		q = q.Join("LEFT JOIN "+pairs+` AS "vx" ON "vx"."component_id" = "f"."component_id"`+
			` AND "vx"."vulnerability_id" = "f"."vulnerability_id"`+
			// Correlated on the row's own product where the list spans them,
			// so a statement in one product cannot answer for a finding in
			// another.
			` AND "vx"."product_id" = `+where, joined...).
			// The union is distinct on the pair, so the join adds at most one
			// row to a finding. A statement the run answered a finding with
			// is in the finding's own product, because the run reads that
			// product's statements and no other's.
			Where(`("vx"."component_id" IS NOT NULL OR "f"."stated_by" IN
				(SELECT "ss"."id" FROM "received_vex_statement" AS "ss" WHERE `+narrowing+`))`, about...)
	}
	return q
}

// foldedNames is typed component names as the fold stored beside each name.
func foldedNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, graph.Folded(name))
	}
	return out
}

// containsTerm prepares a term to be searched for literally.
//
// A search box is not a pattern language. Typing `50%` means a component whose
// name contains "50%", not every component containing "50" — and `a_b` means
// what it says rather than "a, anything, b". So the wildcards are escaped and
// the escape character is stated: every engine here takes `ESCAPE`, and SQLite
// has no default escape character at all, so leaving it out makes a backslash
// mean one thing on three engines and another on the fourth.
//
// The escape character is `#`, and a backslash is what it must not be.
// MySQL and MariaDB treat a backslash as an escape inside a string literal, so
// `ESCAPE '\'` is an unterminated string: a syntax error there, and parsed
// happily by the other two, which only the four-engine run catches.
//
// Case is folded here and again by the engine, which is a compromise worth
// naming. Folding the term in Go is Unicode-aware; `LOWER()` on the column is
// ASCII-only on SQLite — so a name carrying a non-ASCII capital is found on
// three engines and missed on the fourth, wherever the comparison is against a
// column with no folded copy.
//
// The component half has one — `component.name_folded`, which the search
// clause above compares against — so this applies to the issue half, where
// `vulnerability.identifier_folded` exists and `LOWER(v.identifier)` is what
// is still asked. Issue identifiers are ASCII in every scheme anybody
// publishes, which is why this is written down rather than fixed.
func containsTerm(term string) string {
	return database.LikeEscaped(strings.ToLower(term))
}

// foldedLabels is a set of labels as they are stored, without the ones that fold
// to nothing. Folded rather than trimmed, because a label is matched on the
// folded form everywhere else and a filter that skipped the folding would
// answer nothing for a word somebody typed with a capital.
func foldedLabels(words []string) []string {
	kept := make([]string, 0, len(words))
	for _, word := range words {
		if label := LabelAs(word); label != "" {
			kept = append(kept, label)
		}
	}
	return kept
}
