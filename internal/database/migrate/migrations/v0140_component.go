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

// packageBatchV0140 is how many components one read of the package step
// takes.
const packageBatchV0140 = 5_000


// componentV0140 is v0.14.0's declaration of the component table.
//
// v0.13.0's, with what the inventory says the component is, and the name the
// component's package identifier gives, folded, with an index on it. A
// component keeps the name its first inventory gave it, and a statement is
// stored under the name its identifier gives, so a statement is matched to a
// component by either.
func componentV0140(t *columnTypes) []string {
	statements := append([]string(nil), componentV0130(t)...)
	statements[0] = withColumn(statements[0], `"license"            `+t.free+` NULL,`,
		`-- What the inventory says the component is, as one line cut to
			-- the width of an index's summary. Shown where no index gave a
			-- summary. Absent where no inventory said.
			"description"        `+t.free+` NULL,`)
	statements[0] = withColumn(statements[0], `"identifying_folded" `+t.name+` NULL,`,
		`-- The name the package identifier gives, folded: decoded, without
			-- namespace, version, qualifiers or subpath. Null where the
			-- component carries no package identifier.
			"package_folded" `+t.name+` NULL,`)
	return append(statements,
		`CREATE INDEX "component_package_folded_idx" ON "component" ("package_folded")`)
}

// componentDescriptionV0140 adds the column holding what the inventory says a
// component is. v0.13.0 kept none, so every component starts without one, and
// the next inventory stating one fills it.
func componentDescriptionV0140(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("component", "description")
	if err != nil || present {
		return err
	}
	return u.change(componentV0140(u.t), change{table: "component",
		add: []added{{column: "description"}}})
}

// componentPackageV0140 adds the column holding the name each component's
// package identifier gives, fills it, and indexes it.
//
// Filled only where empty, so a start after one that stopped fills what it
// left.
func componentPackageV0140(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasColumn("component", "package_folded")
	if err != nil {
		return err
	}
	if !present {
		if err := u.change(componentV0140(u.t), change{table: "component",
			add: []added{{column: "package_folded"}}}); err != nil {
			return err
		}
	}
	for after := int64(0); ; {
		var rows []struct {
			ID   int64  `bun:"id"`
			Purl string `bun:"purl"`
		}
		if err := tx.NewSelect().TableExpr(`"component"`).
			ColumnExpr(`"id", "purl"`).
			Where(`"id" > ?`, after).
			Where(`"purl" IS NOT NULL`).
			Where(`"package_folded" IS NULL`).
			OrderExpr(`"id"`).Limit(packageBatchV0140).
			Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read the components holding a package identifier: %w", err)
		}
		for _, row := range rows {
			after = row.ID
			name := packageNameV0140(row.Purl)
			if name == "" {
				continue
			}
			if _, err := tx.NewUpdate().TableExpr(`"component"`).
				Set(`"package_folded" = ?`, foldedV0130(name)).
				Where(`"id" = ?`, row.ID).Exec(ctx); err != nil {
				return fmt.Errorf("store the package name of component %d: %w", row.ID, err)
			}
		}
		if len(rows) < packageBatchV0140 {
			break
		}
	}
	return u.index(componentV0140(u.t), "component", "component_package_folded_idx")
}

// packageNameV0140 is the name a package identifier gives its package, as
// v0.14.0 reads it: the last path segment, decoded, without the version, the
// qualifiers or the subpath. Empty where the identifier is not a package
// identifier.
func packageNameV0140(purl string) string {
	purl = strings.TrimSpace(purl)
	purl, _, _ = strings.Cut(purl, "#")
	body, _, _ := strings.Cut(purl, "?")
	scheme, rest, found := strings.Cut(body, ":")
	if !found || !strings.EqualFold(scheme, "pkg") {
		return ""
	}
	path := rest
	if at := strings.LastIndex(rest, "@"); at > 0 && rest[at-1] != '/' {
		path = rest[:at]
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) < 2 {
		return ""
	}
	name := segments[len(segments)-1]
	if decoded, err := url.PathUnescape(name); err == nil {
		name = decoded
	}
	return printableV0130(name)
}
