// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// namesBatchV0140 is how many components one read of the names step takes.
const namesBatchV0140 = 5_000

// componentV0140 is v0.14.0's declaration of the component table.
//
// v0.13.0's, with what the inventory says the component is.
func componentV0140(t *columnTypes) []string {
	statements := append([]string(nil), componentV0130(t)...)
	statements[0] = withColumn(statements[0], `"license"            `+t.free+` NULL,`,
		`-- What the inventory says the component is, as one line cut to
			-- the width of an index's summary. Shown where no index gave a
			-- summary. Absent where no inventory said.
			"description"        `+t.free+` NULL,`)
	return statements
}

// componentNameV0140 is v0.14.0's declaration of the component name table:
// every name a component goes by, folded. Its own name, and the name its
// package identifier gives where that differs. A component keeps the name its
// first inventory gave it, and a statement is stored under the name its
// identifier gives, so a statement reaches a component through this table by
// one indexed equality whichever name it used.
func componentNameV0140(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "component_name" (
			"id"           ` + t.id + `,
			"component_id" ` + t.ref + ` NOT NULL,
			"name_folded"  ` + t.name + ` NOT NULL,
			CONSTRAINT "component_name_unique" UNIQUE ("name_folded", "component_id"),
			CONSTRAINT "component_name_component_fk" FOREIGN KEY ("component_id") REFERENCES "component"("id")
		)` + t.suffix,
		`CREATE INDEX "component_name_component_idx" ON "component_name" ("component_id")`,
	}
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

// componentNameRowV0140 is one row of the component name table as the names
// step writes it.
type componentNameRowV0140 struct {
	bun.BaseModel `bun:"table:component_name"`
	ID            int64  `bun:"id,pk,autoincrement"`
	ComponentID   int64  `bun:"component_id"`
	NameFolded    string `bun:"name_folded"`
}

// componentNamesV0140 makes the component name table and fills it: each
// component's folded name, and the folded name its package identifier gives
// where that differs, the second by a copy of the application's rule.
//
// A name already held is kept, so a start after one that stopped fills what
// it left.
func componentNamesV0140(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	present, err := u.hasTable("component_name")
	if err != nil {
		return err
	}
	if !present {
		if err := u.create(componentNameV0140(u.t), "component_name"); err != nil {
			return err
		}
	} else if held, err := u.hasIndex("component_name", "component_name_component_idx"); err != nil {
		return err
	} else if !held {
		if err := u.index(componentNameV0140(u.t), "component_name", "component_name_component_idx"); err != nil {
			return err
		}
	}
	for after := int64(0); ; {
		var rows []struct {
			ID     int64  `bun:"id"`
			Purl   string `bun:"purl"`
			Folded string `bun:"name_folded"`
		}
		if err := tx.NewSelect().TableExpr(`"component"`).
			ColumnExpr(`"id", COALESCE("purl", '') AS "purl", COALESCE("name_folded", '') AS "name_folded"`).
			Where(`"id" > ?`, after).OrderExpr(`"id"`).Limit(namesBatchV0140).
			Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read the components whose names are kept: %w", err)
		}
		named := make([]componentNameRowV0140, 0, len(rows))
		for _, row := range rows {
			after = row.ID
			if row.Folded != "" {
				named = append(named, componentNameRowV0140{ComponentID: row.ID, NameFolded: row.Folded})
			}
			if apart := foldedV0130(packageNameV0140(row.Purl)); apart != "" && apart != row.Folded {
				named = append(named, componentNameRowV0140{ComponentID: row.ID, NameFolded: apart})
			}
		}
		if err := database.InBatchesKeeping(ctx, tx, named); err != nil {
			return fmt.Errorf("keep the names components go by: %w", err)
		}
		if len(rows) < namesBatchV0140 {
			return nil
		}
	}
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
		return printableV0130(decoded)
	}
	return name
}
