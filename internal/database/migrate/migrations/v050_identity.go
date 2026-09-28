// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/uptrace/bun"
)

// statedFromComponents gives every open node the identifiers of the component
// it holds.
func statedFromComponents(ctx context.Context, tx bun.Tx) error {
	_, err := tx.ExecContext(ctx, `UPDATE "graph_node" SET
		"purl" = (SELECT "c"."purl" FROM "component" AS "c" WHERE "c"."id" = "graph_node"."component_id"),
		"cpe" = (SELECT "c"."cpe" FROM "component" AS "c" WHERE "c"."id" = "graph_node"."component_id")
		WHERE "closed_scan_id" IS NULL`)
	if err != nil {
		return fmt.Errorf("give each open node its component's identifiers: %w", err)
	}
	return nil
}

// reidentified works out every component's identity again by the rule given.
//
// Read in pages by identifier and written one row at a time. A row's new
// identity is never another row's old one, because the two rules hash into
// spaces that do not meet, so the unique index holds at every step.
//
// Two rows the rule identifies alike are refused, naming both. v0.5.0 holds
// apart a name shaped like a package identifier and that package, and a name
// and version that join to the same text, and v0.4.0 has one row for each
// pair. Nothing here can say which row's findings and decisions are the
// pair's, so the choice is left to whoever is rolling back.
func reidentified(ctx context.Context, tx bun.Tx, identity func(purl, name, version string) string) error {
	const page = 1000
	var after int64
	held := map[string]string{}
	for {
		var rows []struct {
			ID      int64          `bun:"id"`
			Purl    sql.NullString `bun:"purl"`
			Name    string         `bun:"name"`
			Version string         `bun:"version"`
		}
		if err := tx.NewSelect().TableExpr(`"component"`).
			Column("id", "purl", "name", "version").
			Where(`"id" > ?`, after).
			OrderExpr(`"id"`).Limit(page).
			Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read components to identify again: %w", err)
		}
		for _, row := range rows {
			becomes := identity(row.Purl.String, row.Name, row.Version)
			this := fmt.Sprintf("%d (%q at %q, package identifier %q)",
				row.ID, row.Name, row.Version, row.Purl.String)
			if other, taken := held[becomes]; taken {
				return fmt.Errorf("components %s and %s are one component to the release "+
					"being restored, which cannot hold both: remove one of them first", other, this)
			}
			held[becomes] = this
			if _, err := tx.NewRaw(`UPDATE "component" SET "identity" = ? WHERE "id" = ?`,
				becomes, row.ID).Exec(ctx); err != nil {
				return fmt.Errorf("identify component %d again: %w", row.ID, err)
			}
			after = row.ID
		}
		if len(rows) < page {
			return nil
		}
	}
}

// identityV050 is a component's identity as v0.5.0 works it out: the package
// identifier and the name with a version hashed apart, the name prefixed with
// its length.
//
// Copied rather than called, as every rule a migration applies is: the
// function the graph reads is free to change, and this migration is not.
func identityV050(purl, name, version string) string {
	basis := canonicalPurlV040(purl)
	if basis == "" {
		name = strings.TrimSpace(name)
		basis = "name\x00" + strconv.Itoa(len(name)) + "\x00" + name + strings.TrimSpace(version)
	} else {
		basis = "purl\x00" + basis
	}
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// identityV040 is a component's identity as v0.4.0 works it out.
func identityV040(purl, name, version string) string {
	basis := canonicalPurlV040(purl)
	if basis == "" {
		basis = strings.TrimSpace(name) + "@" + strings.TrimSpace(version)
	}
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// canonicalPurlV040 reduces a package identifier to what identifies the
// package, as both releases do: qualifiers and subpath dropped, escapes
// decoded, the scheme and the type lowercased.
func canonicalPurlV040(purl string) string {
	purl = strings.TrimSpace(purl)
	if purl == "" {
		return ""
	}
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	decode := func(s string) string {
		unescaped, err := url.PathUnescape(s)
		if err != nil {
			return s
		}
		return unescaped
	}
	scheme, rest, found := strings.Cut(purl, ":")
	if !found {
		return decode(purl)
	}
	kind, path, split := strings.Cut(rest, "/")
	if !split {
		return strings.ToLower(scheme) + ":" + decode(rest)
	}
	return strings.ToLower(scheme) + ":" + strings.ToLower(kind) + "/" + decode(path)
}

// senders is who can have sent a scan: every key and every person, by the
// name v0.4.0 recorded and the qualified sender v0.5.0 records.
func senders(ctx context.Context, tx bun.Tx) (map[string]string, error) {
	byName := map[string]string{}
	var people []struct {
		ID       int64  `bun:"id"`
		Identity string `bun:"identity"`
	}
	if err := tx.NewSelect().TableExpr(`"person"`).Column("id", "identity").
		Scan(ctx, &people); err != nil {
		return nil, fmt.Errorf("read who may have sent a scan: %w", err)
	}
	for _, p := range people {
		byName[p.Identity] = "person:" + strconv.FormatInt(p.ID, 10)
	}
	// Keys second, so a name a key and a person share is read as the key's:
	// v0.4.0 read it back to the key.
	var keys []struct {
		ID   int64  `bun:"id"`
		Name string `bun:"name"`
	}
	if err := tx.NewSelect().TableExpr(`"api_key"`).Column("id", "name").
		Scan(ctx, &keys); err != nil {
		return nil, fmt.Errorf("read which keys may have sent a scan: %w", err)
	}
	for _, k := range keys {
		byName[k.Name] = "key:" + strconv.FormatInt(k.ID, 10)
	}
	return byName, nil
}

// sendersQualified rewrites each recorded sender from a name to the key or
// person holding it.
func sendersQualified(ctx context.Context, tx bun.Tx) error {
	byName, err := senders(ctx, tx)
	if err != nil {
		return err
	}
	return rewriteSenders(ctx, tx, byName)
}

// sendersNamed rewrites each recorded sender back to the name v0.4.0 reads.
func sendersNamed(ctx context.Context, tx bun.Tx) error {
	byName, err := senders(ctx, tx)
	if err != nil {
		return err
	}
	back := make(map[string]string, len(byName))
	for name, sender := range byName {
		back[sender] = name
	}
	return rewriteSenders(ctx, tx, back)
}

// rewriteSenders replaces each recorded sender the mapping names, on scans and
// on refused uploads. One statement per distinct sender: a deployment holds a
// few keys and a few people, however many scans they sent.
func rewriteSenders(ctx context.Context, tx bun.Tx, mapping map[string]string) error {
	for _, table := range []string{"scan", "scan_refusal"} {
		var held []string
		if err := tx.NewSelect().TableExpr(`"`+table+`"`).
			ColumnExpr(`DISTINCT "credential"`).
			Where(`"credential" IS NOT NULL`).
			Scan(ctx, &held); err != nil {
			return fmt.Errorf("read who sent what %s holds: %w", table, err)
		}
		for _, from := range held {
			to, known := mapping[from]
			if !known {
				continue
			}
			if _, err := tx.NewRaw(`UPDATE "`+table+`" SET "credential" = ? WHERE "credential" = ?`,
				to, from).Exec(ctx); err != nil {
				return fmt.Errorf("record who sent what %s holds: %w", table, err)
			}
		}
	}
	return nil
}
