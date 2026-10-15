// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
)

// The rows v0.8.0 holds for claims and references, moved to v0.9.0's keys.
//
//   - A claim's reasoning is stored once, in the statement text table, and
//     each claim row of a build or a supplier points at it. v0.8.0 kept a copy
//     on every row.
//   - A build's claim is keyed on its reasoning as well as on what it says,
//     so a changed explanation is a changed claim. Every claim v0.8.0 holds is
//     keyed again, so the first scan after the upgrade finds each one it
//     restates already held.
//   - A reference to an issue is keyed on its address as it was given. v0.8.0
//     keyed it on the address in capitals and cut to an index key's width, so
//     two addresses differing in case or past that width were one reference.
//
// Everything here is written for this migration and frozen with it: how the
// reasoning is cut and how each key is worked out is copied rather than
// called, so a later change to the application does not change what a
// database v0.8.0 built is upgraded into.

// mostWordsV090 is the bound the reasoning is cut to, in bytes.
const mostWordsV090 = 64 << 10

// wordsOfV090 is reasoning as v0.9.0 keeps it: valid UTF-8, without NUL, and
// cut to the bound on a character boundary.
func wordsOfV090(said string) string {
	kept := strings.ReplaceAll(strings.ToValidUTF8(said, "�"), "\x00", "")
	if len(kept) <= mostWordsV090 {
		return kept
	}
	cut := mostWordsV090
	for cut > 0 && !utf8.RuneStart(kept[cut]) {
		cut--
	}
	return kept[:cut]
}

// headRunesV090 keeps the first most characters.
func headRunesV090(s string, most int) string {
	kept := 0
	for i := range s {
		if kept == most {
			return s[:i]
		}
		kept++
	}
	return s
}

// digestV090 is the hex SHA-256 of a string.
func digestV090(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// claimRowV090 is one build claim as v0.8.0 stored it.
type claimRowV090 struct {
	ID             int64  `bun:"id"`
	Identity       string `bun:"identity"`
	Vulnerability  string `bun:"vulnerability"`
	Status         string `bun:"status"`
	Justification  string `bun:"justification"`
	Statement      string `bun:"statement"`
	Origin         string `bun:"origin"`
	SubjectPurl    string `bun:"subject_purl"`
	SubjectName    string `bun:"subject_name"`
	SubjectVersion string `bun:"subject_version"`
	WithinPurl     string `bun:"within_purl"`
	WithinName     string `bun:"within_name"`
	WithinVersion  string `bun:"within_version"`
	StatedBy       *int64 `bun:"stated_by"`
}

// claimIdentityV090 is v0.9.0's key for a build's claim.
func claimIdentityV090(c claimRowV090) string {
	parts := []string{
		strings.ToUpper(strings.TrimSpace(c.Vulnerability)),
		c.Status, c.Justification, c.Origin, c.SubjectPurl, c.SubjectName,
	}
	if c.SubjectVersion != "" {
		parts = append(parts, c.SubjectVersion)
	}
	if c.WithinPurl != "" || c.WithinName != "" {
		parts = append(parts, "within", c.WithinPurl, c.WithinName, c.WithinVersion)
	}
	if c.StatedBy != nil {
		parts = append(parts, "stated", strconv.FormatInt(*c.StatedBy, 10))
	}
	if c.Statement != "" {
		parts = append(parts, "statement", c.Statement)
	}
	return digestV090(strings.Join(parts, "\x00"))
}

// nameWidthV090 is the width of an indexed name column, in characters.
const nameWidthV090 = 191

// shapeWordsV090 makes the statement text table and the column each claim
// table points at it with.
//
// On MySQL and MariaDB this commits as it runs, and a start resuming after it
// steps over the table and each column already made, as it steps over
// anything a migration already created.
func shapeWordsV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	if err := u.create(statementTextV090(t), "statement_text"); err != nil {
		return err
	}
	for table, declared := range map[string][]string{
		"suppression": suppressionV090(t), "vex_statement": vexStatementsV090(t),
	} {
		if err := u.change(declared, change{table: table, add: []added{{column: "statement_id"}}}); err != nil {
			return err
		}
	}
	return nil
}

// moveWordsV090 stores each claim's reasoning once, points the claim at it,
// keys every build claim again, and keys every reference on its address.
//
// Read a page of rows at a time, by identifier: the copies being removed are
// what made these tables large, and a build's claims read whole could be the
// size of every statement it ever multiplied.
//
// Written so that running it twice writes the same rows: a start resuming on
// MySQL or MariaDB runs it again over what a first attempt committed.
func moveWordsV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	held := map[string]int64{}

	if has, err := u.hasColumn("suppression", "statement"); err != nil {
		return err
	} else if has {
		if err := moveClaimWordsV090(ctx, tx, held); err != nil {
			return err
		}
	}
	if has, err := u.hasColumn("vex_statement", "statement"); err != nil {
		return err
	} else if has {
		if err := moveStatementWordsV090(ctx, tx, held); err != nil {
			return err
		}
	}
	return keyReferencesV090(ctx, tx)
}

// pageV090 is how many rows one read of a table takes.
const pageV090 = 1000

// moveClaimWordsV090 keys every build claim again and points each at its
// reasoning.
func moveClaimWordsV090(ctx context.Context, tx bun.Tx, held map[string]int64) error {
	for after := int64(0); ; {
		var claims []claimRowV090
		if err := tx.NewSelect().TableExpr(`"suppression" AS "sup"`).
			ColumnExpr(`sup.id, sup.identity, sup.vulnerability, sup.status, sup.origin`).
			ColumnExpr(`COALESCE(sup.justification, '') AS "justification"`).
			ColumnExpr(`COALESCE(sup.statement, '') AS "statement"`).
			ColumnExpr(`COALESCE(sup.subject_purl, '') AS "subject_purl"`).
			ColumnExpr(`COALESCE(sup.subject_name, '') AS "subject_name"`).
			ColumnExpr(`COALESCE(sup.subject_version, '') AS "subject_version"`).
			ColumnExpr(`COALESCE(sup.within_purl, '') AS "within_purl"`).
			ColumnExpr(`COALESCE(sup.within_name, '') AS "within_name"`).
			ColumnExpr(`COALESCE(sup.within_version, '') AS "within_version"`).
			ColumnExpr(`sup.stated_by`).
			Where("sup.id > ?", after).
			OrderExpr("sup.id").Limit(pageV090).
			Scan(ctx, &claims); err != nil {
			return fmt.Errorf("read the build claims: %w", err)
		}
		if len(claims) == 0 {
			return nil
		}
		after = claims[len(claims)-1].ID
		identity, vulnerability, justification := map[int64]any{}, map[int64]any{}, map[int64]any{}
		version := map[int64]any{}
		pointed := map[int64][]int64{}
		for _, claim := range claims {
			words := wordsOfV090(claim.Statement)
			cutVulnerability := headRunesV090(claim.Vulnerability, nameWidthV090)
			cutJustification := headRunesV090(claim.Justification, nameWidthV090)
			if cutVulnerability != claim.Vulnerability {
				vulnerability[claim.ID] = cutVulnerability
			}
			if cutJustification != claim.Justification {
				justification[claim.ID] = cutJustification
			}
			// A claim taken from a published statement states the version
			// the statement was made about, which moveStatementWordsV090
			// cuts as the statement's is cut.
			if claim.Origin == publishedV090 {
				if cut := headRunesV090(claim.SubjectVersion, nameWidthV090); cut != claim.SubjectVersion {
					version[claim.ID] = cut
					claim.SubjectVersion = cut
				}
			}
			claim.Vulnerability, claim.Justification, claim.Statement = cutVulnerability, cutJustification, words
			if key := claimIdentityV090(claim); key != claim.Identity {
				identity[claim.ID] = key
			}
			if words != "" {
				id, err := internWordsV090(ctx, tx, held, words)
				if err != nil {
					return err
				}
				pointed[id] = append(pointed[id], claim.ID)
			}
		}
		for _, column := range []struct {
			name   string
			values map[int64]any
		}{
			{"identity", identity}, {"vulnerability", vulnerability}, {"justification", justification},
			{"subject_version", version},
		} {
			if err := setByIDV090(ctx, tx, "suppression", column.name, column.values); err != nil {
				return err
			}
		}
		if err := pointAtWordsV090(ctx, tx, "suppression", pointed); err != nil {
			return err
		}
	}
}

// publishedV090 is the origin of a build's claim taken from a published
// statement.
const publishedV090 = "published"

// moveStatementWordsV090 points every supplier statement at its reasoning,
// and cuts what it says it is about and why to the width of their columns.
//
// SQLite held those at any length, and a claim taken from a statement is
// keyed on them: one cut on the claim and whole on the statement would close
// and reopen on the first scan after the upgrade.
func moveStatementWordsV090(ctx context.Context, tx bun.Tx, held map[string]int64) error {
	for after := int64(0); ; {
		var said []struct {
			ID            int64  `bun:"id"`
			Statement     string `bun:"statement"`
			About         string `bun:"about"`
			WithinAbout   string `bun:"within_about"`
			Justification string `bun:"justification"`
		}
		if err := tx.NewSelect().TableExpr(`"vex_statement" AS "ss"`).
			ColumnExpr(`ss.id, ss.about`).
			ColumnExpr(`COALESCE(ss.statement, '') AS "statement"`).
			ColumnExpr(`COALESCE(ss.within_about, '') AS "within_about"`).
			ColumnExpr(`COALESCE(ss.justification, '') AS "justification"`).
			Where("ss.id > ?", after).
			OrderExpr("ss.id").Limit(pageV090).
			Scan(ctx, &said); err != nil {
			return fmt.Errorf("read the supplier statements: %w", err)
		}
		if len(said) == 0 {
			return nil
		}
		after = said[len(said)-1].ID
		pointed := map[int64][]int64{}
		cut := map[string]map[int64]any{"about": {}, "within_about": {}, "justification": {}}
		for _, one := range said {
			for column, value := range map[string]string{
				"about": one.About, "within_about": one.WithinAbout, "justification": one.Justification,
			} {
				if kept := headRunesV090(value, nameWidthV090); kept != value {
					cut[column][one.ID] = kept
				}
			}
			words := wordsOfV090(one.Statement)
			if words == "" {
				continue
			}
			id, err := internWordsV090(ctx, tx, held, words)
			if err != nil {
				return err
			}
			pointed[id] = append(pointed[id], one.ID)
		}
		for _, column := range []string{"about", "within_about", "justification"} {
			if err := setByIDV090(ctx, tx, "vex_statement", column, cut[column]); err != nil {
				return err
			}
		}
		if err := pointAtWordsV090(ctx, tx, "vex_statement", pointed); err != nil {
			return err
		}
	}
}

// keyReferencesV090 keys every reference on its address as it was given.
//
// No two keys collide on the way: two references of one issue that v0.8.0
// held apart differ in their capitals or past the cut, and so differ as
// given.
func keyReferencesV090(ctx context.Context, tx bun.Tx) error {
	for after := int64(0); ; {
		var references []struct {
			ID       int64  `bun:"id"`
			URL      string `bun:"url"`
			Identity string `bun:"url_identity"`
		}
		if err := tx.NewSelect().TableExpr(`"vulnerability_reference" AS "vr"`).
			ColumnExpr(`vr.id, vr.url, vr.url_identity`).
			Where("vr.id > ?", after).
			OrderExpr("vr.id").Limit(pageV090).
			Scan(ctx, &references); err != nil {
			return fmt.Errorf("read the references: %w", err)
		}
		if len(references) == 0 {
			return nil
		}
		after = references[len(references)-1].ID
		keyed := map[int64]any{}
		for _, reference := range references {
			if key := digestV090(strings.TrimSpace(reference.URL)); key != reference.Identity {
				keyed[reference.ID] = key
			}
		}
		if err := setByIDV090(ctx, tx, "vulnerability_reference", "url_identity", keyed); err != nil {
			return err
		}
	}
}

// internWordsV090 is the stored copy of the words, written where there is
// none.
func internWordsV090(ctx context.Context, tx bun.Tx, held map[string]int64, words string) (int64, error) {
	digest := digestV090(words)
	if id, ok := held[digest]; ok {
		return id, nil
	}
	var id int64
	err := tx.NewSelect().TableExpr(`"statement_text"`).ColumnExpr(`"id"`).
		Where(`"words_digest" = ?`, digest).Scan(ctx, &id)
	switch {
	case database.IsNoRows(err):
		row := &wordsRowV090{Digest: digest, Words: words}
		if _, err := tx.NewInsert().Model(row).Exec(ctx); err != nil {
			return 0, fmt.Errorf("store a claim's reasoning: %w", err)
		}
		id = row.ID
	case err != nil:
		return 0, fmt.Errorf("read a claim's stored reasoning: %w", err)
	}
	held[digest] = id
	return id, nil
}

// wordsRowV090 is a row of the statement text table as this migration writes
// it.
type wordsRowV090 struct {
	bun.BaseModel `bun:"table:statement_text"`

	ID     int64  `bun:"id,pk,autoincrement"`
	Digest string `bun:"words_digest"`
	Words  string `bun:"words"`
}

// pointAtWordsV090 points the rows of a table at the stored copies, by the
// copy each points at.
func pointAtWordsV090(ctx context.Context, tx bun.Tx, table string, pointed map[int64][]int64) error {
	copies := make([]int64, 0, len(pointed))
	for id := range pointed {
		copies = append(copies, id)
	}
	slices.Sort(copies)
	for _, id := range copies {
		rows := pointed[id]
		for from := 0; from < len(rows); from += database.BatchSize {
			if _, err := tx.NewUpdate().TableExpr(`"`+table+`"`).
				Set(`"statement_id" = ?`, id).
				Where(`"id" IN (?)`, bun.List(rows[from:min(from+database.BatchSize, len(rows))])).
				Exec(ctx); err != nil {
				return fmt.Errorf("point %s at its reasoning: %w", table, err)
			}
		}
	}
	return nil
}

// setByIDV090 writes one column of many rows, a value each, a batch to a
// statement.
func setByIDV090(ctx context.Context, tx bun.Tx, table, column string, values map[int64]any) error {
	ids := make([]int64, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for from := 0; from < len(ids); from += database.BatchSize {
		batch := ids[from:min(from+database.BatchSize, len(ids))]
		var set strings.Builder
		args := make([]any, 0, 2*len(batch)+1)
		set.WriteString(`CASE "id"`)
		for _, id := range batch {
			set.WriteString(` WHEN ? THEN ?`)
			args = append(args, id, values[id])
		}
		set.WriteString(` END`)
		args = append(args, bun.List(batch))
		if _, err := tx.ExecContext(ctx, `UPDATE "`+table+`" SET "`+column+`" = `+set.String()+
			` WHERE "id" IN (?)`, args...); err != nil {
			return fmt.Errorf("write %s.%s: %w", table, column, err)
		}
	}
	return nil
}

// dropWordsV090 removes the copy of the reasoning each claim row carried.
func dropWordsV090(ctx context.Context, tx bun.Tx) error {
	t, err := types(ctx)
	if err != nil {
		return err
	}
	u := &upgrader{ctx: ctx, tx: tx, raw: tx.Tx, t: t, engine: migrate.EngineFrom(ctx)}
	for _, table := range []struct {
		name     string
		declared []string
	}{
		{"suppression", suppressionV090(t)},
		{"vex_statement", vexStatementsV090(t)},
	} {
		has, err := u.hasColumn(table.name, "statement")
		if err != nil {
			return err
		}
		if !has {
			continue
		}
		if err := u.change(table.declared, change{table: table.name, drop: []string{"statement"}}); err != nil {
			return err
		}
	}
	return nil
}
