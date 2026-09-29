// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// suppressionV050 is v0.5.0's declaration of a build's own claims, and its
// index.
//
// v0.2.0's, which v0.3.0 and v0.4.0 left as it was, with the subject's name
// folded and the version the claim was made about.
func suppressionV050(t *columnTypes) []string {
	return []string{
		`CREATE TABLE "suppression" (
			"id"             ` + t.id + `,
			"target_id"      ` + t.ref + ` NOT NULL,
			"identity"       ` + t.hash + ` NOT NULL,
			"vulnerability"  ` + t.free + ` NOT NULL,
			-- The status vocabulary is the exchange format's, not ours, and
			-- its longest word today is longer than a short identifier
			-- column allows. Whatever it adds next is not ours to bound.
			"status"         ` + t.name + ` NOT NULL,
			"justification"  ` + t.free + ` NULL,
			"statement"      ` + t.text + ` NULL,
			"origin"         ` + t.kind + ` NOT NULL,
			"subject_purl"   ` + t.text + ` NULL,
			"subject_name"   ` + t.free + ` NULL,
			-- The subject's name folded, which a name somebody types is
			-- matched against, for the reason a component's is. The name
			-- beside it is the producer's spelling, which is what is shown.
			"subject_folded" ` + t.name + ` NULL,
			-- The version the claim was made about, where the document stated
			-- one outside the package identifier. A publisher naming no
			-- package states it as the branch its product sits in, and a
			-- claim stored without it covers every version of the name.
			"subject_version" ` + t.free + ` NULL,
			"opened_scan_id" ` + t.ref + ` NOT NULL,
			"closed_scan_id" ` + t.refNull + ` NULL,
			CONSTRAINT "suppression_target_id_fk" FOREIGN KEY ("target_id") REFERENCES "target"("id"),
			CONSTRAINT "suppression_opened_scan_id_fk" FOREIGN KEY ("opened_scan_id") REFERENCES "scan"("id"),
			CONSTRAINT "suppression_closed_scan_id_fk" FOREIGN KEY ("closed_scan_id") REFERENCES "scan"("id")
		)` + t.suffix,

		`CREATE INDEX "suppression_open_idx" ON "suppression" ("target_id", "closed_scan_id")`,
	}
}

// foldedV050 is a name people type as v0.5.0 stores it: without the spaces
// around it, in lower case, and cut to the width of the column that holds it.
//
// Copied rather than called, as every rule a migration applies is.
func foldedV050(name string) string {
	return bound.HeadRunes(strings.ToLower(strings.TrimSpace(name)), database.NameWidth)
}

// subjectsFolded fills in every claim's folded subject from its name. One
// statement per distinct name: a build restates the same subjects scan after
// scan, so there are far fewer names than rows.
func subjectsFolded(ctx context.Context, tx bun.Tx) error {
	var names []string
	if err := tx.NewSelect().TableExpr(`"suppression"`).
		ColumnExpr(`DISTINCT "subject_name"`).
		Where(`"subject_name" IS NOT NULL`).
		Where(`"subject_name" <> ''`).
		Scan(ctx, &names); err != nil {
		return fmt.Errorf("read the names claims are about: %w", err)
	}
	for _, name := range names {
		if _, err := tx.NewRaw(`UPDATE "suppression" SET "subject_folded" = ? WHERE "subject_name" = ?`,
			foldedV050(name), name).Exec(ctx); err != nil {
			return fmt.Errorf("fold the name a claim is about: %w", err)
		}
	}
	return nil
}

// credential is a key or a personal token, as folding its name needs it.
type credential struct {
	ID int64 `bun:"id"`
	// Owner is who the name is unique to: the person holding a token, and
	// zero for a key, whose name is unique across the deployment.
	Owner   int64        `bun:"owner"`
	Name    string       `bun:"name"`
	Revoked sql.NullTime `bun:"revoked_at"`
	// About is the person holding a token, whom the administrative trail
	// names beside it, and empty for a key.
	About string `bun:"about"`
}

// credentialKind is one of the two tables whose names are folded.
type credentialKind struct {
	table string
	// what names one of them in a sentence, and a name that is only spaces.
	what string
	// read is every row, with its owner and how the trail names it.
	read string
}

var (
	keysV050 = credentialKind{table: "api_key", what: "key", read: `SELECT "id", 0 AS "owner",
		"name", "revoked_at", '' AS "about" FROM "api_key"`}
	tokensV050 = credentialKind{table: "personal_token", what: "token", read: `SELECT
		"t"."id", "t"."person_id" AS "owner", "t"."name", "t"."revoked_at",
		"p"."identity" AS "about"
		FROM "personal_token" AS "t" JOIN "person" AS "p" ON "p"."id" = "t"."person_id"`}
)

// namesFolded stores every key's or token's name folded, the way v0.5.0
// stores and matches it, and withdraws every one whose name clashes with
// another's.
//
// A key's name is unique across the deployment and a token's to the person
// holding it. Two names v0.4.0 held apart can fold to one, and v0.5.0 cannot
// tell them apart by it. The first to hold a folded name keeps it and stays as
// it was: one in force before a withdrawn one, then the oldest. Every other
// folding to that name is withdrawn at the moment of the upgrade where it is
// still in force, and left as it was where it is withdrawn already. A pipeline
// or a script sending with a withdrawn one is refused from then on and needs a
// new one. Each withdrawal is recorded in the administrative trail, with the
// upgrade as its actor, named as a withdrawal by a person would name it.
//
// The name stays unique across withdrawn ones too, so each that does not keep
// its name is named by the folded name and its number, as "ci #7". Every first
// holder is reserved before any is numbered, so one already named like a
// number keeps that name and the number moves past it, as "ci #7.2". One whose
// name is only spaces names nothing, clashes with nothing, and is named
// "key #7" or "token #7" the same way.
//
// The names are moved in two steps, through placeholders nothing holds, so
// that no step writes a name another row still has.
func namesFolded(ctx context.Context, tx bun.Tx, kind credentialKind) error {
	var rows []credential
	if err := tx.NewRaw(kind.read).Scan(ctx, &rows); err != nil {
		return fmt.Errorf("read each %s to fold its name: %w", kind.what, err)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Revoked.Valid != rows[j].Revoked.Valid {
			return !rows[i].Revoked.Valid
		}
		return rows[i].ID < rows[j].ID
	})

	held := func(owner int64, name string) string {
		return strconv.FormatInt(owner, 10) + "\x00" + name
	}
	now := map[string]bool{}
	for _, row := range rows {
		now[row.Name] = true
	}
	final := map[int64]string{}
	taken := map[string]bool{}
	// Every first holder is reserved before anybody is numbered, so a number
	// never takes a name another folds to on its own.
	for _, row := range rows {
		if name := foldedV050(row.Name); name != "" && !taken[held(row.Owner, name)] {
			taken[held(row.Owner, name)], final[row.ID] = true, name
		}
	}
	var withdrawing []int64
	for _, row := range rows {
		if _, kept := final[row.ID]; kept {
			continue
		}
		base := foldedV050(row.Name)
		if base != "" && !row.Revoked.Valid {
			withdrawing = append(withdrawing, row.ID)
		}
		if base == "" {
			base = kind.what
		}
		// One already named like a number keeps that name, so the number
		// taken here moves past it.
		id := strconv.FormatInt(row.ID, 10)
		number := " #" + id
		for again := 2; ; again++ {
			name := bound.HeadRunes(base, database.NameWidth-len(number)) + number
			if !taken[held(row.Owner, name)] {
				taken[held(row.Owner, name)], final[row.ID] = true, name
				break
			}
			number = " #" + id + "." + strconv.Itoa(again)
		}
	}

	var moving []int64
	about := map[int64]string{}
	for _, row := range rows {
		if row.About != "" {
			// How a withdrawal by a person names a token: its owner, then it.
			about[row.ID] = row.About + " · "
		}
		if final[row.ID] != row.Name {
			moving = append(moving, row.ID)
		}
	}
	placeholder := map[int64]string{}
	for _, id := range moving {
		name := "folding " + kind.what + " " + strconv.FormatInt(id, 10)
		for now[name] {
			name += "~"
		}
		now[name] = true
		placeholder[id] = name
	}
	for _, step := range []map[int64]string{placeholder, final} {
		for _, id := range moving {
			if _, err := tx.NewRaw(`UPDATE "`+kind.table+`" SET "name" = ? WHERE "id" = ?`,
				step[id], id).Exec(ctx); err != nil {
				return fmt.Errorf("fold the name of %s %d: %w", kind.what, id, err)
			}
		}
	}

	at := time.Now().UTC().Truncate(time.Microsecond)
	for _, id := range withdrawing {
		if _, err := tx.NewRaw(`UPDATE "`+kind.table+`" SET "revoked_at" = ? WHERE "id" = ?`,
			at, id).Exec(ctx); err != nil {
			return fmt.Errorf("withdraw %s %d, whose name another holds: %w", kind.what, id, err)
		}
		if _, err := tx.NewRaw(`INSERT INTO "admin_change"
			("at", "by", "kind", "about", "was", "became", "actor") VALUES (?, NULL, ?, ?, ?, NULL, ?)`,
			at, "credential", about[id]+final[id], "in force", "upgrade").Exec(ctx); err != nil {
			return fmt.Errorf("record that %s %d was withdrawn: %w", kind.what, id, err)
		}
	}
	return nil
}
