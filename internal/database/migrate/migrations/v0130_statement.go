// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/uptrace/bun"
)

// receivedStatementV0130 is v0.13.0's declaration of the received VEX
// statement table.
//
// v0.11.0's, with when the publisher made each statement and which newer
// statement of theirs set it aside.
func receivedStatementV0130(t *columnTypes) []string {
	statements := append([]string(nil), declaredV0110(t, "received_vex_statement")...)
	statements[0] = withColumn(statements[0], `"declined_by" `+t.refNull+` NULL,`,
		`-- When the publisher made the statement: its own timestamp, else
			-- its document's. Null where neither states one, so the upload
			-- orders it.
			"said_at" `+t.timestamp+` NULL,
			-- The newer statement from the same publisher about the same
			-- product and issue that set this one aside, which a statement
			-- set aside by a revision of its own document has none of. A
			-- plain reference without a foreign key: statements are never
			-- deleted, so it cannot dangle.
			"overtaken_by" `+t.refNull+` NULL,`)
	return statements
}

// receivedStatementTimedV0130 adds when each statement was made and what
// overtook it. v0.12.0 kept neither, so every statement starts without them
// and is ordered by its upload. Each column is asked for alone: on MySQL and
// MariaDB a stop between two leaves the first added.
func receivedStatementTimedV0130(ctx context.Context, tx bun.Tx) error {
	u, err := upgraderIn(ctx, tx)
	if err != nil {
		return err
	}
	for _, column := range []string{"said_at", "overtaken_by"} {
		present, err := u.hasColumn("received_vex_statement", column)
		if err != nil {
			return err
		}
		if present {
			continue
		}
		if err := u.change(receivedStatementV0130(u.t), change{table: "received_vex_statement",
			add: []added{{column: column}}}); err != nil {
			return err
		}
	}
	return nil
}

// subjectV0130 is what a received statement is about: the issue, the
// component at the version named, and the product it ships inside.
type subjectV0130 struct {
	ProductID   int64   `bun:"product_id"`
	Publisher   string  `bun:"publisher"`
	Source      string  `bun:"source"`
	Issue       string  `bun:"vulnerability"`
	Purl        *string `bun:"purl"`
	Component   string  `bun:"component"`
	About       string  `bun:"about"`
	WithinPurl  *string `bun:"within_purl"`
	Within      *string `bun:"within"`
	WithinAbout *string `bun:"within_about"`
}

// key is the subject as one comparable value, an absent column apart from an
// empty one.
func (s subjectV0130) key() string {
	text := func(v *string) string {
		if v == nil {
			return "\x01"
		}
		return "\x02" + *v
	}
	return fmt.Sprint(s.ProductID) + "\x00" + s.Publisher + "\x00" + s.Source + "\x00" + s.Issue +
		"\x00" + text(s.Purl) + "\x00" + s.Component + "\x00" + s.About + "\x00" + text(s.WithinPurl) +
		"\x00" + text(s.Within) + "\x00" + text(s.WithinAbout)
}

// receivedStatementNewestV0130 leaves in force only the newest of a
// publisher's statements about one subject in documents of one kind, as
// recording does from v0.13.0. v0.12.0 replaced a VEX document by every
// earlier one from its publisher, so its VEX statements never compete; its
// supplier advisories and upstream documents each replaced only their own
// name, and two of them can speak about one subject. None carries a time of
// its own, so the later upload is the newer, and the later recorded on a tie.
// Run again after a stop, it finds the older already set aside.
func receivedStatementNewestV0130(ctx context.Context, tx bun.Tx) error {
	var shared []struct {
		ProductID int64  `bun:"product_id"`
		Issue     string `bun:"vulnerability"`
	}
	if err := tx.NewSelect().TableExpr(`"received_vex_statement"`).
		ColumnExpr(`"product_id", "vulnerability"`).
		Where(`"superseded_at" IS NULL`).
		GroupExpr(`"product_id", "publisher", "source", "vulnerability", "purl", "component", "about",
			"within_purl", "within", "within_about"`).
		Having(`COUNT(*) > 1`).
		Scan(ctx, &shared); err != nil {
		return fmt.Errorf("read the subjects more than one statement stands on: %w", err)
	}
	issues := map[int64][]string{}
	for _, one := range shared {
		if !slices.Contains(issues[one.ProductID], one.Issue) {
			issues[one.ProductID] = append(issues[one.ProductID], one.Issue)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	products := make([]int64, 0, len(issues))
	for id := range issues {
		products = append(products, id)
	}
	slices.Sort(products)
	for _, product := range products {
		var rows []struct {
			subjectV0130
			ID         int64     `bun:"id"`
			UploadedAt time.Time `bun:"uploaded_at"`
		}
		if err := tx.NewSelect().TableExpr(`"received_vex_statement"`).
			ColumnExpr(`"id", "uploaded_at", "product_id", "publisher", "source", "vulnerability", "purl",
				"component", "about", "within_purl", "within", "within_about"`).
			Where(`"product_id" = ?`, product).
			Where(`"vulnerability" IN (?)`, bun.List(issues[product])).
			Where(`"superseded_at" IS NULL`).
			Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read the statements standing on those subjects: %w", err)
		}
		newest := map[string]int{}
		for i, row := range rows {
			at, held := newest[row.key()]
			if !held || row.UploadedAt.After(rows[at].UploadedAt) ||
				row.UploadedAt.Equal(rows[at].UploadedAt) && row.ID > rows[at].ID {
				newest[row.key()] = i
			}
		}
		for i, row := range rows {
			if at := newest[row.key()]; at != i {
				if _, err := tx.NewUpdate().TableExpr(`"received_vex_statement"`).
					Set(`"superseded_at" = ?`, now).
					Set(`"overtaken_by" = ?`, rows[at].ID).
					Where(`"id" = ?`, row.ID).
					Exec(ctx); err != nil {
					return fmt.Errorf("set aside a statement a newer one overtook: %w", err)
				}
			}
		}
	}
	return nil
}
