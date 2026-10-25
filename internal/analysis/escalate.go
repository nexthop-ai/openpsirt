// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// MaxImportantPaths bounds the paths a product marks important. Each is
// asked of every baseline lead its lists read.
const MaxImportantPaths = 500

// escalation is a lead somebody pulled into the queue.
type escalation struct {
	bun.BaseModel `bun:"table:lead_escalation,alias:le"`

	ID            int64     `bun:"id,pk,autoincrement"`
	ProductID     int64     `bun:"product_id,notnull"`
	PlaceIdentity string    `bun:"place_identity,notnull"`
	EscalatedBy   int64     `bun:"escalated_by,notnull"`
	EscalatedAt   time.Time `bun:"escalated_at,notnull"`
}

// importantPath is a path prefix whose baseline leads are in the queue.
type importantPath struct {
	bun.BaseModel `bun:"table:lead_important_path,alias:ip"`

	ID             int64  `bun:"id,pk,autoincrement"`
	ProductID      int64  `bun:"product_id,notnull"`
	Prefix         string `bun:"prefix,notnull"`
	PrefixIdentity string `bun:"prefix_identity,notnull"`
	Under          string `bun:"under,notnull"`
	UnderLength    int    `bun:"under_length,notnull"`
}

// Escalated is a lead pulled into the queue: by whom and when. Pulled in
// again, it keeps the first.
type Escalated struct {
	By int64
	At time.Time
}

// Escalate pulls a product's lead into the queue on every build it is on.
// The subject has to triage the lead's visibility; a lead the subject may
// not read, and a place holding no open lead, are finding.ErrNothingOpenThere.
func Escalate(ctx context.Context, db bun.IDB, subject access.Subject, productID int64,
	placeIdentity string, now time.Time) (*Escalated, error) {

	out := &Escalated{}
	err := database.Within(ctx, db, func(ctx context.Context, tx bun.IDB) error {
		kinds, kindArgs := kind.Leads.Where(`"f"."kind"`)
		var held []access.Visibility
		if err := tx.NewSelect().TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "t" ON "t"."id" = "f"."target_id"`).
			Join(`JOIN "stream" AS "s" ON "s"."id" = "t"."stream_id"`).
			ColumnExpr(`DISTINCT "f"."visibility"`).
			Where(`"s"."product_id" = ?`, productID).
			Where(`"f"."place_identity" = ?`, placeIdentity).
			Where(`"f"."closed_at" IS NULL`).
			Where(kinds, kindArgs...).
			Scan(ctx, &held); err != nil {
			return fmt.Errorf("read the lead at that place: %w", err)
		}
		readable := slices.DeleteFunc(held, func(v access.Visibility) bool { return !subject.Reads(v, productID) })
		if len(readable) == 0 {
			return finding.ErrNothingOpenThere
		}
		for _, v := range readable {
			if !subject.Triages(v, productID) {
				return access.Denied(fmt.Sprintf("pull a lead in product %d into the queue", productID))
			}
		}
		row := escalation{ProductID: productID, PlaceIdentity: placeIdentity,
			EscalatedBy: subject.ID, EscalatedAt: now.UTC().Truncate(time.Microsecond)}
		if err := database.InBatchesKeeping(ctx, tx, []escalation{row}); err != nil {
			return fmt.Errorf("pull the lead in: %w", err)
		}
		var kept escalation
		if err := tx.NewSelect().Model(&kept).
			Where(`"le"."product_id" = ?`, productID).
			Where(`"le"."place_identity" = ?`, placeIdentity).
			Scan(ctx); err != nil {
			return fmt.Errorf("read the lead pulled in: %w", err)
		}
		out.By, out.At = kept.EscalatedBy, kept.EscalatedAt
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ImportantPaths is the path prefixes a product marks important, in order.
func ImportantPaths(ctx context.Context, db bun.IDB, productID int64) ([]string, error) {
	var rows []importantPath
	if err := db.NewSelect().Model(&rows).
		Where(`"ip"."product_id" = ?`, productID).
		OrderExpr(`"ip"."prefix" ASC`).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the important paths of product %d: %w", productID, err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Prefix)
	}
	return out, nil
}

// CleanImportantPaths is a product's important paths as they are stored:
// each from the top of the checkout with no leading or trailing slash. A
// path that is empty, climbs out of the checkout, or is named twice is
// refused, naming it.
func CleanImportantPaths(paths []string) ([]string, error) {
	if len(paths) > MaxImportantPaths {
		return nil, refusal.Errorf("%d important paths; a product marks at most %d", len(paths), MaxImportantPaths)
	}
	out := make([]string, 0, len(paths))
	seen := map[string]bool{}
	for _, p := range paths {
		clean, ok := sourcelink.CleanPath(p)
		switch {
		case !ok:
			return nil, refusal.Errorf("important path %q climbs out of the checkout or holds an empty segment", p)
		case clean == "":
			return nil, refusal.Errorf("an important path names a directory; the empty path is the whole checkout")
		case seen[clean]:
			return nil, refusal.Errorf("important path %q is named twice", clean)
		}
		seen[clean] = true
		out = append(out, clean)
	}
	slices.Sort(out)
	return out, nil
}

// ReplaceImportantPaths replaces the path prefixes a product marks
// important with paths, as CleanImportantPaths returns them.
func ReplaceImportantPaths(ctx context.Context, tx bun.IDB, productID int64, paths []string) error {
	if _, err := tx.NewDelete().Model((*importantPath)(nil)).
		Where(`"product_id" = ?`, productID).Exec(ctx); err != nil {
		return fmt.Errorf("clear the important paths of product %d: %w", productID, err)
	}
	if len(paths) == 0 {
		return nil
	}
	rows := make([]importantPath, 0, len(paths))
	for _, p := range paths {
		sum := sha256.Sum256([]byte(p))
		rows = append(rows, importantPath{
			ProductID: productID, Prefix: p, PrefixIdentity: hex.EncodeToString(sum[:]),
			Under: p + "/", UnderLength: utf8.RuneCountInString(p) + 1,
		})
	}
	if err := database.InBatches(ctx, tx, rows); err != nil {
		return fmt.Errorf("record the important paths of product %d: %w", productID, err)
	}
	return nil
}
