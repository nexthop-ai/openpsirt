package finding

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// CVSS is one published rating of an issue, under one generation of the
// scoring scheme.
//
// A report commonly rates one issue under version 3 and version 4, and the two
// are different judgments rather than two spellings of one: the schemes weigh
// reachability and impact differently. Each is kept, so the screen can show the
// newest and a published advisory can state the one its format has a field
// for.
//
// One type for what a report states and what is stored, as a reference is.
type CVSS struct {
	bun.BaseModel `bun:"table:vulnerability_rating,alias:vr"`

	ID              int64 `bun:"id,pk,autoincrement"`
	VulnerabilityID int64 `bun:"vulnerability_id,notnull"`
	// Generation is the major version of the scheme: 2, 3 or 4. Version 3.0
	// and 3.1 are one generation.
	Generation int    `bun:"generation,notnull"`
	ScoreCenti int    `bun:"score_centi,notnull"`
	Vector     string `bun:"vector,notnull"`
	// Version, Source and Kind are the scheme's version as the report spells
	// it, who published the rating, and whether it is their primary one.
	Version string `bun:"score_version"`
	Source  string `bun:"score_source"`
	Kind    string `bun:"score_kind"`
}

// GenerationOf is the generation a rating is on: the major version the report
// states, or the one the vector names where it states none.
//
// Zero where neither says, which leaves the rating out of the table rather
// than filed under a guess. A version 2 vector names no scheme at all, and a
// report always states its version beside one.
func GenerationOf(version, vector string) int {
	major, _, _ := strings.Cut(strings.TrimSpace(version), ".")
	if n, err := strconv.Atoi(major); err == nil && n > 0 {
		return n
	}
	named, _, _ := strings.Cut(strings.ToUpper(strings.TrimSpace(vector)), "/")
	if rest, found := strings.CutPrefix(named, "CVSS:"); found {
		major, _, _ = strings.Cut(rest, ".")
		if n, err := strconv.Atoi(major); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// rate records the ratings a report states under a generation this issue has
// no rating for yet.
//
// The first stated in each generation is kept, whole: a later report does not
// replace it, for the reason a description is filled in rather than
// overwritten — reports disagree and arrive in an order nobody controls, so
// taking the latest would make what is stored a fact about which scan ran
// last. Kept whole, so the number and the vector never come from two
// different publishers.
//
// A re-scan of unchanged data writes nothing: the pair is unique and the
// generations already held are read first.
func (v *Vulnerabilities) rate(ctx context.Context, id int64, ratings []CVSS) error {
	if len(ratings) == 0 {
		return nil
	}
	var held []int
	if err := v.db.NewSelect().Model((*CVSS)(nil)).
		ColumnExpr("vr.generation").
		Where("vr.vulnerability_id = ?", id).
		Scan(ctx, &held); err != nil {
		return fmt.Errorf("read the ratings already held: %w", err)
	}
	known := map[int]bool{}
	for _, generation := range held {
		known[generation] = true
	}
	var missing []CVSS
	for _, rating := range ratings {
		if rating.Generation <= 0 || rating.ScoreCenti <= 0 ||
			strings.TrimSpace(rating.Vector) == "" || known[rating.Generation] {
			continue
		}
		known[rating.Generation] = true
		rating.ID, rating.VulnerabilityID = 0, id
		missing = append(missing, rating)
	}
	if len(missing) == 0 {
		return nil
	}
	if err := database.InBatches(ctx, v.db, missing); err != nil {
		return fmt.Errorf("record how the issue is rated: %w", err)
	}
	return nil
}

// Ratings reads every rating held for one issue, newest generation first.
func (v *Vulnerabilities) Ratings(ctx context.Context, id int64) ([]CVSS, error) {
	var ratings []CVSS
	if err := v.db.NewSelect().Model(&ratings).
		Where("vr.vulnerability_id = ?", id).
		OrderExpr("vr.generation DESC").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read how the issue is rated: %w", err)
	}
	return ratings, nil
}
