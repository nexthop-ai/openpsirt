package finding

import (
	"context"
	"fmt"
	"math"
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

// hundredths is a published number in hundredths, rounded. Cut instead, 8.2
// is 819: it is 819.999… as a float.
func hundredths(f float64) int { return int(math.Round(f * 100)) }

// perMillion is a published fraction in parts per million, rounded for the
// same reason.
func perMillion(f float64) int { return int(math.Round(f * 1_000_000)) }

// ratingsOf is the ratings a report states: the ones it lists, or the one its
// score and vector make where it lists none.
func ratingsOf(named Named) []CVSS {
	if len(named.Ratings) > 0 || named.Score <= 0 || strings.TrimSpace(named.Vector) == "" {
		return named.Ratings
	}
	return []CVSS{{
		Generation: GenerationOf(named.ScoreVersion, named.Vector),
		ScoreCenti: hundredths(named.Score), Vector: named.Vector,
		Version: named.ScoreVersion, Source: named.ScoreSource, Kind: named.ScoreKind,
	}}
}

// rate records the ratings a report states, keeping the worst in each
// generation.
//
// The worst, because it is the one answer that is the same whatever order the
// reports arrived in: reports disagree, and keeping the first or the latest
// would make what is held a fact about which scan ran first or last. Kept
// whole, number, vector and publisher together, so the vector never explains
// a number somebody else published.
//
// A re-scan of unchanged data writes nothing. A generation already held is
// replaced only where the report's number is higher, and a new one is inserted
// keeping whatever a concurrent writer put there first, which a retry then
// reads and raises.
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
			strings.TrimSpace(rating.Vector) == "" {
			continue
		}
		if known[rating.Generation] {
			if _, err := v.db.NewUpdate().Model((*CVSS)(nil)).
				Set("score_centi = ?", rating.ScoreCenti).
				Set("vector = ?", rating.Vector).
				Set("score_version = ?", rating.Version).
				Set("score_source = ?", rating.Source).
				Set("score_kind = ?", rating.Kind).
				Where("vulnerability_id = ?", id).
				Where("generation = ?", rating.Generation).
				Where("score_centi < ?", rating.ScoreCenti).
				Exec(ctx); err != nil {
				return fmt.Errorf("raise how the issue is rated: %w", err)
			}
			continue
		}
		known[rating.Generation] = true
		rating.ID, rating.VulnerabilityID = 0, id
		missing = append(missing, rating)
	}
	if len(missing) == 0 {
		return nil
	}
	if err := database.InBatchesKeeping(ctx, v.db, missing); err != nil {
		return fmt.Errorf("record how the issue is rated: %w", err)
	}
	return nil
}

// settle copies the newest generation's rating onto the issue, whole, and
// says whether its number moved.
//
// The issue's number is what the order ranks by and what every list shows
// beside its scheme, so it and its vector, version and publisher are one
// rating rather than five columns filled by different rules. Moved is what
// tells the caller the issue's findings need ranking again.
func (v *Vulnerabilities) settle(ctx context.Context, id int64) (bool, error) {
	var newest []CVSS
	if err := v.db.NewSelect().Model(&newest).
		Where("vr.vulnerability_id = ?", id).
		OrderExpr("vr.generation DESC").
		Limit(1).Scan(ctx); err != nil {
		return false, fmt.Errorf("read the newest rating: %w", err)
	}
	if len(newest) == 0 {
		return false, nil
	}
	rating := newest[0]
	var row Vulnerability
	if err := v.db.NewSelect().Model(&row).Where("id = ?", id).Scan(ctx); err != nil {
		return false, fmt.Errorf("read the issue's rating: %w", err)
	}
	moved := row.ScoreCenti == nil || *row.ScoreCenti != rating.ScoreCenti
	if !moved && row.Vector == rating.Vector && row.ScoreVersion == rating.Version &&
		row.ScoreSource == rating.Source && row.ScoreKind == rating.Kind {
		return false, nil
	}
	if _, err := v.db.NewUpdate().Model((*Vulnerability)(nil)).
		Set("score_centi = ?", rating.ScoreCenti).
		Set("vector = ?", rating.Vector).
		Set("score_version = ?", rating.Version).
		Set("score_source = ?", rating.Source).
		Set("score_kind = ?", rating.Kind).
		Where("id = ?", id).
		Exec(ctx); err != nil {
		return false, fmt.Errorf("record the issue's rating: %w", err)
	}
	return moved, nil
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
