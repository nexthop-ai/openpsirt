// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/uptrace/bun"
)

// PointsAtFor is every address held for an issue, patches first, as this
// subject may be told them.
//
// Read on its own because DescribeFor answers what an issue *is* and this is
// where to read about it — one document wants both and the screens want one
// each, and a reader that always fetched both would make the cheaper question
// cost the same as the dearer one. Left out where DescribeFor leaves out the
// description, for the same reason: the addresses a flaw recorded here names
// are part of its record.
func (v *Vulnerabilities) PointsAtFor(ctx context.Context, subject access.Subject,
	id int64) ([]Reference, error) {

	withheld, err := recordedOutOfReach(ctx, v.db, subject, id)
	if err != nil || withheld {
		return nil, err
	}
	return v.pointsAt(ctx, id)
}

// pointsAt is PointsAtFor before anything is withheld.
func (v *Vulnerabilities) pointsAt(ctx context.Context, id int64) ([]Reference, error) {
	var references []Reference
	if err := v.db.NewSelect().Model(&references).
		Where(`"vulnerability_id" = ?`, id).
		// Patches first, the same order the finding's own evidence reads
		// them in: for somebody deciding whether to backport, the change
		// itself is the answer and everything else is background.
		OrderExpr(`CASE WHEN "kind" = ? THEN 0 ELSE 1 END, "url"`, Patch).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read where this is written up: %w", err)
	}
	return references, nil
}

// ErrNoSuchIssue is what a name nobody has filed under comes back as.
//
// A sentinel rather than a sentence, because whoever asked has to tell it from
// a read that could not be made: the first is a 404 and the second is a fault,
// and a caller matching on words cannot tell them apart at all.
var ErrNoSuchIssue = refusal.New("no issue is known by that name")

// ByName resolves an issue by any name it is known under.
//
// Any of them, because identity spans the aliases: somebody who read a
// national identifier in an advisory and somebody looking at a report that
// used a database's own identifier are asking about the same issue.
func (v *Vulnerabilities) ByName(ctx context.Context, name string) (int64, error) {
	normalized := normalize(name)
	if normalized == "" {
		return 0, fmt.Errorf("no issue is named %q: %w", name, ErrNoSuchIssue)
	}
	var alias Alias
	if err := v.db.NewSelect().Model(&alias).
		Where(`"identifier" = ?`, normalized).Scan(ctx); err != nil {
		return 0, database.FromRead(err, fmt.Errorf("no issue is named %q: %w", name, ErrNoSuchIssue),
			fmt.Sprintf("look up what issue %q is", name))
	}
	return alias.VulnerabilityID, nil
}

// IDsByName resolves many issues at once, by any name each is known under.
//
// One statement rather than one per name. A judgment covering two thousand
// issues resolved one at a time is two thousand round trips before any of the
// work starts.
func (v *Vulnerabilities) IDsByName(ctx context.Context, names []string) (map[string]int64, error) {
	found := map[string]int64{}
	if len(names) == 0 {
		return found, nil
	}
	wanted := make([]string, 0, len(names))
	for _, name := range names {
		if normalized := normalize(name); normalized != "" {
			wanted = append(wanted, normalized)
		}
	}
	if len(wanted) == 0 {
		return found, nil
	}
	var aliases []Alias
	if err := v.db.NewSelect().Model(&aliases).
		Column("identifier", "vulnerability_id").
		Where(`"identifier" IN (?)`, bun.List(wanted)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which issues these are: %w", err)
	}
	byIdentifier := make(map[string]int64, len(aliases))
	for _, alias := range aliases {
		byIdentifier[alias.Identifier] = alias.VulnerabilityID
	}
	// Keyed by what the caller wrote, not by the normalized form, so a caller
	// can say which of the names it gave was not recognized.
	for _, name := range names {
		if id, ok := byIdentifier[normalize(name)]; ok {
			found[name] = id
		}
	}
	return found, nil
}

// NamesByID resolves issues to the name each is filed under.
//
// The name it is filed under, not every name it is known by: a list showing
// three aliases per row is a list nobody scans. Whatever a caller typed to
// find it, the one shown back is the recognized one.
func (v *Vulnerabilities) NamesByID(ctx context.Context, ids []int64) (map[int64]string, error) {
	names, err := database.NamesByID(ctx, v.db, `"vulnerability"`, `"identifier"`, ids)
	if err != nil {
		return nil, fmt.Errorf("read what these issues are called: %w", err)
	}
	return names, nil
}

// DescribeFor reads what is known about one issue, and every name it goes by,
// as this subject may be told it.
//
// For the page that answers about an issue rather than about a product : the
// row itself is the same one every finding points at, so what this adds over a
// lookup is the names — and those are the reason somebody arrived here,
// because the name their scanner used is often not the one it is filed under.
//
// A flaw recorded here writes its summary as the issue's description and its
// minted identifier among the issue's names. Where such a record sits in a
// product the subject may not read, at its visibility, both are left out: the
// summary of an undisclosed flaw in somebody else's product is the embargo.
func (v *Vulnerabilities) DescribeFor(ctx context.Context, subject access.Subject,
	id int64) (Named, error) {

	known, err := v.describe(ctx, id)
	if err != nil {
		return Named{}, err
	}
	withheld, err := recordedOutOfReach(ctx, v.db, subject, id)
	if err != nil {
		return Named{}, err
	}
	if withheld {
		known.withholdRecorded()
		return known, nil
	}
	// Every record of the issue is in this reader's reach, so the rating a
	// product recorded it at stands where the issue holds none of its own.
	if err := v.recordedOver(ctx, &known, id); err != nil {
		return Named{}, err
	}
	return known, nil
}

// recordedOver fills in what the issue holds no value of its own for from the
// rating a product recorded it at: the word, and the score, its vector and its
// scheme. Where several products recorded it, the first to have done so.
func (v *Vulnerabilities) recordedOver(ctx context.Context, known *Named, id int64) error {
	var rows []RecordedRating
	if err := v.db.NewSelect().Model(&rows).
		Where(`"rr"."vulnerability_id" = ?`, id).
		OrderExpr(`"rr"."id"`).Limit(1).Scan(ctx); err != nil {
		return fmt.Errorf("read how this was rated when it was recorded: %w", err)
	}
	if len(rows) == 0 {
		return nil
	}
	recorded := rows[0]
	if known.Severity == "" && recorded.Severity != nil {
		known.Severity = *recorded.Severity
	}
	if known.Score == 0 && recorded.ScoreCenti != nil {
		known.Score = float64(*recorded.ScoreCenti) / 100
		known.Vector, known.ScoreVersion, known.ScoreSource = deref(recorded.Vector), deref(recorded.ScoreVersion), ""
	}
	return nil
}

// deref is a string held as optional, or nothing.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// withholdRecorded leaves out what a flaw recorded out of the reader's reach
// may have written onto the issue: the description and the other names. Its
// rating is the recording product's own and never on the issue.
func (n *Named) withholdRecorded() {
	n.Description = ""
	n.Aliases = nil
}

// WithholdRecorded leaves out of an issue row what a flaw recorded out of the
// reader's reach may have written onto it, by the rule Named follows.
func (v *Vulnerability) WithholdRecorded() {
	v.Description = ""
}

// recordedOutOfReach reports whether a flaw recorded here about this issue sits
// where this subject may not read it.
func recordedOutOfReach(ctx context.Context, db bun.IDB, subject access.Subject,
	id int64) (bool, error) {

	out, err := RecordedOutOfReach(ctx, db, subject, []int64{id})
	return out[id], err
}

// RecordedOutOfReach reports, of these issues, which have a flaw recorded here
// about them that sits where this subject may not read it.
//
// Every reader of an issue's description, other names or addresses asks this,
// because a recorded flaw writes its summary, its minted name and its
// addresses onto the issue row every product shares.
func RecordedOutOfReach(ctx context.Context, db bun.IDB, subject access.Subject,
	ids []int64) (map[int64]bool, error) {

	out := make(map[int64]bool, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	if _, all := subject.Products(); all {
		return out, nil
	}
	where, args := recordedOutOfReachOf(subject, `"ro"."id"`)
	var withheld []int64
	if err := db.NewSelect().
		TableExpr(`"vulnerability" AS "ro"`).
		ColumnExpr(`"ro"."id"`).
		Where(`"ro"."id" IN (?)`, bun.List(ids)).
		Where(where, args...).
		Scan(ctx, &withheld); err != nil {
		return nil, fmt.Errorf("read where these issues were recorded: %w", err)
	}
	for _, id := range withheld {
		out[id] = true
	}
	return out, nil
}

// RecordedElsewhere reports, of these issues, which have a flaw recorded here
// about them in a product other than this one.
//
// Asked by what one product publishes about an issue, whoever generates it:
// a published document is read by everybody, so another product's record is
// out of its reach whatever the generator may read.
func RecordedElsewhere(ctx context.Context, db bun.IDB, productID int64,
	ids []int64) (map[int64]bool, error) {

	out := make(map[int64]bool, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	var elsewhere []int64
	if err := db.NewSelect().
		TableExpr(`"vulnerability" AS "ro"`).
		ColumnExpr(`"ro"."id"`).
		Where(`"ro"."id" IN (?)`, bun.List(ids)).
		Where(`EXISTS (SELECT 1 FROM "finding" AS "rf"
			JOIN "target" AS "rt" ON "rt"."id" = "rf"."target_id"
			JOIN "stream" AS "rs" ON "rs"."id" = "rt"."stream_id"
			WHERE "rf"."vulnerability_id" = "ro"."issue_id"
			AND "rf"."kind" = ? AND "rs"."product_id" <> ?)`, Entered, productID).
		Scan(ctx, &elsewhere); err != nil {
		return nil, fmt.Errorf("read where else these issues were recorded: %w", err)
	}
	for _, id := range elsewhere {
		out[id] = true
	}
	return out, nil
}

// recordedOutOfReachOf is the condition that a flaw recorded here about the
// issue in column sits where this subject may not read it, for a query that
// matches against an issue's description.
func recordedOutOfReachOf(subject access.Subject, column string) (string, []any) {
	products, all := subject.Products()
	if all {
		return "1 = 0", nil
	}
	// Neither column is ever null, so negating the reader's narrowing is
	// exact.
	both, public, private := access.Split(products, subject.Reads)
	visible, args := access.VisibleWhere(`"rs"."product_id"`, `"rf"."visibility"`, both, public, private)
	return `EXISTS (SELECT 1 FROM "finding" AS "rf"
		JOIN "target" AS "rt" ON "rt"."id" = "rf"."target_id"
		JOIN "stream" AS "rs" ON "rs"."id" = "rt"."stream_id"
		WHERE "rf"."vulnerability_id" = (SELECT "ri"."issue_id" FROM "vulnerability" AS "ri" WHERE "ri"."id" = ` + column + `)
		AND "rf"."kind" = ? AND NOT (` + visible + `))`, append([]any{Entered}, args...)
}

// describe is DescribeFor before anything is withheld.
func (v *Vulnerabilities) describe(ctx context.Context, id int64) (Named, error) {
	var row Vulnerability
	if err := v.db.NewSelect().Model(&row).Where(`"id" = ?`, id).Scan(ctx); err != nil {
		return Named{}, fmt.Errorf("read what this issue is: %w", err)
	}
	var names []string
	if err := v.db.NewSelect().Model((*Alias)(nil)).
		ColumnExpr(`"va"."identifier"`).
		Where(`"va"."vulnerability_id" = ?`, id).
		OrderExpr(`"va"."identifier"`).
		Scan(ctx, &names); err != nil {
		return Named{}, fmt.Errorf("read what else it is called: %w", err)
	}
	ratings, err := v.Ratings(ctx, id)
	if err != nil {
		return Named{}, err
	}
	known := Named{
		Identifier: row.Identifier, Severity: row.Severity,
		Description: row.Description, Advisory: row.Advisory,
		Vector: row.Vector, Exploited: row.Exploited,
		Ratings: ratings,
	}
	if row.ScoreCenti != nil {
		// The scheme with the number. Two are scorable and their numbers are
		// not comparable, so a caller handed one without the other cannot
		// place it beside another.
		known.Score = float64(*row.ScoreCenti) / 100
		known.ScoreVersion = row.ScoreVersion
		known.ScoreSource = row.ScoreSource
	}
	for _, name := range names {
		// The name it is filed under is one of these, and repeating it as an
		// alias of itself reads as a second issue.
		if name != row.Identifier {
			known.Aliases = append(known.Aliases, name)
		}
	}
	return known, nil
}
