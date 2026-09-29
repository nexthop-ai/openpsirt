// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/filed"
)

// Merge is the record of one issue merged into another, because a report
// named both.
//
// The act is a record of its own. What was decided under the issue that was
// absorbed stays filed under it, and is read as the issue it merged into
// through the issue each row states.
type Merge struct {
	bun.BaseModel `bun:"table:vulnerability_merge,alias:vm"`

	ID int64 `bun:"id,pk,autoincrement"`
	// AbsorbedID is the issue that stopped holding findings and aliases, and
	// KeptID the one it was merged into at the time. The absorbed row keeps
	// the name it is filed under, and every lookup by that name resolves
	// through the issue it states, which is why no later report can merge it
	// a second time.
	AbsorbedID int64 `bun:"absorbed_id,notnull"`
	KeptID     int64 `bun:"kept_id,notnull"`
	// Named is the names the report gave the issue, as it gave them,
	// separated by a space. An identifier holds none.
	Named string `bun:"named,notnull"`
	// RunID is the run whose report named both.
	RunID    *int64    `bun:"run_id"`
	MergedAt time.Time `bun:"merged_at,notnull"`
}

// FiledUnder is the condition that a row whose issue is held in column is
// about the issue bound in its one placeholder. The filed package holds the
// spelling.
func FiledUnder(column string) string { return filed.Under(column) }

// FiledUnderAny is FiledUnder for a list of issues bound in its one
// placeholder.
func FiledUnderAny(column string) string { return filed.UnderAny(column) }

// Decisions is every decision `de` beside `dv`, the issue it was filed under.
//
// A decision is related to a finding through `dv.issue_id`, because the issue
// a decision was filed under may since have merged into the one the finding
// holds. Written as a join, so every engine reaches the decisions of a finding
// through an index on each side.
const Decisions = `"vulnerability" AS "dv" JOIN "decision" AS "de" ON de.vulnerability_id = dv.id`

// LiveKey is what a live decision is a claim about, hashed: the product, the
// issue, the place, and both upstream versions it was made against — or the
// place alone, where the claim stands at any version.
//
// Hashed rather than stored as its parts, because it exists to be compared for
// equality under a unique index and nothing ever reads it back. The versions
// are trimmed the way they are everywhere else, so a claim written with spaces
// around a version collides with one written without.
//
// The two shapes cannot collide. A key over three fields and a key over five
// are different strings before they are hashed, so a correction and a claim
// about a place that states no version at all stay apart.
func LiveKey(productID, issueID int64, place, componentUpstream, consumerUpstream string,
	anyVersion bool) string {

	parts := []string{
		strconv.FormatInt(productID, 10),
		strconv.FormatInt(issueID, 10),
		place,
	}
	if !anyVersion {
		parts = append(parts, strings.TrimSpace(componentUpstream), strings.TrimSpace(consumerUpstream))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:])
}

// DecisionIssue joins `dv`, the issue a decision `de` was filed under, to a
// query that starts from the decisions. The issue it is read as is
// `dv.issue_id`.
const DecisionIssue = `JOIN "vulnerability" AS "dv" ON dv.id = de.vulnerability_id`

// SameIssue is the condition that the finding issue column holds the issue a
// row filed under the issue in filed is read as. A finding is always filed
// under the issue it is read as.
//
// A correlated existence test on the issue's primary key rather than an
// equality with a scalar subquery: MariaDB refuses the second wherever it
// rewrites the comparison into an IN. Both columns are spliced into the
// statement, so they are always ones named in code.
func SameIssue(finding, filed string) string {
	return `EXISTS (SELECT 1 FROM "vulnerability" AS "si" WHERE "si"."id" = ` + filed +
		` AND "si"."issue_id" = ` + finding + `)`
}

// HeldAs is the condition that a finding's issue column holds the issue the
// row bound in its one placeholder is read as. A record filed under an issue
// that merged into another names the issue it was filed under, and its
// findings are held under the other.
func HeldAs(column string) string {
	return column + ` = (SELECT "hi"."issue_id" FROM "vulnerability" AS "hi" WHERE "hi"."id" = ?)`
}

// IssuesOf is the issue each of these rows is read as.
func IssuesOf(ctx context.Context, db bun.IDB, ids []int64) (map[int64]int64, error) {
	out := make(map[int64]int64, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	var rows []Vulnerability
	if err := db.NewSelect().Model(&rows).
		Column("id", "issue_id").
		Where("vu.id IN (?)", bun.List(ids)).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which issues these are: %w", err)
	}
	for _, row := range rows {
		out[row.ID] = row.IssueID
	}
	return out, nil
}

// issueOf is the issue a row filed under this one is read as: itself, or the
// issue it was merged into.
func issueOf(ctx context.Context, db bun.IDB, vulnerabilityID int64) (int64, error) {
	var issue int64
	if err := db.NewSelect().Model((*Vulnerability)(nil)).
		ColumnExpr("vu.issue_id").
		Where("vu.id = ?", vulnerabilityID).
		Scan(ctx, &issue); err != nil {
		return 0, fmt.Errorf("read which issue this is: %w", err)
	}
	return issue, nil
}

// MergesInto is every merge into one issue, the earliest first, including
// those into an issue that later merged into it.
func MergesInto(ctx context.Context, db bun.IDB, issueID int64) ([]Merge, error) {
	var merges []Merge
	if err := db.NewSelect().Model(&merges).
		Where(FiledUnder("vm.absorbed_id"), issueID).
		OrderExpr("vm.merged_at, vm.id").
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what merged into this issue: %w", err)
	}
	return merges, nil
}

// merging resolves the rows a report's names reach to one, merging the rest
// into it.
//
// The one kept is the row filed under the name the issue is best known by,
// which is the name it keeps. Where no row holds that name, the one recorded
// first is kept and refiled under it.
func (v *Vulnerabilities) merging(ctx context.Context, rows []int64, names []string) (int64, error) {
	sort.Slice(rows, func(i, j int) bool { return rows[i] < rows[j] })
	// Every row taken before anything about them is read, and each still its
	// own issue when taken. Two scans can merge overlapping sets at once, one
	// keeping a row the other absorbs; without this the second reads a row
	// the first is moving and leaves an issue two steps from the one that
	// stands. An ordinary row update is a lock every engine honors, so the
	// second waits, finds a row that is no longer its own issue, and goes
	// again against what the first committed.
	res, err := v.db.NewUpdate().Model((*Vulnerability)(nil)).
		Set("issue_id = vu.issue_id").
		Where("vu.id IN (?)", bun.List(rows)).
		Where("vu.issue_id = vu.id").Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("take the issues a report named together: %w", err)
	}
	taken, err := database.Affected(res)
	if err != nil {
		return 0, fmt.Errorf("take the issues a report named together: %w", err)
	}
	if taken != int64(len(rows)) {
		return 0, database.ErrGoAgain
	}
	var held []Vulnerability
	if err := v.db.NewSelect().Model(&held).
		Where("vu.id IN (?)", bun.List(rows)).
		OrderExpr("vu.id").Scan(ctx); err != nil {
		return 0, fmt.Errorf("read the issues a report named together: %w", err)
	}
	// Every row's filed name first, in the order the rows were recorded, so
	// a report leaving out the better name is no reason to prefer a lesser one.
	choices := make([]string, 0, len(held)+len(names))
	for _, row := range held {
		choices = append(choices, row.Identifier)
	}
	choices = append(choices, names...)
	best := preferred(Named{Identifier: choices[0], Aliases: choices[1:]})
	kept := rows[0]
	for _, row := range held {
		if normalize(row.Identifier) == best {
			kept = row.ID
		}
	}
	for _, row := range held {
		if row.ID == kept {
			continue
		}
		if err := v.absorb(ctx, kept, row, names); err != nil {
			return 0, err
		}
	}
	return kept, nil
}

// absorb merges one issue into another.
//
// What a report said about the issue it absorbed is what a report now says
// about the one kept: its names, its classification, its ratings, where it
// is written up and the signals that rank it. What was observed of it moves
// too, which is its findings. What people recorded against it stays filed
// under it and is read as the issue kept through the issue the absorbed row
// states. Where a judgment under each name now stands in one product, the one
// with more standing stays and the other stops standing: settleDecisions and
// settleRecords hold the rules.
func (v *Vulnerabilities) absorb(ctx context.Context, kept int64, gone Vulnerability, names []string) error {
	now := v.now().Truncate(time.Microsecond)
	record := &Merge{
		AbsorbedID: gone.ID, KeptID: kept,
		Named: strings.Join(names, " "), MergedAt: now,
	}
	if v.run != 0 {
		run := v.run
		record.RunID = &run
	}
	if _, err := v.db.NewInsert().Model(record).Exec(ctx); err != nil {
		return fmt.Errorf("record %s merging into the issue it is: %w", gone.Identifier, err)
	}
	// Every row read as the issue absorbed, itself and anything merged into it
	// before, is read as the one kept.
	if _, err := v.db.NewUpdate().Model((*Vulnerability)(nil)).
		Set("issue_id = ?", kept).
		Where("vu.issue_id = ?", gone.ID).Exec(ctx); err != nil {
		return fmt.Errorf("read %s as the issue it merged into: %w", gone.Identifier, err)
	}
	if _, err := v.db.NewUpdate().Model((*Alias)(nil)).
		Set("vulnerability_id = ?", kept).
		Where("va.vulnerability_id = ?", gone.ID).Exec(ctx); err != nil {
		return fmt.Errorf("carry the names %s goes by: %w", gone.Identifier, err)
	}

	said, err := v.saidOf(ctx, gone)
	if err != nil {
		return err
	}
	if err := v.describeGaps(ctx, kept, gone); err != nil {
		return err
	}
	if _, err := v.enrich(ctx, kept, said); err != nil {
		return err
	}
	if err := v.classify(ctx, kept, said.Weaknesses, ""); err != nil {
		return fmt.Errorf("carry what kind of flaw %s is: %w", gone.Identifier, err)
	}
	if err := v.rate(ctx, kept, said.Ratings); err != nil {
		return fmt.Errorf("carry how %s is rated: %w", gone.Identifier, err)
	}
	if _, err := v.settle(ctx, kept); err != nil {
		return fmt.Errorf("carry how %s is rated: %w", gone.Identifier, err)
	}
	if err := v.moveFindings(ctx, kept, gone, now); err != nil {
		return err
	}
	if err := v.settleDecisions(ctx, kept, record.ID, now); err != nil {
		return err
	}
	if err := v.settleRecords(ctx, kept, gone, record.ID, now); err != nil {
		return err
	}
	// The findings the absorbed issue held were clocked by its rating and
	// its signals, and each product's clock is now the kept issue's.
	products, err := productsHolding(ctx, v.db, kept)
	if err != nil {
		return err
	}
	for _, product := range products {
		if err := redue(ctx, v.db, product, kept); err != nil {
			return err
		}
	}
	// Everything open against the issue kept is ranked from signals that may
	// have moved, and every finding the absorbed issue held was ranked from
	// its own.
	v.moved[kept] = true
	v.absorbed[gone.ID] = kept
	return nil
}

// saidOf is what reports said about an issue, as a report would say it.
func (v *Vulnerabilities) saidOf(ctx context.Context, row Vulnerability) (Named, error) {
	said := Named{
		Identifier: row.Identifier, Severity: row.Severity,
		Description: row.Description, Advisory: row.Advisory,
		Exploited: row.Exploited, ExploitedOn: row.ExploitedOn, LikelihoodOn: row.LikelihoodOn,
	}
	if row.LikelihoodPPM != nil {
		said.Likelihood = float64(*row.LikelihoodPPM) / 1_000_000
	}
	if row.LikelihoodPercentilePPM != nil {
		said.LikelihoodPercentile = float64(*row.LikelihoodPercentilePPM) / 1_000_000
	}
	if err := v.db.NewSelect().Model((*Weakness)(nil)).
		ColumnExpr("vw.cwe").
		Where("vw.vulnerability_id = ?", row.ID).
		OrderExpr("vw.cwe").
		Scan(ctx, &said.Weaknesses); err != nil {
		return Named{}, fmt.Errorf("read what kind of flaw %s is: %w", row.Identifier, err)
	}
	ratings, err := v.Ratings(ctx, row.ID)
	if err != nil {
		return Named{}, err
	}
	said.Ratings = ratings
	if len(ratings) == 0 && row.ScoreCenti != nil {
		// A number with no rating behind it, which a report states the same
		// way.
		said.Score = float64(*row.ScoreCenti) / 100
		said.Vector = row.Vector
	}
	references, err := v.PointsAt(ctx, row.ID)
	if err != nil {
		return Named{}, err
	}
	said.References = references
	return said, nil
}

// describeGaps fills what the issue kept does not say with what the absorbed
// one did: the published word for how bad it is, and when either was first
// seen.
func (v *Vulnerabilities) describeGaps(ctx context.Context, kept int64, gone Vulnerability) error {
	if strings.TrimSpace(gone.Severity) != "" {
		if _, err := v.db.NewUpdate().Model((*Vulnerability)(nil)).
			Set("severity = ?", gone.Severity).
			Where("vu.id = ?", kept).
			Where("(vu.severity IS NULL OR vu.severity = '')").Exec(ctx); err != nil {
			return fmt.Errorf("carry how bad %s is said to be: %w", gone.Identifier, err)
		}
	}
	if _, err := v.db.NewUpdate().Model((*Vulnerability)(nil)).
		Set("first_seen_at = ?", gone.FirstSeenAt).
		Where("vu.id = ?", kept).
		Where("vu.first_seen_at > ?", gone.FirstSeenAt).Exec(ctx); err != nil {
		return fmt.Errorf("carry when %s was first seen: %w", gone.Identifier, err)
	}
	return nil
}

// moveFindings files the absorbed issue's findings under the issue kept.
//
// A place in a build open under both issues is one finding held twice. The one
// open longer stays open, since it carries the history of the place, and the
// other closes as a record that duplicates an issue already tracked. Where
// only the one that closes was assigned, the one that stays takes its
// assignment, so the work stays in the queue it was in.
//
// Scanned findings alone. A finding a person entered shares a place with a
// scanned one by design, and is closed only by a person.
func (v *Vulnerabilities) moveFindings(ctx context.Context, kept int64, gone Vulnerability, now time.Time) error {
	var open []Finding
	if err := v.db.NewSelect().Model(&open).
		Where("f.vulnerability_id IN (?, ?)", kept, gone.ID).
		Where("f.closed_at IS NULL").
		Where("f.kind = ?", Vulnerable).
		OrderExpr("f.opened_at, f.id").
		Scan(ctx); err != nil {
		return fmt.Errorf("read what is open against %s: %w", gone.Identifier, err)
	}
	type spot struct {
		target, component, consumer int64
	}
	first := map[spot]Finding{}
	var twice []int64
	for _, f := range open {
		at := spot{f.TargetID, f.ComponentID, value(f.ConsumerID)}
		stays, held := first[at]
		if !held {
			first[at] = f
			continue
		}
		twice = append(twice, f.ID)
		if stays.AssignedTo == nil && f.AssignedTo != nil {
			if _, err := v.db.NewUpdate().Model((*Finding)(nil)).
				Set("assigned_to = ?", *f.AssignedTo).
				Set("assigned_at = ?", f.AssignedAt).
				Where("f.id = ?", stays.ID).Exec(ctx); err != nil {
				return fmt.Errorf("carry the assignment of a place held twice under %s: %w",
					gone.Identifier, err)
			}
			stays.AssignedTo, stays.AssignedAt = f.AssignedTo, f.AssignedAt
			first[at] = stays
		}
	}
	if len(twice) > 0 {
		var run *int64
		if v.run != 0 {
			r := v.run
			run = &r
		}
		if _, err := v.db.NewUpdate().Model((*Finding)(nil)).
			Set("closed_at = ?", now).
			Set("closed_run_id = ?", run).
			Set("closed_because = ?", Invalid).
			Set("closed_note = ?", "Held twice once "+gone.Identifier+" merged into the issue it is.").
			Where("f.id IN (?)", bun.List(twice)).Exec(ctx); err != nil {
			return fmt.Errorf("close a place held twice under %s: %w", gone.Identifier, err)
		}
	}
	if _, err := v.db.NewUpdate().Model((*Finding)(nil)).
		Set("vulnerability_id = ?", kept).
		Where("f.vulnerability_id = ?", gone.ID).Exec(ctx); err != nil {
		return fmt.Errorf("file the findings of %s under the issue it is: %w", gone.Identifier, err)
	}
	return nil
}
