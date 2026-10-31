// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// The lines apart two code findings' last places may be for the leads to be one flaw,
// and for them to be offered as possibly one. Measured over clang, cppcheck,
// CodeQL and semgrep on four projects and seeded flaws: the family and the
// last place within two lines grouped every pair that was one flaw and none
// of five pairs of flaws a line or two apart.
const (
	groupLines     = 2
	duplicateLines = 10
)

// nearby is whether the finding under "g", whose result is under "ag", is
// open on the build of the finding under "f", whose result is under "ar",
// reported by another analyzer, under a rule of a weakness family the other's
// rule shares, with its last place in the same file within lines of the
// other's. Two results of one analyzer are never one flaw: two flaws of a
// class on adjacent lines are told apart only by the tool reporting them as
// two, and two rules of one tool on one line are two checks it makes.
//
// The last path is compared by its digest first, which is what the index on
// it holds, and then as written.
func nearby(lines int) string {
	n := strconv.Itoa(lines)
	return `"ag"."last_path_identity" = "ar"."last_path_identity" AND "ag"."last_path" = "ar"."last_path"
	  AND "ag"."last_line" BETWEEN "ar"."last_line" - ` + n + ` AND "ar"."last_line" + ` + n + `
	  AND "g"."build_id" = "f"."build_id" AND "g"."closed_at" IS NULL
	  AND "g"."kind" = '` + string(kind.Analysis) + `'
	  AND "g"."vulnerability_id" <> "f"."vulnerability_id"
	  AND EXISTS (SELECT 1 FROM "rule_family" AS "fa"
		JOIN "rule_family" AS "fb" ON "fb"."family" = "fa"."family" AND "fb"."tool" <> "fa"."tool"
		WHERE "fa"."vulnerability_id" = "f"."vulnerability_id" AND "fb"."vulnerability_id" = "g"."vulnerability_id")`
}

// corroboratedIn is the code findings of the scope's builds that another
// analyzer's code finding is the same flaw as: nearby within the lines of a
// group, worked out over every code finding of those builds, whoever reads
// it, because where a code finding sorts does not depend on who is looking.
//
// Each code finding is read once for each weakness family of its rule, and
// the rows of one build, file and family are compared within those lines as
// a window: the analyzers of the open code findings in it, fewest and most,
// differ from the row's own where another analyzer reports the flaw. A rule
// belongs to a family once, under its own analyzer, so another analyzer is
// another rule.
//
// A window, because every pairing of a code finding with the open ones near
// it was planned by some engine through every open finding of a build or of
// a rule, with statistics as loaded:
//
// | Pairing | What an engine did |
// |---|---|
// | Asked of each row | MySQL 8.4: 12 s for 8,000 code findings |
// | Joined to the rows | PostgreSQL 16: planned for a handful, 1.8 s |
// | A set with the family among the joins | MySQL 8.4: paired every code finding of one rule with every one of another, 11 s |
// | A set reaching the open ones by build | MySQL 8.4: past 30 s; with them read as a set of their own, 7 s |
// | Two sets of their own, paired by build and file | PostgreSQL 16: planned for one row each and read one set once per row of the other, 5.5 s |
//
// The set is asked of each row of the page.
func (scope Scope) corroboratedIn(db bun.IDB) *bun.SelectQuery {
	n := strconv.Itoa(groupLines)
	open := `CASE WHEN "f"."closed_at" IS NULL AND "f"."kind" = '` + string(kind.Analysis) + `' THEN "fa"."tool" END`
	near := ` OVER (PARTITION BY "f"."build_id", "ar"."last_path_identity", "ar"."last_path", "fa"."family"
		ORDER BY "ar"."last_line" RANGE BETWEEN ` + n + ` PRECEDING AND ` + n + ` FOLLOWING)`
	kinds, kindArgs := kind.CodeFindings.Where(`"f"."kind"`)
	placed := scope.builtIn(db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "rule_family" AS "fa" ON "fa"."vulnerability_id" = "f"."vulnerability_id"`).
		ColumnExpr(`"f"."id", "fa"."tool"`).
		ColumnExpr(`MIN(`+open+`)`+near+` AS "fewest"`).
		ColumnExpr(`MAX(`+open+`)`+near+` AS "most"`).
		Where(`"ar"."last_line" IS NOT NULL`).
		Where(kinds, kindArgs...))
	return identifiers(db, db.NewSelect().TableExpr(`(?) AS "nw"`, placed).
		ColumnExpr(`"nw"."id"`).
		Where(`("nw"."fewest" <> "nw"."tool" OR "nw"."most" <> "nw"."tool")`).
		GroupExpr(`"nw"."id"`))
}

// Kin is another code finding on a code finding's build that is the same flaw, or possibly
// is.
type Kin struct {
	Occurrence string
	Rule       string
	Path       string
	Line       *int
	// Same is whether it is the same flaw rather than possibly so.
	Same bool
}

// KinOf is the code findings on a code finding's build that are the same flaw as it, or
// possibly are, where the subject may read them: same first, then by line.
func KinOf(ctx context.Context, db bun.IDB, subject access.Subject, productID, codeFindingID int64) ([]Kin, error) {
	// A grant of one code finding, or of one case, reads no other code finding.
	if !subject.Sees(productID) {
		return []Kin{}, nil
	}
	visible, err := finding.CodeFindingVisible(subject, productID)
	if err != nil {
		return nil, err
	}
	reach := finding.CodeFindingReach(subject, productID)
	var rows []struct {
		Occurrence string `bun:"occurrence_identity"`
		Rule       string `bun:"rule"`
		Path       string `bun:"last_path"`
		Line       *int   `bun:"last_line"`
		Same       int    `bun:"same"`
	}
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "finding" AS "g" ON "g"."build_id" = "f"."build_id"`).
		Join(`JOIN "analysis_result" AS "ag" ON "ag"."finding_id" = "g"."id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "g"."vulnerability_id"`).
		ColumnExpr(`"g"."occurrence_identity", "vu"."identifier" AS "rule", "ag"."last_path", "ag"."last_line"`).
		ColumnExpr(`CASE WHEN "ag"."last_line" BETWEEN "ar"."last_line" - ? AND "ar"."last_line" + ? `+
			`THEN 1 ELSE 0 END AS "same"`, groupLines, groupLines).
		Where(`"f"."id" = ?`, codeFindingID).
		Where(nearby(duplicateLines)).
		// A code finding included in its flaw's case is read by the flaw's readers
		// beside the product's own visibilities, as the queue reads it.
		Where(`("g"."visibility" IN (?) OR EXISTS (SELECT 1 FROM "finding" AS "f" WHERE "f"."id" = "g"."id" AND `+
			reach.Included+`))`, append([]any{bun.List(visible)}, reach.IncludedArgs...)...).
		OrderExpr(`"same" DESC, "ag"."last_line" ASC, "g"."occurrence_identity" ASC`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the code findings code finding %d may be one flaw with: %w", codeFindingID, err)
	}
	out := make([]Kin, 0, len(rows))
	for _, r := range rows {
		out = append(out, Kin{Occurrence: r.Occurrence, Rule: r.Rule, Path: r.Path, Line: r.Line, Same: r.Same == 1})
	}
	return out, nil
}

// Member is a code finding one decision about another code finding also answers.
type Member struct {
	VulnerabilityID int64             `bun:"vulnerability_id"`
	Occurrence      string            `bun:"occurrence_identity"`
	Visibility      access.Visibility `bun:"visibility"`
}

// Unanswered is the code findings on a code finding's build that are the same flaw as it and
// that nothing answers yet, where the subject may read them: open, under no
// live decision, waiting or not, covered by no suppression rule, not recorded as a flaw, and
// seen in a release still in support. A code finding already answered keeps its own
// answer, and a code finding past its end of life is kept as it stands.
func Unanswered(ctx context.Context, db bun.IDB, subject access.Subject, productID, codeFindingID int64) ([]Member, error) {
	visible, err := finding.CodeFindingVisible(subject, productID)
	if err != nil {
		return nil, err
	}
	ended, err := catalog.NewStore(db).BranchesAndTagsPastEndOfLife(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	// The code finding asked about is under "g" and each of its kin under "f", so
	// that the decision and the rule are asked of the kin. Which code findings are one
	// flaw does not depend on which of the two is asked about.
	var out []Member
	product := inProduct(productID)
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "finding" AS "g" ON "g"."id" = ?`, codeFindingID).
		Join(`JOIN "analysis_result" AS "ag" ON "ag"."finding_id" = "g"."id"`).
		ColumnExpr(`"f"."vulnerability_id", "f"."occurrence_identity", "f"."visibility"`).
		Where(nearby(groupLines)).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(`NOT EXISTS (SELECT 1 FROM "decision_occurrence" AS "dc"
			WHERE "dc"."product_id" = ? AND "dc"."live_key" IS NOT NULL AND `+finding.DecisionOccurrenceFiledAt("dc", "f")+`)`,
			productID).
		Where(`NOT `+ruledIn(product), product.times(1)...).
		Where(`NOT `+recordedAsFlawIn(product), product.times(1)...).
		Apply(func(q *bun.SelectQuery) *bun.SelectQuery {
			if len(ended) == 0 {
				return q
			}
			// The rule finding.CodeFindingEnded applies to one code finding: seen in at
			// least one release that is not past its end of life.
			kinds, kindArgs := kind.CodeFindings.Where(`"fs"."kind"`)
			args := append([]any{productID}, kindArgs...)
			args = append(args, bun.List(ended))
			return q.Where(`EXISTS (SELECT 1 FROM "finding" AS "fs"
				JOIN "build" AS "ts" ON "ts"."id" = "fs"."build_id"
				JOIN "branch_or_tag" AS "ss" ON "ss"."id" = "ts"."branch_or_tag_id"
				WHERE "ss"."product_id" = ? AND "fs"."occurrence_identity" = "f"."occurrence_identity"
				  AND `+kinds+` AND "ts"."branch_or_tag_id" NOT IN (?))`, args...)
		}).
		OrderExpr(`"f"."occurrence_identity" ASC`).
		Scan(ctx, &out); err != nil {
		return nil, fmt.Errorf("read the code findings one decision about code finding %d answers: %w", codeFindingID, err)
	}
	return out, nil
}
