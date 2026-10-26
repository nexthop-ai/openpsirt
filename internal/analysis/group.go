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

// The lines apart two leads' last places may be for the leads to be one flaw,
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
	  AND "g"."target_id" = "f"."target_id" AND "g"."closed_at" IS NULL
	  AND "g"."kind" = '` + string(kind.Analysis) + `'
	  AND "g"."vulnerability_id" <> "f"."vulnerability_id"
	  AND EXISTS (SELECT 1 FROM "rule_family" AS "fa"
		JOIN "rule_family" AS "fb" ON "fb"."family" = "fa"."family" AND "fb"."tool" <> "fa"."tool"
		WHERE "fa"."vulnerability_id" = "f"."vulnerability_id" AND "fb"."vulnerability_id" = "g"."vulnerability_id")`
}

// corroborated is whether another analyzer's lead on the build of the finding
// under "f", whose result is under "ar", is the same flaw. It is worked out
// over every lead, whoever reads it, because where a lead sorts does not
// depend on who is looking.
var corroborated = `EXISTS (SELECT 1 FROM "analysis_result" AS "ag"
	JOIN "finding" AS "g" ON "g"."id" = "ag"."finding_id"
	WHERE ` + nearby(groupLines) + `)`

// Kin is another lead on a lead's build that is the same flaw, or possibly
// is.
type Kin struct {
	Place string
	Rule  string
	Path  string
	Line  *int
	// Same is whether it is the same flaw rather than possibly so.
	Same bool
}

// KinOf is the leads on a lead's build that are the same flaw as it, or
// possibly are, where the subject may read them: same first, then by line.
func KinOf(ctx context.Context, db bun.IDB, subject access.Subject, productID, leadID int64) ([]Kin, error) {
	// A grant of one lead, or of one case, reads no other lead.
	if !subject.Sees(productID) {
		return []Kin{}, nil
	}
	visible, err := finding.LeadVisible(subject, productID)
	if err != nil {
		return nil, err
	}
	reach := finding.LeadReach(subject, productID)
	var rows []struct {
		Place string `bun:"occurrence_identity"`
		Rule  string `bun:"rule"`
		Path  string `bun:"last_path"`
		Line  *int   `bun:"last_line"`
		Same  int    `bun:"same"`
	}
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "finding" AS "g" ON "g"."target_id" = "f"."target_id"`).
		Join(`JOIN "analysis_result" AS "ag" ON "ag"."finding_id" = "g"."id"`).
		Join(`JOIN "vulnerability" AS "vu" ON "vu"."id" = "g"."vulnerability_id"`).
		ColumnExpr(`"g"."occurrence_identity", "vu"."identifier" AS "rule", "ag"."last_path", "ag"."last_line"`).
		ColumnExpr(`CASE WHEN "ag"."last_line" BETWEEN "ar"."last_line" - ? AND "ar"."last_line" + ? `+
			`THEN 1 ELSE 0 END AS "same"`, groupLines, groupLines).
		Where(`"f"."id" = ?`, leadID).
		Where(nearby(duplicateLines)).
		// A lead included in its flaw's case is read by the flaw's readers
		// beside the product's own visibilities, as the queue reads it.
		Where(`("g"."visibility" IN (?) OR EXISTS (SELECT 1 FROM "finding" AS "f" WHERE "f"."id" = "g"."id" AND `+
			reach.Included+`))`, append([]any{bun.List(visible)}, reach.IncludedArgs...)...).
		OrderExpr(`"same" DESC, "ag"."last_line" ASC, "g"."occurrence_identity" ASC`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the leads lead %d may be one flaw with: %w", leadID, err)
	}
	out := make([]Kin, 0, len(rows))
	for _, r := range rows {
		out = append(out, Kin{Place: r.Place, Rule: r.Rule, Path: r.Path, Line: r.Line, Same: r.Same == 1})
	}
	return out, nil
}

// Member is a lead one judgment about another lead also answers.
type Member struct {
	VulnerabilityID int64             `bun:"vulnerability_id"`
	Place           string            `bun:"occurrence_identity"`
	Visibility      access.Visibility `bun:"visibility"`
}

// Unanswered is the leads on a lead's build that are the same flaw as it and
// that nothing answers yet, where the subject may read them: open, under no
// live claim, waiting or not, covered by no standing rule, not handed off, and
// seen in a release still in support. A lead already answered keeps its own
// answer, and a lead past its end of life is kept as it stands.
func Unanswered(ctx context.Context, db bun.IDB, subject access.Subject, productID, leadID int64) ([]Member, error) {
	visible, err := finding.LeadVisible(subject, productID)
	if err != nil {
		return nil, err
	}
	ended, err := catalog.NewStore(db).StreamsPastEndOfLife(ctx, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	// The lead asked about is under "g" and each of its kin under "f", so
	// that the claim and the rule are asked of the kin. Which leads are one
	// flaw does not depend on which of the two is asked about.
	var out []Member
	if err := db.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "finding" AS "g" ON "g"."id" = ?`, leadID).
		Join(`JOIN "analysis_result" AS "ag" ON "ag"."finding_id" = "g"."id"`).
		ColumnExpr(`"f"."vulnerability_id", "f"."occurrence_identity", "f"."visibility"`).
		Where(nearby(groupLines)).
		Where(`"f"."closed_at" IS NULL`).
		Where(`"f"."visibility" IN (?)`, bun.List(visible)).
		Where(`NOT EXISTS (SELECT 1 FROM "decision_occurrence" AS "dc"
			WHERE "dc"."product_id" = ? AND "dc"."live_key" IS NOT NULL AND `+finding.DecisionFiledAt("dc", "f")+`)`,
			productID).
		Where(`NOT `+ruled, productID).
		Where(`NOT `+handedOff, productID).
		Apply(func(q *bun.SelectQuery) *bun.SelectQuery {
			if len(ended) == 0 {
				return q
			}
			// The rule finding.LeadEnded applies to one lead: seen in at
			// least one release that is not past its end of life.
			kinds, kindArgs := kind.Leads.Where(`"fs"."kind"`)
			args := append([]any{productID}, kindArgs...)
			args = append(args, bun.List(ended))
			return q.Where(`EXISTS (SELECT 1 FROM "finding" AS "fs"
				JOIN "target" AS "ts" ON "ts"."id" = "fs"."target_id"
				JOIN "stream" AS "ss" ON "ss"."id" = "ts"."stream_id"
				WHERE "ss"."product_id" = ? AND "fs"."occurrence_identity" = "f"."occurrence_identity"
				  AND `+kinds+` AND "ts"."stream_id" NOT IN (?))`, args...)
		}).
		OrderExpr(`"f"."occurrence_identity" ASC`).
		Scan(ctx, &out); err != nil {
		return nil, fmt.Errorf("read the leads one judgment about lead %d answers: %w", leadID, err)
	}
	return out, nil
}
