// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"strconv"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
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
// under another rule, of a weakness family the other's rule shares, with its
// last place in the same file within lines of the other's. Two results of one
// rule are never one flaw: two flaws of a class on adjacent lines are told
// apart only by the tool reporting them as two.
func nearby(lines int) string {
	n := strconv.Itoa(lines)
	return `"g"."target_id" = "f"."target_id" AND "g"."closed_at" IS NULL
	  AND "g"."kind" = '` + string(kind.Analysis) + `'
	  AND "g"."vulnerability_id" <> "f"."vulnerability_id"
	  AND "ag"."last_path" = "ar"."last_path"
	  AND "ag"."last_line" BETWEEN "ar"."last_line" - ` + n + ` AND "ar"."last_line" + ` + n + `
	  AND EXISTS (SELECT 1 FROM "rule_family" AS "fa"
		JOIN "rule_family" AS "fb" ON "fb"."family" = "fa"."family"
		WHERE "fa"."vulnerability_id" = "f"."vulnerability_id" AND "fb"."vulnerability_id" = "g"."vulnerability_id")`
}

// corroborated is whether another analyzer's lead on the build of the finding
// under "f", whose result is under "ar", is the same flaw. It is worked out
// over every lead, whoever reads it, because where a lead stands does not
// depend on who is looking.
var corroborated = `EXISTS (SELECT 1 FROM "finding" AS "g"
	JOIN "analysis_result" AS "ag" ON "ag"."finding_id" = "g"."id"
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
	visible, err := access.Readable(subject, productID)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Place string `bun:"place_identity"`
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
		ColumnExpr(`"g"."place_identity", "vu"."identifier" AS "rule", "ag"."last_path", "ag"."last_line"`).
		ColumnExpr(`CASE WHEN "ag"."last_line" BETWEEN "ar"."last_line" - ? AND "ar"."last_line" + ? `+
			`THEN 1 ELSE 0 END AS "same"`, groupLines, groupLines).
		Where(`"f"."id" = ?`, leadID).
		Where(nearby(duplicateLines)).
		Where(`"g"."visibility" IN (?)`, bun.List(visible)).
		OrderExpr(`"same" DESC, "ag"."last_line" ASC, "g"."place_identity" ASC`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the leads lead %d may be one flaw with: %w", leadID, err)
	}
	out := make([]Kin, 0, len(rows))
	for _, r := range rows {
		out = append(out, Kin{Place: r.Place, Rule: r.Rule, Path: r.Path, Line: r.Line, Same: r.Same == 1})
	}
	return out, nil
}
