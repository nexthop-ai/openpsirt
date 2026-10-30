// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
)

// OwnCase is one case somebody was brought into: one issue in one product.
type OwnCase struct {
	Product     string    `bun:"product"`
	ProductName string    `bun:"product_name"`
	Issue       string    `bun:"issue"`
	AddedAt     time.Time `bun:"added_at"`
}

// OwnCodeFinding is one code finding recorded as a flaw somebody was granted,
// named by the build it was last sighted in.
type OwnCodeFinding struct {
	Product         string    `bun:"product"`
	ProductName     string    `bun:"product_name"`
	BranchOrTag     string    `bun:"branch_or_tag"`
	BranchOrTagName string    `bun:"branch_or_tag_name"`
	Variant         string    `bun:"variant"`
	VariantName     string    `bun:"variant_name"`
	Occurrence      string    `bun:"occurrence"`
	Rule            string    `bun:"rule"`
	Path            string    `bun:"path"`
	Flaw            string    `bun:"flaw"`
	AddedAt         time.Time `bun:"added_at"`
}

// OwnCases is the cases and code findings the subject was granted one at a
// time, newest grant first: the grants that stand, and of the code findings,
// only those whose flaw nobody disclosed, since disclosure ends that grant.
// Anybody but a person holds none.
func (s *Store) OwnCases(ctx context.Context, subject access.Subject) ([]OwnCase, []OwnCodeFinding, error) {
	if subject.Kind != access.Person {
		return nil, nil, nil
	}
	var cases []OwnCase
	if err := s.db.NewSelect().
		TableExpr(`"case_collaborator" AS "cc"`).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "cc"."vulnerability_id"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "cc"."product_id"`).
		ColumnExpr(`"p"."name" AS "product"`).
		ColumnExpr(catalog.ShownExpr("p")+` AS "product_name"`).
		ColumnExpr(`"v"."identifier" AS "issue"`).
		ColumnExpr(`"cc"."added_at" AS "added_at"`).
		Where(`"cc"."person_id" = ?`, subject.ID).
		Where(`"cc"."live_person_id" IS NOT NULL`).
		OrderExpr(`"cc"."added_at" DESC, "cc"."id" DESC`).
		Scan(ctx, &cases); err != nil {
		return nil, nil, fmt.Errorf("read the cases you were brought into: %w", err)
	}
	// The newest sighting of each code finding names the build it opens in:
	// a code finding is one occurrence across every build it was seen in, and
	// its page is reached through one of them.
	var codeFindings []OwnCodeFinding
	if err := s.db.NewSelect().
		TableExpr(`"code_finding_collaborator" AS "lc"`).
		Join(`JOIN "code_finding_flaw" AS "lh" ON "lh"."product_id" = "lc"."product_id"
			AND "lh"."occurrence_identity" = "lc"."occurrence_identity"`).
		Join(`JOIN "vulnerability" AS "fv" ON "fv"."id" = "lh"."vulnerability_id"`).
		Join(`JOIN "finding" AS "f" ON "f"."id" = (SELECT MAX("sf"."id") FROM "finding" AS "sf"
			JOIN "build" AS "sb" ON "sb"."id" = "sf"."build_id"
			JOIN "branch_or_tag" AS "sst" ON "sst"."id" = "sb"."branch_or_tag_id"
			WHERE "sf"."occurrence_identity" = "lc"."occurrence_identity"
			  AND "sf"."kind" = ? AND "sst"."product_id" = "lc"."product_id")`, kind.Analysis).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "f"."vulnerability_id"`).
		Join(`JOIN "analysis_result" AS "ar" ON "ar"."finding_id" = "f"."id"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		Join(`JOIN "product" AS "p" ON "p"."id" = "lc"."product_id"`).
		Apply(catalog.BuildNames("p", "st", "va")).
		ColumnExpr(`"lc"."occurrence_identity" AS "occurrence"`).
		ColumnExpr(`"v"."identifier" AS "rule"`).
		ColumnExpr(`"ar"."path" AS "path"`).
		ColumnExpr(`"fv"."identifier" AS "flaw"`).
		ColumnExpr(`"lc"."added_at" AS "added_at"`).
		Where(`"lc"."person_id" = ?`, subject.ID).
		Where(`"lc"."live_person_id" IS NOT NULL`).
		Where(`"lh"."disclosed_at" IS NULL`).
		OrderExpr(`"lc"."added_at" DESC, "lc"."id" DESC`).
		Scan(ctx, &codeFindings); err != nil {
		return nil, nil, fmt.Errorf("read the code findings you were granted: %w", err)
	}
	return cases, codeFindings, nil
}
