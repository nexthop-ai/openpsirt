// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"sort"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// BuildClaim is what the build says about a finding: one of its claims covering
// a place the finding sits at, with the words it was made in.
//
// Shown on the finding the way a publisher's statement is, because the words
// are the reason the finding is marked, closed, or still work. A claim that the
// flaw applies carries the workaround the build published.
type BuildClaim struct {
	ID            int64
	Status        string
	Justification string
	Statement     string
	// Subject and Version are what the claim names, and Within the product
	// it names the subject as shipping inside, with its version.
	Subject       string
	Version       string
	Within        string
	WithinVersion string
	// Pedigree says the claim arrived attached to the component: a patch
	// declaring what it fixes.
	Pedigree bool
	// Publisher and Document say whose document a claim taken from a
	// published statement came from. Empty for a claim sent with the
	// inventory, which is the build's producer speaking.
	Publisher string
	Document  string
}

// claimedOn reads the build's claims the given findings name, one entry per
// claim, the claims that suppress first.
func claimedOn(ctx context.Context, db bun.IDB, ids []int64) ([]BuildClaim, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var rows []struct {
		ID            int64  `bun:"id"`
		Status        string `bun:"status"`
		Justification string `bun:"justification"`
		Statement     string `bun:"statement"`
		Origin        string `bun:"origin"`
		SubjectPurl   string `bun:"subject_purl"`
		SubjectName   string `bun:"subject_name"`
		Version       string `bun:"subject_version"`
		WithinPurl    string `bun:"within_purl"`
		WithinName    string `bun:"within_name"`
		WithinVersion string `bun:"within_version"`
		Publisher     string `bun:"publisher"`
		Document      string `bun:"document"`
	}
	where, args := database.InAnyOf("sup.id", ids)
	if err := db.NewSelect().
		TableExpr(`"suppression" AS "sup"`).
		Join(`LEFT JOIN "vex_statement" AS "ss" ON ss.id = sup.stated_by`).
		ColumnExpr(`sup.id AS "id"`).
		ColumnExpr(`sup.status AS "status"`).
		ColumnExpr(`COALESCE(sup.justification, '') AS "justification"`).
		ColumnExpr(`COALESCE(sup.statement, '') AS "statement"`).
		ColumnExpr(`sup.origin AS "origin"`).
		ColumnExpr(`COALESCE(sup.subject_purl, '') AS "subject_purl"`).
		ColumnExpr(`COALESCE(sup.subject_name, '') AS "subject_name"`).
		ColumnExpr(`COALESCE(sup.subject_version, '') AS "subject_version"`).
		ColumnExpr(`COALESCE(sup.within_purl, '') AS "within_purl"`).
		ColumnExpr(`COALESCE(sup.within_name, '') AS "within_name"`).
		ColumnExpr(`COALESCE(sup.within_version, '') AS "within_version"`).
		ColumnExpr(`COALESCE(ss.publisher, '') AS "publisher"`).
		ColumnExpr(`COALESCE(ss.document, '') AS "document"`).
		Where(where, args...).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what the build says about this: %w", err)
	}
	out := make([]BuildClaim, 0, len(rows))
	for _, row := range rows {
		subject := sbom.Target{Purl: row.SubjectPurl, Name: row.SubjectName, Version: row.Version}
		claim := BuildClaim{
			ID: row.ID, Status: row.Status, Justification: row.Justification,
			Statement: row.Statement,
			Subject:   subject.ComponentNamed(), Version: subject.VersionNamed(),
			Pedigree:  row.Origin == string(sbom.FromPedigree),
			Publisher: row.Publisher, Document: row.Document,
		}
		if row.WithinPurl != "" || row.WithinName != "" {
			within := sbom.Target{Purl: row.WithinPurl, Name: row.WithinName, Version: row.WithinVersion}
			claim.Within, claim.WithinVersion = within.ComponentNamed(), within.VersionNamed()
		}
		out = append(out, claim)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := sbom.Status(out[i].Status).Suppresses(), sbom.Status(out[j].Status).Suppresses()
		if a != b {
			return a
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}
