// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// publishedForBuild keeps a build's claims taken from published documents in
// step with the statements that stand.
//
// A statement whose product is the build's root speaks for the build's
// producer, whichever way it arrived. One sent with the inventory is recorded
// as the build's claim when the scan is read; one in a document uploaded on its
// own is recorded here, as a claim of the build taken from that statement, so
// that the run applies both alike. A statement set aside, or a root at another
// version, closes the claim taken from it.
//
// The root is named by the package identifier the inventory gave it, at the
// version the statement names. A statement naming no version is about every
// release and is left as evidence, as a supplier's is.
func publishedForBuild(ctx context.Context, tx bun.IDB, productID, targetID int64) error {
	var build struct {
		ScanID int64  `bun:"scan_id"`
		Root   string `bun:"root_identifier"`
	}
	err := tx.NewSelect().
		TableExpr(`"target" AS "t"`).
		Join(`JOIN "scan" AS "sc" ON sc.id = t.last_scan_id`).
		ColumnExpr(`sc.id AS "scan_id"`).
		ColumnExpr(`COALESCE(sc.root_identifier, '') AS "root_identifier"`).
		Where("t.id = ?", targetID).
		Scan(ctx, &build)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read the build's root: %w", err)
	}

	wanted := map[string]Claim{}
	rootBase, rootVersion := graph.PackageOf(build.Root)
	if rootBase != "" && rootVersion != "" {
		var said []Statement
		if err := tx.NewSelect().Model(&said).
			Where("ss.product_id = ?", productID).
			Where("ss.superseded_at IS NULL").
			Where("ss.placement = ?", PlacedInside).
			Where("ss.within = ?", folded(nameOf(build.Root))).
			Order("ss.id").
			Scan(ctx); err != nil {
			return fmt.Errorf("read what is published about the build's root: %w", err)
		}
		for _, one := range said {
			base, version := graph.PackageOf(one.WithinPurl)
			if version == "" {
				version = one.WithinAbout
			}
			if base != rootBase || version != rootVersion {
				continue
			}
			id := one.ID
			row := Claim{
				TargetID: targetID, Vulnerability: one.Vulnerability,
				Status: one.Status, Justification: one.Justification,
				Statement: one.Statement, Origin: Published,
				SubjectPurl: one.Purl, SubjectName: one.Component,
				SubjectFolded:  one.Component,
				SubjectVersion: statedBeside(sbom.Target{Purl: one.Purl, Version: one.About}),
				StatedBy:       &id,
				OpenedScanID:   build.ScanID,
			}
			row.Identity = claimIdentity(row)
			wanted[row.Identity] = row
		}
	}

	var open []Claim
	if err := tx.NewSelect().Model(&open).
		Where("target_id = ?", targetID).
		Where("closed_scan_id IS NULL").
		Where("origin = ?", Published).
		Scan(ctx); err != nil {
		return fmt.Errorf("read the build's claims taken from published statements: %w", err)
	}
	held := make(map[string]bool, len(open))
	var closing []int64
	for _, row := range open {
		held[row.Identity] = true
		if _, still := wanted[row.Identity]; !still {
			closing = append(closing, row.ID)
		}
	}
	var opening []Claim
	for identity, row := range wanted {
		if !held[identity] {
			opening = append(opening, row)
		}
	}
	// Written in the order the statements were, so the claims are read back in
	// it and the one a finding names does not move between runs.
	slices.SortFunc(opening, func(a, b Claim) int { return cmp.Compare(*a.StatedBy, *b.StatedBy) })
	if len(opening) > 0 {
		if err := database.InBatches(ctx, tx, opening); err != nil {
			return fmt.Errorf("record %d claims taken from published statements: %w", len(opening), err)
		}
	}
	if len(closing) > 0 {
		err := database.IDsInBatches(ctx, closing, func(ctx context.Context, batch []int64) error {
			_, err := tx.NewUpdate().Model((*Claim)(nil)).
				Set("closed_scan_id = ?", build.ScanID).
				Where("id IN (?)", bun.List(batch)).Exec(ctx)
			return err
		})
		if err != nil {
			return fmt.Errorf("close %d claims taken from published statements: %w", len(closing), err)
		}
	}
	return nil
}

// nameOf is the name a package identifier gives its package, which is what a
// statement's product is stored under.
func nameOf(purl string) string {
	return sbom.Target{Purl: purl}.ComponentNamed()
}
