// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A container image is identified by its name. The version a build states for
// one is a tag, a build stamp or a digest, and a product that rebuilds its
// images in CI states a new one every build whether or not anything inside
// moved. Identified by version, every image would be a new component every
// night, and every finding beneath it would close and open again as a new row.
//
// What each build states for an image is kept beside its node rather than in
// its identity: one row per stated version, open across the scans that stated
// it, the way a node and an edge are.

// imageTypes are the package identifier types that name a container image.
var imageTypes = map[string]bool{"oci": true, "docker": true}

// IsImage reports whether a described component is a container image.
//
// The package identifier decides where there is one, because identity is
// derived from it: an identifier of type oci or docker is an image, and an
// identifier of any other type is not, whatever else the document says. Where
// there is no identifier, the format's own word decides.
func (d Described) IsImage() bool {
	if strings.TrimSpace(d.Purl) != "" {
		return imageTypes[PartsOfPurl(d.Purl).Type]
	}
	return d.Container
}

// AsImage is how an image is stored: everything the build said about it except
// the version, which is cut from the package identifier and from the
// component alike.
func (d Described) AsImage() Described {
	d.Version = ""
	d.Purl = withoutVersion(d.Purl)
	return d
}

// withoutVersion cuts the version from a package identifier and keeps the
// rest as it was written: qualifiers and subpath included.
//
// The version follows the last "@" in the part before the qualifiers that has
// something other than a slash before it, which is the rule PackageOf reads it
// by.
func withoutVersion(purl string) string {
	purl = strings.TrimSpace(purl)
	end := len(purl)
	if cut := strings.IndexAny(purl, "?#"); cut >= 0 {
		end = cut
	}
	at := strings.LastIndex(purl[:end], "@")
	if at <= 0 || purl[at-1] == '/' {
		return purl
	}
	return purl[:at] + purl[end:]
}

// imagesByName is the stored form of every image the snapshot's components
// state once, keyed by what the document stated.
//
// A name a document states at more than one version keeps each of those as a
// component of its own, identified by its version: one component is one node
// in a build, and two images of one name side by side are two things the
// build ships. apko describes every layer of an image as an image of one name.
func imagesByName(components []Described) map[string]Described {
	held := map[string][]Described{}
	for _, d := range components {
		if !d.IsImage() {
			continue
		}
		stored := d.AsImage()
		held[stored.Identity()] = append(held[stored.Identity()], d)
	}
	out := map[string]Described{}
	for _, stated := range held {
		if len(stated) == 1 {
			out[stated[0].Identity()] = stated[0].AsImage()
		}
	}
	return out
}

// ImageVersion is the version one build stated for an image, across the scans
// that stated it.
type ImageVersion struct {
	bun.BaseModel `bun:"table:image_version,alias:iv"`

	ID     int64 `bun:"id,pk,autoincrement"`
	NodeID int64 `bun:"node_id,notnull"`
	// Version and Purl are what the build stated, as it stated them: the
	// format's version, empty where it gave none, and the package identifier
	// whole, version and qualifiers included.
	Version      string `bun:"version,notnull"`
	Purl         string `bun:"purl,nullzero"`
	OpenedScanID int64  `bun:"opened_scan_id,notnull"`
	ClosedScanID *int64 `bun:"closed_scan_id"`
}

// statedImage is what one scan stated for an image it identifies by name.
type statedImage struct {
	version, purl string
}

// reconcileImageVersions brings the open version rows of a build's images in
// line with what a scan stated for them, and reports how many it opened and
// closed.
//
// A row is open while the build states that version and identifier. A scan
// stating another closes it and opens one for what it stated; a scan in which
// the image is gone, or stated at more than one version, closes it. An image
// rebuilt at the same version writes nothing.
func reconcileImageVersions(ctx context.Context, tx bun.IDB, targetID, scanID int64,
	stated map[int64]statedImage) (int, int, error) {

	var open []ImageVersion
	if err := tx.NewSelect().Model(&open).
		Join(`JOIN "graph_node" AS "n" ON n.id = iv.node_id`).
		Where("n.target_id = ?", targetID).
		Where("iv.closed_scan_id IS NULL").
		Scan(ctx); err != nil {
		return 0, 0, fmt.Errorf("read the versions the build states for its images: %w", err)
	}
	have := map[int64]bool{}
	var gone []int64
	for _, row := range open {
		says, still := stated[row.NodeID]
		if still && says.version == row.Version && says.purl == row.Purl {
			have[row.NodeID] = true
			continue
		}
		gone = append(gone, row.ID)
	}
	var missing []ImageVersion
	for nodeID, says := range stated {
		if have[nodeID] {
			continue
		}
		missing = append(missing, ImageVersion{
			NodeID: nodeID, Version: says.version, Purl: says.purl, OpenedScanID: scanID,
		})
	}
	if len(gone) > 0 {
		err := database.IDsInBatches(ctx, gone, func(ctx context.Context, batch []int64) error {
			_, err := tx.NewUpdate().Model((*ImageVersion)(nil)).
				Set("closed_scan_id = ?", scanID).
				Where("id IN (?)", bun.List(batch)).Exec(ctx)
			return err
		})
		if err != nil {
			return 0, 0, fmt.Errorf("close %d image versions: %w", len(gone), err)
		}
	}
	if len(missing) > 0 {
		if err := database.InBatches(ctx, tx, missing); err != nil {
			return 0, 0, fmt.Errorf("open %d image versions: %w", len(missing), err)
		}
	}
	return len(missing), len(gone), nil
}

// StatedImages is what a build currently states for each image it holds by
// name, by component: the version and the identifier whole.
//
// A claim or a statement naming an image at a version is about the image the
// build states at that version, and the component row carries no version to
// compare it with.
func StatedImages(ctx context.Context, db bun.IDB, targetID int64) (map[int64]ImageVersion, error) {
	var rows []struct {
		ComponentID int64  `bun:"component_id"`
		Version     string `bun:"version"`
		Purl        string `bun:"purl"`
	}
	if err := db.NewSelect().
		TableExpr(`"image_version" AS "iv"`).
		Join(`JOIN "graph_node" AS "n" ON n.id = iv.node_id`).
		ColumnExpr(`n.component_id AS "component_id"`).
		ColumnExpr(`iv.version AS "version"`).
		ColumnExpr(`COALESCE(iv.purl, '') AS "purl"`).
		Where("n.target_id = ?", targetID).
		Where("n.closed_scan_id IS NULL").
		Where("iv.closed_scan_id IS NULL").
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read the versions the build states for its images: %w", err)
	}
	out := make(map[int64]ImageVersion, len(rows))
	for _, row := range rows {
		out[row.ComponentID] = ImageVersion{Version: row.Version, Purl: row.Purl}
	}
	return out, nil
}

// Stated is one version a build stated for an image, and the builds it was
// stated across: from the build time of the scan that first stated it until
// the build time of the scan that stated something else, absent while it is
// still what the build states.
type Stated struct {
	Version string
	Purl    string
	From    time.Time
	Until   *time.Time
}

// TargetComponent is one component in one build.
type TargetComponent struct {
	TargetID, ComponentID int64
}

// StatedVersions is every version these builds stated for these images,
// newest first, by build and component. A component no build holds by name has
// none.
func StatedVersions(ctx context.Context, db bun.IDB, targets, components []int64) (
	map[TargetComponent][]Stated, error) {

	out := map[TargetComponent][]Stated{}
	if len(targets) == 0 || len(components) == 0 {
		return out, nil
	}
	type statedRow struct {
		TargetID    int64      `bun:"target_id"`
		ComponentID int64      `bun:"component_id"`
		Version     string     `bun:"version"`
		Purl        string     `bun:"purl"`
		From        time.Time  `bun:"from_at"`
		Until       *time.Time `bun:"until_at"`
	}
	var rows []statedRow
	err := database.IDsInBatches(ctx, components, func(ctx context.Context, batch []int64) error {
		var some []statedRow
		if err := db.NewSelect().
			TableExpr(`"image_version" AS "iv"`).
			Join(`JOIN "graph_node" AS "n" ON n.id = iv.node_id`).
			Join(`JOIN "scan" AS "so" ON so.id = iv.opened_scan_id`).
			Join(`LEFT JOIN "scan" AS "sc" ON sc.id = iv.closed_scan_id`).
			ColumnExpr(`n.target_id AS "target_id"`).
			ColumnExpr(`n.component_id AS "component_id"`).
			ColumnExpr(`iv.version AS "version"`).
			ColumnExpr(`COALESCE(iv.purl, '') AS "purl"`).
			ColumnExpr(`so.built_at AS "from_at"`).
			ColumnExpr(`sc.built_at AS "until_at"`).
			Where("n.target_id IN (?)", bun.List(targets)).
			Where("n.component_id IN (?)", bun.List(batch)).
			OrderExpr("iv.opened_scan_id DESC, iv.id DESC").
			Scan(ctx, &some); err != nil {
			return err
		}
		rows = append(rows, some...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read the versions builds stated for their images: %w", err)
	}
	for _, row := range rows {
		key := TargetComponent{row.TargetID, row.ComponentID}
		out[key] = append(out[key], Stated{Version: row.Version, Purl: row.Purl, From: row.From, Until: row.Until})
	}
	return out, nil
}
