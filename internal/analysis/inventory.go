// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
)

// inventory is the read inventory a run is applied against: the scan, and
// the component that is the build.
type inventory struct {
	scanID int64
	root   int64
}

// inventoryOf is the build's newest inventory that has been read, or nil
// where none has. A result is placed on a component of the build, so a run
// waits for the build to have components.
func inventoryOf(ctx context.Context, db bun.IDB, buildID int64) (*inventory, error) {
	var scan struct {
		ID int64 `bun:"id"`
	}
	err := db.NewSelect().
		TableExpr(`"scan" AS "sc"`).
		ColumnExpr(`"sc"."id"`).
		Where(`"sc"."build_id" = ?`, buildID).
		Where(`"sc"."components" IS NOT NULL`).
		OrderExpr(`"sc"."built_at" DESC, "sc"."id" DESC`).
		Limit(1).
		Scan(ctx, &scan)
	if database.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the build's inventory: %w", err)
	}
	var root struct {
		ID int64 `bun:"component_id"`
	}
	err = db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."component_id"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`"n"."is_root" = ?`, true).
		OrderExpr(`"n"."id" ASC`).
		Limit(1).
		Scan(ctx, &root)
	if database.IsNoRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read what the build is: %w", err)
	}
	return &inventory{scanID: scan.ID, root: root.ID}, nil
}

// componentsOf is, for each repository a result is in, the component of the
// build the inventory says was built from it: the first whose package
// identifier or stated repository names it, and otherwise the first whose
// platform enumeration names the repository's owner and name. A repository
// the inventory names no component for is absent, and its results are
// placed on the build.
func componentsOf(ctx context.Context, db bun.IDB, buildID int64, fresh []Keyed) (map[string]int64, error) {
	wanted := map[string]bool{}
	for _, k := range fresh {
		if k.Remote != "" {
			wanted[k.Remote] = true
		}
	}
	out := map[string]int64{}
	if len(wanted) == 0 {
		return out, nil
	}
	var nodes []struct {
		ComponentID int64  `bun:"component_id"`
		Purl        string `bun:"purl"`
		Repository  string `bun:"repository"`
		CPE         string `bun:"cpe"`
	}
	if err := db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		ColumnExpr(`"n"."component_id", "n"."purl", "n"."repository", "n"."cpe"`).
		Where(`"n"."build_id" = ?`, buildID).
		Where(`"n"."closed_scan_id" IS NULL`).
		Where(`("n"."purl" IS NOT NULL OR "n"."repository" IS NOT NULL OR "n"."cpe" IS NOT NULL)`).
		OrderExpr(`"n"."id" ASC`).
		Scan(ctx, &nodes); err != nil {
		return nil, fmt.Errorf("read the build's components: %w", err)
	}
	for _, n := range nodes {
		remote := remoteOf(n.Purl, n.Repository)
		if !wanted[remote] {
			continue
		}
		if _, ok := out[remote]; !ok {
			out[remote] = n.ComponentID
		}
	}
	// A platform enumeration is weaker than an identifier naming the
	// repository, so it places only a repository nothing else named.
	named := map[string]int64{}
	for _, n := range nodes {
		if key := cpeRepository(n.CPE); key != "" {
			if _, ok := named[key]; !ok {
				named[key] = n.ComponentID
			}
		}
	}
	for remote := range wanted {
		if _, ok := out[remote]; ok {
			continue
		}
		if id, ok := named[ownerAndName(remote)]; ok {
			out[remote] = id
		}
	}
	return out, nil
}

// cpeRepository is the owner and name a platform enumeration's vendor and
// product would be as a repository, folded as ownerAndName folds them, or
// empty where it names neither.
func cpeRepository(cpe string) string {
	vendor, product, ok := cverecord.CPEProduct(cpe)
	if !ok {
		return ""
	}
	return foldedName(vendor) + "/" + foldedName(product)
}

// ownerAndName is the last two segments of a normalized repository address,
// its owner and its name, folded so that a hyphen and an underscore compare
// alike: the enumeration's dictionary writes the one where a repository
// writes the other. Empty where the address has no owner.
func ownerAndName(remote string) string {
	segments := strings.Split(remote, "/")
	if len(segments) < 3 {
		return ""
	}
	return foldedName(segments[len(segments)-2]) + "/" + foldedName(segments[len(segments)-1])
}

// foldedName is a name in lower case with every underscore written as a
// hyphen.
func foldedName(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "-")
}

// hosts is the package identifier types that name a repository on a hosting
// service, and the host each names.
var hosts = map[string]string{
	"github":    "github.com",
	"gitlab":    "gitlab.com",
	"bitbucket": "bitbucket.org",
}

// remoteOf is the repository a component is built from, normalized: the one
// its package identifier names, and otherwise the version-control reference
// the inventory states beside it.
func remoteOf(purl, repository string) string {
	if remote := remoteOfPurl(purl); remote != "" {
		return remote
	}
	return sourcelink.Normalize(repository)
}

// remoteOfPurl is the repository a package identifier says the package is
// built from, normalized: the hosting service's repository for a type that
// names one, and the version-control address a qualifier states otherwise.
func remoteOfPurl(purl string) string {
	parts := graph.PartsOfPurl(purl)
	if host, ok := hosts[parts.Type]; ok && parts.Namespace != "" {
		return sourcelink.Normalize(host + "/" + parts.Namespace + "/" + parts.Name)
	}
	_, qualifiers, _ := strings.Cut(strings.SplitN(purl, "#", 2)[0], "?")
	for _, pair := range strings.Split(qualifiers, "&") {
		key, value, found := strings.Cut(pair, "=")
		if found && strings.EqualFold(key, "vcs_url") {
			if decoded, err := url.QueryUnescape(value); err == nil {
				return sourcelink.Normalize(decoded)
			}
		}
	}
	return ""
}
