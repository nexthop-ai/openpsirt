// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// Reading findings back, and the naming layer every other read here shares.
//
// The whole-target read, which product a target belongs to and what a subject
// may read of it, and the lookups that turn identifiers into names. The
// narrowing is in narrow.go, the page in groups.go, and what is open at one
// component in component.go.

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// productOf reads which product a build belongs to.
func productOf(ctx context.Context, db bun.IDB, targetID int64) (int64, error) {
	return catalog.NewStore(db).ProductOf(ctx, targetID)
}

// readableIn is the product a build belongs to and which visibilities this
// subject may read of its findings, refused where that is none.
//
// Every read of one build's findings starts here, so a subject who may read
// nothing in the product is refused by all of them alike rather than answered
// empty by some. Where the read is about one issue a collaborator may have
// been brought into, the caller asks access.ReadableOn instead.
func readableIn(ctx context.Context, db bun.IDB, subject access.Subject,
	targetID int64) (int64, []access.Visibility, error) {

	productID, err := productOf(ctx, db, targetID)
	if err != nil {
		return 0, nil, err
	}
	visible, err := access.Readable(subject, productID)
	if err != nil {
		return 0, nil, err
	}
	return productID, visible, nil
}

// issuesNamed reads what these issues are called and how bad they were
// published to be, as this subject may be told it.
//
// The published rating only. What a product says instead belongs to the
// product, so it is read alongside by whoever knows which product is being
// asked about and put on the copy the row shows (RatedIn). A description a
// flaw recorded out of the subject's reach wrote is left out.
func issuesNamed(ctx context.Context, db bun.IDB, subject access.Subject,
	ids []int64) (map[int64]Vulnerability, error) {
	held := map[int64]Vulnerability{}
	if len(ids) == 0 {
		return held, nil
	}
	var issues []Vulnerability
	if err := db.NewSelect().Model(&issues).
		// The description too, for the one line the row shows of it. One
		// lookup for the page either way, and the row is already being read
		// for the identifier beside it.
		Column("id", "identifier", "severity", "description").
		Where(`"id" IN (?)`, bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these issues are: %w", err)
	}
	withheld, err := RecordedOutOfReach(ctx, db, subject, ids)
	if err != nil {
		return nil, err
	}
	for _, issue := range issues {
		if withheld[issue.ID] {
			issue.WithholdRecorded()
		}
		held[issue.ID] = issue
	}
	return held, nil
}

// componentsNamed reads what these components are, including the upstream they
// were cut from where one is known.
func componentsNamed(ctx context.Context, db bun.IDB, ids []int64) (map[int64]graph.Component, error) {
	held := map[int64]graph.Component{}
	if len(ids) == 0 {
		return held, nil
	}
	var components []graph.Component
	if err := db.NewSelect().Model(&components).
		Column("id", "purl", "name", "version", "upstream_name", "upstream_version").
		Where(`"id" IN (?)`, bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these components are: %w", err)
	}
	for _, component := range components {
		held[component.ID] = component
	}
	return held, nil
}
