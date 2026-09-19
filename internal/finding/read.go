package finding

// Reading findings back, and the naming layer every other read here shares.
//
// The remainder, after the filter, the page and the component view moved to
// files of their own: the whole-target read, which product a target belongs
// to, and the two lookups that turn identifiers into names. The narrowing is
// in narrow.go, the page in groups.go, and what is open at one component in
// component.go.

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// Open returns the findings currently open against a target that this subject
// may read.
//
// The filtering happens here rather than in whatever asked. A check in a
// handler is a check somebody forgets the first time they add another handler,
// and the thing being forgotten is not a blank screen — it is somebody seeing
// an issue that has not been disclosed.
//
// The product the target belongs to is read here too, rather than accepted
// from the caller. A caller that could name the product could name a different
// one, and then the check would be answering a question nobody asked.
func (s *Store) Open(ctx context.Context, subject access.Subject, targetID int64) ([]Finding, error) {
	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	if !subject.Sees(productID) {
		// Not merely empty: a product somebody holds nothing on does not
		// exist as far as they are concerned, and an empty list is a
		// different statement from a refusal.
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return nil, access.Denied(fmt.Sprintf("read findings in product %d", productID))
	}

	var rows []Finding
	err = s.db.NewSelect().Model(&rows).
		Where("target_id = ?", targetID).
		Where("closed_at IS NULL").
		Where("visibility IN (?)", bun.List(visible)).
		Order("id").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read open findings: %w", err)
	}
	return rows, nil
}

// productOf reads which product a build belongs to.
func productOf(ctx context.Context, db bun.IDB, targetID int64) (int64, error) {
	return catalog.NewStore(db).ProductOf(ctx, targetID)
}

// issuesNamed reads what these issues are called and how bad they were
// published to be.
//
// The published rating only. What a product says instead belongs to the
// product, so it is read alongside by whoever knows which product is being
// asked about and put on the copy the row shows (RatedIn).
func issuesNamed(ctx context.Context, db bun.IDB, ids []int64) (map[int64]Vulnerability, error) {
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
		Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these issues are: %w", err)
	}
	for _, issue := range issues {
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
		Where("id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these components are: %w", err)
	}
	for _, component := range components {
		held[component.ID] = component
	}
	return held, nil
}
