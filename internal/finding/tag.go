// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// A word somebody put on a finding.
//
// People mark work regardless. With nowhere to put it they do it inside
// the reasoning text, where nothing can filter on it and an approver reads it
// as part of the argument. This is where that goes instead.
//
// No fixed vocabulary, because none has been earned. A tag that becomes
// universal is a signal that it should be promoted to a real concept — "waiting
// on vendor" is a state the tool would want to reason about rather than a
// string somebody typed — and inventing the vocabulary first is guessing at
// which states matter.

// Tag is one word on one issue in one component of one product.
type Tag struct {
	bun.BaseModel `bun:"table:finding_tag,alias:ft"`

	ID              int64 `bun:"id,pk,autoincrement"`
	ProductID       int64 `bun:"product_id,notnull"`
	VulnerabilityID int64 `bun:"vulnerability_id,notnull"`
	ComponentID     int64 `bun:"component_id,notnull"`
	// Tag is the matched form and Typed is the spelling somebody used,
	// which is what is shown back.
	Tag     string    `bun:"tag,notnull"`
	Typed   string    `bun:"typed,notnull"`
	AddedBy int64     `bun:"added_by,notnull"`
	AddedAt time.Time `bun:"added_at,notnull"`
}

// TagAs folds a tag the way every other name people type is folded.
func TagAs(tag string) string { return strings.ToLower(strings.TrimSpace(tag)) }

// TagIt puts a word on a finding.
//
// Marking work is triage, so it asks for the right that names it rather
// than for the right to read: a tag changes what a filtered list answers, and
// somebody who may only read a product should not be able to move work into or
// out of somebody else's saved filter.
//
// Tagging what is already tagged is not a failure — the state asked for is the
// state that holds — and the first spelling is kept, because a tag that
// re-spelled itself on every use would make the list of what exists unstable.
func (s *Store) TagIt(ctx context.Context, subject access.Subject, productID,
	vulnerabilityID, componentID int64, typed string) error {

	folded := TagAs(typed)
	if folded == "" {
		return fmt.Errorf("a tag has to say something")
	}
	if !subject.TriagesIn(productID) {
		return access.Denied(fmt.Sprintf("mark work in product %d", productID))
	}
	row := &Tag{
		ProductID: productID, VulnerabilityID: vulnerabilityID, ComponentID: componentID,
		Tag: folded, Typed: strings.TrimSpace(typed),
		AddedBy: subject.ID, AddedAt: s.now().UTC().Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(row).Exec(ctx); err != nil {
		if on, err := s.tagged(ctx, productID, vulnerabilityID, componentID, folded); err == nil && on {
			return nil
		}
		return fmt.Errorf("mark it: %w", err)
	}
	return nil
}

// Untag takes a word off. Taking one off that is not there is not a failure.
func (s *Store) Untag(ctx context.Context, subject access.Subject, productID,
	vulnerabilityID, componentID int64, typed string) error {

	if !subject.TriagesIn(productID) {
		return access.Denied(fmt.Sprintf("mark work in product %d", productID))
	}
	if _, err := s.db.NewDelete().Model((*Tag)(nil)).
		Where("product_id = ?", productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("component_id = ?", componentID).
		Where("tag = ?", TagAs(typed)).Exec(ctx); err != nil {
		return fmt.Errorf("take the mark off: %w", err)
	}
	return nil
}

// TagsOn is what is on one finding, as they were typed.
func (s *Store) TagsOn(ctx context.Context, productID, vulnerabilityID,
	componentID int64) ([]string, error) {

	var rows []Tag
	if err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("component_id = ?", componentID).
		Order("tag").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what it is marked with: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Typed)
	}
	return out, nil
}

// TagsInUse is every tag used in a product, most-used first.
//
// A filter's own offer rather than a vocabulary: the list is what people have
// actually written, which is also the evidence for promoting one to a real
// concept.
func (s *Store) TagsInUse(ctx context.Context, subject access.Subject,
	productID int64) ([]string, error) {

	visible := access.Visible(subject, productID)
	if len(visible) == 0 {
		return nil, nil
	}
	var rows []struct {
		Typed string `bun:"typed"`
		Used  int    `bun:"used"`
	}
	// Narrowed to the findings the tag is actually on, because the tag row
	// carries no visibility of its own — it is keyed on the issue and the
	// component, and both of those name an undisclosed finding as readily as
	// a public one. Free text somebody typed while triaging an embargo says
	// what the embargo is about, so the words are as disclosing as the row.
	//
	// A word survives where any finding it marks is readable, which is the
	// same rule the list it filters answers by: offering a filter that
	// matches nothing the caller may see would be its own small oracle.
	const onSomethingReadable = `EXISTS (SELECT 1 FROM "finding" AS "f"
		JOIN "target" AS "tg" ON tg.id = f.target_id
		JOIN "stream" AS "st" ON st.id = tg.stream_id
		WHERE st.product_id = ft.product_id
		  AND f.vulnerability_id = ft.vulnerability_id
		  AND f.component_id = ft.component_id
		  AND f.visibility IN (?))`
	if err := s.db.NewSelect().Model((*Tag)(nil)).
		ColumnExpr(`MIN(ft.typed) AS "typed"`).
		ColumnExpr(`COUNT(*) AS "used"`).
		Where("ft.product_id = ?", productID).
		Where(onSomethingReadable, bun.List(visible)).
		GroupExpr("ft.tag").
		OrderExpr("used DESC, typed").
		Limit(100).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what is in use: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.Typed)
	}
	return out, nil
}

// tagged says whether one word is already on one finding.
func (s *Store) tagged(ctx context.Context, productID, vulnerabilityID,
	componentID int64, folded string) (bool, error) {

	on, err := s.db.NewSelect().Model((*Tag)(nil)).
		Column("ft.id").
		Where("ft.product_id = ?", productID).
		Where("ft.vulnerability_id = ?", vulnerabilityID).
		Where("ft.component_id = ?", componentID).
		Where("ft.tag = ?", folded).Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether it is marked: %w", err)
	}
	return on, nil
}

// markKey is one row of a list: an issue in a component.
type markKey struct{ Vulnerability, Component int64 }

// tagsFor reads the words on a page of rows, in one statement.
//
// Keyed on the pair the list groups by rather than on a place: a tag is put on
// one issue in one component, which is the row somebody is looking at.
func (s *Store) tagsFor(ctx context.Context, productID int64,
	rows []decorated) (map[markKey][]string, error) {

	out := map[markKey][]string{}
	if productID == 0 || len(rows) == 0 {
		return out, nil
	}
	issues := make([]int64, 0, len(rows))
	components := make([]int64, 0, len(rows))
	for _, row := range rows {
		issues = append(issues, row.VulnerabilityID)
		components = append(components, row.ComponentID)
	}
	var found []Tag
	if err := s.db.NewSelect().Model(&found).
		Where("product_id = ?", productID).
		// Two lists rather than the pairs: that admits a tag on one row's
		// issue at another row's component, and those are dropped by the key
		// below. What it buys is the index — the same trade the decision
		// counts on this page make.
		Where("vulnerability_id IN (?)", bun.List(issues)).
		Where("component_id IN (?)", bun.List(components)).
		Order("tag").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these are marked with: %w", err)
	}
	wanted := make(map[markKey]bool, len(rows))
	for _, row := range rows {
		wanted[markKey{row.VulnerabilityID, row.ComponentID}] = true
	}
	for _, row := range found {
		key := markKey{row.VulnerabilityID, row.ComponentID}
		if wanted[key] {
			out[key] = append(out[key], row.Typed)
		}
	}
	return out, nil
}

// acrossKey is one row of the list that spans products: an issue in a
// component, in one of them.
//
// A tag is a product's own word — the same issue in the same library is two
// pieces of work in two products, marked separately by different people — so a
// row on a list spanning products carries the marks of the product it belongs
// to and no others. That is the whole reason this key exists beside markKey.
type acrossKey struct{ Product, Vulnerability, Component int64 }

// tagsAcross reads the words on a page of rows that spans products.
//
// Three lists rather than the triples, dropped on the way into the map by the
// key, for the same reason tagsFor uses two: it is the shape an index answers.
func (s *Store) tagsAcross(ctx context.Context, wanted map[acrossKey]bool,
	products, issues, components []int64) (map[acrossKey][]string, error) {

	out := map[acrossKey][]string{}
	if len(wanted) == 0 {
		return out, nil
	}
	var found []Tag
	if err := s.db.NewSelect().Model(&found).
		Where("product_id IN (?)", bun.List(products)).
		Where("vulnerability_id IN (?)", bun.List(issues)).
		Where("component_id IN (?)", bun.List(components)).
		Order("tag").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what these are marked with: %w", err)
	}
	for _, row := range found {
		key := acrossKey{row.ProductID, row.VulnerabilityID, row.ComponentID}
		if wanted[key] {
			out[key] = append(out[key], row.Typed)
		}
	}
	return out, nil
}
