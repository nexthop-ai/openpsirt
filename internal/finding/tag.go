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
	"github.com/nexthop-ai/openpsirt/internal/refusal"
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

// Tag is one word on one issue in one component of one product. A tag belongs
// to the fold, so a word on a fold is one row per package of it.
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
// A tag belongs to the fold, the unit a judgment covers and the finding screen
// shows, so it is written on every component of the fold this product holds the
// issue at. Each list row, which is one component, then carries it.
//
// Tagging what is already tagged is not a failure — the state asked for is the
// state that holds — and the first spelling is kept, because a tag that
// re-spelled itself on every use would make the list of what exists unstable.
func (s *Store) TagIt(ctx context.Context, subject access.Subject, productID,
	vulnerabilityID, componentID int64, typed string) error {

	folded := TagAs(typed)
	if folded == "" {
		return refusal.Errorf("a tag has to say something")
	}
	held, err := s.mayMark(ctx, subject, productID, vulnerabilityID, componentID)
	if err != nil {
		return err
	}
	at := s.now().UTC().Truncate(time.Microsecond)
	for _, component := range held {
		row := &Tag{
			ProductID: productID, VulnerabilityID: vulnerabilityID, ComponentID: component,
			Tag: folded, Typed: strings.TrimSpace(typed),
			AddedBy: subject.ID, AddedAt: at,
		}
		if _, err := s.db.NewInsert().Model(row).Exec(ctx); err != nil {
			if on, err := s.tagged(ctx, productID, vulnerabilityID, component, folded); err == nil && on {
				continue
			}
			return fmt.Errorf("mark it: %w", err)
		}
	}
	return nil
}

// Untag takes a word off the packages of the fold the caller may triage.
// Taking one off that is not there is not a failure.
//
// A package of the fold whose findings here sit at a visibility the caller
// does not triage keeps its word: a tag is an act on a finding, at the
// finding's own visibility.
func (s *Store) Untag(ctx context.Context, subject access.Subject, productID,
	vulnerabilityID, componentID int64, typed string) error {

	held, err := s.mayMark(ctx, subject, productID, vulnerabilityID, componentID)
	if err != nil {
		return err
	}
	if _, err := s.db.NewDelete().Model((*Tag)(nil)).
		Where("product_id = ?", productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("component_id IN (?)", bun.List(held)).
		Where("tag = ?", TagAs(typed)).Exec(ctx); err != nil {
		return fmt.Errorf("take the mark off: %w", err)
	}
	return nil
}

// mayMark refuses somebody who may not argue about this finding, and answers
// the components of its fold this product holds the issue at.
//
// A tag names one issue in one fold, so it is asked of the finding rather than
// of the product: triage at a visibility some finding of the fold in this
// product carries. Somebody triaging undisclosed work alone does not mark a
// disclosed finding because the same issue is undisclosed in another fold.
func (s *Store) mayMark(ctx context.Context, subject access.Subject, productID,
	vulnerabilityID, componentID int64) ([]int64, error) {

	refused := access.Denied(fmt.Sprintf("mark work in product %d", productID))
	triaged := triagedIn(subject, productID)
	if len(triaged) == 0 {
		return nil, refused
	}
	var held []int64
	q := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr("f.component_id").
		Where(inThisProductAs("f.target_id"), productID).
		Where("f.vulnerability_id = ?", vulnerabilityID)
	if err := InTheFoldOf(q, componentID).
		GroupExpr("f.component_id").
		Having("SUM(CASE WHEN f.visibility IN (?) THEN 1 ELSE 0 END) > 0", bun.List(triaged)).
		OrderExpr("f.component_id").
		Scan(ctx, &held); err != nil {
		return nil, fmt.Errorf("read whether that finding may be marked: %w", err)
	}
	if len(held) == 0 {
		return nil, refused
	}
	return held, nil
}

// TagsOn is what is on one finding's fold, as first typed, one entry per word.
//
// Read from the packages of the fold whose findings of the issue in this
// product the reader may see, the visibilities given. A word on a package
// whose findings sit at another visibility says what that finding is about.
func (s *Store) TagsOn(ctx context.Context, productID, vulnerabilityID,
	componentID int64, visible []access.Visibility) ([]string, error) {

	if len(visible) == 0 {
		return []string{}, nil
	}
	var readable []int64
	q := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		ColumnExpr("f.component_id").
		Where(inThisProductAs("f.target_id"), productID).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("f.visibility IN (?)", bun.List(visible))
	if err := InTheFoldOf(q, componentID).
		GroupExpr("f.component_id").
		OrderExpr("f.component_id").
		Scan(ctx, &readable); err != nil {
		return nil, fmt.Errorf("read which packages of the fold may be read: %w", err)
	}
	if len(readable) == 0 {
		return []string{}, nil
	}
	var rows []Tag
	if err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).
		Where("vulnerability_id = ?", vulnerabilityID).
		Where("component_id IN (?)", bun.List(readable)).
		Order("tag", "id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what it is marked with: %w", err)
	}
	out := make([]string, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		if !seen[row.Tag] {
			seen[row.Tag] = true
			out = append(out, row.Typed)
		}
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

	visible, err := access.Readable(subject, productID)
	if err != nil {
		return nil, err
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

// markKey is one row of a list: an issue at a fold.
type markKey struct {
	Vulnerability int64
	Fold          string
}

// foldMark is a word on one package of a fold, read with the fold it is on.
type foldMark struct {
	ProductID       int64  `bun:"product_id"`
	VulnerabilityID int64  `bun:"vulnerability_id"`
	Fold            string `bun:"fold"`
	Tag             string `bun:"tag"`
	Typed           string `bun:"typed"`
}

// marksOnFolds reads the words on the packages of some folds, each one
// narrowed to a package carrying a finding of its issue in its product that
// the reader may see: readable narrows a query over finding AS "f" joined to
// its stream as "st".
//
// Through the fold, because a tag belongs to it: a package that joined the
// fold after the word was put on carries no row of its own. Narrowed by the
// package's own findings, because a word written on a package whose findings
// sit at another visibility says what that finding is about.
//
// Three lists rather than the tuples, dropped by the caller's key, for the
// index.
func (s *Store) marksOnFolds(ctx context.Context, products, issues []int64, folds []string,
	readable func(*bun.SelectQuery) *bun.SelectQuery) ([]foldMark, error) {

	seen := readable(s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		ColumnExpr("1").
		Where("st.product_id = ft.product_id").
		Where("f.vulnerability_id = ft.vulnerability_id").
		Where("f.component_id = ft.component_id"))
	var found []foldMark
	if err := s.db.NewSelect().
		TableExpr(`"finding_tag" AS "ft"`).
		Join(`JOIN "component" AS "ct" ON ct.id = ft.component_id`).
		ColumnExpr(`ft.product_id AS "product_id"`).
		ColumnExpr(`ft.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`ct.fold_key AS "fold"`).
		ColumnExpr(`ft.tag AS "tag"`).
		ColumnExpr(`ft.typed AS "typed"`).
		Where("ft.product_id IN (?)", bun.List(products)).
		Where("ft.vulnerability_id IN (?)", bun.List(issues)).
		Where("ct.fold_key IN (?)", bun.List(folds)).
		Where("EXISTS (?)", seen).
		OrderExpr("ft.tag, ft.id").
		Scan(ctx, &found); err != nil {
		return nil, fmt.Errorf("read what these are marked with: %w", err)
	}
	return found, nil
}

// tagsFor reads the words on a page of rows, in one statement.
func (s *Store) tagsFor(ctx context.Context, productID int64, rows []decorated,
	visible []access.Visibility) (map[markKey][]string, error) {

	out := map[markKey][]string{}
	if productID == 0 || len(rows) == 0 || len(visible) == 0 {
		return out, nil
	}
	issues := make([]int64, 0, len(rows))
	folds := make([]string, 0, len(rows))
	wanted := make(map[markKey]bool, len(rows))
	for _, row := range rows {
		issues = append(issues, row.VulnerabilityID)
		folds = append(folds, row.Fold)
		wanted[markKey{row.VulnerabilityID, row.Fold}] = true
	}
	found, err := s.marksOnFolds(ctx, []int64{productID}, issues, folds,
		func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("f.visibility IN (?)", bun.List(visible))
		})
	if err != nil {
		return nil, err
	}
	said := map[markKey]map[string]bool{}
	for _, row := range found {
		key := markKey{row.VulnerabilityID, row.Fold}
		if !wanted[key] || said[key][row.Tag] {
			continue
		}
		if said[key] == nil {
			said[key] = map[string]bool{}
		}
		said[key][row.Tag] = true
		out[key] = append(out[key], row.Typed)
	}
	return out, nil
}

// acrossKey is one row of the list that spans products: an issue at a fold,
// in one of them.
//
// A tag is a product's own word — the same issue in the same library is two
// pieces of work in two products, marked separately by different people — so a
// row on a list spanning products carries the marks of the product it belongs
// to and no others. That is the whole reason this key exists beside markKey.
type acrossKey struct {
	Product, Vulnerability int64
	Fold                   string
}

// tagsAcross reads the words on a page of rows that spans products, each one
// narrowed to what the subject may read in its own product.
func (s *Store) tagsAcross(ctx context.Context, subject access.Subject, readableIn []int64,
	all bool, wanted map[acrossKey]bool) (map[acrossKey][]string, error) {

	out := map[acrossKey][]string{}
	if len(wanted) == 0 {
		return out, nil
	}
	var products, issues []int64
	var folds []string
	for key := range wanted {
		products = append(products, key.Product)
		issues = append(issues, key.Vulnerability)
		folds = append(folds, key.Fold)
	}
	found, err := s.marksOnFolds(ctx, products, issues, folds,
		func(q *bun.SelectQuery) *bun.SelectQuery {
			return onlyReadable(q, subject, readableIn, all)
		})
	if err != nil {
		return nil, err
	}
	said := map[acrossKey]map[string]bool{}
	for _, row := range found {
		key := acrossKey{row.ProductID, row.VulnerabilityID, row.Fold}
		if !wanted[key] || said[key][row.Tag] {
			continue
		}
		if said[key] == nil {
			said[key] = map[string]bool{}
		}
		said[key][row.Tag] = true
		out[key] = append(out[key], row.Typed)
	}
	return out, nil
}
