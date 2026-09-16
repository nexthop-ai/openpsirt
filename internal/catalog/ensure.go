package catalog

import (
	"context"
	"errors"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// ErrDiffers is returned when something has been declared before, with
// something else.
//
// It is a separate answer from having declared it twice identically. A
// pipeline that declares before every build must not fail on the second one,
// and a pipeline that has quietly changed what it means by a name must not
// pass — telling those apart is the whole point of a declaration step.
var ErrDiffers = errors.New("already declared, differently")

// EnsureProduct declares a product, or confirms one already declared.
//
// The returned flag says which happened, because a caller scripting this into
// whatever cuts a branch needs to know whether anything changed, and a person
// reading the answer needs to know whether they created something.
func (s *Store) EnsureProduct(ctx context.Context, name, displayName string) (*Product, bool, error) {
	for again := true; ; again = false {
		product, made, err := s.ensureProduct(ctx, name, displayName)
		if again && raced(err) {
			continue
		}
		return product, made, err
	}
}

// raced reports whether a declaration lost to another writer.
//
// The read and the write below it are two statements, so two pipelines
// declaring the same thing at once both find nothing and both insert. The
// unique index refuses the loser, and without this the loser is handed a
// constraint violation on a route documented as idempotent — which is the
// ordinary case from CI, where nothing coordinates the pipelines.
//
// Going round once more lands in the confirm arm, which is the answer the
// second caller was always going to get. Once and no more: a row that keeps
// disappearing is not a race and must not become a loop.
func raced(err error) bool {
	return database.IsDuplicate(err) || errors.Is(err, ErrExists)
}

func (s *Store) ensureProduct(ctx context.Context, name, displayName string) (*Product, bool, error) {
	existing, err := s.ProductByName(ctx, name)
	switch {
	case err == nil:
		if displayName != "" && displayName != existing.DisplayName {
			return nil, false, fmt.Errorf("product %q: %w: it is displayed as %q, not %q",
				name, ErrDiffers, existing.DisplayName, displayName)
		}
		return existing, false, nil
	case !errors.Is(err, ErrNotFound):
		return nil, false, err
	}

	created, err := s.DeclareProduct(ctx, name, displayName)
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

// EnsureStream declares a branch or tag, or confirms one already declared.
func (s *Store) EnsureStream(ctx context.Context, productID int64, name string, kind Kind, parentID *int64) (*Stream, bool, error) {
	for again := true; ; again = false {
		stream, made, err := s.ensureStream(ctx, productID, name, kind, parentID)
		if again && raced(err) {
			continue
		}
		return stream, made, err
	}
}

func (s *Store) ensureStream(ctx context.Context, productID int64, name string, kind Kind, parentID *int64) (*Stream, bool, error) {
	existing, err := s.StreamByName(ctx, productID, name)
	switch {
	case err == nil:
		// Whether a line moves is not something that can quietly change. A tag
		// that became a branch would make everything filed against it as a
		// frozen point into something that is rebuilt nightly.
		if existing.Kind != kind {
			return nil, false, fmt.Errorf("%q: %w: it was declared as a %s, not a %s",
				name, ErrDiffers, existing.Kind, kind)
		}
		// Saying it was cut from a *different* branch is a change, and a
		// contradiction: a tag is one frozen point and it came from wherever
		// it came from.
		if parentID != nil && existing.ParentID != nil && *existing.ParentID != *parentID {
			return nil, false, fmt.Errorf("%q: %w: it was not cut from the branch now being named",
				name, ErrDiffers)
		}
		// **Filling in one that was never stated is not a change.** It was
		// left out, and there was no way to supply it afterwards — so a tag
		// declared without it stayed that way, and release readiness, which
		// asks what was cut from this branch, reported that nothing had ever
		// been released. Recording it later is the same act as recording it at
		// the time, arriving late.
		if parentID != nil && existing.ParentID == nil {
			if _, err := s.db.NewUpdate().Model((*Stream)(nil)).
				Set("parent_id = ?", *parentID).
				Where("id = ?", existing.ID).
				Where("parent_id IS NULL").Exec(ctx); err != nil {
				return nil, false, fmt.Errorf("record what %q was cut from: %w", name, err)
			}
			existing.ParentID = parentID
			return existing, false, nil
		}
		return existing, false, nil
	case !errors.Is(err, ErrNotFound):
		return nil, false, err
	}

	created, err := s.DeclareStream(ctx, productID, name, kind, parentID)
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

// EnsureVariant declares a way a product is built, or confirms one already
// declared.
func (s *Store) EnsureVariant(ctx context.Context, productID int64, name string, customerFacing bool) (*Variant, bool, error) {
	for again := true; ; again = false {
		variant, made, err := s.ensureVariant(ctx, productID, name, customerFacing)
		if again && raced(err) {
			continue
		}
		return variant, made, err
	}
}

func (s *Store) ensureVariant(ctx context.Context, productID int64, name string, customerFacing bool) (*Variant, bool, error) {
	existing, err := s.VariantByName(ctx, productID, name)
	switch {
	case err == nil:
		// Whether something reaches customers feeds how its findings rank, so
		// a change here changes what people are told to work on first. It is a
		// decision somebody should make deliberately rather than a field a
		// pipeline overwrites on its next run.
		if existing.CustomerFacing != customerFacing {
			return nil, false, fmt.Errorf("variant %q: %w: it was declared as %s",
				name, ErrDiffers, facing(existing.CustomerFacing))
		}
		return existing, false, nil
	case !errors.Is(err, ErrNotFound):
		return nil, false, err
	}

	created, err := s.DeclareVariant(ctx, productID, name, customerFacing)
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

// facing names the two states in the words somebody reading an error would.
func facing(customerFacing bool) string {
	if customerFacing {
		return "customer-facing"
	}
	return "internal"
}

// Products lists what this subject may know about.
//
// A product somebody holds nothing on is not listed and not counted. The list
// itself is a statement about what an organization ships, so filtering it is
// not a nicety — an unfiltered list tells somebody the names of things they
// were never granted.
func (s *Store) Products(ctx context.Context, subject access.Subject) ([]Product, error) {
	// What may be known to exist rather than what may be read: an
	// administrator administers the catalog without holding a role on
	// anything in it.
	visible, all := subject.Knows()
	if !all && len(visible) == 0 {
		return nil, nil
	}

	var rows []Product
	query := s.db.NewSelect().Model(&rows).Order("name")
	if !all {
		query = query.Where("id IN (?)", bun.List(visible))
	}
	if err := query.Scan(ctx); err != nil {
		return nil, fmt.Errorf("list products: %w", err)
	}
	return rows, nil
}

// Streams lists the branches and tags of a product.
//
// Guarded here rather than by whoever asked. Somebody who cannot see a product
// cannot see what releases it has either, and finding that out endpoint by
// endpoint is how the second one gets forgotten.
func (s *Store) Streams(ctx context.Context, subject access.Subject, productID int64) ([]Stream, error) {
	if !subject.Sees(productID) {
		return nil, access.Denied("list the releases of a product")
	}
	var rows []Stream
	err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).Order("kind", "name").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list streams: %w", err)
	}
	return rows, nil
}

// Variants lists the ways a product is built.
func (s *Store) Variants(ctx context.Context, subject access.Subject, productID int64) ([]Variant, error) {
	if !subject.Sees(productID) {
		return nil, access.Denied("list the variants of a product")
	}
	var rows []Variant
	err := s.db.NewSelect().Model(&rows).
		Where("product_id = ?", productID).Order("name").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list variants: %w", err)
	}
	return rows, nil
}

// BuiltAs lists the variants a release has actually been built as, which is a
// subset of what the product builds: a release predating a variant has no row
// for it, and one that stopped being built as something keeps its history.
// Which product the release belongs to is read here rather than accepted, for
// the reason its counterpart over findings gives: a caller that can name the
// product can name a different one, and then the check is answering a question
// nobody asked. It is correct at every call site today, which is exactly the
// kind of correctness that stops being true when somebody adds another.
func (s *Store) BuiltAs(ctx context.Context, subject access.Subject, streamID int64) ([]Variant, error) {
	var stream Stream
	if err := s.db.NewSelect().Model(&stream).Where("id = ?", streamID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("look up the release %d: %w", streamID, err)
	}
	if !subject.Sees(stream.ProductID) {
		return nil, access.Denied("list what a release is built as")
	}
	var rows []Variant
	err := s.db.NewSelect().Model(&rows).
		Join(`JOIN "target" AS "tg" ON tg.variant_id = v.id`).
		Where("tg.stream_id = ?", streamID).Order("v.name").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("list what a release is built as: %w", err)
	}
	return rows, nil
}

// VisibleProduct finds a product this subject may know about.
//
// Something they hold nothing on is reported as not declared — the same answer
// as a name that was never declared at all. That is what invisible means:
// telling the two apart lets somebody holding one product guess at the names
// of every other, one request at a time, and get a different answer when they
// are right.
//
// So the lookup and the check happen together. Resolving the name first and
// authorizing afterwards is how the difference gets out, however carefully the
// second half is written.
func (s *Store) VisibleProduct(ctx context.Context, subject access.Subject, name string) (*Product, error) {
	product, err := s.ProductByName(ctx, name)
	if err != nil {
		return nil, err
	}
	if !subject.Sees(product.ID) {
		return nil, fmt.Errorf("product %q: %w", name, ErrNotFound)
	}
	return product, nil
}

// VisibleStream finds a release of a product this subject may know about.
//
// A release inside a product they cannot see does not exist as far as they are
// concerned, and neither does one that was never declared.
func (s *Store) VisibleStream(ctx context.Context, subject access.Subject, product, stream string) (*Product, *Stream, error) {
	p, err := s.VisibleProduct(ctx, subject, product)
	if err != nil {
		return nil, nil, err
	}
	st, err := s.StreamByName(ctx, p.ID, stream)
	if err != nil {
		return nil, nil, fmt.Errorf("product %q: %w", product, err)
	}
	return p, st, nil
}

// Shape is how much a product holds.
type Shape struct {
	Branches int
	Tags     int
	Variants int
}

// Shapes counts what each of these products holds.
//
// A catalog row saying only a name makes somebody open it to find out
// whether there is anything there, which for a list whose whole job is to say
// what exists is the question it should have answered.
// It carries a subject like every other read here. The caller passes ids it
// already narrowed, which is why nothing leaked — but "the filtering is in the
// handler" is the arrangement the non-negotiable exists to prevent, and it is
// one careless caller from being a count of products somebody cannot see.
func (s *Store) Shapes(ctx context.Context, subject access.Subject,
	productIDs []int64) (map[int64]Shape, error) {

	out := make(map[int64]Shape, len(productIDs))
	held := make([]int64, 0, len(productIDs))
	for _, id := range productIDs {
		if subject.Sees(id) {
			held = append(held, id)
		}
	}
	productIDs = held
	if len(productIDs) == 0 {
		return out, nil
	}

	var streams []struct {
		ProductID int64  `bun:"product_id"`
		Kind      string `bun:"kind"`
		Count     int    `bun:"count"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"stream" AS "st"`).
		ColumnExpr(`st.product_id AS "product_id"`).
		ColumnExpr(`st.kind AS "kind"`).
		ColumnExpr(`COUNT(*) AS "count"`).
		Where("st.product_id IN (?)", bun.List(productIDs)).
		GroupExpr("st.product_id, st.kind").
		Scan(ctx, &streams); err != nil {
		return nil, fmt.Errorf("count branches and tags: %w", err)
	}
	for _, row := range streams {
		shape := out[row.ProductID]
		if Kind(row.Kind) == Tag {
			shape.Tags = row.Count
		} else {
			shape.Branches = row.Count
		}
		out[row.ProductID] = shape
	}

	var variants []struct {
		ProductID int64 `bun:"product_id"`
		Count     int   `bun:"count"`
	}
	if err := s.db.NewSelect().
		TableExpr(`"variant" AS "va"`).
		ColumnExpr(`va.product_id AS "product_id"`).
		ColumnExpr(`COUNT(*) AS "count"`).
		Where("va.product_id IN (?)", bun.List(productIDs)).
		GroupExpr("va.product_id").
		Scan(ctx, &variants); err != nil {
		return nil, fmt.Errorf("count variants: %w", err)
	}
	for _, row := range variants {
		shape := out[row.ProductID]
		shape.Variants = row.Count
		out[row.ProductID] = shape
	}
	return out, nil
}
