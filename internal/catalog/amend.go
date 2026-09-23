// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// RenameVariant corrects what a variant is called.
//
// The stored name is what a scan is matched against and what a published
// document is identified by, so this moves both halves: the matching name and
// the spelling shown back. A name another variant of the product holds is
// refused, retired ones included — the unique constraint covers them and a
// caller gets the reason rather than a constraint violation.
//
// Whether any document naming the old name has been published is decided by
// the caller, which is where that is known. This refuses nothing on that
// ground and is not the place the rule is enforced.
func (s *Store) RenameVariant(ctx context.Context, productID, variantID int64, name string) error {
	if err := validName("variant", name); err != nil {
		return err
	}
	existing, err := s.VariantByName(ctx, productID, name)
	switch {
	case err == nil && existing.ID != variantID:
		return fmt.Errorf("variant %q: %w", name, ErrExists)
	case err == nil:
		// Already called this, in some spelling of it. The matching name is
		// unchanged and the spelling may not be, so the write still runs.
	case !errors.Is(err, ErrNotFound):
		return err
	}
	res, err := s.db.NewUpdate().Model((*Variant)(nil)).
		Set("name = ?", matching(name)).
		Set("display_name = ?", name).
		Where("id = ?", variantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("rename variant %d: %w", variantID, err)
	}
	return counted(res, "variant", variantID, "rename")
}

// SetVariantCustomerFacing records whether a variant ships to customers.
//
// It feeds ranking, so moving it moves what everybody is told to work on
// first. A pipeline is refused this on its next run for that reason, and this
// is the deliberate act that was missing: declared wrongly once, it could not
// be corrected at all.
func (s *Store) SetVariantCustomerFacing(ctx context.Context, variantID int64, facing bool) error {
	res, err := s.db.NewUpdate().Model((*Variant)(nil)).
		Set("customer_facing = ?", facing).
		Where("id = ?", variantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("record whether variant %d ships: %w", variantID, err)
	}
	return counted(res, "variant", variantID, "record whether it ships")
}

// RetireVariant takes a variant out of use.
//
// Nothing it holds goes with it. Its findings, its decisions and the documents
// issued for it all name it, and every one of those still resolves afterwards
// — what changes is that no list offers it and no scan may be filed against
// it. Retiring one already retired is refused, so that two administrators
// doing it at once do not both record having done it.
func (s *Store) RetireVariant(ctx context.Context, variantID int64) error {
	res, err := s.db.NewUpdate().Model((*Variant)(nil)).
		Set("retired_at = ?", now()).
		Where("id = ?", variantID).
		Where("retired_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("retire variant %d: %w", variantID, err)
	}
	return counted(res, "variant", variantID, "retire")
}

// restoreVariant brings a retired variant back, which is what declaring it
// again does.
//
// Declaring is idempotent because a pipeline runs it on every build, so a
// retired name has to answer that call with the variant rather than with a
// constraint violation.
func (s *Store) restoreVariant(ctx context.Context, variantID int64) error {
	res, err := s.db.NewUpdate().Model((*Variant)(nil)).
		Set("retired_at = NULL").
		Where("id = ?", variantID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("bring variant %d back: %w", variantID, err)
	}
	return counted(res, "variant", variantID, "bring it back")
}

// RenameProduct corrects what a product is called.
//
// The matching name only. A product's display name is what screens and
// documents show and is corrected separately, because it is text rather than
// something anything is identified by.
func (s *Store) RenameProduct(ctx context.Context, productID int64, name string) error {
	if err := validName("product", name); err != nil {
		return err
	}
	existing, err := s.ProductByName(ctx, name)
	switch {
	case err == nil && existing.ID != productID:
		return fmt.Errorf("product %q: %w", name, ErrExists)
	case err == nil:
	case !errors.Is(err, ErrNotFound):
		return err
	}
	res, err := s.db.NewUpdate().Model((*Product)(nil)).
		Set("name = ?", matching(name)).
		Where("id = ?", productID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("rename product %d: %w", productID, err)
	}
	return counted(res, "product", productID, "rename")
}

// SetProductDisplayName records what a product is called on a screen.
//
// Free to move at any time. It is text: a screen shows it, a report is titled
// with it, and a published document names it in the branch a reader reads
// rather than in the identifier a reader matches. Nothing is identified by it,
// so correcting it strands nothing.
func (s *Store) SetProductDisplayName(ctx context.Context, productID int64, shown string) error {
	shown = strings.TrimSpace(shown)
	if err := validName("product display", shown); err != nil {
		return err
	}
	res, err := s.db.NewUpdate().Model((*Product)(nil)).
		Set("display_name = ?", shown).
		Where("id = ?", productID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("record what product %d is called: %w", productID, err)
	}
	return counted(res, "product", productID, "record what it is called")
}

// RetireProduct takes a product out of use.
//
// Its releases and variants are left as they are. They are reachable only
// through the product, so a retired product takes them out of every list with
// it, and writing a date onto each of them would be a bulk write whose only
// effect is to make bringing the product back a second bulk write that has to
// remember exactly what it changed.
func (s *Store) RetireProduct(ctx context.Context, productID int64) error {
	res, err := s.db.NewUpdate().Model((*Product)(nil)).
		Set("retired_at = ?", now()).
		Where("id = ?", productID).
		Where("retired_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("retire product %d: %w", productID, err)
	}
	return counted(res, "product", productID, "retire")
}

func (s *Store) restoreProduct(ctx context.Context, productID int64) error {
	res, err := s.db.NewUpdate().Model((*Product)(nil)).
		Set("retired_at = NULL").
		Where("id = ?", productID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("bring product %d back: %w", productID, err)
	}
	return counted(res, "product", productID, "bring it back")
}

// RenameStream corrects what a release is called.
//
// Both halves, the way a variant's name moves: the matching name and the
// spelling shown back are derived from one string, and a release has no
// display name of its own that anything sets apart from it.
func (s *Store) RenameStream(ctx context.Context, productID, streamID int64, name string) error {
	if err := validName("release", name); err != nil {
		return err
	}
	existing, err := s.StreamByName(ctx, productID, name)
	switch {
	case err == nil && existing.ID != streamID:
		return fmt.Errorf("release %q: %w", name, ErrExists)
	case err == nil:
	case !errors.Is(err, ErrNotFound):
		return err
	}
	res, err := s.db.NewUpdate().Model((*Stream)(nil)).
		Set("name = ?", matching(name)).
		Set("display_name = ?", name).
		Where("id = ?", streamID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("rename release %d: %w", streamID, err)
	}
	return counted(res, "release", streamID, "rename")
}

// RetireStream takes a release out of use.
func (s *Store) RetireStream(ctx context.Context, streamID int64) error {
	res, err := s.db.NewUpdate().Model((*Stream)(nil)).
		Set("retired_at = ?", now()).
		Where("id = ?", streamID).
		Where("retired_at IS NULL").
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("retire release %d: %w", streamID, err)
	}
	return counted(res, "release", streamID, "retire")
}

func (s *Store) restoreStream(ctx context.Context, streamID int64) error {
	res, err := s.db.NewUpdate().Model((*Stream)(nil)).
		Set("retired_at = NULL").
		Where("id = ?", streamID).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("bring release %d back: %w", streamID, err)
	}
	return counted(res, "release", streamID, "bring it back")
}

// EveryProduct lists every product, retired ones included.
//
// Beside Products, which answers what is offered and leaves out what is out of
// use. This answers what exists, for a caller naming rows that already refer
// to a product rather than offering anybody a choice: a role held against a
// retired product is still held, and a table that cannot name it renders the
// role against a blank.
//
// Unauthorized, the way the name lookups beside it are. A caller reaches this
// having been authorized for the act it is part of, and the answer is a name
// they already hold an identifier for.
func (s *Store) EveryProduct(ctx context.Context) ([]Product, error) {
	var rows []Product
	if err := s.db.NewSelect().Model(&rows).Order("name").Scan(ctx); err != nil {
		return nil, fmt.Errorf("list every product: %w", err)
	}
	return rows, nil
}

// counted turns an update that matched nothing into the reason it did.
//
// Matched rather than changed: the connection settings make an affected count
// mean the row was still there, so a write whose values were already correct
// still counts. Zero means the row is gone or a condition on it held.
func counted(res sql.Result, what string, id int64, doing string) error {
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("%s %s %d: %w", doing, what, id, err)
	}
	if n == 0 {
		return fmt.Errorf("%s %d: %w", what, id, ErrNotFound)
	}
	return nil
}
