package catalog

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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
