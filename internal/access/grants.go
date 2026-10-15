// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"fmt"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/uptrace/bun"
)

// Grant is one role held against one product.
type Grant struct {
	bun.BaseModel `bun:"table:role_grant,alias:rg"`

	ID        int64 `bun:"id,pk,autoincrement"`
	PersonID  int64 `bun:"person_id,notnull"`
	ProductID int64 `bun:"product_id,notnull"`
	Role      Role  `bun:"role,notnull"`
	// Source says whether an administrator assigned this or a group derived
	// it, and Active whether it grants anything at all right now. A grant made
	// inactive by a change of mode is kept so the change can be undone, and it
	// is never counted as access while it sits there.
	Source    Source    `bun:"source,notnull"`
	Active    bool      `bun:"active,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
}

// insertOnce writes a row whose refusal is a unique index, and turns that
// refusal into success where the state the caller asked for already holds. It
// reports whether it wrote the row.
//
// The question is only ever asked of a uniqueness violation, which is the one
// failure that means "somebody got there first". Any other insert error is the
// caller's to hear.
//
// The insert stands on a savepoint of its own. On PostgreSQL a refused
// statement aborts the transaction around it, so the read that asks whether
// the state holds would fail, and so would everything the caller writes
// after it. Rolled back to the savepoint, the transaction carries on. Outside
// a transaction the savepoint is a transaction of its own, which changes
// nothing. SAVEPOINT is plain SQL on all four engines.
//
// The predicate stays the caller's, because what "already holds" means is the
// one part that genuinely differs: a grant asks whether it is in force, and
// each caller says why beside itself.
//
// With the row there and the predicate saying no, the caller hears what
// happened rather than the driver's constraint message.
//
// AddToTeam reads and writes inside one transaction instead. This is the shape
// for a write whose refusal is a unique index rather than a row it has to see
// first.
func (s *Store) insertOnce(ctx context.Context, what string, row any,
	present func(context.Context) (bool, error)) (bool, error) {

	sp, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("%s: %w", what, err)
	}
	if _, err := sp.NewInsert().Model(row).Exec(ctx); err != nil {
		_ = sp.Rollback()
		if !database.IsDuplicate(err) {
			return false, fmt.Errorf("%s: %w", what, err)
		}
		there, err := present(ctx)
		if err != nil {
			return false, fmt.Errorf("%s: %w", what, err)
		}
		if there {
			return false, nil
		}
		return false, refusal.Errorf("%s: it is already recorded and is not in force, so it "+
			"cannot be granted again from here", what)
	}
	if err := sp.Commit(); err != nil {
		return false, fmt.Errorf("%s: %w", what, err)
	}
	return true, nil
}

// GrantRole gives somebody a role on a product.
func (s *Store) GrantRole(ctx context.Context, personID, productID int64, role Role) error {
	if !role.Valid() {
		return refusal.Errorf("%q is not a role", role)
	}
	grant := &Grant{
		PersonID: personID, ProductID: productID, Role: role,
		Source: Assigned, Active: true,
		CreatedAt: s.now().Truncate(time.Microsecond),
	}
	// Granting what somebody already holds is not a failure. In force, like
	// every other question about what somebody holds: a row set aside by a
	// change of mode grants nothing, so reporting success on one would tell an
	// administrator they had granted something that does not exist.
	_, err := s.insertOnce(ctx, fmt.Sprintf("grant %q", role), grant,
		func(ctx context.Context) (bool, error) {
			return s.holds(ctx, personID, productID, role)
		})
	return err
}

func (s *Store) holds(ctx context.Context, personID, productID int64, role Role) (bool, error) {
	n, err := s.db.NewSelect().Model((*Grant)(nil)).
		Where(`"person_id" = ?`, personID).Where(`"product_id" = ?`, productID).
		Where(`"role" = ?`, role).Where(`"active" = ?`, true).Count(ctx)
	return n > 0, err
}

// People lists everybody and what they hold, inactive grants included and
// marked as such.
//
// The rows are returned whole rather than filtered, because this is the view
// an access review reads: a grant that has been set aside has to be visible as
// set aside, not hidden and not counted. An inactive row must never read like
// a live one, which is what the caller renders.
func (s *Store) People(ctx context.Context) ([]Account, map[int64][]Grant, error) {
	var people []Account
	if err := s.db.NewSelect().Model(&people).Order("identity").Scan(ctx); err != nil {
		return nil, nil, fmt.Errorf("list people: %w", err)
	}
	var grants []Grant
	if err := s.db.NewSelect().Model(&grants).Order("person_id", "product_id").Scan(ctx); err != nil {
		return nil, nil, fmt.Errorf("list what people hold: %w", err)
	}
	held := map[int64][]Grant{}
	for _, grant := range grants {
		held[grant.PersonID] = append(held[grant.PersonID], grant)
	}
	return people, held, nil
}

// Grants lists what one person holds, inactive grants included and marked as
// such, the same way People reports them.
//
// Asked when a person has just been changed and the answer has to describe
// them: what is in force, and where each role came from, are the store's to
// say. Reading them back is the difference between reporting the record and
// repeating the request that changed it.
func (s *Store) Grants(ctx context.Context, personID int64) ([]Grant, error) {
	var grants []Grant
	if err := s.db.NewSelect().Model(&grants).
		Where(`"person_id" = ?`, personID).Order("product_id").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what they hold: %w", err)
	}
	return grants, nil
}

// Withdraw takes a role away.
//
// The row is removed rather than marked. A grant is a statement about now, and
// what somebody used to hold is answered by the record of what they did, not
// by keeping a permission that no longer applies.
func (s *Store) Withdraw(ctx context.Context, personID, productID int64, role Role) error {
	res, err := s.db.NewDelete().Model((*Grant)(nil)).
		Where(`"person_id" = ?`, personID).
		Where(`"product_id" = ?`, productID).
		Where(`"role" = ?`, role).Exec(ctx)
	if err != nil {
		return fmt.Errorf("withdraw %q: %w", role, err)
	}
	// A withdrawal that matched nothing is not a withdrawal. Answered as
	// success, the caller wrote a trail row recording an act that did not
	// happen, and then asked whether the person still held anything here —
	// which, for a role they never had, came back no, and handed back every
	// finding they were dealing with in that product.
	return matched(res, fmt.Sprintf("withdraw %q", role), fmt.Sprintf("they do not hold %q here", role))
}

// HoldsAnythingIn reports whether somebody still has any role on a product.
//
// Asked after a role is withdrawn, because the last one going is what turns
// their assigned work into work nobody can reach: assigned, so not in the
// shared queue, and assigned to somebody who can no longer open it.
func (s *Store) HoldsAnythingIn(ctx context.Context, personID, productID int64) (bool, error) {
	// And they are still here. A departed person's grant rows are left in
	// place deliberately, so counting them left their work with somebody who
	// is refused at sign-in and the answer said nothing was released.
	here, err := s.here(ctx, personID)
	if err != nil || !here {
		return false, err
	}
	// Any role at all, asked of the same union every other question uses. In
	// force, like every question about what somebody holds: a row that grants
	// nothing must never be counted as access — a grant left inactive by a
	// switch to group-bound roles answers "they still hold something here", so
	// their assigned findings stay with somebody who can no longer open them
	// and the response says nothing was released. And a role held across
	// every product is a role held here, so withdrawing their last per-product
	// grant does not leave their work unreachable.
	held, err := holdingAny(s.db.NewSelect().
		TableExpr(`"person" AS "p"`).ColumnExpr(`"p"."id"`).
		Where(`"p"."id" = ?`, personID), `"p"."id"`, Roles(), productID).Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read what they still hold: %w", err)
	}
	return held, nil
}
