// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// EstateGrant is a role held across every product (REQ-42).
//
// A standing fact rather than a copy per product: a product declared after it
// was made is covered, because what somebody holds is worked out when they
// ask rather than frozen when the grant was written. Expanding it into
// per-product rows is the defect it replaces — those record the products of
// the moment, and a new product is then a permissions sweep across everybody.
type EstateGrant struct {
	bun.BaseModel `bun:"table:role_grant_all,alias:rga"`

	ID       int64 `bun:"id,pk,autoincrement"`
	PersonID int64 `bun:"person_id,notnull"`
	Role     Role  `bun:"role,notnull"`
	// Source and Active mean what they mean on a per-product grant, so a
	// change of role-assignment mode covers these rows by the same act.
	Source    Source    `bun:"source,notnull"`
	Active    bool      `bun:"active,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
}

// GrantEstateRole gives somebody a role across every product.
func (s *Store) GrantEstateRole(ctx context.Context, personID int64, role Role) error {
	if !role.Valid() {
		return fmt.Errorf("%q is not a role", role)
	}
	grant := &EstateGrant{
		PersonID: personID, Role: role,
		Source: Assigned, Active: true,
		CreatedAt: s.now().Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(grant).Exec(ctx); err != nil {
		// Granting what is already granted is not a failure. Asked as a count
		// rather than written as an upsert: the clause that would express it
		// is spelled differently on each of the four engines, and
		// engine-specific SQL belongs in the database package rather than
		// here (REQ-71).
		return s.alreadyThere(ctx, err,
			fmt.Sprintf("grant %q across every product", role),
			func(ctx context.Context) (bool, error) {
				// In force, like every other question about what somebody
				// holds. A row set aside by a change of mode grants nothing,
				// so reporting success on one would tell an administrator they
				// had granted something that does not exist.
				n, err := s.db.NewSelect().Model((*EstateGrant)(nil)).
					Where("person_id = ?", personID).Where("role = ?", role).
					Where("active = ?", true).Count(ctx)
				return n > 0, err
			})
	}
	return nil
}

// WithdrawEstateRole takes one back.
//
// Removed rather than marked, like a per-product grant: what somebody holds is
// a statement about now, and what they used to hold is answered by the record
// of what they did.
//
// It does not leave per-product grants behind in its place. Expanding at
// withdrawal would record the products of that moment, which is the freezing
// this whole shape exists to avoid — so an estate grant is withdrawn whole,
// and anything still wanted is granted per product deliberately.
func (s *Store) WithdrawEstateRole(ctx context.Context, personID int64, role Role) error {
	res, err := s.db.NewDelete().Model((*EstateGrant)(nil)).
		Where("person_id = ?", personID).Where("role = ?", role).Exec(ctx)
	if err != nil {
		return fmt.Errorf("withdraw %q across every product: %w", role, err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("withdraw %q across every product: %w", role, err)
	}
	if n == 0 {
		return fmt.Errorf("they do not hold %q across every product: %w", role, ErrNothingMatched)
	}
	return nil
}

// EstateGrants is what somebody holds across every product, in force or not.
func (s *Store) EstateGrants(ctx context.Context, personID int64) ([]EstateGrant, error) {
	var grants []EstateGrant
	if err := s.db.NewSelect().Model(&grants).
		Where("person_id = ?", personID).Order("role").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what they hold everywhere: %w", err)
	}
	return grants, nil
}

// EveryEstateGrant is what everybody holds across every product, by person.
//
// Batched because the alternative is a query per row, and the list this feeds
// is exactly the one that is long. The per-product grants beside it are read
// the same way.
func (s *Store) EveryEstateGrant(ctx context.Context) (map[int64][]EstateGrant, error) {
	var grants []EstateGrant
	if err := s.db.NewSelect().Model(&grants).
		Order("person_id", "role").Scan(ctx); err != nil {
		return nil, fmt.Errorf("list what people hold everywhere: %w", err)
	}
	held := map[int64][]EstateGrant{}
	for _, grant := range grants {
		held[grant.PersonID] = append(held[grant.PersonID], grant)
	}
	return held, nil
}

// everyProduct is the catalog, for resolving an estate grant.
//
// Read at the moment somebody asks rather than written into their grants when
// the estate role was given, which is what makes a product declared afterwards
// covered without anybody being re-granted anything.
func (s *Store) everyProduct(ctx context.Context) ([]int64, error) {
	var ids []int64
	if err := s.db.NewSelect().Table("product").Column("id").
		Order("id").Scan(ctx, &ids); err != nil {
		return nil, fmt.Errorf("read the products an estate grant covers: %w", err)
	}
	return ids, nil
}

// spreadEstate resolves estate grants into the per-product grants a subject
// carries.
//
// Resolved here rather than at each query. Every check that asks what
// somebody may do — reading, triaging, knowing a product exists, narrowing a
// list, counting, exporting — goes through the per-product grants, so putting
// the estate role into them answers all of those at once and by construction.
//
// The alternative was a flag meaning "every product" carried into each of
// those queries, which is the shape already there for the deployment's own
// background passes. That flag means *no narrowing at all*, visibility
// included, so an estate grant reading only disclosed findings would have
// reached every undisclosed one in the deployment. Reusing it would have been
// the obvious change and a disclosure (REQ-43).
func spreadEstate(grants map[int64][]Role, estate []Role, products []int64) {
	for _, role := range estate {
		for _, product := range products {
			if !holds(grants[product], role) {
				grants[product] = append(grants[product], role)
			}
		}
	}
}

// holds reports whether a role is already in a list.
func holds(roles []Role, role Role) bool {
	for _, held := range roles {
		if held == role {
			return true
		}
	}
	return false
}

// ProductsCovered is every product an estate grant reaches, which is the
// catalog.
//
// Named rather than reusing everyProduct at the call site: what the withdrawal
// path needs is "what did that grant cover", and spelling it as "every
// product" there would read as an assumption rather than as the rule.
func (s *Store) ProductsCovered(ctx context.Context) ([]int64, error) {
	return s.everyProduct(ctx)
}
