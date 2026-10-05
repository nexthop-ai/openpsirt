// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Mode is where a person's roles come from, for the whole deployment.
//
// One mode at a time, never both. A hybrid needs a precedence rule for
// somebody holding one role from a team and another directly — which is
// forgettable, and is how a stale direct grant outlives somebody's removal
// from the team it was meant to shadow. One mode means one answer to "where
// did this person's access come from".
type Mode string

const (
	// Direct means an administrator assigns roles to people.
	Direct Mode = "direct"
	// GroupBound means roles come from provider groups, through the mappings
	// configuration states. Per-person assignment is off while it is on.
	GroupBound Mode = "group-bound"
)

// AsMode reads a stored value, treating anything unrecognized as direct.
//
// Direct is the safe reading: it is the mode in which nothing is derived from
// what a provider says, so a value nobody can parse cannot turn group
// membership into roles.
func AsMode(s string) Mode {
	if Mode(s) == GroupBound {
		return GroupBound
	}
	return Direct
}

// Source says where a grant came from.
type Source string

const (
	// Assigned means an administrator granted it.
	Assigned Source = "assigned"
	// Derived means it came from group membership and is replaced at each
	// sign-in.
	Derived Source = "derived"
)

// Binding is a provider group bound to a role on one product.
//
// The product is named rather than referenced, so a product configuration
// names before any pipeline declares it is held and grants once it exists.
type Binding struct {
	bun.BaseModel `bun:"table:group_role,alias:gr"`

	ID          int64     `bun:"id,pk,autoincrement"`
	GroupName   string    `bun:"group_name,notnull"`
	ProductName string    `bun:"product_name,notnull"`
	Role        Role      `bun:"role,notnull"`
	CreatedAt   time.Time `bun:"created_at,notnull"`
}

// EstateBinding is a provider group bound to a role on every product,
// including one declared later (REQ-42).
type EstateBinding struct {
	bun.BaseModel `bun:"table:group_role_all,alias:gra"`

	ID        int64     `bun:"id,pk,autoincrement"`
	GroupName string    `bun:"group_name,notnull"`
	Role      Role      `bun:"role,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
}

// AdminBinding is a provider group bound to something held over the
// deployment: administering it, or auditing what it is set to.
//
// Apart from the tables above because those name a role and this names
// neither a role nor a product.
type AdminBinding struct {
	bun.BaseModel `bun:"table:group_admin,alias:ga"`

	ID        int64     `bun:"id,pk,autoincrement"`
	GroupName string    `bun:"group_name,notnull"`
	Grants    Over      `bun:"grants,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
}

// Mappings lists every mapping in force, sorted as ParseGroupRoles sorts.
func (s *Store) Mappings(ctx context.Context) ([]Mapping, error) {
	return mappingsIn(ctx, s.db)
}

func mappingsIn(ctx context.Context, db bun.IDB) ([]Mapping, error) {
	var out []Mapping
	var onProducts []Binding
	if err := db.NewSelect().Model(&onProducts).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the group bindings: %w", err)
	}
	for _, binding := range onProducts {
		out = append(out, Mapping{Group: binding.GroupName, Grants: string(binding.Role),
			Product: binding.ProductName})
	}
	var everywhere []EstateBinding
	if err := db.NewSelect().Model(&everywhere).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the group bindings across every product: %w", err)
	}
	for _, binding := range everywhere {
		out = append(out, Mapping{Group: binding.GroupName, Grants: string(binding.Role)})
	}
	var over []AdminBinding
	if err := db.NewSelect().Model(&over).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read what groups hold over this deployment: %w", err)
	}
	for _, binding := range over {
		out = append(out, Mapping{Group: binding.GroupName, Grants: string(binding.Grants)})
	}
	slices.SortFunc(out, func(a, b Mapping) int {
		return strings.Compare(a.Group+"\x00"+a.Product+"\x00"+a.Grants,
			b.Group+"\x00"+b.Product+"\x00"+b.Grants)
	})
	return out, nil
}

// Mapped is what one application of configuration's mappings changed.
type Mapped struct {
	// Added is what configuration maps and did not before.
	Added []Mapping
	// Removed is what configuration mapped before and does not now.
	Removed []Mapping
}

// ApplyMappings makes the mappings in force exactly what configuration states.
//
// Applied at every start. Only what changed is written, so a mapping that
// stands keeps the moment it was first applied, and what changed is returned
// for the start to record.
func (s *Store) ApplyMappings(ctx context.Context, wanted []Mapping) (Mapped, error) {
	var mapped Mapped
	err := database.Within(ctx, s.db, func(ctx context.Context, db bun.IDB) error {
		mapped = Mapped{}
		held, err := mappingsIn(ctx, db)
		if err != nil {
			return err
		}
		for _, mapping := range held {
			if !slices.Contains(wanted, mapping) {
				mapped.Removed = append(mapped.Removed, mapping)
			}
		}
		for _, mapping := range wanted {
			if !slices.Contains(held, mapping) {
				mapped.Added = append(mapped.Added, mapping)
			}
		}
		for _, mapping := range mapped.Removed {
			if err := unmap(ctx, db, mapping); err != nil {
				return err
			}
		}
		now := s.now().Truncate(time.Microsecond)
		for _, mapping := range mapped.Added {
			if err := mapOne(ctx, db, mapping, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Mapped{}, err
	}
	return mapped, nil
}

// mapOne writes one mapping into the table that holds its shape.
func mapOne(ctx context.Context, db bun.IDB, mapping Mapping, now time.Time) error {
	var row any
	switch over, deployment := mapping.Over(); {
	case deployment:
		row = &AdminBinding{GroupName: mapping.Group, Grants: over, CreatedAt: now}
	case mapping.Product == "":
		row = &EstateBinding{GroupName: mapping.Group, Role: Role(mapping.Grants), CreatedAt: now}
	default:
		row = &Binding{GroupName: mapping.Group, ProductName: mapping.Product,
			Role: Role(mapping.Grants), CreatedAt: now}
	}
	if _, err := db.NewInsert().Model(row).Exec(ctx); err != nil {
		return fmt.Errorf("map %s to %q: %w", mapping, mapping.Grants, err)
	}
	return nil
}

// unmap removes one mapping from the table that holds its shape.
func unmap(ctx context.Context, db bun.IDB, mapping Mapping) error {
	var q *bun.DeleteQuery
	switch over, deployment := mapping.Over(); {
	case deployment:
		q = db.NewDelete().Model((*AdminBinding)(nil)).Where("grants = ?", over)
	case mapping.Product == "":
		q = db.NewDelete().Model((*EstateBinding)(nil)).Where("role = ?", mapping.Grants)
	default:
		q = db.NewDelete().Model((*Binding)(nil)).
			Where("product_name = ?", mapping.Product).Where("role = ?", mapping.Grants)
	}
	if _, err := q.Where("group_name = ?", mapping.Group).Exec(ctx); err != nil {
		return fmt.Errorf("unmap %s from %q: %w", mapping, mapping.Grants, err)
	}
	return nil
}

// AdmitByGroups signs somebody in against what a provider says they belong to.
//
// This is the one path that may record a person, and only in group-bound mode.
// It does not contradict access being granted in advance: the mapping *is* the
// advance authorization, stated in configuration before anybody arrived, and
// somebody in no mapped group is refused exactly as a stranger is.
//
// Every derived grant is replaced rather than merged, so a group somebody left
// takes its roles with it. Assignments an administrator made are left alone —
// in this mode they are inactive anyway, and deleting them would make
// switching modes back a reconstruction from memory.
func (s *Store) AdmitByGroups(ctx context.Context, who Arrival, groups []string) (Subject, error) {
	if strings.TrimSpace(who.Username) == "" {
		return Subject{}, ErrDenied
	}

	// Applied whole. This runs on every request in a deployment where a proxy
	// reports membership, so two requests from one person overlap constantly —
	// and the middle of it is a moment when their derived roles have been
	// removed and not yet written back. Without a transaction a second request
	// reads that moment and refuses somebody who holds everything they should,
	// or collides on the row the first is about to insert.
	// Retried whole, and everything it depends on is read inside it. A
	// clustered database certifies a write when it commits rather than when
	// the statement runs, so two nodes signing the same person in find out at
	// commit — and the loser is told the whole transaction was rolled back,
	// including the reads it decided from.
	db, err := s.handle()
	if err != nil {
		return Subject{}, err
	}

	// Somebody who has left is refused before anything is written.
	//
	// Anybody else getting in is settled after the writes, deliberately,
	// because their roles are what this sign-in derives. Deactivation is not
	// that: it is a standing fact about the account, unchanged by the groups
	// they arrived with, so rewriting their derived grants on the way to
	// turning them away is a write with no reader — and it rewrites the record
	// of what somebody who has left held.
	if known, err := s.match(ctx, who); err == nil && known.DeactivatedAt != nil {
		return Subject{}, ErrDenied
	}

	var person *Account
	if err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		var err error
		person, err = s.over(tx).admit(ctx, who, groups)
		return err
	}); err != nil {
		return Subject{}, err
	}

	// Read after the writes are committed, and deliberately not inside them.
	// This sign-in yields whatever they now hold, and somebody who
	// left every group holds nothing — but the leaving has to stand. Deciding
	// inside the transaction would make the refusal roll back the very
	// withdrawal that caused it, so their roles would come back each time they
	// were turned away.
	return s.Resolve(ctx, person.Identity)
}

// admit records what a sign-in changes, and returns whose it was. It says
// nothing about whether they get in.
func (s *Store) admit(ctx context.Context, who Arrival, groups []string) (*Account, error) {

	roles, admin, err := s.rolesFor(ctx, groups)
	if err != nil {
		return nil, err
	}

	// Somebody unknown and in no mapped group was never authorized, so nothing
	// is recorded for them. The check is narrow on purpose: it only skips
	// *recording* somebody new. Whether anybody gets in is settled at the end,
	// by reading what they hold — and somebody already known has to be taken
	// through the withdrawal below first, or leaving every group would refuse
	// this sign-in while quietly leaving the last one's roles in place.
	//
	// Matched down whichever path they arrived by. Through the provider that
	// is its stable identifier rather than the name, so that somebody who
	// renamed themselves is still themselves and somebody who took the name
	// they left behind is not.
	person, err := s.match(ctx, who)
	known := err == nil
	if !known && len(roles) == 0 && len(admin.everywhere) == 0 && !admin.administers && !admin.audits {
		return nil, ErrDenied
	}

	if !known {
		// Somebody an administrator recorded who has not signed in yet is that
		// person, not a second one. An identity is a username, so the record
		// waiting under it is theirs whichever path they arrived by.
		//
		// Their administration is left alone: it is derived below from the
		// groups they arrived with, and reading it from here would overwrite
		// that with what the row happened to say.
		//
		// Adopted only while the authorization waiting for them is still
		// redeemable. The match above refused a lapsed one or one pinned to
		// another identifier, and a group does not reopen either: the window
		// holds on every path, and renewing it here would hand the account to
		// whoever arrived holding the name.
		//
		// An account with no authorization waiting under the name is refused
		// too. Its holder's name moved away at the provider, which moved the
		// name their identity carries, and whoever holds the name now is
		// somebody else.
		if waiting, err := s.ByIdentity(ctx, who.handle()); err == nil {
			claimed, err := s.claimedBy(ctx, who.handle())
			if err != nil || claimed.Subject != nil || lapsed(claimed, s.now()) {
				return nil, ErrDenied
			}
			person = waiting
		} else {
			person = &Account{
				Identity: who.handle(), DisplayName: who.DisplayName,
				CreatedAt: s.now().Truncate(time.Microsecond),
			}
			if err := s.record(ctx, person); err != nil {
				return nil, fmt.Errorf("record %q: %w", who.handle(), err)
			}
		}
		// The mapping authorized them, so the way they arrived is recorded and
		// pinned now rather than waiting for a second sign-in.
		// A name somebody else holds is a refusal, as any arrival nothing
		// authorized is: asking again cannot change it.
		if err := s.Claim(ctx, person.ID, who.Username); errors.Is(err, ErrNameTaken) {
			return nil, ErrDenied
		} else if err != nil {
			return nil, err
		}
		if _, err := s.match(ctx, who); err != nil {
			return nil, err
		}
	}

	// Only what a group granted is taken back by a group, which is what
	// admin_derived records. Somebody promoted inside the application keeps
	// that: their administration did not come from a group, so a group not
	// mentioning them says nothing about it.
	//
	// An administrator named in configuration keeps it whatever the groups
	// say, and not through this column: that half is is_bootstrap, which
	// Resolve reads beside it. Folded in here, configuration's grant would
	// be written as one made here and outlive the name.
	effective := admin.administers || (person.IsAdmin && !person.AdminDerived)
	// A group's grant is derived only where it is what made them an
	// administrator. Written as "whatever the groups say this time", the
	// column destroys the input the line above depends on next time:
	// somebody promoted in the application who also happens to be in an
	// admin-bound group is rewritten as derived, and losing the group then
	// took away administration the group never gave — irrecoverably, since a
	// switch back to direct roles clears exactly the rows marked derived.
	derived := person.AdminDerived || (admin.administers && !person.IsAdmin)
	if !effective {
		// Nothing to have come from anywhere.
		derived = false
	}
	// Auditing follows administration's rule exactly, for the same reasons:
	// only what a group gave is taken back by a group, and the stamp is what
	// bounds the flag for a credential that never signs in. It has no
	// bootstrap arm — configuration names an administrator, which is the way
	// back in, and nothing is locked out by holding no audit permission.
	audits := admin.audits || (person.Audits && !person.AuditsDerived)
	auditsDerived := person.AuditsDerived || (admin.audits && !person.Audits)
	if !audits {
		auditsDerived = false
	}
	// The stamp is written whenever a group is what says so, and not only when
	// the answer changes: what it records is when a group last confirmed it,
	// which is the question a credential that never signs in has to be
	// measured against. Written only when the answer changes it would have
	// recorded the last change instead, and a flag that has held steady for a
	// year would read as a year stale.
	var derivedAt *time.Time
	if derived {
		now := s.now().Truncate(time.Microsecond)
		derivedAt = &now
	}
	var auditsAt *time.Time
	if auditsDerived {
		now := s.now().Truncate(time.Microsecond)
		auditsAt = &now
	}
	if person.IsAdmin != effective || person.AdminDerived != derived || derived ||
		person.Audits != audits || person.AuditsDerived != auditsDerived || auditsDerived {

		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("is_admin = ?", effective).Set("admin_derived = ?", derived).
			Set("admin_derived_at = ?", derivedAt).
			Set("audits = ?", audits).Set("audits_derived = ?", auditsDerived).
			Set("audits_derived_at = ?", auditsAt).
			Where("id = ?", person.ID).Exec(ctx); err != nil {
			return nil, fmt.Errorf("record what %q holds over this deployment: %w",
				person.Identity, err)
		}
		person.IsAdmin = effective
		person.AdminDerived = derived
		person.AdminDerivedAt = derivedAt
		person.Audits = audits
		person.AuditsDerived = auditsDerived
		person.AuditsDerivedAt = auditsAt
	}

	if err := s.replaceDerived(ctx, person.ID, roles, admin.everywhere); err != nil {
		return nil, err
	}

	return person, nil
}

// rolesFor reads what a set of groups maps to.
//
// Groups nobody bound contribute nothing, and no groups at all contribute
// nothing — never everything. That is the failure which would otherwise be
// silent and total. A mapping naming a product nobody has declared contributes
// nothing until somebody does.
func (s *Store) rolesFor(ctx context.Context, groups []string) (map[int64][]Role, held, error) {
	named := make([]string, 0, len(groups))
	for _, group := range groups {
		if trimmed := strings.TrimSpace(group); trimmed != "" {
			named = append(named, trimmed)
		}
	}
	if len(named) == 0 {
		return nil, held{}, nil
	}

	var bound []struct {
		ProductID int64 `bun:"product_id"`
		Role      Role  `bun:"role"`
	}
	if err := s.db.NewSelect().TableExpr(`"group_role" AS "gr"`).
		ColumnExpr(`"p"."id" AS "product_id"`).ColumnExpr(`"gr"."role"`).
		Join(`JOIN "product" AS "p" ON "p"."name" = "gr"."product_name"`).
		Where(`"gr"."group_name" IN (?)`, bun.List(named)).Scan(ctx, &bound); err != nil {
		return nil, held{}, fmt.Errorf("read what these groups are bound to: %w", err)
	}
	roles := map[int64][]Role{}
	for _, binding := range bound {
		if binding.Role.Valid() && !holds(roles[binding.ProductID], binding.Role) {
			roles[binding.ProductID] = append(roles[binding.ProductID], binding.Role)
		}
	}

	var everywhere []EstateBinding
	if err := s.db.NewSelect().Model(&everywhere).
		Where("group_name IN (?)", bun.List(named)).Scan(ctx); err != nil {
		return nil, held{}, fmt.Errorf("read what these groups are bound to across every product: %w", err)
	}
	var deployment held
	for _, binding := range everywhere {
		if binding.Role.Valid() && !holds(deployment.everywhere, binding.Role) {
			deployment.everywhere = append(deployment.everywhere, binding.Role)
		}
	}

	var over []AdminBinding
	if err := s.db.NewSelect().Model(&over).
		Where("group_name IN (?)", bun.List(named)).Scan(ctx); err != nil {
		return nil, held{}, fmt.Errorf("read what these groups hold over this deployment: %w", err)
	}
	for _, binding := range over {
		switch binding.Grants {
		case Administers:
			deployment.administers = true
		case Audits:
			deployment.audits = true
		}
	}
	return roles, deployment, nil
}

// held is what a set of groups gives beyond one product: over the deployment
// itself, and across every product.
type held struct {
	administers bool
	audits      bool
	// everywhere is the roles held across every product.
	everywhere []Role
}

// replaceDerived makes somebody's derived grants exactly what their groups say.
func (s *Store) replaceDerived(ctx context.Context, personID int64, roles map[int64][]Role,
	everywhere []Role) error {

	if _, err := s.db.NewDelete().Model((*Grant)(nil)).
		Where("person_id = ?", personID).Where("source = ?", Derived).Exec(ctx); err != nil {
		return fmt.Errorf("clear what was derived from groups: %w", err)
	}
	if _, err := s.db.NewDelete().Model((*EstateGrant)(nil)).
		Where("person_id = ?", personID).Where("source = ?", Derived).Exec(ctx); err != nil {
		return fmt.Errorf("clear what was derived from groups across every product: %w", err)
	}

	now := s.now().Truncate(time.Microsecond)
	fresh := make([]Grant, 0, len(roles))
	for productID, held := range roles {
		for _, role := range held {
			fresh = append(fresh, Grant{
				PersonID: personID, ProductID: productID, Role: role,
				Source: Derived, Active: true, CreatedAt: now,
			})
		}
	}
	if len(fresh) > 0 {
		if _, err := s.db.NewInsert().Model(&fresh).Exec(ctx); err != nil {
			return fmt.Errorf("record what these groups grant: %w", err)
		}
	}
	estate := make([]EstateGrant, 0, len(everywhere))
	for _, role := range everywhere {
		estate = append(estate, EstateGrant{
			PersonID: personID, Role: role, Source: Derived, Active: true, CreatedAt: now,
		})
	}
	if len(estate) > 0 {
		if _, err := s.db.NewInsert().Model(&estate).Exec(ctx); err != nil {
			return fmt.Errorf("record what these groups grant across every product: %w", err)
		}
	}
	return nil
}

// SwitchTo changes where roles come from, for the whole deployment.
//
// Switching to group-bound mode marks what an administrator assigned inactive
// rather than deleting it, and switching back makes it active again. People do
// switch back — usually on discovering their groups do not map to how the team
// actually divides work — and deleting would make that a reconstruction from
// memory rather than a change of setting.
//
// Derived grants are cleared on the way out of group-bound mode. They are a
// cache of what a provider said at somebody's last sign-in, and keeping them
// once nothing refreshes them would leave roles nobody assigned and nothing
// will ever withdraw.
func (s *Store) SwitchTo(ctx context.Context, mode Mode) error {
	// Applied whole, because a sign-in that overlaps it would otherwise write
	// derived grants back after they were cleared — leaving roles in a
	// deployment where nothing derives them any more, which is exactly what
	// clearing them was for.
	return database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		return s.over(tx).switchTo(ctx, mode)
	})
}

func (s *Store) switchTo(ctx context.Context, mode Mode) error {
	switch mode {
	case GroupBound:
		if _, err := s.db.NewUpdate().Model((*Grant)(nil)).
			Set("active = ?", false).
			Where("source = ?", Assigned).Exec(ctx); err != nil {
			return fmt.Errorf("set aside the assigned roles: %w", err)
		}
		// Estate grants are assignments too, so they are set aside by the
		// same act. Leaving them live would keep a role over every product
		// standing in a deployment where nothing derives one.
		if _, err := s.db.NewUpdate().Model((*EstateGrant)(nil)).
			Set("active = ?", false).
			Where("source = ?", Assigned).Exec(ctx); err != nil {
			return fmt.Errorf("set aside the assigned roles over every product: %w", err)
		}
	case Direct:
		if _, err := s.db.NewDelete().Model((*Grant)(nil)).
			Where("source = ?", Derived).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups derived: %w", err)
		}
		if _, err := s.db.NewDelete().Model((*EstateGrant)(nil)).
			Where("source = ?", Derived).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups derived across every product: %w", err)
		}
		if _, err := s.db.NewUpdate().Model((*Grant)(nil)).
			Set("active = ?", true).
			Where("source = ?", Assigned).Exec(ctx); err != nil {
			return fmt.Errorf("restore the assigned roles: %w", err)
		}
		if _, err := s.db.NewUpdate().Model((*EstateGrant)(nil)).
			Set("active = ?", true).
			Where("source = ?", Assigned).Exec(ctx); err != nil {
			return fmt.Errorf("restore the assigned roles over every product: %w", err)
		}
		// Administration derived from a group goes with it — but only what a
		// group actually derived. Somebody an administrator promoted inside
		// the application never got it from a group, and clearing theirs would
		// make a mode switch destroy access that was never derived and cannot
		// be restored by switching back.
		//
		// The two are told apart by admin_derived. Somebody named in
		// configuration keeps administration through is_bootstrap, which this
		// does not touch.
		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("is_admin = ?", false).
			Where("admin_derived = ?", true).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups administered: %w", err)
		}
		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("admin_derived = ?", false).
			Where("admin_derived = ?", true).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups administered: %w", err)
		}
		// Auditing goes the same way and by the same rule: what a group gave
		// is cleared, what somebody here granted stands. There is no
		// bootstrap arm because configuration names an administrator and not
		// an auditor — nobody is locked out by holding none of this.
		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("audits = ?", false).
			Where("audits_derived = ?", true).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups audited: %w", err)
		}
		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("audits_derived = ?", false).
			Where("audits_derived = ?", true).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups audited: %w", err)
		}
	default:
		return refusal.Errorf("%q is not a way for roles to be assigned", mode)
	}
	return nil
}

// CanAdminister reports whether anybody could administer this deployment in
// the mode given.
//
// Checked at startup, because a deployment that cannot reach its own
// administration has one route back — editing the database by hand — and
// nobody discovers that at a good moment.
func (s *Store) CanAdminister(ctx context.Context, mode Mode) (bool, error) {
	return canAdminister(ctx, s.db, mode)
}

// canAdminister is the three counts, against whichever handle is given.
func canAdminister(ctx context.Context, db bun.IDB, mode Mode) (bool, error) {
	// Somebody who has left cannot administer anything: they are refused at
	// sign-in. Counting a deactivated bootstrap administrator would let the
	// deployment start with no group mapped to administration and nobody able
	// to administer it, which is what this check exists to prevent.
	bootstrapped, err := db.NewSelect().Model((*Account)(nil)).
		Where("is_bootstrap = ?", true).
		Where("deactivated_at IS NULL").Count(ctx)
	if err != nil {
		return false, fmt.Errorf("read who was named as an administrator: %w", err)
	}
	if bootstrapped > 0 {
		return true, nil
	}

	if mode == GroupBound {
		// Groups bound to administration, not to anything else held over the
		// deployment: an auditor cannot grant themselves administration, so a
		// deployment whose only binding is an audit one is a deployment
		// nobody can administer.
		bound, err := db.NewSelect().Model((*AdminBinding)(nil)).
			Where("grants = ?", Administers).Count(ctx)
		if err != nil {
			return false, fmt.Errorf("read which groups administer: %w", err)
		}
		return bound > 0, nil
	}

	administrators, err := db.NewSelect().Model((*Account)(nil)).
		Where("is_admin = ?", true).
		Where("deactivated_at IS NULL").Count(ctx)
	if err != nil {
		return false, fmt.Errorf("read who administers: %w", err)
	}
	return administrators > 0, nil
}

// NameBootstrapAdmins makes configuration authoritative over who is named.
//
// Applied at every startup rather than once, so that losing administration is
// recoverable by naming somebody and restarting — the documented way back in.
// It is a pre-authorization and not a bypass: being named grants the role and
// admits nobody who has not authenticated.
//
// Each is a plain username, the same one the provider or the trusted proxy
// reports. Written "provider:username" with a bare name falling back to the
// proxy path, it grants administration to an account nobody signed in as
// whenever the two disagree — silently, at the one moment somebody needs this
// to work.
//
// Configuration's administration is recorded apart from administration
// granted here, and this writes only its own half. Anybody no longer named
// stops administering through the name, and keeps whatever was granted here or
// derived from a group, because that did not come from configuration. Who
// came to be named and who stopped being named are returned, so that the start
// that applied them can record and say so.
func (s *Store) NameBootstrapAdmins(ctx context.Context, identities []string) (Naming, error) {
	named := make([]string, 0, len(identities))
	for _, identity := range identities {
		// Folded, because that is how an identity is stored and how a sign-in
		// matches one. A name written "Alice" in configuration names the row
		// "alice", both in the NOT IN below and in the update that names them.
		trimmed := folded(identity)
		if trimmed == "" {
			continue
		}
		// A name written "provider:username" is refused. Accepted it makes an
		// administrator account literally called "okta:alice" that nobody can
		// sign in as, while the real alice is refused — and the startup check
		// that exists to catch a deployment nobody can administer is satisfied
		// by the phantom. This is the way back in, so it fails loudly at the
		// one moment somebody needs it.
		if before, _, found := strings.Cut(trimmed, ":"); found && before != "" {
			return Naming{}, refusal.Errorf(
				"%q names an administrator as \"provider:username\". A name here is the "+
					"plain username the provider or the trusted proxy reports, with no "+
					"prefix. Write %q and start again",
				trimmed, strings.TrimPrefix(trimmed, before+":"))
		}
		named = append(named, trimmed)
	}

	// Both halves or neither. Clearing who was named and naming who is
	// named now are one act: this function is the way back into a
	// deployment nobody can administer, and run half through it is what
	// creates that state rather than what ends it.
	var naming Naming
	err := database.Within(ctx, s.db, func(ctx context.Context, db bun.IDB) error {
		within := s.over(db)
		naming = Naming{}
		leaving := db.NewSelect().Model((*Account)(nil)).Column("identity").
			Where("is_bootstrap = ?", true).OrderExpr("identity")
		clearing := db.NewUpdate().Model((*Account)(nil)).
			Set("is_bootstrap = ?", false).Where("is_bootstrap = ?", true)
		if len(named) > 0 {
			leaving = leaving.Where("identity NOT IN (?)", bun.List(named))
			clearing = clearing.Where("identity NOT IN (?)", bun.List(named))
		}
		if err := leaving.Scan(ctx, &naming.Unnamed); err != nil {
			return fmt.Errorf("read who is no longer named as an administrator: %w", err)
		}
		if _, err := clearing.Exec(ctx); err != nil {
			return fmt.Errorf("clear who was named as an administrator: %w", err)
		}

		for _, identity := range named {
			// Recorded without a word about administration: being named is
			// the grant, and it is held in is_bootstrap below rather than
			// in the column an administrator here writes.
			person, err := within.Ensure(ctx, identity, "", nil, nil)
			if err != nil {
				return err
			}
			if !person.IsBootstrap {
				naming.Named = append(naming.Named, identity)
			}
			// Named in configuration is an authorization to sign in, so the
			// way they will sign in is recorded with it. Without this the
			// named administrator would exist and have no door to come
			// through.
			if err := within.Claim(ctx, person.ID, identity); err != nil {
				return err
			}
			// Naming them in configuration is the deliberate act of letting
			// a departed administrator back in, so it clears the date. A
			// departed administrator is refused at sign-in, and nothing else
			// clears it.
			//
			// Here rather than in Ensure, which recording a person also
			// calls: an administrator re-recording a departed colleague must
			// not silently readmit them.
			if _, err := db.NewUpdate().Model((*Account)(nil)).
				Set("is_bootstrap = ?", true).
				Set("deactivated_at = NULL").
				Where("id = ?", person.ID).Exec(ctx); err != nil {
				return fmt.Errorf("name %q as an administrator: %w", identity, err)
			}
		}
		return nil
	})
	if err != nil {
		return Naming{}, err
	}
	return naming, nil
}

// Naming is what one application of the administrators configuration names
// changed.
type Naming struct {
	// Named is who configuration names and did not before.
	Named []string
	// Unnamed is who configuration named before and does not now.
	Unnamed []string
}
