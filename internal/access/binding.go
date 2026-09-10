package access

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/database"
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
	// GroupBound means roles come from provider groups, through mappings an
	// administrator manages. Per-person assignment is off while it is on.
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

// Binding is a provider group bound to a role on a product.
type Binding struct {
	bun.BaseModel `bun:"table:group_role,alias:gr"`

	ID        int64     `bun:"id,pk,autoincrement"`
	GroupName string    `bun:"group_name,notnull"`
	ProductID int64     `bun:"product_id,notnull"`
	Role      Role      `bun:"role,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
}

// AdminBinding is a provider group whose members administer this deployment.
type AdminBinding struct {
	bun.BaseModel `bun:"table:group_admin,alias:ga"`

	ID        int64     `bun:"id,pk,autoincrement"`
	GroupName string    `bun:"group_name,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
}

// Bind maps a group to a role on a product.
func (s *Store) Bind(ctx context.Context, group string, productID int64, role Role) error {
	group = strings.TrimSpace(group)
	if group == "" {
		return fmt.Errorf("a binding needs a group to bind")
	}
	if !role.Valid() {
		return fmt.Errorf("%q is not a role", role)
	}
	binding := &Binding{
		GroupName: group, ProductID: productID, Role: role,
		CreatedAt: s.now().Truncate(time.Microsecond),
	}
	if _, err := s.db.NewInsert().Model(binding).Exec(ctx); err != nil {
		// Binding what is already bound is not a failure.
		n, counted := s.db.NewSelect().Model((*Binding)(nil)).
			Where("group_name = ?", group).Where("product_id = ?", productID).
			Where("role = ?", role).Count(ctx)
		if counted == nil && n > 0 {
			return nil
		}
		return fmt.Errorf("bind %q to %q: %w", group, role, err)
	}
	return nil
}

// Unbind removes one mapping.
func (s *Store) Unbind(ctx context.Context, group string, productID int64, role Role) error {
	if _, err := s.db.NewDelete().Model((*Binding)(nil)).
		Where("group_name = ?", group).Where("product_id = ?", productID).
		Where("role = ?", role).Exec(ctx); err != nil {
		return fmt.Errorf("unbind %q from %q: %w", group, role, err)
	}
	return nil
}

// Bindings lists every group-to-role mapping.
func (s *Store) Bindings(ctx context.Context) ([]Binding, error) {
	var bindings []Binding
	if err := s.db.NewSelect().Model(&bindings).
		Order("group_name ASC", "product_id ASC", "role ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the group bindings: %w", err)
	}
	return bindings, nil
}

// BindAdmin makes a group's members administrators.
func (s *Store) BindAdmin(ctx context.Context, group string) error {
	group = strings.TrimSpace(group)
	if group == "" {
		return fmt.Errorf("a binding needs a group to bind")
	}
	binding := &AdminBinding{GroupName: group, CreatedAt: s.now().Truncate(time.Microsecond)}
	if _, err := s.db.NewInsert().Model(binding).Exec(ctx); err != nil {
		n, counted := s.db.NewSelect().Model((*AdminBinding)(nil)).
			Where("group_name = ?", group).Count(ctx)
		if counted == nil && n > 0 {
			return nil
		}
		return fmt.Errorf("bind %q to administration: %w", group, err)
	}
	return nil
}

// UnbindAdmin stops a group's members being administrators.
func (s *Store) UnbindAdmin(ctx context.Context, group string) error {
	if _, err := s.db.NewDelete().Model((*AdminBinding)(nil)).
		Where("group_name = ?", group).Exec(ctx); err != nil {
		return fmt.Errorf("unbind %q from administration: %w", group, err)
	}
	return nil
}

// AdminGroups lists the groups whose members administer this deployment.
func (s *Store) AdminGroups(ctx context.Context) ([]string, error) {
	var bindings []AdminBinding
	if err := s.db.NewSelect().Model(&bindings).Order("group_name ASC").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the administrator bindings: %w", err)
	}
	names := make([]string, 0, len(bindings))
	for _, binding := range bindings {
		names = append(names, binding.GroupName)
	}
	return names, nil
}

// AdmitByGroups signs somebody in against what a provider says they belong to.
//
// This is the one path that may record a person, and only in group-bound mode.
// It does not contradict access being granted in advance: the mapping *is* the
// advance authorization, made by an administrator before anybody arrived, and
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
	var person *Account
	if err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		var err error
		person, err = (&Store{db: tx, now: s.now}).admit(ctx, who, groups)
		return err
	}); err != nil {
		return Subject{}, err
	}

	// Read after the writes are committed, and deliberately not inside them.
	// What this sign-in yields is whatever they now hold, and somebody who
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
	// Matched through the provider rather than by name, so that somebody who
	// renamed themselves is still themselves and somebody who took the name
	// they left behind is not.
	person, err := s.MatchProvider(ctx, who.Provider, who.Subject, who.Username)
	known := err == nil
	if !known && len(roles) == 0 && !admin {
		return nil, ErrDenied
	}

	if !known {
		person = &Account{
			Identity: who.handle(), DisplayName: who.DisplayName,
			CreatedAt: s.now().Truncate(time.Microsecond),
		}
		if err := s.record(ctx, person); err != nil {
			return nil, fmt.Errorf("record %q: %w", who.handle(), err)
		}
		// The mapping authorized them, so the way they arrived is recorded and
		// pinned now rather than waiting for a second sign-in.
		if err := s.Claim(ctx, person.ID, who.Provider, who.Username); err != nil {
			return nil, err
		}
		if _, err := s.MatchProvider(ctx, who.Provider, who.Subject, who.Username); err != nil {
			return nil, err
		}
	}

	// An administrator named in configuration keeps it whatever the groups
	// say. That naming is the documented way back in when the mapping is
	// wrong or the provider is unreachable. Somebody promoted inside the
	// application keeps that: their administration did not come from a
	// group, so a group not mentioning them says nothing about it. Only
	// what a group granted is taken back by a group, which is what
	// admin_derived records.
	effective := admin || person.IsBootstrap || (person.IsAdmin && !person.AdminDerived)
	if person.IsAdmin != effective || person.AdminDerived != admin {
		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("is_admin = ?", effective).Set("admin_derived = ?", admin).
			Where("id = ?", person.ID).Exec(ctx); err != nil {
			return nil, fmt.Errorf("record what %q administers: %w", person.Identity, err)
		}
		person.IsAdmin = effective
		person.AdminDerived = admin
	}

	if err := s.replaceDerived(ctx, person.ID, roles); err != nil {
		return nil, err
	}

	return person, nil
}

// rolesFor reads what a set of groups maps to.
//
// Groups nobody bound contribute nothing, and no groups at all contribute
// nothing — never everything. That is the failure which would otherwise be
// silent and total.
func (s *Store) rolesFor(ctx context.Context, groups []string) (map[int64][]Role, bool, error) {
	named := make([]string, 0, len(groups))
	for _, group := range groups {
		if trimmed := strings.TrimSpace(group); trimmed != "" {
			named = append(named, trimmed)
		}
	}
	if len(named) == 0 {
		return nil, false, nil
	}

	var bindings []Binding
	if err := s.db.NewSelect().Model(&bindings).
		Where("group_name IN (?)", bun.List(named)).Scan(ctx); err != nil {
		return nil, false, fmt.Errorf("read what these groups are bound to: %w", err)
	}
	roles := map[int64][]Role{}
	for _, binding := range bindings {
		if !binding.Role.Valid() {
			continue
		}
		roles[binding.ProductID] = append(roles[binding.ProductID], binding.Role)
	}

	administers, err := s.db.NewSelect().Model((*AdminBinding)(nil)).
		Where("group_name IN (?)", bun.List(named)).Count(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("read whether these groups administer: %w", err)
	}
	return roles, administers > 0, nil
}

// replaceDerived makes somebody's derived grants exactly what their groups say.
func (s *Store) replaceDerived(ctx context.Context, personID int64, roles map[int64][]Role) error {
	if _, err := s.db.NewDelete().Model((*Grant)(nil)).
		Where("person_id = ?", personID).Where("source = ?", Derived).Exec(ctx); err != nil {
		return fmt.Errorf("clear what was derived from groups: %w", err)
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
	if len(fresh) == 0 {
		return nil
	}
	if _, err := s.db.NewInsert().Model(&fresh).Exec(ctx); err != nil {
		return fmt.Errorf("record what these groups grant: %w", err)
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
	db, err := s.handle()
	if err != nil {
		return err
	}
	return database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		return (&Store{db: tx, now: s.now}).switchTo(ctx, mode)
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
	case Direct:
		if _, err := s.db.NewDelete().Model((*Grant)(nil)).
			Where("source = ?", Derived).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups derived: %w", err)
		}
		if _, err := s.db.NewUpdate().Model((*Grant)(nil)).
			Set("active = ?", true).
			Where("source = ?", Assigned).Exec(ctx); err != nil {
			return fmt.Errorf("restore the assigned roles: %w", err)
		}
		// Administration derived from a group goes with it — but only what a
		// group actually derived. Somebody an administrator promoted inside
		// the application never got it from a group, and clearing theirs would
		// make a mode switch destroy access that was never derived and cannot
		// be restored by switching back.
		//
		// Which is which is knowable from the identity: a person admitted by a
		// group mapping is the one whose administration came from one. Anybody
		// holding a role assigned to them, or named in configuration, keeps it.
		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("is_admin = ?", false).
			Where("is_bootstrap = ?", false).
			Where("admin_derived = ?", true).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups administered: %w", err)
		}
		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("admin_derived = ?", false).
			Where("admin_derived = ?", true).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups administered: %w", err)
		}
	default:
		return fmt.Errorf("%q is not a way for roles to be assigned", mode)
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
	bootstrapped, err := s.db.NewSelect().Model((*Account)(nil)).
		Where("is_bootstrap = ?", true).Count(ctx)
	if err != nil {
		return false, fmt.Errorf("read who was named as an administrator: %w", err)
	}
	if bootstrapped > 0 {
		return true, nil
	}

	if mode == GroupBound {
		bound, err := s.db.NewSelect().Model((*AdminBinding)(nil)).Count(ctx)
		if err != nil {
			return false, fmt.Errorf("read which groups administer: %w", err)
		}
		return bound > 0, nil
	}

	administrators, err := s.db.NewSelect().Model((*Account)(nil)).
		Where("is_admin = ?", true).Count(ctx)
	if err != nil {
		return false, fmt.Errorf("read who administers: %w", err)
	}
	return administrators > 0, nil
}

// NameBootstrapAdmins makes configuration authoritative over who is named.
//
// Applied at every startup rather than once, so that losing administration is
// recoverable by naming somebody and restarting — the documented way back in .
// It is a pre-authorization and not a bypass: being named grants the role and
// admits nobody who has not authenticated.
//
// Anybody no longer named stops being one. Configuration says who is named, so
// a deployment that removes somebody and restarts should not still have them
// named — though an administrator promoted from inside the application keeps
// that, because it did not come from here.
func (s *Store) NameBootstrapAdmins(ctx context.Context, identities []string) error {
	named := make([]string, 0, len(identities))
	for _, identity := range identities {
		if trimmed := strings.TrimSpace(identity); trimmed != "" {
			named = append(named, trimmed)
		}
	}

	handles := make([]string, 0, len(named))
	for _, identity := range named {
		handles = append(handles, arrivalFor(identity).handle())
	}

	// Both halves or neither. Clearing who was named and naming who is
	// named now are one act: this function is the way back into a
	// deployment nobody can administer, and run half through it is what
	// creates that state rather than what ends it. It runs at startup, so
	// the next start repairs it — by running the same sequence, which is
	// not a guarantee, and a start that fails after the clear leaves a
	// database another node is already reading.
	return database.Within(ctx, s.db, func(ctx context.Context, db bun.IDB) error {
		within := &Store{db: db, now: s.now}
		clearing := db.NewUpdate().Model((*Account)(nil)).
			Set("is_bootstrap = ?", false).Where("is_bootstrap = ?", true)
		if len(handles) > 0 {
			clearing = clearing.Where("identity NOT IN (?)", bun.List(handles))
		}
		if _, err := clearing.Exec(ctx); err != nil {
			return fmt.Errorf("clear who was named as an administrator: %w", err)
		}

		for _, identity := range named {
			who := arrivalFor(identity)
			person, err := within.Ensure(ctx, who.handle(), "", true)
			if err != nil {
				return err
			}
			// Named in configuration is an authorization to sign in, so the
			// way they will sign in is recorded with it. Without this the
			// named administrator would exist and have no door to come
			// through.
			if err := within.Claim(ctx, person.ID, who.Provider, who.Username); err != nil {
				return err
			}
			if _, err := db.NewUpdate().Model((*Account)(nil)).
				Set("is_bootstrap = ?", true).Where("id = ?", person.ID).Exec(ctx); err != nil {
				return fmt.Errorf("name %q as an administrator: %w", identity, err)
			}
		}
		return nil
	})
}

// arrivalFor reads a named administrator.
//
// Written "provider:username", because a username is only unique within the
// provider that issued it and naming a bare one would be ambiguous the moment
// a second provider is configured. A bare name is taken as the trusted-header
// path, which is the arrangement that has no provider at all.
func arrivalFor(identity string) Arrival {
	if provider, username, found := strings.Cut(identity, ":"); found {
		provider, username = strings.TrimSpace(provider), strings.TrimSpace(username)
		if provider != "" && username != "" {
			return Arrival{Provider: provider, Subject: "", Username: username}
		}
	}
	return Arrival{Provider: ProxyProvider, Username: strings.TrimSpace(identity)}
}
