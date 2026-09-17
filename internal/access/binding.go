package access

import (
	"context"
	"errors"
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
//
// **The name is stored as given and matched as given.** A group name is an
// identity the provider hands over rather than a name anybody here types, and
// the rule for those is exact comparison — a folded column would make
// "Security" and "security" one binding, when the provider means only one of
// them. The cost is that a binding typed with the wrong capitals grants
// nothing and the refusal says only "not authorized", which is what the
// endpoint's description warns about; the alternative costs an administrator
// the ability to bind two groups a provider genuinely distinguishes.
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
		return s.alreadyThere(ctx, err, fmt.Sprintf("bind %q to %q", group, role),
			func(ctx context.Context) (bool, error) {
				// Whether the row is there, which is what the index refused.
				// A binding has nothing to be in force: it grants at each
				// member's next sign-in and holds nothing of its own.
				return s.db.NewSelect().Model((*Binding)(nil)).
					Where("group_name = ?", group).Where("product_id = ?", productID).
					Where("role = ?", role).Exists(ctx)
			})
	}
	return nil
}

// Unbind removes one mapping.
func (s *Store) Unbind(ctx context.Context, group string, productID int64, role Role) error {
	// Trimmed the way Bind trims, so a name typed with a trailing space
	// removes the row that name created rather than matching nothing.
	group = strings.TrimSpace(group)
	res, err := s.db.NewDelete().Model((*Binding)(nil)).
		Where("group_name = ?", group).Where("product_id = ?", productID).
		Where("role = ?", role).Exec(ctx)
	if err != nil {
		return fmt.Errorf("unbind %q from %q: %w", group, role, err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("unbind %q from %q: %w", group, role, err)
	}
	if n == 0 {
		return fmt.Errorf("%q is not bound to %q here: %w", group, role, ErrNothingMatched)
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
		return s.alreadyThere(ctx, err, fmt.Sprintf("bind %q to administration", group),
			func(ctx context.Context) (bool, error) {
				return s.db.NewSelect().Model((*AdminBinding)(nil)).
					Where("group_name = ?", group).Exists(ctx)
			})
	}
	return nil
}

// ErrLastAdministrator is what unbinding the last thing granting
// administration comes back as.
//
// A sentinel, because the caller answers it differently from a failure: it is
// a refusal somebody can act on rather than something that went wrong.
var ErrLastAdministrator = errors.New("nothing would be left to administer this deployment")

// modeIn reads where roles come from, against whichever handle it is given.
//
// Taken as a function because this package does not read settings — the one
// that does sits above it — and the mode has to be read inside the transaction
// that acts on it rather than handed in already stale.
type modeIn func(context.Context, bun.IDB) (Mode, error)

// UnbindAdminIfOthersRemain stops a group's members being administrators,
// unless they are the last thing granting it.
//
// One transaction, because the count has to see the delete. Written as a
// delete, a count and a compensating re-insert, a re-insert that failed left
// the binding gone and nobody able to administer — a state whose only route
// back is editing the database by hand. Rolling back is also what puts the
// original row back: BindAdmin stamps a fresh CreatedAt, so a "restored"
// binding was not the row that had been there.
func (s *Store) UnbindAdminIfOthersRemain(ctx context.Context, group string, mode modeIn) error {
	group = strings.TrimSpace(group)
	return database.Within(ctx, s.db, func(ctx context.Context, tx bun.IDB) error {
		// Read here, not by the caller. A retry re-runs this closure against a
		// database somebody else has moved, so a mode fetched before it began
		// describes a world that is gone (REQ-71) — and judging by the old one
		// keeps a delete that leaves nobody able to administer the deployment,
		// which is the state this function exists to prevent.
		in, err := mode(ctx, tx)
		if err != nil {
			return err
		}
		res, err := tx.NewDelete().Model((*AdminBinding)(nil)).
			Where("group_name = ?", group).Exec(ctx)
		if err != nil {
			return fmt.Errorf("unbind %q from administration: %w", group, err)
		}
		// Read, because a delete that matched nothing leaves the check below
		// passing *because* the withdrawal did nothing — the deployment is
		// still administrable, and the caller is told the binding is gone.
		n, err := database.Affected(res)
		if err != nil {
			return fmt.Errorf("unbind %q from administration: %w", group, err)
		}
		if n == 0 {
			return fmt.Errorf("%q administers nothing here: %w", group, ErrNothingMatched)
		}
		switch can, err := canAdminister(ctx, tx, in); {
		case err != nil:
			return err
		case !can:
			return ErrLastAdministrator
		}
		return nil
	})
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

	// Somebody who has left is refused before anything is written.
	//
	// Whether anybody else gets in is settled after the writes, deliberately,
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
	// Matched down whichever path they arrived by. Through the provider that
	// is its stable identifier rather than the name, so that somebody who
	// renamed themselves is still themselves and somebody who took the name
	// they left behind is not.
	person, err := s.match(ctx, who)
	known := err == nil
	if !known && len(roles) == 0 && !admin {
		return nil, ErrDenied
	}

	if !known {
		// Somebody an administrator recorded who has not signed in yet is that
		// person, not a second one. An identity is a username now, so the
		// record waiting under it is theirs — where it was qualified by the
		// path they arrived on, the two were different rows and this arrival
		// quietly became a second account.
		//
		// Whether they administer is left alone: it is derived below from the
		// groups they arrived with, and reading it from here would overwrite
		// that with what the row happened to say.
		if waiting, err := s.ByIdentity(ctx, who.handle()); err == nil {
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
		if err := s.Claim(ctx, person.ID, who.Username); err != nil {
			return nil, err
		}
		if _, err := s.match(ctx, who); err != nil {
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
	// **A group's grant is derived only where it is what made them an
	// administrator.** Written as "whatever the groups say this time", the
	// column destroyed the input the line above depends on next time:
	// somebody promoted in the application who also happened to be in an
	// admin-bound group was rewritten as derived, and losing the group then
	// took away administration the group never gave — irrecoverably, since a
	// switch back to direct roles clears exactly the rows marked derived.
	derived := person.AdminDerived || (admin && !person.IsAdmin)
	if !effective {
		// Nothing to have come from anywhere.
		derived = false
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
	if person.IsAdmin != effective || person.AdminDerived != derived || derived {
		if _, err := s.db.NewUpdate().Model((*Account)(nil)).
			Set("is_admin = ?", effective).Set("admin_derived = ?", derived).
			Set("admin_derived_at = ?", derivedAt).
			Where("id = ?", person.ID).Exec(ctx); err != nil {
			return nil, fmt.Errorf("record what %q administers: %w", person.Identity, err)
		}
		person.IsAdmin = effective
		person.AdminDerived = derived
		person.AdminDerivedAt = derivedAt
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
		// Only the per-product table is cleared of derived rows, because only
		// it holds any: a group binding names a product, so nothing derives a
		// role across the estate. `DESIGN-access.md` states that as the rule,
		// and the delete that stood here against the estate table matched
		// nothing on every deployment there has ever been.
		if _, err := s.db.NewDelete().Model((*Grant)(nil)).
			Where("source = ?", Derived).Exec(ctx); err != nil {
			return fmt.Errorf("clear what groups derived: %w", err)
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
	return canAdminister(ctx, s.db, mode)
}

// canAdminister is the three counts, against whichever handle the caller is
// asking through. Taken as a parameter so that a caller deciding whether to
// keep a delete can ask inside the transaction that made it: asked outside,
// the counts describe a database the delete has not reached.
func canAdminister(ctx context.Context, db bun.IDB, mode Mode) (bool, error) {
	// Somebody who has left cannot administer anything: they are refused at
	// sign-in. Counted, a deactivated bootstrap administrator made this answer
	// true on their strength alone — so the last admin group could be unbound
	// and the deployment started cleanly with nobody able to administer it,
	// which is exactly what this check exists to prevent.
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
		bound, err := db.NewSelect().Model((*AdminBinding)(nil)).Count(ctx)
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
// recoverable by naming somebody and restarting — the documented way back in .
// It is a pre-authorization and not a bypass: being named grants the role and
// admits nobody who has not authenticated.
//
// Each is a plain username, the same one the provider or the trusted proxy
// reports. It used to be written "provider:username" with a bare name falling
// back to the proxy path, which granted administration to an account nobody
// signed in as whenever the two disagreed — silently, at the one moment
// somebody needs this to work.
//
// Anybody no longer named stops being one. Configuration says who is named, so
// a deployment that removes somebody and restarts should not still have them
// named — though an administrator promoted from inside the application keeps
// that, because it did not come from here.
func (s *Store) NameBootstrapAdmins(ctx context.Context, identities []string) error {
	named := make([]string, 0, len(identities))
	for _, identity := range identities {
		// Folded, because that is how an identity is stored and how a sign-in
		// matches one. Compared with its capitals, a name written "Alice" in
		// configuration cleared nobody and named nobody: the row is "alice",
		// so the NOT IN below did not spare it and the update below did not
		// find it — the way back into a deployment nobody can administer,
		// silently doing nothing.
		trimmed := folded(identity)
		if trimmed == "" {
			continue
		}
		// The old form was "provider:username". Accepted silently it makes an
		// administrator account literally called "okta:alice" that nobody can
		// sign in as, while the real alice is refused — and the startup check
		// that exists to catch a deployment nobody can administer is satisfied
		// by the phantom. This is the way back in, so it fails loudly at the
		// one moment somebody needs it.
		if before, _, found := strings.Cut(trimmed, ":"); found && before != "" {
			return fmt.Errorf(
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
	// creates that state rather than what ends it. It runs at startup, so
	// the next start repairs it — by running the same sequence, which is
	// not a guarantee, and a start that fails after the clear leaves a
	// database another node is already reading.
	return database.Within(ctx, s.db, func(ctx context.Context, db bun.IDB) error {
		within := s.over(db)
		clearing := db.NewUpdate().Model((*Account)(nil)).
			Set("is_bootstrap = ?", false).Where("is_bootstrap = ?", true)
		if len(named) > 0 {
			clearing = clearing.Where("identity NOT IN (?)", bun.List(named))
		}
		if _, err := clearing.Exec(ctx); err != nil {
			return fmt.Errorf("clear who was named as an administrator: %w", err)
		}

		for _, identity := range named {
			person, err := within.Ensure(ctx, identity, "", Stated(true))
			if err != nil {
				return err
			}
			// Named in configuration is an authorization to sign in, so the
			// way they will sign in is recorded with it. Without this the
			// named administrator would exist and have no door to come
			// through.
			if err := within.Claim(ctx, person.ID, identity); err != nil {
				return err
			}
			// Named here, and readmitted. This is the documented way back
			// into a deployment nobody can administer, and it did not work
			// for the case that produces one: a departed administrator is
			// refused at sign-in, and nothing else clears the date. Naming
			// them in configuration is the deliberate act of letting them
			// back in, so it is the act that undoes it.
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
}
