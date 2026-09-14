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

// Team is a named set of people that holds work and grants nothing.
//
// Belonging to one says nothing about what somebody may read or do. That is
// what lets a team carry mixed clearance, which is the ordinary arrangement
// rather than a misconfiguration: a kernel team where two members may read
// undisclosed work and four may not.
type Team struct {
	bun.BaseModel `bun:"table:team,alias:tm"`

	ID int64 `bun:"id,pk,autoincrement"`
	// PartyID is what work is routed to. A team and a person share one
	// name space so that "who holds this" is one question.
	PartyID int64 `bun:"party_id,notnull"`
	// Name is what is matched, stored normalized, and DisplayName is the
	// spelling somebody typed, which is what gets shown back.
	Name        string `bun:"name,notnull"`
	DisplayName string `bun:"display_name"`
	// RetiredAt takes a team out of use without deleting it. Work already
	// routed to it has to keep resolving to something a screen can name.
	RetiredAt *time.Time `bun:"retired_at"`
	CreatedAt time.Time  `bun:"created_at,notnull"`
}

// Called is the spelling to show, which is the typed one where there is one.
func (t Team) Called() string {
	if t.DisplayName != "" {
		return t.DisplayName
	}
	return t.Name
}

// Membership is one person on one team. It carries who put them there, for the
// same reason every other grant does.
type Membership struct {
	bun.BaseModel `bun:"table:team_member,alias:tmm"`

	TeamID   int64     `bun:"team_id,pk"`
	PersonID int64     `bun:"person_id,pk"`
	AddedAt  time.Time `bun:"added_at,notnull"`
	AddedBy  int64     `bun:"added_by,notnull"`
}

// ErrNoSuchTeam is returned when a name matches no team in use.
var ErrNoSuchTeam = errors.New("no team is known by that name")

// DeclareTeam records a team, or returns the one already declared under that
// name.
//
// Declaring rather than creating, the way a product is: the same name arriving
// twice is one team, and a second call is how a deployment script stays
// runnable.
func (s *Store) DeclareTeam(ctx context.Context, name, displayName string) (*Team, error) {
	matched := teamNamed(name)
	if matched == "" {
		return nil, fmt.Errorf("a team needs a name")
	}
	shown := strings.TrimSpace(displayName)

	db, ok := database.Handle(s.db)
	if !ok {
		return nil, fmt.Errorf("this store is already inside a transaction")
	}

	team := new(Team)
	// Both statements or neither, for the reason a person and their party
	// are written together: a team nothing can be routed to is not a team.
	// And the lookup is inside, because a retry runs against a database
	// that has moved and what it decides is whether to insert.
	err := database.InTransaction(ctx, db, func(ctx context.Context, tx bun.Tx) error {
		*team = Team{}
		found := new(Team)
		err := tx.NewSelect().Model(found).
			Where("name = ?", matched).Limit(1).Scan(ctx)
		switch {
		case err == nil && found.RetiredAt == nil:
			*team = *found
			return nil
		case err == nil:
			// Retired, and declaring the name again brings it back. The name
			// is unique across retired teams too — work already routed to one
			// has to keep resolving to something a screen can name, so the row
			// stays — and inserting a second team under the same name would be
			// refused by the index with a message about a team that is not
			// there as far as anybody can see. Reinstating is also what
			// somebody typing a name they retired last week means.
			if _, err := tx.NewUpdate().Model((*Team)(nil)).
				Set("retired_at = ?", nil).
				Set("display_name = ?", shown).
				Where("id = ?", found.ID).Exec(ctx); err != nil {
				return err
			}
			found.RetiredAt, found.DisplayName = nil, shown
			*team = *found
			return nil
		}

		party := &Party{Kind: ATeam}
		if _, err := tx.NewInsert().Model(party).Exec(ctx); err != nil {
			return err
		}
		fresh := &Team{
			PartyID: party.ID, Name: matched, DisplayName: shown,
			CreatedAt: s.now().Truncate(time.Microsecond),
		}
		if _, err := tx.NewInsert().Model(fresh).Exec(ctx); err != nil {
			return err
		}
		*team = *fresh
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("record the team %q: %w", name, err)
	}
	return team, nil
}

// TeamByName reads a team by the name people type. A retired one is not found:
// nothing new is routed to it, and it is absent from every list. The name is
// not free, though — the row stays so that work already routed to it resolves
// to something a screen can name — so declaring that name again reinstates
// the team rather than making a second one.
func (s *Store) TeamByName(ctx context.Context, name string) (*Team, error) {
	team := new(Team)
	err := s.db.NewSelect().Model(team).
		Where("name = ?", teamNamed(name)).
		Where("retired_at IS NULL").
		Limit(1).Scan(ctx)
	if err != nil {
		return nil, ErrNoSuchTeam
	}
	return team, nil
}

// Teams lists the teams in use, by name.
func (s *Store) Teams(ctx context.Context) ([]Team, error) {
	var teams []Team
	if err := s.db.NewSelect().Model(&teams).
		Where("retired_at IS NULL").
		Order("name").Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which teams there are: %w", err)
	}
	return teams, nil
}

// RetireTeam takes a team out of use. Its membership goes with it — the team
// is not somewhere work arrives any more, and a list of people who used to be
// on it is a record nobody asked for — while the row and its party stay, so
// that work routed to it before still names something.
func (s *Store) RetireTeam(ctx context.Context, teamID int64) error {
	write := func(ctx context.Context, db bun.IDB) error {
		if _, err := db.NewDelete().Model((*Membership)(nil)).
			Where("team_id = ?", teamID).Exec(ctx); err != nil {
			return err
		}
		res, err := db.NewUpdate().Model((*Team)(nil)).
			Set("retired_at = ?", s.now().Truncate(time.Microsecond)).
			Where("id = ?", teamID).
			Where("retired_at IS NULL").
			Exec(ctx)
		if err != nil {
			return err
		}
		n, err := database.Affected(res)
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrNoSuchTeam
		}
		return nil
	}
	err := database.Within(ctx, s.db, write)
	if err != nil && !errors.Is(err, ErrNoSuchTeam) {
		return fmt.Errorf("retire that team: %w", err)
	}
	return err
}

// AddToTeam puts somebody on a team. Saying it twice is not an error: what is
// being asserted is that they are on it.
//
// Read then written rather than as one upsert, because there is no portable
// spelling of one — two of the four engines want ON CONFLICT and the other two
// ON DUPLICATE KEY UPDATE, and engine-specific SQL stays out of the core .
// Both statements in one transaction, so what the read saw is what the write
// writes against; two administrators adding the same person at once resolve
// against the primary key.
func (s *Store) AddToTeam(ctx context.Context, teamID, personID, by int64) error {
	add := func(ctx context.Context, db bun.IDB) error {
		on, err := db.NewSelect().Model((*Membership)(nil)).
			Where("team_id = ?", teamID).Where("person_id = ?", personID).Count(ctx)
		if err != nil {
			return err
		}
		if on > 0 {
			return nil
		}
		_, err = db.NewInsert().Model(&Membership{
			TeamID: teamID, PersonID: personID,
			AddedAt: s.now().Truncate(time.Microsecond), AddedBy: by,
		}).Exec(ctx)
		return err
	}
	if err := database.Within(ctx, s.db, add); err != nil {
		return fmt.Errorf("put that person on the team: %w", err)
	}
	return nil
}

// RemoveFromTeam takes somebody off a team. What they have already taken is
// theirs and stays theirs: membership says where work arrives, not who holds
// what has arrived.
func (s *Store) RemoveFromTeam(ctx context.Context, teamID, personID int64) error {
	_, err := s.db.NewDelete().Model((*Membership)(nil)).
		Where("team_id = ?", teamID).Where("person_id = ?", personID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("take that person off the team: %w", err)
	}
	return nil
}

// MembersOf lists who is on a team, by person.
func (s *Store) MembersOf(ctx context.Context, teamID int64) ([]int64, error) {
	var people []int64
	if err := s.db.NewSelect().Model((*Membership)(nil)).
		Column("person_id").
		Where("team_id = ?", teamID).
		Order("person_id").Scan(ctx, &people); err != nil {
		return nil, fmt.Errorf("read who is on that team: %w", err)
	}
	return people, nil
}

// TeamsOf lists the teams somebody is on, in use only.
//
// Read on every request that resolves a subject, because "assigned to me"
// means mine or my team's everywhere the phrase appears.
func (s *Store) TeamsOf(ctx context.Context, personID int64) ([]Team, error) {
	var teams []Team
	err := s.db.NewSelect().Model(&teams).
		Join(`JOIN "team_member" AS "tmm" ON tmm.team_id = tm.id`).
		Where("tmm.person_id = ?", personID).
		Where("tm.retired_at IS NULL").
		Order("tm.name").Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read which teams somebody is on: %w", err)
	}
	return teams, nil
}

// teamNamed folds a team name the way every other name people type is folded :
// normalized on the way in, so every engine compares it the same without any
// of them being asked to compare loosely.
func teamNamed(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Held is who a party is, for a screen that has an assignment and needs a name
// for it.
type Held struct {
	// Party is the name in the assignable space, which is what the assignment
	// column holds.
	Party int64
	// Name is what to show. A person's display name or sign-in identity, or a
	// team's.
	Name string
	// Team says this is a queue rather than a holding: work routed here is
	// unheld until somebody takes it.
	Team bool
}

// WhoHolds resolves parties to names, whether each is a person or a team.
//
// One call for both, because a screen holding an assignment does not know
// which it has — that is the point of one column — and asking two tables at
// every call site is how the two answers come to disagree.
func (s *Store) WhoHolds(ctx context.Context, parties []int64) (map[int64]Held, error) {
	held := map[int64]Held{}
	if len(parties) == 0 {
		return held, nil
	}
	var people []Account
	if err := s.db.NewSelect().Model(&people).
		Column("party_id", "identity", "display_name").
		Where("party_id IN (?)", bun.List(parties)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who holds these: %w", err)
	}
	for _, person := range people {
		name := person.DisplayName
		if name == "" {
			name = person.Identity
		}
		held[person.PartyID] = Held{Party: person.PartyID, Name: name}
	}
	var teams []Team
	if err := s.db.NewSelect().Model(&teams).
		Column("party_id", "name", "display_name").
		Where("party_id IN (?)", bun.List(parties)).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which teams hold these: %w", err)
	}
	for _, team := range teams {
		held[team.PartyID] = Held{Party: team.PartyID, Name: team.Called(), Team: true}
	}
	return held, nil
}

// PersonReads reports whether one person may read a finding of this visibility
// in this product.
//
// The question assigning asks: an assignment carries visibility of what was
// assigned, so what is left to check is the *level* — public against embargoed
// — rather than whether they can already see that row, which before the
// assignment they cannot by construction. Handing an embargoed finding to
// somebody cleared for nothing embargoed would make the assignment itself the
// disclosure.
func (s *Store) PersonReads(ctx context.Context, personID, productID int64,
	visibility Visibility) (bool, error) {

	enough := rolesReading(productID, visibility)
	if len(enough) == 0 {
		return false, nil
	}
	reads, err := s.db.NewSelect().
		TableExpr(`role_grant AS "rg"`).
		Column("rg.id").
		Where("rg.person_id = ?", personID).
		Where("rg.product_id = ?", productID).
		Where("rg.active = ?", true).
		Where("rg.role IN (?)", bun.List(enough)).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether they may see this: %w", err)
	}
	if reads {
		return true, nil
	}
	// A role held across every product is held here too. Asked as a second
	// statement rather than folded into the one above, because this table
	// names no product and a join would have to invent one.
	everywhere, err := s.db.NewSelect().
		TableExpr(`role_grant_all AS "rga"`).
		Column("rga.id").
		Where("rga.person_id = ?", personID).
		Where("rga.active = ?", true).
		Where("rga.role IN (?)", bun.List(enough)).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether they may see this anywhere: %w", err)
	}
	return everywhere, nil
}

// rolesReading is which roles are enough to read at a visibility, asked of the
// same rule every query uses rather than spelled again — so "may read" cannot
// come to mean two things.
func rolesReading(productID int64, visibility Visibility) []Role {
	var enough []Role
	for _, role := range Roles() {
		if NewPerson(0, "", false, map[int64][]Role{productID: {role}}, 0).
			Reads(visibility, productID) {
			enough = append(enough, role)
		}
	}
	return enough
}

// AnyMemberReads reports whether at least one person on a team may read a
// finding of this visibility in this product.
//
// Not every member: requiring that would turn routing pressure into access
// pressure — an administrator granting somebody private reading so that a
// queue works is an access decision made as a workflow convenience, and it
// arrives one team at a time. Requiring nobody is the failure in the other
// direction: work that shows as held in every administrative view and sits in
// nobody's list.
//
// Asked of the same rule every query uses rather than spelled again here, so
// that "may read" cannot come to mean two things.
func (s *Store) AnyMemberReads(ctx context.Context, teamID, productID int64,
	visibility Visibility) (bool, error) {

	enough := rolesReading(productID, visibility)
	if len(enough) == 0 {
		return false, nil
	}
	// An administrator is not counted. Administration is not a read grant
	// , and a team whose only qualifying member is an administrator is a
	// queue nobody working the product can see.
	reads, err := s.db.NewSelect().
		TableExpr(`team_member AS "tmm"`).
		Join(`JOIN "role_grant" AS "rg" ON rg.person_id = tmm.person_id`).
		Column("tmm.person_id").
		Where("tmm.team_id = ?", teamID).
		Where("rg.product_id = ?", productID).
		Where("rg.active = ?", true).
		Where("rg.role IN (?)", bun.List(enough)).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether anybody on that team may see this: %w", err)
	}
	if reads {
		return true, nil
	}
	everywhere, err := s.db.NewSelect().
		TableExpr(`team_member AS "tmm"`).
		Join(`JOIN "role_grant_all" AS "rga" ON rga.person_id = tmm.person_id`).
		Column("tmm.person_id").
		Where("tmm.team_id = ?", teamID).
		Where("rga.active = ?", true).
		Where("rga.role IN (?)", bun.List(enough)).
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether anybody on that team may see this anywhere: %w", err)
	}
	return everywhere, nil
}
