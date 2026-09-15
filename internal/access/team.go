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
		// A read that could not be made is not an answer about what exists:
		// every caller turns the sentinel into "no such team", and a database
		// nobody can reach would have said that of every team there is.
		return nil, database.FromRead(err, ErrNoSuchTeam,
			fmt.Sprintf("look up the team called %q", name))
	}
	return team, nil
}

// Teams lists the teams in use, by name.
//
// Bounded like every other listing. A picker declaring that it returns
// twenty-five names appended every team there is after them, so a deployment
// with two hundred teams answered a bounded question with an unbounded list.
//
// The term narrows in the statement rather than after it: filtering a bounded
// read in the caller cuts before the match is looked for, so a team whose name
// sorts late would be missing from a search that names it exactly.
func (s *Store) Teams(ctx context.Context, term string, limit int) ([]Team, error) {
	var teams []Team
	query := narrowTeams(s.db.NewSelect().Model(&teams), term).
		Order("name").
		// Read in bulk rather than a screenful at a time: the picker asks for
		// a screenful and the two callers that want every team say so with
		// this kind's own ceiling. Bounded as a list somebody pages through,
		// "all of them" fell past the 200 ceiling and took the 50-row default
		// — so a deployment past fifty teams rendered every routing rule owned
		// by an alphabetically-later team with a blank team name.
		Limit(database.InBulk.Of(limit))
	if err := query.Scan(ctx); err != nil {
		return nil, fmt.Errorf("read which teams there are: %w", err)
	}
	return teams, nil
}

// CountTeams is how many teams a term matches, in all.
//
// The same narrowing as the listing above, so a picker showing a few of them
// can say how many there are without counting the few it was handed.
func (s *Store) CountTeams(ctx context.Context, term string) (int, error) {
	total, err := narrowTeams(s.db.NewSelect().Model((*Team)(nil)), term).Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count which teams there are: %w", err)
	}
	return total, nil
}

// narrowTeams is the team listing's own matching, spelled once so the listing
// and the count of it cannot come to narrow differently.
func narrowTeams(query *bun.SelectQuery, term string) *bun.SelectQuery {
	query = query.Where("retired_at IS NULL")
	wanted := strings.TrimSpace(term)
	if wanted == "" {
		return query
	}
	// Matched without regard to capitals, the way every name a person types is
	// matched here, and escaped: a search box is not a pattern language, and a
	// term of "%" would answer with every team there is.
	like := database.LikeContains(wanted)
	return query.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.WhereOr(`LOWER("name") LIKE ?`+database.LikeClause, like).
			WhereOr(`LOWER(COALESCE(NULLIF("display_name", ''), "name")) LIKE ?`+
				database.LikeClause, like)
	})
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
//
// A removal that matched nothing is ErrNothingMatched, like every other write
// here that takes access away: taking somebody off a team they were never on
// otherwise answered as though it had happened, and the caller wrote a trail
// row saying a membership was ended that never existed. Membership is what
// routes an undisclosed finding to somebody, so a trail that says who stopped
// receiving them is a record of who could have seen what.
func (s *Store) RemoveFromTeam(ctx context.Context, teamID, personID int64) error {
	res, err := s.db.NewDelete().Model((*Membership)(nil)).
		Where("team_id = ?", teamID).Where("person_id = ?", personID).Exec(ctx)
	if err != nil {
		return fmt.Errorf("take that person off the team: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return fmt.Errorf("take that person off the team: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("they are not on that team: %w", ErrNothingMatched)
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
	// Somebody who has left reads nothing, whatever their grants still say.
	// Deactivation leaves the grant rows in place on purpose — it is the
	// recorded act of leaving rather than an undoing of what they held — so
	// every question of this shape has to ask the person as well.
	here, err := s.here(ctx, personID)
	if err != nil || !here {
		return false, err
	}
	reads, err := holdingAny(s.db.NewSelect().
		TableExpr(`"person" AS "p"`).ColumnExpr("p.id").
		Where("p.id = ?", personID), "p.id", enough, productID).Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether they may see this: %w", err)
	}
	return reads, nil
}

// here reports whether this person is still someone the deployment answers
// for: recorded, and not deactivated.
//
// One spelling, because "may this person do this" has to exclude somebody who
// has left at every site that asks it, and it excluded them at one — the
// mention picker, whose own doc gives the reason: they are refused at sign-in,
// so offering their name mentions somebody who will never see it. The same
// sentence applies to routing work to them and to counting administrators, and
// was carried to neither.
func (s *Store) here(ctx context.Context, personID int64) (bool, error) {
	live, err := s.db.NewSelect().Model((*Account)(nil)).
		Where("id = ?", personID).
		Where("deactivated_at IS NULL").
		Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether they are still here: %w", err)
	}
	return live, nil
}

// holdingAny narrows a query to the rows whose person holds one of these roles
// here: granted on the product, or granted across every product, both in force.
//
// One builder, because the union was written out at every question that asked
// it inside this package — and this package was exactly where
// `internal/tools/granted` could not reach, since that gate refused a query
// naming one table and not the other *outside* here. DESIGN-access.md records
// what the union costs when it is spelled by hand: predicates missed
// role_grant_all the day it was added, "each answering no for somebody who held
// the role — which compiles and passes".
//
// person names the column holding the person in the caller's own query, so the
// same rule attaches to a query about one person, about a team's members, or
// about everybody who may be mentioned. It is written at the call site and
// never supplied by anybody: a column name cannot be bound by a placeholder,
// and the only safe source for one is the code (REQ-66).
//
// Two EXISTS rather than a union, because that is the shape all four engines
// take: a union inside an EXISTS is a syntax error on SQLite.
func holdingAny(q *bun.SelectQuery, person string, enough []Role, productID int64) *bun.SelectQuery {
	return q.Where(`EXISTS (SELECT 1 FROM "role_grant" AS "g"
			WHERE g.person_id = `+person+` AND g.active = ?
			  AND g.product_id = ? AND g.role IN (?))
		OR EXISTS (SELECT 1 FROM "role_grant_all" AS "ga"
			WHERE ga.person_id = `+person+` AND ga.active = ?
			  AND ga.role IN (?))`,
		true, productID, bun.List(enough), true, bun.List(enough))
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
	// A member who has left is not a member who can read it. The team is a
	// queue, and one whose only qualifying member is gone is a queue nobody
	// working the product can see — the argument the administrator case above
	// already makes, for a case nobody made it for.
	reads, err := holdingAny(s.db.NewSelect().
		TableExpr(`"team_member" AS "tmm"`).
		Join(`JOIN "person" AS "pe" ON pe.id = tmm.person_id`).
		ColumnExpr("tmm.person_id").
		Where("tmm.team_id = ?", teamID).
		Where("pe.deactivated_at IS NULL"), "tmm.person_id", enough, productID).Exists(ctx)
	if err != nil {
		return false, fmt.Errorf("read whether anybody on that team may see this: %w", err)
	}
	return reads, nil
}
