// Package trail records what somebody changed about how this deployment works.
//
// Not what was triaged — that is the decision history, and it is kept beside
// the decisions. This is the layer above: the settings, grants and dates that
// decide what the triage record *says*.
package trail

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Kind is what sort of thing was changed. A reader filters by it, so the set
// is small and named for what somebody would look for rather than for which
// table was written.
type Kind string

const (
	// Setting is a value in the settings, including the three that rewrite
	// what the tool reports: the deadline windows, the triage floor, and how
	// roles are assigned.
	Setting Kind = "setting"
	// Role is a grant or a withdrawal against one product.
	Role Kind = "role"
	// Support is an end-of-life date on a product or a release, which takes
	// the deadline off everything in it.
	Support Kind = "support"
	// Credential is a key or a token: made, or revoked.
	Credential Kind = "credential"
	// Account is somebody recorded, which is the act that lets them in at all.
	Account Kind = "account"
	// Team is a team declared or retired, or somebody put on one or taken off.
	Team Kind = "team"
	// Release is when a tag went out and what it was cut from. Both are
	// recorded after the fact and both change what a chart and a set of
	// release notes say, so who moved them is the same question as who moved
	// an end-of-life date.
	Release Kind = "release"
	// Case is somebody brought into one undisclosed case, or taken off it
	// . An access change like the rest of these: it is the one way
	// somebody reaches an embargoed finding without holding private
	// reading on the product, so who was let in and when is exactly what
	// is asked afterwards.
	Case Kind = "case"
)

// Change is one administrative act.
type Change struct {
	bun.BaseModel `bun:"table:admin_change,alias:ac"`

	ID int64     `bun:"id,pk,autoincrement"`
	At time.Time `bun:"at,notnull"`
	// By is who did it. Never absent: a change nobody made is a change nothing
	// records, which is the state this exists to end.
	By   int64  `bun:"by,notnull"`
	Kind Kind   `bun:"kind,notnull"`
	Name string `bun:"about,notnull"`
	// Was is what it held before and Became what it holds now. Absent before
	// means nobody had set it; absent after means it was cleared. The two are
	// different acts and a blank cannot tell them apart.
	Was    *string `bun:"was"`
	Became *string `bun:"became"`
}

// Store reads and writes the trail.
type Store struct {
	db  bun.IDB
	now func() time.Time
}

func NewStore(db bun.IDB) *Store {
	return &Store{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Record writes one administrative act.
//
// Called where the actor is known, which is the request that made the change:
// the stores underneath take no subject, and threading one through every
// setting write to reach this would make a signature about auditing rather
// than about the thing being written.
//
// **A failure here is not a failure of the change.** The change has happened;
// answering with an error would invite a retry that makes it twice. The caller
// logs and carries on, which is the same choice the assignment notification
// makes for the same reason.
func (s *Store) Record(ctx context.Context, by access.Subject, kind Kind, name string,
	was, became *string) error {

	if by.Kind != access.Person || by.ID == 0 {
		return fmt.Errorf("an administrative change is recorded against whoever made it")
	}
	change := &Change{
		At: s.now().Truncate(time.Microsecond), By: by.ID,
		Kind: kind, Name: name, Was: was, Became: became,
	}
	if _, err := s.db.NewInsert().Model(change).Exec(ctx); err != nil {
		return fmt.Errorf("record that %q changed: %w", name, err)
	}
	return nil
}

// Changes reads the trail, newest first, optionally of one kind.
//
// Paged, because it only grows: a deployment a year old has every setting
// anybody ever moved in it, and a screen that asks for all of them is one that
// stops answering.
func (s *Store) Changes(ctx context.Context, kind Kind, limit, offset int) ([]Change, int, error) {
	limit = database.AList.Of(limit)
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		if kind != "" {
			q = q.Where("kind = ?", kind)
		}
		return q
	}

	total, err := narrow(s.db.NewSelect().Model((*Change)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count what has been changed: %w", err)
	}
	var changes []Change
	err = narrow(s.db.NewSelect().Model(&changes)).
		Order("at DESC", "id DESC").
		Limit(limit).Offset(offset).
		Scan(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read what has been changed: %w", err)
	}
	return changes, total, nil
}

// About reads the trail for one subject of a change, newest first.
//
// The trail names what changed rather than pointing at it — a role change is
// recorded as "somebody on some product" — so this asks for the name and for
// every name beginning with it followed by " on ". That covers a role, which is
// per product, and a change recorded against the bare name.
//
// **What LIKE treats as special is escaped.** An identity is an email address
// and "_" is a wildcard, so `a_b@example.com` would otherwise match
// `axb@example.com` and report somebody else's history as this person's. The
// escape character is "#" rather than a backslash, because a backslash inside a
// string literal is itself an escape on two of the four engines and `ESCAPE
// '\'` does not parse there at all — the same reason the routing rules use it.
func (s *Store) About(ctx context.Context, kind Kind, name string,
	limit, offset int) ([]Change, int, error) {

	limit = database.AList.Of(limit)
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		if kind != "" {
			q = q.Where("kind = ?", kind)
		}
		return q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("about = ?", name).
				WhereOr(`about LIKE ?`+database.LikeClause, database.LikeEscaped(name)+" on %")
		})
	}

	total, err := narrow(s.db.NewSelect().Model((*Change)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count what changed about %q: %w", name, err)
	}
	var changes []Change
	err = narrow(s.db.NewSelect().Model(&changes)).
		Order("at DESC", "id DESC").
		Limit(limit).Offset(offset).
		Scan(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("read what changed about %q: %w", name, err)
	}
	return changes, total, nil
}

// Said turns a value into what the trail stores, where absent means unset.
func Said(value string, set bool) *string {
	if !set {
		return nil
	}
	return &value
}
