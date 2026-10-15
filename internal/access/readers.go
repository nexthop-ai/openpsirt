// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"context"
	"fmt"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/typedname"
	"github.com/uptrace/bun"
)

// Names resolves people to what to call them, for showing who did something.
//
// A display name where one is known, and the identity they signed in with
// otherwise. Batched because the alternative is a query per row, and the
// places this is needed — a review queue, a list of what was dismissed — are
// exactly the ones that are long.
//
// Its answer is never sent back to a lookup. A display name is a
// label somebody chose and resolves to nobody; Handles is what a route naming
// a person in its path matches.
func (s *Store) Names(ctx context.Context, ids []int64) (map[int64]string, error) {
	names, err := database.NamesByID(ctx, s.db, `"person"`,
		database.Composed(`COALESCE(NULLIF("display_name", ''), "identity")`), ids)
	if err != nil {
		return nil, fmt.Errorf("read who these people are: %w", err)
	}
	return names, nil
}

// Handles resolves people to the identity they sign in under.
//
// Beside Names, and the other half of it: Names is for showing and this is for
// resolving, and wherever somebody has a display name the two are different
// strings. ByIdentity matches the folded identity column alone, so a list that
// publishes a display name in a field a route resolves cannot be acted on: a
// collaborator on an embargoed case listed that way cannot be removed.
//
// Batched, for the reason Names is.
func (s *Store) Handles(ctx context.Context, ids []int64) (map[int64]string, error) {
	handles, err := database.NamesByID(ctx, s.db, `"person"`, `"identity"`, ids)
	if err != nil {
		return nil, fmt.Errorf("read what these people sign in as: %w", err)
	}
	return handles, nil
}

// Mentionable is somebody who could be named in text about a product.
type Mentionable struct {
	// ID is who they are, for telling them. It is not offered to a caller —
	// the editor needs the name to write and nothing else — and it is here so
	// that whoever may be *offered* and whoever may be *told* come from one
	// query rather than two that could come to disagree.
	ID       int64  `bun:"id"`
	Identity string `bun:"identity"`
	Name     string `bun:"name"`
}

// WhoCanRead lists the people who may read findings of this visibility in this
// product, for offering as mentions.
//
// Offering only people who can already see the thing is the whole point.
// An autocomplete that lists everybody teaches somebody to mention a colleague
// who then cannot open what they were called to, and on an undisclosed finding
// the mention itself says that a finding exists — which is the disclosure the
// visibility rule is there to prevent.
//
// An administrator is not included for being one. Administering the
// catalog is not reading its findings, which is the split the roles were
// separated to make possible — so an administrator holding nothing on the
// product was offered as a mention target on an undisclosed finding there,
// and the mention itself told them a finding exists that they may not open.
// One who wants to be mentionable grants themselves a read role, which is how
// everything else here works.
//
// Inactive grants are read past entirely, the same way every other question
// about what somebody holds reads past them, and so is somebody who has left:
// they are refused at sign-in, so offering their name mentions somebody who
// will never see it.
func (s *Store) WhoCanRead(ctx context.Context, subject Subject, productID int64,
	visibility Visibility, term string, limit int) ([]Mentionable, error) {

	// A request for who may read something undisclosed is itself about
	// undisclosed work, and the answer is the one every other read gives:
	// nothing. Asked here rather than only at the handlers that call it,
	// because an endpoint over this query that forgot to ask would answer for
	// everybody, and visibility is carried on the query rather than written
	// out at each caller.
	if !subject.Reads(visibility, productID) {
		return nil, nil
	}
	limit = database.APicker.Of(limit)

	query := s.readersIn(productID, visibility)
	if query == nil {
		return nil, nil
	}
	query = narrowToTerm(query.OrderExpr(`"p"."identity"`).Limit(limit), term)
	// Narrowed here rather than in the caller, because a picker at a
	// hundred people cannot fetch them all and filter in a browser — and
	// the limit would cut the list before the term did, so the name
	// somebody typed would be missing from a list that says it matched
	// nothing.
	//
	// Lowered on both sides rather than asked to compare loosely: the
	// engines do not agree on what a case-insensitive comparison is, and
	// one spelled the same way everywhere behaves the same way everywhere.
	//
	// Folded here and again by the engine, and this is the caller where that
	// still costs something. Folding in Go is Unicode-aware and LOWER() on
	// SQLite is ASCII-only, so a display name carrying a non-ASCII capital is
	// found on three engines and missed on the fourth. An identity is an
	// address and ASCII; a display name is free human text and has no folded
	// column to compare against, unlike the component names that do.
	//
	// Escaped, because a search box is not a pattern language: a term of "%"
	// matched every person the deployment could offer, in one request, from
	// the picker that decides who may be named on an embargoed case.
	var found []Mentionable
	if err := query.Scan(ctx, &found); err != nil {
		return nil, fmt.Errorf("read who may be mentioned: %w", err)
	}
	return found, nil
}

// narrowToTerm is the picker's own matching, spelled once so the page and the
// count of it cannot come to narrow differently.
func narrowToTerm(query *bun.SelectQuery, term string) *bun.SelectQuery {
	return database.LikeNameOrShown(query, bun.Ident("p.identity"), bun.Ident("p.display_name"), term)
}

// CountWhoCanRead is how many the picker has to choose from in all.
//
// The same narrowing as the page above, so a listing that says "25 of 140" is
// counting the thing it is showing part of. Asked as its own statement rather
// than read off the page, for the reason every capped listing here states: a
// figure taken from a page answers a different question from the one it looks
// like.
func (s *Store) CountWhoCanRead(ctx context.Context, subject Subject, productID int64,
	visibility Visibility, term string) (int, error) {

	if !subject.Reads(visibility, productID) {
		return 0, nil
	}
	query := s.readersIn(productID, visibility)
	if query == nil {
		return 0, nil
	}
	total, err := narrowToTerm(query, term).Count(ctx)
	if err != nil {
		return 0, fmt.Errorf("count who may be mentioned: %w", err)
	}
	return total, nil
}

// ReadersNamed resolves these sign-in identities to the people among them who
// may read findings of this visibility in this product.
//
// The resolver behind a mention, and the reason it is not the picker's query
// with a different argument: the picker narrows by what somebody typed and
// then takes a page, and a mention has a name in hand and needs the answer
// for that name. Paging the picker instead answered from the
// alphabetically-first hundred readers, so mentioning anybody sorting past
// position one hundred reached nobody, deterministically, and the author was
// told the name matched nobody — a failure that grows with the deployment.
//
// A name nobody holds and a name held by somebody who may not read this both
// come back absent, and are not told apart.
func (s *Store) ReadersNamed(ctx context.Context, subject Subject, productID int64,
	visibility Visibility, names []string) ([]Mentionable, error) {

	// The same gate the picker carries, for the same reason: what this answers
	// is who may read something, which is a fact about the thing being read.
	if !subject.Reads(visibility, productID) {
		return nil, nil
	}
	query := s.readersIn(productID, visibility)
	if query == nil || len(names) == 0 {
		return nil, nil
	}
	wanted := make([]string, 0, len(names))
	for _, name := range names {
		wanted = append(wanted, typedname.Matching(name))
	}
	// Lowered on both sides rather than asked to compare loosely, for the
	// reason the picker does it: the engines do not agree on what a
	// case-insensitive comparison is.
	var found []Mentionable
	if err := query.Where(`LOWER("p"."identity") IN (?)`, bun.List(wanted)).
		Scan(ctx, &found); err != nil {
		return nil, fmt.Errorf("read who may be told: %w", err)
	}
	return found, nil
}

// readersIn is the half the picker and the mention resolver share: the people
// who may read findings of this visibility in this product.
//
// Nil where no role reaches that visibility at all, which is an answer rather
// than an empty condition to be filled in.
func (s *Store) readersIn(productID int64, visibility Visibility) *bun.SelectQuery {
	// The roles enough to read at this visibility, asked of the rule
	// rather than of a list: one spelling, so "may read" means one thing.
	enough := rolesReading(productID, visibility)
	if len(enough) == 0 {
		return nil
	}
	return holdingAny(s.db.NewSelect().
		TableExpr(`"person" AS "p"`).
		ColumnExpr(`"p"."id" AS "id"`).
		ColumnExpr(`"p"."identity" AS "identity"`).
		ColumnExpr(`COALESCE(NULLIF("p"."display_name", ''), "p"."identity") AS "name"`).
		Where(`"p"."deactivated_at" IS NULL`), `"p"."id"`, enough, productID)
}
