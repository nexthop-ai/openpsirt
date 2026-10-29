// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// The people a condition reaches.
//
// Shared by all three groups of conditions — the waits in stale.go, the
// operational alerts in watch.go, and the embargo conditions in disclosure.go
// — and belonging to none of them, so the question has one answer.

// acts is what one person may do with one product, as the questions these
// conditions ask of it.
//
// Approving and reading are separate: Approver is a capability bounded by what
// the person may read, so a decision waiting goes to somebody who holds both and
// to nobody who holds one.
//
// Reading and triaging are kept apart rather than folded into one pair,
// because the conditions divide on exactly that: a message about work waiting
// goes to whoever may *act*, and one about something that has happened goes to
// whoever may read it.
//
// A condition about findings asks of two classes of row: disclosed, and
// withheld, which is every other visibility. A withheld row is told to
// whoever reads or triages private work. A condition about decisions asks of
// three, because a decision on a code finding is security testing work, which a reader of
// undisclosed work does not read (rows).
type acts struct {
	approves                                                 bool
	readsPublic, readsPrivate, triagesPublic, triagesPrivate bool
	readsSecurityTesting, triagesSecurityTesting             bool
}

// reads is what a condition sent to whoever may read it asks, of something
// disclosed or withheld. Each visibility is its own grant, so neither answers
// for the other.
func (a acts) reads(private bool) bool {
	if private {
		return a.readsPrivate
	}
	return a.readsPublic
}

// rows is how many rows of a decision sit at each visibility.
type rows struct{ public, private, securityTesting int }

// rowsOf splits a count of a decision's rows by the withheld and security testing rows
// among them.
func rowsOf(all, withheld, securityTesting int) rows {
	return rows{public: all - withheld, private: withheld - securityTesting, securityTesting: securityTesting}
}

// told is the marks a condition about these rows carries.
func (r rows) told() (private, securityTesting bool) {
	return r.private+r.securityTesting > 0, r.securityTesting > 0
}

// readsAll is whether they read every row of something spanning
// visibilities: a decision may mix disclosed and undisclosed occurrences, and a
// condition about it is sent to somebody who reads every one of them.
func (a acts) readsAll(r rows) bool {
	return (r.public == 0 || a.readsPublic) && (r.private == 0 || a.readsPrivate) &&
		(r.securityTesting == 0 || a.readsSecurityTesting)
}

// approvesAll is whether they may agree to every row of something spanning
// visibilities: the rule a signed-in approver is held to, at each
// visibility the rows are at.
func (a acts) approvesAll(r rows) bool {
	return (r.public == 0 || access.MayApprove(access.Public, a.approves, a.readsPublic, a.triagesPublic)) &&
		(r.private == 0 || access.MayApprove(access.Private, a.approves, a.readsPrivate, a.triagesPrivate)) &&
		(r.securityTesting == 0 || access.MayApprove(access.SecurityTesting, a.approves, a.readsSecurityTesting, false))
}

// readsIn is whether they read the product at any visibility: the question
// for something about the product that names no finding.
func (a acts) readsIn() bool { return a.readsPublic || a.readsPrivate || a.readsSecurityTesting }

// triages is the same question for a condition sent to whoever may act: a
// reader who cannot argue about a product can do nothing about work sitting in
// it, and telling them is noise.
func (a acts) triages(private bool) bool {
	if private {
		return a.triagesPrivate
	}
	return a.triagesPublic
}

// whoActs is everybody, with what they may do with each product.
//
// Read once per sweep rather than per condition, and once per upload where one
// upload is what raised the question. Every condition asking the
// same two tables is that much more work to answer one question, and — the
// part that matters more — that many places for "may read" to be spelled
// slightly differently.
func whoActs(ctx context.Context, db bun.IDB) (map[int64]map[int64]acts, error) {
	people, held, err := access.NewStore(db).PeopleReaching(ctx)
	if err != nil {
		return nil, fmt.Errorf("read who may hear about this: %w", err)
	}
	return actsOf(present(people), held), nil
}

// present is the people who have not left.
//
// Every audience starts from it. A departed person's grants stay in place, so
// a question answered from grants alone would keep telling somebody who has
// left (design-docs/access-grants.md § Somebody who has left).
func present(people []access.Account) []access.Account {
	out := make([]access.Account, 0, len(people))
	for _, person := range people {
		if person.DeactivatedAt == nil {
			out = append(out, person)
		}
	}
	return out
}

// actsOf is whoActs over people and grants already read.
func actsOf(people []access.Account, held map[int64][]access.Grant) map[int64]map[int64]acts {
	out := make(map[int64]map[int64]acts, len(people))
	for _, person := range people {
		per := map[int64]acts{}
		for _, grant := range held[person.ID] {
			if !grant.Active {
				continue
			}
			at := per[grant.ProductID]
			switch grant.Role {
			case access.Approver:
				at.approves = true
			case access.PublicRead:
				at.readsPublic = true
			case access.PrivateRead:
				at.readsPrivate = true
			case access.PublicTriage:
				at.readsPublic, at.triagesPublic = true, true
			case access.PrivateTriage:
				at.readsPrivate, at.triagesPrivate = true, true
			case access.SecurityTestingRead:
				at.readsSecurityTesting = true
			case access.SecurityTestingTriage:
				at.readsSecurityTesting, at.triagesSecurityTesting = true, true
			}
			per[grant.ProductID] = at
		}
		out[person.ID] = per
	}
	return out
}

// everybody is the map a sweep starts from: an entry, empty, for every person
// already holding a condition of this kind.
//
// Reconcile makes somebody's open set exactly what it is handed, so a person
// whose condition has stopped being true has to be handed an empty list. A
// person holding nothing and handed nothing has nothing to reconcile, and is
// added only when a condition is found for them.
func (w *Watch) everybody(ctx context.Context, kind Kind) (map[int64][]Holds, error) {
	out := map[int64][]Holds{}
	told, err := w.beingTold(ctx, kind)
	if err != nil {
		return nil, err
	}
	for _, person := range told {
		out[person] = nil
	}
	return out, nil
}
