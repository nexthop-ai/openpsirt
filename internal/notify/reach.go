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
// the person may read, so a claim waiting goes to somebody who holds both and
// to nobody who holds one.
//
// Reading and triaging are kept apart rather than folded into one pair,
// because the conditions divide on exactly that: a message about work waiting
// goes to whoever may *act*, and one about something that has happened goes to
// whoever may read it.
type acts struct {
	approves                                                 bool
	readsPublic, readsPrivate, triagesPublic, triagesPrivate bool
}

// reads is what a condition sent to whoever may read it asks, of something at
// one visibility. Each visibility is its own grant, so neither answers for the
// other.
func (a acts) reads(private bool) bool {
	if private {
		return a.readsPrivate
	}
	return a.readsPublic
}

// readsAll is whether they read every row of something spanning both
// visibilities: a claim may mix disclosed and undisclosed places, and a
// condition about it is sent to somebody who reads every one of them.
func (a acts) readsAll(public, private int) bool {
	return (public == 0 || a.readsPublic) && (private == 0 || a.readsPrivate)
}

// approvesAll is whether they may agree to every row of something spanning
// both visibilities: the rule a signed-in approver is held to, at each
// visibility the rows are at.
func (a acts) approvesAll(public, private int) bool {
	return (public == 0 || access.MayApprove(a.approves, a.readsPublic, a.triagesPublic)) &&
		(private == 0 || access.MayApprove(a.approves, a.readsPrivate, a.triagesPrivate))
}

// readsIn is whether they read the product at either visibility: the question
// for something about the product that names no finding.
func (a acts) readsIn() bool { return a.readsPublic || a.readsPrivate }

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
	people, held, err := access.NewStore(db).People(ctx)
	if err != nil {
		return nil, fmt.Errorf("read who may hear about this: %w", err)
	}
	return actsOf(people, held), nil
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
