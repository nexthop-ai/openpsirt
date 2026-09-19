package notify

import (
	"context"
	"fmt"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// The people a condition reaches.
//
// Shared by all three groups of conditions — the waits in stale.go, the
// operational alerts in watch.go, and the embargo conditions in disclosure.go
// — and belonging to none of them. They lived in the file of whichever
// condition asked first, which is how the same question came to be answered
// three ways.

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
// whoever may read it. Folded, the two hand-written copies of this loop asked
// the narrower question and the named one asked the wider, and which a
// condition got depended on which copy its author started from.
type acts struct {
	approves                                                 bool
	readsPublic, readsPrivate, triagesPublic, triagesPrivate bool
}

// public and private are what a condition sent to whoever may read it asks.
func (a acts) public() bool { return a.readsPublic }

func (a acts) private() bool { return a.readsPrivate }

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
// Read once per sweep rather than per condition. Every condition asking the
// same two tables is that much more work to answer one question, and — the
// part that matters more — that many places for "may read" to be spelled
// slightly differently. It was three: this, and two copies written out by hand
// in watch.go that also re-read access.People per condition.
func (w *Watch) whoActs(ctx context.Context) (map[int64]map[int64]acts, error) {
	people, held, err := access.NewStore(w.db).People(ctx)
	if err != nil {
		return nil, fmt.Errorf("read who may hear about this: %w", err)
	}
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
				at.readsPublic, at.readsPrivate = true, true
			case access.PublicTriage:
				at.readsPublic, at.triagesPublic = true, true
			case access.PrivateTriage:
				at.readsPublic, at.readsPrivate = true, true
				at.triagesPublic, at.triagesPrivate = true, true
			}
			per[grant.ProductID] = at
		}
		out[person.ID] = per
	}
	return out, nil
}

// everybody is the map a sweep starts from: an entry for every person who
// might hold one of these, and for every person already holding one.
//
// Both halves are needed. Reconcile makes somebody's open set exactly what it
// is handed, so a person whose condition has stopped being true has to be
// handed an empty list — and a person who has never been told anything has to
// be in the map before anything can be added for them.
func (w *Watch) everybody(ctx context.Context, kind Kind,
	reach map[int64]map[int64]acts) (map[int64][]Holds, error) {

	return w.everybodyAnd(ctx, kind, reach, nil)
}

// everybodyAnd is everybody, plus people named directly.
//
// The conditions about an embargo go to whoever holds it and to every
// administrator, and an administrator is not in the reach map: that map
// answers who may act on a product, and administration is not held per
// product.
func (w *Watch) everybodyAnd(ctx context.Context, kind Kind,
	reach map[int64]map[int64]acts, also []int64) (map[int64][]Holds, error) {

	out := map[int64][]Holds{}
	told, err := w.beingTold(ctx, kind)
	if err != nil {
		return nil, err
	}
	for _, person := range told {
		out[person] = nil
	}
	for _, person := range also {
		if _, already := out[person]; !already {
			out[person] = nil
		}
	}
	for personID := range reach {
		if _, already := out[personID]; !already {
			out[personID] = nil
		}
	}
	return out, nil
}
