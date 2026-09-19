package finding

import (
	"context"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

// The sort of release a build sits in, and whether it is still in support.
const (
	// OnBranch is a release that moves: work lands in it.
	OnBranch = "branch"
	// OnTag is a release that was built once and is what somebody received.
	// No work will land in it whatever anybody decides.
	OnTag = "tag"
	// InSupport is a release nobody has dated out, or whose date is ahead.
	InSupport = "in-support"
	// PastEndOfLife is a release whose end-of-life date has passed, its own
	// or the product's.
	PastEndOfLife = "past-eol"
)

// Workable narrows a list to the releases work can actually land in.
//
// Two questions kept apart because they are two: a tag can be in support and
// a branch can be past end-of-life, and a single control offering four
// combinations as four words is a control nobody reads correctly.
//
// **The zero value narrows nothing.** What the working population is is a
// property of the question a screen asks rather than of the data, so a caller
// that has not been asked answers about everything; the findings list applies
// its defaults through Working.
type Workable struct {
	// Kinds is which sorts of release to keep. Empty is both.
	Kinds []string
	// Support is whether to keep releases in support, past end-of-life, or
	// both. Empty is both.
	Support []string
}

// Working is what a work list means by these two questions: branches, in
// support.
//
// Both defaults narrow, and both are stated on the screen for that reason —
// a count that is not the whole count with nothing saying so is the defect
// the older silent defaults have.
func Working(kinds, support []string) Workable {
	w := Workable{Kinds: kept(kinds, OnBranch, OnTag), Support: kept(support, InSupport, PastEndOfLife)}
	if len(w.Kinds) == 0 {
		w.Kinds = []string{OnBranch}
	}
	if len(w.Support) == 0 {
		w.Support = []string{InSupport}
	}
	return w
}

// kept drops anything that is not one of the two words. A word nothing
// recognizes is not a narrowing, and treating it as one would answer with
// nothing and say why nowhere.
func kept(words []string, allowed ...string) []string {
	out := make([]string, 0, len(words))
	seen := make(map[string]bool, len(words))
	for _, word := range words {
		// Each at most once. A repeated value — `?on=branch&on=branch` — made
		// a set of two out of one word, and every reader here asks how many
		// there are: two reads as "both kinds, so no narrowing", which
		// silently put tags back into a list somebody had asked to see
		// branches of.
		if seen[word] {
			continue
		}
		for _, ok := range allowed {
			if word == ok {
				seen[word] = true
				out = append(out, word)
			}
		}
	}
	return out
}

// asks reports whether this narrows anything at all.
func (w Workable) asks() bool {
	return (len(w.Kinds) > 0 && len(w.Kinds) < 2) || (len(w.Support) > 0 && len(w.Support) < 2)
}

// narrow applies it to a query that joins target AS tg and stream AS st.
//
// The end-of-life rule is the catalog's own, read as the set of releases it
// says are past their date rather than restated as a condition here: it
// inherits the product's date where a release has none, and two copies of that
// disagree the first time one of them is changed.
func (w Workable) narrow(ctx context.Context, db bun.IDB, now time.Time,
	q *bun.SelectQuery) (*bun.SelectQuery, error) {

	if len(w.Kinds) == 1 {
		q = q.Where("st.kind = ?", w.Kinds[0])
	}
	if len(w.Support) != 1 {
		return q, nil
	}
	past, err := catalog.NewStore(db).StreamsPastEndOfLife(ctx, now)
	if err != nil {
		return nil, err
	}
	if w.Support[0] == PastEndOfLife {
		if len(past) == 0 {
			// Nothing is out of support, so asking for what is out of support
			// is an empty answer rather than an unnarrowed one.
			return q.Where("1 = 0"), nil
		}
		return q.Where("st.id IN (?)", bun.List(past)), nil
	}
	if len(past) > 0 {
		q = q.Where("st.id NOT IN (?)", bun.List(past))
	}
	return q, nil
}
