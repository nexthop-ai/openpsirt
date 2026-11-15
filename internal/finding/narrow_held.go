// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"strings"

	"github.com/uptrace/bun"
)

// Who is dealing with a group, as a findings list asks it.
const (
	// HeldByMe is mine or a team I am on, at every occurrence.
	HeldByMe = "me"
	// HeldBySomebody is held at every occurrence, by anybody.
	HeldBySomebody = "somebody"
	// HeldByNobody is held at no occurrence.
	HeldByNobody = "nobody"
)

// Assignees is every word a findings list asks who is dealing with a group in.
func Assignees() []string { return []string{HeldByMe, HeldBySomebody, HeldByNobody} }

// heldBy keeps only the groups whose occurrences are held by who was asked
// about.
//
// One condition holding an OR rather than several applied in turn: "mine or
// whatever nobody has picked up" is one question, and applied one at a time
// these would AND and answer with nothing.
//
// A condition on the group, so "mine" means every occurrence held and every one
// of them by one of my names. A group split between me and somebody else is not
// mine, and saying it is would hand somebody work that is half theirs.
func (f Filter) heldBy(q *bun.SelectQuery, g grain) *bun.SelectQuery {
	asked := trimmed(f.Assigned)
	if len(asked) == 0 {
		return q
	}
	says := make([]string, 0, len(asked))
	args := make([]any, 0, 2)
	for _, who := range asked {
		switch who {
		case HeldByNobody:
			says = append(says, g.held()+" < 1")
		case HeldBySomebody:
			says = append(says, g.held()+" >= "+g.occurrences())
		case HeldByMe:
			// Mine or my team's, everywhere the phrase appears. A subject
			// holding no party names nobody, so the phrase contributes
			// nothing — which the guard below turns into an answer of nothing
			// where it is the only thing asked for.
			if len(f.HeldBy) == 0 {
				continue
			}
			says = append(says, "("+g.held()+" >= "+g.occurrences()+
				" AND "+g.heldLeast()+" IN (?) AND "+g.heldMost()+" IN (?))")
			args = append(args, bun.List(f.HeldBy), bun.List(f.HeldBy))
		}
	}
	if len(says) == 0 {
		// Something was asked for and none of it could be turned into a
		// condition: a word this does not know, or "mine" from a subject that
		// holds no party. That is a narrowing that cannot be applied rather
		// than no narrowing, and dropping it would answer with every finding
		// there is while the screen shows the filter as on.
		return having(q, "1 = 0")
	}
	return having(q, "("+strings.Join(says, " OR ")+")", args...)
}
