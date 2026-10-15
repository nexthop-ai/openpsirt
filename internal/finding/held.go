// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// What applying a scan reads of the findings already open, and how it writes
// the ones that moved.

import (
	"strings"
	"time"

	"github.com/uptrace/bun"
)

// heldFinding is an open finding as applying a scan reads it: what makes it the
// finding it is, and every column an update compares against or counts from.
type heldFinding struct {
	bun.BaseModel `bun:"table:finding,alias:f"`

	ID                 int64      `bun:"id"`
	VulnerabilityID    int64      `bun:"vulnerability_id"`
	ComponentID        int64      `bun:"component_id"`
	ConsumerID         *int64     `bun:"consumer_id"`
	PlaceIdentity      string     `bun:"place_identity"`
	FixState           FixState   `bun:"fix_state"`
	FixedIn            string     `bun:"fixed_in"`
	FixedAt            *time.Time `bun:"fixed_at"`
	Matched            Matched    `bun:"matched"`
	MatchedFrom        string     `bun:"matched_from"`
	MatchedIn          string     `bun:"matched_in"`
	MatchedRange       string     `bun:"matched_range"`
	SuppressedBy       *int64     `bun:"suppressed_by"`
	StatedBy           *int64     `bun:"stated_by"`
	ClaimedBy          *int64     `bun:"claimed_by"`
	Urgency            int64      `bun:"urgency"`
	RankExploited      bool       `bun:"urgency_exploited"`
	RankShipped        bool       `bun:"urgency_shipped"`
	ExploitedLearnedAt *time.Time `bun:"exploited_learned_at"`
	OpenedAt           time.Time  `bun:"opened_at"`
	DueAt              *time.Time `bun:"due_at"`
}

// moving is what one update to an open finding writes, and the findings it is
// written to.
//
// Findings whose updates write the same values are one statement over their
// identifiers. The order is the exception: it is written from each finding's
// own value, chosen by identifier inside the statement. An issue's likelihood
// moving rewrites the order of every place it sits, and the likelihood is
// close to unique to the issue, so a statement per value of the order is a
// statement per issue.
type moving struct {
	f Finding
	// described is whether the fix, the match, or what answers the finding
	// moved. Where none did, those columns hold what the update would write
	// and are left out of it.
	described         bool
	moved             bool
	exploitationMoved bool
	learned           *time.Time
	clockMoved        bool
	ids               []int64
	// urgencies is the order each of ids takes, where moved.
	urgencies []int64
}

// changeKey is every value an update writes to every row it names, in a form
// that compares.
//
// A column the update leaves alone is zero here, so findings differing only
// in a value nobody writes share a statement. The order is written per row
// and is not here.
type changeKey struct {
	fixState                             FixState
	fixedIn                              string
	fixedAt                              string
	matched                              Matched
	matchedFrom, matchedIn, matchedRange string
	suppressedBy, statedBy, claimedBy    reference
	described                            bool
	moved                                bool
	rankExploited, rankShipped           bool
	exploitationMoved                    bool
	learned                              string
	clockMoved                           bool
	dueAt                                string
}

// reference is an identifier that may be absent, in a form that compares.
type reference struct {
	held bool
	id   int64
}

func referenceOf(id *int64) reference {
	if id == nil {
		return reference{}
	}
	return reference{held: true, id: *id}
}

// instantOf is a moment in a form that compares, with its offset, so two
// findings share a statement only where the value written is the same text.
// Absent is the empty string, which no formatted moment is.
func instantOf(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339Nano)
}

func (m moving) key() changeKey {
	k := changeKey{
		described:         m.described,
		moved:             m.moved,
		exploitationMoved: m.exploitationMoved,
		clockMoved:        m.clockMoved,
	}
	if m.described {
		k.fixState, k.fixedIn, k.fixedAt = m.f.FixState, m.f.FixedIn, instantOf(m.f.FixedAt)
		k.matched, k.matchedFrom, k.matchedIn = m.f.Matched, m.f.MatchedFrom, m.f.MatchedIn
		k.matchedRange = m.f.MatchedRange
		k.suppressedBy, k.statedBy = referenceOf(m.f.SuppressedBy), referenceOf(m.f.StatedBy)
		k.claimedBy = referenceOf(m.f.ClaimedBy)
	}
	if m.moved {
		k.rankExploited, k.rankShipped = m.f.RankExploited, m.f.RankShipped
	}
	if m.exploitationMoved {
		k.learned = instantOf(m.learned)
	}
	if m.clockMoved {
		k.dueAt = instantOf(m.f.DueAt)
	}
	return k
}

// add names one more finding this change is written to, with the order it
// takes.
func (m *moving) add(id int64, urgency int64) {
	m.ids = append(m.ids, id)
	m.urgencies = append(m.urgencies, urgency)
}

// update is the statement writing this change to the findings from first up
// to last.
//
// The order is a CASE over the identifier, which no assignment in the list
// writes, so the engines that read a value already assigned earlier in the
// list read the same thing as the ones that do not. The ELSE names the column
// and nothing reaches it, because the statement names only the findings the
// CASE does.
func (m moving) update(tx bun.IDB, first, last int) *bun.UpdateQuery {
	f := m.f
	update := tx.NewUpdate().Model((*Finding)(nil))
	if m.described {
		update = update.
			Set(`"fix_state" = ?`, f.FixState).
			Set(`"fixed_in" = ?`, f.FixedIn).
			Set(`"fixed_at" = ?`, f.FixedAt).
			Set(`"matched" = ?`, f.Matched).
			Set(`"matched_from" = ?`, f.MatchedFrom).
			Set(`"matched_in" = ?`, f.MatchedIn).
			Set(`"matched_range" = ?`, f.MatchedRange).
			Set(`"suppressed_by" = ?`, f.SuppressedBy).
			Set(`"stated_by" = ?`, f.StatedBy).
			Set(`"claimed_by" = ?`, f.ClaimedBy)
	}
	if m.moved {
		urgencies := make([]any, 0, 2*(last-first))
		for i := first; i < last; i++ {
			urgencies = append(urgencies, m.ids[i], m.urgencies[i])
		}
		update = update.
			Set(`"urgency" = CASE "id"`+strings.Repeat(" WHEN ? THEN ?", last-first)+` ELSE "urgency" END`,
				urgencies...).
			Set(`"urgency_exploited" = ?`, f.RankExploited).
			Set(`"urgency_shipped" = ?`, f.RankShipped)
	}
	if m.exploitationMoved {
		// The moment, kept beside the deadline it produced. Every later
		// recount counts from it, and nothing else on the row holds it.
		update = update.Set(`"exploited_learned_at" = ?`, m.learned)
	}
	if m.clockMoved {
		update = update.Set(`"due_at" = ?`, f.DueAt)
	}
	return update.Where(`"id" IN (?)`, bun.List(m.ids[first:last]))
}
