// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

// What applying a scan reads of the findings already open, and how it writes
// the ones that moved.

import (
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
// identifiers. An issue's likelihood moving rewrites the order of every place
// it sits, and those places share almost everything an update writes.
type moving struct {
	f                 Finding
	moved             bool
	exploitationMoved bool
	learned           *time.Time
	clockMoved        bool
	ids               []int64
}

// changeKey is every value an update writes, in a form that compares.
//
// A column the update leaves alone is zero here, so findings differing only
// in a value nobody writes share a statement.
type changeKey struct {
	fixState                             FixState
	fixedIn                              string
	fixedAt                              string
	matched                              Matched
	matchedFrom, matchedIn, matchedRange string
	suppressedBy, statedBy, claimedBy    reference
	moved                                bool
	urgency                              int64
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
		fixState: m.f.FixState, fixedIn: m.f.FixedIn, fixedAt: instantOf(m.f.FixedAt),
		matched: m.f.Matched, matchedFrom: m.f.MatchedFrom, matchedIn: m.f.MatchedIn,
		matchedRange: m.f.MatchedRange,
		suppressedBy: referenceOf(m.f.SuppressedBy), statedBy: referenceOf(m.f.StatedBy),
		claimedBy:         referenceOf(m.f.ClaimedBy),
		moved:             m.moved,
		exploitationMoved: m.exploitationMoved,
		clockMoved:        m.clockMoved,
	}
	if m.moved {
		k.urgency, k.rankExploited, k.rankShipped = m.f.Urgency, m.f.RankExploited, m.f.RankShipped
	}
	if m.exploitationMoved {
		k.learned = instantOf(m.learned)
	}
	if m.clockMoved {
		k.dueAt = instantOf(m.f.DueAt)
	}
	return k
}

// update is the statement writing this change, without the rows it is
// written to.
func (m moving) update(tx bun.IDB, now time.Time) *bun.UpdateQuery {
	f := m.f
	update := tx.NewUpdate().Model((*Finding)(nil)).
		Set("fix_state = ?", f.FixState).
		Set("fixed_in = ?", f.FixedIn).
		Set("fixed_at = ?", f.FixedAt).
		Set("matched = ?", f.Matched).
		Set("matched_from = ?", f.MatchedFrom).
		Set("matched_in = ?", f.MatchedIn).
		Set("matched_range = ?", f.MatchedRange).
		Set("suppressed_by = ?", f.SuppressedBy).
		Set("stated_by = ?", f.StatedBy).
		Set("claimed_by = ?", f.ClaimedBy).
		Set("last_changed_at = ?", now)
	if m.moved {
		update = update.
			Set("urgency = ?", f.Urgency).
			Set("urgency_exploited = ?", f.RankExploited).
			Set("urgency_shipped = ?", f.RankShipped)
	}
	if m.exploitationMoved {
		// The moment, kept beside the deadline it produced. Every later
		// recount counts from it, and nothing else on the row holds it.
		update = update.Set("exploited_learned_at = ?", m.learned)
	}
	if m.clockMoved {
		update = update.Set("due_at = ?", f.DueAt)
	}
	return update
}
