package triage

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// What became of what somebody proposed.
//
// Approval stays silent, and the reasoning for that survives: an approval is
// the expected outcome and a message per approval is a channel people stop
// reading. What did not survive was its premise. The gap silence leaves was
// closed with a view rather than more mail, and that only works if the view
// records outcomes — and the review queue's own "mine" tab lists what is
// *pending*, so approved, withdrawn, lapsed and undone all present
// identically, as the row disappearing.
//
// So this is the other question, asked separately: not what is waiting, but
// what happened. The two are different lists and are answered by different
// statements, rather than one list with a filter — a page of "everything I
// proposed" that counts only the pending ones is exactly the disagreement
// between a count and a list that the queue was fixed to avoid.

// WhatHappened is what became of a claim, in one word.
//
// Read from the rows every time rather than stored. A claim has no state of
// its own — its rows do — and a word kept beside it would be a second place
// for the truth, updated by every path that approves, withdraws, sends back or
// lapses one, and wrong from the first path that forgets.
type WhatHappened string

const (
	// StillWaiting is proposed, needing a second person, nobody has answered.
	StillWaiting WhatHappened = "waiting"
	// SentBackFor is an approver asking for more. It is waiting on its author
	// rather than on an approver, which is why it is its own word.
	SentBackFor WhatHappened = "sent-back"
	// AgreedTo is a second person having agreed, and it standing.
	AgreedTo WhatHappened = "approved"
	// TakenBack is the proposer having withdrawn it themselves.
	TakenBack WhatHappened = "withdrawn"
	// MovedUnder is the code having changed, so the claim stopped applying.
	MovedUnder WhatHappened = "lapsed"
	// AgreementUndone is an agreement taken back, leaving the claim waiting
	// again. Distinguished from StillWaiting because somebody had agreed: it
	// is the one outcome a proposer is entitled to find surprising.
	AgreementUndone WhatHappened = "undone"
	// SeveralWays is a claim whose rows did not all end the same way — an
	// approver agreeing to most of a bulk set and setting some aside, or half
	// of it lapsing as one build moved. Said rather than picked between,
	// because choosing one of them would report the claim as something it only
	// partly is.
	SeveralWays WhatHappened = "mixed"
)

// Became is one claim somebody proposed and what happened to it.
type Became struct {
	Claim Claim
	// Decision is a representative row — the earliest — and Reasoning is what
	// it currently rests on.
	Decision  Decision
	Reasoning string
	Happened  WhatHappened
	// When is when it became that, and By is who did it where a person did.
	// Both are absent for a claim still waiting: nothing has happened to it,
	// which is the whole of what it has to report.
	When *time.Time
	By   int64
	// Rows, Issues and Places are how big the claim is, in the three units a
	// queue card already uses.
	Rows, Issues, Places int
	// Outliers is what in a bulk set does not look like the rest — the same
	// signals an approver is shown, for the same reason.
	//
	// Whoever wrote a bulk claim faces the choice an approver faces: hold part
	// of it back, or argue all of it as one. Showing the signals to one of them
	// and not the other left the person best placed to say "not those four"
	// with no way to see which four.
	Outliers *Outliers
}

// Became returns what became of the claims this person proposed, newest first.
//
// Everything they proposed, whatever happened to it — which is the point.
// Narrowed to what they may still read: losing the reading of a product does
// not leave a list of its issues behind on a personal page.
func (s *Store) Became(ctx context.Context, subject access.Subject,
	limit, offset int) ([]Became, int, error) {

	if subject.Kind != access.Person {
		return nil, 0, nil
	}
	limit = database.AList.Of(limit)

	// One row per claim, ordered by its newest decision, so a page is a page
	// of claims and the count counts claims.
	mine := func() *bun.SelectQuery {
		q := s.db.NewSelect().Model((*Decision)(nil)).
			ColumnExpr(`de.claim_id AS "claim_id"`).
			ColumnExpr(`MAX(de.id) AS "newest"`).
			Where("de.proposed_by = ?", subject.ID).
			GroupExpr("de.claim_id")
		return readableBy(q, subject, "de")
	}

	page, err := s.pageClaims(ctx, subject, mine, limit, offset, "what you proposed")
	if err != nil {
		return nil, 0, err
	}
	if len(page.Order) == 0 {
		return nil, page.Total, nil
	}
	total, ids, byID, rows := page.Total, page.Order, page.Claims, page.Rows

	var agreements []Approval
	if err := s.db.NewSelect().Model(&agreements).
		Where("claim_id IN (?)", bun.List(ids)).Scan(ctx); err != nil {
		return nil, 0, fmt.Errorf("read what was agreed to: %w", err)
	}
	agreed := map[int64][]Approval{}
	for _, one := range agreements {
		agreed[one.ClaimID] = append(agreed[one.ClaimID], one)
	}

	gathered := map[int64]*Became{}
	for _, row := range rows {
		entry, seen := gathered[row.ClaimID]
		if !seen {
			entry = &Became{Claim: byID[row.ClaimID], Decision: row}
			gathered[row.ClaimID] = entry
		}
		entry.Rows++
	}
	issues := map[int64]map[int64]bool{}
	places := map[int64]map[string]bool{}
	for _, row := range rows {
		if issues[row.ClaimID] == nil {
			issues[row.ClaimID] = map[int64]bool{}
			places[row.ClaimID] = map[string]bool{}
		}
		issues[row.ClaimID][row.VulnerabilityID] = true
		places[row.ClaimID][row.PlaceIdentity] = true
	}
	for id, entry := range gathered {
		entry.Issues = len(issues[id])
		entry.Places = len(places[id])
	}

	byClaim := map[int64][]Decision{}
	for _, row := range rows {
		byClaim[row.ClaimID] = append(byClaim[row.ClaimID], row)
	}
	for id, entry := range gathered {
		entry.Happened, entry.When, entry.By = became(byClaim[id], agreed)
	}

	representatives := make([]Decision, 0, len(ids))
	for _, id := range ids {
		if entry, ok := gathered[id]; ok {
			representatives = append(representatives, entry.Decision)
		}
	}
	reasoning, err := s.currentReasoning(ctx, representatives)
	if err != nil {
		return nil, 0, err
	}

	// The same signals an approver is shown, for a claim its author may still
	// hold part of back. Only a bulk claim has outliers, and only one that is
	// still being argued has anything to do about them.
	var bulk []Claim
	for _, id := range ids {
		entry, ok := gathered[id]
		if !ok || entry.Claim.Kind != TogetherClaim {
			continue
		}
		if entry.Happened == StillWaiting || entry.Happened == SentBackFor ||
			entry.Happened == AgreementUndone || entry.Happened == SeveralWays {
			bulk = append(bulk, entry.Claim)
		}
	}
	outliers, err := s.outliersFor(ctx, subject, bulk)
	if err != nil {
		return nil, 0, err
	}

	out := make([]Became, 0, len(ids))
	for _, id := range ids {
		entry, ok := gathered[id]
		if !ok {
			continue
		}
		entry.Reasoning = reasoning[entry.Decision.ID]
		entry.Outliers = outliers[entry.Claim.ID]
		out = append(out, *entry)
	}
	return out, total, nil
}

// became reads one word out of a claim's rows and the agreements against them.
//
// The order is what makes it right. Rows that ended differently are said to
// have ended differently rather than reported as whichever came first; and a
// row that is proposed is three different things depending on how it got
// there — never agreed to, sent back for more, or agreed to and undone — which
// is exactly the distinction the queue could not draw.
func became(rows []Decision, agreed map[int64][]Approval) (WhatHappened, *time.Time, int64) {
	var (
		waiting, sentBack, approved, withdrawn, lapsed, undone int
		when                                                   *time.Time
		by                                                     int64
	)
	at := func(moment *time.Time, who int64) {
		if moment == nil {
			return
		}
		if when == nil || moment.After(*when) {
			when, by = moment, who
		}
	}
	for _, row := range rows {
		switch row.State {
		case Approved:
			approved++
			for _, one := range agreed[row.ClaimID] {
				if one.WithdrawnAt == nil {
					stamp := one.ApprovedAt
					at(&stamp, one.ApprovedBy)
				}
			}
		case Withdrawn:
			withdrawn++
			at(row.EndedAt, row.ProposedBy)
		case LapsedState:
			lapsed++
			at(row.EndedAt, 0)
		default:
			// Proposed, which is three different situations.
			switch {
			case row.SentBackAt != nil:
				sentBack++
				at(row.SentBackAt, 0)
			case tookBackAgreement(agreed[row.ClaimID]):
				undone++
				for _, one := range agreed[row.ClaimID] {
					at(one.WithdrawnAt, one.ApprovedBy)
				}
			default:
				waiting++
			}
		}
	}

	kinds := 0
	for _, n := range []int{waiting, sentBack, approved, withdrawn, lapsed, undone} {
		if n > 0 {
			kinds++
		}
	}
	if kinds > 1 {
		return SeveralWays, when, by
	}
	switch {
	case approved > 0:
		return AgreedTo, when, by
	case withdrawn > 0:
		return TakenBack, when, by
	case lapsed > 0:
		return MovedUnder, when, by
	case undone > 0:
		return AgreementUndone, when, by
	case sentBack > 0:
		return SentBackFor, when, by
	default:
		// Nothing has happened to it, which is the whole of what it reports.
		return StillWaiting, nil, 0
	}
}

// tookBackAgreement says somebody had agreed to this row and the agreement was
// taken back — which is what tells "undone" from "never answered", since the
// row reads as proposed either way.
func tookBackAgreement(against []Approval) bool {
	for _, one := range against {
		if one.WithdrawnAt != nil {
			return true
		}
	}
	return false
}
