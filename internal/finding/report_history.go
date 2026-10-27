// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// ReportAct is one kind of thing done to a report.
type ReportAct string

// Every act a report's history holds.
const (
	ActRecorded        ReportAct = "recorded"
	ActEdited          ReportAct = "edited"
	ActNoted           ReportAct = "noted"
	ActNoteEdited      ReportAct = "note-edited"
	ActSent            ReportAct = "sent"
	ActReceived        ReportAct = "received"
	ActAssigned        ReportAct = "assigned"
	ActHandedBack      ReportAct = "handed-back"
	ActAttached        ReportAct = "attached"
	ActRulingProposed  ReportAct = "ruling-proposed"
	ActRulingSettled   ReportAct = "ruling-settled"
	ActRulingWithdrawn ReportAct = "ruling-withdrawn"
	ActAccepted        ReportAct = "accepted"
)

// ReportActs is every act, in no order.
func ReportActs() []ReportAct {
	return []ReportAct{ActRecorded, ActEdited, ActNoted, ActNoteEdited, ActSent, ActReceived,
		ActAssigned, ActHandedBack, ActAttached, ActRulingProposed, ActRulingSettled,
		ActRulingWithdrawn, ActAccepted}
}

// ReportEvent is one act in a report's history.
type ReportEvent struct {
	At  time.Time
	Act ReportAct
	// By is the person who did it. Absent where an assignment rule placed the
	// report, or an administrator's hand-over moved it.
	By *int64
	// Party is who it went to, on an assignment.
	Party *int64
	// RuleID is the assignment rule that placed it, where one did.
	RuleID *int64
	// Ordinal is the version an edit replaced, or the note's version.
	Ordinal int
	// NoteID is the note written or changed.
	NoteID int64
	// Dated is the day a message carries.
	Dated *time.Time
	// RulingID and Disposition are the ruling proposed, settled or withdrawn.
	RulingID    int64
	Disposition Disposition
	// VulnerabilityID is the issue it was accepted as.
	VulnerabilityID int64
	// Filename is the file attached.
	Filename string
}

// ReportHistory is every act on one report, oldest first, assembled from the
// rows that hold each: the report, its revisions, its notes and their
// revisions, its correspondence, who held it, the rulings over it, and what
// was attached to it.
func (s *Store) ReportHistory(ctx context.Context, subject access.Subject, productID int64,
	reference string) ([]ReportEvent, error) {

	row, err := s.ReportBy(ctx, subject, productID, reference)
	if err != nil {
		return nil, err
	}
	recordedBy := row.RecordedBy
	out := []ReportEvent{{At: row.RecordedAt, Act: ActRecorded, By: &recordedBy}}

	var revisions []ReportRevision
	if err := s.db.NewSelect().Model(&revisions).
		Where(`"frr"."flaw_report_id" = ?`, row.ID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the edits: %w", err)
	}
	for _, r := range revisions {
		by := r.ReplacedBy
		out = append(out, ReportEvent{At: r.ReplacedAt, Act: ActEdited, By: &by, Ordinal: r.Ordinal})
	}

	notes, err := notesOf(ctx, s.db, row.ID)
	if err != nil {
		return nil, err
	}
	author := map[int64]int64{}
	noteIDs := make([]int64, 0, len(notes))
	for _, n := range notes {
		by := n.WrittenBy
		author[n.ID] = by
		noteIDs = append(noteIDs, n.ID)
		out = append(out, ReportEvent{At: n.WrittenAt, Act: ActNoted, By: &by, NoteID: n.ID})
	}
	if len(noteIDs) > 0 {
		var was []WasReportNoted
		if err := s.db.NewSelect().Model(&was).
			Where(`"rnr"."note_id" IN (?)`, bun.List(noteIDs)).Scan(ctx); err != nil {
			return nil, fmt.Errorf("read the note edits: %w", err)
		}
		for _, w := range was {
			by := author[w.NoteID]
			out = append(out, ReportEvent{At: w.ReplacedAt, Act: ActNoteEdited, By: &by,
				NoteID: w.NoteID, Ordinal: w.Ordinal})
		}
	}

	messages, err := messagesOf(ctx, s.db, row.ID)
	if err != nil {
		return nil, err
	}
	for _, m := range messages {
		by, dated := m.LoggedBy, m.Dated
		act := ActReceived
		if m.Direction == Sent {
			act = ActSent
		}
		out = append(out, ReportEvent{At: m.LoggedAt, Act: act, By: &by, Dated: &dated})
	}

	var held []ReportAssignment
	if err := s.db.NewSelect().Model(&held).
		Where(`"ra"."flaw_report_id" = ?`, row.ID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read who held it: %w", err)
	}
	for _, h := range held {
		act := ActAssigned
		if h.AssignedTo == nil {
			act = ActHandedBack
		}
		out = append(out, ReportEvent{At: h.AssignedAt, Act: act, By: h.AssignedBy,
			Party: h.AssignedTo, RuleID: h.AssignedByRule})
	}

	var rulings []ReportRuling
	if err := s.db.NewSelect().Model(&rulings).
		Join(`JOIN "report_ruled" AS "rd" ON "rd"."ruling_id" = "rr"."id"`).
		Where(`"rd"."flaw_report_id" = ?`, row.ID).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the rulings over it: %w", err)
	}
	for _, r := range rulings {
		proposer := r.ProposedBy
		out = append(out, ReportEvent{At: r.ProposedAt, Act: ActRulingProposed, By: &proposer,
			RulingID: r.ID, Disposition: r.Disposition})
		if r.SettledAt != nil {
			by := r.ApprovedBy
			if by == nil {
				by = &proposer
			}
			out = append(out, ReportEvent{At: *r.SettledAt, Act: ActRulingSettled, By: by,
				RulingID: r.ID, Disposition: r.Disposition})
		}
		if r.WithdrawnAt != nil {
			out = append(out, ReportEvent{At: *r.WithdrawnAt, Act: ActRulingWithdrawn,
				By: r.WithdrawnBy, RulingID: r.ID, Disposition: r.Disposition})
		}
	}

	if row.VulnerabilityID != nil && row.EvaluatedAt != nil {
		out = append(out, ReportEvent{At: *row.EvaluatedAt, Act: ActAccepted, By: row.EvaluatedBy,
			VulnerabilityID: *row.VulnerabilityID})
	}

	var files []struct {
		Filename   string    `bun:"filename"`
		UploadedBy int64     `bun:"uploaded_by"`
		UploadedAt time.Time `bun:"uploaded_at"`
	}
	if err := s.db.NewSelect().TableExpr(`"attachment" AS "at"`).
		ColumnExpr(`"at"."filename" AS "filename"`).
		ColumnExpr(`"at"."uploaded_by" AS "uploaded_by"`).
		ColumnExpr(`"at"."uploaded_at" AS "uploaded_at"`).
		Where(`"at"."flaw_report_id" = ?`, row.ID).
		Where(`"at"."attached_at" IS NOT NULL`).
		Scan(ctx, &files); err != nil {
		return nil, fmt.Errorf("read what was attached: %w", err)
	}
	for _, f := range files {
		by := f.UploadedBy
		out = append(out, ReportEvent{At: f.UploadedAt, Act: ActAttached, By: &by, Filename: f.Filename})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}
