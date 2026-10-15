// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// Progress is how far an upload has got, in the terms the sender asked in.
//
// A producer that was told its upload was accepted wants to know two things:
// whether the file parsed, and whether anything came of it. Which of our two
// queues the work is sitting in is not a producer's business and would tie
// their build scripts to our internals, so the queues are collapsed into one
// sequence here.
type Progress string

const (
	// Reading means taken, not yet parsed.
	Reading Progress = "reading"
	// Scanning means parsed and stored, with the vulnerability scan still to
	// finish.
	Scanning Progress = "scanning"
	// Scanned means done — the graph is stored and the findings are recorded.
	Scanned Progress = "scanned"
	// Refused means it was taken and could not be used. Failure says why, and
	// is the whole reason this endpoint exists: a producer emitting files
	// nothing can read would otherwise see a successful upload every night.
	Refused Progress = "failed"
)

// Progresses is every state an upload can reach, in the order it reaches them.
func Progresses() []Progress { return []Progress{Reading, Scanning, Scanned, Refused} }

// Receipt is what became of one upload.
type Receipt struct {
	Scan    Scan
	State   Progress
	Failure string
	// Caution is what the scanner said while succeeding — a qualification on
	// the answer this receipt reports rather than a reason there is none. It
	// travels with the receipt because that is where somebody reads what came
	// of an upload, and a warning nobody is shown is a warning discarded.
	Caution string
	// RunID is the scan run that reflects this upload, where one has finished.
	//
	// A run covers a target rather than an upload, so several uploads can be
	// answered by one run. It is attributed to the newest upload it covered
	// and left off the rest: what a run opened and closed is one fact, and
	// repeating it down three rows reads as three separate changes.
	RunID *int64
	// Measured is what the run that answers *this* upload was made with.
	// On every receipt, unlike the counts above: the versions are a
	// property of the run rather than a change it made, and a page of
	// receipts spanning a scanner upgrade or a database that stopped
	// moving is exactly what somebody is reading this screen to notice.
	//
	// It is also what makes a corrected feed answerable: which
	// vulnerability database produced the finding somebody dismissed on a
	// given day.
	Measured *finding.Run
}

// Of is one scan of one build, narrowed the way the receipts are.
//
// Answered here rather than in a handler for the same reason the list is: a
// check beside the query cannot be skipped by adding another endpoint, and
// that covers which builds a key reaches as well as which product it sees. A
// scan that belongs to another build answers as one that does not exist.
func (s *Store) Of(ctx context.Context, subject access.Subject, targetID, scanID int64) (*Scan, error) {
	if err := s.mayRead(ctx, subject, targetID); err != nil {
		if errors.Is(err, access.ErrDenied) {
			return nil, ErrNoScan
		}
		return nil, err
	}
	held := new(Scan)
	if err := s.db.NewSelect().Model(held).
		Where(`"id" = ?`, scanID).
		Where(`"target_id" = ?`, targetID).
		Scan(ctx); err != nil {
		return nil, database.FromRead(err, ErrNoScan,
			fmt.Sprintf("look up scan %d on this build", scanID))
	}
	return held, nil
}

// mayRead refuses a subject who may not read what was filed against a build:
// the rule catalog.ReadsBuild holds.
func (s *Store) mayRead(ctx context.Context, subject access.Subject, targetID int64) error {
	return catalog.ReadsBuild(ctx, s.db, subject, targetID)
}

// Receipts reports what became of the scans filed against a target, newest
// first, with how many there are in total.
//
// Who may read them is decided here from the subject, and is the rule Of
// holds.
func (s *Store) Receipts(ctx context.Context, subject access.Subject, targetID int64,
	limit, offset int) ([]Receipt, int, error) {

	// Asked here rather than only in the handler. A check beside the query
	// cannot be skipped by adding another endpoint, which is the whole reason
	// visibility is decided in this layer — and receipts carry a producer's
	// own failure text, so reaching them is reaching something.
	//
	// A typed refusal, so the handler answers it the way a build nobody
	// declared is answered rather than as a fault: a 500 where a stranger
	// gets a 404 says the build is there, one name at a time.
	if err := s.mayRead(ctx, subject, targetID); err != nil {
		return nil, 0, err
	}

	// Clamped here rather than trusted from the caller: one more endpoint over
	// the same store, and a limit of zero asks for the whole table.
	limit = database.AList.Of(limit)

	sent := func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.Where(`"target_id" = ?`, targetID)
	}

	total, err := sent(s.db.NewSelect().Model((*Scan)(nil))).Count(ctx)
	if err != nil {
		return nil, 0, err
	}

	var scans []Scan
	if err := sent(s.db.NewSelect().Model(&scans)).
		Order("id DESC").Limit(int64(limit)).Offset(int64(offset)).Scan(ctx); err != nil {
		return nil, 0, err
	}
	if len(scans) == 0 {
		return nil, int(total), nil
	}

	// The read job carries the outcome of parsing, and it is kept after it
	// finishes rather than deleted, so it stays answerable for as long as the
	// scan it belongs to.
	references := make([]string, 0, len(scans))
	for _, sc := range scans {
		references = append(references, strconv.FormatInt(sc.ID, 10))
	}
	// A scan can be read more than once — set aside as overtaken, then read
	// again when the scan that overtook it failed — so the latest job for it
	// is the one that says where it has got to.
	var jobs []queue.Job
	if err := s.db.NewSelect().Model(&jobs).
		Where(`"kind" = ?`, queue.Parse).
		Where(`"reference" IN (?)`, bun.List(references)).
		Order("id ASC").Scan(ctx); err != nil {
		return nil, 0, err
	}
	read := make(map[string]queue.Job, len(jobs))
	for _, j := range jobs {
		read[j.Reference] = j
	}

	// One run covers a target rather than a scan, so what matters is whether a
	// run finished after this upload was parsed. Every finished run rather
	// than only the newest, because a page of receipts spans several and each
	// upload is answered by the run that came after it rather than by the last
	// one to happen.
	// Ordered by when they finished, because that is the order the
	// attribution below walks them in. Asked for by identifier, the two agree
	// only while no run finishes out of the order it was started in — which is
	// routine the moment one run is long and another is queued behind it, and
	// the receipt then cites the wrong run and loses its counts. The
	// identifier is the tiebreaker, so the result is deterministic.
	var runs []finding.Run
	if err := s.db.NewSelect().Model(&runs).
		Where(`"target_id" = ?`, targetID).
		Where(`"finished_at" IS NOT NULL`).
		Order("finished_at DESC", "id DESC").Scan(ctx); err != nil {
		return nil, 0, err
	}

	// The upload each run is attributed to, worked out over *every* scan
	// rather than over this page.
	//
	// A page is a window on the same history. Decided from the rows in front
	// of us, a run claimed on page one is claimed again on page two by the
	// first older upload it also covered, and its counts render twice. The
	// claim is a property of the scan, not of the page it appears on.
	claimed, err := s.claims(ctx, targetID, runs)
	if err != nil {
		return nil, 0, err
	}

	receipts := make([]Receipt, 0, len(scans))
	for _, sc := range scans {
		state, failure, caution, run := progressOf(sc, read[strconv.FormatInt(sc.ID, 10)], runs)
		receipt := Receipt{Scan: sc, State: state, Failure: failure, Caution: caution}
		if run != nil {
			// The tooling it was measured with, on every receipt the run
			// answers — and the counts only on the one it is attributed to.
			for i := range runs {
				if runs[i].ID == *run {
					receipt.Measured = &runs[i]
					break
				}
			}
			if claimed[*run] == sc.ID {
				receipt.RunID = run
			}
		}
		receipts = append(receipts, receipt)
	}
	return receipts, int(total), nil
}

// progressOf folds a scan, the job that read it and the target's latest
// finished run into one answer.
func progressOf(sc Scan, job queue.Job, runs []finding.Run) (Progress, string, string, *int64) {
	if sc.Status == Failed {
		return Refused, sc.Failure, "", nil
	}
	switch job.State {
	case queue.Dead:
		// The scan row is marked too, but a job that died before it could mark
		// anything would otherwise read as still being worked on. Fixed words:
		// the job's last error is whatever failed, a dropped connection's
		// address included, and a refusal reaches the receipt through the
		// scan row instead.
		return Refused, "the scan could not be applied", "", nil
	case queue.Pending, queue.Running:
		return Reading, "", "", nil
	}
	if job.State != queue.Done {
		// No job row at all. An upload that matched one already held is
		// answered by the scan it matched, which has its own job.
		return Reading, "", "", nil
	}

	parsed := job.UpdatedAt
	if parsed.IsZero() {
		parsed = sc.ReceivedAt
	}
	// The run that answers this upload is the earliest *successful* one to
	// finish after it was parsed. The query asks for them newest first by
	// finish time, so the last assignment in each branch below is the earliest
	// of its kind.
	//
	// A run that failed only answers an upload while nothing has succeeded
	// since. A scan run covers a build rather than an upload, and this upload
	// is the newest document the build holds, so a later run that finished
	// cleanly did read this document, and saying otherwise makes one bad night
	// permanent. Taking the earliest run after parsing whatever became of it,
	// a scanner that falls over once poisons every receipt already waiting on
	// it for ever, however many green runs come afterwards, and the scans
	// screen gets steadily more wrong the longer a deployment runs.
	//
	// Still Refused while every run since has failed, which is the honest
	// answer to "did anything come of my upload" at that point.
	var answered, failed *finding.Run
	for i := range runs {
		if runs[i].FinishedAt == nil || runs[i].FinishedAt.Before(parsed) {
			continue
		}
		if runs[i].Failure != "" {
			failed = &runs[i]
			continue
		}
		answered = &runs[i]
	}
	if answered != nil {
		return Scanned, "", answered.Caution, &answered.ID
	}
	if failed != nil {
		return Refused, failed.Failure, "", nil
	}
	return Scanning, "", "", nil
}

// claims says which upload each run's numbers belong to: the newest one it
// covered, decided over the whole history rather than over one page of it.
//
// Two columns for every scan filed here and read, which the target index
// answers directly, and the state of the job that read each. Arrival stands in for the moment a document was parsed — they are
// seconds apart, and what is being decided is only which of two uploads a run
// came after, so the distinction cannot change the answer without the two
// having arrived either side of the run finishing, in which case arrival is
// the more truthful of the two anyway.
func (s *Store) claims(ctx context.Context, targetID int64,
	runs []finding.Run) (map[int64]int64, error) {

	var filed []filing
	// Only an upload that was read can have been covered by a run. One that
	// failed carries no run, and one still being read is not yet what the
	// build holds, so attributed to either, a run's counts appear on no
	// receipt.
	q := s.db.NewSelect().TableExpr(`"scan" AS "sc"`).
		Column("sc.id", "sc.received_at").
		Where(`"sc"."target_id" = ?`, targetID).
		Where(`"sc"."status" = ?`, Accepted)
	// Newest first by when it arrived, which is what "the newest upload this
	// run covered" asks about. By arrival rather than by identifier because
	// two uploads recorded at the same moment take their identifiers in
	// whichever order they reach the table, and identifier order is then not
	// arrival order; the identifier breaks the tie so that the answer does not
	// depend on which engine is underneath.
	if err := q.Order("sc.received_at DESC", "sc.id DESC").Scan(ctx, &filed); err != nil {
		return nil, fmt.Errorf("read what has been filed here: %w", err)
	}
	done, err := s.readDone(ctx, filed)
	if err != nil {
		return nil, err
	}
	kept := filed[:0]
	for _, sc := range filed {
		if done[sc.ID] {
			kept = append(kept, sc)
		}
	}
	filed = kept

	// The runs newest first by when they finished, which is the order the
	// uploads are already in. Sorted here rather than by the engine: the
	// caller holds them in identifier order because that is the order the page
	// reads them in, and an ordering that answers one question is not the one
	// that answers the other.
	order := make([]int, 0, len(runs))
	for i := range runs {
		if runs[i].FinishedAt != nil {
			order = append(order, i)
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		return runs[order[a]].FinishedAt.After(*runs[order[b]].FinishedAt)
	})

	// One pass over each list rather than a pass over the uploads for every
	// run. Both lists run newest first, so the upload a run is attributed to
	// is never newer than the one the run before it was attributed to, and the
	// walk carries on from where that one stopped.
	claimed := make(map[int64]int64, len(order))
	at := 0
	for _, i := range order {
		run := runs[i]
		for at < len(filed) && filed[at].ReceivedAt.After(*run.FinishedAt) {
			at++
		}
		if at == len(filed) {
			// Every upload here arrived after this run finished, which is also
			// true of every older run behind it.
			break
		}
		claimed[run.ID] = filed[at].ID
	}
	return claimed, nil
}

// filing is one upload filed against a build, as attribution reads it.
type filing struct {
	ID         int64     `bun:"id"`
	ReceivedAt time.Time `bun:"received_at"`
}

// readDone is which of these scans the reader has finished reading: the
// latest job to read each is done. A scan can be read more than once, so the
// latest job is the one that says where it has got to.
func (s *Store) readDone(ctx context.Context, filed []filing) (map[int64]bool, error) {
	ids := make([]int64, 0, len(filed))
	for _, sc := range filed {
		ids = append(ids, sc.ID)
	}
	latest := make(map[string]queue.State, len(ids))
	err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		references := make([]string, 0, len(batch))
		for _, id := range batch {
			references = append(references, strconv.FormatInt(id, 10))
		}
		var jobs []queue.Job
		if err := s.db.NewSelect().Model(&jobs).
			Column("reference", "state").
			Where(`"kind" = ?`, queue.Parse).
			Where(`"reference" IN (?)`, bun.List(references)).
			Order("id ASC").Scan(ctx); err != nil {
			return err
		}
		for _, j := range jobs {
			latest[j.Reference] = j.State
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read which uploads have been read: %w", err)
	}
	done := make(map[int64]bool, len(ids))
	for _, id := range ids {
		done[id] = latest[strconv.FormatInt(id, 10)] == queue.Done
	}
	return done, nil
}
