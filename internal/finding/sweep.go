// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Arrived queues the assignment sweep of a product that work has just opened
// in, inside the transaction that opened it, so the sweep cannot be claimed
// before the work it is for exists.
//
// A rule places what nobody holds whenever its product's sweep runs, so a
// sweep runs when a rule is written and when work arrives.
//
// Queued only where the product has a rule placing findings, so a deployment
// with no rules queues nothing. A full sweep queue leaves this arrival to the
// next one rather than failing what brought it: refusing a scan loses its
// findings, where an unqueued sweep only delays placing them.
func Arrived(ctx context.Context, tx bun.IDB, q *queue.Queue, productID int64) error {
	if q == nil {
		return nil
	}
	ruled, err := tx.NewSelect().Model((*AssignmentRule)(nil)).
		Where(`"product_id" = ?`, productID).
		Where(`"retired_at" IS NULL`).
		Where(`"reports" = ?`, false).
		Exists(ctx)
	if err != nil {
		return fmt.Errorf("ask whether a rule places work in product %d: %w", productID, err)
	}
	if !ruled {
		return nil
	}
	_, err = q.AddTx(ctx, tx, queue.AssignmentSweep, strconv.FormatInt(productID, 10))
	if errors.Is(err, queue.ErrBacklogFull) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("queue the assignment sweep of product %d: %w", productID, err)
	}
	return nil
}

// Sweeper applies standing assignment rules to work nobody holds.
//
// Queued work, in bounded batches. One rule naming a source package sweeps
// thousands of existing unowned issues across every occurrence each sits at, so
// what was asked for — one rule — and what is written differ by four orders of
// magnitude. Doing it inside the request that saved the rule would make saving
// either time out or hold a transaction open across the whole estate.
//
// A batch that fills its cap queues itself again rather than looping here: a
// worker that holds one job for the length of an estate is a worker nothing
// else can use, and a job that reappears is a job an operator can see.
type Sweeper struct {
	db     *database.DB
	queue  *queue.Queue
	logger *slog.Logger
	name   string
}

// NewSweeper is the sweep as a deployment runs it, taking its bound from the
// deployment's settings: a pass too big holds a connection through the whole
// of it, and one too small leaves a fifty-thousand-finding product re-queuing
// twenty-five times.
func NewSweeper(db *database.DB, q *queue.Queue, logger *slog.Logger, name string) *Sweeper {
	return &Sweeper{db: db, queue: q, logger: logger, name: name}
}

// betweenSweeps is how often this looks where the caller says nothing. Short,
// because what it places is somebody's work arriving.
const betweenSweeps = 10 * time.Second

// Run works the sweep queue until the context ends.
//
// A pass claims sweeps until none is waiting, a sweep that places nothing
// included: most arrivals find their work already placed, and a pass ending
// there drains one sweep per interval while scans queue them at the speed of
// the work, until a full queue refuses every rule written.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	background.Drain(ctx, interval, betweenSweeps, func(ctx context.Context) (bool, error) {
		claimed, placed, err := s.Once(ctx)
		if placed > 0 {
			s.logger.Info("placed work by rule", "findings", placed)
		}
		return claimed, err
	}, func(err error) { s.logger.Error("placing work by rule", "error", err) })
}

// Once claims one sweep and runs a batch of it, reporting whether it claimed
// one and how many findings it placed.
func (s *Sweeper) Once(ctx context.Context) (bool, int, error) {
	// Read as the pass begins rather than when the sweeper was built, so a
	// number an administrator changes takes effect on the next pass rather
	// than on the next restart. Read before anything is claimed, so a failure
	// here leaves no job held until its claim goes stale.
	batch, err := setting.NewStore(s.db.DB).Count(ctx, setting.AssignmentBatch,
		setting.DefaultAssignmentBatch)
	if err != nil {
		return false, 0, err
	}

	job, err := s.queue.Claim(ctx, s.name, queue.AssignmentSweep)
	if err != nil || job == nil {
		return false, 0, err
	}
	productID, err := strconv.ParseInt(job.Reference, 10, 64)
	if err != nil {
		// A reference nothing can read is not something to retry. Failing it
		// is what puts it in front of an operator.
		settled, done := queue.Settling(ctx)
		defer done()
		// A failure to fail it is returned, and the loop reports it: the job
		// otherwise sits claimed until its lease runs out, and nobody hears.
		if err := s.queue.Fail(settled, job.ID, s.name,
			fmt.Errorf("not a product: %q", job.Reference)); err != nil {
			return true, 0, fmt.Errorf("fail assignment sweep %d, whose reference is not a product: %w", job.ID, err)
		}
		return true, 0, nil
	}

	working, release := s.queue.Holding(ctx, job.ID, s.name, s.logger)
	placed, filled, outgrown, err := NewStore(s.db.DB).ApplyRules(working, productID, batch)
	// A rule that has outgrown the bound is named rather than left to be
	// noticed. It ran when it was written and the tree grew under it, so the
	// sweep carries on past it — but a rule that has silently stopped placing
	// reads exactly like a rule nobody has needed.
	for _, rule := range outgrown {
		s.logger.Warn("an assignment rule names too much of the tree to run",
			"product", productID, "rule", rule)
	}
	taken := release()

	// A full batch means there is more of the estate to walk. Queued again
	// rather than looped here, so the worker is free between batches and an
	// operator can see that the work is still going.
	//
	// Full is measured by what the batch read: one assignment made by a
	// person inside the window leaves a row of the batch already held, and
	// counted on writes the sweep ends with the rest of the estate unrouted.
	//
	// Queued before this job is settled, and a failure to queue is this job's
	// failure, which is tried again: settled as done first, a failure to queue
	// the rest ends the sweep as a success. A batch run twice places only what
	// nobody holds.
	if filled && err == nil {
		// Its own context that outlives a cancellation, for the same reason
		// settling has one: a shutdown must not be what loses the rest of the
		// estate.
		queuing, done := queue.Settling(ctx)
		if _, queued := s.queue.Add(queuing, queue.AssignmentSweep, job.Reference); queued != nil {
			err = fmt.Errorf("queue the rest of the assignment sweep of product %d: %w", productID, queued)
		}
		done()
	}

	ending := s.queue.Settle(ctx, job, s.name, "product", s.logger, err, taken, nil)
	if ending.HandedOver || ending.Err != nil {
		return true, placed, ending.Err
	}
	return true, placed, nil
}
