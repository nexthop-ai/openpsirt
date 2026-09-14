package finding

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Sweeper applies standing routing rules to work nobody holds.
//
// **Queued work, in bounded batches.** One rule naming a source package sweeps
// thousands of existing unowned issues across every place each sits at, so what
// was asked for — one rule — and what is written differ by four orders of
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
	// batch is how many findings one job may place, where a test fixes it.
	// Zero reads the deployment's own number as each pass begins.
	batch int
}

// NewSweeper is the sweep as a deployment runs it, taking its bound from the
// deployment rather than from the binary.
//
// The bound was a constant here and a second constant in the writer, under a
// comment declining the decision that says a bulk write's cap is a setting.
// An operator on a large estate has reason to move it in either direction — a
// pass too big holds a connection through the whole of it, and one too small
// leaves a fifty-thousand-finding product re-queuing twenty-five times — and
// neither is a rebuild.
func NewSweeper(db *database.DB, q *queue.Queue, logger *slog.Logger, name string) *Sweeper {
	return &Sweeper{db: db, queue: q, logger: logger, name: name}
}

// NewSweeperOfSize is a sweeper with a batch of a given size, so that what a
// batch does when it fills can be exercised against a handful of findings
// rather than two thousand.
func NewSweeperOfSize(db *database.DB, q *queue.Queue, logger *slog.Logger,
	name string, batch int) *Sweeper {
	if batch <= 0 {
		batch = 2000
	}
	return &Sweeper{db: db, queue: q, logger: logger, name: name, batch: batch}
}

// Run works the sweep queue until the context ends.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		for {
			placed, err := s.Once(ctx)
			if err != nil {
				if ctx.Err() == nil {
					s.logger.Error("placing work by rule", "error", err)
				}
				break
			}
			if placed == 0 {
				break
			}
			s.logger.Info("placed work by rule", "findings", placed)
		}
		timer.Reset(interval)
	}
}

// Once claims one sweep and runs a batch of it, reporting how many findings it
// placed.
func (s *Sweeper) Once(ctx context.Context) (int, error) {
	job, err := s.queue.Claim(ctx, s.name, queue.Route)
	if err != nil || job == nil {
		return 0, err
	}
	productID, err := strconv.ParseInt(job.Reference, 10, 64)
	if err != nil {
		// A reference nothing can read is not something to retry. Failing it
		// is what puts it in front of an operator.
		settled, done := queue.Settling(ctx)
		defer done()
		_ = s.queue.Fail(settled, job.ID, s.name, fmt.Errorf("not a product: %q", job.Reference))
		return 0, nil
	}

	// Read as the pass begins rather than when the sweeper was built, so a
	// number an administrator changes takes effect on the next pass rather
	// than on the next restart.
	batch := s.batch
	if batch <= 0 {
		batch, err = setting.NewStore(s.db.DB).Count(ctx, setting.RoutingBatch,
			setting.DefaultRoutingBatch)
		if err != nil {
			return 0, err
		}
	}

	working, release := s.queue.Holding(ctx, job.ID, s.name, s.logger)
	placed, filled, err := NewStore(s.db.DB).ApplyRules(working, productID, batch)
	taken := release()

	ending := s.queue.Settle(ctx, job, s.name, "product", s.logger, err, taken, nil)
	if ending.HandedOver || ending.Err != nil {
		return placed, ending.Err
	}

	// A full batch means there is more of the estate to walk. Queued again
	// rather than looped here, so the worker is free between batches and an
	// operator can see that the work is still going.
	//
	// Full is measured by what the batch read rather than by what it wrote:
	// one assignment made by a person inside the window leaves a row of the
	// batch already held, and reading that as the end stopped the sweep with
	// the rest of the estate unrouted and the job reported successful.
	if filled {
		// Its own context that outlives a cancellation, for the same reason
		// settling has one: a shutdown must not be what loses the rest of the
		// estate.
		settled, done := queue.Settling(ctx)
		defer done()
		if _, err := s.queue.Add(settled, queue.Route, job.Reference); err != nil {
			s.logger.Warn("could not queue the rest of a routing sweep",
				"product", productID, "error", err)
		}
	}
	return placed, nil
}
