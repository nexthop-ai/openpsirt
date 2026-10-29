// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/series"
)

// Worker applies queued runs.
type Worker struct {
	applier *Applier
	queue   *queue.Queue
	logger  *slog.Logger
	name    string
}

// NewWorker returns a worker applying runs with applier, which queues the
// assignment sweep of what a run opens on q, the queue the runs come from.
func NewWorker(applier *Applier, q *queue.Queue, logger *slog.Logger, name string) *Worker {
	applier.sweeps = q
	return &Worker{applier: applier, queue: q, logger: logger, name: name}
}

// untilInventory is how long a run waiting for its build's inventory waits
// before it is asked about again. An analysis job and the inventory upload
// usually finish within minutes of each other.
const untilInventory = time.Minute

// Applied is what applying one run did.
type Applied struct {
	RunID  int64
	Status series.Status
}

// Once claims one run and applies it, reporting whether there was anything to
// do. A run waiting for its build's inventory hands its job back untried.
func (w *Worker) Once(ctx context.Context) (*Applied, error) {
	job, err := w.queue.Claim(ctx, w.name, queue.Analyze)
	if err != nil || job == nil {
		return nil, err
	}
	runID, err := strconv.ParseInt(job.Reference, 10, 64)
	if err != nil {
		err = fmt.Errorf("job names %q, which is not a run: %w", job.Reference, err)
		ending := w.queue.Settle(ctx, job, w.name, "run", w.logger, err, nil, nil)
		return nil, ending.Err
	}

	working, release := w.queue.Holding(ctx, job.ID, w.name, w.logger)
	status, err := w.applier.Apply(working, runID)
	taken := release()

	if err == nil && taken == nil && status == series.Waiting {
		if err := w.queue.Postpone(ctx, job.ID, w.name, untilInventory,
			"the build has no inventory that has been read"); err != nil {
			return nil, fmt.Errorf("hand back a run waiting for its build's inventory: %w", err)
		}
		return &Applied{RunID: runID, Status: status}, nil
	}
	ending := w.queue.Settle(ctx, job, w.name, "run", w.logger, err, taken, nil)
	if ending.HandedOver {
		return nil, nil
	}
	return &Applied{RunID: runID, Status: status}, ending.Err
}

// betweenRuns is how long an idle worker waits before asking for work again
// where the caller says nothing.
const betweenRuns = 5 * time.Second

// Run applies runs until the context ends.
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	background.Drain(ctx, interval, betweenRuns, func(ctx context.Context) (bool, error) {
		applied, err := w.Once(ctx)
		if err != nil || applied == nil {
			return false, err
		}
		w.logger.Info("applied an analyzer run", "run", applied.RunID, "status", applied.Status)
		// A run handed back to wait is not progress, and draining on would
		// claim it again at once.
		return applied.Status != series.Waiting, nil
	}, func(err error) { w.logger.Error("applying an analyzer run", "error", err) })
}
