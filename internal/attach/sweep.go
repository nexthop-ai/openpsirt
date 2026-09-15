package attach

import (
	"context"
	"log/slog"
	"time"

	"github.com/uptrace/bun"
)

// betweenSweeps is how often uploads nothing refers to are looked for.
//
// Slow, because what it collects is slow to appear: somebody abandons a form
// once in a while, not once a minute. Looking is one query that finds nothing,
// which is the answer on nearly every pass.
const betweenSweeps = time.Hour

// keepUnattachedFor is how long an upload nothing refers to is kept.
//
// Somebody attaching a file is part way through writing a justification, and
// the justification is not saved until they finish it. A day is far longer
// than that takes, and short enough that what was abandoned does not sit
// there being counted against the deployment's quota.
const keepUnattachedFor = 24 * time.Hour

// Keeper removes uploads that were never referred to.
//
// Its own pass rather than work done on the way past something else: an
// abandoned upload is not noticed by anything a person does, so nothing else
// would ever be the moment to look.
type Keeper struct {
	store  *Store
	logger *slog.Logger
	after  time.Duration
}

// NewKeeper returns the sweep, or nil where this deployment holds no files.
//
// Nil rather than a pass that does nothing: a worker started for a feature the
// deployment does not have is a goroutine and a log line an operator has to
// work out the meaning of.
//
// **The caller checks, and Run does not.** A nil-receiver guard on Run as well
// made the answer here look optional to read and left a branch nothing could
// reach — the caller that starts this is the one place that knows whether a
// deployment keeps files.
func NewKeeper(db *bun.DB, files Storage, logger *slog.Logger, after time.Duration) *Keeper {
	if files == nil {
		return nil
	}
	if after <= 0 {
		after = keepUnattachedFor
	}
	return &Keeper{store: NewStore(db, files), logger: logger, after: after}
}

// Run sweeps until the context ends.
func (k *Keeper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = betweenSweeps
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		// Logged and carried on, like every other background pass here: a
		// sweep that cannot run is not a reason to stop serving, and what it
		// failed to collect is still there on the next one.
		if gone, err := k.store.Sweep(ctx, k.after); err != nil {
			k.logger.ErrorContext(ctx, "removing uploads nothing refers to", "error", err)
		} else if gone > 0 {
			k.logger.InfoContext(ctx, "removed uploads nothing refers to", "files", gone)
		}
		timer.Reset(interval)
	}
}
