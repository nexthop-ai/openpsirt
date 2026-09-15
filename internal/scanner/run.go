package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Runner scans what a target contains and records what was found.
//
// Separate work from reading a scan, because the two happen at different
// times: an inventory is read once when it arrives, and it is scanned again
// and again as the vulnerability data moves underneath it. A release built a
// year ago has the same components it always had and a different answer every
// month.
type Runner struct {
	db      *database.DB
	queue   *queue.Queue
	scanner Scanner
	logger  *slog.Logger
	name    string
	// told carries what lapsed to whoever tells people about it.
	//
	// A hook rather than a call, because a scanner has no business knowing
	// how anybody is notified — and because the notification package reads
	// what has been ingested, so a scanner that reached it directly would
	// close a cycle between the two.
	told func(context.Context, []triage.ForPerson)
}

// NewRunner returns a runner over db.
func NewRunner(db *database.DB, q *queue.Queue, s Scanner, logger *slog.Logger, name string) *Runner {
	return &Runner{db: db, queue: q, scanner: s, logger: logger, name: name}
}

// Outcome is what scanning one target did.
type Outcome struct {
	TargetID   int64
	RunID      int64
	Components int
	Applied    finding.Applied
	// Lapsed is how many judgments this scan moved out from under, and so how
	// many people have something waiting for them that they did not have
	// before.
	Lapsed int64
}

// Telling says what to do with the claims a scan took out from under people.
//
// Left unset a runner tells nobody, which is what every test and every
// single-purpose invocation wants; the deployment wires it once.
func (r *Runner) Telling(tell func(context.Context, []triage.ForPerson)) *Runner {
	r.told = tell
	return r
}

// Once claims one target and scans it, reporting whether there was anything to
// do.
func (r *Runner) Once(ctx context.Context) (*Outcome, error) {
	job, err := r.queue.Claim(ctx, r.name, queue.Scan)
	if err != nil || job == nil {
		return nil, err
	}

	// The claim is renewed while the scan runs. A scan of a large image
	// legitimately takes longer than a claim is honored for with nothing heard
	// from the worker, and without renewal a second worker would take the job
	// over and scan the same target alongside this one.
	working, release := r.queue.Holding(ctx, job.ID, r.name, r.logger)
	outcome, err := r.scan(working, job.Reference)
	taken := release()

	ending := r.queue.Settle(ctx, job, r.name, "target", r.logger, err, taken, nil)
	if ending.HandedOver {
		return nil, nil
	}
	return outcome, ending.Err
}

// betweenRuns is how long an idle runner waits before asking for work again
// where the caller says nothing.
const betweenRuns = 5 * time.Second

// Run scans until the context ends.
func (r *Runner) Run(ctx context.Context, interval time.Duration) {
	background.Every(ctx, interval, betweenRuns, func(ctx context.Context) {
		for {
			outcome, err := r.Once(ctx)
			if err != nil {
				if ctx.Err() == nil {
					r.logger.Error("scanning a target", "error", err)
				}
				break
			}
			if outcome == nil {
				break
			}
			r.logger.Info("scanned a target",
				"target", outcome.TargetID, "run", outcome.RunID,
				"components", outcome.Components,
				"findings_opened", outcome.Applied.Opened,
				"findings_closed", outcome.Applied.Closed,
				"suppressed", outcome.Applied.Suppressed,
				"claims_reaching", outcome.Applied.ClaimsReaching,
				"claims_reaching_nothing", outcome.Applied.ClaimsReachingNothing,
				"updated", outcome.Applied.Updated,
				"unexplained", outcome.Applied.Unexplained,
				"unplaced", outcome.Applied.Unplaced,
				"lapsed", outcome.Lapsed)

			// Several findings vanishing at once, with the components still
			// present and unchanged, is one broken scan rather than a dozen
			// independent oddities. Each one is already flagged on its own —
			// this only says which shape the fault is, so nobody spends the
			// morning chasing them separately.
			//
			// A count rather than a proportion: on a large image a handful of
			// genuine disappearances is ordinary and a handful of unexplained
			// ones is not, and dividing by the size of the image would hide
			// exactly that.
			if outcome.Applied.Unexplained >= unexplainedAlert {
				r.logger.Warn("several findings disappeared with nothing to explain it, "+
					"which usually means one scan went wrong rather than many things changing",
					"target", outcome.TargetID, "run", outcome.RunID,
					"unexplained", outcome.Applied.Unexplained,
					"closed", outcome.Applied.Closed)
			}
		}
	})
}

// unexplainedAlert is how many unexplained disappearances in one scan suggest
// the scan rather than the software.
//
// Low, because it is a hint and not a gate: the individual flags are raised
// either way, and the cost of saying so when nothing was wrong is one log line
// somebody ignores.
const unexplainedAlert = 5

// scan runs the scanner over one target's contents.
func (r *Runner) scan(ctx context.Context, reference string) (*Outcome, error) {
	targetID, err := strconv.ParseInt(reference, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("job names %q, which is not a target: %w", reference, err)
	}

	components, err := graph.NewStore(r.db.DB).CurrentComponents(ctx, targetID)
	if err != nil {
		return nil, err
	}

	findings := finding.NewStore(r.db.DB)
	run, err := findings.Begin(ctx, finding.Run{
		TargetID: targetID, Scanner: r.scanner.Name(), RanHere: true,
	})
	if err != nil {
		return nil, err
	}

	outcome, result, err := r.assess(ctx, targetID, run.ID, components, findings)
	// The run is recorded as having ended either way. A scanner that stopped
	// working is otherwise indistinguishable from a product that stopped
	// having problems — and a shutdown that canceled the scan must not also
	// cancel the record of it, or the run is left open for ever.
	settled, done := queue.Settling(ctx)
	defer done()
	if finished := findings.Finish(settled, run.ID, result.Version, result.DatabaseVersion,
		result.Caution, err); finished != nil {
		r.logger.Error("could not record the end of a scan run", "run", run.ID, "error", finished)
	}
	if err != nil {
		return nil, err
	}
	return outcome, nil
}

// assess writes the inventory, runs the scanner over it, and records what came
// back.
func (r *Runner) assess(ctx context.Context, targetID, runID int64, components []graph.Described, findings *finding.Store) (*Outcome, Result, error) {
	var inventory bytes.Buffer
	if err := sbom.WriteInventory(&inventory, components); err != nil {
		return nil, Result{}, err
	}

	result, err := r.scanner.Scan(ctx, &inventory)
	if err != nil {
		return nil, Result{}, err
	}

	applied, err := findings.Apply(ctx, targetID, runID, result.Reported)
	if err != nil {
		return nil, result, err
	}

	// Now that the versions have moved, mark the judgments they moved out from
	// under. A decision is matched on the versions it was made about, so one
	// whose versions changed already stops applying — what this adds is that
	// somebody is told, rather than the finding quietly reappearing as new
	// with the reasoning stranded on a row nothing points at.
	//
	// A failure here is reported and not fatal. What was found is recorded and
	// correct; the marking is a prompt, and losing a scan over a prompt would
	// be the wrong trade.
	lapsed, err := triage.NewStore(r.db.DB).Lapse(ctx, targetID)
	if err != nil {
		r.logger.Error("could not mark what the code moved out from under",
			"target", targetID, "error", err)
	}
	if r.told != nil && len(lapsed.Told) > 0 {
		r.told(ctx, lapsed.Told)
	}

	return &Outcome{
		TargetID: targetID, RunID: runID,
		Components: len(components), Applied: applied, Lapsed: lapsed.Rows,
	}, result, nil
}
