// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/cverecord"
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
	// superseded carries the judgments a merge of two issues took out of
	// force, for the same reason.
	superseded func(context.Context, []finding.Displaced)
	// records is the CVE record snapshot a match is narrowed with. Nil reads
	// none and narrows nothing.
	records *cverecord.Held
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

// Telling is the instruction for claims a scan took out from under people.
//
// Left unset a runner tells nobody, which is what every test and every
// single-purpose invocation wants; the deployment wires it once.
func (r *Runner) Telling(tell func(context.Context, []triage.ForPerson)) *Runner {
	r.told = tell
	return r
}

// TellingSuperseded is the instruction for judgments a merge of two issues took
// out of force because another said something different in the same product.
func (r *Runner) TellingSuperseded(tell func(context.Context, []finding.Displaced)) *Runner {
	r.superseded = tell
	return r
}

// Narrowing is the CVE record snapshot matches are narrowed with.
func (r *Runner) Narrowing(records *cverecord.Held) *Runner {
	r.records = records
	return r
}

// Once claims one target and scans it, reporting whether there was anything to
// do.
func (r *Runner) Once(ctx context.Context) (*Outcome, error) {
	job, err := r.queue.Claim(ctx, r.name, queue.Scan)
	if err != nil || job == nil {
		return nil, err
	}

	// Asked before the run begins, and a scan that has to wait hands its job
	// back untried: a failed attempt would set the job aside after a few
	// minutes, and a run begun would keep the schedule from asking again for
	// a day.
	records, wait := r.narrowedWith(ctx, job.Reference)
	if wait != nil {
		r.logger.Warn("a scan waits for the CVE record snapshot", "target", job.Reference, "reason", wait)
		if err := r.queue.Postpone(ctx, job.ID, r.name, untilRecords, wait.Error()); err != nil {
			return nil, fmt.Errorf("hand back a scan waiting for the CVE record snapshot: %w", err)
		}
		return nil, nil
	}

	// The claim is renewed while the scan runs. A scan of a large image
	// legitimately takes longer than a claim is honored for with nothing heard
	// from the worker, and without renewal a second worker would take the job
	// over and scan the same target alongside this one.
	working, release := r.queue.Holding(ctx, job.ID, r.name, r.logger)
	outcome, err := r.scan(working, job.Reference, records)
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
	background.Drain(ctx, interval, betweenRuns, func(ctx context.Context) (bool, error) {
		outcome, err := r.Once(ctx)
		if err != nil || outcome == nil {
			return false, err
		}
		r.logger.Info("scanned a target",
			"target", outcome.TargetID, "run", outcome.RunID,
			"components", outcome.Components,
			"findings_opened", outcome.Applied.Opened,
			"findings_closed", outcome.Applied.Closed,
			"suppressed", outcome.Applied.Suppressed,
			"patched", outcome.Applied.Patched,
			"unaffected", outcome.Applied.Unaffected,
			"claims_reaching", outcome.Applied.ClaimsReaching,
			"claims_reaching_nothing", outcome.Applied.ClaimsReachingNothing,
			"updated", outcome.Applied.Updated,
			"unexplained", outcome.Applied.Unexplained,
			"unplaced", outcome.Applied.Unplaced,
			"merged", outcome.Applied.Merged,
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
		return true, nil
	}, func(err error) { r.logger.Error("scanning a target", "error", err) })
}

// unexplainedAlert is how many unexplained disappearances in one scan suggest
// the scan rather than the software.
//
// Low, because it is a hint and not a gate: the individual flags are raised
// either way, and the cost of saying so when nothing was wrong is one log line
// somebody ignores.
const unexplainedAlert = 5

// untilRecords is how long a scan waiting for the CVE record snapshot is put
// back for. A fetch takes minutes.
const untilRecords = 5 * time.Minute

// narrowedWith is the CVE record snapshot a scan of a target narrows with, or
// why the scan has to wait for one.
//
// A snapshot that cannot be read is waited for: run without it, every finding
// a record had closed opens again, and closes again on the next run that reads
// one. So is a snapshot absent where any run of the build read one, which is
// what a replica restarted on scratch space holds until its first fetch lands.
// A build no run ever narrowed is scanned without one.
func (r *Runner) narrowedWith(ctx context.Context, reference string) (*cverecord.Snapshot, error) {
	records, err := r.records.Current()
	if err != nil {
		return nil, err
	}
	if records != nil || r.records == nil {
		return records, nil
	}
	targetID, err := strconv.ParseInt(reference, 10, 64)
	if err != nil {
		// The scan reports a reference that is not a target, as it always has.
		return nil, nil
	}
	last, err := finding.NewStore(r.db.DB).LastRecordsVersion(ctx, targetID)
	switch {
	case err != nil:
		return nil, err
	case last != "":
		return nil, fmt.Errorf("no CVE record snapshot is held in %s, and this build was "+
			"last scanned with the one of %s", r.records.Dir(), last)
	}
	return nil, nil
}

// scan runs the scanner over one target's contents.
func (r *Runner) scan(ctx context.Context, reference string, records *cverecord.Snapshot) (*Outcome, error) {
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
		RecordsVersion: records.Version(),
	})
	if err != nil {
		return nil, err
	}

	outcome, result, err := r.assess(ctx, targetID, run.ID, components, records, findings)
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
func (r *Runner) assess(ctx context.Context, targetID, runID int64, components []graph.Described,
	records *cverecord.Snapshot, findings *finding.Store) (*Outcome, Result, error) {
	// A build holding nothing but itself has nothing to scan, and the scanner
	// is not asked. Handed an inventory of no components it exits with an
	// error rather than answering none, and a run recorded as failed reads as
	// a scanner that stopped working. A services-only inventory, a VEX
	// document sent as one, and a source document naming only itself all
	// arrive this way.
	var result Result
	if len(components) > 0 {
		var inventory bytes.Buffer
		if err := sbom.WriteInventory(&inventory, components); err != nil {
			return nil, Result{}, err
		}
		scanned, err := r.scanner.Scan(ctx, &inventory)
		if err != nil {
			return nil, Result{}, err
		}
		result = scanned
	}

	if err := narrow(records, components, result.Reported); err != nil {
		return nil, result, err
	}
	applied, err := findings.Apply(ctx, targetID, runID, result.Reported)
	if err != nil {
		return nil, result, err
	}
	if r.superseded != nil && len(applied.Displaced) > 0 {
		r.superseded(ctx, applied.Displaced)
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
	// And the judgments a rating this scan raised has outgrown (REQ-25). An
	// issue is one row for the whole deployment, so a scan of one build can
	// raise the rating a claim in another product was made against; the issues
	// asked about are the ones this build has open. Unlike a version lapse,
	// nothing matched changes, so a claim this fails to mark stands until the
	// next scan with the issue open sweeps again.
	worse, err := triage.NewStore(r.db.DB).LapseRatedWorse(ctx,
		triage.RatedWorseWhere{OpenIn: targetID})
	if err != nil {
		r.logger.Error("could not mark what a rating rise outgrew",
			"target", targetID, "error", err)
	}
	if r.told != nil && len(worse.Told) > 0 {
		r.told(ctx, worse.Told)
	}
	lapsed.Rows += worse.Rows

	// A scan is the write that moves the tables furthest, so it is where the
	// planner's statistics fall behind. Not fatal: what was found is recorded,
	// and stale statistics make a query slow rather than wrong.
	if err := database.RefreshStatistics(ctx, r.db); err != nil {
		r.logger.Error("could not refresh the planner's statistics", "target", targetID, "error", err)
	}

	return &Outcome{
		TargetID: targetID, RunID: runID,
		Components: len(components), Applied: applied, Lapsed: lapsed.Rows,
	}, result, nil
}
