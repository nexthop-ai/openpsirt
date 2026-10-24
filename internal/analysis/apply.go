// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package analysis applies an analyzer's run to a build: each result placed
// in the checkout, matched to what the series saw before, and recorded as a
// finding of the analysis kind.
package analysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sarif"
	"github.com/nexthop-ai/openpsirt/internal/series"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Applier applies stored runs.
type Applier struct {
	db     *database.DB
	limits sarif.Limits
	now    func() time.Time
}

// NewApplier returns an applier reading documents within limits.
func NewApplier(db *database.DB, limits sarif.Limits) *Applier {
	return &Applier{db: db, limits: limits, now: func() time.Time { return time.Now().UTC() }}
}

// Receipt is what a pipeline is told about a run it sent. It counts and
// never names a result.
type Receipt struct {
	Opened        int            `json:"opened" doc:"Results the run reported that the build did not hold open"`
	Seen          int            `json:"seen" doc:"Results the build held open that the run reported again"`
	Returned      int            `json:"returned" doc:"Of those seen again, the ones an earlier run had not reported"`
	NotReproduced int            `json:"not_reproduced" doc:"Results the build held open that this comparable run did not report"`
	WouldMark     int            `json:"would_mark,omitempty" doc:"How many a held run would have marked not reproduced"`
	Dropped       map[string]int `json:"dropped,omitempty" doc:"Results left out, by reason: advisory-identifier, outside-the-checkout, repeat, failure-signal, not-a-problem, suppressed or absent"`
	Scanners      []string       `json:"scanners,omitempty" doc:"The dependency and secret scanners whose runs were left out whole"`
	Discarded     map[string]int `json:"discarded,omitempty" doc:"What was left out of the results kept, by what it was: snippets, markdown, contents or fixes"`
}

// The reasons a result is dropped, as a receipt names them.
const (
	DroppedAdvisory = "advisory-identifier"
	DroppedOutside  = "outside-the-checkout"
	DroppedRepeat   = "repeat"
	DroppedFailure  = "failure-signal"
	// DroppedNotAProblem is a result whose kind reports no problem: a check
	// that passed, or one that did not apply.
	DroppedNotAProblem = "not-a-problem"
	DroppedSuppressed  = "suppressed"
	// DroppedAbsent is a result the tool says is no longer found.
	DroppedAbsent = "absent"
)

// prepared is a run's documents, read and placed.
type prepared struct {
	results []sarif.Placed
	tools   []string // per result, the tool that reported it
	remotes []string // per result, the repository its file is in
	rules   map[string]finding.Rule
	modules []series.Module
	signals int
	receipt Receipt
	failure string
}

// inventoryWait is how long a run waits for its build's inventory before it
// fails. A waiting run's job and documents are held while it waits, so a
// series analyzed on a build that is never inventoried would otherwise hold
// one of each per upload for good.
const inventoryWait = 24 * time.Hour

// Apply reads one stored run and applies it, reporting what became of it.
//
// The documents are read before the transaction that applies them. They do
// not change once stored, and the run's own state is read again inside.
func (a *Applier) Apply(ctx context.Context, runID int64) (series.Status, error) {
	store := series.NewStore(a.db.DB)
	run, err := store.ByID(ctx, runID)
	if err != nil {
		return "", err
	}
	if !pending(run.Status) {
		return run.Status, nil
	}
	read, err := a.read(ctx, store, run)
	if err != nil {
		return "", err
	}
	var status series.Status
	err = database.InTransaction(ctx, a.db.DB, func(ctx context.Context, tx bun.Tx) error {
		status, err = a.apply(ctx, tx, runID, read)
		return err
	})
	return status, err
}

// pending is whether a run is still to be applied.
func pending(s series.Status) bool { return s == series.Queued || s == series.Waiting }

// read reads a run's documents and places their results. A document that
// cannot be read is the run's failure, stated in words the sender is shown;
// a fault reading the stored bytes is returned.
func (a *Applier) read(ctx context.Context, store *series.Store, run *series.Run) (prepared, error) {
	docs, err := store.Documents(ctx, run.ID)
	if err != nil {
		return prepared{}, err
	}
	var logs []sarif.Log
	upload := sarif.NewUpload(a.limits)
	for i := range docs {
		log, err := upload.Read(store.Open(ctx, &docs[i]))
		var refused refusal.Refusal
		switch {
		case errors.As(err, &refused):
			return prepared{failure: fmt.Sprintf("document %d: %s", i+1, err)}, nil
		case err != nil:
			return prepared{}, err
		}
		logs = append(logs, log)
	}
	return place(logs, run), nil
}

// place puts every result of a run's documents in the checkout.
func place(logs []sarif.Log, run *series.Run) prepared {
	out := prepared{
		rules:   map[string]finding.Rule{},
		receipt: Receipt{Dropped: map[string]int{}, Discarded: map[string]int{}},
	}
	placer := sarif.NewPlacer()
	var discarded sarif.Discarded
	kept := 0
	for _, log := range logs {
		for i := range log.Runs {
			r := &log.Runs[i]
			if sarif.Scanner(r.Tool.Name) {
				out.receipt.Scanners = append(out.receipt.Scanners, r.Tool.Name)
				continue
			}
			kept++
			if !r.Ran {
				out.failure = "a run states no results, which is an analyzer that did not run"
				return out
			}
			discarded.Add(r.Discarded)
			for _, inv := range r.Invocations {
				out.signals += inv.Errors
			}
			for _, res := range placer.Place(r, run.SourceRoot) {
				name := ruleName(r.Tool.Name, res.RuleID)
				if _, ok := out.rules[name]; !ok {
					rule, _ := r.RuleOf(res.RuleID)
					out.rules[name] = finding.Rule{Name: name, Description: rule.Description, Tags: rule.Tags}
				}
				remote := ""
				if res.Module >= 0 && res.Module < len(r.Modules) {
					remote = normalizedRemote(r.Modules[res.Module].Repository)
				}
				out.results = append(out.results, res)
				out.tools = append(out.tools, r.Tool.Name)
				out.remotes = append(out.remotes, remote)
			}
			out.modules = append(out.modules, modulesOf(r, run.SourceRoot)...)
		}
	}
	if kept == 0 {
		out.failure = "every run is a dependency or secret scanner's, and this upload takes neither"
		return out
	}
	d := placer.Dropped()
	out.signals += d.Failure
	for reason, n := range map[string]int{
		DroppedAdvisory: d.Advisory, DroppedOutside: d.Outside, DroppedRepeat: d.Repeats,
		DroppedFailure: d.Failure, DroppedNotAProblem: d.NotAProblem,
		DroppedSuppressed: d.Suppressed, DroppedAbsent: d.Absent,
	} {
		if n > 0 {
			out.receipt.Dropped[reason] += n
		}
	}
	for what, n := range map[string]int{
		"snippets": discarded.Snippets, "markdown": discarded.Markdown,
		"contents": discarded.Contents, "fixes": discarded.Fixes,
	} {
		if n > 0 {
			out.receipt.Discarded[what] = n
		}
	}
	return out
}

// modulesOf is the repositories a run says its checkout held, placed in it.
func modulesOf(r *sarif.Run, root string) []series.Module {
	paths := sarif.PathsOf(r, root)
	changed := map[string]bool{}
	for _, c := range r.Properties.Changed {
		changed[c] = true
	}
	var out []series.Module
	for i, m := range r.Modules {
		at, ok := paths.ModulePath(i)
		if !ok {
			continue
		}
		out = append(out, series.Module{
			Path: at, Remote: m.Repository, Revision: m.Revision, Changed: changed[at],
		})
	}
	return out
}

// apply applies a prepared run inside one transaction.
func (a *Applier) apply(ctx context.Context, tx bun.Tx, runID int64, read prepared) (series.Status, error) {
	store := series.NewStore(tx)
	if err := store.Take(ctx, runID); err != nil {
		return "", err
	}
	run, err := store.ByID(ctx, runID)
	if err != nil {
		return "", err
	}
	if !pending(run.Status) {
		return run.Status, nil
	}
	if read.failure != "" {
		run.Status, run.Failure = series.Failed, read.failure
		return run.Status, a.end(ctx, store, run, read.receipt)
	}

	previous, err := store.Previous(ctx, run)
	if err != nil {
		return "", err
	}
	// Only a run newer than the series' last on this build is applied. An
	// older one arriving late would mark results not reproduced and the next
	// run would reopen them.
	if previous != nil && !run.BuiltAt.After(previous.BuiltAt) {
		run.Status = series.Superseded
		return run.Status, a.end(ctx, store, run, read.receipt)
	}

	inventory, err := inventoryOf(ctx, tx, run.TargetID)
	if err != nil {
		return "", err
	}
	if inventory == nil {
		if a.now().Sub(run.ReceivedAt) >= inventoryWait {
			run.Status, run.Failure = series.Failed, "the build had no inventory read within a day of the run arriving"
			return run.Status, a.end(ctx, store, run, read.receipt)
		}
		run.Status = series.Waiting
		return run.Status, store.Mark(ctx, run)
	}
	run.ScanID = &inventory.scanID

	set, err := store.SeriesOf(ctx, run)
	if err != nil {
		return "", err
	}
	comparable, reason := series.Comparability(run.Params, previous, read.signals)
	run.Comparable, run.Reason = &comparable, reason
	if comparable {
		had, err := store.HasBaseline(ctx, set.ID)
		if err != nil {
			return "", err
		}
		run.Baseline = !had
	}

	keyed := make([]Keyed, len(read.results))
	for i, res := range read.results {
		keyed[i] = key(ruleName(read.tools[i], res.RuleID), res)
		keyed[i].Remote = read.remotes[i]
	}
	open, err := store.Sightings(ctx, kind.Analysis, set.ID, run.TargetID)
	if err != nil {
		return "", err
	}
	matched, fresh, missed, returned, err := match(ctx, tx, open, keyed)
	if err != nil {
		return "", err
	}

	receipt := read.receipt
	if comparable && previous != nil {
		drop, err := sharpDrop(ctx, tx, len(missed), live(open))
		if err != nil {
			return "", err
		}
		if drop {
			run.Status = series.Held
			receipt.WouldMark = len(missed)
			return run.Status, a.end(ctx, store, run, receipt)
		}
	}

	issues := finding.NewVulnerabilities(tx)
	ruleIDs := map[string]int64{}
	for name, rule := range read.rules {
		id, err := issues.Rule(ctx, rule)
		if err != nil {
			return "", err
		}
		ruleIDs[name] = id
	}

	held, err := baselined(ctx, tx, set.ID, fresh)
	if err != nil {
		return "", err
	}
	components, err := componentsOf(ctx, tx, run.TargetID, fresh)
	if err != nil {
		return "", err
	}
	opened, inBaseline, err := a.open(ctx, tx, run, set.ID, fresh, ruleIDs, held, components, inventory.root)
	if err != nil {
		return "", err
	}
	if err := describeAgain(ctx, tx, matched); err != nil {
		return "", err
	}

	// A result the baseline holds on another build is in it here too: it is
	// the same result, seen first by another build.
	carriedIn := make(map[int64]bool, len(inBaseline))
	for _, id := range inBaseline {
		carriedIn[id] = true
	}
	seen := make([]int64, 0, len(matched)+len(opened))
	for id := range matched {
		seen = append(seen, id)
	}
	for _, id := range opened {
		if !carriedIn[id] {
			seen = append(seen, id)
		}
	}
	sort.Slice(seen, func(i, j int) bool { return seen[i] < seen[j] })
	if err := store.Saw(ctx, run, seen, run.Baseline); err != nil {
		return "", err
	}
	if err := store.Saw(ctx, run, inBaseline, true); err != nil {
		return "", err
	}
	if comparable {
		if err := store.Missed(ctx, run, missed); err != nil {
			return "", err
		}
		receipt.NotReproduced = len(missed)
	}
	if err := store.Modules(ctx, run.ID, read.modules); err != nil {
		return "", err
	}

	receipt.Opened, receipt.Seen, receipt.Returned = len(opened), len(matched), returned
	run.Status = series.Applied
	return run.Status, a.end(ctx, store, run, receipt)
}

// end records what became of a run and lets its documents go. Nothing reads
// them again: a run is applied once, and a held run changes nothing.
func (a *Applier) end(ctx context.Context, store *series.Store, run *series.Run, receipt Receipt) error {
	said, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("write the receipt: %w", err)
	}
	run.Receipt = string(said)
	if err := store.Discard(ctx, run.ID); err != nil {
		return err
	}
	run.SourceRoot = ""
	return store.Mark(ctx, run)
}

// live is the sightings a comparable run could mark not reproduced: those
// the last comparable run saw.
func live(open []series.Sighting) int {
	n := 0
	for _, s := range open {
		if s.AbsentRunID == nil {
			n++
		}
	}
	return n
}

// sharpDrop is whether marking this many of a build's live results not
// reproduced is more than the deployment allows in one run. Both the share
// and the floor have to be passed, so a small series does not hold every
// time two results go.
func sharpDrop(ctx context.Context, db bun.IDB, missed, live int) (bool, error) {
	if missed == 0 || live == 0 {
		return false, nil
	}
	settings := setting.NewStore(db)
	share, err := settings.Count(ctx, setting.AnalysisDropShare, setting.DefaultAnalysisDropShare)
	if err != nil {
		return false, fmt.Errorf("read how much of a series may go in one run: %w", err)
	}
	floor, err := settings.Count(ctx, setting.AnalysisDropFloor, setting.DefaultAnalysisDropFloor)
	if err != nil {
		return false, fmt.Errorf("read how few results going is worth holding a run for: %w", err)
	}
	return missed >= floor && missed*100 > share*live, nil
}

// OpensAt is the visibility every lead opens at, and the one a receipt
// counting leads is read at: a result nobody has judged is internal.
const OpensAt = access.Internal
