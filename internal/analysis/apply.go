// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package analysis applies an analyzer's run to a build: each result placed
// in the checkout, matched to what the series saw before, and recorded as a
// finding of the analysis kind.
package analysis

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
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
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// Applier applies stored runs.
type Applier struct {
	db  *database.DB
	now func() time.Time
	// drops is told of each applied run that dropped sharply, once its
	// transaction has committed.
	drops func(context.Context, Drop)
}

// NewApplier returns an applier.
func NewApplier(db *database.DB) *Applier {
	return &Applier{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Drop is an applied run that marked more of a build's open leads not
// reproduced than the deployment expects of one run.
type Drop struct {
	RunID, SeriesID, TargetID int64
	// Missed is how many it marked, and Live how many it could have.
	Missed, Live int
}

// TellingDrops has the applier tell somebody of each run that drops sharply.
// It is told after the run's transaction commits, so a retried transaction
// tells once.
func (a *Applier) TellingDrops(tell func(context.Context, Drop)) *Applier {
	a.drops = tell
	return a
}

// Receipt is what a pipeline is told about a run it sent. It counts and
// never names a result.
type Receipt struct {
	Opened        int            `json:"opened" doc:"Results the run reported that the build did not hold open"`
	Seen          int            `json:"seen" doc:"Results the build held open that the run reported again"`
	Returned      int            `json:"returned" doc:"Of those seen again, the ones an earlier run had not reported"`
	NotReproduced int            `json:"not_reproduced" doc:"Results the build held open that this comparable run did not report"`
	SharpDrop     bool           `json:"sharp_drop,omitempty" doc:"Whether the run marked more of the build's open results not reproduced than the deployment expects of one run, which tells the product's internal readers"`
	Probable      int            `json:"probable,omitempty" doc:"Results paired with a lead on its function or its nearest line rather than its whole key"`
	Inherited     int            `json:"inherited,omitempty" doc:"Results new to the build carried from a lead of the branch it was cut from"`
	Reopened      int            `json:"reopened,omitempty" doc:"Results found again at the place of a lead on the build that was closed"`
	Rebaseline    bool           `json:"rebaseline,omitempty" doc:"Whether the fingerprints the results carry changed from the last run on the build that carried any"`
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

// inventoryWait is how long a run waits for its build's inventory before it
// fails. A waiting run's job and placed results are held while it waits, so a
// series analyzed on a build that is never inventoried would otherwise hold
// one of each per upload for good.
const inventoryWait = 24 * time.Hour

// Apply reads one stored run and applies it, reporting what became of it.
//
// The placed results are read before the transaction that applies them. They
// do not change once stored, and the run's own state is read again inside.
// They are read only once the build has an inventory to apply them to: a
// waiting run is asked about every minute for a day, and each asking would
// decode it again.
func (a *Applier) Apply(ctx context.Context, runID int64) (series.Status, error) {
	store := series.NewStore(a.db.DB)
	run, err := store.ByID(ctx, runID)
	if err != nil {
		return "", err
	}
	if !pending(run.Status) {
		return run.Status, nil
	}
	built, err := inventoryOf(ctx, a.db.DB, run.TargetID)
	if err != nil {
		return "", err
	}
	var read *held
	if built != nil {
		h, err := a.read(ctx, store, run)
		if err != nil {
			return "", err
		}
		read = &h
	}
	var status series.Status
	var drop *Drop
	err = database.InTransaction(ctx, a.db.DB, func(ctx context.Context, tx bun.Tx) error {
		drop = nil
		status, err = a.apply(ctx, tx, runID, read, &drop)
		return err
	})
	if err == nil && drop != nil && a.drops != nil {
		a.drops(ctx, *drop)
	}
	return status, err
}

// pending is whether a run is still to be applied.
func pending(s series.Status) bool { return s == series.Queued || s == series.Waiting }

// Place puts every result of a run's documents in the checkout, leaving out
// what a run does not keep. root is the checkout's absolute path where the
// pipeline states one, and most is how large the placed results may be
// once encoded, and keep is whether source under a path is kept. An upload
// that holds nothing to apply, or more than most, is refused in words the
// sender reads.
func Place(logs []sarif.Log, root string, most int64, keep func(path string) bool) (Placed, error) {
	out := Placed{
		Rules:   map[string]finding.Rule{},
		Receipt: Receipt{Dropped: map[string]int{}, Discarded: map[string]int{}},
	}
	placer := sarif.NewPlacer(keep)
	var discarded sarif.Discarded
	kept := 0
	for _, log := range logs {
		for i := range log.Runs {
			r := &log.Runs[i]
			if sarif.Scanner(r.Tool.Name) {
				out.Receipt.Scanners = append(out.Receipt.Scanners, r.Tool.Name)
				continue
			}
			kept++
			if !r.Ran {
				return Placed{}, refusal.New("a run states no results, which is an analyzer that did not run")
			}
			discarded.Add(r.Discarded)
			for _, inv := range r.Invocations {
				out.Signals += inv.Errors
			}
			run := HeldRun{Tool: r.Tool.Name, Salt: r.Properties.Salt, Remotes: make([]string, len(r.Modules))}
			for j, m := range r.Modules {
				run.Remotes[j] = sourcelink.Normalize(m.Repository)
			}
			at := len(out.Runs)
			out.Runs = append(out.Runs, run)
			for _, res := range placer.Place(r, root) {
				name := ruleName(r.Tool.Name, res.RuleID)
				if _, ok := out.Rules[name]; !ok {
					rule, _ := r.RuleOf(res.RuleID)
					tenths, precision := finding.RuleRating(rule.SecuritySeverity, rule.Precision)
					out.Rules[name] = finding.Rule{Name: name, Description: rule.Description, Tags: rule.Tags,
						Documentation:  sourcelink.Documentation(rule.HelpURI),
						SeverityTenths: tenths, Precision: precision}
				}
				out.Results = append(out.Results, res)
				out.RunOf = append(out.RunOf, at)
			}
			out.Modules = append(out.Modules, modulesOf(r, root)...)
		}
	}
	if kept == 0 {
		return Placed{}, refusal.Errorf("every run is a dependency or secret scanner's (%s), and this upload takes neither",
			strings.Join(out.Receipt.Scanners, ", "))
	}
	d := placer.Dropped()
	out.Signals += d.Failure
	for reason, n := range map[string]int{
		DroppedAdvisory: d.Advisory, DroppedOutside: d.Outside, DroppedRepeat: d.Repeats,
		DroppedFailure: d.Failure, DroppedNotAProblem: d.NotAProblem,
		DroppedSuppressed: d.Suppressed, DroppedAbsent: d.Absent,
	} {
		if n > 0 {
			out.Receipt.Dropped[reason] += n
		}
	}
	for what, n := range map[string]int{
		"snippets": placer.Snippets(), "markdown": discarded.Markdown,
		"contents": discarded.Contents, "fixes": discarded.Fixes,
	} {
		if n > 0 {
			out.Receipt.Discarded[what] = n
		}
	}
	if err := within(out, most); err != nil {
		return Placed{}, err
	}
	return out, nil
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
			Path: at, Remote: sourcelink.WithoutCredential(m.Repository), Revision: m.Revision, Changed: changed[at],
		})
	}
	return out
}

// apply applies a placed run inside one transaction.
func (a *Applier) apply(ctx context.Context, tx bun.Tx, runID int64, read *held, drop **Drop) (series.Status, error) {
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
	// A run not read yet ends with a receipt that counts nothing.
	var placed Placed
	if read != nil {
		if read.failure != "" {
			run.Status, run.Failure = series.Failed, read.failure
			return run.Status, a.end(ctx, store, run, Receipt{})
		}
		placed = read.placed
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
		return run.Status, a.end(ctx, store, run, placed.Receipt)
	}

	inventory, err := inventoryOf(ctx, tx, run.TargetID)
	if err != nil {
		return "", err
	}
	if inventory == nil {
		if a.now().Sub(run.ReceivedAt) >= inventoryWait {
			run.Status, run.Failure = series.Failed, "the build had no inventory read within a day of the run arriving"
			return run.Status, a.end(ctx, store, run, placed.Receipt)
		}
		run.Status = series.Waiting
		return run.Status, store.Mark(ctx, run)
	}
	if read == nil {
		// The inventory was read after the run was asked about. It is
		// applied when it is next asked about, read.
		run.Status = series.Waiting
		return run.Status, store.Mark(ctx, run)
	}
	run.ScanID = &inventory.scanID

	set, err := store.SeriesOf(ctx, run)
	if err != nil {
		return "", err
	}
	comparable, reason := series.Comparability(run.Params, previous, placed.Signals)
	run.Comparable, run.Reason = &comparable, reason
	if comparable {
		had, err := store.HasBaseline(ctx, set.ID)
		if err != nil {
			return "", err
		}
		run.Baseline = !had
	}

	keyed := make([]Keyed, len(placed.Results))
	for i, res := range placed.Results {
		keyed[i] = key(ruleName(placed.tool(i), res.RuleID), res)
		keyed[i].Remote = placed.remote(i)
	}
	run.Fingerprints = printsOf(placed, keyed)
	if run.Fingerprints != "" {
		last, err := store.LastPrinted(ctx, run)
		if err != nil {
			return "", err
		}
		run.Rebaseline = last != "" && last != run.Fingerprints
	}
	open, err := store.Sightings(ctx, kind.Analysis, set.ID, run.TargetID)
	if err != nil {
		return "", err
	}
	matched, fresh, missed, returned, err := match(ctx, tx, open, keyed)
	if err != nil {
		return "", err
	}

	receipt := placed.Receipt
	if comparable && previous != nil {
		sharp, err := sharpDrop(ctx, tx, len(missed), live(open))
		if err != nil {
			return "", err
		}
		if sharp {
			receipt.SharpDrop = true
			*drop = &Drop{RunID: run.ID, SeriesID: set.ID, TargetID: run.TargetID,
				Missed: len(missed), Live: live(open)}
		}
	}

	issues := finding.NewVulnerabilities(tx)
	ruleIDs := map[string]int64{}
	for name, rule := range placed.Rules {
		id, err := issues.Rule(ctx, rule)
		if err != nil {
			return "", err
		}
		ruleIDs[name] = id
	}

	from, err := carry(ctx, tx, run, set.ID, previous == nil, fresh)
	if err != nil {
		return "", err
	}
	components, err := componentsOf(ctx, tx, run.TargetID, fresh)
	if err != nil {
		return "", err
	}
	again := make([]int64, 0, len(matched))
	for id := range matched {
		again = append(again, id)
	}
	sort.Slice(again, func(i, j int) bool { return again[i] < again[j] })
	// Marked before the run reads a hand-off or writes a lead's source: a
	// disclosure or a move of a lead it describes waits for it, or reads
	// again.
	if err := finding.Describing(ctx, tx, set.ProductID, run.ID, freshPlaces(set.ID, fresh, from), again); err != nil {
		return "", err
	}
	opened, inBaseline, err := a.open(ctx, tx, run, set.ProductID, set.ID, fresh, ruleIDs, from, components, inventory.root)
	if err != nil {
		return "", err
	}
	if err := describeAgain(ctx, tx, matched); err != nil {
		return "", err
	}
	// What the run kept beside a lead disclosed with its flaw is stripped
	// again, as disclosure stripped it.
	described := append(append([]int64{}, opened...), again...)
	if err := finding.StripDisclosedLeads(ctx, tx, set.ProductID, described); err != nil {
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
	if err := store.Modules(ctx, run.ID, placed.Modules); err != nil {
		return "", err
	}

	receipt.Opened, receipt.Seen, receipt.Returned = len(opened), len(matched), returned
	receipt.Rebaseline = run.Rebaseline
	for _, k := range matched {
		if !strong(k.On) {
			receipt.Probable++
		}
	}
	for _, c := range from {
		if !strong(c.on) {
			receipt.Probable++
		}
		switch c.from {
		case fromParent:
			receipt.Inherited++
		case fromReopened:
			receipt.Reopened++
		}
	}
	if err := lapseProbable(ctx, tx, set.ProductID, matched, from, a.now()); err != nil {
		return "", err
	}
	run.Status = series.Applied
	return run.Status, a.end(ctx, store, run, receipt)
}

// lapseProbable lapses the claims dismissing each lead this run paired only
// probably, on its function or its nearest line, whether it was a lead open on
// the build or one carried from elsewhere.
func lapseProbable(ctx context.Context, tx bun.IDB, productID int64, matched map[int64]Keyed,
	from map[int]carried, now time.Time) error {

	var ids []int64
	for id, k := range matched {
		if !strong(k.On) {
			ids = append(ids, id)
		}
	}
	var places []string
	if err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
		var some []string
		if err := tx.NewSelect().TableExpr(`"finding" AS "f"`).ColumnExpr(`"f"."place_identity"`).
			Where(`"f"."id" IN (?)`, bun.List(batch)).Scan(ctx, &some); err != nil {
			return fmt.Errorf("read the places of leads paired probably: %w", err)
		}
		places = append(places, some...)
		return nil
	}); err != nil {
		return err
	}
	for _, c := range from {
		if !strong(c.on) {
			places = append(places, c.place)
		}
	}
	_, err := triage.LapseLeads(ctx, tx, productID, places, now)
	return err
}

// printsOf is what a run's results are fingerprinted with: the scheme each
// key was built from, sorted and named once, "none" where no result carried
// one, and the mark of each salt. Empty where the run reported nothing, so a
// run with no results never reads as a change.
func printsOf(placed Placed, keyed []Keyed) string {
	if len(keyed) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var parts []string
	for _, k := range keyed {
		if k.Scheme != "" && !seen[k.Scheme] {
			seen[k.Scheme] = true
			parts = append(parts, k.Scheme)
		}
	}
	// A result carrying no fingerprint beside others that do says nothing
	// of how the run fingerprints, so it alone never makes a re-baseline.
	if len(parts) == 0 {
		parts = append(parts, "none")
	}
	for _, r := range placed.Runs {
		if mark := "salt " + r.Salt; r.Salt != "" && !seen[mark] {
			seen[mark] = true
			parts = append(parts, mark)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// end records what became of a run and lets its placed results go. Nothing
// reads them again: a run is applied once, and a held run changes nothing.
func (a *Applier) end(ctx context.Context, store *series.Store, run *series.Run, receipt Receipt) error {
	said, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("write the receipt: %w", err)
	}
	run.Receipt = string(said)
	if err := store.Discard(ctx, run.ID); err != nil {
		return err
	}
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
// reproduced is more than the deployment expects of one run. Both the share
// and the floor have to be passed, so a small series does not raise it every
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
		return false, fmt.Errorf("read how few results going is worth saying so: %w", err)
	}
	return missed >= floor && missed*100 > share*live, nil
}

// OpensAt is the visibility a lead opens at unless it was handed off, and the
// one a receipt counting leads is read at: a result nobody has judged is
// internal.
const OpensAt = access.Internal
