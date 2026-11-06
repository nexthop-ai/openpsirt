// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// MostTrendSteps is the most steps a trend is worked out over: two years of
// days.
const MostTrendSteps = 731

// Within narrows a trend to part of one build's tree.
//
// A team that owns the kernel reads the same series for the part of the tree
// it owns. These are the findings list's own two narrowings, so a chart and a
// list cannot disagree about what a subtree is.
type Within struct {
	// Component keeps what is open against components of this name, at any
	// version.
	Component string
	// Beneath is what sits at a component or anywhere under it, by the
	// component's identifier, resolved by the caller in the one build the
	// scope holds. A subtree is a walk over one build's edges, so it is
	// answerable only where the selection names exactly one build. Nil is no
	// narrowing.
	Beneath *int64
}

// Point is one step of a trend: what was open at its end, and what moved in it.
//
// Each count is of issues at components: one issue at one component, at any
// version, however many products, builds and occurrences hold it. The pair is
// recognized when it comes back, because its identity is derived from content,
// so one that leaves and returns returned, never was corrected and new.
type Point struct {
	At   time.Time
	Open int
	// New is issues in the open set for the first time ever in the scope,
	// other than through a build's first scan.
	New int
	// Corrected is issues that left the open set in this step by a
	// resolution and have not been open since.
	Corrected int
	// Returned is issues back in the open set after having been in it before.
	// The closure that took one out is not corrected.
	Returned int
	// Restored is returns whose last departure was a removal by an upload
	// that moved a sharp share of its build's inventory: a broken inventory
	// put right. Kept out of Returned, because it is the inventory coming
	// back, not work arriving.
	Restored int
	// Baseline is issues a build's first scan brought into the open set, and
	// FirstScans the builds first scanned in this step. A first scan is the
	// inventory arriving, not work arriving, so it is no flow.
	Baseline   int
	FirstScans int
	// BySeverity is the open count split up. A total that barely moves while
	// its critical share rises is getting worse, and one line hides that.
	BySeverity map[string]int
	// The flows split the same way. A corrected issue is counted at the
	// severity it held while open, which is the last step that held it.
	NewBySeverity       map[string]int
	CorrectedBySeverity map[string]int
	ReturnedBySeverity  map[string]int
}

// trendRow is one reduced moment: an issue at a component in one product,
// opened and closed at one moment each, by one run.
type trendRow struct {
	VulnerabilityID int64      `bun:"vulnerability_id"`
	Component       string     `bun:"component"`
	BuildID         int64      `bun:"build_id"`
	ComponentID     int64      `bun:"component_id"`
	Severity        string     `bun:"severity"`
	OpenedAt        time.Time  `bun:"opened_at"`
	OpenedRunID     *int64     `bun:"opened_run_id"`
	ClosedAt        *time.Time `bun:"closed_at"`
	ClosedBecause   string     `bun:"closed_because"`
}

// Trend reports open, new, corrected, returned and baseline over time, split by
// severity, worked out when asked.
//
// A step ends at the moment its point names and holds the interval after the
// one before; the moment before the first step is the window's start. An issue
// is open at a moment when one of its findings in the scope opened at or
// before it and closed after it, or not at all.
func (s *Store) Trend(ctx context.Context, subject access.Subject, scope Scope, since time.Time,
	step time.Duration, steps int, within Within) ([]Point, error) {

	// "You cannot ask" is not "here is nothing"; a person holding nothing is
	// the second, answered below.
	if subject.Kind != access.Person {
		return nil, access.Denied("read how findings are trending")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, nil
	}
	if steps <= 0 || steps > MostTrendSteps {
		steps = 12
	}
	// A step of nothing makes every point the same instant.
	if step <= 0 {
		step = 7 * 24 * time.Hour
	}
	// The range is a query parameter, and the loops below walk it.
	if step > 366*24*time.Hour {
		step = 366 * 24 * time.Hour
	}
	if since.IsZero() {
		since = s.now().UTC().Add(-time.Duration(steps) * step)
	}

	narrow, err := s.trendNarrowing(ctx, subject, products, all, scope, within)
	if err != nil {
		return nil, err
	}
	// Every moment after the window's start, through now. A row opened after
	// the last step says an issue closed inside the window came back, which
	// decides whether that closure is corrected. Every caller's window ends
	// now, so cost follows its start.
	rows, err := s.trendMoments(ctx, narrow, `("f"."closed_at" IS NULL OR "f"."closed_at" > ?)`, since)
	if err != nil {
		return nil, err
	}
	first, err := s.firstScans(ctx, rows, since)
	if err != nil {
		return nil, err
	}

	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key().less(rows[j].key()) })
	type issue struct {
		id                   trendKey
		from, to             int
		minOpened, maxOpened time.Time
	}
	var issues []issue
	var unseen []trendKey
	for i := 0; i < len(rows); {
		one := issue{id: rows[i].key(), from: i, minOpened: rows[i].OpenedAt, maxOpened: rows[i].OpenedAt}
		for ; i < len(rows) && rows[i].key() == one.id; i++ {
			if rows[i].OpenedAt.Before(one.minOpened) {
				one.minOpened = rows[i].OpenedAt
			}
			if rows[i].OpenedAt.After(one.maxOpened) {
				one.maxOpened = rows[i].OpenedAt
			}
		}
		one.to = i
		// A row opened at or before the start was present before any step.
		// For the rest, the rows closed before the window say.
		if one.minOpened.After(since) {
			unseen = append(unseen, one.id)
		}
		issues = append(issues, one)
	}
	before, err := s.presentBefore(ctx, narrow, since, unseen)
	if err != nil {
		return nil, err
	}
	sharp, err := s.sharpRemovals(ctx, rows, before)
	if err != nil {
		return nil, err
	}

	end := func(k int) time.Time { return since.Add(time.Duration(k+1) * step) }
	// The first step whose end is at or after a moment, and -1 where the
	// moment is at or before the window's start. A moment exactly on a step's
	// end belongs to that step: closed there, it is gone by that point, and
	// opened there, it is present.
	stepOf := func(at time.Time) int {
		d := at.Sub(since)
		if d <= 0 {
			return -1
		}
		return int((d+step-1)/step) - 1
	}

	points := make([]Point, steps)
	for k := range points {
		points[k] = Point{
			At: end(k), BySeverity: map[string]int{}, NewBySeverity: map[string]int{},
			CorrectedBySeverity: map[string]int{}, ReturnedBySeverity: map[string]int{},
		}
	}
	for _, started := range first {
		if k := stepOf(started); k >= 0 && k < steps {
			points[k].FirstScans++
		}
	}

	// held[k+1] is the severity the issue held at the end of step k, and
	// held[0] at the window's start, where open says it was open. An issue
	// open in two products takes the strictest band, the one the aging
	// figures count it in.
	held := make([]string, steps+1)
	ranked := make([]int, steps+1)
	open := make([]bool, steps+1)
	quiet := make([]bool, steps)
	baseline := make([]bool, steps)
	for _, one := range issues {
		clear(held)
		clear(ranked)
		clear(open)
		clear(quiet)
		clear(baseline)
		for _, row := range rows[one.from:one.to] {
			rank := Ranks(row.Severity)
			lo, hi := max(stepOf(row.OpenedAt), -1), steps-1
			if row.ClosedAt != nil {
				hi = min(hi, stepOf(*row.ClosedAt)-1)
			}
			for k := lo; k <= hi; k++ {
				if !open[k+1] || rank > ranked[k+1] {
					open[k+1], held[k+1], ranked[k+1] = true, row.Severity, rank
				}
			}
			// A closure that is not a fix holds the departure back from
			// corrected: the scanner going quiet is a fault, and a superseded
			// row was replaced. Resolving is the one list of fixes.
			if row.ClosedAt != nil && !Closure(row.ClosedBecause).Resolves() {
				if k := stepOf(*row.ClosedAt); k >= 0 && k < steps {
					quiet[k] = true
				}
			}
			if row.OpenedRunID != nil {
				if _, firstScan := first[*row.OpenedRunID]; firstScan {
					if k := stepOf(row.OpenedAt); k >= 0 && k < steps {
						baseline[k] = true
					}
				}
			}
		}
		for k := 0; k < steps; k++ {
			was, is := open[k], open[k+1]
			if is {
				points[k].Open++
				points[k].BySeverity[held[k+1]]++
			}
			switch {
			case is && !was:
				switch {
				// Present before: a row opened by the previous step's end, or
				// one closed before the window.
				case before[one.id] != nil || !one.minOpened.After(end(k-1)):
					if sharp.removed(lastClosure(rows[one.from:one.to], before[one.id], end(k-1))) {
						points[k].Restored++
					} else {
						points[k].Returned++
						points[k].ReturnedBySeverity[held[k+1]]++
					}
				case baseline[k]:
					points[k].Baseline++
				default:
					points[k].New++
					points[k].NewBySeverity[held[k+1]]++
				}
			case was && !is:
				// Every closure in the step was a fix, and nothing of the issue
				// opened after it, so it is still closed now.
				if !quiet[k] && !one.maxOpened.After(end(k)) {
					points[k].Corrected++
					points[k].CorrectedBySeverity[held[k]]++
				}
			}
		}
	}
	return points, nil
}

// trendNarrowing applies what every statement of a trend narrows by to a query
// over findings under "f", "tg" and "st", with a condition on when.
type trendNarrowing func(ctx context.Context, q *bun.SelectQuery, when string, args ...any) (*bun.SelectQuery, error)

// trendNarrowing builds the narrowing: what the subject may read, the scope,
// the kinds a statistic counts, never what was never present, and the
// component or subtree asked for. A record taken back as invalid, and a version
// the issue's record states is unaffected, were never present.
func (s *Store) trendNarrowing(ctx context.Context, subject access.Subject, products []int64, all bool,
	scope Scope, within Within) (trendNarrowing, error) {

	var buildID int64
	var under []int64
	if within.Beneath != nil {
		buildIDs, err := s.Builds(ctx, scope)
		if err != nil {
			return nil, err
		}
		// Refused rather than answered from whichever build sorted first,
		// which is a chart of somewhere else and silent about it.
		if len(buildIDs) != 1 {
			return nil, refusal.Errorf("trend beneath a component: a subtree is a walk over one"+
				" build's edges, and %d builds are in scope", len(buildIDs))
		}
		buildID = buildIDs[0]
		// A finding keeps the component it opened on, so what a version bump
		// closed sits on the version it replaced, and is beneath wherever the
		// present version of its name is.
		replaced, err := graph.Replaced(ctx, s.db, buildID)
		if err != nil {
			return nil, err
		}
		if under, err = graph.ReplacedWithin(ctx, s.db, buildID, *within.Beneath, replaced); err != nil {
			return nil, err
		}
	}
	kinds, kindArgs := kind.Statistics.Where(`"f"."kind"`)
	return func(ctx context.Context, q *bun.SelectQuery, when string, args ...any) (*bun.SelectQuery, error) {
		q = q.Where(`COALESCE("f"."closed_because", '') NOT IN (?)`, bun.List(NeverPresent())).
			Where(kinds, kindArgs...).
			Where(when, args...)
		// What a subject may read is decided per finding, so every narrowing
		// applies before the occurrences are reduced.
		q = scope.Narrow(onlyReadable(q, subject, products, all))
		// A component name is matched at any version: a chart of one version
		// of one package is a chart of a moment.
		if name := strings.TrimSpace(within.Component); name != "" {
			q = q.Where(`"f"."component_id" IN (?)`,
				componentsWhere(q, `"c"."name_folded" = ?`, graph.Folded(name)))
		}
		if within.Beneath != nil {
			// Only the replaced components holding a finding in the range read.
			held, err := holding(ctx, s.db, buildID, under, when, args...)
			if err != nil {
				return nil, err
			}
			q = q.Where(`"f"."component_id" IN (?)`, graph.WithinAnd(q.DB(), buildID, *within.Beneath, held))
		}
		return q, nil
	}, nil
}

// trendMoments is the reduced moments of the findings a trend reads.
//
// The moments are reduced before anything is joined to them: a scan opens one
// issue at every occurrence it reaches at the same instant, and on a real
// image 367,000 rows in range are 15,000 distinct moments. A DISTINCT over the
// joined rows reaches the same answer and is slower on PostgreSQL, because the
// join runs before it.
func (s *Store) trendMoments(ctx context.Context, narrow trendNarrowing, when string, args ...any) ([]trendRow, error) {
	moments := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		// The product, because the rating is this product's where it has
		// stated one.
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		// Off the row, so a finding recorded or closed by hand, which has no
		// run, is on the chart.
		ColumnExpr(`"f"."opened_at" AS "opened_at"`).
		// The run, which says whether the row arrived with its build's first
		// scan.
		ColumnExpr(`"f"."opened_run_id" AS "opened_run_id"`).
		ColumnExpr(`"f"."closed_at" AS "closed_at"`).
		ColumnExpr(`COALESCE("f"."closed_because", '') AS "closed_because"`).
		// Grouped on the stored reason: an absent and an empty reason fold to
		// one word, so at worst one moment arrives twice, and the count reads
		// it once.
		// The component, named below, because a version bump moves a finding
		// to another component of the same name.
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		// The build, because a removal is an upload to one build.
		ColumnExpr(`"f"."build_id" AS "build_id"`).
		GroupExpr(`"f"."vulnerability_id", "f"."component_id", "f"."build_id", "st"."product_id", "f"."opened_at", "f"."opened_run_id", "f"."closed_at", "f"."closed_because"`)
	moments, err := narrow(ctx, moments, when, args...)
	if err != nil {
		return nil, err
	}
	var rows []trendRow
	if err := s.db.NewSelect().
		TableExpr(`(?) AS "grouped"`, moments).
		Join(`JOIN "vulnerability" AS "v" ON "v"."id" = "grouped"."vulnerability_id"`).
		// This product's rating where it has stated one, folded to the words
		// that rank, as on the release chart beside it. An issue with no
		// published severity is stored as '' and a scanner's "unknown" is a
		// word of its own; the browser draws one unrated rung for both.
		Join(rating.For(rating.OnGrouped)).
		Join(`JOIN "component" AS "c" ON "c"."id" = "grouped"."component_id"`).
		ColumnExpr(`"grouped"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"c"."name_folded" AS "component"`).
		ColumnExpr(`"grouped"."build_id" AS "build_id"`).
		ColumnExpr(`"grouped"."component_id" AS "component_id"`).
		ColumnExpr(rating.BandExpr+` AS "severity"`).
		ColumnExpr(`"grouped"."opened_at" AS "opened_at"`).
		ColumnExpr(`"grouped"."opened_run_id" AS "opened_run_id"`).
		ColumnExpr(`"grouped"."closed_at" AS "closed_at"`).
		ColumnExpr(`"grouped"."closed_because" AS "closed_because"`).
		Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what changed over time: %w", err)
	}
	return rows, nil
}

// firstScans is, of the runs that opened a row after the window's start, the
// ones that were their build's first scan, with when each started. A first
// scan is a build's earliest run by start that did not fail.
func (s *Store) firstScans(ctx context.Context, rows []trendRow, since time.Time) (map[int64]time.Time, error) {
	seen := map[int64]bool{}
	var runs []int64
	for _, row := range rows {
		if row.OpenedRunID != nil && row.OpenedAt.After(since) && !seen[*row.OpenedRunID] {
			seen[*row.OpenedRunID] = true
			runs = append(runs, *row.OpenedRunID)
		}
	}
	type run struct {
		ID        int64     `bun:"id"`
		BuildID   int64     `bun:"build_id"`
		StartedAt time.Time `bun:"started_at"`
	}
	earliest := map[int64]run{}
	for start := 0; start < len(runs); start += database.BatchSize {
		chunk := runs[start:min(start+database.BatchSize, len(runs))]
		var read []run
		// Every run that did not fail, on the builds these runs belong to.
		if err := s.db.NewSelect().TableExpr(`"scan_run" AS "sr"`).
			ColumnExpr(`"sr"."id", "sr"."build_id", "sr"."started_at"`).
			Where(`"sr"."build_id" IN (?)`, s.db.NewSelect().TableExpr(`"scan_run" AS "of"`).
				ColumnExpr(`"of"."build_id"`).Where(`"of"."id" IN (?)`, bun.List(chunk))).
			Where(`COALESCE("sr"."failure", '') = ''`).
			Scan(ctx, &read); err != nil {
			return nil, fmt.Errorf("read the first scan of each build: %w", err)
		}
		for _, r := range read {
			was, ok := earliest[r.BuildID]
			if !ok || r.StartedAt.Before(was.StartedAt) || (r.StartedAt.Equal(was.StartedAt) && r.ID < was.ID) {
				earliest[r.BuildID] = r
			}
		}
	}
	out := map[int64]time.Time{}
	for _, r := range earliest {
		if seen[r.ID] {
			out[r.ID] = r.StartedAt
		}
	}
	return out, nil
}

// trendKey is what a trend counts: an issue at a component, by the component's
// name, so one version replacing another is the same component.
type trendKey struct {
	vulnerability int64
	component     string
}

func (k trendKey) less(o trendKey) bool {
	if k.vulnerability != o.vulnerability {
		return k.vulnerability < o.vulnerability
	}
	return k.component < o.component
}

func (r trendRow) key() trendKey {
	return trendKey{vulnerability: r.VulnerabilityID, component: r.Component}
}

// presentBefore is which of these issues at components had a finding in the
// scope closed at or before the window's start: present once, before the
// window.
//
// Asked by issue and answered by pair, because a statement naming each pair is
// a row-value list the engines spell differently. A pair nobody asked about is
// never looked up.
func (s *Store) presentBefore(ctx context.Context, narrow trendNarrowing, since time.Time,
	pairs []trendKey) (map[trendKey]*trendRow, error) {

	seen := map[int64]bool{}
	var issues []int64
	for _, p := range pairs {
		if !seen[p.vulnerability] {
			seen[p.vulnerability] = true
			issues = append(issues, p.vulnerability)
		}
	}
	out := map[trendKey]*trendRow{}
	for start := 0; start < len(issues); start += database.BatchSize {
		chunk := issues[start:min(start+database.BatchSize, len(issues))]
		q := s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
			Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
			Join(`JOIN "component" AS "pc" ON "pc"."id" = "f"."component_id"`).
			ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
			ColumnExpr(`"pc"."name_folded" AS "component"`).
			// The last closure of each, because a return after a removal is
			// told by what removed it.
			ColumnExpr(`"f"."build_id" AS "build_id"`).
			ColumnExpr(`"f"."component_id" AS "component_id"`).
			ColumnExpr(`"f"."closed_at" AS "closed_at"`).
			ColumnExpr(`COALESCE("f"."closed_because", '') AS "closed_because"`).
			Where(`"f"."vulnerability_id" IN (?)`, bun.List(chunk)).
			GroupExpr(`"f"."vulnerability_id", "pc"."name_folded", "f"."build_id", "f"."component_id", "f"."closed_at", "f"."closed_because"`)
		q, err := narrow(ctx, q, `"f"."closed_at" <= ?`, since)
		if err != nil {
			return nil, err
		}
		var read []trendRow
		if err := q.Scan(ctx, &read); err != nil {
			return nil, fmt.Errorf("read which issues were present before the trend's window: %w", err)
		}
		for i := range read {
			r := &read[i]
			if was := out[r.key()]; was == nil || r.ClosedAt.After(*was.ClosedAt) {
				out[r.key()] = r
			}
		}
	}
	return out, nil
}

// lastClosure is the row of an issue at a component that closed last at or
// before a moment, among those read in the window and the one closed before
// it, or nil where none closed then.
func lastClosure(rows []trendRow, before *trendRow, by time.Time) *trendRow {
	last := before
	for i := range rows {
		r := &rows[i]
		if r.ClosedAt == nil || r.ClosedAt.After(by) {
			continue
		}
		if last == nil || r.ClosedAt.After(*last.ClosedAt) {
			last = r
		}
	}
	return last
}

// removal is a component leaving a build.
type removal struct{ build, component int64 }

// sharpness is, for each removal a closure reads as, the upload that removed
// it and whether that upload moved a sharp share of its build's inventory.
type sharpness struct {
	uploads map[removal][]removedBy
	sharp   map[int64]bool
}

// removedBy is one upload that took a component out of a build, and when it
// arrived.
type removedBy struct {
	scan       int64
	receivedAt time.Time
}

// removed says whether a closure was a removal by a sharp upload: the latest
// upload to take the component out of the build at or before the closure.
func (s sharpness) removed(row *trendRow) bool {
	if row == nil || row.ClosedAt == nil || Closure(row.ClosedBecause) != Removed {
		return false
	}
	var by *removedBy
	for i, up := range s.uploads[removal{row.BuildID, row.ComponentID}] {
		if !up.receivedAt.After(*row.ClosedAt) && (by == nil || up.receivedAt.After(by.receivedAt)) {
			by = &s.uploads[removal{row.BuildID, row.ComponentID}][i]
		}
	}
	return by != nil && s.sharp[by.scan]
}

// sharpRemovals reads, for every removal a trend's rows could count a return
// after, the uploads that removed the component, and which of them moved a
// sharp share of the build's inventory.
//
// Sharp is the rule the alert about an inventory that moved sharply applies,
// with its two settings, worked out for each upload from the inventories
// stored. A closure is tied to its upload through the build's graph: the
// component's node closed by the upload, which arrived before the closure.
func (s *Store) sharpRemovals(ctx context.Context, rows []trendRow,
	before map[trendKey]*trendRow) (sharpness, error) {

	out := sharpness{uploads: map[removal][]removedBy{}, sharp: map[int64]bool{}}
	asked := map[removal]bool{}
	var builds, components []int64
	seenBuild, seenComponent := map[int64]bool{}, map[int64]bool{}
	note := func(r *trendRow) {
		if r == nil || r.ClosedAt == nil || Closure(r.ClosedBecause) != Removed {
			return
		}
		at := removal{r.BuildID, r.ComponentID}
		if asked[at] {
			return
		}
		asked[at] = true
		if !seenBuild[r.BuildID] {
			seenBuild[r.BuildID] = true
			builds = append(builds, r.BuildID)
		}
		if !seenComponent[r.ComponentID] {
			seenComponent[r.ComponentID] = true
			components = append(components, r.ComponentID)
		}
	}
	for i := range rows {
		note(&rows[i])
	}
	for _, r := range before {
		note(r)
	}
	if len(asked) == 0 {
		return out, nil
	}

	type closedNode struct {
		BuildID     int64     `bun:"build_id"`
		ComponentID int64     `bun:"component_id"`
		ScanID      int64     `bun:"closed_scan_id"`
		ReceivedAt  time.Time `bun:"received_at"`
	}
	scans := map[int64]int64{}
	for start := 0; start < len(components); start += database.BatchSize {
		chunk := components[start:min(start+database.BatchSize, len(components))]
		var read []closedNode
		if err := s.db.NewSelect().
			TableExpr(`"graph_node" AS "n"`).
			Join(`JOIN "scan" AS "sc" ON "sc"."id" = "n"."closed_scan_id"`).
			ColumnExpr(`"n"."build_id", "n"."component_id", "n"."closed_scan_id", "sc"."received_at"`).
			Where(`"n"."build_id" IN (?)`, bun.List(builds)).
			Where(`"n"."component_id" IN (?)`, bun.List(chunk)).
			GroupExpr(`"n"."build_id", "n"."component_id", "n"."closed_scan_id", "sc"."received_at"`).
			Scan(ctx, &read); err != nil {
			return out, fmt.Errorf("read which uploads removed what a trend counts back: %w", err)
		}
		for _, n := range read {
			at := removal{n.BuildID, n.ComponentID}
			if !asked[at] {
				continue
			}
			out.uploads[at] = append(out.uploads[at], removedBy{scan: n.ScanID, receivedAt: n.ReceivedAt})
			scans[n.ScanID] = n.BuildID
		}
	}

	settings := setting.NewStore(s.db)
	share, err := settings.Count(ctx, setting.DeltaShare, setting.DefaultDeltaShare)
	if err != nil {
		return out, fmt.Errorf("read how much of a build may move: %w", err)
	}
	floor, err := settings.Count(ctx, setting.DeltaFloor, setting.DefaultDeltaFloor)
	if err != nil {
		return out, fmt.Errorf("read how few names are worth reporting: %w", err)
	}
	graphs := graph.NewStore(s.db)
	for scan, build := range scans {
		moved, answered, err := graphs.Moved(ctx, build, scan)
		if err != nil {
			return out, err
		}
		out.sharp[scan] = answered && moved.Outsized(share, floor)
	}
	return out, nil
}
