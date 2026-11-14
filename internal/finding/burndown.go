// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// ProjectionDays is how many of the latest days a burndown's projection reads
// its rate from: two weeks, long enough that one quiet weekend does not swing
// it and short enough that a change of pace shows within the sprint it
// happened in.
const ProjectionDays = 14

// MostBurndownDays is the most days a burndown is drawn over: two years, the
// widest window a trend heldSpans for.
const MostBurndownDays = 730

// BurnPoint is one day of a burndown: what was left at its end, and what moved
// in it.
//
// Left is open and answered by nothing that takes it off the backlog: an issue
// at a component with a finding open and not under a dismissal in force. Each
// count is of issues at components, as the trend counts.
type BurnPoint struct {
	At   time.Time
	Left int
	// BySeverity is what was left, split by the severity each held.
	BySeverity map[string]int
	// New and Returned push the line up: in the backlog for the first time,
	// and back in it after having been in the selection before, a dismissal
	// lapsing or being withdrawn included.
	New      int
	Returned int
	// Fixed and Dismissed pull it down: left by a fix, or answered by a
	// dismissal in force or a publisher's statement that it is not affected.
	// Either stops counting when its issue comes back, at whatever later
	// moment, so a done issue is one still done now.
	Fixed     int
	Dismissed int
	// Restored, Baseline and FirstScans are marks, never moves: an inventory
	// a sharp removal broke put right, what a build's first scan brought, and
	// how many builds were first scanned that day.
	Restored   int
	Baseline   int
	FirstScans int
}

// Projection is where the recent pace takes what is left.
type Projection struct {
	// Days is how many days the rate was read over, which is fewer than
	// ProjectionDays where the burndown holds fewer.
	Days int
	// Done and Added are the totals over those days: fixed and dismissed, and
	// new and returned.
	Done, Added int
	// PerDay is the net pace, done less added, a day. Converging is whether
	// it is above zero, and ZeroOn the day the line reaches zero at that
	// pace, where it does.
	PerDay     float64
	Converging bool
	ZeroOn     *time.Time
}

// ChosenPackage is one package a name or an identifier prefix chose, so a reader can
// see two ecosystems sharing a name and pick one.
type ChosenPackage struct {
	Package   string
	Ecosystem string
	Name      string
}

// Burndown is the backlog of one selection from a day 0: what was left at the
// start, each day after it, and where the recent pace takes it.
type Burndown struct {
	// Since is day 0's start, a midnight UTC, and Start what was left then.
	Since  time.Time
	Start  int
	Points []BurnPoint
	Ahead  Projection
	// Chosen is the packages the narrowing chose by name or identifier, at
	// most mostMatched of them, and MoreChosen whether it chose more.
	Chosen     []ChosenPackage
	MoreChosen bool
}

// mostMatched is how many chosen packages a burndown names back.
const mostMatched = 20

// Burndown works out the backlog of a selection day by day from day 0 through
// today, narrowed as a trend narrows, to issues rated at least as severe as
// least where one is named.
//
// Day 0 is the day since falls on. Zero is the day the earliest finding in the
// selection opened at any severity: the first scan that found anything there. A day 0 more
// than 729 days back is moved to 729 days back, so at most MostBurndownDays are
// drawn, today included.
func (s *Store) Burndown(ctx context.Context, subject access.Subject, scope Scope, since time.Time,
	least string, within Within) (*Burndown, error) {

	if subject.Kind != access.Person {
		return nil, access.Denied("read how the backlog is burning down")
	}
	now := s.now().UTC()
	until := now.Truncate(24 * time.Hour).Add(24 * time.Hour)
	out := &Burndown{}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		out.Since = until.Add(-24 * time.Hour)
		return out, nil
	}
	narrow, err := s.trendNarrowing(ctx, subject, products, all, scope, within)
	if err != nil {
		return nil, err
	}
	if since.IsZero() {
		first, err := s.firstOpened(ctx, narrow, within)
		if err != nil {
			return nil, err
		}
		if first == nil {
			out.Since = until.Add(-24 * time.Hour)
			return out, nil
		}
		since = *first
	}
	since = since.UTC().Truncate(24 * time.Hour)
	if earliest := until.Add(-MostBurndownDays * 24 * time.Hour); since.Before(earliest) {
		since = earliest
	}
	if !since.Before(until) {
		since = until.Add(-24 * time.Hour)
	}
	days := int(until.Sub(since) / (24 * time.Hour))
	out.Since = since

	rows, err := s.trendMoments(ctx, narrow, within, `("f"."closed_at" IS NULL OR "f"."closed_at" > ?)`, since)
	if err != nil {
		return nil, err
	}
	// What the name or prefix chose, before the floor narrows it: a name
	// whose issues are all below the floor still names its package.
	out.Chosen, out.MoreChosen = chosenPackages(rows, within)
	if band := Band(least); least != "" {
		// Unrated reads as medium, as everything that filters on a band reads it.
		floor := Ranks(band)
		kept := rows[:0]
		for _, row := range rows {
			if Ranks(Band(row.Severity)) >= floor {
				kept = append(kept, row)
			}
		}
		rows = kept
	}
	first, err := s.firstScans(ctx, rows, since)
	if err != nil {
		return nil, err
	}
	answered, err := s.dismissedSpans(ctx, narrow, since, rows, now)
	if err != nil {
		return nil, err
	}

	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key().less(rows[j].key()) })
	type identity struct {
		id        trendKey
		from, to  int
		minOpened time.Time
	}
	var identities []identity
	var unseen []trendKey
	for i := 0; i < len(rows); {
		one := identity{id: rows[i].key(), from: i, minOpened: rows[i].OpenedAt}
		for ; i < len(rows) && rows[i].key() == one.id; i++ {
			if rows[i].OpenedAt.Before(one.minOpened) {
				one.minOpened = rows[i].OpenedAt
			}
		}
		one.to = i
		if one.minOpened.After(since) {
			unseen = append(unseen, one.id)
		}
		identities = append(identities, one)
	}
	before, err := s.presentBefore(ctx, narrow, within, since, unseen)
	if err != nil {
		return nil, err
	}
	day := 24 * time.Hour
	// bound(j) is the j-th boundary: day 0's start, then each day's end.
	bound := func(j int) time.Time { return since.Add(time.Duration(j) * day) }
	stepOf := func(at time.Time) int {
		d := at.Sub(since)
		if d <= 0 {
			return -1
		}
		return int((d+day-1)/day) - 1
	}
	points := make([]BurnPoint, days)
	for k := range points {
		points[k] = BurnPoint{At: bound(k + 1), BySeverity: map[string]int{}}
	}
	for _, started := range first {
		if k := stepOf(started); k >= 0 && k < days {
			points[k].FirstScans++
		}
	}

	// A return back from absent is judged after every identity is read, so
	// the uploads deciding them are worked out in one pass.
	type comeBack struct {
		day     int
		closure *trendRow
	}
	var absent []comeBack
	present := make([]bool, days+1)
	left := make([]bool, days+1)
	held := make([]string, days+1)
	ranked := make([]int, days+1)
	for _, one := range identities {
		clear(present)
		clear(left)
		clear(held)
		clear(ranked)
		group := rows[one.from:one.to]
		// The latest moment the issue was left in the backlog, which says
		// whether a leaving has held through now.
		var lastLeft time.Time
		baseline := map[int]bool{}
		for i := range group {
			row := &group[i]
			spans := answered[row.moment()]
			// The boundaries the row is open at: opened at or before, and
			// closed after or not at all.
			lo, hi := boundaryAtOrAfter(since, day, row.OpenedAt), days
			if row.ClosedAt != nil {
				hi = min(hi, boundaryAtOrAfter(since, day, *row.ClosedAt)-1)
			}
			for j := max(lo, 0); j <= hi; j++ {
				at := bound(j)
				present[j] = true
				if spans.covered(at) < row.Findings {
					rank := Ranks(row.Severity)
					if !left[j] || rank > ranked[j] {
						left[j], held[j], ranked[j] = true, row.Severity, rank
					}
				}
			}
			end := now
			if row.ClosedAt != nil && row.ClosedAt.Before(end) {
				end = *row.ClosedAt
			}
			if last := spans.lastLeft(row.OpenedAt, end, row.Findings, row.ClosedAt == nil); last.After(lastLeft) {
				lastLeft = last
			}
			if row.OpenedRunID != nil {
				if _, firstScan := first[*row.OpenedRunID]; firstScan {
					if k := stepOf(row.OpenedAt); k >= 0 && k < days {
						baseline[k] = true
					}
				}
			}
		}
		if left[0] {
			out.Start++
		}
		for k := 0; k < days; k++ {
			was, is := left[k], left[k+1]
			if is {
				points[k].Left++
				points[k].BySeverity[held[k+1]]++
			}
			switch {
			case is && !was:
				switch {
				case before[one.id] != nil || !one.minOpened.After(bound(k)):
					// Back from absent after a sharp removal is the inventory
					// put right; anything else back is returned, a dismissal
					// that stopped standing included.
					if !present[k] {
						absent = append(absent, comeBack{k, lastClosure(group, before[one.id], bound(k))})
					} else {
						points[k].Returned++
					}
				case baseline[k]:
					points[k].Baseline++
				default:
					points[k].New++
				}
			case was && !is:
				// Done only where it has stayed done through now.
				if lastLeft.After(bound(k + 1)) {
					continue
				}
				if present[k+1] {
					points[k].Dismissed++
					continue
				}
				switch leftBy(group, bound(k), bound(k+1)) {
				case byFix:
					points[k].Fixed++
				case byStatement:
					points[k].Dismissed++
				}
			}
		}
	}
	closures := make([]*trendRow, 0, len(absent))
	for _, r := range absent {
		closures = append(closures, r.closure)
	}
	sharp, err := s.sharpRemovals(ctx, closures)
	if err != nil {
		return nil, err
	}
	for _, r := range absent {
		if sharp[r.closure] {
			points[r.day].Restored++
		} else {
			points[r.day].Returned++
		}
	}
	out.Points = points
	out.Ahead = projected(points, now)
	return out, nil
}

// boundaryAtOrAfter is the first boundary, counted from since in steps of
// step, at or after a moment: zero for a moment at or before since.
func boundaryAtOrAfter(since time.Time, step time.Duration, at time.Time) int {
	d := at.Sub(since)
	if d <= 0 {
		return 0
	}
	return int((d + step - 1) / step)
}

// leaving is how an issue that left the backlog by closing left it.
type leaving int

const (
	// byNothing is a closure that is no progress: superseded, unexplained, or
	// a mixture holding one.
	byNothing leaving = iota
	byFix
	// byStatement is every closure in the day a publisher's statement that
	// the occurrence is not affected.
	byStatement
)

// departed reads the closures of an issue's rows in the interval after one
// moment through another: a fix where every closure resolves or is a
// statement and one resolves, a statement where every one is a statement.
func leftBy(rows []trendRow, after, through time.Time) leaving {
	fixed, stated := false, false
	for _, row := range rows {
		if row.ClosedAt == nil || !row.ClosedAt.After(after) || row.ClosedAt.After(through) {
			continue
		}
		switch reason := Closure(row.ClosedBecause); {
		case reason.Resolves():
			fixed = true
		case reason == Disclaimed:
			stated = true
		default:
			return byNothing
		}
	}
	switch {
	case fixed:
		return byFix
	case stated:
		return byStatement
	}
	return byNothing
}

// projected is the pace of the latest days, and the day it reaches zero.
func projected(points []BurnPoint, now time.Time) Projection {
	recent := points[max(0, len(points)-ProjectionDays):]
	out := Projection{Days: len(recent)}
	if len(recent) == 0 {
		return out
	}
	for _, p := range recent {
		out.Done += p.Fixed + p.Dismissed
		out.Added += p.New + p.Returned
	}
	out.PerDay = float64(out.Done-out.Added) / float64(len(recent))
	out.Converging = out.PerDay > 0
	left := points[len(points)-1].Left
	if out.Converging && left > 0 {
		days := float64(left) / out.PerDay
		// Past the widest window drawn, the date says nothing anybody plans by.
		if days <= 10*365 {
			zero := now.Truncate(24 * time.Hour).Add(time.Duration(days*24) * time.Hour)
			out.ZeroOn = &zero
		}
	}
	return out
}

// chosenPackages is the packages the rows sit on where the narrowing chose
// them by name or identifier, with the ecosystem each is in, at most
// mostMatched, and whether there were more.
func chosenPackages(rows []trendRow, within Within) ([]ChosenPackage, bool) {
	if within.Component == "" && within.Purl.Empty() {
		return nil, false
	}
	seen := map[string]bool{}
	var out []ChosenPackage
	for _, row := range rows {
		name := graph.PackageName(row.Purl)
		if name == "" {
			name = row.Component
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, ChosenPackage{Package: name, Ecosystem: graph.Ecosystem(row.Purl), Name: row.Component})
	}
	slices.SortFunc(out, func(a, b ChosenPackage) int {
		if a.Package < b.Package {
			return -1
		}
		if a.Package > b.Package {
			return 1
		}
		return 0
	})
	if len(out) > mostMatched {
		return out[:mostMatched], true
	}
	return out, false
}

// firstOpened is when the earliest finding the narrowing reads opened, or nil
// where it reads none. It ignores a severity floor, so every floor of one
// selection draws from one day 0.
//
// With a prefix, grouped by component and each component's identifier read
// after: grouped on the identifier, a long text, MariaDB took 1.0 s after a
// year of history against 0.14 s on the component.
func (s *Store) firstOpened(ctx context.Context, narrow trendNarrowing, within Within) (*time.Time, error) {
	var read []struct {
		Purl   string    `bun:"purl"`
		Opened time.Time `bun:"opened"`
	}
	q := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		ColumnExpr(`MIN("f"."opened_at") AS "opened"`)
	if !within.Purl.Empty() {
		q = q.ColumnExpr(`"f"."component_id" AS "component_id"`).GroupExpr(`"f"."component_id"`)
	}
	q, err := narrow(ctx, q, `"f"."opened_at" IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	if !within.Purl.Empty() {
		// By identifier, which is tested here rather than in the statement.
		q = s.db.NewSelect().TableExpr(`(?) AS "g"`, q).
			Join(`JOIN "component" AS "pc" ON "pc"."id" = "g"."component_id"`).
			ColumnExpr(`"g"."opened" AS "opened", COALESCE("pc"."purl", '') AS "purl"`)
	}
	if err := q.Scan(ctx, &read); err != nil {
		return nil, fmt.Errorf("read when the selection was first scanned: %w", err)
	}
	var first *time.Time
	for _, r := range read {
		if r.Opened.IsZero() || !within.keeps(r.Purl) && !within.Purl.Empty() {
			continue
		}
		if first == nil || r.Opened.Before(*first) {
			at := r.Opened
			first = &at
		}
	}
	return first, nil
}

// momentKey is one reduced moment, as the trend groups findings into them.
type momentKey struct {
	vulnerability, component, product int64
	opened, closed                    int64
	run                               int64
	because                           string
}

func (r trendRow) moment() momentKey {
	k := momentKey{
		vulnerability: r.VulnerabilityID, component: r.ComponentID, product: r.ProductID,
		opened: r.OpenedAt.UnixNano(), because: r.ClosedBecause,
	}
	if r.ClosedAt != nil {
		k.closed = r.ClosedAt.UnixNano()
	}
	if r.OpenedRunID != nil {
		k.run = *r.OpenedRunID
	}
	return k
}

// heldSpan is how many findings of a moment a dismissal held, over one span.
type heldSpan struct {
	from     time.Time
	to       *time.Time
	findings int
}

// heldSpans is the spans dismissals held one moment's findings over.
type heldSpans []heldSpan

// covered is how many of the moment's findings were answered at a moment.
//
// Summed over the dismissals: two standing at once over the same finding count
// it twice, which is the one place this reads early.
func (a heldSpans) covered(at time.Time) int {
	n := 0
	for _, one := range a {
		if !one.from.After(at) && (one.to == nil || one.to.After(at)) {
			n += one.findings
		}
	}
	return n
}

// lastLeft is the latest moment from opened through end at which fewer than
// all of the moment's findings were answered, or the zero time where every
// moment of it was answered. Open is whether the row is open still, so its
// end is now and the moment after it counts.
func (a heldSpans) lastLeft(opened, end time.Time, findings int, open bool) time.Time {
	if len(a) == 0 {
		return end
	}
	if open && a.covered(end) < findings {
		return end
	}
	// The moments the count can change at, latest first: a span's end leaves
	// what it held, and the moment before a span's start is still unanswered.
	var edges []time.Time
	for _, one := range a {
		edges = append(edges, one.from)
		if one.to != nil {
			edges = append(edges, *one.to)
		}
	}
	slices.SortFunc(edges, func(x, y time.Time) int { return y.Compare(x) })
	for _, edge := range edges {
		if edge.After(end) || edge.Before(opened) {
			continue
		}
		// Just before a change, and at it.
		if before := edge.Add(-time.Nanosecond); !before.Before(opened) && a.covered(before) < findings {
			return before
		}
		if edge.Before(end) && a.covered(edge) < findings {
			return edge
		}
	}
	if a.covered(opened) < findings {
		return opened
	}
	return time.Time{}
}

// dismissedSpans reads, for the moments a burndown reads, the spans dismissals
// held their findings over: from agreement to when the agreement was taken back
// or the decision stopped, or from proposal for one needing nobody.
//
// A dismissal is matched to a finding as the deadline matches one: the
// product, the issue under any name it merged into, the occurrence, and the
// versions the finding holds, a wrong match at any version.
func (s *Store) dismissedSpans(ctx context.Context, narrow trendNarrowing, since time.Time,
	rows []trendRow, now time.Time) (map[momentKey]heldSpans, error) {

	out := map[momentKey]heldSpans{}
	if len(rows) == 0 {
		return out, nil
	}
	wanted := make(map[momentKey]bool, len(rows))
	for _, row := range rows {
		wanted[row.moment()] = true
	}
	var read []struct {
		VulnerabilityID int64      `bun:"vulnerability_id"`
		ComponentID     int64      `bun:"component_id"`
		ProductID       int64      `bun:"product_id"`
		OpenedAt        time.Time  `bun:"opened_at"`
		OpenedRunID     *int64     `bun:"opened_run_id"`
		ClosedAt        *time.Time `bun:"closed_at"`
		ClosedBecause   string     `bun:"closed_because"`
		DecisionID      int64      `bun:"decision_id"`
		ProposedAt      time.Time  `bun:"proposed_at"`
		EndedAt         *time.Time `bun:"ended_at"`
		State           string     `bun:"state"`
		NeedsApproval   bool       `bun:"needs_approval"`
		SentBack        int        `bun:"sent_back"`
		Findings        int        `bun:"findings"`
	}
	q := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "build" AS "tg" ON "tg"."id" = "f"."build_id"`).
		Join(`JOIN "branch_or_tag" AS "st" ON "st"."id" = "tg"."branch_or_tag_id"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		// The consumer, for the version a decision is keyed on.
		Join(`LEFT JOIN "component" AS "uc" ON "uc"."id" = "f"."consumer_id"`).
		Join(`JOIN (`+DecisionOccurrences+`) ON `+DecisionOccurrenceAt(`"st"."product_id"`)).
		Join(`JOIN "decision" AS "cl" ON "cl"."id" = "de"."decision_id"`).
		Where(`"cl"."outcome" IN (?)`, bun.List(Dismissing)).
		Where(KeyMatches).
		// Ended rows held something while they stood; only those never in
		// force are left out, below.
		ColumnExpr(`"f"."vulnerability_id" AS "vulnerability_id"`).
		ColumnExpr(`"f"."component_id" AS "component_id"`).
		ColumnExpr(`"st"."product_id" AS "product_id"`).
		ColumnExpr(`"f"."opened_at" AS "opened_at"`).
		ColumnExpr(`"f"."opened_run_id" AS "opened_run_id"`).
		ColumnExpr(`"f"."closed_at" AS "closed_at"`).
		ColumnExpr(`COALESCE("f"."closed_because", '') AS "closed_because"`).
		ColumnExpr(`"de"."decision_id" AS "decision_id"`).
		ColumnExpr(`"de"."proposed_at" AS "proposed_at"`).
		ColumnExpr(`"de"."ended_at" AS "ended_at"`).
		ColumnExpr(`"de"."state" AS "state"`).
		ColumnExpr(`"de"."needs_approval" AS "needs_approval"`).
		ColumnExpr(`CASE WHEN "de"."sent_back_at" IS NULL THEN 0 ELSE 1 END AS "sent_back"`).
		ColumnExpr(`COUNT(DISTINCT "f"."id") AS "findings"`).
		GroupExpr(`"f"."vulnerability_id", "f"."component_id", "st"."product_id", "f"."opened_at", "f"."opened_run_id", ` +
			`"f"."closed_at", "f"."closed_because", "de"."decision_id", "de"."proposed_at", "de"."ended_at", ` +
			`"de"."state", "de"."needs_approval", "de"."sent_back_at"`)
	q, err := narrow(ctx, q, `("f"."closed_at" IS NULL OR "f"."closed_at" > ?)`, since)
	if err != nil {
		return nil, err
	}
	if err := q.Scan(ctx, &read); err != nil {
		return nil, fmt.Errorf("read the dismissals over the backlog: %w", err)
	}

	// The agreements each decision needing one was in force under.
	agreed := map[int64][]heldSpan{}
	var asked []int64
	seen := map[int64]bool{}
	for _, r := range read {
		if r.NeedsApproval && !seen[r.DecisionID] {
			seen[r.DecisionID] = true
			asked = append(asked, r.DecisionID)
		}
	}
	for start := 0; start < len(asked); start += database.BatchSize {
		chunk := asked[start:min(start+database.BatchSize, len(asked))]
		var approvals []struct {
			DecisionID  int64      `bun:"decision_id"`
			ApprovedAt  time.Time  `bun:"approved_at"`
			WithdrawnAt *time.Time `bun:"withdrawn_at"`
		}
		if err := s.db.NewSelect().TableExpr(`"decision_approval" AS "da"`).
			ColumnExpr(`"da"."decision_id", "da"."approved_at", "da"."withdrawn_at"`).
			Where(`"da"."decision_id" IN (?)`, bun.List(chunk)).
			Scan(ctx, &approvals); err != nil {
			return nil, fmt.Errorf("read when the dismissals were agreed: %w", err)
		}
		for _, a := range approvals {
			agreed[a.DecisionID] = append(agreed[a.DecisionID], heldSpan{from: a.ApprovedAt, to: a.WithdrawnAt})
		}
	}

	for _, r := range read {
		key := momentKey{
			vulnerability: r.VulnerabilityID, component: r.ComponentID, product: r.ProductID,
			opened: r.OpenedAt.UnixNano(), because: r.ClosedBecause,
		}
		if r.ClosedAt != nil {
			key.closed = r.ClosedAt.UnixNano()
		}
		if r.OpenedRunID != nil {
			key.run = *r.OpenedRunID
		}
		if !wanted[key] {
			continue
		}
		standing := StandsInForce(r.State, r.NeedsApproval, r.SentBack != 0)
		var spans []heldSpan
		switch {
		case !r.NeedsApproval:
			// In force from its proposal, unless it was sent back, which takes
			// it out until it is revised; the record keeps only that it is.
			if r.SentBack == 0 {
				spans = []heldSpan{{from: r.ProposedAt}}
			}
		default:
			for _, a := range agreed[r.DecisionID] {
				// An agreement still open on a row no longer agreed was taken
				// back by setting the row aside, which writes no withdrawal.
				if a.to == nil && !standing && r.EndedAt == nil {
					continue
				}
				spans = append(spans, a)
			}
		}
		for _, span := range spans {
			from := span.from
			if from.Before(r.ProposedAt) {
				from = r.ProposedAt
			}
			to := span.to
			if r.EndedAt != nil && (to == nil || r.EndedAt.Before(*to)) {
				to = r.EndedAt
			}
			if to != nil && !to.After(from) {
				continue
			}
			if from.After(now) {
				continue
			}
			out[key] = append(out[key], heldSpan{from: from, to: to, findings: r.Findings})
		}
	}
	return out, nil
}
