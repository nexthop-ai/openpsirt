// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Within narrows a trend to part of one build's tree.
//
// A trend over a whole product answers "are we keeping pace" for whoever owns
// the whole product. A team that owns the kernel wants the same three lines
// for the part of the tree they own, and there was no way to ask for it: the
// findings list has narrowed by a component and by a subtree from the start,
// and the chart beside it took a product, a branch and a variant and nothing
// else. These are the list's own two narrowings rather than a second pair
// written beside them, so a chart and a list cannot come to disagree about
// what a subtree is.
type Within struct {
	// Component keeps what is open against components of this name, at any
	// version.
	Component string
	// Beneath is what sits at a component or anywhere under it. A subtree is a
	// walk over one build's edges, so it is answerable only where the
	// selection names exactly one build.
	//
	// BeneathVersion, BeneathEcosystem and BeneathNamespace say which
	// component, where the name means more than one. A build ships some libraries at several versions,
	// and a few at one version as two components — and with no way to say
	// which, a subtree of either was unaskable.
	Beneath          string
	BeneathVersion   string
	BeneathEcosystem string
	BeneathNamespace string
}

// Point is what was true at one moment.
type Point struct {
	At       time.Time
	Open     int
	Opened   int
	Resolved int
	// BySeverity is the open count split up. A total that barely moves while
	// its critical share rises is getting worse, and one line hides that.
	BySeverity map[string]int
	// OpenedBySeverity and ResolvedBySeverity are the same split over the two
	// flows. The question a backlog is read for is what kind of thing is
	// arriving and what kind is being answered: ten arriving and ten
	// resolved is a team keeping pace where both are low, and a team losing
	// ground where the ten arriving are critical and the ten resolved are
	// not. Split only on the open count, that reads as a flat line.
	//
	// A resolved issue is counted at the severity it held while it was open,
	// which is the last step that held it: the row it was resolved in no
	// longer has one.
	OpenedBySeverity   map[string]int
	ResolvedBySeverity map[string]int
}

// Trend reports new, resolved and open over time, split by severity.
//
// Worked out when it is asked for. Nothing is precomputed or refreshed on a
// schedule until a measurement says it has to be: a stale answer is a cost
// paid up front for a benefit nobody has demonstrated, and it brings its own
// invalidation bugs.
//
// Three series rather than one. Separately they are three numbers; together
// they say whether the team is keeping pace, and new consistently outrunning
// resolved is a growing backlog that should be visible before somebody works
// it out from a chart of open alone.
func (s *Store) Trend(ctx context.Context, subject access.Subject, scope Scope, since time.Time,
	step time.Duration, steps int, within Within) ([]Point, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, access.Denied("read how findings are trending")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, nil
	}
	if steps <= 0 || steps > 104 {
		steps = 12
	}
	// A step of nothing makes every point the same instant, so the chart is
	// one number drawn twelve times. A week is what the callers ask for.
	if step <= 0 {
		step = 7 * 24 * time.Hour
	}
	// Longer than the whole history is a range nothing falls in. Bounded here
	// rather than trusted, because the range is a query parameter and the loop
	// below walks it whatever it says.
	if step > 366*24*time.Hour {
		step = 366 * 24 * time.Hour
	}
	if since.IsZero() {
		since = s.now().UTC().Add(-time.Duration(steps) * step)
	}
	until := since.Add(time.Duration(steps) * step)

	// Every open and closed moment in range, once, and the counting happens
	// here. The alternative is a statement per point per severity, which is
	// sixty round trips to answer one question.
	var rows []struct {
		VulnerabilityID int64      `bun:"vulnerability_id"`
		Severity        string     `bun:"severity"`
		OpenedAt        time.Time  `bun:"opened_at"`
		ClosedAt        *time.Time `bun:"closed_at"`
		ClosedBecause   string     `bun:"closed_because"`
	}
	query := s.db.NewSelect().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		// This product's rating where it has stated one, folded to the four
		// words that rank. The other chart on this screen reads it the same
		// way, so a product that re-rated an issue does not see one severity
		// on the release chart and another on the one beside it.
		//
		// Folded rather than taken raw: an issue with no published severity is
		// stored as '' rather than NULL, and a scanner's own "unknown" is a
		// word of its own, so the split grew keys the browser has no color for
		// — and it draws them all as one "unrated" rung, which is three
		// different nothings stacked under one name.
		Join(rating.For(rating.OnStream)).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(rating.BandExpr+` AS "severity"`).
		// Off the row, not through the run that opened it. That join was an
		// inner one, so a finding with no run — one somebody recorded by hand
		// — did not appear on the chart at all rather than appearing wrongly.
		ColumnExpr(`f.opened_at AS "opened_at"`).
		// And the closing off the row too, for the same reason and the same
		// join. A finding a person closed has no run either, so reaching for
		// one to get the moment drops it from the chart exactly as it does on
		// the opening side.
		ColumnExpr(`f.closed_at AS "closed_at"`).
		ColumnExpr(`COALESCE(f.closed_because, '') AS "closed_because"`).
		// Only what can fall in the range. A finding opened after the last
		// point contributes to nothing, and one closed before the first
		// contributes to nothing either — reading the whole table to discard
		// most of it grows the cost of a chart with the age of the deployment.
		Where("f.opened_at <= ?", until).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr("f.closed_at IS NULL").
				WhereOr("f.closed_at > ?", since)
		})
	query = scope.Narrow(onlyReadable(query, subject, products, all))

	// The same two narrowings the findings list takes, applied to the same
	// column. A component name is matched at any version, because a chart of
	// one version of one package is a chart of a moment rather than of a
	// component.
	if name := strings.TrimSpace(within.Component); name != "" {
		query = query.Where("f.component_id IN (?)", componentsWhere(query, "c.name = ?", name))
	}
	if under := strings.TrimSpace(within.Beneath); under != "" {
		targets, err := s.Builds(ctx, scope)
		if err != nil {
			return nil, err
		}
		// Refused rather than answered from whichever build sorted first,
		// which is what leaving the identifier at zero would have done —
		// silently, and with an empty chart.
		if len(targets) != 1 {
			return nil, fmt.Errorf("trend beneath a component: a subtree is a walk over one"+
				" build's edges, and %d builds are in scope", len(targets))
		}
		componentID, err := graph.NewStore(s.db).ComponentAs(ctx, targets[0], under, graph.Choice{
			Version:   strings.TrimSpace(within.BeneathVersion),
			Ecosystem: strings.TrimSpace(within.BeneathEcosystem),
			Namespace: strings.TrimSpace(within.BeneathNamespace),
		})
		if err != nil {
			// Wrapped so the caller can still see what it is: a name meaning
			// two components is the caller's question, and reported as a fault
			// it becomes a 500 for something the reader can answer.
			return nil, fmt.Errorf("trend beneath %q: %w", under, err)
		}
		query = query.Where("f.component_id IN (?)",
			graph.Within(query.DB(), targets[0], componentID))
	}

	if err := query.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what changed over time: %w", err)
	}

	// Counted as issues, not as places.
	//
	// A finding is a component at a place, and one issue in one shared library
	// reaches every consumer of it — on a real image the kernel alone produced
	// 305,487 findings for a few thousand issues. Counting rows here reported
	// 441,108 open where 5,661 issues were open, which is not a chart anybody
	// can read: it measures how much the dependency graph shares rather than
	// how much there is to answer.
	//
	// So each point is a *set* of issues, and the three numbers come from the
	// same set. That also settles what "resolved" means without a second rule:
	// an issue whose version moved and came with it is still in the set, so a
	// bump that fixed nothing cannot appear as work completed.
	open := make([]map[int64]string, steps)
	for i := range open {
		open[i] = map[int64]string{}
	}
	// Issues that stopped being present without explanation, per step.
	// The scanner going quiet is a fault to investigate rather than a fix,
	// so it is held back from the resolved count even though the issue has
	// left the set.
	quiet := make([]map[int64]bool, steps)
	for i := range quiet {
		quiet[i] = map[int64]bool{}
	}

	for _, row := range rows {
		// The step an unexplained disappearance falls in, worked out once
		// from the moment rather than by walking the steps looking for it.
		// Inside the loop below it did not depend on the step it sat in, so a
		// row that went quiet re-walked every bucket once per step — steps
		// squared per row, writing the same true each time, and at the
		// hundred-and-four steps this accepts that is eleven thousand
		// iterations to record one fact.
		if row.ClosedAt != nil && row.ClosedAt.After(since) &&
			Closure(row.ClosedBecause) == Unexplained {

			if at := int(row.ClosedAt.Sub(since) / step); at >= 0 && at < steps {
				// A moment exactly on a boundary belongs to the step it ends,
				// which is what the walk this replaces said: the bucket was
				// the one whose end the moment did not pass. Stored
				// timestamps are rounded to what the engine keeps, so a real
				// row lands on a boundary about never — which is why the case
				// is written out here rather than left to be discovered.
				if row.ClosedAt.Equal(since.Add(time.Duration(at) * step)) {
					at--
				}
				if at >= 0 {
					quiet[at][row.VulnerabilityID] = true
				}
			}
		}
		for i := 0; i < steps; i++ {
			to := since.Add(time.Duration(i+1) * step)
			if row.OpenedAt.After(to) {
				continue
			}
			if row.ClosedAt != nil && !row.ClosedAt.After(to) {
				continue
			}
			open[i][row.VulnerabilityID] = row.Severity
		}
	}

	points := make([]Point, 0, steps)
	for i := 0; i < steps; i++ {
		point := Point{
			At: since.Add(time.Duration(i+1) * step), BySeverity: map[string]int{},
			OpenedBySeverity: map[string]int{}, ResolvedBySeverity: map[string]int{},
		}
		point.Open = len(open[i])
		for _, severity := range open[i] {
			point.BySeverity[severity]++
		}
		// New and resolved are the difference between this step's set and the
		// last one's, so all three numbers agree with each other rather than
		// counting events that may not change what is open. The first step has
		// nothing to differ from, so it reports neither.
		if i == 0 {
			points = append(points, point)
			continue
		}
		before := open[i-1]
		for id, severity := range open[i] {
			if _, was := before[id]; !was {
				point.Opened++
				point.OpenedBySeverity[severity]++
			}
		}
		for id, severity := range before {
			if _, still := open[i][id]; !still && !quiet[i][id] {
				point.Resolved++
				point.ResolvedBySeverity[severity]++
			}
		}
		points = append(points, point)
	}

	return points, nil
}
