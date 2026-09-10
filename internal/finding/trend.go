package finding

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
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
	// BeneathVersion and BeneathEcosystem say which component, where the name
	// means more than one. A build ships some libraries at several versions,
	// and a few at one version as two components — and with no way to say
	// which, a subtree of either was unaskable.
	Beneath          string
	BeneathVersion   string
	BeneathEcosystem string
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

	products, all := subject.Products()
	if subject.Kind != access.Person || (!all && len(products) == 0) {
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
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		ColumnExpr("f.vulnerability_id AS vulnerability_id").
		// An issue with no published severity is stored as '', not NULL, so
		// the empty string is what has to be named — a COALESCE alone never
		// fires and the chart's split gained a key with no name.
		ColumnExpr("COALESCE(NULLIF(v.severity, ''), 'unknown') AS severity").
		// Off the row, not through the run that opened it. That join was an
		// inner one, so a finding with no run — one somebody recorded by hand
		// — did not appear on the chart at all rather than appearing wrongly.
		ColumnExpr("f.opened_at AS opened_at").
		// And the closing off the row too, for the same reason and the same
		// join. A finding a person closed has no run either, so reaching one
		// for the moment dropped it from the chart exactly as the opening
		// side used to — this is that lesson arriving on the other half.
		ColumnExpr("f.closed_at AS closed_at").
		ColumnExpr("COALESCE(f.closed_because, '') AS closed_because").
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
		componentID, err := graph.NewStore(s.db).ComponentAs(ctx, targets[0], under,
			strings.TrimSpace(within.BeneathVersion), strings.TrimSpace(within.BeneathEcosystem))
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
	// Where an issue stopped being present without explanation, per step.
	// The scanner going quiet is a fault to investigate rather than a fix,
	// so it is held back from the resolved count even though the issue has
	// left the set.
	quiet := make([]map[int64]bool, steps)
	for i := range quiet {
		quiet[i] = map[int64]bool{}
	}

	for _, row := range rows {
		for i := 0; i < steps; i++ {
			to := since.Add(time.Duration(i+1) * step)
			if row.OpenedAt.After(to) {
				continue
			}
			if row.ClosedAt != nil && !row.ClosedAt.After(to) {
				// Gone by this point. Note an unexplained disappearance so the
				// step it happened in does not read as work done.
				if Closure(row.ClosedBecause) == Unexplained {
					for j := 0; j < steps; j++ {
						from := since.Add(time.Duration(j) * step)
						until := from.Add(step)
						if row.ClosedAt.After(from) && !row.ClosedAt.After(until) {
							quiet[j][row.VulnerabilityID] = true
						}
					}
				}
				continue
			}
			open[i][row.VulnerabilityID] = row.Severity
		}
	}

	points := make([]Point, 0, steps)
	for i := 0; i < steps; i++ {
		point := Point{At: since.Add(time.Duration(i+1) * step), BySeverity: map[string]int{}}
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
		for id := range open[i] {
			if _, was := before[id]; !was {
				point.Opened++
			}
		}
		for id := range before {
			if _, still := open[i][id]; !still && !quiet[i][id] {
				point.Resolved++
			}
		}
		points = append(points, point)
	}

	return points, nil
}
