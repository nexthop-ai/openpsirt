package currency

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Why says which of three things left a component without an upstream
// answer.
//
// One report rather than two, because the two questions are asked together.
// What was held back says what the default is costing, and what no index knows
// is the list an operator reads to decide what else should be held back — so a
// name promoted from the second appears in the first afterwards, which is the
// confirmation that the promotion worked.
type Why string

const (
	// WhyOurs is a name this deployment calls its own, so it was never sent.
	WhyOurs Why = "ours"
	// WhyUnknown is a name that was sent and no index had heard of.
	WhyUnknown Why = "unknown"
	// WhyUnreadable is an identifier nothing can turn into a request. It is
	// separated from the one above because it is a fault in a document this
	// deployment accepted rather than a fact about the world, and reading it
	// as "no index knows this" would put it on the list of names an operator
	// is about to hold back, where it means nothing.
	WhyUnreadable Why = "unreadable"
)

// Unanswered is one component with no upstream answer, and why.
type Unanswered struct {
	Purl      string
	Ecosystem string
	Why       Why
	// Checked is when the pass last reached it. For a held-back name that is
	// when it was last decided against rather than when anything was asked.
	Checked time.Time
}

// MostExamined bounds how many components one read of the report classifies.
//
// The classification is applied after the rows arrive, because it is a list of
// names rather than anything a query can express, so the read has to be
// bounded by something other than the page. Far above what the set can be on
// any real estate — it is components in the four askable ecosystems that were
// asked and came back with nothing, which is the private and vendored part of
// an inventory rather than the whole of it — and the answer says when it was
// reached rather than quietly reporting a count that is a floor.
const MostExamined = 20000

// mostExamined is that ceiling, in a variable only so that a test can lower
// it.
//
// Nothing in production writes it. Seeding twenty thousand components to reach
// the arm past it is a test nobody runs, and what that arm does is report a
// count as a floor — a claim about the answer's own accuracy, which is exactly
// the kind that has to be exercised rather than reasoned about.
var mostExamined = MostExamined

// unanswered is one row as the database hands it over.
type unanswered struct {
	Purl    string    `bun:"purl"`
	Checked time.Time `bun:"latest_checked_at"`
}

// Unanswerable reads what has no upstream answer, and says why of each.
//
// **Derived rather than stored.** A held-back name and one no index knows are
// recorded identically — asked at this time, no version — because the pass
// must record both or starve its own window on them for ever. What tells them
// apart is the same list applied again, here, which also means the report
// follows a change to that list immediately instead of waiting for a month of
// backoff to expire.
//
// Narrowed to the products this subject may read. A component identifier says
// what a build is made of, so a list of them across the estate is an answer
// about products, not about the deployment (REQ-42).
func Unanswerable(ctx context.Context, db bun.IDB, subject access.Subject, ours Ours,
	limit, offset int) (rows []Unanswered, total int, whole bool, err error) {

	products, all := subject.Products()
	if !all && len(products) == 0 {
		// Nothing readable is a real answer rather than an empty condition to
		// be filled in: narrowed on an empty set the clause would read as no
		// narrowing at all on one engine and as nothing on another.
		return nil, 0, true, nil
	}

	q := db.NewSelect().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`DISTINCT c.purl AS "purl"`).
		ColumnExpr(`c.latest_checked_at AS "latest_checked_at"`).
		Join(`JOIN "graph_node" AS "n" ON n.component_id = c.id`).
		Join(`JOIN "target" AS "tg" ON tg.id = n.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		// Still carried. A component that was in a build last year and is not
		// now is not a name that would leave this deployment tonight.
		Where("n.closed_scan_id IS NULL").
		Where("c.purl <> ''").
		// Asked and answered with nothing. A component never reached is not
		// unanswered, it is waiting — and reporting the backlog as though the
		// indexes had failed on it would make the list useless on the first
		// day, which is the day somebody reads it.
		Where("c.latest_checked_at IS NOT NULL").
		Where("c.latest_version IS NULL").
		// Only what there is an index for. One spelling with the pass's own
		// condition, because the report has to describe the same candidates
		// the pass asks about.
		WhereGroup(" AND ", askableOnly).
		// Ordered before it is cut, so a deployment past the ceiling reads
		// the same part of the list twice rather than whatever the engine
		// happened to hand over.
		OrderExpr("c.purl ASC").
		// One more than the ceiling, so reaching it is told apart from
		// landing exactly on it.
		Limit(mostExamined + 1)
	if !all {
		q = q.Where("st.product_id IN (?)", bun.List(products))
	}

	var found []unanswered
	if err := q.Scan(ctx, &found); err != nil {
		return nil, 0, false, fmt.Errorf("read what has no upstream answer: %w", err)
	}

	whole = len(found) <= mostExamined
	if !whole {
		found = found[:mostExamined]
	}
	for _, row := range found {
		ecosystem, _, readable := Asked(row.Purl)
		why := WhyUnknown
		switch {
		case !readable:
			why = WhyUnreadable
		case ours.HeldBack(row.Purl):
			why = WhyOurs
		}
		rows = append(rows, Unanswered{
			Purl: row.Purl, Ecosystem: ecosystem, Why: why, Checked: row.Checked,
		})
	}
	// Sorted here rather than by the database, because the order a person
	// reads this in is by name and the classification the name is grouped by
	// is worked out after the rows arrive.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Why != rows[j].Why {
			return rows[i].Why < rows[j].Why
		}
		return rows[i].Purl < rows[j].Purl
	})
	total = len(rows)
	if offset >= len(rows) {
		return nil, total, whole, nil
	}
	rows = rows[offset:]
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, total, whole, nil
}
