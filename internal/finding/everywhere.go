package finding

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// One issue, everywhere it sits.
//
// **The work starts from an issue as often as from a product**, and it could
// not: findings are answered per product, so "a critical just landed in
// openssl — which of our products ship an affected version" was a question
// asked a dozen times and assembled by hand. At a dozen products that is the
// first thing anybody complains about.
//
// **Narrowed the way every other read is**, per product and per visibility, in
// the query. A page that spans products is exactly where filtering afterwards
// gets forgotten, and the count is the leak even when no row is shown.

// Sighting is one issue in one component of one build, with what stands there.
type Sighting struct {
	Product     string
	ProductName string
	Stream      string
	Variant     string
	Component   string
	Version     string
	// Places is how many times that component sits in that build carrying
	// this issue — one issue in one component can sit at sixty places.
	Places int
	// State is how far it has been decided, by the same definition the
	// findings list uses: a group is agreed when every place is, waiting when
	// any is, undecided when none has a claim.
	State       string
	Undisclosed bool
	DueAt       *time.Time
	FixedIn     string
}

// Everywhere is every build that carries one issue, across every product the
// subject may see.
//
// **One row per build and component**, not per place: the same component at
// the same version in two builds is two rows because they are two things
// somebody ships, and sixty places of it in one build is one row with a count,
// because it is one piece of work.
//
// Capped, with the total said. A kernel flaw across a dozen products and forty
// builds is a real answer and an unbounded one is a page nobody can read.
func (s *Store) Everywhere(ctx context.Context, subject access.Subject,
	vulnerabilityID int64, limit int) ([]Sighting, int, error) {

	limit = database.AWholeBuild.Of(limit)
	products, all := subject.Products()
	if subject.Kind != access.Person || (!all && len(products) == 0) {
		return nil, 0, nil
	}

	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.TableExpr("finding AS f").
			Join(`JOIN "target" AS tg ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS st ON st.id = tg.stream_id`).
			Join(`JOIN "variant" AS va ON va.id = tg.variant_id`).
			Join(`JOIN "product" AS p ON p.id = st.product_id`).
			Join(`JOIN "component" AS c ON c.id = f.component_id`).
			Join(`LEFT JOIN "component" AS uc ON uc.id = f.consumer_id`).
			Where("f.vulnerability_id = ?", vulnerabilityID).
			Where("f.closed_at IS NULL")
		return onlyReadable(q, subject, products, all)
	}

	total, err := s.db.NewSelect().
		TableExpr(`(?) AS "sightings"`, narrow(s.db.NewSelect()).
			ColumnExpr("DISTINCT st.product_id, tg.id, f.component_id")).
		Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count where this issue sits: %w", err)
	}

	var rows []struct {
		Product     string     `bun:"product"`
		ProductName string     `bun:"product_name"`
		Stream      string     `bun:"stream"`
		Variant     string     `bun:"variant"`
		Component   string     `bun:"component"`
		Version     string     `bun:"version"`
		Places      int        `bun:"places"`
		AnyClaim    int        `bun:"any_claim"`
		Waiting     int        `bun:"waiting"`
		Approved    int        `bun:"approved"`
		Lapsed      int        `bun:"lapsed"`
		Private     int        `bun:"private"`
		DueAt       *time.Time `bun:"due_at"`
		FixedIn     string     `bun:"fixed_in"`
	}
	// How far each place has been decided, asked as a correlated count per
	// place rather than by joining the decisions in. A join multiplies the
	// rows — a place with two decisions counts twice — and the number of
	// places is exactly what the state word compares against. This is the
	// same expression the findings list uses, so the two agree about what
	// "agreed" means.
	decided := func(alias, condition string) string {
		return `SUM(CASE WHEN EXISTS (SELECT 1 FROM "decision" AS de
			WHERE de.product_id = st.product_id
			  AND de.vulnerability_id = f.vulnerability_id
			  AND de.place_identity = f.place_identity
			  AND ` + coversHere + condition + `) THEN 1 ELSE 0 END) AS ` + alias
	}
	err = narrow(s.db.NewSelect()).
		ColumnExpr("p.name AS product").
		ColumnExpr("COALESCE(NULLIF(p.display_name, ''), p.name) AS product_name").
		ColumnExpr("st.name AS stream").
		ColumnExpr("va.name AS variant").
		ColumnExpr("c.name AS component").
		ColumnExpr("MIN(c.version) AS version").
		ColumnExpr("COUNT(*) AS places").
		ColumnExpr(decided("any_claim", "")).
		ColumnExpr(decided("waiting", " AND de.state = ? AND de.live_key IS NOT NULL"), "proposed").
		ColumnExpr(decided("approved", " AND de.state = ? AND de.live_key IS NOT NULL"), "approved").
		ColumnExpr(decided("lapsed", " AND de.state = ?"), "lapsed").
		ColumnExpr("SUM(CASE WHEN f.visibility = ? THEN 1 ELSE 0 END) AS private", access.Private).
		ColumnExpr("MIN(f.due_at) AS due_at").
		ColumnExpr("MIN(COALESCE(f.fixed_in, '')) AS fixed_in").
		GroupExpr("p.name, p.display_name, st.name, va.name, c.name").
		OrderExpr("p.name, st.name, va.name, c.name").
		Limit(limit).
		Scan(ctx, &rows)
	if err != nil {
		return nil, 0, fmt.Errorf("read where this issue sits: %w", err)
	}

	out := make([]Sighting, 0, len(rows))
	for _, row := range rows {
		out = append(out, Sighting{
			Product: row.Product, ProductName: row.ProductName,
			Stream: row.Stream, Variant: row.Variant,
			Component: row.Component, Version: row.Version,
			Places:      row.Places,
			State:       stateWord(row.Places, row.AnyClaim, row.Waiting, row.Approved, row.Lapsed),
			Undisclosed: row.Private > 0,
			DueAt:       row.DueAt,
			FixedIn:     row.FixedIn,
		})
	}
	// Ordered here as well as in the statement, so two engines that disagree
	// about how names sort still answer in the same order.
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Product != b.Product {
			return a.Product < b.Product
		}
		if a.Stream != b.Stream {
			return a.Stream < b.Stream
		}
		if a.Variant != b.Variant {
			return a.Variant < b.Variant
		}
		return a.Component < b.Component
	})
	return out, total, nil
}
