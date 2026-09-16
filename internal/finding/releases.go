package finding

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/rating"
)

// Release is one build of a product and how much stands open against it.
type Release struct {
	Stream  string
	Kind    string
	Variant string
	// Open is what the findings list would show for this build, before any
	// triage line: one per issue at a component, however many places it sits
	// at there.
	//
	// **Not a row count.** Rows are places, and a component reached twenty
	// ways carries the same issue twenty times — counting them reported
	// 241,161 for a build every other screen reports at 7,546. The trend chart
	// made exactly this mistake and its comment records the fix; this is the
	// same lesson arriving in a second place.
	Open int
	// BySeverity is that total split the four ways everything else here ranks
	// by, folded through the one expression the line and the deadline use so a
	// chart cannot disagree with a list about what "high" means.
	BySeverity map[string]int
}

// Releases reports what is open against every build of one product.
//
// The number a release-over-release chart is drawn from, which nothing
// reported before: the comparison screen could say what changed between two
// builds and could not say whether the estate was getting better or worse
// across all of them.
//
// One statement rather than one per build. A product with thirty tags would
// otherwise be thirty round trips to draw one chart, and the answer would be
// assembled from thirty moments rather than one.
func (s *Store) Releases(ctx context.Context, subject access.Subject,
	productID int64) ([]Release, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are different
	// statements, and a pipeline key asking this is the second. A person who
	// cannot see the product is the first, and is answered below — this is a
	// narrowed read, and an empty answer is the correct one for somebody the
	// product does not exist for.
	if subject.Kind != access.Person {
		return nil, access.Denied("read what the releases hold")
	}
	if !subject.Sees(productID) {
		return nil, nil
	}
	_, all := subject.Products()

	var rows []struct {
		Stream  string `bun:"stream"`
		Kind    string `bun:"kind"`
		Variant string `bun:"variant"`
		Band    string `bun:"band"`
		Open    int    `bun:"open"`
	}
	// The distinct pairs first, counted after. Counting distinct over two
	// columns at once is not something every engine spells the same way, and
	// concatenating them into one string is a portability trap of its own.
	inner := s.db.NewSelect().
		Distinct().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
		Join(rating.Here, productID).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`st.kind AS "kind"`).
		ColumnExpr(`va.name AS "variant"`).
		ColumnExpr(rating.BandExpr+` AS "band"`).
		ColumnExpr(`f.vulnerability_id AS "vulnerability_id"`).
		ColumnExpr(`f.component_id AS "component_id"`).
		Where("st.product_id = ?", productID).
		Where("f.closed_at IS NULL")
	inner = inOneProduct(inner, subject, productID, all)

	query := s.db.NewSelect().
		TableExpr(`(?) AS "at"`, inner).
		ColumnExpr(`at.stream AS "stream"`).
		ColumnExpr(`at.kind AS "kind"`).
		ColumnExpr(`at.variant AS "variant"`).
		ColumnExpr(`at.band AS "band"`).
		ColumnExpr(`COUNT(*) AS "open"`).
		GroupExpr("at.stream, at.kind, at.variant, at.band").
		// Ordered here rather than in the caller, so every reader of this gets
		// the same sequence. A chart whose points move between requests is
		// worse than one that is wrong in a fixed way.
		OrderExpr("at.stream, at.variant")

	if err := query.Scan(ctx, &rows); err != nil {
		return nil, fmt.Errorf("read what is open against each build: %w", err)
	}

	// **Every build that has been scanned, whether or not anything is open
	// against it.** Read separately and merged, because the counts come from
	// the findings and a build with none has no finding to be read from.
	//
	// Driven from the findings alone, a release with nothing open was simply
	// absent — and absent is how this list says "never scanned". So a clean
	// build read as an unmeasured one, which is the opposite of what it is,
	// and it was missing from the chart that is meant to show the estate
	// getting better.
	var scanned []struct {
		Stream  string `bun:"stream"`
		Kind    string `bun:"kind"`
		Variant string `bun:"variant"`
	}
	builds := s.db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`st.kind AS "kind"`).
		ColumnExpr(`va.name AS "variant"`).
		Where("st.product_id = ?", productID).
		Where(`EXISTS (SELECT 1 FROM "scan_run" AS "sr"
			WHERE sr.target_id = tg.id AND sr.finished_at IS NOT NULL)`).
		OrderExpr("st.name, va.name")
	if err := builds.Scan(ctx, &scanned); err != nil {
		return nil, fmt.Errorf("read which builds have been scanned: %w", err)
	}

	// Folded in order, so the sequence the database returned is the sequence
	// the caller sees. The scanned builds go in first, which is also what
	// fixes the order: a build with nothing open would otherwise be appended
	// after everything that has something.
	var releases []Release
	at := map[string]int{}
	place := func(stream, kind, variant string) int {
		key := stream + "\x00" + variant
		index, seen := at[key]
		if !seen {
			index = len(releases)
			at[key] = index
			releases = append(releases, Release{
				Stream: stream, Kind: kind, Variant: variant,
				BySeverity: map[string]int{},
			})
		}
		return index
	}
	for _, build := range scanned {
		place(build.Stream, build.Kind, build.Variant)
	}
	for _, row := range rows {
		index := place(row.Stream, row.Kind, row.Variant)
		releases[index].Open += row.Open
		releases[index].BySeverity[row.Band] += row.Open
	}
	return releases, nil
}

// LatestRun is the most recent finished scan run against a build.
//
// What the numbers on a screen were measured against: which scanner, at which
// version, reading which vulnerability database. The scan run has always
// carried it and nothing showed it, so a reader had no way to tell a build
// with nothing wrong from one last measured against a database from March.
func (s *Store) LatestRun(ctx context.Context, subject access.Subject,
	targetID int64) (*Run, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	// A person, and one who may see this product. `Sees` alone is true for a
	// pipeline credential naming the product, which ignores the stream and
	// variant that credential is pinned to — `Releases` beside this checks the
	// kind explicitly and this did not. No route reaches it as a pipeline
	// today; the next one added would.
	if subject.Kind != access.Person {
		return nil, access.Denied("read what the releases hold")
	}
	if !subject.Sees(productID) {
		return nil, nil
	}
	var runs []Run
	err = s.db.NewSelect().Model(&runs).
		Where("target_id = ?", targetID).
		Where("finished_at IS NOT NULL").
		Order("id DESC").
		Limit(1).
		Scan(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the last run against this build: %w", err)
	}
	if len(runs) == 0 {
		return nil, nil
	}
	return &runs[0], nil
}

// VersionsWithIssue lists the versions of a named component in one build that
// this issue is actually open against.
//
// The component lookup raises an ambiguity before it knows which issue is
// being asked about, so on its own it can only offer every version of the
// name. A real image ships one library at fifteen, of which three carry a
// given issue — offering all fifteen is a list where four in five choices lead
// to "no such finding", which is a worse answer than the refusal it replaced.
func (s *Store) VersionsWithIssue(ctx context.Context, subject access.Subject,
	targetID, vulnerabilityID int64, name string) ([]graph.Choice, error) {

	productID, err := productOf(ctx, s.db, targetID)
	if err != nil {
		return nil, err
	}
	visible := access.Visible(subject, productID)
	if !subject.Sees(productID) || len(visible) == 0 {
		return nil, nil
	}

	var rows []struct {
		Version string `bun:"version"`
		Purl    string `bun:"purl"`
	}
	err = s.db.NewSelect().
		Distinct().
		TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
		ColumnExpr(`c.version AS "version"`).
		ColumnExpr(`c.purl AS "purl"`).
		Where("f.target_id = ?", targetID).
		Where("f.vulnerability_id = ?", vulnerabilityID).
		Where("f.closed_at IS NULL").
		Where("c.name = ?", name).
		Where("f.visibility IN (?)", bun.List(visible)).
		OrderExpr("c.version, c.purl").
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which versions carry this issue: %w", err)
	}
	choices := make([]graph.Choice, 0, len(rows))
	for _, row := range rows {
		choices = append(choices, graph.Choice{
			Version: row.Version, Ecosystem: graph.EcosystemOf(row.Purl),
		})
	}
	return choices, nil
}
