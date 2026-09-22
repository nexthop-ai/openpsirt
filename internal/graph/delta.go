package graph

import (
	"context"
	"fmt"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
)

// Delta is what one scan made of a build's inventory.
//
// Counted by name rather than by component. A name is what somebody reading a
// build acts on, and an inventory that carries one name at two versions at
// once — which a vendored tree does routinely — has not gained and lost a
// dependency every time one of the two moves.
type Delta struct {
	// Added is names the inventory did not hold before this scan.
	Added int
	// Removed is names it held and does not any more.
	Removed int
	// Changed is names held on both sides at a different set of versions.
	Changed int
}

// Deltas says what each of these scans made of one build's inventory.
//
// The comparison is against the inventory as it stood immediately before each
// scan, which is what the intervals already record: a node is present before
// scan S where it opened earlier and had not closed by then, and present at S
// where it opened no later and has not closed since. Nothing is stored for
// this and nothing needs to be — the answer is worked out from the rows the
// scan wrote when it was applied.
//
// A scan is absent from the answer where there is nothing to compare it
// against: the earliest scan to apply a graph here is the first picture of
// this build rather than a change to one. Every other scan asked about is
// present whatever it changed, so that a caller can tell a rebuild that moved
// nothing from a scan this does not answer for.
//
// Two statements for the whole set, because the surface asking is a page of
// receipts: a pair per upload would be a hundred round trips to fill three
// columns.
func (s *Store) Deltas(ctx context.Context, subject access.Subject, targetID int64,
	scanIDs []int64) (map[int64]Delta, error) {

	if len(scanIDs) == 0 {
		return map[int64]Delta{}, nil
	}
	productID, err := catalog.NewStore(s.db).ProductOf(ctx, targetID)
	if err != nil {
		return nil, err
	}
	// What a build shipped, rather than what is open against it. The
	// visibility a finding carries narrows no part of this: the answer is
	// arithmetic over the document a build sent, in the same class as the
	// component and placed counts a receipt already carries, and the pipeline
	// that sent it is who asks. So the question is whether this subject
	// reaches the build at all.
	if !subject.Sees(productID) {
		return nil, access.Denied(fmt.Sprintf("read what product %d contains", productID))
	}

	wanted, err := s.comparable(ctx, targetID, scanIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[int64]Delta, len(wanted))
	for _, id := range wanted {
		out[id] = Delta{}
	}
	if len(wanted) == 0 {
		return out, nil
	}

	rows, err := s.moved(ctx, targetID, wanted)
	if err != nil {
		return nil, err
	}

	// Versions are counted rather than collected: a name whose version set
	// moved is one whose count on either side differs from the count present
	// on both, which answers the same question without carrying the strings.
	type tally struct{ before, after, both int }
	names := map[int64]map[string]*tally{}
	for _, row := range rows {
		at, ok := names[row.At]
		if !ok {
			at = map[string]*tally{}
			names[row.At] = at
		}
		seen, ok := at[row.Name]
		if !ok {
			seen = &tally{}
			at[row.Name] = seen
		}
		switch {
		case row.Had == 1 && row.Has == 1:
			seen.before, seen.after, seen.both = seen.before+1, seen.after+1, seen.both+1
		case row.Had == 1:
			seen.before++
		case row.Has == 1:
			seen.after++
		}
	}

	// One statement answers the whole page, so every name any scan on the
	// page moved is looked at against every scan on it. A name that stood on
	// neither side of this one belongs to another upload.
	for at, seen := range names {
		delta := out[at]
		for _, name := range seen {
			switch {
			case name.before == 0 && name.after == 0:
				// Another scan on the page moved this name; this one did not.
			case name.before == 0:
				delta.Added++
			case name.after == 0:
				delta.Removed++
			case name.before != name.both || name.after != name.both:
				delta.Changed++
			}
		}
		out[at] = delta
	}
	return out, nil
}

// comparable is which of these scans this build can be compared across.
//
// A scan of another build is not one of them, so an identifier a caller took
// from somewhere else is answered for by nothing rather than by three zeros
// that read as a scan which changed nothing.
//
// Neither is the earliest scan to have written a graph here, which is the
// first picture of the build. The root opens with it, so it is the first scan
// whatever the document placed. A build nothing has ever been applied to
// leaves that subquery empty, and the comparison against it is true of no
// scan — which is the same answer for the same reason.
func (s *Store) comparable(ctx context.Context, targetID int64, scanIDs []int64) ([]int64, error) {
	first := s.db.NewSelect().
		TableExpr(`"graph_node" AS "fn"`).
		ColumnExpr(`MIN(fn.opened_scan_id)`).
		Where("fn.target_id = ?", targetID)

	var wanted []int64
	err := s.db.NewSelect().
		TableExpr(`"scan" AS "sc"`).
		ColumnExpr(`sc.id`).
		Where("sc.target_id = ?", targetID).
		Where("sc.id IN (?)", bun.List(scanIDs)).
		Where("sc.id > (?)", first).
		Scan(ctx, &wanted)
	if err != nil {
		return nil, fmt.Errorf("read which scans this build can be compared across: %w", err)
	}
	return wanted, nil
}

// movedRow is one name at one of its versions, and whether that version stood
// on each side of one scan.
type movedRow struct {
	At   int64  `bun:"at"`
	Name string `bun:"nm"`
	Had  int    `bun:"had"`
	Has  int    `bun:"has"`
}

// moved reads every version of every name one of these scans may have moved,
// with what each scan found there and what it left.
//
// The names are narrowed to what these scans opened or closed a row of, which
// is the whole of what any of them can have moved: a scan stamps its own
// identifier on both ends of an interval, so a name none of them touched
// stands identically on both sides of every one of them.
//
// The narrowing is per page rather than per scan, so a name comes back against
// every scan on the page and not only against the one that moved it. Against
// the others it stands the same on both sides, or on neither side where the
// name reached this build after them — and the caller counts both as no
// change.
func (s *Store) moved(ctx context.Context, targetID int64, scanIDs []int64) ([]movedRow, error) {
	earliest, latest := scanIDs[0], scanIDs[0]
	for _, id := range scanIDs {
		earliest, latest = min(earliest, id), max(latest, id)
	}

	touched := s.db.NewSelect().
		TableExpr(`"graph_node" AS "tn"`).
		Join(`JOIN "component" AS "tc" ON tc.id = tn.component_id`).
		ColumnExpr(`tc.name_folded`).
		Where("tn.target_id = ?", targetID).
		Where("tn.is_root = ?", false).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("tn.opened_scan_id IN (?)", bun.List(scanIDs)).
				WhereOr("tn.closed_scan_id IN (?)", bun.List(scanIDs))
		})

	var rows []movedRow
	err := s.db.NewSelect().
		TableExpr(`"scan" AS "sc"`).
		Join(`JOIN "graph_node" AS "n" ON n.target_id = ?`, targetID).
		Join(`JOIN "component" AS "c" ON c.id = n.component_id`).
		ColumnExpr(`sc.id AS "at"`).
		ColumnExpr(`c.name_folded AS "nm"`).
		// Present immediately before the scan, and present at it. A row the
		// scan closed was still there on the near side of it, which is why
		// one bound is inclusive and the other is not.
		ColumnExpr(`MAX(CASE WHEN n.opened_scan_id < sc.id
			AND (n.closed_scan_id IS NULL OR n.closed_scan_id >= sc.id)
			THEN 1 ELSE 0 END) AS "had"`).
		ColumnExpr(`MAX(CASE WHEN n.opened_scan_id <= sc.id
			AND (n.closed_scan_id IS NULL OR n.closed_scan_id > sc.id)
			THEN 1 ELSE 0 END) AS "has"`).
		Where("sc.target_id = ?", targetID).
		Where("sc.id IN (?)", bun.List(scanIDs)).
		// The build's own root is not one of its components, and its version
		// is not stored, so it can neither arrive nor move.
		Where("n.is_root = ?", false).
		Where("c.name_folded IN (?)", touched).
		// Rows that stood on neither side of any of these scans count
		// towards none of them, and a year of nights leaves most of a
		// build's rows closed long before the page being read. Without this
		// bound the cost grew with the calendar rather than with the page:
		// on SQLite a page of fifty took 78 ms behind 73 nights of history
		// and 264 ms behind 365. With it, 73 ms and 102 ms.
		Where("n.opened_scan_id <= ?", latest).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("n.closed_scan_id IS NULL").
				WhereOr("n.closed_scan_id >= ?", earliest)
		}).
		// The version is grouped on and not selected: what is being asked is
		// how many versions of a name stood on each side, and the strings
		// themselves are nobody's answer here.
		GroupExpr(`sc.id, c.name_folded, c.version`).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what these scans changed: %w", err)
	}
	return rows, nil
}
