// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package graph

import (
	"context"
	"fmt"
	"slices"
	"strings"

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
// The same statements for the whole set however many uploads it holds,
// because the surface asking is a page of receipts: a set per upload would be a
// hundred round trips to fill three columns.
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

	// Counted from the same fold the listing of one upload is made of. Two
	// folds is two answers to "did this name move", and the one nobody reads
	// beside the other is the one that drifts.
	for at, changes := range changed(rows) {
		out[at] = count(changes)
	}
	return out, nil
}

// count is the delta a list of changes adds up to.
func count(changes []Change) Delta {
	var delta Delta
	for _, change := range changes {
		switch change.Kind {
		case Added:
			delta.Added++
		case Removed:
			delta.Removed++
		case Changed:
			delta.Changed++
		}
	}
	return delta
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
//
// Name is the folded name, which is what two versions of one dependency have
// in common, and Display is that name as a producer wrote it, for a reader.
type movedRow struct {
	At      int64  `bun:"at"`
	Name    string `bun:"nm"`
	Display string `bun:"dsp"`
	Version string `bun:"ver"`
	Had     int    `bun:"had"`
	Has     int    `bun:"has"`
}

// moved reads every version of every name one of these scans moved, with what
// each scan found there and what it left.
//
// A scan moved a name where it opened or closed a row of it: a scan stamps its
// own identifier on both ends of an interval, so a name none of them touched
// stands identically on both sides of every one of them. Each name is paired
// with the scans that touched it and no other, so the work is what the page's
// uploads changed rather than that times the length of the page.
//
// Two statements and a fold, rather than one statement joining the names to
// the build's rows. Joined, PostgreSQL drove from the names and looked each
// one's rows up through the index led by the build, where the component is the
// third column: 54,902 lookups each reading the build's whole range, 40.5 s for
// one upload that removed a file inventory. Read once by the build instead,
// the rows are matched to the names here.
func (s *Store) moved(ctx context.Context, targetID int64, scanIDs []int64) ([]movedRow, error) {
	earliest, latest := scanIDs[0], scanIDs[0]
	asked := make(map[int64]bool, len(scanIDs))
	for _, id := range scanIDs {
		earliest, latest = min(earliest, id), max(latest, id)
		asked[id] = true
	}

	// The names each scan opened or closed a row of.
	var ends []struct {
		Opened int64  `bun:"opened"`
		Closed *int64 `bun:"closed"`
		Name   string `bun:"nm"`
	}
	err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "tn"`).
		Join(`JOIN "component" AS "tc" ON tc.id = tn.component_id`).
		ColumnExpr(`tn.opened_scan_id AS "opened"`).
		ColumnExpr(`tn.closed_scan_id AS "closed"`).
		ColumnExpr(`tc.name_folded AS "nm"`).
		Where("tn.target_id = ?", targetID).
		Where("tn.is_root = ?", false).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("tn.opened_scan_id IN (?)", bun.List(scanIDs)).
				WhereOr("tn.closed_scan_id IN (?)", bun.List(scanIDs))
		}).
		Scan(ctx, &ends)
	if err != nil {
		return nil, fmt.Errorf("read what these scans changed: %w", err)
	}
	touched := map[string][]int64{}
	touch := func(name string, at int64) {
		if asked[at] && !slices.Contains(touched[name], at) {
			touched[name] = append(touched[name], at)
		}
	}
	for _, end := range ends {
		touch(end.Name, end.Opened)
		if end.Closed != nil {
			touch(end.Name, *end.Closed)
		}
	}
	if len(touched) == 0 {
		return nil, nil
	}

	// Every row of the build that stood on either side of any of these scans.
	// Rows that stood on neither count towards none of them, and a year of
	// nights leaves most of a build's rows closed long before the page being
	// read, so this bound is what keeps the cost with the page rather than the
	// calendar: unbounded, on SQLite, a page of fifty takes 78 ms behind 73
	// nights of history and 264 ms behind 365.
	var nodes []struct {
		Opened  int64  `bun:"opened"`
		Closed  *int64 `bun:"closed"`
		Name    string `bun:"nm"`
		Display string `bun:"dsp"`
		Version string `bun:"ver"`
	}
	err = s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON c.id = n.component_id`).
		ColumnExpr(`n.opened_scan_id AS "opened"`).
		ColumnExpr(`n.closed_scan_id AS "closed"`).
		ColumnExpr(`c.name_folded AS "nm"`).
		// The name as a producer wrote it, for the listing to show. Two
		// producers writing one dependency in different capitals are one name
		// here, and either spelling names the same thing on a screen.
		ColumnExpr(`c.name AS "dsp"`).
		ColumnExpr(`c.version AS "ver"`).
		Where("n.target_id = ?", targetID).
		// The build's own root is not one of its components, and its version
		// is not stored, so it can neither arrive nor move.
		Where("n.is_root = ?", false).
		Where("n.opened_scan_id <= ?", latest).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("n.closed_scan_id IS NULL").
				WhereOr("n.closed_scan_id >= ?", earliest)
		}).
		Scan(ctx, &nodes)
	if err != nil {
		return nil, fmt.Errorf("read what these scans changed: %w", err)
	}

	// One row per version of a name at each scan that touched it, which is
	// what makes "the same name at a different set of versions" answerable:
	// the page of receipts counts those rows and the listing of one scan reads
	// the strings off them.
	type key struct {
		at            int64
		name, version string
	}
	folded := map[key]*movedRow{}
	var order []key
	for _, node := range nodes {
		for _, at := range touched[node.Name] {
			k := key{at, node.Name, node.Version}
			row, ok := folded[k]
			if !ok {
				row = &movedRow{At: at, Name: node.Name, Display: node.Display, Version: node.Version}
				folded[k] = row
				order = append(order, k)
			} else if node.Display < row.Display {
				row.Display = node.Display
			}
			// Present immediately before the scan, and present at it. A row
			// the scan closed was still there on the near side of it, which is
			// why one bound is inclusive and the other is not.
			if node.Opened < at && (node.Closed == nil || *node.Closed >= at) {
				row.Had = 1
			}
			if node.Opened <= at && (node.Closed == nil || *node.Closed > at) {
				row.Has = 1
			}
		}
	}
	rows := make([]movedRow, 0, len(order))
	for _, k := range order {
		rows = append(rows, *folded[k])
	}
	return rows, nil
}

// Change is what one scan did to one name in a build's inventory.
type Change struct {
	// Name is the name as a producer wrote it.
	Name string
	// Kind is what happened to it.
	Kind ChangeKind
	// Before and After are the versions the name stood at immediately before
	// the scan and stands at from it, in the order they sort. A name that
	// arrived has nothing before it and one that went has nothing after it.
	Before []string
	After  []string
}

// ChangeKind is what one scan did to one name.
//
// The three the delta counts, spelled the same way: a screen reading a listing
// and a pipeline reading a receipt are looking at one answer.
type ChangeKind string

const (
	// Added is a name the inventory did not hold before this scan.
	Added ChangeKind = "added"
	// Removed is a name it held and does not any more. The one worth reading
	// first: a build that stopped describing a dependency looks exactly like
	// one that stopped shipping it.
	Removed ChangeKind = "removed"
	// Changed is a name both sides hold at a different set of versions.
	Changed ChangeKind = "changed"
)

// Changes is every name one scan moved, in the order they are worth reading.
//
// The same comparison the counts on a receipt are made of, read off the same
// statement: a listing that disagreed with the number beside it would leave a
// reader with two answers and no way to tell which is the build's.
//
// Removals first, then arrivals, then the names that moved version, and each
// group by name. A build that stopped describing a dependency and one that
// stopped shipping it look identical from here, and that is the case somebody
// opens this to find.
//
// The page is taken after the comparison rather than in the statement. What is
// read is the scan's own delta — the names it opened or closed a row of — so
// the cost is what the upload changed rather than what the build contains.
func (s *Store) Changes(ctx context.Context, subject access.Subject, targetID, scanID int64,
	only ChangeKind, limit, offset int) ([]Change, int, error) {

	productID, err := catalog.NewStore(s.db).ProductOf(ctx, targetID)
	if err != nil {
		return nil, 0, err
	}
	// The rule the counts are answered under, for the reason they are: this is
	// what a build sent rather than what is open against it, so what it asks
	// is whether this subject reaches the build at all.
	if !subject.Sees(productID) {
		return nil, 0, access.Denied(fmt.Sprintf("read what product %d contains", productID))
	}

	wanted, err := s.comparable(ctx, targetID, []int64{scanID})
	if err != nil {
		return nil, 0, err
	}
	if len(wanted) == 0 {
		// The first scan applied to this build, a scan of another build, or
		// one nothing has applied. None of them is a change to an inventory.
		return nil, 0, nil
	}

	rows, err := s.moved(ctx, targetID, wanted)
	if err != nil {
		return nil, 0, err
	}
	changes := changed(rows)[scanID]
	if only != "" {
		// A word this does not know would narrow the answer to nothing, which
		// reads as an upload that changed nothing rather than as a question
		// nobody can answer.
		if only != Added && only != Removed && only != Changed {
			return nil, 0, fmt.Errorf("%q is not a kind of change", only)
		}
		kept := changes[:0]
		for _, change := range changes {
			if change.Kind == only {
				kept = append(kept, change)
			}
		}
		changes = kept
	}
	total := len(changes)
	if offset >= total {
		return []Change{}, total, nil
	}
	changes = changes[offset:]
	if limit > 0 && limit < len(changes) {
		changes = changes[:limit]
	}
	return changes, total, nil
}

// changed folds the rows into what happened to each name, per scan.
//
// Each name comes back against the scans that touched it. A name standing at
// the same versions on both sides of one of them, or on neither, is no change
// of that scan's.
func changed(rows []movedRow) map[int64][]Change {
	type sides struct {
		display       string
		before, after []string
	}
	names := map[int64]map[string]*sides{}
	order := map[int64][]string{}
	for _, row := range rows {
		at, ok := names[row.At]
		if !ok {
			at = map[string]*sides{}
			names[row.At] = at
		}
		seen, ok := at[row.Name]
		if !ok {
			seen = &sides{display: row.Display}
			at[row.Name] = seen
			order[row.At] = append(order[row.At], row.Name)
		} else if row.Display < seen.display {
			// The smallest of the spellings rather than whichever row came
			// back first. One name at two versions is two rows, a producer
			// that changed how it capitalizes a dependency gives them
			// different spellings, and nothing orders the rows — so taken
			// from the first, the same request answers differently twice and
			// the link a screen builds from it lands on nothing.
			seen.display = row.Display
		}
		if row.Had == 1 {
			seen.before = append(seen.before, row.Version)
		}
		if row.Has == 1 {
			seen.after = append(seen.after, row.Version)
		}
	}

	out := make(map[int64][]Change, len(names))
	for at, seen := range names {
		changes := make([]Change, 0, len(order[at]))
		for _, name := range order[at] {
			side := seen[name]
			before, after := sorted(side.before), sorted(side.after)
			change := Change{Name: side.display, Before: before, After: after}
			switch {
			case len(before) == 0 && len(after) == 0:
				// Another scan on the page moved this name; this one did not.
				continue
			case len(before) == 0:
				change.Kind = Added
			case len(after) == 0:
				change.Kind = Removed
			case !slices.Equal(before, after):
				change.Kind = Changed
			default:
				// The same versions on both sides. A scan that closed one
				// place of a name and opened another at the same version has
				// moved nothing about what the build ships.
				continue
			}
			changes = append(changes, change)
		}
		// Removals first, then arrivals, then what moved version, and each
		// group by name. The order is the answer to "what should somebody
		// look at", so it is decided here rather than by whichever column a
		// screen happens to sort on.
		slices.SortFunc(changes, func(a, b Change) int {
			if a.Kind != b.Kind {
				return weigh(a.Kind) - weigh(b.Kind)
			}
			return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		})
		out[at] = changes
	}
	return out
}

// weigh is the order the three are worth reading in.
//
// A removal first: a build that stopped describing a dependency looks exactly
// like one that stopped shipping it, and that is the case somebody opens this
// to find.
func weigh(kind ChangeKind) int {
	switch kind {
	case Removed:
		return 0
	case Added:
		return 1
	default:
		return 2
	}
}

// sorted is the versions of one name in a stable order.
//
// Ordered as text rather than as versions. Ordering them properly is
// per-ecosystem work, and what this is for is a reader looking at a handful of
// strings beside a name — an order they can rely on being the same twice, not
// a claim about which is newer.
func sorted(versions []string) []string {
	out := slices.Clone(versions)
	slices.Sort(out)
	return out
}

// Movement is what one scan made of a build's inventory, against the size of
// the inventory it changed.
//
// The size is what makes a count mean anything: forty names moving is a
// rebuild on an inventory of two thousand and a different build on an
// inventory of sixty.
type Movement struct {
	Delta
	// Held is how many names stood in the inventory immediately before this
	// scan, counted the way the delta counts them.
	Held int
}

// Moved is what one scan made of a build's inventory, for the pass that
// decides whether anybody should hear about it.
//
// Answers whether there is an answer at all, which is false for the first scan
// applied to a build: it is the first picture rather than a change to one.
//
// No subject, because there is nobody asking — this is the deployment working
// out what happened, in the same shape as the passes that derive what is true
// across every product before deciding who may hear each part. Who is told is
// decided where the telling is.
func (s *Store) Moved(ctx context.Context, targetID, scanID int64) (Movement, bool, error) {
	wanted, err := s.comparable(ctx, targetID, []int64{scanID})
	if err != nil {
		return Movement{}, false, err
	}
	if len(wanted) == 0 {
		return Movement{}, false, nil
	}

	rows, err := s.moved(ctx, targetID, wanted)
	if err != nil {
		return Movement{}, false, err
	}
	moved := Movement{Delta: count(changed(rows)[scanID])}

	held, err := s.held(ctx, targetID, scanID)
	if err != nil {
		return Movement{}, false, err
	}
	moved.Held = held
	return moved, true, nil
}

// held is how many names stood in a build's inventory immediately before one
// scan.
//
// The same side of the scan the comparison reads — a row the scan closed was
// still there on the near side of it — and the same exclusion: the build's own
// root is not one of its components.
func (s *Store) held(ctx context.Context, targetID, scanID int64) (int, error) {
	var held int
	// Scanned rather than counted: the count is of names rather than of rows,
	// and asking the query builder to count wraps this in a count of its one
	// row.
	err := s.db.NewSelect().
		TableExpr(`"graph_node" AS "n"`).
		Join(`JOIN "component" AS "c" ON c.id = n.component_id`).
		ColumnExpr(`COUNT(DISTINCT c.name_folded)`).
		Where("n.target_id = ?", targetID).
		Where("n.is_root = ?", false).
		Where("n.opened_scan_id < ?", scanID).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("n.closed_scan_id IS NULL").
				WhereOr("n.closed_scan_id >= ?", scanID)
		}).
		Scan(ctx, &held)
	if err != nil {
		return 0, fmt.Errorf("read how many names this build held: %w", err)
	}
	return held, nil
}
