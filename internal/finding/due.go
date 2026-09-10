package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Windows is how long a finding may stay open before it is late, by how urgent
// it is.
//
// Exploited is separate and shortest. Severity says how bad the flaw is; being
// exploited says somebody is using it, and that is the one that should decide
// how long there is.
type Windows struct {
	Exploited time.Duration
	Critical  time.Duration
	High      time.Duration
	Medium    time.Duration
	Low       time.Duration
}

// DefaultWindows are the shipped numbers, a starting point rather than a
// recommendation: what a deployment can hold to is a question about that
// deployment, and a deadline nobody agreed to produces an estate that is
// permanently late and a signal everybody ignores.
func DefaultWindows() Windows {
	const day = 24 * time.Hour
	return Windows{
		Exploited: 3 * day, Critical: 7 * day, High: 30 * day,
		Medium: 90 * day, Low: 180 * day,
	}
}

// LoadWindows reads how long a finding may stay open, by how urgent it is.
//
// Read here rather than by the caller because ingest needs the same answer as
// the screen does: a deadline is computed once, when a finding is first seen ,
// so the two have to agree about what the policy says or a finding would be
// stored with one deadline and read against another.
func LoadWindows(ctx context.Context, db bun.IDB) (Windows, error) {
	windows := DefaultWindows()
	settings := setting.NewStore(db)
	for _, each := range []struct {
		name string
		at   *time.Duration
	}{
		{setting.DueExploited, &windows.Exploited},
		{setting.DueCritical, &windows.Critical},
		{setting.DueHigh, &windows.High},
		{setting.DueMedium, &windows.Medium},
		{setting.DueLow, &windows.Low},
	} {
		held, err := settings.Duration(ctx, each.name, *each.at)
		if err != nil {
			return Windows{}, err
		}
		*each.at = held
	}
	return windows, nil
}

// For returns how long something of this urgency may stay open.
//
// Being exploited sets its own clock whatever the severity says, because
// severity is how bad the flaw is and being exploited is a fact about the
// world — and it is the one that decides how long you have. Anything rated in
// a word nobody recognizes falls to the middle band rather than the longest:
// an unrated issue is unknown, not harmless.
func (w Windows) For(exploited bool, severity string) time.Duration {
	if exploited {
		return w.Exploited
	}
	switch severity {
	case "critical":
		return w.Critical
	case "high":
		return w.High
	case "low", "negligible", "none":
		return w.Low
	default:
		return w.Medium
	}
}

// Late is a finding whose time is running out with nobody having decided about
// it.
type Late struct {
	Vulnerability string `bun:"vulnerability"`
	Component     string `bun:"component"`
	// Version is which one, because a build ships a name at more than one
	// version often enough that a link without it cannot be resolved — and a
	// screen offering a link that dead-ends is worse than one offering none.
	Version    string `bun:"version"`
	Severity   string `bun:"severity"`
	Exploited  bool   `bun:"exploited"`
	Product    string `bun:"product"`
	Stream     string `bun:"stream"`
	Variant    string `bun:"variant"`
	AssignedTo *int64 `bun:"assigned_to"`
	// Due is the earliest deadline among the places this row covers — the one
	// that makes the whole group late.
	Due time.Time `bun:"due"`
	// Places is how many places this issue sits at in this component. One row
	// covers all of them, because they are one thing to answer.
	Places int `bun:"places"`
	// AssignedHigh and AssignedCount decide whether one name can be reported
	// for the group. They are read and then discarded.
	AssignedHigh  *int64 `bun:"assigned_high"`
	AssignedCount int    `bun:"assigned_count"`
}

// OffTheClock is the condition under which a decision standing at a finding
// takes it off the clock, as SQL, with the values it binds.
//
// One spelling, because there were two. What is running out of time excluded
// any live claim, so a proposal waiting for a second person took a finding off
// that list for as long as it sat in the queue; what each person was holding
// excluded nothing, so the same finding still counted as overdue against
// whoever held it. Two screens answering "is this late" differently is the
// kind of disagreement that gets one of them ignored.
//
// It says what the triage package says when it asks whether a decision
// applies to a place, and nothing else: this product's decision about this
// issue at this place, keyed on the versions the place holds now, approved or
// proposed by somebody whose claim needs no agreement — and a deferral only
// until its date, after which the finding is back on the clock.
//
// The finding is `f`, its component `c` and its consumer `uc`, all joined by
// the caller; product is the SQL naming the finding's product, which a list
// across products reads from the stream and a list within one binds.
func OffTheClock(product string, now time.Time) (string, []any) {
	standing, held := InForce()
	return `EXISTS (SELECT 1 FROM "decision" AS de
		JOIN "claim" AS cl ON cl.id = de.claim_id
		WHERE de.product_id = ` + product + `
		  AND de.vulnerability_id = f.vulnerability_id
		  AND de.place_identity = f.place_identity
		  AND ` + KeyMatches + `
		  AND ` + standing + `
		  AND (cl.deferred_until IS NULL OR cl.deferred_until > ?))`,
		append(held, now.UTC())
}

// InForce is the test for a claim that is in force: agreed, or made by
// somebody whose claim needed no agreement. The decision is `de`, joined by
// the caller, and the values it binds come back with it.
//
// **A claim waiting for a second person is not standing.** It suppresses
// nothing, answers for nothing and covers nothing in the meantime — otherwise
// the review queue is decorative and one person dismisses a finding on their
// own, which is the whole thing a second pair of eyes exists to prevent.
//
// Said in one place because it was spelled several ways, and two of those
// tested only that a claim existed. A proposal nobody had agreed to therefore
// counted as an answer: it took a finding out of the overdue figure and it
// raised a notice saying a deferral was about to end when nothing was in
// force. Pair it with whatever says the claim still applies — `live_key IS NOT
// NULL` where any version will do, KeyMatches where the versions matter.
func InForce() (string, []any) {
	return "(de.state = ? OR (de.state = ? AND de.needs_approval = ?))",
		[]any{"approved", "proposed", false}
}

// RunningOut reports findings whose deadline is within this many days and
// which nobody has decided about, most pressing first.
//
// **Undecided only.** A deadline that has been answered is not a deadline
// running out: a dismissal takes a finding off the clock, because the claim is
// that it will not be fixed, and a deferral replaces the deadline with its own
// date. What is left is time passing with nothing said, which is the only part
// worth interrupting somebody about.
//
// **One row per issue at a component**, not per place. A kernel flaw sitting
// at sixty places is one thing somebody has to answer, and sixty rows of it is
// a list with one entry in it.
//
// The deadline is read rather than derived. It used to be worked out per
// request, which meant a pass over every open finding **per urgency band** —
// each band allows a different number of days, and the window has to narrow
// the rows before they are read rather than after. Measured at about eight
// seconds over 441,108 findings. a deadline stored at ingest stores it
// instead, so this is one range over an index.
//
// A finding with no deadline is left out. That is a row recorded before the
// deadline was stored, and it will have one the next time a scan reopens it —
// which is honestly "not known yet" rather than "not due", and either way not
// something to interrupt anybody about.
func (s *Store) RunningOut(ctx context.Context, subject access.Subject, scope Scope,
	within time.Duration, limit int) ([]Late, error) {

	return s.RunningOutPage(ctx, subject, scope, within, limit, 0)
}

// RunningOutPage is the same list, from a position in it.
//
// Separate from RunningOut because a screen reads the first page and a file
// reads all of them, and the file is the reason the offset exists: an export
// that stopped at the screen's page would be the screen with extra steps, and
// what somebody exports a deadline report for is precisely the part they have
// not read.
func (s *Store) RunningOutPage(ctx context.Context, subject access.Subject, scope Scope,
	within time.Duration, limit, offset int) ([]Late, error) {

	products, all := subject.Products()
	if subject.Kind != access.Person || (!all && len(products) == 0) {
		return nil, nil
	}
	limit = database.AList.Of(limit)

	standing, args := OffTheClock("st.product_id", s.now())
	query := s.db.NewSelect().
		TableExpr("finding AS f").
		Join("JOIN target AS tg ON tg.id = f.target_id").
		Join("JOIN stream AS st ON st.id = tg.stream_id").
		Join("JOIN variant AS va ON va.id = tg.variant_id").
		Join("JOIN product AS p ON p.id = st.product_id").
		Join("JOIN vulnerability AS v ON v.id = f.vulnerability_id").
		Join("JOIN component AS c ON c.id = f.component_id").
		// The consumer, for the versions a decision is keyed on.
		Join("LEFT JOIN component AS uc ON uc.id = f.consumer_id").
		ColumnExpr("v.identifier AS vulnerability").
		ColumnExpr("c.name AS component").
		ColumnExpr("c.version AS version").
		ColumnExpr("MIN(COALESCE(v.severity, '')) AS severity").
		ColumnExpr("f.urgency_exploited AS exploited").
		ColumnExpr("p.display_name AS product").
		ColumnExpr("st.display_name AS stream").
		ColumnExpr("va.display_name AS variant").
		// The earliest of the places this row covers, because that is the one
		// that makes the whole group late.
		ColumnExpr("MIN(f.due_at) AS due").
		ColumnExpr("COUNT(*) AS places").
		// Named only where every place has the same person. Reporting one of
		// several would tell somebody a finding is being dealt with when most
		// of it is not.
		ColumnExpr("MIN(f.assigned_to) AS assigned_to").
		ColumnExpr("MAX(f.assigned_to) AS assigned_high").
		ColumnExpr("COUNT(f.assigned_to) AS assigned_count").
		Where("f.closed_at IS NULL").
		Where("f.due_at IS NOT NULL").
		Where("f.due_at <= ?", s.now().UTC().Add(within)).
		// Nothing the build already argued away, and nothing a decision
		// takes off the clock. Not merely a claim: a proposal waiting for a
		// second person suppresses nothing, and it took findings off this list
		// for as long as it sat in the queue — a quarter, on one — while the
		// same findings still counted as overdue against whoever held them.
		Where("f.suppressed_by IS NULL").
		Where("NOT "+standing, args...).
		GroupExpr("v.identifier, c.name, c.version, f.urgency_exploited, p.display_name, " +
			"st.display_name, va.display_name, f.target_id, f.vulnerability_id, f.component_id").
		// The build is in the order as well as in the grouping. Without it two
		// rows identical down to the component name order arbitrarily, and an
		// arbitrary order between pages is how a paged read repeats one row
		// and skips another.
		OrderExpr("due, v.identifier, c.name, f.target_id").
		Limit(limit).Offset(offset)
	if !all {
		query = query.Where("st.product_id IN (?)", bun.List(products))
	}
	query = onlyVisible(query, subject, products, all)
	query = scope.Narrow(query)

	var late []Late
	if err := query.Scan(ctx, &late); err != nil {
		return nil, fmt.Errorf("read what is running out of time: %w", err)
	}
	for i := range late {
		if late[i].AssignedCount != late[i].Places || late[i].AssignedTo == nil ||
			late[i].AssignedHigh == nil || *late[i].AssignedTo != *late[i].AssignedHigh {
			late[i].AssignedTo = nil
		}
	}
	return late, nil
}

// Recompute rewrites the deadline on every open finding.
//
// The one event that makes a stored deadline wrong is somebody changing the
// policy that sets it. Urgency has the same shape and is left stale until the
// next scan, which is tolerable because nobody edits the ranking — but people
// will edit deadlines, and a deadline that ignores the number you just typed
// is worse than a slow query.
//
// Written as one statement per run and band rather than one per finding. A
// deadline is the run's start plus a fixed number of days, so every finding
// opened by one run and rated the same way lands on the same instant: the
// arithmetic happens here, in Go, and the statement writes a constant. That
// keeps it portable — no engine agrees on how to add days to a timestamp — and
// it is a handful of statements rather than hundreds of thousands.
func (s *Store) Recompute(ctx context.Context, windows Windows) (int, error) {
	// The distinct moments something opened, off the findings themselves.
	// This walked the runs and joined back for the timestamp, which asked the
	// question in terms of the thing that usually answers it rather than the
	// thing that always does: a finding a person opened has no run, so its
	// deadline was never rewritten when the policy changed.
	//
	// The same cardinality either way — every finding a run opened carries
	// that run's start — so this is one table fewer rather than more rows.
	var opened []time.Time
	err := s.db.NewSelect().
		TableExpr("finding AS f").
		ColumnExpr("f.opened_at").
		Where("f.closed_at IS NULL").
		GroupExpr("f.opened_at").
		Scan(ctx, &opened)
	if err != nil {
		return 0, fmt.Errorf("read when what is still open was opened: %w", err)
	}

	// Bands as predicates on the rating, in the same order For() decides them,
	// so a finding lands in exactly one.
	type band struct {
		window time.Duration
		where  func(*bun.UpdateQuery) *bun.UpdateQuery
	}
	rated := func(words ...string) func(*bun.UpdateQuery) *bun.UpdateQuery {
		return func(q *bun.UpdateQuery) *bun.UpdateQuery {
			return q.Where("urgency_exploited = ?", false).
				Where(`vulnerability_id IN (SELECT id FROM "vulnerability" AS v WHERE `+
					BandExpr+` IN (?))`, bun.List(words))
		}
	}
	bands := []band{
		{windows.Exploited, func(q *bun.UpdateQuery) *bun.UpdateQuery {
			return q.Where("urgency_exploited = ?", true)
		}},
		{windows.Critical, rated("critical")},
		{windows.High, rated("high")},
		{windows.Low, rated("low")},
		// Everything else: medium, and anything nobody rated — folded the
		// same way by Band, because unknown is not harmless.
		{windows.Medium, rated("medium")},
	}

	// Written in slices of the identifier range rather than as one statement
	// per band. SQLite is held to a single connection on purpose — it has one
	// writer, and more connections add contention rather than concurrency — so
	// a statement rewriting four hundred thousand rows is not merely slow, it
	// is the whole process answering nothing until it finishes. Measured at
	// nineteen seconds, which is the outage this project already diagnosed
	// once. A slice at a time takes the same total and gives the connection
	// back between them.
	var highest int64
	if err := s.db.NewSelect().Model((*Finding)(nil)).
		ColumnExpr("COALESCE(MAX(id), 0)").Scan(ctx, &highest); err != nil {
		return 0, fmt.Errorf("read how far the findings run: %w", err)
	}

	changed := 0
	for _, at := range opened {
		for _, each := range bands {
			due := at.Add(each.window)
			for from := int64(0); from <= highest; from += recomputeSlice {
				query := s.db.NewUpdate().
					Model((*Finding)(nil)).
					Set("due_at = ?", due).
					Where("id > ?", from).
					Where("id <= ?", from+recomputeSlice).
					Where("opened_at = ?", at).
					Where("closed_at IS NULL")
				result, err := each.where(query).Exec(ctx)
				if err != nil {
					return changed, fmt.Errorf("rewrite deadlines: %w", err)
				}
				if n, err := result.RowsAffected(); err == nil {
					changed += int(n)
				}
				// Cancellation is honored between slices rather than only at
				// the end, so shutting down during a rewrite stops promptly
				// and leaves the rest for the next scan or the next edit.
				if err := ctx.Err(); err != nil {
					return changed, err
				}
			}
		}
	}

	// And then take the deadline away from everything below the line.
	//
	// Done as a pass afterwards rather than folded into the bands above,
	// because the two say different things and reading them together is
	// how one quietly becomes a condition of the other: the bands say how
	// long something has, and this says that some things are not on a
	// clock at all .
	cleared, err := s.clearBelowFloor(ctx)
	if err != nil {
		return changed, err
	}

	// And from everything on a release that has gone out of support.
	//
	// A second pass for the same reason as the first: the bands say how
	// long something has, the line says some things are not work, and this
	// says some *releases* are not work. Folding any of the three into the
	// others is how one quietly becomes a condition of another.
	retired, err := s.clearPastEndOfLife(ctx)
	if err != nil {
		return changed + cleared, err
	}

	// And from everything in a release that was built once.
	//
	// A third pass for the same reason as the second, and it says the most
	// fundamental of the three: a tag is what somebody received, so no work
	// will land there whatever the date says. A supported tag is as unfixable
	// as a retired one, and real deployments accumulate tags while branches do
	// not — so a deadline on every one of them fills every overdue figure with
	// work nobody could ever have done.
	fixed, err := s.clearOnTags(ctx)
	if err != nil {
		return changed + cleared + retired, err
	}
	return changed + cleared + retired + fixed, nil
}

// clearOnTags removes the deadline from open findings in releases that were
// built once.
//
// Like end-of-life and unlike the line, this takes the deadline away from a
// known-exploited finding too. A line is a claim about how bad something has to
// be before it is worth an afternoon, and exploitation answers that; a tag not
// moving is not an opinion about the finding at all. The finding is still
// recorded, still counted and still reportable — what ends is the clock.
func (s *Store) clearOnTags(ctx context.Context) (int, error) {
	tags, err := catalog.NewStore(s.db).TagStreams(ctx)
	if err != nil {
		return 0, err
	}
	if len(tags) == 0 {
		return 0, nil
	}
	cleared := 0
	err = database.IDsInBatches(ctx, tags, func(ctx context.Context, batch []int64) error {
		result, err := s.db.NewUpdate().
			Model((*Finding)(nil)).
			Set("due_at = NULL").
			Where("closed_at IS NULL").
			Where("due_at IS NOT NULL").
			Where(`target_id IN (SELECT tg.id FROM "target" AS tg
				WHERE tg.stream_id IN (?))`, bun.List(batch)).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("take the deadline off what cannot change: %w", err)
		}
		if n, err := result.RowsAffected(); err == nil {
			cleared += int(n)
		}
		return nil
	})
	return cleared, err
}

// clearPastEndOfLife removes the deadline from open findings on releases that
// have gone out of support.
//
// Unlike the line, this one takes the deadline away from a known-exploited
// finding too. A line is a claim about how bad something has to be before it
// is worth an afternoon, and exploitation answers that; end-of-life is a
// statement that nothing on this release will be fixed at all, which no
// property of a finding argues with. The finding is still recorded, still
// counted and still reportable — what ends is the clock.
func (s *Store) clearPastEndOfLife(ctx context.Context) (int, error) {
	past, err := catalog.NewStore(s.db).StreamsPastEndOfLife(ctx, s.now().UTC())
	if err != nil {
		return 0, err
	}
	if len(past) == 0 {
		return 0, nil
	}

	cleared := 0
	err = database.IDsInBatches(ctx, past, func(ctx context.Context, batch []int64) error {
		result, err := s.db.NewUpdate().
			Model((*Finding)(nil)).
			Set("due_at = NULL").
			Where("closed_at IS NULL").
			Where("due_at IS NOT NULL").
			Where(`target_id IN (SELECT tg.id FROM "target" AS tg
				WHERE tg.stream_id IN (?))`, bun.List(batch)).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("take the deadline off what is out of support: %w", err)
		}
		if n, err := result.RowsAffected(); err == nil {
			cleared += int(n)
		}
		return nil
	})
	return cleared, err
}

// clearBelowFloor removes the deadline from open findings their product does
// not consider worth triaging.
func (s *Store) clearBelowFloor(ctx context.Context) (int, error) {
	var products []int64
	err := s.db.NewSelect().
		TableExpr("product AS p").
		ColumnExpr("p.id").
		Scan(ctx, &products)
	if err != nil {
		return 0, fmt.Errorf("read which products there are: %w", err)
	}

	cleared := 0
	for _, productID := range products {
		floor, err := FloorFor(ctx, s.db, productID)
		if err != nil {
			return cleared, err
		}
		words := floor.admits()
		if len(words) == 0 {
			continue
		}
		// Everything this product holds that the line does not admit, and is
		// not known-exploited — being exploited is a fact about the world
		// rather than a rating, and no line sets it aside.
		result, err := s.db.NewUpdate().
			Model((*Finding)(nil)).
			Set("due_at = NULL").
			Where("closed_at IS NULL").
			Where("due_at IS NOT NULL").
			Where("urgency_exploited = ?", false).
			Where(`target_id IN (SELECT tg.id FROM "target" AS tg
				JOIN "stream" AS st ON st.id = tg.stream_id
				WHERE st.product_id = ?)`, productID).
			Where(`vulnerability_id NOT IN (SELECT id FROM "vulnerability" AS v
				WHERE `+BandExpr+` IN (?))`, bun.List(words)).
			Exec(ctx)
		if err != nil {
			return cleared, fmt.Errorf("take the deadline off what is below the line: %w", err)
		}
		if n, err := result.RowsAffected(); err == nil {
			cleared += int(n)
		}
	}
	return cleared, nil
}

// recomputeSlice is how many identifiers one rewriting statement covers.
//
// Large enough that the statement count stays small, small enough that no one
// of them holds the connection long. Twenty thousand rows is well under a
// second on every engine here.
const recomputeSlice = 20_000
