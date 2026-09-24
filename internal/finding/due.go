// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"context"
	"fmt"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/rating"
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

// DefaultOwnWindows are the shipped numbers for a flaw in our own product. Longer
// at every step than DefaultWindows, because the fix has to be developed rather
// than taken from upstream.
func DefaultOwnWindows() Windows {
	const day = 24 * time.Hour
	return Windows{
		Exploited: 7 * day, Critical: 30 * day, High: 90 * day,
		Medium: 180 * day, Low: 365 * day,
	}
}

// LoadOwnWindows reads how long a flaw recorded in our own product may stay
// open, by how urgent it is.
func LoadOwnWindows(ctx context.Context, db bun.IDB) (Windows, error) {
	return loadWindows(ctx, db, DefaultOwnWindows(), [5]string{
		setting.OwnDueExploited, setting.OwnDueCritical, setting.OwnDueHigh,
		setting.OwnDueMedium, setting.OwnDueLow,
	})
}

// LoadWindows reads how long a finding may stay open, by how urgent it is.
//
// Read here rather than by the caller because ingest needs the same answer as
// the screen does: a deadline is computed once, when a finding is first seen ,
// so the two have to agree about what the policy says or a finding would be
// stored with one deadline and read against another.
func LoadWindows(ctx context.Context, db bun.IDB) (Windows, error) {
	return loadWindows(ctx, db, DefaultWindows(), [5]string{
		setting.DueExploited, setting.DueCritical, setting.DueHigh,
		setting.DueMedium, setting.DueLow,
	})
}

// loadWindows reads one set of windows, named exploited to low, over its
// shipped numbers.
func loadWindows(ctx context.Context, db bun.IDB, windows Windows,
	names [5]string) (Windows, error) {

	settings := setting.NewStore(db)
	for i, at := range []*time.Duration{
		&windows.Exploited, &windows.Critical, &windows.High,
		&windows.Medium, &windows.Low,
	} {
		held, err := settings.Duration(ctx, names[i], *at)
		if err != nil {
			return Windows{}, err
		}
		*at = held
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

// Closable reports whether anything upstream would close a finding in this
// state, which is what makes a deadline on it meetable.
//
// A deadline nobody can meet is not a deadline. Where upstream has released
// nothing, and where upstream has declined, there is no version to take: the
// clock runs and the only thing that can stop it is a person recording a
// judgment, which is the one act the deadline exists to ask for and cannot be
// the answer to. It is the statement three other rules here already make from
// other directions — a tag that cannot change, a build past its end of life,
// and an issue below the triage line all carry no deadline for the same reason.
//
// A scanner that did not answer is not upstream saying no. Reading silence
// as "no fix exists" is a claim about the world made out of a gap in a report,
// and it is the direction that loses a deadline somebody could have met. So an
// unstated state stays on the clock.
func Closable(state FixState) bool {
	switch state {
	case NoFix, WontFix:
		return false
	default:
		return true
	}
}

// Clocked is whether a finding in this state carries a deadline at all.
//
// Upstream declining is the one answer exploitation overrides. A fix that has
// not arrived may arrive tomorrow, and a deadline set against it could only be
// met by waiting; a refusal will never be reversed, and on an issue somebody is
// using that leaves work only this deployment can do — patching the package
// itself, replacing it, or recording what stands in the way. A refusal on an
// issue nobody is using stays off the clock, since otherwise it is red for
// ever for a reason nothing here can act on.
//
// Exploited is either signal: the world's, or a record that this product was
// attacked.
func Clocked(state FixState, exploited bool) bool {
	return Closable(state) || (state == WontFix && exploited)
}

// Deadline is when a finding in this state has to be answered by, or nothing
// where it carries no clock (Clocked).
//
// Counted from the latest of the three moments that start the clock, never
// from the earliest and never from now:
//
//   - When we first saw it. A fix that already existed when the finding opened
//     leaves this the only answer, which is the ordinary case.
//   - When exploitation was learned. An issue that becomes exploited after six
//     months would otherwise land three days before anybody knew.
//   - When the fix became available. Seeing a flaw before upstream has released
//     anything and counting from the sighting sets a deadline against a version
//     that did not exist, which is the common case for a distribution-heavy
//     inventory and the one this was wrong about. Bounded by observedAt, the
//     moment the caller is reasoning at, because that one is a feed's and the
//     other two are ours.
//
// All three are facts about moments that have passed, so recounting this
// answers the same thing every time — which is what keeps a deadline from
// restarting nightly and never arriving.
func Deadline(state FixState, exploited bool, openedAt, observedAt time.Time,
	exploitedLearnedAt, fixedAt *time.Time, window time.Duration) *time.Time {

	if !Clocked(state, exploited) {
		return nil
	}
	from := openedAt
	// A fix cannot have arrived after the moment we saw that it had, and a
	// date saying otherwise is a feed's, parsed and never checked. One entry
	// dated two centuries out would carry the deadline with it, and the
	// finding would leave the overdue list and the compliance rate for as long
	// as it stayed open — which is the silent disappearance this rule exists
	// to stop, arriving through the field that implements it.
	//
	// Taken as an argument rather than read from a clock, so that this answers
	// the same thing every time it is asked about the same finding.
	if fixedAt != nil && fixedAt.After(observedAt) {
		fixedAt = nil
	}
	for _, later := range []*time.Time{exploitedLearnedAt, fixedAt} {
		if later != nil && later.After(from) {
			from = *later
		}
	}
	due := from.Add(window)
	return &due
}

// Late is a finding whose time is running out with nobody having decided about
// it.
type Late struct {
	Vulnerability string `bun:"vulnerability"`
	Component     string `bun:"component"`
	// Version is which one, because a build ships a name at more than one
	// version often enough that a link without it cannot be resolved — and a
	// screen offering a link that dead-ends is worse than one offering none.
	Version     string `bun:"version"`
	Severity    string `bun:"severity"`
	Exploited   bool   `bun:"exploited"`
	Product     string `bun:"product"`
	ProductName string `bun:"product_name"`
	Stream      string `bun:"stream"`
	StreamName  string `bun:"stream_name"`
	Variant     string `bun:"variant"`
	VariantName string `bun:"variant_name"`
	AssignedTo  *int64 `bun:"assigned_to"`
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
	// Total is how many rows the question has in all, counted after the
	// grouping and before the limit. It rides on the page rather than being
	// asked for separately, and it is read off the first row and discarded.
	Total int `bun:"total"`
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
	return `EXISTS (SELECT 1 FROM "decision" AS "de"
		JOIN "claim" AS "cl" ON cl.id = de.claim_id
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
// A claim waiting for a second person is not standing. It suppresses
// nothing, answers for nothing and covers nothing in the meantime — otherwise
// the review queue is decorative and one person dismisses a finding on their
// own, which is the whole thing a second pair of eyes exists to prevent.
//
// And not one that was sent back. Only a claim needing nobody can be both
// sent back and standing, and it went on suppressing the finding while the
// record said it had been returned — with the notice to its author saying, in
// those words, that it applied to nothing until it was revised. Sending back
// is not a state of its own, but it is a statement that nobody is relying on
// this yet.
//
// Said in one place because it was spelled several ways, and two of those
// tested only that a claim existed. A proposal nobody had agreed to therefore
// counted as an answer: it took a finding out of the overdue figure and it
// raised a notice saying a deferral was about to end when nothing was in
// force. The sent-back half arrived the same way and landed on one caller's
// own copy, which left the other six reading a returned claim as standing.
// Pair it with whatever says the claim still applies — `live_key IS NOT NULL`
// where any version will do, KeyMatches where the versions matter.
func InForce() (string, []any) {
	return "(de.state = ? OR (de.state = ? AND de.needs_approval = ? AND de.sent_back_at IS NULL))",
		[]any{"approved", "proposed", false}
}

// RunningOut reports findings whose deadline is within this many days and
// which nobody has decided about, most pressing first.
//
// Undecided only. A deadline that has been answered is not a deadline
// running out: a dismissal takes a finding off the clock, because the claim is
// that it will not be fixed, and a deferral replaces the deadline with its own
// date. What is left is time passing with nothing said, which is the only part
// worth interrupting somebody about.
//
// One row per issue at a component, not per place. A kernel flaw sitting
// at sixty places is one thing somebody has to answer, and sixty rows of it is
// a list with one entry in it.
//
// The deadline is read rather than derived. Worked out per request it is a
// pass over every open finding per urgency band — each band allows a different
// number of days, and the window has to narrow the rows before they are read
// rather than after — measured at about eight seconds over 441,108 findings.
// Stored at ingest, this is one range over an index.
//
// A finding with no deadline is left out. That is a row recorded before the
// deadline was stored, and it will have one the next time a scan reopens it —
// which is honestly "not known yet" rather than "not due", and either way not
// something to interrupt anybody about.
func (s *Store) RunningOut(ctx context.Context, subject access.Subject, scope Scope,
	within time.Duration, limit int) ([]Late, int, error) {

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
	within time.Duration, limit, offset int) ([]Late, int, error) {

	// Not merely empty: "here is nothing" and "you cannot ask" are
	// different statements, and this is the second. A person holding
	// nothing is the first, and is answered below.
	if subject.Kind != access.Person {
		return nil, 0, access.Denied("read what is running out of time")
	}
	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, 0, nil
	}
	limit = database.AList.Of(limit)

	standing, args := OffTheClock("st.product_id", s.now())
	// The narrowing, on its own, so the page and the count ask the same
	// question of the same joins. Two spellings of one predicate is how a
	// total stops describing the list it sits under.
	narrow := func(q *bun.SelectQuery) *bun.SelectQuery {
		q = q.TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			Join(`JOIN "variant" AS "va" ON va.id = tg.variant_id`).
			Join(`JOIN "product" AS "p" ON p.id = st.product_id`).
			Join(`JOIN "vulnerability" AS "v" ON v.id = f.vulnerability_id`).
			// Each row's own product rates its own findings. The list spans
			// products, so the join reads the stream's product per row rather
			// than binding one.
			Join(rating.For(rating.OnStream)).
			Join(`JOIN "component" AS "c" ON c.id = f.component_id`).
			// The consumer, for the versions a decision is keyed on.
			Join(`LEFT JOIN "component" AS "uc" ON uc.id = f.consumer_id`).
			Where("f.closed_at IS NULL").
			Where("f.due_at IS NOT NULL").
			Where("f.due_at <= ?", s.now().UTC().Add(within)).
			// Nothing the build already argued away, and nothing a decision
			// takes off the clock. Not merely a claim: a proposal waiting for
			// a second person suppresses nothing, and it took findings off
			// this list for as long as it sat in the queue — a quarter, on
			// one — while the same findings still counted as overdue against
			// whoever held them.
			Where("f.suppressed_by IS NULL").
			Where("NOT "+standing, args...)
		if !all {
			q = q.Where("st.product_id IN (?)", bun.List(products))
		}
		return scope.Narrow(onlyVisible(q, subject, products, all))
	}
	// The grouping, which decides what one row is: an issue at a component in
	// one build, however many places it sits at there.
	const grouping = "v.identifier, c.name, c.version, f.urgency_exploited, p.name, p.display_name, " +
		"st.name, st.display_name, va.name, va.display_name, f.target_id, f.vulnerability_id, f.component_id"

	query := narrow(s.db.NewSelect()).
		ColumnExpr(`v.identifier AS "vulnerability"`).
		ColumnExpr(`c.name AS "component"`).
		ColumnExpr(`c.version AS "version"`).
		ColumnExpr(`MIN(` + rating.EffectiveExpr + `) AS "severity"`).
		ColumnExpr(`f.urgency_exploited AS "exploited"`).
		ColumnExpr(`p.name AS "product"`).
		ColumnExpr(`COALESCE(NULLIF(p.display_name, ''), p.name) AS "product_name"`).
		ColumnExpr(`st.name AS "stream"`).
		ColumnExpr(`st.display_name AS "stream_name"`).
		ColumnExpr(`va.name AS "variant"`).
		ColumnExpr(`va.display_name AS "variant_name"`).
		// The earliest of the places this row covers, because that is the one
		// that makes the whole group late.
		ColumnExpr(`MIN(f.due_at) AS "due"`).
		ColumnExpr(`COUNT(*) AS "places"`).
		// Named only where every place has the same person. Reporting one of
		// several would tell somebody a finding is being dealt with when most
		// of it is not.
		ColumnExpr(`MIN(f.assigned_to) AS "assigned_to"`).
		ColumnExpr(`MAX(f.assigned_to) AS "assigned_high"`).
		ColumnExpr(`COUNT(f.assigned_to) AS "assigned_count"`).
		// The number of groups the question has, counted over the grouped
		// result and before the limit. A screen that counted its own page said
		// two hundred over a list of four hundred and sixty-two.
		ColumnExpr(`COUNT(*) OVER () AS "total"`).
		GroupExpr(grouping).
		// The build is in the order as well as in the grouping. Without it two
		// rows identical down to the component name order arbitrarily, and an
		// arbitrary order between pages is how a paged read repeats one row
		// and skips another.
		OrderExpr("due, v.identifier, c.name, f.target_id").
		Limit(limit).Offset(offset)

	var late []Late
	if err := query.Scan(ctx, &late); err != nil {
		return nil, 0, fmt.Errorf("read what is running out of time: %w", err)
	}
	for i := range late {
		if late[i].AssignedCount != late[i].Places || late[i].AssignedTo == nil ||
			late[i].AssignedHigh == nil || *late[i].AssignedTo != *late[i].AssignedHigh {
			late[i].AssignedTo = nil
		}
	}
	// A page past the end of the answer carries no row to read the count off.
	// The groups are counted on their own in that case, which is the one call
	// that costs a second statement.
	total := 0
	if len(late) > 0 {
		total = late[0].Total
	} else if offset > 0 {
		// The derived table is named "grouped" and quoted: GROUPS names a
		// window frame type on MySQL 8, so the obvious alias is a syntax
		// error on one engine and fine on the other three.
		count, err := s.db.NewSelect().
			TableExpr(`(?) AS "grouped"`, narrow(s.db.NewSelect()).
				ColumnExpr("f.vulnerability_id").
				GroupExpr(grouping)).
			Count(ctx)
		if err != nil {
			return nil, 0, fmt.Errorf("count what is running out of time: %w", err)
		}
		total = count
	}
	return late, total, nil
}

// whenOpened is the deadline each of these moments produces, as one
// expression, so that a statement can carry a set of them rather than one.
//
// The arithmetic stays in Go, which is what keeps it portable — no engine
// agrees on how to add days to a timestamp — and the statement writes
// constants, which is what it did when it carried one moment.
//
// The caller types the result. A bound value arrives untyped, so a CASE
// choosing between several of them is a string as far as the engine can tell,
// and one of the four refuses to write a string into a timestamp column.
func whenOpened(column string, moments []time.Time, window time.Duration) (string, []any) {
	said := "CASE " + column
	args := make([]any, 0, len(moments)*2)
	for _, at := range moments {
		said += " WHEN ? THEN ?"
		args = append(args, at, at.Add(window))
	}
	return said + " END", args
}

// Recompute rewrites the deadline on every open finding.
//
// The windows are the ones a scanned finding is held to. A flaw recorded in our
// own product is recounted against its own, read from the settings.
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
// it is a handful of statements rather than hundreds of thousands: the
// identifier range is walked once and the moments ride inside the statement.
func (s *Store) Recompute(ctx context.Context, windows Windows) (int, error) {
	// A product at a time, because severity sets the deadline and a rating
	// belongs to a product: the same issue rated critical in one product and
	// left at the published low in another is two deadlines, and one statement
	// spanning both would write whichever the join happened to reach.
	//
	// The product is also what the moments below are read for. A scan run
	// belongs to one build and a build to one product, so the moments a
	// product's findings opened at are its own — the loop costs one pass over
	// the same rows rather than a pass per product over all of them.
	products, err := s.everyProduct(ctx)
	if err != nil {
		return 0, err
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
	for _, productID := range products {
		// The flaws recorded here, on their own windows and counted from
		// their first rating.
		own, err := recountOwn(ctx, s.db, productID, nil, s.now())
		changed += own
		if err != nil {
			return changed, err
		}

		// The distinct moments something opened in this product, off the
		// findings themselves. This walked the runs and joined back for the
		// timestamp, which asked the question in terms of the thing that
		// usually answers it rather than the thing that always does: a
		// finding a person opened has no run, so its deadline was never
		// rewritten when the policy changed.
		//
		// The same cardinality either way — every finding a run opened
		// carries that run's start — so this is one table fewer rather than
		// more rows.
		var opened []time.Time
		err = s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			ColumnExpr("f.opened_at").
			Where("f.closed_at IS NULL").
			Where("st.product_id = ?", productID).
			GroupExpr("f.opened_at").
			Scan(ctx, &opened)
		if err != nil {
			return changed, fmt.Errorf("read when what is still open was opened: %w", err)
		}
		if len(opened) == 0 {
			continue
		}

		// Bands as predicates on the rating, in the same order For() decides
		// them, so a finding lands in exactly one. The rating compared is
		// this product's where it has made one, which is what the bound
		// identifier in the join carries.
		type band struct {
			window time.Duration
			where  func(*bun.UpdateQuery) *bun.UpdateQuery
		}
		rated := func(words ...string) func(*bun.UpdateQuery) *bun.UpdateQuery {
			return func(q *bun.UpdateQuery) *bun.UpdateQuery {
				return q.Where("urgency_exploited = ?", false).
					Where(`vulnerability_id IN (SELECT v.id FROM "vulnerability" AS "v" `+
						rating.Here+` WHERE `+rating.BandExpr+` IN (?))`,
						productID, bun.List(words))
			}
		}
		bands := []band{
			// Exploited with nothing recorded to count from. The opening is
			// what is left, which is what a row marked exploited before the
			// moment was recorded falls back to; the rest are rewritten in a
			// pass of their own below, keyed on the learning.
			{windows.Exploited, func(q *bun.UpdateQuery) *bun.UpdateQuery {
				return q.Where("urgency_exploited = ?", true).
					Where("exploited_learned_at IS NULL")
			}},
			{windows.Critical, rated("critical")},
			{windows.High, rated("high")},
			{windows.Low, rated("low")},
			// Everything else: medium, and anything nobody rated — folded the
			// same way by Band, because unknown is not harmless.
			{windows.Medium, rated("medium")},
		}

		// The slice is the outer loop, and the moments are carried into the
		// statement rather than looped over.
		//
		// The other way round, the statement count was moments × bands ×
		// slices: a product scanned nightly for a year holds about 1,800
		// distinct moments, so five builds and twenty-one slices came to
		// 189,000 statements — against this function's own note promising a
		// handful — almost all of them matching nothing, because one moment
		// lives in one slice. The half-hour the caller allows expired partway
		// and left the estate split between the old policy and the new with
		// nothing to retry it.
		for from := int64(0); from <= highest; from += recomputeSlice {
			for _, each := range bands {
				for start := 0; start < len(opened); start += database.BatchSize {
					chunk := opened[start:min(start+database.BatchSize, len(opened))]
					said, args := whenOpened("opened_at", chunk, each.window)
					query := s.db.NewUpdate().
						Model((*Finding)(nil)).
						Set("due_at = "+database.AsTimestamp(s.db, said), args...).
						Where("id > ?", from).
						Where("id <= ?", from+recomputeSlice).
						Where("opened_at IN (?)", bun.List(chunk)).
						Where("closed_at IS NULL").
						Where("kind <> ?", Entered).
						Where(inThisProduct, productID)
					result, err := each.where(query).Exec(ctx)
					if err != nil {
						return changed, fmt.Errorf("rewrite deadlines: %w", err)
					}
					n, err := database.Affected(result)
					if err != nil {
						return changed, fmt.Errorf("rewrite deadlines: %w", err)
					}
					changed += int(n)
					// Cancellation is honored between slices rather than only
					// at the end, so shutting down during a rewrite stops
					// promptly and leaves the rest for the next scan or the
					// next edit.
					if err := ctx.Err(); err != nil {
						return changed, err
					}
				}
			}
		}

		// And the exploited rows, counted from when exploitation was learned
		// rather than from when the finding opened. Six months after a
		// finding opens, a few days from the learning is a deadline somebody
		// can meet and a few days from the opening is one already in the past.
		var learned []time.Time
		err = s.db.NewSelect().
			TableExpr(`"finding" AS "f"`).
			Join(`JOIN "target" AS "tg" ON tg.id = f.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			ColumnExpr("f.exploited_learned_at").
			Where("f.closed_at IS NULL").
			Where("f.urgency_exploited = ?", true).
			Where("f.exploited_learned_at IS NOT NULL").
			Where("st.product_id = ?", productID).
			GroupExpr("f.exploited_learned_at").
			Scan(ctx, &learned)
		if err != nil {
			return changed, fmt.Errorf("read when exploitation was learned: %w", err)
		}
		for from := int64(0); from <= highest; from += recomputeSlice {
			for start := 0; start < len(learned); start += database.BatchSize {
				chunk := learned[start:min(start+database.BatchSize, len(learned))]
				said, args := whenOpened("exploited_learned_at", chunk, windows.Exploited)
				result, err := s.db.NewUpdate().
					Model((*Finding)(nil)).
					Set("due_at = "+database.AsTimestamp(s.db, said), args...).
					Where("id > ?", from).
					Where("id <= ?", from+recomputeSlice).
					Where("exploited_learned_at IN (?)", bun.List(chunk)).
					Where("urgency_exploited = ?", true).
					Where("closed_at IS NULL").
					Where("kind <> ?", Entered).
					Where(inThisProduct, productID).Exec(ctx)
				if err != nil {
					return changed, fmt.Errorf("rewrite deadlines: %w", err)
				}
				n, err := database.Affected(result)
				if err != nil {
					return changed, fmt.Errorf("rewrite deadlines: %w", err)
				}
				changed += int(n)
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

	// And from everything upstream has released no fix for, or has declined
	// to fix.
	//
	// A fourth pass, for the reason there are three already: each says some
	// things are not on a clock, and each says it about something different —
	// the rating, the release's support, the release's nature, and this one
	// about what there is to take. Without it, an administrator saving a
	// remediation window hands back every deadline the scan path took off,
	// and the recount that exists to keep the policy and the rows agreeing is
	// what puts them back out of step.
	nothing, err := s.clearNothingToTake(ctx)
	if err != nil {
		return changed + cleared + retired + fixed, err
	}
	return changed + cleared + retired + fixed + nothing, nil
}

// clearNothingToTake removes the deadline from open findings that carry no
// clock: upstream has released no fix, or has declined to fix an issue nobody
// is exploiting (Clocked).
//
// Like a tag and unlike the line, a missing fix reaches a known-exploited
// finding too. Being exploited says how long there is; it says nothing about
// there being a version to take, and a deadline that no upgrade could meet is
// not made meetable by the flaw being urgent. A refusal is the exception,
// because on an exploited issue it leaves work only this deployment can do.
func (s *Store) clearNothingToTake(ctx context.Context) (int, error) {
	result, err := s.db.NewUpdate().
		Model((*Finding)(nil)).
		Set("due_at = NULL").
		Where("closed_at IS NULL").
		Where("due_at IS NOT NULL").
		WhereGroup(" AND ", func(q *bun.UpdateQuery) *bun.UpdateQuery {
			return q.Where("fix_state = ?", NoFix).
				WhereGroup(" OR ", func(q *bun.UpdateQuery) *bun.UpdateQuery {
					return q.Where("fix_state = ?", WontFix).
						Where("urgency_exploited = ?", false).
						Where("urgency_exploited_here = ?", false)
				})
		}).
		Exec(ctx)
	if err != nil {
		return 0, fmt.Errorf("take the deadline off what has nothing to take: %w", err)
	}
	gone, err := database.Affected(result)
	if err != nil {
		return 0, fmt.Errorf("take the deadline off what has nothing to take: %w", err)
	}
	return int(gone), nil
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
	return s.clearClockOn(ctx, tags, "what cannot change")
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
	return s.clearClockOn(ctx, past, "what is out of support")
}

// clearClockOn takes the deadline off every open finding in these releases.
//
// The two passes above differ in which releases they are about and in what a
// failure says; the write is one statement, and it was written twice. They
// stay two passes, because Recompute argues for that explicitly: a release can
// be both a tag and out of support, and one pass merging the lists would
// report one number where the receipt says which rule ended the clock.
//
// The count is what the database says it matched, and a failure to read it is
// a failure: a number quietly short is a receipt saying less work was done
// than was done, which is the shape somebody investigates for an afternoon.
func (s *Store) clearClockOn(ctx context.Context, streams []int64, why string) (int, error) {
	if len(streams) == 0 {
		return 0, nil
	}
	cleared := 0
	err := database.IDsInBatches(ctx, streams, func(ctx context.Context, batch []int64) error {
		result, err := s.db.NewUpdate().
			Model((*Finding)(nil)).
			Set("due_at = NULL").
			Where("closed_at IS NULL").
			Where("due_at IS NOT NULL").
			Where(`target_id IN (SELECT tg.id FROM "target" AS "tg"
				WHERE tg.stream_id IN (?))`, bun.List(batch)).
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("take the deadline off %s: %w", why, err)
		}
		n, err := database.Affected(result)
		if err != nil {
			return fmt.Errorf("take the deadline off %s: %w", why, err)
		}
		cleared += int(n)
		return nil
	})
	return cleared, err
}

// clearBelowFloor removes the deadline from open findings their product does
// not consider worth triaging.
func (s *Store) clearBelowFloor(ctx context.Context) (int, error) {
	products, err := s.everyProduct(ctx)
	if err != nil {
		return 0, err
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
			Where(inThisProduct, productID).
			Where(`vulnerability_id NOT IN (SELECT v.id FROM "vulnerability" AS "v" `+
				rating.Here+` WHERE `+rating.BandExpr+` IN (?))`, productID, bun.List(words)).
			Exec(ctx)
		if err != nil {
			return cleared, fmt.Errorf("take the deadline off what is below the line: %w", err)
		}
		n, err := database.Affected(result)
		if err != nil {
			return cleared, fmt.Errorf("take the deadline off what is below the line: %w", err)
		}
		cleared += int(n)
	}
	return cleared, nil
}

// recomputeSlice is how many identifiers one rewriting statement covers.
//
// Large enough that the statement count stays small, small enough that no one
// of them holds the connection long. Twenty thousand rows is well under a
// second on every engine here.
const recomputeSlice = 20_000

// everyProduct is the identifiers of every product, in a stable order.
//
// Both passes that rewrite deadlines walk products, because both compare a
// rating and a rating belongs to one. Read through one place so the two cannot
// come to disagree about what the set is.
func (s *Store) everyProduct(ctx context.Context) ([]int64, error) {
	var products []int64
	if err := s.db.NewSelect().
		TableExpr(`"product" AS "p"`).
		ColumnExpr("p.id").
		OrderExpr("p.id").
		Scan(ctx, &products); err != nil {
		return nil, fmt.Errorf("read which products there are: %w", err)
	}
	return products, nil
}
