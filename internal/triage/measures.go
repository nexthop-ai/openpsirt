package triage

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// Measures are the numbers about how this deployment is working, as opposed to
// what it holds.
//
// **Every one of them is already in the record and none was ever added up.**
// How long a finding waits before anybody says anything, how long a claim waits
// for a second person, and how much each person actually got through: three
// questions a manager asks constantly, and the answer to all three was a screen
// somebody counted rows on.
//
// **The arithmetic happens here rather than in SQL.** Subtracting two moments
// is spelled four ways across the engines this runs on — `julianday`, `EXTRACT
// (EPOCH ...)`, `TIMESTAMPDIFF` — and so is the percentile. Reading the two
// timestamps and subtracting them in Go is one spelling that behaves the same
// everywhere, and the bound below is what keeps that honest.
//
// **Bounded, and it says so.** A window of any length on a busy deployment is
// more rows than a figure needs, so a fixed ceiling is read and the answer
// reports how many it was measured over. A number quoted from a sample that
// does not say it is a sample is the one thing a figure like this must not be.
type Measures struct {
	// Since and Until are the window every figure below was measured over.
	Since time.Time
	Until time.Time
	// ToDecide is how long a finding sat before anybody proposed anything
	// about it, per severity band. Answering the question the backlog cannot:
	// a queue of the same size is a different place depending on whether
	// things sit in it for a day or a quarter.
	ToDecide []Spread
	// ToAgree is how long a claim waited for a second person, per severity.
	// The other half of the same story — a fast decision that waits three
	// weeks for agreement is not a fast decision.
	ToAgree []Spread
	// Throughput is what each person got through in the window.
	Throughput []Worked
	// SentBack is how many claims an approver asked more of in the window.
	//
	// Counted for the deployment rather than per person, because the record
	// does not hold who sent one back — only that it was, and the reason,
	// which travels as a comment. Attributing it by finding the comment
	// written at that moment would be a guess presented as a figure, and the
	// deployment-wide number is the one somebody actually asks about: how much
	// of what was proposed came back.
	SentBack int
	// Sampled says the figures were measured over this many observations, and
	// Capped says the ceiling was reached — so a reader knows whether they are
	// looking at the window or at the most recent part of it.
	Sampled int
	Capped  bool
}

// Spread is a set of durations said in the three ways worth saying: how many,
// the middle, and the tail.
//
// The average alone hides the case that matters. Ten decisions in a day and one
// in a quarter average to a fortnight, which describes neither — and it is the
// quarter that somebody is asking about.
type Spread struct {
	// Band is the severity these were rated at, or empty for the whole set.
	Band string
	// Count is how many observations, Median the middle one, and P90 the value
	// nine in ten came in under.
	Count  int
	Median time.Duration
	P90    time.Duration
	// Worst is the longest single one, because a tail figure invites the
	// question and a screen that cannot answer it sends somebody to the
	// database.
	Worst time.Duration
}

// Worked is what one person got through.
//
// Counted per person because that is who does the work, and narrowed like
// every other list here: a count is a disclosure, and a figure about somebody
// else's work in a product this reader holds nothing on is one they should not
// have.
type Worked struct {
	Person string
	// Proposed is claims they made, Approved ones they agreed to, and
	// Withdrawn ones they took back. There is no send-back count here: the
	// record holds that a claim was sent back and not by whom.
	Proposed  int
	Approved  int
	Withdrawn int
}

// measuredAtMost is how many observations one figure is worked out from.
//
// The most recent ones in the window rather than a sample across it, because
// the recent ones are what somebody is asking about — "are we getting faster"
// is a question about now. Stated in the answer, so a figure taken from part
// of a window is never quoted as if it were the whole.
const measuredAtMost = 5000

// Measure works out the figures about how triage is going in a window.
func (s *Store) Measure(ctx context.Context, subject access.Subject,
	since, until time.Time) (Measures, error) {

	if until.IsZero() {
		until = s.now().UTC()
	}
	if since.IsZero() {
		since = until.AddDate(0, 0, -90)
	}
	out := Measures{Since: since, Until: until}

	// The two spans, read as their endpoints. One query rather than two,
	// because they are the same rows read for two different subtractions and
	// asking twice is two chances for the two answers to be about different
	// populations.
	var rows []struct {
		Severity   string     `bun:"severity"`
		OpenedAt   time.Time  `bun:"opened_at"`
		ProposedAt time.Time  `bun:"proposed_at"`
		ApprovedAt *time.Time `bun:"approved_at"`
	}
	q := s.db.NewSelect().
		TableExpr("decision AS de").
		// The finding this was a claim about, for when it was first seen and
		// how it was rated. Joined on the same three columns a decision is
		// matched by, and left-joined: a claim about a place that has since
		// closed still happened, and dropping it would make the figures
		// flatter exactly where work was finished.
		Join(`LEFT JOIN finding AS f ON f.vulnerability_id = de.vulnerability_id
			AND f.place_identity = de.place_identity`).
		Join("LEFT JOIN vulnerability AS v ON v.id = de.vulnerability_id").
		Join(`LEFT JOIN claim_approval AS da ON da.claim_id = de.claim_id
			AND da.withdrawn_at IS NULL`).
		ColumnExpr("COALESCE(v.severity, '') AS severity").
		ColumnExpr("MIN(f.opened_at) AS opened_at").
		ColumnExpr("de.proposed_at AS proposed_at").
		ColumnExpr("MIN(da.approved_at) AS approved_at").
		Where("de.proposed_at >= ?", since).
		Where("de.proposed_at < ?", until).
		GroupExpr("de.id, de.proposed_at, COALESCE(v.severity, '')").
		OrderExpr("de.proposed_at DESC").
		Limit(measuredAtMost + 1)
	q = readableBy(q, subject, "de")
	if err := q.Scan(ctx, &rows); err != nil {
		return Measures{}, fmt.Errorf("read how long triage is taking: %w", err)
	}
	if len(rows) > measuredAtMost {
		rows, out.Capped = rows[:measuredAtMost], true
	}
	out.Sampled = len(rows)

	toDecide := map[string][]time.Duration{}
	toAgree := map[string][]time.Duration{}
	for _, row := range rows {
		// Folded through the one place that says which words are real: a
		// scanner's "unknown" and no rating at all are the same state, and
		// two lines for it is two names for one nothing.
		band := finding.BandOf(row.Severity)
		// A decision proposed before the finding was first seen is not a
		// negative wait; it is a row whose finding has since been replaced by
		// a later one at the same place. Dropped rather than clamped, because
		// a zero here would be read as "answered at once".
		if !row.OpenedAt.IsZero() && row.ProposedAt.After(row.OpenedAt) {
			toDecide[band] = append(toDecide[band], row.ProposedAt.Sub(row.OpenedAt))
		}
		if row.ApprovedAt != nil && row.ApprovedAt.After(row.ProposedAt) {
			toAgree[band] = append(toAgree[band], row.ApprovedAt.Sub(row.ProposedAt))
		}
	}
	out.ToDecide = spreads(toDecide)
	out.ToAgree = spreads(toAgree)

	worked, err := s.throughput(ctx, subject, since, until)
	if err != nil {
		return Measures{}, err
	}
	out.Throughput = worked

	// How much came back. Sending a claim back is the approver's other answer
	// and nothing counted it, so a queue that is moving because claims are
	// good and one that is moving because nobody reads them looked alike.
	back := s.db.NewSelect().TableExpr("decision AS de").
		ColumnExpr("COUNT(*) AS number").
		Where("de.sent_back_at IS NOT NULL").
		Where("de.sent_back_at >= ?", since).
		Where("de.sent_back_at < ?", until)
	if err := readableBy(back, subject, "de").Scan(ctx, &out.SentBack); err != nil {
		return Measures{}, fmt.Errorf("read how much came back: %w", err)
	}
	return out, nil
}

// throughput is what each person got through in the window.
//
// Four counts from three tables, keyed on the person rather than joined into
// one statement: a claim proposed, an agreement given, a claim sent back and a
// claim withdrawn are four different rows in three places, and one query
// counting all four would multiply them together.
func (s *Store) throughput(ctx context.Context, subject access.Subject,
	since, until time.Time) ([]Worked, error) {

	by := map[int64]*Worked{}
	forPerson := func(id int64) *Worked {
		if one, held := by[id]; held {
			return one
		}
		one := &Worked{}
		by[id] = one
		return one
	}

	count := func(build func() *bun.SelectQuery, into func(*Worked) *int) error {
		var rows []struct {
			Person int64 `bun:"person"`
			Number int   `bun:"number"`
		}
		if err := build().Scan(ctx, &rows); err != nil {
			return fmt.Errorf("read what each person got through: %w", err)
		}
		for _, row := range rows {
			*into(forPerson(row.Person)) = row.Number
		}
		return nil
	}

	// Proposed and withdrawn are both read off the decision. Withdrawn is
	// dated by the proposal for the same reason the audit is: a claim belongs
	// to the window it was argued in.
	if err := count(func() *bun.SelectQuery {
		q := s.db.NewSelect().TableExpr("decision AS de").
			ColumnExpr("de.proposed_by AS person").
			ColumnExpr("COUNT(*) AS number").
			Where("de.proposed_at >= ?", since).
			Where("de.proposed_at < ?", until).
			GroupExpr("de.proposed_by")
		return readableBy(q, subject, "de")
	}, func(w *Worked) *int { return &w.Proposed }); err != nil {
		return nil, err
	}
	if err := count(func() *bun.SelectQuery {
		q := s.db.NewSelect().TableExpr("decision AS de").
			ColumnExpr("de.proposed_by AS person").
			ColumnExpr("COUNT(*) AS number").
			Where("de.state = ?", Withdrawn).
			Where("de.proposed_at >= ?", since).
			Where("de.proposed_at < ?", until).
			GroupExpr("de.proposed_by")
		return readableBy(q, subject, "de")
	}, func(w *Worked) *int { return &w.Withdrawn }); err != nil {
		return nil, err
	}
	// Agreements are dated by the agreement, which is when that person did the
	// work: an approver's week is the week they approved in.
	if err := count(func() *bun.SelectQuery {
		// Counted distinctly, because the join is one approval to every row of
		// the claim it was given for: an approver agreeing to one argument
		// covering forty-four places did one piece of work, not forty-four.
		q := s.db.NewSelect().TableExpr("claim_approval AS da").
			Join("JOIN decision AS de ON de.claim_id = da.claim_id").
			ColumnExpr("da.approved_by AS person").
			ColumnExpr("COUNT(DISTINCT da.id) AS number").
			Where("da.withdrawn_at IS NULL").
			Where("da.approved_at >= ?", since).
			Where("da.approved_at < ?", until).
			GroupExpr("da.approved_by")
		return readableBy(q, subject, "de")
	}, func(w *Worked) *int { return &w.Approved }); err != nil {
		return nil, err
	}
	ids := make([]int64, 0, len(by))
	for id := range by {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var people []struct {
		ID       int64  `bun:"id"`
		Identity string `bun:"identity"`
	}
	if err := s.db.NewSelect().TableExpr("person AS p").
		ColumnExpr("p.id AS id").ColumnExpr("p.identity AS identity").
		Where("p.id IN (?)", bun.List(ids)).
		Scan(ctx, &people); err != nil {
		return nil, fmt.Errorf("read who did the work: %w", err)
	}
	out := make([]Worked, 0, len(people))
	for _, who := range people {
		one := *by[who.ID]
		one.Person = who.Identity
		out = append(out, one)
	}
	// Most done first, which is the order somebody reads this in.
	sort.Slice(out, func(i, j int) bool {
		left := out[i].Proposed + out[i].Approved
		right := out[j].Proposed + out[j].Approved
		if left != right {
			return left > right
		}
		return out[i].Person < out[j].Person
	})
	return out, nil
}

// spreads turns each band's durations into the three numbers worth saying,
// worst band first — critical above high above medium, and unrated last.
func spreads(by map[string][]time.Duration) []Spread {
	out := make([]Spread, 0, len(by))
	for band, all := range by {
		if len(all) == 0 {
			continue
		}
		sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
		out = append(out, Spread{
			Band: band, Count: len(all),
			Median: nearestRank(all, 0.5), P90: nearestRank(all, 0.9),
			Worst: all[len(all)-1],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		left, right := bandRank(out[i].Band), bandRank(out[j].Band)
		if left != right {
			return left < right
		}
		return out[i].Band < out[j].Band
	})
	return out
}

// nearestRank is the value at a position in a sorted set.
//
// Nearest-rank rather than interpolated because these are waits somebody
// actually had: a p90 of eleven and a half days is a number nothing took, and
// the honest answer is the longest of the nine in ten.
func nearestRank(sorted []time.Duration, part float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted))*part) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// bandRank orders the severity words worst first, the way every other list here
// orders them.
func bandRank(band string) int {
	switch band {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}
