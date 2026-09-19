package currency

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// StaleAfter is how long an answer stands before it is asked again.
//
// A day. The question is whether upstream has released since a flaw was
// disclosed, which is a thing that changes on the order of days, and asking
// every hour would put a deployment's whole component list through four public
// indexes for an answer that had not moved.
const StaleAfter = 24 * time.Hour

// UnknownAfter is how long we leave alone a package the index has never heard
// of.
//
// Much longer, because the answer almost never changes. A component an index
// does not know is a private module, an internal fork, or something vendored
// from a git URL, and none of those becomes published next week. Asking daily
// would put thousands of permanently unanswerable questions at free services
// run by other people, which is how a caller ends up rate-limited and deserves
// to be. A month still notices the rare package that does get published, and
// still recovers from an index that was having a bad day in a way that looked
// like "never heard of it".
const UnknownAfter = 30 * 24 * time.Hour

// mostPerPass bounds one cycle.
//
// A first run against a real image has thousands of components in these
// ecosystems and no answer for any of them. Asking all of them at once is a
// burst at somebody else's index that looks exactly like abuse, so a pass takes
// a slice and the next pass takes the next — a backlog drains over hours, and
// nothing here needs it sooner.
const MostPerPass = 200

// betweenAsks is the pause between one index request and the next.
//
// Deliberate politeness rather than a rate limit we were given: these are free
// public services, and a tool that walks them as fast as it can is the reason
// they end up needing one.
const betweenAsks = 250 * time.Millisecond

// Refresher fills in what upstream has released, for components we build
// ourselves.
type Refresher struct {
	db bun.IDB
	// Index returns the asker for an ecosystem, or nil where there is none.
	// A field rather than a call so a test can answer without a network, which
	// is the only way to test this at all: the real ones are somebody else's
	// service and their answers change.
	Index  func(ecosystem string) Asker
	logger *slog.Logger
	// Pause is how long to wait between one request and the next. A field so a
	// test does not spend a real second being polite to a fake.
	Pause time.Duration
	// Now is the clock, so a test can ask what happens a month from now
	// without waiting a month.
	Now func() time.Time
	// Ours is what this deployment calls its own, from its publisher
	// namespace and whatever else it stated. The roots a scan was about are
	// added per pass rather than held here, because a product declared this
	// morning is one whose name should not leave this afternoon.
	//
	// The zero value holds nothing back, which is a deployment that has
	// configured no publisher and scanned nothing published under a namespace.
	Ours Ours
	// leases is how the replicas decide which of them asks. replica names this
	// one in the lease it takes, and interval is how long it is taken for —
	// remembered by Run so the pass can take it again as it goes rather than
	// guessing at its own length.
	leases   *queue.Leases
	replica  string
	interval time.Duration
}

// NewRefresher returns a refresher over db, asking the real public indexes as
// whichever replica this is.
//
// The name identifies this replica in the lease. Every replica runs this pass,
// and only the one holding the lease asks anything.
func NewRefresher(db *bun.DB, logger *slog.Logger, replica string, ours Ours) *Refresher {
	client := New()
	return &Refresher{
		db: db, Index: client.For, logger: logger,
		leases: queue.NewLeases(db), replica: replica,
		Pause: betweenAsks, Now: time.Now, Ours: ours,
	}
}

// betweenCycles is how often the pass looks where the caller says nothing.
//
// Not the pause between one request and the next, which is betweenAsks: this
// is the gap between one slice of components and the following one.
const betweenCycles = time.Minute

// Run asks, forever, until the context ends.
//
// The setting is read each cycle rather than at startup, so turning this on
// takes effect without a restart — and, more to the point, so does turning it
// off. This is the one thing here that reaches the network, and an operator
// who decides that was a mistake should not have to redeploy to stop it.
func (r *Refresher) Run(ctx context.Context, interval time.Duration) {
	background.Every(ctx, interval, betweenCycles, func(ctx context.Context) {
		on, err := r.enabled(ctx)
		switch {
		case err != nil:
			r.logger.Error("reading whether to ask upstream", "error", err)
		case !on:
		default:
			// One replica asks. These are free public services run
			// by other people, and the politeness this pass is
			// built around — 200 at a time, a quarter-second apart
			// — is a rate per deployment, not a rate per replica.
			// Three replicas each keeping to it would be three
			// times the traffic at somebody else's expense, and
			// would spend two thirds of it asking questions
			// another replica had already answered.
			//
			// A cycle that does not get the lease does nothing and
			// tries again next time, which is the right answer for
			// a pass whose work is never urgent: whoever holds it
			// is doing it.
			r.interval = interval
			mine, err := r.asking(ctx, interval)
			if err != nil {
				r.logger.Error("deciding which replica asks upstream", "error", err)
				return
			}
			if !mine {
				return
			}
			if asked, err := r.Once(ctx); err != nil {
				// Logged and carried on. An index having a bad day is not a
				// reason to stop asking about everything else, and this
				// answer is an extra rather than something the rest depends
				// on.
				r.logger.Error("asking what upstream has released", "error", err)
			} else if asked > 0 {
				r.logger.Info("asked upstream what it has released", "components", asked)
			}
		}
	})
}

// asking reports whether this replica is the one that asks this cycle.
//
// The lease covers several cycles rather than one, and is taken again inside
// the pass as well as at the top of it. Sized from the interval alone it was
// a guess at how long a pass takes, and the arithmetic beside it said the
// guess was wrong: a pass is up to 200 requests with a timeout each, which is
// far past five intervals. So a slow index handed the pass to a second replica
// mid-flight and both asked — which is the thing a lease exists to prevent,
// and the asking is at somebody else's expense.
//
// Taken again rather than sized larger, because how long a pass takes is not
// a number anybody can name: it depends on an index this deployment does not
// run.
func (r *Refresher) asking(ctx context.Context, interval time.Duration) (bool, error) {
	if r.leases == nil {
		// Nothing to coordinate with. A refresher built without leases is one
		// a test drives directly, where there is one of it by construction.
		return true, nil
	}
	return r.leases.Take(ctx, AskingLease, r.replica, leaseFor(interval))
}

// AskingLease names the work of asking the public indexes what has been
// released, so that one replica does it.
const AskingLease = "upstream.currency"

// renewEvery is how many components a pass gets through before it asks for
// the lease again.
//
// Often enough that a slow index cannot outlast the lease between renewals —
// twenty-five requests at the outward timeout is well inside it — and rarely
// enough that the pass is not a conditional update every time it asks a
// question.
const renewEvery = 25

// leaseFor is how long to hold the lease, given how often the pass runs.
//
// Several cycles, so a replica that is briefly slow does not lose the work to
// another and then take it back; bounded below so a very short interval in a
// test does not produce a lease that has already lapsed by the time it is
// read. What keeps it alive across a long pass is the renewal inside the pass
// rather than this number.
func leaseFor(interval time.Duration) time.Duration {
	held := 5 * interval
	if held < time.Minute {
		held = time.Minute
	}
	return held
}

// enabled reports whether this deployment has turned asking on.
func (r *Refresher) enabled(ctx context.Context) (bool, error) {
	value, set, err := setting.NewStore(r.db).Get(ctx, setting.UpstreamCurrency)
	if err != nil {
		return false, err
	}
	return set && value == setting.On, nil
}

// stale is one component due a question.
type stale struct {
	ID   int64  `bun:"id"`
	Purl string `bun:"purl"`
}

// Once asks about one slice of components and records what came back.
//
// Returns how many were asked about, which is how the caller knows whether a
// backlog is still draining.
func (r *Refresher) Once(ctx context.Context) (int, error) {
	due, err := r.due(ctx)
	if err != nil {
		return 0, err
	}
	// Read once for the pass rather than once per component. It is one
	// statement over the roots, and the answer cannot change part way through
	// a pass in any way that matters: a product declared during it is held
	// back from the next one, a few minutes later.
	roots, err := RootOwners(ctx, r.db)
	if err != nil {
		return 0, fmt.Errorf("read who publishes what was scanned: %w", err)
	}
	ours := r.Ours.With(roots...)
	asked := 0
	for at, component := range due {
		if ctx.Err() != nil {
			return asked, nil
		}
		// The lease is asked for again as the pass runs, rather than sized
		// from a guess at how long the pass will take. It also stops a pass
		// that has already lost the lease from going on asking: two replicas
		// asking is the thing the lease exists to prevent, and the asking is
		// at somebody else's expense.
		if at > 0 && at%renewEvery == 0 {
			switch mine, err := r.asking(ctx, r.interval); {
			case err != nil:
				return asked, fmt.Errorf("keep the lease on asking upstream: %w", err)
			case !mine:
				return asked, nil
			}
		}
		// Read every time round rather than once per cycle. A pass is up to
		// 200 requests with a timeout each, so reading it only at the top
		// leaves an operator who has just turned this off waiting the better
		// part of an hour while it keeps talking to the network — which is the
		// one thing the setting exists to stop.
		on, err := r.enabled(ctx)
		if err != nil {
			// Reported rather than read as "turned off". A pass that stopped
			// because it could not read the setting looked exactly like one
			// that stopped because an operator turned it off, and neither
			// logged anything.
			return asked, fmt.Errorf("read whether asking upstream is on: %w", err)
		}
		if !on {
			return asked, nil
		}

		// **A name of ours never leaves, and is still answered.** Recorded
		// exactly as an unanswerable one below is, and for the same reason:
		// left unrecorded it would stay due for ever, and the window takes
		// the never-asked first, so it would hold the head of every pass
		// afterwards with the components behind it never reached. What tells
		// the two apart afterwards is the same list applied again, which is
		// what the report of what was held back is.
		//
		// **Anything an index said is dropped.** It was obtained by sending
		// this name, which is the thing that stops here. Kept, the version
		// stays on the screen with nothing that will ever refresh it, the
		// component never reaches the report of what was held back, and the
		// row goes stale in a day rather than in thirty — so it takes one of
		// the two hundred slots every day for ever and sends nothing.
		if ours.HeldBack(component.Purl) {
			if err := r.forget(ctx, component.ID); err != nil {
				return asked, err
			}
			continue
		}

		// **A question with nowhere to send it is still answered.** Not
		// recording here is what made this feature do nothing: a component
		// whose ecosystem has no index stayed due forever, and `due` takes the
		// oldest 200 with never-asked first — so on a real image, where 3,929
		// components are `generic`, `oci`, `github` or `maven` against 3,010
		// that are askable, the window filled with rows nothing ever wrote and
		// the pass asked upstream about nothing at all, every cycle, forever.
		ecosystem, name, ok := Asked(component.Purl)
		if !ok || r.Index(ecosystem) == nil {
			if err := r.record(ctx, component.ID, Latest{}); err != nil {
				return asked, err
			}
			continue
		}

		latest, err := r.Index(ecosystem).Latest(ctx, name)
		switch {
		case err == nil:
		case errors.Is(err, ErrUnknown):
			// The index has never heard of it, which a private module and a
			// vendored fork both look like. Recorded as asked so it is not
			// asked again tomorrow and every day after: an answer we will
			// never get is still an answer about this component.
			latest = Latest{}
		case errors.Is(err, ErrUnaskable):
			// A refusal the index will repeat every time: a name that cannot
			// be turned into a request at all, a package withdrawn, a region
			// blocked, a document nothing can read. That is a fact about this
			// component rather than a bad day, so it is recorded — left
			// unrecorded it starves the window exactly as below, and one
			// uploaded document full of them stops the worker.
			r.logger.Warn("an index will not answer about this component",
				"ecosystem", ecosystem, "package", name, "error", err)
			latest = Latest{}
		case ctx.Err() != nil:
			return asked, nil
		default:
			// A bad day at the index, and the only class worth coming back
			// to. One index failing is not the pass failing: nothing is
			// written, so it stays due and the next pass tries again.
			//
			// Everything else reaches the arm above rather than this one.
			// Read as a bad day, a refusal the index repeats every time left
			// the component unrecorded — and the window takes the never-asked
			// first, so it held the head of every pass afterwards for ever,
			// with the components behind it never reached.
			r.logger.Warn("an index did not answer",
				"ecosystem", ecosystem, "package", name, "error", err)
			r.pause(ctx)
			continue
		}

		if err := r.record(ctx, component.ID, latest); err != nil {
			return asked, err
		}
		asked++
		r.pause(ctx)
	}
	return asked, nil
}

// pause waits between requests, and stops waiting if we are shutting down.
//
// A bare time.Sleep in a worker driven by a context is a worker ignoring the
// signal it was given; the wait is short, but short is not cancellable.
func (r *Refresher) pause(ctx context.Context) {
	if r.Pause <= 0 {
		return
	}
	timer := time.NewTimer(r.Pause)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// due reads the components whose answer is missing or old.
//
// Ordered oldest first, with never-asked before everything, so a first run
// works through the list rather than circling the same slice of it.
func (r *Refresher) due(ctx context.Context) ([]stale, error) {
	var rows []stale
	err := r.db.NewSelect().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`c.id AS "id"`).
		ColumnExpr(`c.purl AS "purl"`).
		Where("c.purl <> ''").
		WhereGroup(" AND ", askableOnly).
		// Never asked, or asked long enough ago — where "long enough" depends
		// on whether we got an answer. A version we have goes stale in a day;
		// a package the index has never heard of is left for a month.
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr("c.latest_checked_at IS NULL").
				WhereOr("c.latest_version IS NOT NULL AND c.latest_checked_at < ?",
					r.Now().Add(-StaleAfter).UTC()).
				WhereOr("c.latest_version IS NULL AND c.latest_checked_at < ?",
					r.Now().Add(-UnknownAfter).UTC())
		}).
		OrderExpr("c.latest_checked_at IS NULL DESC").
		OrderExpr("c.latest_checked_at ASC").
		Limit(MostPerPass).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read what has not been asked about lately: %w", err)
	}
	return rows, nil
}

// askableOnly narrows to the ecosystems there is an index for.
//
// One spelling, because the pass that asks and the report that says what went
// unanswered have to describe the same set of candidates.
//
// Built from the list of those ecosystems rather than from its complement. A
// distribution package is the case a complement was written for and is still
// excluded by being absent from the list: for one of those the distribution is
// the maintainer, and the date it released says nothing about the age of the
// software inside it. Every other unaskable ecosystem is excluded too, which a
// complement did not do — each of them reached the asker, found none and was
// recorded empty, spending one of the two hundred slots a pass has.
//
// Lowercased, because Asked lowercases the ecosystem and the two have to
// agree. SQLite's LIKE is case-insensitive and PostgreSQL's is not, so
// "pkg:DEB/..." was excluded by one engine and kept by another, and the row
// that got through had no index and stuck.
func askableOnly(q *bun.SelectQuery) *bun.SelectQuery {
	for _, each := range Askable() {
		q = q.WhereOr("LOWER(c.purl) LIKE ?", "pkg:"+each+"/%")
	}
	return q
}

// record writes what an index said.
//
// The time of asking is written whatever came back, because "we asked and
// there is nothing" and "we have not asked" are different states and only one
// of them should be retried tomorrow. A version we did not get is stored as
// nothing rather than as an empty string standing in for an answer, and a date
// we did not get is left null — the beginning of time is not a release date.
func (r *Refresher) record(ctx context.Context, id int64, latest Latest) error {
	q := r.db.NewUpdate().
		Table("component").
		Set("latest_checked_at = ?", r.Now().UTC()).
		Where("id = ?", id)
	if latest.Version == "" {
		// An empty answer records that we asked and leaves any previous answer
		// alone. Overwriting it would let one 404 — which npm and crates.io
		// return for a renamed package and for some transient conditions —
		// destroy a version we had, and then sit on the hole for a month.
		// Keeping it also means the row goes stale in a day rather than in
		// thirty, so a package that has stopped answering is looked at again
		// soon rather than written off.
		if _, err := q.Exec(ctx); err != nil {
			return fmt.Errorf("record that we asked: %w", err)
		}
		return nil
	}
	q = q.Set("latest_version = ?", latest.Version)
	// The index's description of the package, and where it is developed. Both are
	// somebody else's text arriving over the network and rendered to staff who
	// hold the most access, so both are bounded and the address is judged
	// before it is stored rather than only before it is drawn.
	//
	// Absent is normal and overwrites nothing: three of the four indexes serve
	// a summary and the module proxy serves none, so a package with a version
	// and no summary is the ordinary case rather than a half-written row.
	if summary := clip(latest.Summary, MostSummary); summary != "" {
		q = q.Set("summary = ?", summary)
	}
	if project := addressable(latest.Project); project != "" {
		q = q.Set("project_url = ?", project)
	}
	if latest.Released.IsZero() {
		q = q.Set("latest_released_at = NULL")
	} else {
		q = q.Set("latest_released_at = ?", latest.Released.UTC())
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("record what upstream has released: %w", err)
	}
	return nil
}

// forget records that a component was held back, and drops what an index had
// said about it.
//
// The opposite of record's rule that an empty answer overwrites nothing. That
// rule is about an index having a bad day, where a previous answer is still
// the best thing known; this is a name that is not asked about at all any
// more, and everything stored against it came from asking.
//
// The time of asking is written, because "held back" and "not looked at yet"
// are different states and only one of them belongs at the head of the next
// pass.
func (r *Refresher) forget(ctx context.Context, id int64) error {
	_, err := r.db.NewUpdate().
		Table("component").
		Set("latest_checked_at = ?", r.Now().UTC()).
		Set("latest_version = NULL").
		Set("latest_released_at = NULL").
		Set("summary = NULL").
		Set("project_url = NULL").
		Where("id = ?", id).
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("drop what an index said about a name of ours: %w", err)
	}
	return nil
}

// MostSummary bounds what an index's one-line summary may be.
//
// A label rather than a document. What some indexes call a description is a
// whole README and this is not that field, but a publisher may still put a
// paragraph in the summary, and a row of a table is not where a paragraph is
// read. Cut on a rune boundary, because cutting a byte sequence in half makes
// text no renderer can draw.
const MostSummary = 300

// clip shortens text to a bound, on a rune boundary, and trims what is left.
func clip(text string, most int) string {
	text = strings.Join(strings.Fields(text), " ")
	if len([]rune(text)) <= most {
		return text
	}
	return strings.TrimSpace(string([]rune(text)[:most]))
}

// MostAddress bounds an address an index hands over.
//
// Refused rather than shortened, unlike the summary beside it: a cut address
// is a different address, and this one becomes somewhere to click. In bytes
// rather than characters, because an address is carried as bytes and this is a
// bound on what travels rather than on what is read.
//
// Generous — no index here serves one a tenth this long — because what it is
// for is a document nobody meant rather than a long address.
const MostAddress = 2048

// addressable is an address from an index, bounded and judged before it is
// stored.
//
// The same two schemes anything else typed into this deployment may link to. An
// index is a third party, and what it hands over goes into an `href`: a scheme
// a browser acts on is not encoded output. Judged here as well as where it is
// drawn, because a value that never should have been stored is one somebody
// later reads out of the database by another route.
//
// The bound is the half that was missing. The comment beside the two values
// said both were bounded and only the summary was, so the column took whatever
// arrived — bounded by nothing but the ceiling on the whole document.
func addressable(url string) string {
	at := strings.TrimSpace(url)
	if at == "" || len(at) > MostAddress {
		return ""
	}
	if err := markdown.Addressable(at); err != nil {
		return ""
	}
	return at
}
