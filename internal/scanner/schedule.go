package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Schedule asks for everything tracked to be scanned again, on a schedule.
//
// The vulnerability data is produced here rather than by the build, which
// means a release built a year ago has the same components it always had and a
// different answer every month. Nothing else asks for that: an inventory
// arriving puts one scan on the queue, and a build that is never rebuilt would
// otherwise be measured once and never again — which is exactly the build an
// advisory published this morning is most likely to be about.
type Schedule struct {
	db     *database.DB
	queue  *queue.Queue
	leases *queue.Leases
	logger *slog.Logger
	// replica names this process in the lease. Every replica runs this and one
	// of them asks, because asking twice would put two scans of one target on
	// the queue and the second would find nothing to do.
	replica string
	now     func() time.Time
}

// NewSchedule returns a schedule over db, asking as whichever replica this is.
func NewSchedule(db *database.DB, q *queue.Queue, logger *slog.Logger, replica string) *Schedule {
	return &Schedule{
		db: db, queue: q, leases: queue.NewLeases(db.DB),
		logger: logger, replica: replica,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// ScheduleLease names the work of deciding what to scan again, so that one
// replica does it.
const ScheduleLease = "vulnerability.schedule"

// betweenSchedules is how often this looks where the caller says nothing.
//
// Far more often than anything is due, and deliberately: what it looks *for*
// is a setting an administrator may shorten, and a pass that woke only once a
// day would take up to a day to notice they had.
const betweenSchedules = 5 * time.Minute

// Run asks until the context ends.
func (s *Schedule) Run(ctx context.Context, interval time.Duration) {
	background.Every(ctx, interval, betweenSchedules, func(ctx context.Context) {
		if asked, err := s.Once(ctx); err != nil {
			// Logged and carried on, like every other background pass here. A
			// cycle that cannot run is not a reason to stop the process, and
			// the next one is along shortly.
			if ctx.Err() == nil {
				s.logger.Error("working out what needs scanning again", "error", err)
			}
		} else if asked > 0 {
			s.logger.Info("asked for builds to be scanned again", "builds", asked)
		}
	})
}

// Once puts a scan on the queue for everything that is due one, reporting how
// many it asked for.
func (s *Schedule) Once(ctx context.Context) (int, error) {
	mine, err := s.leases.Take(ctx, ScheduleLease, s.replica, s.leaseFor(ctx))
	if err != nil || !mine {
		// Somebody else is doing it. Not an error and not worth saying: the
		// work happens either way, and a cycle that skipped is the ordinary
		// case on every replica but one.
		return 0, err
	}

	every, err := s.every(ctx)
	if err != nil {
		return 0, err
	}
	queued, err := s.alreadyQueued(ctx)
	if err != nil {
		return 0, err
	}
	if len(queued) >= dueLimit {
		// A cycle's worth of scanning is already waiting. Nothing this pass
		// could add would be reached before the next cycle anyway, and asking
		// while the queue is this deep is how a producer's arriving
		// inventories end up behind re-scans of things measured yesterday.
		return 0, nil
	}
	due, err := s.due(ctx, every, queued)
	if err != nil {
		return 0, err
	}

	asked := 0
	for _, targetID := range due {
		if err := ctx.Err(); err != nil {
			return asked, nil
		}
		_, err := s.queue.Add(ctx, queue.Scan, strconv.FormatInt(targetID, 10))
		if errors.Is(err, queue.ErrBacklogFull) {
			// The queue is as deep as it is allowed to be, so the rest wait
			// for the next cycle. Not an error: what is due stays due, and
			// pressing on would push a producer's arriving scans behind a
			// re-scan of something last measured yesterday.
			s.logger.Warn("stopped asking for re-scans because the queue is full",
				"asked", asked, "still_due", len(due)-asked)
			return asked, nil
		}
		if err != nil {
			return asked, fmt.Errorf("ask for build %d to be scanned again: %w", targetID, err)
		}
		asked++
	}
	return asked, nil
}

// every is how often everything tracked is scanned again.
func (s *Schedule) every(ctx context.Context) (time.Duration, error) {
	held, err := setting.NewStore(s.db.DB).Duration(ctx, setting.ScanEvery, setting.DefaultScanEvery)
	if err != nil {
		return 0, fmt.Errorf("read how often to scan again: %w", err)
	}
	return held, nil
}

// leaseFor is how long to hold the lease, given how often the pass runs.
//
// Long enough to cover a cycle rather than an instant of one: the pass reads a
// list and writes a job per entry, and a lease that lapsed halfway would let a
// second replica start asking for the same ones.
func (s *Schedule) leaseFor(ctx context.Context) time.Duration {
	every, err := s.every(ctx)
	if err != nil || every < time.Hour {
		return time.Hour
	}
	return every
}

// dueLimit is how many re-scans one cycle asks for.
//
// A bound rather than none, for the reason every bulk write here has one: a
// deployment tracking a great many builds would otherwise fill the queue in
// one pass and push a producer's arriving inventories behind work that is not
// urgent. What is left over is still due on the next cycle.
const dueLimit = 200

// alreadyQueued is the builds a scan is already waiting or running for.
//
// **Read as identifiers rather than joined in the statement.** A job's
// reference is text, because a job may be about anything, and a target's
// identifier is a number, so joining them means converting one inside the
// query — and there is no spelling of that all four engines agree on. The one
// that looked portable, `CAST(id AS CHAR)`, is `char(1)` on PostgreSQL: it
// silently keeps the first digit, so the comparison is right for the first
// nine builds a deployment declares and wrong for every one after. Reading the
// references out and comparing numbers is the same answer with nothing to get
// wrong per engine.
//
// Bounded by the queue's own backlog limit, and the caller stops before using
// this when there is already a cycle's worth waiting.
func (s *Schedule) alreadyQueued(ctx context.Context) ([]int64, error) {
	var references []string
	err := s.db.NewSelect().
		Model((*queue.Job)(nil)).
		Column("reference").
		Where("kind = ?", queue.Scan).
		Where("state IN (?)", bun.List([]queue.State{queue.Pending, queue.Running})).
		Scan(ctx, &references)
	if err != nil {
		return nil, fmt.Errorf("read what is already queued for scanning: %w", err)
	}
	held := make([]int64, 0, len(references))
	for _, reference := range references {
		// A reference that is not a number does not name a build, so it
		// cannot be one of these. The worker that claims it will say so.
		if id, err := strconv.ParseInt(reference, 10, 64); err == nil {
			held = append(held, id)
		}
	}
	return held, nil
}

// due is which builds have not been scanned within the interval.
//
// **Only builds that hold an inventory.** A target is declared before anything
// is filed against it, and scanning one with no components would record a run
// that found nothing against a build that has nothing — an empty answer that
// reads exactly like a clean one.
//
// **And not the ones already queued.** A job per cycle for a build the queue
// has not reached yet would pile up as many jobs as cycles, each of which does
// the same work when it finally runs.
func (s *Schedule) due(ctx context.Context, every time.Duration, queued []int64) ([]int64, error) {
	before := s.now().Add(-every).Truncate(time.Microsecond)

	q := s.db.NewSelect().
		TableExpr(`target AS "tg"`).
		ColumnExpr("tg.id").
		Where(`EXISTS (SELECT 1 FROM "graph_node" AS "gn"
			WHERE gn.target_id = tg.id AND gn.closed_scan_id IS NULL)`).
		Where(`NOT EXISTS (SELECT 1 FROM "scan_run" AS "r"
			WHERE r.target_id = tg.id AND r.started_at >= ?)`, before).
		OrderExpr("tg.id").
		Limit(dueLimit)
	if len(queued) > 0 {
		q = q.Where("tg.id NOT IN (?)", bun.List(queued))
	}

	var due []int64
	if err := q.Scan(ctx, &due); err != nil {
		return nil, fmt.Errorf("read which builds are due a scan: %w", err)
	}
	return due, nil
}
