package patchbranch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// Lease names the work of fetching repositories and looking commits up, so
// that one replica does it.
const Lease = "patch.branches"

// betweenCycles is how often the pass looks for work where the caller says
// nothing.
const betweenCycles = 5 * time.Minute

// LookAgainAfter is how long a commit's branches stand before it is looked up
// again.
//
// A week. The branches a backport sits on do not change; a commit on the
// mainline is taken into each branch cut after it, which happens every few
// months. Looking every commit up again daily would be ninety minutes of one
// core a day for the kernel alone, spent mostly confirming what was known.
const LookAgainAfter = 7 * 24 * time.Hour

// RetryAfter is how long a repository that could not be fetched is left
// before it is tried again. A host having a bad hour and a repository that
// is gone look the same from here, and a day is short for the first and cheap
// for the second.
const RetryAfter = 24 * time.Hour

// renewEvery is how many commits a visit looks up before it asks for the lease
// again, and reads the setting again. At 0.22 seconds a commit that is well
// inside the lease.
const renewEvery = 200

// Pass fetches the repositories patch links point into and records which
// branches each linked commit is on.
type Pass struct {
	db       bun.IDB
	logger   *slog.Logger
	git      git
	copies   copies
	excluded Excluded
	// Now is the clock, so a test can ask what happens a week from now.
	Now func() time.Time

	leases   *queue.Leases
	replica  string
	interval time.Duration
}

// Options is what a deployment decides about the copies.
type Options struct {
	// Dir is where the copies are kept.
	Dir string
	// Quota is how many bytes they may hold together. Zero or less takes
	// DefaultQuota.
	Quota int64
	// Excluded is where no repository is fetched from, on top of this
	// network.
	Excluded Excluded
	// Git is the program. Empty means whatever the environment resolves.
	Git string
}

// NewPass returns the pass over db as whichever replica this is.
func NewPass(db *bun.DB, logger *slog.Logger, replica string, options Options) *Pass {
	quota := options.Quota
	if quota <= 0 {
		quota = DefaultQuota
	}
	return &Pass{
		db: db, logger: logger,
		git:      git{path: options.Git, excluded: options.Excluded, transport: "https"},
		copies:   copies{root: options.Dir, quota: quota, now: time.Now, poll: 15 * time.Second},
		excluded: options.Excluded,
		Now:      time.Now,
		leases:   queue.NewLeases(db), replica: replica,
	}
}

// Run looks for work until the context ends.
//
// The setting is read each cycle, and again as a visit runs, so turning this
// off stops the fetching without a restart.
func (p *Pass) Run(ctx context.Context, interval time.Duration) {
	background.Every(ctx, interval, betweenCycles, func(ctx context.Context) {
		on, err := p.enabled(ctx)
		switch {
		case err != nil:
			p.logger.Error("reading whether to look up patch branches", "error", err)
			return
		case !on:
			return
		}
		p.interval = interval
		if p.interval <= 0 {
			p.interval = betweenCycles
		}
		mine, err := p.holding(ctx)
		if err != nil {
			p.logger.Error("deciding which replica looks up patch branches", "error", err)
			return
		}
		if !mine {
			return
		}
		visited, err := p.Once(ctx)
		if ctx.Err() != nil && p.leases != nil {
			// Shutting down mid-visit. The lease is handed back so the
			// replica that starts next carries on at once rather than
			// waiting for it to lapse.
			releasing, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			if err := p.leases.Release(releasing, Lease, p.replica); err != nil {
				p.logger.Warn("handing back the lease on looking up patch branches", "error", err)
			}
			return
		}
		if err != nil {
			p.logger.Error("looking up the branches patches are on", "error", err)
			return
		}
		if visited != "" {
			p.logger.Info("looked up the branches patches are on", "repository", visited)
		}
	})
}

// holding reports whether this replica is the one doing the work.
//
// Taken again as a visit runs, because a visit to a large repository takes
// hours and no lease sized in advance would cover it.
func (p *Pass) holding(ctx context.Context) (bool, error) {
	if p.leases == nil {
		return true, nil
	}
	held := 5 * p.interval
	if held < 30*time.Minute {
		held = 30 * time.Minute
	}
	return p.leases.Take(ctx, Lease, p.replica, held)
}

// enabled reports whether this deployment has turned the lookups on.
func (p *Pass) enabled(ctx context.Context) (bool, error) {
	value, set, err := setting.NewStore(p.db).Get(ctx, setting.PatchBranches)
	if err != nil {
		return false, err
	}
	return set && value == setting.On, nil
}

// Once records what patch links name, visits the one repository most worth
// visiting, and answers which it was.
//
// The switch is read here as well as in Run: a guard beside the work cannot be
// skipped by calling the work another way.
func (p *Pass) Once(ctx context.Context) (string, error) {
	switch on, err := p.enabled(ctx); {
	case err != nil:
		return "", fmt.Errorf("read whether patch branches are looked up: %w", err)
	case !on:
		return "", nil
	}
	now := p.Now()
	commits, _, err := linked(ctx, p.db)
	if err != nil {
		return "", err
	}
	if err := intern(ctx, p.db, commits, now); err != nil {
		return "", err
	}
	next, err := p.choose(ctx, commits, now)
	if err != nil || next == nil {
		return "", err
	}
	return next.repository.URL, p.visit(ctx, *next, commits)
}

// candidate is a repository with commits due a look.
type candidate struct {
	repository repositoryRow
	due        []commitRow
	// never is how many of those have never been looked up, and worst is the
	// most urgent of them.
	never int
	worst urgency
	// stale is the most urgent of those looked up before.
	stale urgency
	held  bool
}

// choose picks the repository to visit.
//
// A repository whose copy is already on this disk goes first when it has
// commits never looked up: the fetch that brings it up to date is small, and
// looking up everything due in it costs little once it is there. After that,
// the repository holding the most urgent commit never looked up, then the
// most urgent one due again. A repository an administrator excluded is never
// chosen, and one that failed is left for a day.
func (p *Pass) choose(ctx context.Context, commits map[Commit]urgency, now time.Time) (*candidate, error) {
	var repositories []repositoryRow
	if err := p.db.NewSelect().Model(&repositories).Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the repositories patch links point into: %w", err)
	}
	var due []commitRow
	if err := p.db.NewSelect().Model(&due).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr(`"looked_at" IS NULL`).
				WhereOr(`"looked_at" < ?`, now.Add(-LookAgainAfter).UTC())
		}).
		Scan(ctx); err != nil {
		return nil, fmt.Errorf("read the commits due a look: %w", err)
	}
	byID := map[int64]*candidate{}
	for _, repository := range repositories {
		if p.excluded.Host(repository.Host) {
			continue
		}
		if repository.Failed != nil && *repository.Failed != "" && repository.FetchedAt != nil &&
			repository.FetchedAt.After(now.Add(-RetryAfter)) {
			continue
		}
		byID[repository.ID] = &candidate{repository: repository, held: p.copies.has(repository.URL)}
	}
	for _, row := range due {
		one := byID[row.RepositoryID]
		if one == nil {
			continue
		}
		// Only what a report still links to. A commit no issue names any
		// more is left as it was last seen.
		how, linked := commits[Commit{Repository: one.repository.URL, Hash: row.Hash}]
		if !linked {
			continue
		}
		one.due = append(one.due, row)
		if row.LookedAt == nil {
			one.never++
			if how.above(one.worst) || one.never == 1 {
				one.worst = how
			}
		} else if how.above(one.stale) {
			one.stale = how
		}
	}
	var best *candidate
	for _, one := range byID {
		if len(one.due) == 0 {
			continue
		}
		if best == nil || one.before(best) {
			best = one
		}
	}
	return best, nil
}

// before orders two candidates as choose describes.
func (c *candidate) before(other *candidate) bool {
	here, there := c.held && c.never > 0, other.held && other.never > 0
	if here != there {
		return here
	}
	if (c.never > 0) != (other.never > 0) {
		return c.never > 0
	}
	if c.worst != other.worst {
		return c.worst.above(other.worst)
	}
	if c.stale != other.stale {
		return c.stale.above(other.stale)
	}
	if len(c.due) != len(other.due) {
		return len(c.due) > len(other.due)
	}
	return c.repository.ID < other.repository.ID
}

// errStopped is a visit that stopped because the switch was turned off or the
// lease was lost. Not a failure of the repository.
var errStopped = errors.New("stopped")

// visit brings one repository's copy up to date and looks up every commit due
// in it, most urgent first.
func (p *Pass) visit(ctx context.Context, c candidate, commits map[Commit]urgency) error {
	started := p.Now()
	if _, err := p.db.NewUpdate().Model((*repositoryRow)(nil)).
		Set("fetched_at = ?", started.UTC()).
		Set("failed = NULL").
		Where("id = ?", c.repository.ID).Exec(ctx); err != nil {
		return fmt.Errorf("record that a visit began: %w", err)
	}
	dir, err := p.copies.ensure(ctx, p.git, c.repository.URL)
	if err == nil {
		err = p.git.graph(ctx, dir)
	}
	if err == nil {
		err = p.lookUp(ctx, c, commits, dir)
	}
	switch {
	case errors.Is(err, errStopped), ctx.Err() != nil:
		// Nothing about the repository to record: the visit neither
		// finished nor failed. The moment it began is put back to the last
		// one that finished, so the report shows no visit in progress and
		// no finish that did not happen.
		return p.finish(ctx, c.repository.ID, dir, errStopped)
	case err != nil:
		p.logger.Warn("a repository patch links point into could not be read",
			"repository", c.repository.URL, "error", err)
		return p.finish(ctx, c.repository.ID, dir, err)
	}
	return p.finish(ctx, c.repository.ID, dir, nil)
}

// lookUp asks the copy about every due commit, most urgent first.
func (p *Pass) lookUp(ctx context.Context, c candidate, commits map[Commit]urgency, dir string) error {
	sort.SliceStable(c.due, func(i, j int) bool {
		a, b := c.due[i], c.due[j]
		if (a.LookedAt == nil) != (b.LookedAt == nil) {
			return a.LookedAt == nil
		}
		ua := commits[Commit{Repository: c.repository.URL, Hash: a.Hash}]
		ub := commits[Commit{Repository: c.repository.URL, Hash: b.Hash}]
		if ua != ub {
			return ua.above(ub)
		}
		return a.ID < b.ID
	})
	hashes := make([]string, 0, len(c.due))
	for _, row := range c.due {
		hashes = append(hashes, row.Hash)
	}
	full, err := p.git.resolve(ctx, dir, hashes)
	if err != nil {
		return err
	}
	for at, row := range c.due {
		if at > 0 && at%renewEvery == 0 {
			if err := p.stillMine(ctx); err != nil {
				return err
			}
		}
		if ctx.Err() != nil {
			return errStopped
		}
		var branches []string
		name, found := full[row.Hash]
		if found {
			if branches, err = p.git.branches(ctx, dir, name); err != nil {
				return err
			}
		}
		if err := p.record(ctx, row.ID, found, branches); err != nil {
			return err
		}
	}
	return nil
}

// stillMine stops a visit that has lost the lease or been turned off.
func (p *Pass) stillMine(ctx context.Context) error {
	on, err := p.enabled(ctx)
	if err != nil {
		return fmt.Errorf("read whether patch branches are looked up: %w", err)
	}
	if !on {
		return errStopped
	}
	mine, err := p.holding(ctx)
	if err != nil {
		return fmt.Errorf("keep the lease on looking up patch branches: %w", err)
	}
	if !mine {
		return errStopped
	}
	return nil
}

// record writes what the copy said about one commit.
func (p *Pass) record(ctx context.Context, id int64, found bool, branches []string) error {
	sort.Slice(branches, func(i, j int) bool { return versionLess(branches[i], branches[j]) })
	count := len(branches)
	var kept []branchRow
	for _, name := range branches {
		// A name wider than the column is dropped rather than cut: a cut name
		// is a different branch. It is still counted.
		if len([]rune(name)) > database.NameWidth || len(kept) == MostBranches {
			continue
		}
		kept = append(kept, branchRow{CommitID: id, Branch: name})
	}
	now := p.Now().UTC()
	handle, ok := database.Handle(p.db)
	if !ok {
		return errors.New("recording a lookup needs a database handle")
	}
	return database.InTransaction(ctx, handle, func(ctx context.Context, tx bun.Tx) error {
		if _, err := tx.NewDelete().Model((*branchRow)(nil)).
			Where("commit_id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("clear the branches a commit was on: %w", err)
		}
		if len(kept) > 0 {
			if err := database.InBatches(ctx, tx, kept); err != nil {
				return fmt.Errorf("record the branches a commit is on: %w", err)
			}
		}
		if _, err := tx.NewUpdate().Model((*commitRow)(nil)).
			Set("looked_at = ?", now).
			Set("found = ?", found).
			Set("branch_count = ?", count).
			Where("id = ?", id).Exec(ctx); err != nil {
			return fmt.Errorf("record that a commit was looked up: %w", err)
		}
		return nil
	})
}

// finish records how a visit ended, and makes room in the cache.
func (p *Pass) finish(ctx context.Context, id int64, dir string, failed error) error {
	update := p.db.NewUpdate().Model((*repositoryRow)(nil)).Where("id = ?", id)
	switch {
	case errors.Is(failed, errStopped):
		update = update.Set("fetched_at = reached_at")
	case failed != nil:
		update = update.Set("failed = ?", bound.HeadRunes(failed.Error(), MostReason))
	default:
		update = update.Set("failed = NULL").Set("reached_at = ?", p.Now().UTC())
	}
	if dir != "" {
		update = update.Set("held_bytes = ?", size(dir))
	}
	// Recorded on a context of its own: a visit stopped by shutdown still
	// happened, and the report should not show it as running for ever.
	recording, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if _, err := update.Exec(recording); err != nil {
		return fmt.Errorf("record how a visit ended: %w", err)
	}
	removed, err := p.copies.evict(dir, 0)
	if err != nil {
		return err
	}
	if len(removed) > 0 {
		p.logger.Info("removed repository copies to stay within the cache", "removed", len(removed))
	}
	return nil
}
