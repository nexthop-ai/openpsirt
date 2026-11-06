// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package issuedate

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/finding/kind"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// When an answer is asked again.
//
// A known issue's modification date moves as its record is revised, and its
// publication date almost never does. An issue OSV does not know is asked
// daily for its first fortnight here, since a fresh issue reaches OSV within
// hours, and monthly after.
const (
	KnownAfter   = 30 * 24 * time.Hour
	FreshFor     = 14 * 24 * time.Hour
	FreshAfter   = 24 * time.Hour
	UnknownAfter = 30 * 24 * time.Hour
)

// MostPerPass bounds the issues one pass asks about.
const MostPerPass = 200

// mostNames bounds the names asked for one issue: its own identifier first,
// then its other names, until one answers.
const mostNames = 5

// betweenAsks is the pause between one request and the next.
const betweenAsks = 100 * time.Millisecond

// betweenCycles is how often the pass looks where the caller says nothing.
const betweenCycles = time.Minute

// renewEvery is how many issues a pass asks about before it takes the lease
// again; one issue is up to five requests.
const renewEvery = 25

// Lease names the work of asking OSV, so one replica asks.
const Lease = "issue.dates"

// Pass asks OSV for the dates of the issues due an answer.
type Pass struct {
	db     bun.IDB
	Asker  Asker
	logger *slog.Logger
	// Pause and Now are fields so a test neither waits nor ages a month.
	Pause    time.Duration
	Now      func() time.Time
	leases   *queue.Leases
	replica  string
	interval time.Duration
}

// NewPass returns a pass over db asking OSV, as this replica.
func NewPass(db *bun.DB, logger *slog.Logger, replica string) *Pass {
	return &Pass{
		db: db, Asker: NewOSV(), logger: logger,
		Pause: betweenAsks, Now: time.Now,
		leases: queue.NewLeases(db), replica: replica,
	}
}

// Enabled reports whether the deployment asks OSV, which it does unless
// somebody turned it off.
func Enabled(ctx context.Context, db bun.IDB) (bool, error) {
	on, err := setting.NewStore(db).Switch(ctx, setting.IssueDates, true)
	if err != nil {
		return false, fmt.Errorf("read whether to ask for issue dates: %w", err)
	}
	return on, nil
}

// Run asks until the context ends, reading the setting each cycle so turning
// it off takes effect without a restart.
func (p *Pass) Run(ctx context.Context, interval time.Duration) {
	p.interval = interval
	defer p.leases.Handback(ctx, Lease, p.replica, p.logger)
	background.Every(ctx, interval, betweenCycles, func(ctx context.Context) {
		on, err := Enabled(ctx, p.db)
		switch {
		case err != nil:
			p.logger.Error("reading whether to ask for issue dates", "error", err)
			return
		case !on:
			return
		}
		mine, err := p.asking(ctx)
		if err != nil {
			p.logger.Error("deciding which replica asks for issue dates", "error", err)
			return
		}
		if !mine {
			return
		}
		if asked, err := p.Once(ctx); err != nil {
			p.logger.Error("asking OSV for issue dates", "error", err)
		} else if asked > 0 {
			p.logger.Info("asked OSV for issue dates", "issues", asked)
		}
	})
}

// asking takes the lease, or answers true where there is none to take.
func (p *Pass) asking(ctx context.Context) (bool, error) {
	if p.leases == nil {
		return true, nil
	}
	held := max(5*p.interval, time.Minute)
	return p.leases.Take(ctx, Lease, p.replica, held)
}

// dueIssue is one issue due an answer.
type dueIssue struct {
	ID         int64  `bun:"id"`
	Identifier string `bun:"identifier"`
}

// Once asks about one slice of issues and records each answer, returning how
// many were answered.
func (p *Pass) Once(ctx context.Context) (int, error) {
	due, err := p.due(ctx)
	if err != nil {
		return 0, err
	}
	answered := 0
	for at, issue := range due {
		if ctx.Err() != nil {
			return answered, nil
		}
		if at > 0 && at%renewEvery == 0 {
			switch mine, err := p.asking(ctx); {
			case err != nil:
				return answered, fmt.Errorf("keep the lease on asking for issue dates: %w", err)
			case !mine:
				return answered, nil
			}
		}
		// Read before every request, so turning this off stops the pass
		// part way.
		on, err := Enabled(ctx, p.db)
		if err != nil {
			return answered, err
		}
		if !on {
			return answered, nil
		}
		names, err := p.names(ctx, issue)
		if err != nil {
			return answered, err
		}
		dates, err := p.ask(ctx, names)
		switch {
		case err == nil, errors.Is(err, ErrUnknown):
		case ctx.Err() != nil:
			return answered, nil
		default:
			// OSV is unwell: nothing is recorded, so the issue stays due, and
			// the rest wait for the next pass.
			p.logger.Warn("OSV did not answer", "issue", issue.Identifier, "error", err)
			return answered, nil
		}
		if err := p.record(ctx, issue.ID, dates); err != nil {
			return answered, err
		}
		answered++
	}
	return answered, nil
}

// ask asks each name in turn until OSV knows one, and answers no dates where
// it knows none. A name OSV refuses is passed over like one it does not know.
func (p *Pass) ask(ctx context.Context, names []string) (Dates, error) {
	for i, name := range names {
		if i > 0 {
			p.pause(ctx)
		}
		dates, err := p.Asker.Dates(ctx, name)
		switch {
		case err == nil:
			p.pause(ctx)
			return dates, nil
		case errors.Is(err, ErrUnknown):
		case errors.Is(err, ErrUnaskable):
			p.logger.Warn("OSV will not answer about this name", "name", name, "error", err)
		default:
			return Dates{}, err
		}
	}
	p.pause(ctx)
	return Dates{}, ErrUnknown
}

// pause waits between requests, and stops waiting when the context ends.
func (p *Pass) pause(ctx context.Context) {
	if p.Pause <= 0 {
		return
	}
	timer := time.NewTimer(p.Pause)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

// due reads the issues whose answer is missing or old, never-asked first and
// then oldest asked. Only published vulnerabilities are asked about, by the
// row an issue stands as: a flaw minted here and an analyzer's rule are known
// to nobody outside.
func (p *Pass) due(ctx context.Context) ([]dueIssue, error) {
	now := p.Now().UTC()
	var rows []dueIssue
	err := p.db.NewSelect().
		TableExpr(`"vulnerability" AS "v"`).
		ColumnExpr(`"v"."id" AS "id"`).
		ColumnExpr(`"v"."identifier" AS "identifier"`).
		Where(`"v"."id" = "v"."issue_id"`).
		Where(`"v"."kind" = ?`, string(kind.Advisory)).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.WhereOr(`"v"."dates_asked_at" IS NULL`).
				WhereOr(`"v"."published_at" IS NOT NULL AND "v"."dates_asked_at" < ?`, now.Add(-KnownAfter)).
				WhereOr(`"v"."published_at" IS NULL AND "v"."first_seen_at" >= ? AND "v"."dates_asked_at" < ?`,
					now.Add(-FreshFor), now.Add(-FreshAfter)).
				WhereOr(`"v"."published_at" IS NULL AND "v"."dates_asked_at" < ?`, now.Add(-UnknownAfter))
		}).
		OrderExpr(`"v"."dates_asked_at" IS NULL DESC`).
		OrderExpr(`"v"."dates_asked_at" ASC`).
		OrderExpr(`"v"."id" ASC`).
		Limit(MostPerPass).
		Scan(ctx, &rows)
	if err != nil {
		return nil, fmt.Errorf("read which issues are due their dates: %w", err)
	}
	return rows, nil
}

// names is every name an issue is known by, its own identifier first, then
// the CVE and GitHub names, then the rest, at most mostNames of them.
func (p *Pass) names(ctx context.Context, issue dueIssue) ([]string, error) {
	var held []string
	err := p.db.NewSelect().
		TableExpr(`"vulnerability_alias" AS "va"`).
		ColumnExpr(`"va"."identifier"`).
		Where(`"va"."vulnerability_id" IN (SELECT "v2"."id" FROM "vulnerability" AS "v2" WHERE "v2"."issue_id" = ?)`,
			issue.ID).
		Scan(ctx, &held)
	if err != nil {
		return nil, fmt.Errorf("read the names an issue is known by: %w", err)
	}
	var absorbed []string
	err = p.db.NewSelect().
		TableExpr(`"vulnerability" AS "v2"`).
		ColumnExpr(`"v2"."identifier"`).
		Where(`"v2"."issue_id" = ?`, issue.ID).
		Where(`"v2"."id" <> ?`, issue.ID).
		Scan(ctx, &absorbed)
	if err != nil {
		return nil, fmt.Errorf("read the issues merged into one: %w", err)
	}
	return ordered(issue.Identifier, append(held, absorbed...)), nil
}

// ordered is the names to ask, the issue's own first, without repeats.
func ordered(own string, others []string) []string {
	rank := func(name string) int {
		upper := strings.ToUpper(name)
		switch {
		case strings.HasPrefix(upper, "CVE-"):
			return 0
		case strings.HasPrefix(upper, "GHSA-"):
			return 1
		default:
			return 2
		}
	}
	sort.SliceStable(others, func(a, b int) bool { return rank(others[a]) < rank(others[b]) })
	seen := map[string]bool{}
	var out []string
	for _, name := range append([]string{own}, others...) {
		folded := strings.ToUpper(strings.TrimSpace(name))
		if folded == "" || seen[folded] {
			continue
		}
		seen[folded] = true
		out = append(out, strings.TrimSpace(name))
		if len(out) == mostNames {
			break
		}
	}
	return out
}

// record writes when the issue was asked about, and the dates where OSV gave
// them. An empty answer leaves dates already held: a record OSV stops serving
// was still published when it said.
//
// A first date also rewrites what a replaced inventory's check recorded of the
// issue without one, in the same transaction, so a match never reads as dated
// while its stretch still assumes it was not. The issue's row is taken first,
// by the write of when it was asked, so a check holding it commits its matches
// before they are read, and a check arriving later waits and reads the date.
func (p *Pass) record(ctx context.Context, id int64, dates Dates) error {
	asked := p.Now().UTC().Truncate(time.Microsecond)
	var redated finding.Redated
	err := database.Within(ctx, p.db, func(ctx context.Context, tx bun.IDB) error {
		redated = finding.Redated{}
		if _, err := tx.NewUpdate().Table("vulnerability").
			Set(`"dates_asked_at" = ?`, asked).
			Where(`"id" = ?`, id).Exec(ctx); err != nil {
			return fmt.Errorf("record when OSV was asked about an issue: %w", err)
		}
		if dates.Published.IsZero() {
			return nil
		}
		var held struct {
			PublishedAt *time.Time `bun:"published_at"`
		}
		if err := tx.NewSelect().Table("vulnerability").Column("published_at").
			Where(`"id" = ?`, id).Scan(ctx, &held); err != nil {
			return fmt.Errorf("read an issue's dates: %w", err)
		}
		if held.PublishedAt == nil {
			var err error
			if redated, err = finding.Redate(ctx, tx, id, dates.Published); err != nil {
				return err
			}
		}
		q := tx.NewUpdate().Table("vulnerability").
			Set(`"published_at" = ?`, dates.Published.Truncate(time.Microsecond)).
			Where(`"id" = ?`, id)
		if dates.Modified.IsZero() {
			q = q.Set(`"modified_at" = NULL`)
		} else {
			q = q.Set(`"modified_at" = ?`, dates.Modified.Truncate(time.Microsecond))
		}
		if _, err := q.Exec(ctx); err != nil {
			return fmt.Errorf("record an issue's dates: %w", err)
		}
		return nil
	})
	if err == nil && redated.Moved+redated.Withdrawn > 0 {
		p.logger.Info("dated what a check recorded without a date", "issue", id,
			"moved", redated.Moved, "withdrawn", redated.Withdrawn)
	}
	return err
}
