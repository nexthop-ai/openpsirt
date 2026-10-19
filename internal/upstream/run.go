// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// ReadLease names the work of reading what upstreams publish, so that one
// replica does it.
const ReadLease = "upstream.read"

// betweenCycles is how often the pass looks where the caller says nothing.
// Far more often than an upstream is due, so a shortened interval is noticed
// within minutes.
const betweenCycles = 5 * time.Minute

// Pass reads what every trusted upstream publishes, on a schedule, and runs a
// product's builds again where what its upstream says moved.
type Pass struct {
	db     *bun.DB
	read   *Reader
	queue  *queue.Queue
	logger *slog.Logger
	// leases settles which replica reaches out; replica names this one, and
	// interval is how often the pass wakes.
	leases   *queue.Leases
	replica  string
	interval time.Duration
	now      func() time.Time
}

// NewPass returns the pass over db, reaching out as whichever replica this is
// and queueing builds to run again on q. roots are the certificate
// authorities an upstream is checked against, nil for the system's.
func NewPass(db *bun.DB, q *queue.Queue, logger *slog.Logger, replica string, limits sbom.Limits,
	roots *x509.CertPool) *Pass {
	p := &Pass{
		db: db, read: NewReader(db, limits, roots), queue: q, logger: logger,
		leases: queue.NewLeases(db), replica: replica,
		now: func() time.Time { return time.Now().UTC() },
	}
	p.read.keep = p.reaching
	return p
}

// Run reads until the context ends.
func (p *Pass) Run(ctx context.Context, interval time.Duration) {
	defer p.leases.Handback(ctx, ReadLease, p.replica, p.logger)
	background.Every(ctx, interval, betweenCycles, func(ctx context.Context) {
		p.interval = interval
		took, err := p.Once(ctx)
		switch {
		case err != nil:
			if ctx.Err() == nil {
				p.logger.Error("reading what upstreams publish", "error", err)
			}
		case took.Documents > 0 || took.Withdrawn > 0 || took.Refused > 0:
			p.logger.Info("read what upstreams publish", "documents", took.Documents,
				"withdrawn", took.Withdrawn, "refused", took.Refused)
		}
	})
}

// Once reads every upstream that is due a read, answering what it took.
func (p *Pass) Once(ctx context.Context) (Read, error) {
	var took Read
	mine, err := p.reaching(ctx)
	if err != nil || !mine {
		return took, err
	}
	every, err := setting.NewStore(p.db).Duration(ctx, setting.UpstreamEvery, setting.DefaultUpstreamEvery)
	if err != nil {
		return took, fmt.Errorf("read how often to read upstreams: %w", err)
	}
	due, err := NewStore(p.db).Due(ctx, access.Everything("reading what upstreams publish"),
		p.now().Add(-every))
	if err != nil {
		return took, err
	}
	for _, up := range due {
		if ctx.Err() != nil {
			return took, nil
		}
		switch mine, err := p.reaching(ctx); {
		case err != nil:
			return took, fmt.Errorf("keep the lease on reading what upstreams publish: %w", err)
		case !mine:
			return took, nil
		}
		one, err := p.read.From(ctx, up)
		took.Documents += one.Documents
		took.Withdrawn += one.Withdrawn
		took.Refused += one.Refused
		if err != nil {
			p.logger.Warn("an upstream could not be read", "upstream", up.URL, "error", err)
		}
		if one.Moved {
			if err := Again(ctx, p.db, p.queue, up.ProductID); err != nil {
				p.logger.Warn("a product's builds could not be run again after its upstream moved",
					"product", up.ProductID, "error", err)
			}
		}
	}
	return took, nil
}

// reaching reports whether this replica is the one that reaches out.
func (p *Pass) reaching(ctx context.Context) (bool, error) {
	held := max(5*p.interval, time.Minute)
	return p.leases.Take(ctx, ReadLease, p.replica, held)
}

// Again queues a scan of every build of a product that holds an inventory and
// has none waiting, so what its upstream says is applied, or stops being
// applied, without waiting for the schedule. Queued on db, so an act that
// changes what closes a product's findings queues the scans in its own
// transaction.
func Again(ctx context.Context, db bun.IDB, q *queue.Queue, productID int64) error {
	var targets []int64
	if err := db.NewSelect().
		TableExpr(`"target" AS "tg"`).
		ColumnExpr(`"tg"."id"`).
		Join(`JOIN "stream" AS "st" ON "st"."id" = "tg"."stream_id"`).
		Join(`JOIN "variant" AS "va" ON "va"."id" = "tg"."variant_id"`).
		Where(`"st"."product_id" = ?`, productID).
		Where(`"st"."retired_at" IS NULL`).
		Where(`"va"."retired_at" IS NULL`).
		Where(`"tg"."last_scan_id" IS NOT NULL`).
		OrderExpr(`"tg"."id"`).
		Scan(ctx, &targets); err != nil {
		return fmt.Errorf("read which builds a product holds: %w", err)
	}
	if len(targets) == 0 {
		return nil
	}
	var references []string
	if err := db.NewSelect().Model((*queue.Job)(nil)).Column("reference").
		Where(`"kind" = ?`, queue.Scan).
		Where(`"state" IN (?)`, bun.List([]queue.State{queue.Pending})).
		Scan(ctx, &references); err != nil {
		return fmt.Errorf("read which builds are waiting to be scanned: %w", err)
	}
	waiting := make(map[string]bool, len(references))
	for _, reference := range references {
		waiting[reference] = true
	}
	for _, target := range targets {
		reference := strconv.FormatInt(target, 10)
		if waiting[reference] {
			continue
		}
		if _, err := q.AddTx(ctx, db, queue.Scan, reference); err != nil {
			if errors.Is(err, queue.ErrBacklogFull) {
				// The rest wait for the schedule, which reaches them.
				return nil
			}
			return fmt.Errorf("queue build %d to be scanned again: %w", target, err)
		}
	}
	return nil
}
