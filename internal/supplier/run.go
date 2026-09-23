// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

// FetchLease names the work of reading what suppliers publish, so that one
// replica does it.
const FetchLease = "supplier.fetch"

// betweenCycles is how often the pass looks where the caller says nothing.
//
// Far more often than any supplier is due, and deliberately: how often one is
// read again is a setting an administrator may shorten, and a pass that woke
// only once a day would take up to a day to notice they had.
const betweenCycles = 5 * time.Minute

// allHistory is the most days of a supplier's history read, whatever the
// setting says.
//
// A century is further back than any publisher of these documents has issued,
// so it reads as everything; a count past it would overflow the length of time
// it is turned into.
const allHistory = 100 * 365

// Pass reads what every configured supplier publishes, on a schedule.
//
// On the scan schedule, because that is the same question: a supplier's
// advisory is about a component in an inventory, and the answer to "what is
// known about what we ship" moves on the cadence the vulnerability data does.
// A second interval would be a second answer to one question.
type Pass struct {
	db     *bun.DB
	fetch  *Fetcher
	logger *slog.Logger
	// leases is how the replicas decide which of them reaches out. replica
	// names this one in the lease, and interval is how often the pass wakes —
	// remembered by Run so that the lease can be taken again as the pass goes
	// rather than sized from a guess at how long it will take.
	leases   *queue.Leases
	replica  string
	interval time.Duration
	now      func() time.Time
}

// NewPass returns the pass over db, fetching as whichever replica this is.
//
// The name identifies this replica in the lease. Every replica runs this pass,
// and only the one holding the lease reaches out: the politeness this is built
// around is a rate per deployment rather than per replica, and three replicas
// each keeping to it would be three times the traffic at a publisher's expense.
func NewPass(db *bun.DB, logger *slog.Logger, replica string, limits sbom.Limits) *Pass {
	return &Pass{
		db: db, fetch: NewFetcher(db, limits), logger: logger,
		leases: queue.NewLeases(db), replica: replica,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Run reads until the context ends.
//
// Started whatever is configured and doing nothing where nothing is: the
// sources are read each cycle, so naming a supplier takes effect without a
// redeploy and — which matters more — so does withdrawing one. An operator who
// decides that a publisher should no longer be read should not have to redeploy
// to stop it.
func (p *Pass) Run(ctx context.Context, interval time.Duration) {
	background.Every(ctx, interval, betweenCycles, func(ctx context.Context) {
		p.interval = interval
		took, err := p.Once(ctx)
		switch {
		case err != nil:
			// Logged and carried on, like every other background pass here. A
			// publisher having a bad day is not a reason to stop, and this
			// answer is evidence beside a finding rather than something the
			// rest depends on.
			if ctx.Err() == nil {
				p.logger.Error("reading what suppliers have published", "error", err)
			}
		case took.Documents > 0 || took.Refused > 0 || took.Mismatched > 0:
			p.logger.Info("read what suppliers have published",
				"documents", took.Documents, "checked", took.Checked, "claims", took.Recorded,
				"refused", took.Refused, "mismatched", took.Mismatched,
				"other_documents", took.Skipped)
		}
	})
}

// Once reads every supplier that is due one, reporting what it took.
func (p *Pass) Once(ctx context.Context) (Taken, error) {
	var took Taken
	mine, err := p.fetching(ctx)
	if err != nil || !mine {
		// Somebody else is doing it. Not an error and not worth saying: the
		// work happens either way, and a cycle that skipped is the ordinary
		// case on every replica but one.
		return took, err
	}
	every, err := p.every(ctx)
	if err != nil {
		return took, err
	}
	history, err := setting.NewStore(p.db).Count(ctx, setting.SupplierHistory,
		setting.DefaultSupplierHistory)
	if err != nil {
		return took, fmt.Errorf("read how far back to read a supplier: %w", err)
	}
	p.fetch.History = time.Duration(min(history, allHistory)) * 24 * time.Hour
	p.fetch.Keep = p.fetching

	// The deployment itself rather than anybody in it. Nobody is behind a
	// background cycle, and what this asks for is the list of suppliers it is
	// about to work through.
	sources, err := NewStore(p.db).Due(ctx,
		access.Everything("fetching what suppliers publish"), p.now().Add(-every))
	if err != nil {
		return took, err
	}
	for _, source := range sources {
		if ctx.Err() != nil {
			return took, nil
		}
		// The lease is asked for again as the pass runs rather than sized from
		// a guess at how long it takes: here between suppliers, and by the
		// fetcher before each document. A slow publisher handing the pass to a
		// second replica mid-flight is the thing the lease exists to prevent.
		switch mine, err := p.fetching(ctx); {
		case err != nil:
			return took, fmt.Errorf("keep the lease on reading what suppliers publish: %w", err)
		case !mine:
			return took, nil
		}
		one, err := p.from(ctx, source)
		took.Documents += one.Documents
		took.Recorded += one.Recorded
		took.Skipped += one.Skipped
		took.Refused += one.Refused
		took.Checked += one.Checked
		took.Mismatched += one.Mismatched
		if one.Mismatched > 0 {
			// Said per supplier, because a publisher whose digests keep
			// disagreeing reads as healthy otherwise: every fetch succeeds and
			// the documents are stepped over one at a time.
			p.logger.Warn("documents did not match the digests their publisher serves",
				"supplier", source.Display, "documents", one.Mismatched)
		}
		if err != nil {
			// Recorded against the source and carried on. One publisher
			// unreachable says nothing about the next, and a pass that stopped
			// at the first would leave every supplier after it unread for as
			// long as that one stayed down.
			p.logger.Warn("a supplier could not be read",
				"supplier", source.Display, "error", err)
		}
	}
	return took, nil
}

// from reads one supplier and records how it went, whether or not it went
// well.
//
// What came back is written even where nothing did, because "this supplier has
// been unreachable for a week" is the fact an operator needs and it is the gap
// between the last attempt and the last one that worked.
//
// A pass that filled its bound leaves the supplier due rather than waiting for
// the interval. The bound is per wake and the interval is a day, so a publisher
// issuing more in a day than one pass takes would otherwise fall further behind
// every day and never catch up.
func (p *Pass) from(ctx context.Context, source Source) (Taken, error) {
	took, err := p.fetch.From(ctx, recordedAs(source), source)
	store := NewStore(p.db)
	if took.Filled && err == nil {
		if marked := store.CaughtUp(ctx, source.ID, took.CaughtUpTo, took.Mark); marked != nil {
			p.logger.Error("recording how far a supplier was read",
				"supplier", source.Display, "error", marked)
		}
		return took, nil
	}
	if marked := store.Reached(ctx, source.ID, took.CaughtUpTo, took.Mark, err); marked != nil {
		p.logger.Error("recording what came back from a supplier",
			"supplier", source.Display, "error", marked)
	}
	return took, err
}

// recordedAs is who a fetched claim is recorded as having been brought in by.
//
// The administrator who named the supplier. Configuring one is the act that
// admitted this publisher's judgment into this deployment's evidence, and it is
// the only decision anybody made — nothing chose the individual document, which
// is the whole difference between this path and an upload.
//
// It holds nothing: what it is used for is the column saying who brought a
// claim in, and every rule about who may read that claim is asked of the
// reader.
func recordedAs(source Source) access.Subject {
	return access.Subject{Kind: access.Person, ID: source.CreatedBy, Identity: source.Display}
}

// fetching reports whether this replica is the one that reaches out.
func (p *Pass) fetching(ctx context.Context) (bool, error) {
	if p.leases == nil {
		// Nothing to coordinate with. A pass built without leases is one a
		// test drives directly, where there is one of it by construction.
		return true, nil
	}
	return p.leases.Take(ctx, FetchLease, p.replica, leaseFor(p.interval))
}

// every is how long a supplier stands before it is read again.
func (p *Pass) every(ctx context.Context) (time.Duration, error) {
	held, err := setting.NewStore(p.db).Duration(ctx, setting.ScanEvery, setting.DefaultScanEvery)
	if err != nil {
		return 0, fmt.Errorf("read how often to read suppliers again: %w", err)
	}
	return held, nil
}

// leaseFor is how long to hold the lease, given how often the pass runs.
//
// Several cycles, so a replica that is briefly slow does not lose the work to
// another and then take it back; bounded below so a very short interval in a
// test does not produce a lease that has already lapsed by the time it is read.
// What keeps it alive across a long pass is the renewal inside the pass rather
// than this number.
func leaseFor(interval time.Duration) time.Duration {
	held := 5 * interval
	if held < time.Minute {
		held = time.Minute
	}
	return held
}
