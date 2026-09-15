package notify

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// betweenPosts is how often what is unsent is carried out of the application.
//
// A minute, because the categories that leave here at all are the ones
// immediate mail only for an action calls worth interrupting somebody for, and
// an hour's delay on "this is now yours" makes the message a record of
// something rather than a prompt.
const betweenPosts = time.Minute

// sweepBatch is how many messages one cycle carries.
//
// The bound that makes the cycle's cost knowable, which is what the lease is
// sized from.
const sweepBatch = 200

// heldFor is how long a sweep holds its lease.
//
// **Long enough to cover a cycle of the work rather than an instant of it**,
// which is what the lease's own contract asks for: it is not renewed while
// the work runs. Taken for the interval between cycles instead, a batch of
// two hundred messages to a server answering slowly outlived it by an hour —
// a second replica took the lease, read the same rows, and sent every one of
// them again, because what marks a message sent is written after each
// individual send.
//
// Derived from the batch rather than picked: how many messages a cycle
// carries, times how long one of them may take, and a little either side. A
// lease is only a promise not to start a second copy, so being generous costs
// a cycle of nothing happening after a replica dies, and being mean costs
// everybody a second message.
func heldFor(perMessage time.Duration) time.Duration {
	held := time.Duration(sweepBatch) * perMessage
	if held < betweenPosts {
		return betweenPosts
	}
	return held
}

// tries is how many times one message is attempted before it is left alone.
//
// A mailbox that refuses five times has gone, and a sweep that keeps trying it
// is a sweep that eventually does nothing else. The row stays unsent and
// stays readable, which is the honest end state: the notification area still
// has it, and nobody is told a message arrived that did not.
const tries = 5

// Post carries what is unsent to whatever channel a deployment configured.
//
// A sweep rather than a queue of its own. What is unsent is the work list, so
// a message that failed needs no state to say it should be tried again — it is
// simply still unsent — and a deployment that configures mail after running
// for a week finds the last week's messages waiting rather than lost.
type Post struct {
	db      *bun.DB
	channel Channel
	baseURL string
	logger  *slog.Logger
	// leases and replica are how one process carries a message rather than
	// all of them. Every replica runs this sweep, as every replica runs the
	// others; without a lease each one reads the same unsent rows and sends
	// them, and somebody gets a message per replica.
	leases  *queue.Leases
	replica string
	now     func() time.Time
}

// channelTimeout is how long one message may take, or the shipped mail bound
// where no channel is configured.
func (p *Post) channelTimeout() time.Duration {
	if p.channel == nil {
		return defaultMailTimeout
	}
	return p.channel.Timeout()
}

// PostLease names the work of carrying messages out of the application.
const PostLease = "notification.post"

// NewPost returns a sweep over db, or nil where no channel is configured.
//
// Nil because a deployment without mail is ordinary: the notification area is
// the channel that always exists, and it needs nothing set up.
func NewPost(db *bun.DB, channel Channel, baseURL string, logger *slog.Logger,
	replica string) *Post {

	if channel == nil {
		return nil
	}
	return &Post{
		db: db, channel: channel, baseURL: baseURL, logger: logger,
		leases: queue.NewLeases(db), replica: replica,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// Run sweeps until the context ends.
func (p *Post) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = betweenPosts
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if sent, err := p.Digests(ctx); err != nil {
			p.logger.Error("sending digests", "error", err)
		} else if sent > 0 {
			p.logger.Info("digests sent", "channel", p.channel.Name(), "sent", sent)
		}
		if sent, failed, err := p.Once(ctx); err != nil {
			// Logged and carried on, like every other background pass here.
			p.logger.Error("carrying notifications out of the application", "error", err)
		} else if sent > 0 || failed > 0 {
			p.logger.Info("notifications sent",
				"channel", p.channel.Name(), "sent", sent, "failed", failed)
		}
		timer.Reset(interval)
	}
}

// waiting is one notification to carry, with where it goes.
type waiting struct {
	Notification `bun:",extend"`
	Email        string `bun:"email"`
}

// Once carries everything that is waiting.
//
// Ordered oldest first, so a backlog drains in the order things happened
// rather than in the order a query felt like.
func (p *Post) Once(ctx context.Context) (sent, failed int, err error) {
	// One replica carries, the rest skip. Not an error and not worth saying:
	// the work happens either way, and a skipped cycle is the ordinary case
	// on every replica but one.
	if p.leases != nil {
		mine, err := p.leases.Take(ctx, PostLease, p.replica, heldFor(p.channelTimeout()))
		if err != nil || !mine {
			return 0, 0, err
		}
	}

	var rows []waiting
	err = p.db.NewSelect().
		Model((*Notification)(nil)).
		ColumnExpr("nt.*").
		ColumnExpr(`pe.email AS "email"`).
		Join(`JOIN "person" AS "pe" ON pe.id = nt.person_id`).
		Where("nt.sent_at IS NULL").
		// A condition the application has already withdrawn is not news. The
		// sibling sweep carries the rule and this one did not, so mail went
		// about a build that had resumed being scanned or an embargo whose
		// date had moved — and the area inside the application does not show
		// it, so there is nothing to reconcile the message against. For a
		// private condition the message says only that there is something
		// undisclosed needing attention: a message about nothing at all.
		Where("nt.cleared_at IS NULL").
		Where("nt.attempts < ?", tries).
		// Somebody with no address is told nothing outside the
		// application and keeps the area inside it. Excluded in the
		// query rather than skipped after reading, so a deployment
		// where nobody has an address does no work at all.
		Where("pe.email IS NOT NULL AND pe.email <> ?", "").
		OrderExpr("nt.created_at ASC, nt.id ASC").
		Limit(sweepBatch).
		Scan(ctx, &rows)
	if err != nil {
		return 0, 0, fmt.Errorf("read what is waiting to be sent: %w", err)
	}

	for _, row := range rows {
		message := Compose(row.Notification, p.baseURL)
		sendErr := p.channel.Send(ctx, row.Email, message)
		if sendErr != nil {
			failed++
			// Counted rather than recorded as a failure: the row is still
			// unsent, which is already the whole of "try this again".
			if _, err := p.db.NewUpdate().Model((*Notification)(nil)).
				Set("attempts = attempts + 1").
				Where("id = ?", row.ID).Exec(ctx); err != nil {
				return sent, failed, fmt.Errorf("record a failed send: %w", err)
			}
			p.logger.Warn("could not carry a notification out of the application",
				"channel", p.channel.Name(), "notification", row.ID, "error", sendErr)
			continue
		}
		now := p.now()
		if _, err := p.db.NewUpdate().Model((*Notification)(nil)).
			Set("sent_at = ?", now).
			Set("attempts = attempts + 1").
			Where("id = ?", row.ID).Exec(ctx); err != nil {
			// Sent and not recorded as sent, which the next sweep will send
			// again. Reported rather than swallowed: a duplicate message is a
			// small harm and an unexplained one is a confusing one.
			return sent, failed, fmt.Errorf("record that a notification was sent: %w", err)
		}
		sent++
	}
	return sent, failed, nil
}

// atMostInADigest bounds one message.
//
// A person who has never opened the tool holds however much has accumulated,
// and a mail listing eight hundred things is one nobody reads to the end. What
// is over the bound is still in the application, which is where somebody works
// through it.
const atMostInADigest = 50

// Digests sends one message to each person who asked for one.
//
// Daily rather than per event: that is what makes it a digest, and what
// separates it from the categories immediate mail only for an action says are
// worth interrupting somebody for. A person is sent nothing where there is
// nothing to say.
func (p *Post) Digests(ctx context.Context) (sent int, err error) {
	// A lease of its own, for the reason the two constants are separate: a
	// cycle of immediate messages and a day's digests are different work and
	// one holding the other's lease would stop it.
	if p.leases != nil {
		mine, err := p.leases.Take(ctx, DigestLease, p.replica, heldFor(p.channelTimeout()))
		if err != nil || !mine {
			return 0, err
		}
	}

	var people []access.Account
	if err := p.db.NewSelect().Model(&people).
		Where("digest = ?", true).
		// Somebody with no address asked for something this cannot deliver.
		// Narrowed here so a deployment where nobody has one does no work.
		Where("email IS NOT NULL AND email <> ?", "").
		// One a day. The sweep runs far more often than that, because it
		// carries the immediate messages too.
		Where("digest_sent_at IS NULL OR digest_sent_at < ?", p.now().Add(-aDay)).
		// Bounded like every other read here. A deployment with more people
		// than this sends the rest on the next cycle rather than holding the
		// lease for as long as it takes.
		Limit(sweepBatch).
		Scan(ctx, &people); err != nil {
		return 0, fmt.Errorf("read who asked for a digest: %w", err)
	}

	for i := range people {
		person := &people[i]
		// Taken before the read, and written after. A stamp taken afterwards
		// covers the time the queries and the send took — seconds, and a
		// synchronous send can take the whole timeout — and anything that
		// opened inside it belongs to no digest at all: too late for this
		// one's "since", too early for the next one's.
		asOf := p.now()
		digest, err := Assemble(ctx, p.db, person, atMostInADigest)
		if err != nil {
			p.logger.Warn("could not assemble a digest",
				"person", person.Identity, "error", err)
			continue
		}
		// Nothing to say is not a message. A daily "nothing" is how somebody
		// learns to stop opening the daily message, and the ones that say
		// something go unread with it.
		//
		// The stamp still moves. Otherwise a quiet week means the next digest
		// reports the whole week as new, and "since the last digest" stops
		// meaning what it says.
		if !digest.Empty() {
			if err := p.channel.Send(ctx, person.Email, digest.Message(p.baseURL)); err != nil {
				p.logger.Warn("could not send a digest",
					"channel", p.channel.Name(), "person", person.Identity, "error", err)
				// The stamp still moves. A mailbox that refuses is retried
				// tomorrow rather than every minute until it answers — the
				// same reason an immediate message stops after five, and the
				// digest is the pass that would otherwise do nothing else.
			} else {
				sent++
			}
		}
		if _, err := p.db.NewUpdate().Model((*access.Account)(nil)).
			Set("digest_sent_at = ?", asOf).
			Where("id = ?", person.ID).Exec(ctx); err != nil {
			// Reported and carried on, like the sends above. Abandoning the
			// rest of the list because one row would not update leaves
			// everybody after this person unsent for the cycle.
			p.logger.Warn("could not record that a digest went",
				"person", person.Identity, "error", err)
		}
	}
	return sent, nil
}

// aDay is how long between digests.
const aDay = 24 * time.Hour

// DigestLease names the work of assembling and sending digests. Separate from
// the immediate messages so that a long digest cycle does not stop the
// messages immediate mail only for an action says are worth interrupting
// somebody for.
const DigestLease = "notification.digest"
