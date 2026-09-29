// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// ChatDelivery is what has gone to one person directly on one platform.
type ChatDelivery struct {
	bun.BaseModel `bun:"table:chat_delivery,alias:cd"`

	ID             int64      `bun:"id,pk,autoincrement"`
	NotificationID int64      `bun:"notification_id,notnull"`
	Platform       string     `bun:"platform,notnull"`
	Attempts       int        `bun:"attempts,notnull"`
	SentAt         *time.Time `bun:"sent_at"`
	Failed         string     `bun:"failed"`
	FirstSeen      time.Time  `bun:"first_seen,notnull"`
}

// ChatLease names the work of carrying notifications to chat.
const ChatLease = "notification.chat"

// peoplePerSweep is how many people one cycle sends to directly, on each
// platform.
//
// Each is two requests at most, finding them and sending to them. The lease is
// sized from the batch once per platform: half of each platform's share is
// people, and the rest is left for its channels.
const peoplePerSweep = sweepBatch / 4

// atMostComposed bounds what one message is composed from, to a person or to
// a channel.
//
// A night's scans can open hundreds of things for one reader, and they are one
// message. What is past this goes in the next cycle's.
const atMostComposed = 1000

// Talk carries notifications to the chat platforms a deployment configured:
// to a channel, and to a person directly.
//
// Its own sweep, beside the one that carries mail and the one that makes
// signed requests, because it answers a different question: what one
// recipient has been told since the last cycle, as one message. A cycle's
// worth of things to say to one person or one channel is grouped, so a night
// of scans is a message rather than a flood (REQ-80).
type Talk struct {
	db      *bun.DB
	chats   []Chat
	signal  *Signal
	baseURL string
	logger  *slog.Logger
	leases  *queue.Leases
	replica string
	now     func() time.Time
}

// NewTalk returns the sweep over db, or nil where no chat platform is
// configured, which is ordinary.
func NewTalk(db *bun.DB, chats []Chat, baseURL string, logger *slog.Logger,
	replica string) *Talk {

	if len(chats) == 0 {
		return nil
	}
	t := &Talk{
		db: db, chats: chats, signal: NewSignal(db, baseURL, logger, replica),
		baseURL: baseURL, logger: logger,
		leases: queue.NewLeases(db), replica: replica,
		now: func() time.Time { return time.Now().UTC() },
	}
	t.signal.now = func() time.Time { return t.now() }
	return t
}

// Run sweeps until the context ends.
func (t *Talk) Run(ctx context.Context, interval time.Duration) {
	background.Every(ctx, interval, betweenPosts, func(ctx context.Context) {
		if sent, failed, err := t.Once(ctx); err != nil {
			t.logger.Error("carrying notifications to chat", "error", err)
		} else if sent > 0 || failed > 0 {
			t.logger.Info("notifications carried to chat", "sent", sent, "failed", failed)
		}
	})
}

// Once carries one cycle's worth: every channel's note, then every person's.
//
// sent and failed count messages rather than notifications, because a
// message is what a platform accepted or refused.
func (t *Talk) Once(ctx context.Context) (sent, failed int, err error) {
	// One replica carries, the rest skip — the arrangement mail and the
	// signed requests use, for the same reason.
	if t.leases != nil {
		slowest := time.Duration(0)
		for _, chat := range t.chats {
			slowest = max(slowest, chat.Timeout())
		}
		// Every platform's work runs under the one lease, so it covers each
		// of them at the pace of the slowest.
		mine, err := t.leases.Take(ctx, ChatLease, t.replica,
			heldFor(slowest*time.Duration(len(t.chats))))
		if err != nil || !mine {
			return 0, 0, err
		}
	}
	offered := Offering(t.chats)
	for _, chat := range t.chats {
		s, f, err := t.channels(ctx, chat, offered)
		sent, failed = sent+s, failed+f
		if err != nil {
			return sent, failed, err
		}
		s, f, err = t.directs(ctx, chat, offered)
		sent, failed = sent+s, failed+f
		if err != nil {
			return sent, failed, err
		}
	}
	return sent, failed, nil
}

// channels posts one note to each channel on a platform, of what it has not
// yet been told.
//
// A channel is one message whatever number of destinations name it: one row
// per kind is how a destination is recorded, and a channel set up for two
// kinds is still one place somebody reads.
func (t *Talk) channels(ctx context.Context, chat Chat, offered []string) (sent, failed int, err error) {
	var destinations []Outbound
	if err := t.db.NewSelect().Model(&destinations).
		Where("retired_at IS NULL").Where("platform = ?", chat.Platform()).
		OrderExpr("id ASC").Scan(ctx); err != nil {
		return 0, 0, fmt.Errorf("read which channels there are: %w", err)
	}
	type place struct{ channel, topic string }
	var order []place
	named := map[place][]Outbound{}
	for _, to := range destinations {
		at := place{deref(to.Channel), deref(to.Topic)}
		if _, seen := named[at]; !seen {
			order = append(order, at)
		}
		named[at] = append(named[at], to)
	}

	for _, at := range order {
		// One claim per thing said and destination. A condition held by six
		// people is six rows and one thing, and claiming it a second time in
		// the same cycle would read as trying it again. The note says each
		// thing once, however many of the channel's destinations take it.
		var carried []noting
		claims := map[int64][]int64{}
		shown := map[string]bool{}
		for _, to := range named[at] {
			var rows []noting
			q := unsettled(t.db.NewSelect().Model(&rows), to).
				ColumnExpr("nt.*").
				ColumnExpr(`COALESCE(NULLIF("p"."display_name", ''), "p"."name", '') AS "product"`).
				Join(`LEFT JOIN "product" AS "p" ON "p"."id" = "nt"."product_id"`)
			q = forChannel(q, to, offered, t.now().Add(-chatHorizon)).
				OrderExpr("nt.created_at ASC, nt.id ASC").
				Limit(atMostComposed)
			if err := q.Scan(ctx, &rows); err != nil {
				return sent, failed, fmt.Errorf("read what a channel has to be told: %w", err)
			}
			said := map[string]bool{}
			for _, row := range rows {
				key := about(row.Notification)
				if said[key] {
					continue
				}
				said[key] = true
				id, err := t.signal.claim(ctx, to, row.Notification)
				if err != nil {
					return sent, failed, err
				}
				if id == 0 {
					continue
				}
				claims[to.ID] = append(claims[to.ID], id)
				if !shown[key] {
					shown[key] = true
					carried = append(carried, row)
				}
			}
		}
		if len(carried) == 0 {
			continue
		}
		postErr := chat.Post(ctx, at.channel, at.topic, noteOf(carried, t.baseURL))
		for _, to := range named[at] {
			if len(claims[to.ID]) == 0 {
				continue
			}
			if err := t.signal.settle(ctx, to, claims[to.ID], postErr); err != nil {
				return sent, failed, err
			}
		}
		if postErr != nil {
			failed++
			t.logger.Warn("a chat channel refused a note",
				"platform", chat.Platform(), "channel", at.channel, "error", postErr)
			continue
		}
		sent++
	}
	return sent, failed, nil
}

// forChannel narrows a read to what one chat channel carries.
//
// Only what is about a product, a team or the deployment: what is addressed
// to one person goes to that person. Of that, the most specific channel
// covering it: a team's before its product's, and a product's before the
// deployment's. A channel narrower than the deployment carries nothing
// undisclosed, because nobody here can see who sits in it (REQ-81); the
// deployment's carries that there is something, and the way in.
func forChannel(q *bun.SelectQuery, to Outbound, offered []string,
	since time.Time) *bun.SelectQuery {

	q = q.Where("nt.kind IN (?)", bun.List(shared())).
		Where("nt.created_at >= ?", since)
	switch {
	case to.TeamID != nil:
		return q.Where("nt.private = ?", false).Where("nt.team_id = ?", *to.TeamID)
	case to.ProductID != nil:
		return q.Where("nt.private = ?", false).
			Where("nt.product_id = ?", *to.ProductID).
			Where("NOT EXISTS (?)", covering(q, offered, "narrower.team_id = nt.team_id"))
	}
	return q.WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
		return q.Where("nt.private = ?", true).
			WhereOr("NOT EXISTS (?)", covering(q, offered,
				"narrower.product_id = nt.product_id OR narrower.team_id = nt.team_id"))
	})
}

// covering asks for a live chat channel, on a platform this deployment
// offers, taking the notification's kind and matching where.
func covering(q *bun.SelectQuery, offered []string, where string) *bun.SelectQuery {
	return q.NewSelect().
		TableExpr(`"outbound" AS "narrower"`).
		ColumnExpr("1").
		Where("narrower.retired_at IS NULL").
		Where("narrower.platform IN (?)", bun.List(offered)).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("narrower.kind = ?", Everything).WhereOr("narrower.kind = nt.kind")
		}).
		Where("(" + where + ")")
}

// directs sends one note to each person with something to be told directly
// on a platform.
func (t *Talk) directs(ctx context.Context, chat Chat, offered []string) (sent, failed int, err error) {
	since := t.now().Add(-chatHorizon)
	var people []struct {
		PersonID int64  `bun:"person_id"`
		Email    string `bun:"email"`
	}
	if err := direct(t.db.NewSelect().Model((*Notification)(nil)), chat.Platform(), offered, since).
		ColumnExpr("nt.person_id").ColumnExpr(`"pe"."email" AS "email"`).
		GroupExpr(`nt.person_id, "pe"."email"`).
		OrderExpr("MIN(nt.created_at) ASC, nt.person_id ASC").
		Limit(peoplePerSweep).
		Scan(ctx, &people); err != nil {
		return 0, 0, fmt.Errorf("read who has something to be told in chat: %w", err)
	}

	for _, person := range people {
		var rows []noting
		if err := direct(t.db.NewSelect().Model(&rows), chat.Platform(), offered, since).
			ColumnExpr("nt.*").
			ColumnExpr(`COALESCE(NULLIF("p"."display_name", ''), "p"."name", '') AS "product"`).
			Join(`LEFT JOIN "product" AS "p" ON "p"."id" = "nt"."product_id"`).
			Where("nt.person_id = ?", person.PersonID).
			OrderExpr("nt.created_at ASC, nt.id ASC").
			Limit(atMostComposed).
			Scan(ctx, &rows); err != nil {
			return sent, failed, fmt.Errorf("read what somebody has to be told in chat: %w", err)
		}
		var claimed []noting
		for _, row := range rows {
			mine, err := t.claimDirect(ctx, chat.Platform(), row.ID)
			if err != nil {
				return sent, failed, err
			}
			if mine {
				claimed = append(claimed, row)
			}
		}
		if len(claimed) == 0 {
			continue
		}

		account, findErr := chat.Find(ctx, person.Email)
		if findErr == nil && account == "" {
			// Nobody on the platform is registered to their address. They keep
			// the notification area and mail, and the rows are settled so the
			// next cycle does not ask again about the same ones.
			if err := t.settleDirect(ctx, chat.Platform(), claimed, errNotThere, true); err != nil {
				return sent, failed, err
			}
			continue
		}
		sendErr := findErr
		if sendErr == nil {
			sendErr = chat.Direct(ctx, account, noteOf(claimed, t.baseURL))
		}
		if err := t.settleDirect(ctx, chat.Platform(), claimed, sendErr, false); err != nil {
			return sent, failed, err
		}
		if sendErr != nil {
			failed++
			t.logger.Warn("a chat platform refused a direct message",
				"platform", chat.Platform(), "person", person.PersonID, "error", sendErr)
			continue
		}
		sent++
	}
	return sent, failed, nil
}

// errNotThere is why nothing went to somebody the platform does not know.
var errNotThere = errors.New("nobody on the platform is registered to their address")

// direct narrows a read of notifications to what goes to a person directly on
// one platform.
//
// What is somebody's own always does. What is about a product, a team or the
// deployment does where it is undisclosed, because a channel narrower than the
// deployment says nothing about that (REQ-81) and the deployment's says only
// that there is something; where no channel on a platform offered here covers
// it; and where the person asked for it as well as the channel.
func direct(q *bun.SelectQuery, platform string, offered []string,
	since time.Time) *bun.SelectQuery {

	return q.
		Join(`JOIN "person" AS "pe" ON "pe"."id" = "nt"."person_id"`).
		Where("nt.cleared_at IS NULL").
		// Read in the application is told already.
		Where("nt.read_at IS NULL").
		Where("nt.created_at >= ?", since).
		Where(`"pe"."email" IS NOT NULL AND "pe"."email" <> ?`, "").
		Where(`NOT EXISTS (SELECT 1 FROM "chat_preference" AS "off" `+
			`WHERE "off"."person_id" = "nt"."person_id" AND "off"."direct" = ?)`, false).
		Where(`NOT EXISTS (SELECT 1 FROM "chat_delivery" AS "went" `+
			`WHERE "went"."notification_id" = "nt"."id" AND "went"."platform" = ? `+
			`AND ("went"."sent_at" IS NOT NULL OR "went"."attempts" >= ?))`, platform, tries).
		WhereGroup(" AND ", func(q *bun.SelectQuery) *bun.SelectQuery {
			return q.Where("nt.kind NOT IN (?)", bun.List(shared())).
				WhereOr("nt.private = ?", true).
				WhereOr(`EXISTS (SELECT 1 FROM "chat_preference" AS "also" `+
					`WHERE "also"."person_id" = "nt"."person_id" AND "also"."shared" = ?)`, true).
				WhereOr("NOT EXISTS (?)", covering(q, offered,
					"(narrower.product_id IS NULL AND narrower.team_id IS NULL) "+
						"OR narrower.product_id = nt.product_id OR narrower.team_id = nt.team_id"))
		})
}

// claimDirect stakes one notification's direct delivery on a platform, and
// says whether this cycle holds it.
func (t *Talk) claimDirect(ctx context.Context, platform string, id int64) (bool, error) {
	claim := &ChatDelivery{
		NotificationID: id, Platform: platform, Attempts: 1,
		FirstSeen: t.now().UTC().Truncate(time.Microsecond),
	}
	if _, err := t.db.NewInsert().Model(claim).Exec(ctx); err == nil {
		return true, nil
	} else if !database.IsDuplicate(err) {
		return false, fmt.Errorf("claim a direct delivery: %w", err)
	}
	// Tried before and not gone. Another attempt is taken by moving the count,
	// conditionally, so two replicas reaching it together take it once.
	res, err := t.db.NewUpdate().Model((*ChatDelivery)(nil)).
		Set("attempts = attempts + 1").
		Where("notification_id = ?", id).Where("platform = ?", platform).
		Where("sent_at IS NULL").Where("attempts < ?", tries).
		Exec(ctx)
	if err != nil {
		return false, fmt.Errorf("take another attempt at a direct delivery: %w", err)
	}
	n, err := database.Affected(res)
	if err != nil {
		return false, fmt.Errorf("take another attempt at a direct delivery: %w", err)
	}
	return n > 0, nil
}

// settleDirect records how the claimed direct deliveries went. given up
// settles them for good, which is right for somebody the platform does not
// know and wrong for a platform that refused once.
func (t *Talk) settleDirect(ctx context.Context, platform string, rows []noting,
	sendErr error, givenUp bool) error {

	ids := make([]int64, len(rows))
	for i, row := range rows {
		ids[i] = row.ID
	}
	q := t.db.NewUpdate().Model((*ChatDelivery)(nil)).
		Where("notification_id IN (?)", bun.List(ids)).Where("platform = ?", platform)
	switch {
	case sendErr == nil:
		q = q.Set("sent_at = ?", t.now().UTC().Truncate(time.Microsecond)).Set("failed = ?", "")
	case givenUp:
		q = q.Set("attempts = ?", tries).Set("failed = ?", trimTo(sendErr.Error(), 400))
	default:
		q = q.Set("failed = ?", trimTo(sendErr.Error(), 400))
	}
	if _, err := q.Exec(ctx); err != nil {
		return fmt.Errorf("record how a direct message went: %w", err)
	}
	return nil
}

// ChatPreference is what a person chose about chat. No row is the defaults.
type ChatPreference struct {
	bun.BaseModel `bun:"table:chat_preference,alias:cp"`

	ID        int64     `bun:"id,pk,autoincrement"`
	PersonID  int64     `bun:"person_id,notnull"`
	Direct    bool      `bun:"direct,notnull"`
	Shared    bool      `bun:"shared,notnull"`
	UpdatedAt time.Time `bun:"updated_at,notnull"`
}

// ChatChoices is what somebody is sent in chat.
type ChatChoices struct {
	// Direct is whether they are sent direct messages at all.
	Direct bool
	// Shared is whether what a channel carries is sent to them directly as
	// well.
	Shared bool
}

// DefaultChatChoices is what somebody who never chose is sent: what is their
// own, directly, and what a channel carries only where no channel does.
var DefaultChatChoices = ChatChoices{Direct: true}

// ChatChoicesOf is what one person chose, or the defaults.
func (s *Store) ChatChoicesOf(ctx context.Context, subject access.Subject) (ChatChoices, error) {
	if subject.Kind != access.Person || subject.ID == 0 {
		return ChatChoices{}, access.Denied("read what is sent to you in chat")
	}
	var rows []ChatPreference
	if err := s.db.NewSelect().Model(&rows).
		Where("person_id = ?", subject.ID).Scan(ctx); err != nil {
		return ChatChoices{}, fmt.Errorf("read what is sent in chat: %w", err)
	}
	if len(rows) == 0 {
		return DefaultChatChoices, nil
	}
	return ChatChoices{Direct: rows[0].Direct, Shared: rows[0].Shared}, nil
}

// SetChatChoices records what somebody asked to be sent in chat.
//
// Theirs rather than an administrator's, for the reason the digest's switches
// are: a channel somebody cannot turn off is one they mute.
func (s *Store) SetChatChoices(ctx context.Context, subject access.Subject, c ChatChoices) error {
	if subject.Kind != access.Person || subject.ID == 0 {
		return access.Denied("choose what is sent to you in chat")
	}
	// What a channel carries, sent directly, with direct messages off, is a
	// setting that changes nothing.
	if c.Shared && !c.Direct {
		return refusal.New("what a channel carries is sent as a direct message: " +
			"turn direct messages on to have it")
	}
	now := s.now().Truncate(time.Microsecond)
	change := func() (int64, error) {
		res, err := s.db.NewUpdate().Model((*ChatPreference)(nil)).
			Set("direct = ?", c.Direct).Set("shared = ?", c.Shared).Set("updated_at = ?", now).
			Where("person_id = ?", subject.ID).Exec(ctx)
		if err != nil {
			return 0, fmt.Errorf("record what is sent in chat: %w", err)
		}
		return database.Affected(res)
	}
	// One statement at a time rather than one transaction: a refused insert
	// ends a transaction on PostgreSQL, and the refusal here is the ordinary
	// case of two first choices made at once, answered by writing the later
	// over the earlier.
	if n, err := change(); err != nil || n > 0 {
		return err
	}
	_, err := s.db.NewInsert().Model(&ChatPreference{
		PersonID: subject.ID, Direct: c.Direct, Shared: c.Shared, UpdatedAt: now,
	}).Exec(ctx)
	if err == nil {
		return nil
	}
	if !database.IsDuplicate(err) {
		return fmt.Errorf("record what is sent in chat: %w", err)
	}
	_, err = change()
	return err
}
