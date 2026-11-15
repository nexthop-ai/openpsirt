// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// stuckDigests is a channel whose mail server takes a digest and never answers,
// and carries every other message at once.
type stuckDigests struct {
	digestStarted chan struct{}
	carried       chan notify.Message
}

func (s *stuckDigests) Name() string           { return "stuck" }
func (s *stuckDigests) Timeout() time.Duration { return time.Second }

func (s *stuckDigests) Send(ctx context.Context, _ string, m notify.Message) error {
	if m.Subject == "Your daily digest" {
		select {
		case s.digestStarted <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}
	select {
	case s.carried <- m:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// A digest stuck on its mail server holds no immediate message: the two run
// in loops of their own, so a day's digests on one replica never stand in
// front of an assignment.
func TestADigestStuckOnItsMailServerDoesNotHoldImmediateMail(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		rights := access.NewStore(db.DB)
		me, err := rights.Ensure(ctx, "reader@example.com", "Rhea Reader", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, me.ID, w.Product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.NewUpdate().Model((*access.Account)(nil)).
			Set(`"email" = ?`, "reader@example.com").
			Set(`"digest" = ?`, true).
			Where(`"id" = ?`, me.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		s := notify.NewStore(db.DB)
		if err := s.Tell(ctx, notify.Telling{
			PersonID: me.ID, Kind: notify.MergeSuperseded, Body: "Two decisions on CVE-2026-9 met in sonic.",
		}); err != nil {
			t.Fatal(err)
		}

		channel := &stuckDigests{digestStarted: make(chan struct{}, 1), carried: make(chan notify.Message, 1)}
		post := notify.NewPost(db.DB, channel, "https://psirt.example", discard(), "test")
		done := make(chan struct{}, 2)
		go func() { post.RunDigests(ctx, time.Hour); done <- struct{}{} }()
		select {
		case <-channel.digestStarted:
		case <-time.After(30 * time.Second):
			t.Fatal("no digest was sent, so this checked nothing")
		}

		if err := s.Tell(ctx, notify.Telling{
			PersonID: me.ID, Kind: notify.Assigned, Body: "CVE-2026-1 in libfoo", Link: "/findings/1",
		}); err != nil {
			t.Fatal(err)
		}
		go func() { post.Run(ctx, time.Hour); done <- struct{}{} }()
		select {
		case m := <-channel.carried:
			if m.Subject != "Work assigned to you" {
				t.Errorf("mail went with subject %q, want the assignment's", m.Subject)
			}
		case <-time.After(30 * time.Second):
			t.Error("the assignment waited behind a digest stuck on its mail server")
		}
		cancel()
		<-done
		<-done
	})
}
