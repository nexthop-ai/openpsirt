// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// Somebody who has left keeps their grants and their administrator flag, and
// is told nothing: no condition a sweep derives, no event, and nothing carried
// outside of what was opened for them before they left.
func TestSomebodyWhoHasLeftIsToldNothing(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		staying, err := rights.Ensure(ctx, "staying@example.com", "Staying", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		leaving, err := rights.Ensure(ctx, "leaving@example.com", "Leaving", new(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, leaving.ID, w.Product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		for _, who := range []*access.Account{staying, leaving} {
			if err := rights.SetEmail(ctx, who.ID, who.Identity, access.Recorded); err != nil {
				t.Fatal(err)
			}
		}
		// A build declared a month ago and never scanned: a condition every
		// administrator is told.
		if _, err := db.DB.NewUpdate().Table("target").
			Set(`"created_at" = ?`, time.Now().UTC().Add(-30*24*time.Hour)).
			Where(`"id" = ?`, w.Target.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		watch := notify.NewWatch(db.DB, discard())
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		// An event opened while they were still here, and not yet carried.
		if err := store.Tell(ctx, notify.Telling{
			PersonID: leaving.ID, Kind: notify.Assigned, Body: "before they left",
		}); err != nil {
			t.Fatal(err)
		}
		if n := open(t, w, leaving); n != 2 {
			t.Fatalf("before leaving they hold %d notifications, want 2", n)
		}

		if left, err := rights.Deactivate(ctx, leaving.ID); err != nil || !left {
			t.Fatalf("deactivate: left=%v err=%v", left, err)
		}
		if _, _, err := watch.Once(ctx); err != nil {
			t.Fatal(err)
		}
		if err := store.Tell(ctx, notify.Telling{
			PersonID: leaving.ID, Kind: notify.Assigned, Body: "after they left",
		}); err != nil {
			t.Fatal(err)
		}
		if n := open(t, w, leaving); n != 1 {
			t.Errorf("after leaving they hold %d notifications, want only the event from before", n)
		}
		if n := open(t, w, staying); n != 1 {
			t.Errorf("the administrator still here holds %d notifications, want 1", n)
		}

		sender := &recorder{}
		post := notify.NewPost(db.DB, sender, "https://psirt.example", discard(), "test")
		if _, _, err := post.Once(ctx); err != nil {
			t.Fatal(err)
		}
		for _, one := range sender.sent {
			if one.to == leaving.Identity {
				t.Errorf("mail went to somebody who has left: %q", one.message.Text)
			}
		}
		if len(sender.sent) != 1 || sender.sent[0].to != staying.Identity {
			t.Errorf("mail went to %+v, want the administrator still here alone", sender.sent)
		}
	})
}

// A direct chat message is carried on the same terms as mail.
func TestSomebodyWhoHasLeftIsSentNoDirectMessage(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		w.tell(t, notify.Telling{Kind: notify.Assigned, Body: "CVE-2026-1 in libfoo", Link: "/f/1"})
		if left, err := access.NewStore(w.db.DB).Deactivate(t.Context(), w.ana); err != nil || !left {
			t.Fatalf("deactivate: left=%v err=%v", left, err)
		}
		w.sweep(t)
		if len(w.chat.directs) != 0 {
			t.Errorf("a direct message went to somebody who has left: %v", w.chat.directs)
		}
	})
}

// The digest sweep passes over somebody who has left, so a batch of them
// cannot crowd out a subscriber who is still here, and a digest that cannot be
// assembled moves its stamp so it is tried tomorrow rather than every minute.
func TestTheDigestSkipsWhoeverHasLeftAndMovesOnFromWhatItCannotAssemble(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		subscribe := func(identity string) *access.Account {
			t.Helper()
			who, err := rights.Ensure(ctx, identity, identity, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := rights.GrantRole(ctx, who.ID, w.Product.ID, access.PublicTriage); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.NewUpdate().Model((*access.Account)(nil)).
				Set(`"email" = ?`, identity).
				Set(`"digest" = ?`, true).
				Set(`"digest_unassigned" = ?`, true).
				Where(`"id" = ?`, who.ID).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			return who
		}
		gone := subscribe("gone@example.com")
		broken := subscribe("broken@example.com")
		here := subscribe("here@example.com")
		if left, err := rights.Deactivate(ctx, gone.ID); err != nil || !left {
			t.Fatalf("deactivate: left=%v err=%v", left, err)
		}
		// An identity stored with capitals no longer resolves as itself, so
		// the digest cannot be read as its reader.
		if _, err := db.DB.NewUpdate().Model((*access.Account)(nil)).
			Set(`"identity" = ?`, "Broken@Example.com").
			Where(`"id" = ?`, broken.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		// A first digest reports nothing, so give everybody a past one.
		if _, err := db.DB.NewUpdate().Model((*access.Account)(nil)).
			Set(`"digest_sent_at" = ?`, time.Now().UTC().Add(-48*time.Hour)).
			Where(`"digest" = ?`, true).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		var logged strings.Builder
		sender := &recorder{}
		post := notify.NewPost(db.DB, sender, "https://psirt.example", textLogger(&logged), "test")
		for range 2 {
			if _, err := post.Digests(ctx); err != nil {
				t.Fatal(err)
			}
		}
		for _, one := range sender.sent {
			if one.to == gone.Identity {
				t.Errorf("a digest went to somebody who has left")
			}
		}
		if n := strings.Count(logged.String(), "could not assemble a digest"); n != 1 {
			t.Errorf("a digest that cannot be assembled was tried %d times in two sweeps, want 1:\n%s",
				n, logged.String())
		}
		if strings.Contains(logged.String(), gone.Identity) {
			t.Errorf("the sweep reached somebody who has left:\n%s", logged.String())
		}
		stamped, err := rights.ByIdentity(ctx, here.Identity)
		if err != nil {
			t.Fatal(err)
		}
		if stamped.DigestSentAt == nil || time.Since(*stamped.DigestSentAt) > time.Hour {
			t.Errorf("the subscriber still here has stamp %v, want it moved", stamped.DigestSentAt)
		}
	})
}

// open is how many notifications somebody holds that nothing has cleared.
func open(t *testing.T, w *fixture.World, who *access.Account) int {
	t.Helper()
	n, err := w.DB.DB.NewSelect().Model((*notify.Notification)(nil)).
		Where(`"person_id" = ?`, who.ID).Where(`"cleared_at" IS NULL`).Count(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// textLogger writes what a sweep logs into out.
func textLogger(out *strings.Builder) *slog.Logger {
	return slog.New(slog.NewTextHandler(out, nil))
}
