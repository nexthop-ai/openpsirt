// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// fakeChat stands in for a chat platform, so what the sweep sends where is
// testable without one.
type fakeChat struct {
	platform string
	// known is the accounts the platform holds, by address.
	known map[string]string
	fail  error

	mu      sync.Mutex
	finds   int
	directs map[string][]notify.Note
	posts   map[string][]notify.Note
}

func newFakeChat(platform string, known map[string]string) *fakeChat {
	return &fakeChat{
		platform: platform, known: known,
		directs: map[string][]notify.Note{}, posts: map[string][]notify.Note{},
	}
}

func (f *fakeChat) Platform() string       { return f.platform }
func (f *fakeChat) Timeout() time.Duration { return time.Second }

func (f *fakeChat) Find(_ context.Context, email string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finds++
	return f.known[email], nil
}

func (f *fakeChat) Direct(_ context.Context, account string, n notify.Note) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.directs[account] = append(f.directs[account], n)
	return f.fail
}

func (f *fakeChat) Post(_ context.Context, channel, _ string, n notify.Note) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.posts[channel] = append(f.posts[channel], n)
	return f.fail
}

// said is everything a set of notes says, as one string to search.
func said(notes []notify.Note) string {
	var b strings.Builder
	for _, n := range notes {
		b.WriteString(n.Plain() + "\n")
	}
	return b.String()
}

// chatWorld is a deployment with an administrator, a triager on the
// platform, and two products.
type chatWorld struct {
	db       *database.DB
	store    *notify.Store
	admin    access.Subject
	ana      int64
	kernel   int64
	firmware int64
	chat     *fakeChat
	talk     *notify.Talk
}

func eachChat(t *testing.T, fn func(t *testing.T, w *chatWorld)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		rights := access.NewStore(db.DB)
		admin, err := rights.Ensure(ctx, "admin@example.com", "Admin", access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		ana, err := rights.Ensure(ctx, "ana@example.com", "Ana", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.SetEmail(ctx, ana.ID, "ana@example.com", access.Recorded); err != nil {
			t.Fatal(err)
		}
		products := catalog.NewStore(db.DB)
		kernel, err := products.DeclareProduct(ctx, "kernel", "Kernel")
		if err != nil {
			t.Fatal(err)
		}
		firmware, err := products.DeclareProduct(ctx, "firmware", "Firmware")
		if err != nil {
			t.Fatal(err)
		}
		chat := newFakeChat(notify.Slack, map[string]string{"ana@example.com": "U-ANA"})
		fn(t, &chatWorld{
			db: db, store: notify.NewStore(db.DB), admin: asks(t, db, admin), ana: ana.ID,
			kernel: kernel.ID, firmware: firmware.ID, chat: chat,
			talk: notify.NewTalk(db.DB, []notify.Chat{chat}, "https://psirt.example", discard(), "test"),
		})
	})
}

// channel configures a chat channel.
func (w *chatWorld) channel(t *testing.T, name string, d notify.Destination) {
	t.Helper()
	d.Name, d.Channel = name, name
	if d.Kind == "" {
		d.Kind = notify.Everything
	}
	if d.Platform == "" {
		d.Platform = notify.Slack
	}
	if _, err := w.store.AddDestination(t.Context(), w.admin, d,
		[]string{notify.Slack, notify.Zulip}); err != nil {
		t.Fatal(err)
	}
}

// tell records an event for Ana.
func (w *chatWorld) tell(t *testing.T, telling notify.Telling) {
	t.Helper()
	telling.PersonID = w.ana
	if err := w.store.Tell(t.Context(), telling); err != nil {
		t.Fatal(err)
	}
}

// hold opens a condition for Ana.
func (w *chatWorld) hold(t *testing.T, kind notify.Kind, holds ...notify.Holds) {
	t.Helper()
	if _, _, err := w.store.Reconcile(t.Context(), w.ana, kind, holds); err != nil {
		t.Fatal(err)
	}
}

func (w *chatWorld) sweep(t *testing.T) {
	t.Helper()
	if _, _, err := w.talk.Once(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestWhatIsSomebodysOwnGoesToThemAndNeverToAChannel(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		w.channel(t, "psirt", notify.Destination{})
		w.tell(t, notify.Telling{Kind: notify.Assigned, Body: "CVE-2026-1 in libfoo", Link: "/f/1"})
		w.sweep(t)

		if got := said(w.chat.directs["U-ANA"]); !strings.Contains(got, "CVE-2026-1 in libfoo") {
			t.Errorf("Ana was not told directly: %q", got)
		}
		if len(w.chat.posts["psirt"]) != 0 {
			t.Errorf("a channel was told what is somebody's own: %q", said(w.chat.posts["psirt"]))
		}
	})
}

func TestWhatAChannelCarriesIsNotSentDirectlyAsWell(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		w.channel(t, "psirt", notify.Destination{})
		w.hold(t, notify.BuildQuiet, notify.Holds{
			About: "quiet-1", Body: "kernel main has not been scanned", ProductID: &w.kernel,
		})
		w.sweep(t)

		if got := said(w.chat.posts["psirt"]); !strings.Contains(got, "kernel main") {
			t.Errorf("the channel was not told: %q", got)
		}
		if len(w.chat.directs["U-ANA"]) != 0 {
			t.Errorf("Ana was told directly what the channel carries: %q",
				said(w.chat.directs["U-ANA"]))
		}
	})
}

func TestWhatNoChannelCarriesIsSentDirectly(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		// A channel for another product covers nothing about this one.
		w.channel(t, "firmware", notify.Destination{ProductID: &w.firmware})
		w.hold(t, notify.BuildQuiet, notify.Holds{
			About: "quiet-1", Body: "kernel main has not been scanned", ProductID: &w.kernel,
		})
		w.sweep(t)

		if got := said(w.chat.directs["U-ANA"]); !strings.Contains(got, "kernel main") {
			t.Errorf("Ana was not told what no channel carries: %q", got)
		}
		if len(w.chat.posts["firmware"]) != 0 {
			t.Errorf("another product's channel was told: %q", said(w.chat.posts["firmware"]))
		}
	})
}

func TestAChannelOnAPlatformNotOfferedCoversNothing(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		// Configured while Zulip was, and left behind when it stopped being.
		w.channel(t, "zulip-psirt", notify.Destination{Platform: notify.Zulip})
		w.hold(t, notify.BuildQuiet, notify.Holds{
			About: "quiet-1", Body: "kernel main has not been scanned", ProductID: &w.kernel,
		})
		w.sweep(t)

		if got := said(w.chat.directs["U-ANA"]); !strings.Contains(got, "kernel main") {
			t.Errorf("a channel nothing posts to kept Ana from being told: %q", got)
		}
	})
}

func TestTheMostSpecificChannelCarriesIt(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		kernelTeam, err := access.NewStore(w.db.DB).DeclareTeam(t.Context(), "kernel-team", "Kernel team")
		if err != nil {
			t.Fatal(err)
		}
		w.channel(t, "psirt", notify.Destination{})
		w.channel(t, "kernel", notify.Destination{ProductID: &w.kernel})
		w.channel(t, "kernel-team", notify.Destination{TeamID: &kernelTeam.ID})

		w.hold(t, notify.QueueUntaken, notify.Holds{
			About: "queue-1", Body: "Kernel team has 3 waiting in kernel",
			ProductID: &w.kernel, TeamID: &kernelTeam.ID,
		})
		w.hold(t, notify.BuildQuiet, notify.Holds{
			About: "quiet-kernel", Body: "kernel main has not been scanned", ProductID: &w.kernel,
		}, notify.Holds{
			About: "quiet-firmware", Body: "firmware main has not been scanned", ProductID: &w.firmware,
		})
		w.sweep(t)

		team, product, deployment := said(w.chat.posts["kernel-team"]),
			said(w.chat.posts["kernel"]), said(w.chat.posts["psirt"])
		if !strings.Contains(team, "3 waiting") || strings.Contains(product+deployment, "3 waiting") {
			t.Errorf("a team's queue went somewhere other than its channel alone:\n"+
				"team %q\nproduct %q\ndeployment %q", team, product, deployment)
		}
		if !strings.Contains(product, "kernel main") || strings.Contains(deployment, "kernel main") {
			t.Errorf("a product's notification went somewhere other than its channel alone:\n"+
				"product %q\ndeployment %q", product, deployment)
		}
		if !strings.Contains(deployment, "firmware main") {
			t.Errorf("what no narrower channel covers did not reach the deployment's: %q", deployment)
		}
	})
}

// REQ-80.
func TestANarrowChannelSaysNothingUndisclosed(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		w.channel(t, "psirt", notify.Destination{})
		w.channel(t, "kernel", notify.Destination{ProductID: &w.kernel})
		w.hold(t, notify.DisclosureNear, notify.Holds{
			About: "embargo-1", Body: "CVE-2026-9 in the kernel lifts its embargo on Friday",
			Private: true, ProductID: &w.kernel,
		})
		w.sweep(t)

		if len(w.chat.posts["kernel"]) != 0 {
			t.Errorf("a product's channel was told something undisclosed: %q",
				said(w.chat.posts["kernel"]))
		}
		deployment, direct := said(w.chat.posts["psirt"]), said(w.chat.directs["U-ANA"])
		for where, got := range map[string]string{"the deployment's channel": deployment, "Ana": direct} {
			if !strings.Contains(got, "not been disclosed") {
				t.Errorf("%s was not told there is something: %q", where, got)
			}
			if strings.Contains(got, "CVE-2026-9") || strings.Contains(got, "Friday") {
				t.Errorf("%s was told what the embargo is: %q", where, got)
			}
		}
	})
}

// REQ-79.
func TestManyThingsForOnePersonAreOneMessage(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		for i := 0; i < 30; i++ {
			w.tell(t, notify.Telling{Kind: notify.Assigned, Body: "work in the kernel",
				Link: "/f", ProductID: &w.kernel})
		}
		for i := 0; i < 5; i++ {
			w.tell(t, notify.Telling{Kind: notify.Assigned, Body: "work in firmware",
				Link: "/f", ProductID: &w.firmware})
		}
		w.tell(t, notify.Telling{Kind: notify.Mentioned, Body: "Bo named you", Link: "/n"})
		w.sweep(t)

		notes := w.chat.directs["U-ANA"]
		if len(notes) != 1 {
			t.Fatalf("Ana was sent %d messages, want one: %q", len(notes), said(notes))
		}
		got := notes[0].Plain()
		for _, want := range []string{"36 notifications", "in Kernel: 30", "in Firmware: 5", "Bo named you"} {
			if !strings.Contains(got, want) {
				t.Errorf("the one message does not say %q:\n%s", want, got)
			}
		}

		// And nothing the next minute: it has all gone.
		w.sweep(t)
		if len(w.chat.directs["U-ANA"]) != 1 {
			t.Errorf("what went was sent again: %q", said(w.chat.directs["U-ANA"]))
		}
	})
}

func TestSomebodyWhoAskedIsSentWhatTheChannelCarriesToo(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		w.channel(t, "psirt", notify.Destination{})
		if err := w.store.SetChatChoices(t.Context(), asksByID(t, w.db, w.ana),
			notify.ChatChoices{Direct: true, Shared: true}); err != nil {
			t.Fatal(err)
		}
		w.hold(t, notify.BuildQuiet, notify.Holds{
			About: "quiet-1", Body: "kernel main has not been scanned", ProductID: &w.kernel,
		})
		w.sweep(t)

		if !strings.Contains(said(w.chat.directs["U-ANA"]), "kernel main") {
			t.Errorf("Ana asked for what the channels carry and was not sent it")
		}
		if !strings.Contains(said(w.chat.posts["psirt"]), "kernel main") {
			t.Errorf("the channel stopped being told because Ana asked as well")
		}
	})
}

func TestSomebodyWhoTurnedDirectMessagesOffIsSentNone(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		if err := w.store.SetChatChoices(t.Context(), asksByID(t, w.db, w.ana),
			notify.ChatChoices{}); err != nil {
			t.Fatal(err)
		}
		w.tell(t, notify.Telling{Kind: notify.Assigned, Body: "yours", Link: "/f"})
		w.sweep(t)
		if len(w.chat.directs) != 0 {
			t.Errorf("a direct message went to somebody who turned them off: %v", w.chat.directs)
		}
	})
}

func TestChatChoicesAreThePersonsOwnAndSayWhatTheyChange(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		ana := asksByID(t, w.db, w.ana)
		if got, err := w.store.ChatChoicesOf(t.Context(), ana); err != nil ||
			got != notify.DefaultChatChoices {
			t.Errorf("somebody who never chose has %+v (%v), want %+v",
				got, err, notify.DefaultChatChoices)
		}
		if err := w.store.SetChatChoices(t.Context(), ana,
			notify.ChatChoices{Shared: true}); err == nil {
			t.Error("what the channels carry was accepted with direct messages off")
		}
		for _, want := range []notify.ChatChoices{{Direct: true, Shared: true}, {}} {
			if err := w.store.SetChatChoices(t.Context(), ana, want); err != nil {
				t.Fatal(err)
			}
			if got, err := w.store.ChatChoicesOf(t.Context(), ana); err != nil || got != want {
				t.Errorf("chose %+v and read back %+v (%v)", want, got, err)
			}
		}
		key := access.NewPipeline(w.ana, "nightly", access.Scope{ProductID: w.kernel})
		if err := w.store.SetChatChoices(t.Context(), key, notify.DefaultChatChoices); err == nil {
			t.Error("a key chose what it is sent in chat")
		}
	})
}

func TestSomebodyThePlatformDoesNotKnowIsAskedAboutOnce(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		w.chat.known = map[string]string{}
		w.tell(t, notify.Telling{Kind: notify.Assigned, Body: "yours", Link: "/f"})
		w.sweep(t)
		w.sweep(t)
		if w.chat.finds != 1 {
			t.Errorf("the platform was asked %d times about the same notification, want once",
				w.chat.finds)
		}
		if len(w.chat.directs) != 0 {
			t.Errorf("something was sent to nobody: %v", w.chat.directs)
		}
	})
}

func TestADirectMessageRefusedIsTriedAgainAndThenLeftAlone(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		w.chat.fail = errors.New("channel_not_found")
		w.tell(t, notify.Telling{Kind: notify.Assigned, Body: "yours", Link: "/f"})
		for i := 0; i < 8; i++ {
			w.sweep(t)
		}
		if got := len(w.chat.directs["U-ANA"]); got != 5 {
			t.Errorf("tried %d times, want it to stop at 5", got)
		}
	})
}

func TestWhatWasReadOrIsOldIsNotCarriedToChat(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		w.tell(t, notify.Telling{Kind: notify.Assigned, Body: "read already", Link: "/f"})
		w.tell(t, notify.Telling{Kind: notify.Assigned, Body: "from last week", Link: "/f"})
		ctx := t.Context()
		if _, err := w.db.DB.NewUpdate().Model((*notify.Notification)(nil)).
			Set("read_at = ?", time.Now().UTC()).Where("body = ?", "read already").
			Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := w.db.DB.NewUpdate().Model((*notify.Notification)(nil)).
			Set("created_at = ?", time.Now().UTC().Add(-7*24*time.Hour)).
			Where("body = ?", "from last week").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		w.sweep(t)
		if len(w.chat.directs) != 0 {
			t.Errorf("chat was sent what was read or old: %q", said(w.chat.directs["U-ANA"]))
		}
	})
}

func TestAChannelIsToldAConditionHeldByManyOnce(t *testing.T) {
	eachChat(t, func(t *testing.T, w *chatWorld) {
		w.channel(t, "psirt", notify.Destination{})
		bo, err := access.NewStore(w.db.DB).Ensure(t.Context(), "bo@example.com", "Bo", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		held := notify.Holds{About: "quiet-1", Body: "kernel main has not been scanned",
			ProductID: &w.kernel}
		w.hold(t, notify.BuildQuiet, held)
		if _, _, err := w.store.Reconcile(t.Context(), bo.ID, notify.BuildQuiet,
			[]notify.Holds{held}); err != nil {
			t.Fatal(err)
		}
		w.sweep(t)
		w.sweep(t)
		// Said as one thing rather than as a group of two.
		posts := w.chat.posts["psirt"]
		if len(posts) != 1 || posts[0].Heading != "A build has stopped being scanned" {
			t.Errorf("one condition held by two people reached the channel as %q", said(posts))
		}
	})
}
