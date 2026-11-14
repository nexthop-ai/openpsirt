// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// The kinds mailed as they happen are kinds there are, each named once.
func TestEveryKindMailedAtOnceIsAKind(t *testing.T) {
	known := map[notify.Kind]bool{}
	for _, kind := range notify.Kinds() {
		known[kind] = true
	}
	seen := map[notify.Kind]bool{}
	for _, kind := range notify.ImmediateKinds() {
		if !known[kind] {
			t.Errorf("%q is mailed at once and is no kind", kind)
		}
		if seen[kind] {
			t.Errorf("%q is listed twice", kind)
		}
		seen[kind] = true
	}
	if len(seen) == 0 {
		t.Fatal("no kind is mailed at once, so this checked nothing")
	}
	if len(seen) == len(known) {
		t.Error("every kind is mailed at once, so nothing is left to the digest")
	}
}

// Mail carries only what a person must act on as it happens. A build that
// stopped being scanned is told in the area, and mail leaves it to the digest.
func TestOnlyWhatAPersonMustActOnIsMailedAtOnce(t *testing.T) {
	eachWithDB(t, func(t *testing.T, db *database.DB, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		if err := access.NewStore(db.DB).SetEmail(ctx, me.ID, "ana@example", access.Recorded); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Reconcile(ctx, me.ID, notify.BuildQuiet, []notify.Holds{{
			About: "build-quiet sonic master broadcom",
			Body:  "Nothing has been filed against sonic master broadcom.",
			Link:  "/builds/1",
		}}); err != nil {
			t.Fatal(err)
		}
		if err := s.Tell(ctx, notify.Telling{
			PersonID: me.ID, Kind: notify.Assigned, Body: "CVE-2026-1 in libfoo", Link: "/findings/1",
		}); err != nil {
			t.Fatal(err)
		}

		sender := &recorder{}
		post := notify.NewPost(db.DB, sender, "https://psirt.example", discard(), "test")
		if sent, failed, err := post.Once(ctx); err != nil || sent != 1 || failed != 0 {
			t.Fatalf("sent=%d failed=%d err=%v, want the assignment alone", sent, failed, err)
		}
		if got := sender.sent[0].message.Subject; got != "Work assigned to you" {
			t.Errorf("mail went with subject %q, want the assignment's", got)
		}
	})
}

// The digest carries every notice mail left to it: disclosed ones by their
// words, undisclosed ones as a count, and nothing mail already carried or the
// last digest already said.
func TestADigestCarriesTheNoticesMailLeftToIt(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		reader, err := rights.Ensure(ctx, "reader@example.com", "Rhea Reader", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		product := w.Product
		if err := rights.GrantRole(ctx, reader.ID, product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		lastDigest := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
		if _, err := db.DB.NewUpdate().Model((*access.Account)(nil)).
			Set(`"email" = ?`, "reader@example.com").
			Set(`"digest" = ?`, true).
			Set(`"digest_sent_at" = ?`, lastDigest).
			Where(`"id" = ?`, reader.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		for _, each := range []notify.Telling{
			{Kind: notify.MergeSuperseded, Body: "Two decisions on CVE-2026-9 met in\nsonic."},
			{Kind: notify.InventoryMoved, Body: "SONIC-2026-77 moved", Private: true, ProductID: &product.ID},
			{Kind: notify.Assigned, Body: "CVE-2026-1 in libfoo"},
			{Kind: notify.Disclosed, Body: "CVE-2026-5 was said before the last digest"},
			{Kind: notify.BuildQuiet, Body: "CVE-2026-7 went by mail as it happened"},
		} {
			each.PersonID = reader.ID
			if err := store.Tell(ctx, each); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.DB.NewUpdate().Model((*notify.Notification)(nil)).
			Set(`"created_at" = ?`, lastDigest.Add(-time.Hour)).
			Where(`"kind" = ?`, notify.Disclosed).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		// Mailed as it happened by a release that mailed every kind.
		if _, err := db.DB.NewUpdate().Model((*notify.Notification)(nil)).
			Set(`"sent_at" = ?`, lastDigest.Add(time.Hour)).
			Where(`"kind" = ?`, notify.BuildQuiet).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		sender := &recorder{}
		post := notify.NewPost(db.DB, sender, "https://psirt.example", discard(), "test")
		if _, err := post.Digests(ctx); err != nil {
			t.Fatal(err)
		}
		if len(sender.sent) != 1 {
			t.Fatalf("%d digests were sent, want 1", len(sender.sent))
		}
		text := sender.sent[0].message.Text
		for _, want := range []string{
			"2 notices in your notifications",
			"Two decisions met when two issues merged: Two decisions on CVE-2026-9 met in sonic.",
			"1 notice about undisclosed work, not named here.",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("the digest does not say %q:\n%s", want, text)
			}
		}
		for _, absent := range []string{"SONIC-2026-77", "CVE-2026-1", "CVE-2026-5", "CVE-2026-7"} {
			if strings.Contains(text, absent) {
				t.Errorf("the digest carries %q:\n%s", absent, text)
			}
		}
	})
}

// A mail server refused for offering no STARTTLS refuses every message alike,
// and none of it is a message's fault: nothing is counted against them, so they
// go once the configuration changes.
func TestMailRefusedForItsServerWaitsForTheConfiguration(t *testing.T) {
	eachWithDB(t, func(t *testing.T, db *database.DB, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		if err := access.NewStore(db.DB).SetEmail(ctx, me.ID, "ana@example", access.Recorded); err != nil {
			t.Fatal(err)
		}
		if err := s.Tell(ctx, notify.Telling{
			PersonID: me.ID, Kind: notify.Assigned, Body: "CVE-2026-1 in libfoo", Link: "/findings/1",
		}); err != nil {
			t.Fatal(err)
		}
		refused := &recorder{fail: fmt.Errorf("%w, and plain mail is not accepted", notify.ErrUnsecured)}
		for range 10 {
			if _, _, err := notify.NewPost(db.DB, refused, "https://psirt.example", discard(), "test").
				Once(ctx); err != nil {
				t.Fatal(err)
			}
		}
		sender := &recorder{}
		if sent, _, err := notify.NewPost(db.DB, sender, "https://psirt.example", discard(), "test").
			Once(ctx); err != nil || sent != 1 {
			t.Errorf("once the server is accepted, %d sent: %v; want the waiting message", sent, err)
		}
	})
}

// A digest refused for its server's missing STARTTLS is not a digest sent: the
// stamp stays, and the digest goes once the configuration changes.
func TestADigestRefusedForItsServerWaitsForTheConfiguration(t *testing.T) {
	fixture.Each(t, func(t *testing.T, w *fixture.World) {
		db := w.DB
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		reader, err := rights.Ensure(ctx, "reader@example.com", "Rhea Reader", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := rights.GrantRole(ctx, reader.ID, w.Product.ID, access.PrivateTriage); err != nil {
			t.Fatal(err)
		}
		lastDigest := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
		if _, err := db.DB.NewUpdate().Model((*access.Account)(nil)).
			Set(`"email" = ?`, "reader@example.com").
			Set(`"digest" = ?`, true).
			Set(`"digest_sent_at" = ?`, lastDigest).
			Where(`"id" = ?`, reader.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if err := notify.NewStore(db.DB).Tell(ctx, notify.Telling{
			PersonID: reader.ID, Kind: notify.MergeSuperseded, Body: "Two decisions on CVE-2026-9 met",
		}); err != nil {
			t.Fatal(err)
		}
		refused := &recorder{fail: fmt.Errorf("%w, and plain mail is not accepted", notify.ErrUnsecured)}
		if _, err := notify.NewPost(db.DB, refused, "https://psirt.example", discard(), "test").
			Digests(ctx); err != nil {
			t.Fatal(err)
		}
		if len(refused.sent) != 1 {
			t.Fatalf("%d digests were offered to the refusing server, want 1", len(refused.sent))
		}
		var stamped time.Time
		if err := db.DB.NewSelect().Model((*access.Account)(nil)).Column("digest_sent_at").
			Where(`"id" = ?`, reader.ID).Scan(ctx, &stamped); err != nil {
			t.Fatal(err)
		}
		if !stamped.Equal(lastDigest) {
			t.Errorf("a refused digest moved the stamp to %v", stamped)
		}
		sender := &recorder{}
		if sent, err := notify.NewPost(db.DB, sender, "https://psirt.example", discard(), "test").
			Digests(ctx); err != nil || sent != 1 {
			t.Errorf("once the server is accepted, %d digests sent: %v; want the waiting one", sent, err)
		}
	})
}
