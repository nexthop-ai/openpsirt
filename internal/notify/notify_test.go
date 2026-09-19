package notify_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// each gives every engine a migrated database and two people to tell things to.
func each(t *testing.T, fn func(t *testing.T, s *notify.Store, me, them access.Subject)) {
	t.Helper()
	eachWithDB(t, func(t *testing.T, _ *database.DB, s *notify.Store, me, them access.Subject) {
		fn(t, s, me, them)
	})
}

// eachWithDB is the same, for a test that needs to reach past the store — the
// sweep that carries messages out reads people as well as notifications.
func eachWithDB(t *testing.T,
	fn func(t *testing.T, db *database.DB, s *notify.Store, me, them access.Subject),
) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		rights := access.NewStore(db.DB)
		mine, err := rights.Ensure(ctx, "me@example.com", "Me", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := rights.Ensure(ctx, "them@example.com", "Them", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		fn(t, db, notify.NewStore(db.DB),
			access.NewPerson(mine.ID, "me@example.com", false, nil, 0),
			access.NewPerson(theirs.ID, "them@example.com", false, nil, 0))
	})
}

func TestAConditionOpensOnceAndClearsItself(t *testing.T) {
	// A condition clears itself where an event is acknowledged. A build that
	// stopped being scanned is one thing to be told however many times the
	// pass runs, and when it is scanned again the alert goes without
	// anybody dismissing it — otherwise the count fills with problems that
	// already went away and nobody reads it.
	each(t, func(t *testing.T, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		quiet := []notify.Holds{
			{About: "sonic/master/broadcom", Body: "not scanned for 9 days"},
			{About: "sonic/master/mellanox", Body: "not scanned for 30 days"},
		}

		opened, cleared, err := s.Reconcile(ctx, me.ID, notify.BuildQuiet, quiet)
		if err != nil {
			t.Fatal(err)
		}
		if opened != 2 || cleared != 0 {
			t.Fatalf("first pass opened %d cleared %d, want 2 and 0", opened, cleared)
		}

		// Running it again says the same thing, so nothing changes. A pass
		// that opened a second row every time is the failure this prevents.
		opened, cleared, err = s.Reconcile(ctx, me.ID, notify.BuildQuiet, quiet)
		if err != nil {
			t.Fatal(err)
		}
		if opened != 0 || cleared != 0 {
			t.Errorf("running the same pass again opened %d cleared %d, want nothing",
				opened, cleared)
		}
		if _, total, err := s.Waiting(ctx, me, 50, 0); err != nil || total != 2 {
			t.Errorf("waiting on %d after two passes (err %v), want 2", total, err)
		}

		// One build gets scanned again, so its alert stops being true.
		opened, cleared, err = s.Reconcile(ctx, me.ID, notify.BuildQuiet, quiet[:1])
		if err != nil {
			t.Fatal(err)
		}
		if opened != 0 || cleared != 1 {
			t.Errorf("after one recovered: opened %d cleared %d, want 0 and 1", opened, cleared)
		}
		rows, total, err := s.Waiting(ctx, me, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 1 || len(rows) != 1 || rows[0].About != "sonic/master/broadcom" {
			t.Errorf("the one still true should be alone: %d rows %+v", total, rows)
		}

		// And when it goes quiet again it is a new thing to be told, not an
		// edit of the old one — which is what keeps "this cleared" answerable.
		opened, cleared, err = s.Reconcile(ctx, me.ID, notify.BuildQuiet, quiet)
		if err != nil {
			t.Fatal(err)
		}
		if opened != 1 || cleared != 0 {
			t.Errorf("returning: opened %d cleared %d, want 1 and 0", opened, cleared)
		}
	})
}

func TestAnEventIsNotCollapsedIntoTheOneBeforeIt(t *testing.T) {
	// Being assigned the same finding twice is two things that happened, and
	// collapsing them loses the second — the one they have not seen.
	each(t, func(t *testing.T, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		for range 2 {
			if err := s.Tell(ctx, notify.Telling{
				PersonID: me.ID, Kind: notify.Assigned,
				Body: "CVE-2026-1 in openssl", Link: "/findings/1",
			}); err != nil {
				t.Fatal(err)
			}
		}
		if _, total, err := s.Waiting(ctx, me, 50, 0); err != nil || total != 2 {
			t.Errorf("two things happened and %d are waiting (err %v)", total, err)
		}

		// An event that named a subject would be silently deduplicated against
		// an unrelated row, so it is refused rather than accepted and reshaped.
		if err := s.Tell(ctx, notify.Telling{
			PersonID: me.ID, Kind: notify.Assigned, About: "something",
			Body: "CVE-2026-2",
		}); err == nil {
			t.Error("an event was accepted with a subject to clear against")
		}
	})
}

func TestNobodyReadsAnybodyElsesNotifications(t *testing.T) {
	each(t, func(t *testing.T, s *notify.Store, me, them access.Subject) {
		ctx := t.Context()
		if err := s.Tell(ctx, notify.Telling{
			PersonID: them.ID, Kind: notify.Assigned, Body: "work for you",
		}); err != nil {
			t.Fatal(err)
		}
		rows, total, err := s.Waiting(ctx, me, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if total != 0 || len(rows) != 0 {
			t.Errorf("somebody else's notification was listed: %d %+v", total, rows)
		}

		// And the identifier is a number a caller supplies, so acknowledging
		// has to check whose it is rather than trusting it.
		theirs, _, err := s.Waiting(ctx, them, 50, 0)
		if err != nil || len(theirs) != 1 {
			t.Fatalf("the owner should see it: %d (err %v)", len(theirs), err)
		}
		if err := s.Acknowledge(ctx, me, theirs[0].ID); err == nil {
			t.Error("one person acknowledged another's notification")
		}
		if _, total, err := s.Waiting(ctx, them, 50, 0); err != nil || total != 1 {
			t.Errorf("it should still be waiting on its owner: %d (err %v)", total, err)
		}
	})
}

func TestAcknowledgingTakesItOutOfTheCount(t *testing.T) {
	each(t, func(t *testing.T, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		for _, body := range []string{"one", "two", "three"} {
			if err := s.Tell(ctx, notify.Telling{
				PersonID: me.ID, Kind: notify.SentBack, Body: body,
			}); err != nil {
				t.Fatal(err)
			}
		}
		rows, _, err := s.Waiting(ctx, me, 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Acknowledge(ctx, me, rows[0].ID); err != nil {
			t.Fatal(err)
		}
		if _, total, err := s.Waiting(ctx, me, 50, 0); err != nil || total != 2 {
			t.Errorf("after acknowledging one, %d wait (err %v), want 2", total, err)
		}
		n, err := s.AcknowledgeAll(ctx, me)
		if err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Errorf("acknowledging the rest reported %d, want 2", n)
		}
		if _, total, err := s.Waiting(ctx, me, 50, 0); err != nil || total != 0 {
			t.Errorf("nothing should wait: %d (err %v)", total, err)
		}
	})
}

func TestAPipelineKeyIsToldNothing(t *testing.T) {
	// A key is not a person. It has no notification area, and asking for one
	// answers empty rather than failing — there is nothing to refuse.
	//
	// The key is given the same identifier as the person, which is the
	// case worth testing rather than the easy one: a key's identifier comes
	// from one table and a person's from another, so the two collide as a
	// matter of course. Without asking what kind of subject this is, a key
	// numbered 3 reads and acknowledges the notifications of person 3.
	each(t, func(t *testing.T, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		if err := s.Tell(ctx, notify.Telling{
			PersonID: me.ID, Kind: notify.Assigned, Body: "yours, not a key's",
		}); err != nil {
			t.Fatal(err)
		}
		mine, _, err := s.Waiting(ctx, me, 50, 0)
		if err != nil || len(mine) != 1 {
			t.Fatalf("the person should have one: %d (err %v)", len(mine), err)
		}

		key := access.NewPipeline(me.ID, "nightly", access.Scope{ProductID: 1})
		rows, total, err := s.Waiting(ctx, key, 50, 0)
		if err != nil || total != 0 || len(rows) != 0 {
			t.Errorf("a key sharing the person's number was told %d things (err %v)",
				total, err)
		}
		if err := s.Acknowledge(ctx, key, mine[0].ID); err == nil {
			t.Error("a key acknowledged a person's notification")
		}
		if _, total, err := s.Waiting(ctx, me, 50, 0); err != nil || total != 1 {
			t.Errorf("it should still be waiting on the person: %d (err %v)", total, err)
		}
		if n, err := s.AcknowledgeAll(ctx, key); err == nil || n != 0 {
			t.Errorf("a key acknowledged everything: %d (err %v)", n, err)
		}
	})
}

func TestTwoSweepsAtOnceStillSayOneThing(t *testing.T) {
	// A deployment runs more than one of these — the chart ships two replicas
	// and each sweeps — so two processes deriving the same true thing at the
	// same moment is ordinary. The unique index is what makes it one row, and
	// nothing exercised it: the in-memory check inside a single Reconcile
	// satisfied every other test, so the index could have been absent.
	//
	// This runs the passes concurrently and asserts two things: one row, and
	// no error. A duplicate is not retryable, so before this was handled the
	// loser did not merely lose — it aborted the sweep, and every
	// administrator after it in the list was told nothing that cycle.
	each(t, func(t *testing.T, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		holding := []notify.Holds{{About: "sonic/master/broadcom", Body: "not scanned"}}

		const sweeps = 4
		errs := make(chan error, sweeps)
		start := make(chan struct{})
		for range sweeps {
			go func() {
				<-start
				_, _, err := s.Reconcile(ctx, me.ID, notify.BuildQuiet, holding)
				errs <- err
			}()
		}
		close(start)
		for range sweeps {
			if err := <-errs; err != nil {
				t.Errorf("a sweep failed because another was saying the same thing: %v", err)
			}
		}

		if _, total, err := s.Waiting(ctx, me, 50, 0); err != nil || total != 1 {
			t.Errorf("%d rows say the same true thing (err %v), want 1", total, err)
		}
	})
}

func TestOnlySomebodyWithAnAddressIsSentAnything(t *testing.T) {
	// Somebody without an address is told nothing outside the application
	// and keeps the area inside it. Narrowed in the query rather than
	// skipped after reading, so a deployment where nobody has one does no
	// work at all rather than reading every unsent row every minute.
	eachWithDB(t, func(t *testing.T, db *database.DB, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		if err := s.Tell(ctx, notify.Telling{
			PersonID: me.ID, Kind: notify.Assigned,
			Body: "CVE-2026-1 in libfoo", Link: "/findings/1",
		}); err != nil {
			t.Fatal(err)
		}

		sender := &recorder{}
		post := notify.NewPost(db.DB, sender, "https://psirt.example", discard(), "test")
		if sent, failed, err := post.Once(ctx); err != nil || sent != 0 || failed != 0 {
			t.Fatalf("with no address: sent=%d failed=%d err=%v", sent, failed, err)
		}
		if len(sender.sent) != 0 {
			t.Fatalf("a message was sent to somebody with nowhere to send it: %+v", sender.sent)
		}

		if err := access.NewStore(db.DB).SetEmail(ctx, me.ID, "ana@example", access.Recorded); err != nil {
			t.Fatal(err)
		}
		sent, failed, err := post.Once(ctx)
		if err != nil || sent != 1 || failed != 0 {
			t.Fatalf("with an address: sent=%d failed=%d err=%v", sent, failed, err)
		}
		if len(sender.sent) != 1 || sender.sent[0].to != "ana@example" {
			t.Fatalf("what was sent, and where: %+v", sender.sent)
		}

		// And once only. A row that has been carried out is not carried again
		// the next minute, which is what the sent mark is for.
		if sent, _, err := post.Once(ctx); err != nil || sent != 0 {
			t.Fatalf("the same notification was sent twice: sent=%d err=%v", sent, err)
		}
	})
}

func TestAMessageThatCannotBeSentIsLeftAloneEventually(t *testing.T) {
	// A mailbox that refuses every time has gone, and a sweep that keeps
	// trying it is one that eventually does nothing else. The row stays unsent
	// and stays readable: the area still has it, and nobody is told a message
	// arrived that did not.
	eachWithDB(t, func(t *testing.T, db *database.DB, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		if err := access.NewStore(db.DB).SetEmail(ctx, me.ID, "ana@example", access.Recorded); err != nil {
			t.Fatal(err)
		}
		if err := s.Tell(ctx, notify.Telling{
			PersonID: me.ID, Kind: notify.Assigned, Body: "CVE-2026-1 in libfoo",
		}); err != nil {
			t.Fatal(err)
		}

		sender := &recorder{fail: errors.New("no such mailbox")}
		post := notify.NewPost(db.DB, sender, "https://psirt.example", discard(), "test")
		for i := 0; i < 8; i++ {
			if _, _, err := post.Once(ctx); err != nil {
				t.Fatalf("sweep %d: %v", i, err)
			}
		}
		if len(sender.sent) != 5 {
			t.Errorf("tried %d times, want it to stop at 5", len(sender.sent))
		}
	})
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// recorder stands in for a channel, so what the sweep does with an answer is
// testable without a mail server.
type recorder struct {
	fail error
	sent []struct {
		to      string
		message notify.Message
	}
}

func (r *recorder) Name() string { return "recorder" }

// Timeout is what one message may take, which is what the sweep sizes its
// lease from. A test channel answers at once, so this is the smallest span
// that says "a message is not free".
func (r *recorder) Timeout() time.Duration { return time.Second }

func (r *recorder) Send(_ context.Context, to string, m notify.Message) error {
	r.sent = append(r.sent, struct {
		to      string
		message notify.Message
	}{to, m})
	return r.fail
}

func TestADigestCarriesOnlyWhatNothingElseSaid(t *testing.T) {
	// The digest carries what nothing else told you. Two
	// pieces of work are assigned; one produced a message of its own and
	// one did not, which is what happens when somebody assigns something
	// to themselves or when nothing could send at the time. The digest is
	// for the second.
	eachWithDB(t, func(t *testing.T, db *database.DB, s *notify.Store, me, _ access.Subject) {
		ctx := t.Context()
		rights := access.NewStore(db.DB)
		if err := rights.SetEmail(ctx, me.ID, "ana@example", access.Recorded); err != nil {
			t.Fatal(err)
		}

		// Told about one of them, the way assigning to somebody else does.
		if err := s.Tell(ctx, notify.Telling{
			PersonID: me.ID, Kind: notify.Assigned,
			Body:     "CVE-2026-1 in libfoo",
			Concerns: notify.Concerning(7, 11, 13),
		}); err != nil {
			t.Fatal(err)
		}

		told, err := notify.ToldAbout(ctx, db.DB, me.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !told[notify.Concerning(7, 11, 13)] {
			t.Error("what somebody was told about was not recorded")
		}
		if told[notify.Concerning(7, 12, 13)] {
			t.Error("something nobody was told about reads as told")
		}
	})
}

func TestNothingIsMailedAboutAConditionThatHasAlreadyCleared(t *testing.T) {
	// A condition that opens and stops being true inside one sweep interval
	// is withdrawn by the pass that derives it, and the area inside the
	// application stops showing it — so mail about it arrives with nothing to
	// reconcile it against. For a private condition the message says only
	// that there is something undisclosed needing attention: a message about
	// nothing at all.
	//
	// The sibling sweep that carries notifications to configured destinations
	// has had this rule all along, with the reason written beside it.
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
		// It stops being true before the next sweep: a scan arrived.
		if _, cleared, err := s.Reconcile(ctx, me.ID, notify.BuildQuiet, nil); err != nil || cleared != 1 {
			t.Fatalf("clearing the condition: cleared=%d err=%v", cleared, err)
		}

		sender := &recorder{}
		post := notify.NewPost(db.DB, sender, "https://psirt.example", discard(), "test")
		if sent, failed, err := post.Once(ctx); err != nil || sent != 0 || failed != 0 {
			t.Fatalf("a cleared condition was mailed: sent=%d failed=%d err=%v", sent, failed, err)
		}
		if len(sender.sent) != 0 {
			t.Errorf("what was sent about a condition that had already cleared: %+v", sender.sent)
		}
	})
}
