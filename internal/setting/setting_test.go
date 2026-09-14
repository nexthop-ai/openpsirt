package setting_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/setting"
)

func eachSetting(t *testing.T, fn func(t *testing.T, s *setting.Store)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)
		fn(t, setting.NewStore(db.DB))
	})
}

func TestASettingNobodyHasChangedReadsAsItsDefault(t *testing.T) {
	// Every setting has a default and most deployments change none of them, so
	// unset is the ordinary case rather than a fault.
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		got, err := s.Duration(t.Context(), setting.SessionLifetime, 12*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if got != 12*time.Hour {
			t.Errorf("unset read as %v, want the default", got)
		}
		if _, set, err := s.Get(t.Context(), setting.SessionLifetime); err != nil || set {
			t.Errorf("unset reported as set=%v (%v)", set, err)
		}
	})
}

func TestSettingSomethingTwiceRecordsTheSecondValue(t *testing.T) {
	// Written as an update and then an insert, because no upsert spelling is
	// portable across the four engines. Setting twice is what exercises both
	// halves.
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		ctx := t.Context()
		if err := s.Set(ctx, setting.SessionLifetime, "1h"); err != nil {
			t.Fatal(err)
		}
		if err := s.Set(ctx, setting.SessionLifetime, "30m"); err != nil {
			t.Fatal(err)
		}
		got, err := s.Duration(ctx, setting.SessionLifetime, 12*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if got != 30*time.Minute {
			t.Errorf("read back %v, want 30m", got)
		}
	})
}

func TestSettingSomethingToWhatItAlreadySaysIsNotAFailure(t *testing.T) {
	// The ordinary shape of setting something back to what it already said.
	// The timestamp still moves, so this does not by itself reach the case
	// where an engine reports nothing touched — the frozen-clock test beside
	// this one is what pins that.
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		ctx := t.Context()
		if err := s.Set(ctx, setting.SessionLifetime, "8h"); err != nil {
			t.Fatal(err)
		}
		if err := s.Set(ctx, setting.SessionLifetime, "8h"); err != nil {
			t.Fatalf("setting a value to what it already said: %v", err)
		}
		got, err := s.Duration(ctx, setting.SessionLifetime, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if got != 8*time.Hour {
			t.Errorf("read back %v, want 8h", got)
		}
	})
}

func TestAValueNobodyCanParseReadsAsTheDefault(t *testing.T) {
	// A setting typed by hand into the database is a tuning mistake. Refusing
	// to start over it would make that mistake an outage.
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		ctx := t.Context()
		for _, bad := range []string{"soon", "", "-5m", "0"} {
			if err := s.Set(ctx, setting.SessionLifetime, bad); err != nil {
				t.Fatal(err)
			}
			got, err := s.Duration(ctx, setting.SessionLifetime, 12*time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if got != 12*time.Hour {
				t.Errorf("%q read as %v, want the default", bad, got)
			}
		}
	})
}

func TestASettingThatCannotBeReadIsNotReportedAsUnset(t *testing.T) {
	// Every caller falls back to a default when a setting is unset, so a
	// database that cannot answer would silently swap a deployment's
	// configuration for the shipped one — including the threshold deciding
	// which deferrals need a second person. A policy that quietly becomes a
	// different policy under load is the failure nobody finds, because nothing
	// reports it.
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		// Never set: the ordinary case, and not a fault.
		if _, set, err := s.Get(t.Context(), setting.DeferralThreshold); err != nil || set {
			t.Errorf("an untouched setting read as set=%v err=%v", set, err)
		}

		// A read that cannot complete. Whatever the cause — a database in
		// trouble, a client giving up — it is not an answer, and must not read
		// as one.
		stopped, cancel := context.WithCancel(t.Context())
		cancel()

		if _, _, err := s.Get(stopped, setting.DeferralThreshold); err == nil {
			t.Error("a setting that could not be read reported as one nobody had set")
		}
		// And a caller asking for a duration is told, rather than being handed
		// the shipped default as though the deployment had never been tuned.
		if _, err := s.Duration(stopped, setting.DeferralThreshold, time.Hour); err == nil {
			t.Error("a reader was handed a default in place of a failure")
		}
		if _, err := s.Count(stopped, setting.TogetherCap, 100); err == nil {
			t.Error("a reader was handed a default in place of a failure")
		}
	})
}

// TestWhatASettingHeldIsAnsweredByTheWriteThatReplacedIt pins what the
// append-only trail records.
//
// The prior value was read in a statement of its own, before the write. Two
// administrators moving the same setting at once both read the original, so
// the second recorded a "before" that nothing ever held afterwards — a trail
// of who changed what, wrong about the what, and unfixable later because the
// value is gone.
func TestWhatASettingHeldIsAnsweredByTheWriteThatReplacedIt(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)
		ctx := t.Context()
		store := setting.NewStore(db.DB)

		// Nothing held it, which is not the same as holding the empty string.
		before, had, err := store.Change(ctx, setting.TriageFloor, "high")
		if err != nil {
			t.Fatal(err)
		}
		if had || before != "" {
			t.Errorf("a setting nobody had set reports %q, held=%v", before, had)
		}

		// And then what the previous write left.
		before, had, err = store.Change(ctx, setting.TriageFloor, "critical")
		if err != nil {
			t.Fatal(err)
		}
		if !had || before != "high" {
			t.Errorf("the change reports it held %q, held=%v, want \"high\"", before, had)
		}

		// Two at once: each answers something that was really there, and
		// exactly one of them answers the original.
		var wait sync.WaitGroup
		held := make([]string, 2)
		failures := make([]error, 2)
		wait.Add(2)
		for i, to := range []string{"medium", "low"} {
			go func() {
				defer wait.Done()
				held[i], _, failures[i] = store.Change(ctx, setting.TriageFloor, to)
			}()
		}
		wait.Wait()
		for i, err := range failures {
			if err != nil {
				t.Fatalf("changing a setting twice at once: caller %d: %v", i+1, err)
			}
		}
		// One replaced "critical" and the other replaced whatever the first
		// wrote. Neither may report a value nothing ever held.
		for i, was := range held {
			switch was {
			case "critical", "medium", "low":
			default:
				t.Errorf("caller %d reports it held %q, which nothing ever did", i+1, was)
			}
		}
		if held[0] == held[1] {
			t.Errorf("both callers report replacing %q, so one of them did not", held[0])
		}
	})
}

// TestAMintedSettingIsWrittenOnceAndEverybodyAgreesOnIt is the signing key.
//
// Two replicas starting together both found nothing and both minted, and the
// second overwrote the first — so every session signed with the losing key
// stopped verifying, a sign-in already in flight included.
func TestAMintedSettingIsWrittenOnceAndEverybodyAgreesOnIt(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		dbtest.Reset(t, db)
		ctx := t.Context()
		store := setting.NewStore(db.DB)

		const replicas = 4
		var wait sync.WaitGroup
		got := make([]string, replicas)
		failures := make([]error, replicas)
		wait.Add(replicas)
		for i := range got {
			go func() {
				defer wait.Done()
				got[i], failures[i] = store.SetIfAbsent(ctx, setting.SignInKey,
					fmt.Sprintf("minted-by-%d", i))
			}()
		}
		wait.Wait()
		for i, err := range failures {
			if err != nil {
				t.Fatalf("replica %d could not mint: %v", i+1, err)
			}
		}
		for i, key := range got {
			if key != got[0] {
				t.Errorf("replica %d signs with %q and replica 1 with %q", i+1, key, got[0])
			}
		}
		// And what is stored is what they all answered, rather than a fifth
		// value nobody is using.
		stored, found, err := store.Get(ctx, setting.SignInKey)
		if err != nil || !found {
			t.Fatalf("the minted key is not stored: %v found=%v", err, found)
		}
		if stored != got[0] {
			t.Errorf("the stored key is %q and everybody signs with %q", stored, got[0])
		}
	})
}
