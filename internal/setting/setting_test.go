package setting_test

import (
	"context"
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
