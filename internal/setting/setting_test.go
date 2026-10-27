// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

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
	// A read, then an insert or a conditional update, because no upsert
	// spelling is portable across the four engines. Setting twice exercises
	// both arms.
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		ctx := t.Context()
		if _, _, err := s.Change(ctx, setting.SessionLifetime, "1h"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Change(ctx, setting.SessionLifetime, "30m"); err != nil {
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

func TestAValueNobodyCanParseReadsAsTheDefault(t *testing.T) {
	// A setting typed by hand into the database is a tuning mistake. Refusing
	// to start over it would make that mistake an outage.
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		ctx := t.Context()
		for _, bad := range []string{"soon", "", "-5m", "0"} {
			if _, _, err := s.Change(ctx, setting.SessionLifetime, bad); err != nil {
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
		// A count the same way: nothing, or nothing positive, is the default.
		// Read as written, a zero cap refuses every bulk act it bounds.
		for _, bad := range []string{"lots", "", "-5", "0"} {
			if _, _, err := s.Change(ctx, setting.BulkDecisionCap, bad); err != nil {
				t.Fatal(err)
			}
			got, err := s.Count(ctx, setting.BulkDecisionCap, 100)
			if err != nil {
				t.Fatalf("%q: %v", bad, err)
			}
			if got != 100 {
				t.Errorf("%q read as %d, want the default", bad, got)
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
		if _, err := s.Count(stopped, setting.BulkDecisionCap, 100); err == nil {
			t.Error("a reader was handed a default in place of a failure")
		}
	})
}

// TestWhatASettingHeldIsAnsweredByTheWriteThatReplacedIt pins what the
// append-only trail records.
//
// Read in a statement of its own before the write, the prior value is the
// original for two administrators moving the same setting at once, so the
// second records a "before" that nothing held — a trail of who changed what,
// wrong about the what, and unfixable later because the value is gone. The
// collision itself is forced in race_test.go.
func TestWhatASettingHeldIsAnsweredByTheWriteThatReplacedIt(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
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
	})
}

// A setting renamed by an upgrade answers from a row under its former name
// while its own name is unset, and its own name outranks the former when both
// are held. Each state is reported, for the warning at startup.
func TestARenamedSettingReadsItsFormerNameUntilItsOwnIsSet(t *testing.T) {
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		ctx := t.Context()
		if got := formersOf(t, s); len(got) != 0 {
			t.Errorf("nothing under a former name reported as %v", got)
		}
		if _, _, err := s.Change(ctx, "triage.together-cap", "300"); err != nil {
			t.Fatal(err)
		}
		if got := limitOf(t, s); got != 300 {
			t.Errorf("the limit reads %d with only its former name set, want 300", got)
		}
		want := setting.FormerName{Former: "triage.together-cap", Name: setting.BulkDecisionCap}
		if got := formersOf(t, s); len(got) != 1 || got[0] != want {
			t.Errorf("the former name reported as %v, want %v", got, want)
		}
	})
}

// A row under the former name written after the setting's own, as an earlier
// release still running writes it, is outranked and reported as shadowed.
func TestARenamedSettingOutranksItsFormerNameWrittenAfter(t *testing.T) {
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		ctx := t.Context()
		if _, _, err := s.Change(ctx, setting.BulkDecisionCap, "40"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.Change(ctx, "triage.together-cap", "300"); err != nil {
			t.Fatal(err)
		}
		if got := limitOf(t, s); got != 40 {
			t.Errorf("the limit reads %d with both names set, want its own 40", got)
		}
		want := setting.FormerName{Former: "triage.together-cap", Name: setting.BulkDecisionCap, Shadowed: true}
		if got := formersOf(t, s); len(got) != 1 || got[0] != want {
			t.Errorf("both names reported as %v, want %v", got, want)
		}
	})
}

// Changing a renamed setting replaces what its former name held, says so for
// the trail, and clears the former row, so nothing is left to warn about.
func TestChangingARenamedSettingTakesOverItsFormerName(t *testing.T) {
	eachSetting(t, func(t *testing.T, s *setting.Store) {
		ctx := t.Context()
		if _, _, err := s.Change(ctx, "triage.together-cap", "300"); err != nil {
			t.Fatal(err)
		}
		before, had, err := s.Change(ctx, setting.BulkDecisionCap, "40")
		if err != nil {
			t.Fatal(err)
		}
		if !had || before != "300" {
			t.Errorf("the change replaced %q (held %v), want the former name's 300", before, had)
		}
		if got := limitOf(t, s); got != 40 {
			t.Errorf("the limit reads %d after the change, want 40", got)
		}
		if got := formersOf(t, s); len(got) != 0 {
			t.Errorf("the former name is still held after the change: %v", got)
		}
		if _, held, err := s.Get(ctx, "triage.together-cap"); err != nil || held {
			t.Errorf("the former row is held=%v after the change (%v)", held, err)
		}
	})
}

func formersOf(t *testing.T, s *setting.Store) []setting.FormerName {
	t.Helper()
	got, err := s.FormerNames(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func limitOf(t *testing.T, s *setting.Store) int {
	t.Helper()
	got, err := s.Count(t.Context(), setting.BulkDecisionCap, 2000)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
