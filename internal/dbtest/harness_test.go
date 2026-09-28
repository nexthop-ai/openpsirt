// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"strings"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// A test made parallel twice, which is what two harness calls in one test
// function do on SQLite, is told the rule in words rather than handed the
// testing package's panic.
func TestATestMadeParallelTwiceIsToldTheRule(t *testing.T) {
	t.Run("group", func(t *testing.T) {
		t.Run("twice", func(t *testing.T) {
			if err := parallel(t); err != nil {
				t.Fatalf("the first call: %v", err)
			}
			err := parallel(t)
			if err == nil {
				t.Fatal("the second call was accepted")
			}
			if !strings.Contains(err.Error(), "once per test function") {
				t.Errorf("the refusal does not say the rule: %v", err)
			}
		})
	})
}

// Two leaves MySQL and MariaDB out, and says so for each, with the reason: a
// skip that passed silently would read in the output as those engines having
// run.
func TestTwoNamesTheEnginesItLeavesOutAndWhy(t *testing.T) {
	var mu sync.Mutex
	got := map[database.Engine]string{}
	prefix := t.Name() + "/"
	skippedMu.Lock()
	skipped = func(test string, engine database.Engine, reason string) {
		if strings.HasPrefix(test, prefix) {
			mu.Lock()
			got[engine] = reason
			mu.Unlock()
		}
	}
	skippedMu.Unlock()
	t.Cleanup(func() {
		skippedMu.Lock()
		skipped = nil
		skippedMu.Unlock()
	})

	// Two may run its test beside the others; the outer group waits for it.
	t.Run("group", func(t *testing.T) {
		t.Run("two", func(t *testing.T) {
			Two(t, func(*testing.T, *database.DB) {})
		})
	})
	mu.Lock()
	defer mu.Unlock()
	for _, engine := range []database.Engine{database.MySQL, database.MariaDB} {
		if !strings.Contains(got[engine], "not asked for by this kind of test") {
			t.Errorf("%s was left out with %q, want it named as not asked for", engine, got[engine])
		}
	}
}
