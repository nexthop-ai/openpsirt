// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package engines holds the rule for which engines a test run may touch.
//
// It exists as a package of its own, below dbtest, because two of the tests
// that have to obey the rule cannot import dbtest: the migration lock's test
// is an internal test of the migrate package, and dbtest depends on migrate.
// The alternative was a second copy of the parsing in that file, and a rule
// written twice is a rule that differs in one of the copies.
package engines

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Env narrows which engines run, as a comma-separated list of names.
//
// Unset means every engine that is configured. The quick loop sets it to
// "sqlite" so that iterating does not wait on three servers; the gate leaves
// it unset. An engine excluded this way is skipped with a message saying so,
// which is a different message from one that is not configured at all.
const Env = "OPENPSIRT_TEST_ENGINES"

// Wanted reports whether Env admits this engine.
func Wanted(engine database.Engine) bool {
	wanted := Selected()
	return wanted == nil || wanted[engine]
}

// Selected is the set Env names, or nil when it names nothing.
//
// A name no engine answers to panics. The two outcomes are otherwise
// indistinguishable: a typo intersects with nothing, every database test skips
// with a message that reads like a deliberate narrowing, and the run exits 0
// having touched no database at all. There is no *testing.T here — this is
// read before any test starts — so the refusal is at the process level, which
// fails the binary rather than passing it.
func Selected() map[database.Engine]bool {
	raw := strings.TrimSpace(os.Getenv(Env))
	if raw == "" {
		return nil
	}
	wanted := map[database.Engine]bool{}
	for _, name := range strings.Split(raw, ",") {
		engine := database.Engine(strings.TrimSpace(strings.ToLower(name)))
		if !slices.Contains(database.Engines(), engine) {
			panic(fmt.Sprintf("%s names %q, which is not an engine: it must be one of %v",
				Env, engine, database.Engines()))
		}
		wanted[engine] = true
	}
	return wanted
}

// SkipUnless skips the test when Env excludes this engine.
//
// For a test that opens a connection itself rather than through dbtest,
// because what it pins is a property of the connection rather than of a
// query: the pool's idle reaper, the migration lock, the version floor.
// Three of those read the URL and connected without consulting Env at all,
// so a run narrowed to SQLite reached three servers — which is why the quick
// loop, documented as needing no server, failed when the servers stopped.
func SkipUnless(t *testing.T, engine database.Engine) {
	t.Helper()
	if !Wanted(engine) {
		t.Skipf("%s is excluded by %s", engine, Env)
	}
}
