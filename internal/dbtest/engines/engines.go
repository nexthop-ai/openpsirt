// Package engines holds the rule for which engines a test run may touch.
//
// It exists as a package of its own, below dbtest, because two of the tests
// that have to obey the rule cannot import dbtest: the migration lock's test
// is an internal test of the migrate package, and dbtest depends on migrate.
// The alternative was a second copy of the parsing in that file, and a rule
// written twice is a rule that differs in one of the copies.
package engines

import (
	"os"
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
func Selected() map[database.Engine]bool {
	raw := strings.TrimSpace(os.Getenv(Env))
	if raw == "" {
		return nil
	}
	wanted := map[database.Engine]bool{}
	for _, name := range strings.Split(raw, ",") {
		wanted[database.Engine(strings.TrimSpace(strings.ToLower(name)))] = true
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
