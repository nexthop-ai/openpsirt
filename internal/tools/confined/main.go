// Command confined reports engine-specific code outside where it is allowed.
//
// Queries here are written once and run against four engines. The places that
// have to ask an engine directly are enumerated in `DESIGN-database.md`, and
// that list said it was "checked by grep rather than trusted" while nothing
// checked it — which is the shape the list itself was written about: the
// document records that it stated three while there were five, because each
// new one arrived under a comment calling itself one of the few places an
// engine has to be asked.
//
// So this is the grep. It reads for a dialect being named — the engine
// constants, the driver error types, and the SQL each engine spells its own
// way — and refuses any file outside the allowed set.
//
// Deliberately crude, like the gates beside it. It errs toward saying too
// much, which asks somebody to widen the list deliberately rather than
// letting a fifth place arrive unannounced.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// asking is a file naming an engine, a driver's own error type, or SQL only
// some of them accept.
var asking = regexp.MustCompile(
	`(database\.Postgres|database\.MySQL|database\.MariaDB|database\.SQLite|` +
		`mysql\.MySQLError|pgconn\.PgError|` +
		// Asking the handle which engine it is, which is how a branch is
		// written without naming a constant. It was not looked for at all, so
		// the one live branch in the tree that spells it this way —
		// InBatchesKeeping — was invisible, and those three lines pasted into
		// a store package would have passed.
		`Dialect\(\)\.Name|` +
		// And bun's own spellings of the two upsert idioms, which are the same
		// branch written through the query builder rather than as SQL.
		`\.Ignore\(\)|` +
		`ON CONFLICT|ON DUPLICATE KEY|INSERT IGNORE|ILIKE|julianday|` +
		`TIMESTAMPDIFF|EXTRACT\(EPOCH|FOR UPDATE|pg_advisory|GET_LOCK)`)

// selecting is an engine named to choose which engine a test runs against,
// which the harness exists to do. Anything else naming one is a branch.
var selecting = regexp.MustCompile(`dbtest\.\w+\([^)]*database\.\w+`)

// allowed is where an engine may be named, and why.
//
// `DESIGN-database.md` holds the same list in prose. Two copies is the thing
// this program exists to catch, so the document points at the mechanism and
// this is the mechanism: a path added here without the document changing is
// the drift, and a reviewer reading either finds the other.
var allowed = []string{
	"internal/database/",
	// The only place outside that package, because the queue owns the
	// statement its claim is made with.
	"internal/queue/claim_locking.go",
	// This program, which names every engine in order to look for them.
	"internal/tools/confined/",
	// The test harness, whose whole job is to run the same thing against
	// each of the four and say which one it was. It names engines to choose
	// a connection rather than to write a query, which is the distinction
	// the rule is about — and the check that proves each engine ran is
	// itself what stops that naming going quietly wrong.
	"internal/dbtest/",
}

func main() {
	var bad []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "web", "site", "dist", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		path = strings.TrimPrefix(path, "./")
		for _, where := range allowed {
			if strings.HasPrefix(path, where) {
				return nil
			}
		}
		text, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // walked, not supplied
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(text), "\n") {
			// Comments name engines constantly, and correctly: what is being
			// looked for is code that branches on one.
			if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "//") {
				continue
			}
			// Choosing which engine a test runs on is not branching a query on
			// one. `dbtest.Only(t, database.SQLite, …)` says this question has
			// the same answer everywhere and is asked once — which is the
			// distinction the whole rule is about, and the reason the harness
			// itself is allowed to name all four.
			if selecting.MatchString(line) {
				continue
			}
			if match := asking.FindString(line); match != "" {
				bad = append(bad, fmt.Sprintf("%s:%d: %s", path, i+1, match))
			}
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if len(bad) == 0 {
		fmt.Printf("engine-specific code is confined to the %d paths this holds, "+
			"which the design document lists as its own rows\n", len(allowed))
		return
	}
	sort.Strings(bad)
	for _, one := range bad {
		fmt.Fprintf(os.Stderr, "%s asks an engine directly, outside where that is allowed\n", one)
	}
	fmt.Fprintf(os.Stderr, "\n%d place(s) outside internal/database and the queue's locking. "+
		"Move it there, or widen the list here and in DESIGN-database.md together.\n", len(bad))
	os.Exit(1)
}
