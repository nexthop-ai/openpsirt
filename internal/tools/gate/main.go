// Command gate names the checks a change has to pass.
//
// The full gate is minutes and most changes cannot fail most of it. A prose
// edit cannot break a database engine; an interface change cannot make a Go
// query non-portable. Running everything anyway is not caution — it is what
// teaches people to skip the gate, and a gate people skip is the failure the
// gate exists to prevent.
//
// So the tier is chosen from what the change touches, and chosen here rather
// than by somebody consulting a table. A table is read optimistically at six in
// the evening; a program reads the same diff every time.
//
// It prints make targets, one line, and the makefile runs them. Deciding and
// running are kept apart so that what was chosen can be seen before it runs,
// and so that this can be asked what it would do without doing it.
//
// **It never narrows below what the change can break, and errs the other way.**
// A path it does not recognize takes the whole gate. That is the direction a
// check that gates a commit should be wrong in.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
)

// The tiers, cheapest first. A change takes every tier its files land in, so
// these accumulate rather than replace: a commit touching a design document
// and a query runs both the document checks and the engines.
type tier int

const (
	// A document can break a link to a heading that was renamed, and it can
	// leave a decision in force that nothing names. Nothing else in the gate
	// can fail for a prose edit.
	documents tier = iota
	// The interface, checked by its own toolchain.
	web
	// Go that reaches no SQL: the type checks, the analysis gates, the quick
	// test loop.
	code
	// Anything the OpenAPI document is generated from. Two steps that pass
	// only on a commit, because they diff a regenerated file against the last
	// one.
	api
	// A query, the schema, a migration, or the harness the tests share. This
	// is the tier that costs, and the only one that proves portability.
	engines
	// Everything. What a path nobody classified takes, and what a session ends
	// with.
	everything
)

// What each tier runs, in the order a person wants to see a failure: the fast
// and specific before the slow and broad.
var runs = map[tier][]string{
	documents: {"docs-check", "unclaimed"},
	web:       {"web-check"},
	code: {"build", "vet", "lint", "unreachable", "readable", "negatives", "confined", "granted",
		"attached", "test"},
	api:        {"openapi-current", "web-api"},
	engines:    {"reserved", "test-all", "check-engines"},
	everything: {"check", "check-engines"},
}

// The order targets are printed in, which is the order make runs them.
var order = []string{
	"build", "vet", "lint", "unreachable", "readable", "negatives", "reserved", "confined", "granted",
	"attached",
	"docs-check", "unclaimed", "openapi-current",
	"test", "test-all", "check-engines", "web-check", "web-api", "check",
}

func main() {
	full := len(os.Args) > 1 && os.Args[1] == "full"

	touched, err := changed()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var reached map[tier]bool
	switch {
	case full:
		fmt.Fprintln(os.Stderr, "gate: everything, because it was asked for")
		reached = map[tier]bool{everything: true}
	case len(touched) == 0:
		// Nothing to read the change from. A clean tree before a push is
		// carrying work that is already committed, which is exactly when the
		// whole gate is the right answer.
		fmt.Fprintln(os.Stderr, "gate: everything, because nothing is changed here to choose from")
		reached = map[tier]bool{everything: true}
	default:
		reached = tiers(touched)
	}

	fmt.Println(strings.Join(targets(reached), " "))
}

// targets is what the tiers reached come to, deduplicated and ordered. Where
// the whole gate is in the set, it is the whole answer: every other target is
// inside it, and naming them twice would run them twice.
func targets(reached map[tier]bool) []string {
	if reached[everything] {
		return runs[everything]
	}
	wanted := map[string]bool{}
	for t := range reached {
		for _, target := range runs[t] {
			wanted[target] = true
		}
	}
	// The four-engine run subsumes the quick one, which is the same tests
	// against one engine with the build cache on.
	if wanted["test-all"] {
		delete(wanted, "test")
	}
	// So does the interface check, which ends by regenerating the client.
	if wanted["web-check"] {
		delete(wanted, "web-api")
	}
	var chosen []string
	for _, target := range order {
		if wanted[target] {
			chosen = append(chosen, target)
			delete(wanted, target)
		}
	}
	// A target added to a tier and left out of the order above still runs,
	// rather than disappearing from the gate silently.
	rest := make([]string, 0, len(wanted))
	for target := range wanted {
		rest = append(rest, target)
	}
	sort.Strings(rest)
	return append(chosen, rest...)
}

// tiers classifies every changed path, and reports each tier reached.
func tiers(touched []string) map[tier]bool {
	reached := map[tier]bool{}
	for _, file := range touched {
		t := classify(file)
		reached[t] = true
		// The tiers above documents and web add to the one below rather than
		// replacing it: a change that moves a query is still Go, and has to
		// compile and pass the analysis gates before anything asks four
		// engines about it.
		if t == api || t == engines {
			reached[code] = true
		}
		fmt.Fprintf(os.Stderr, "gate: %s -> %s\n", file, name(t))
	}
	return reached
}

func name(t tier) string {
	return [...]string{"documents", "web", "code", "api", "engines", "everything"}[t]
}

// Where the queries, the schema and the harness the tests share live. A change
// under any of these is portability work whatever it looks like.
var storage = []string{
	"internal/database/",
	"internal/dbtest/",
	"internal/schema/",
}

// SQL, and the query builder that writes it. Matched against the whole file
// rather than the diff: a file holding queries is one where a change to
// anything can move what a query returns, and asking whether the edited lines
// themselves were SQL is a narrower question than the one that matters.
var query = regexp.MustCompile(`(?i)\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|CREATE TABLE|CREATE INDEX|ALTER TABLE|JOIN|GROUP BY|ORDER BY)\b|\.New(Select|Insert|Update|Delete|Raw)\(|RunInTx\(`)

// An operation the API document is generated from.
var operation = regexp.MustCompile(`huma\.(Register|Operation)|Summary:|OperationID:`)

func classify(file string) tier {
	switch {
	case strings.HasPrefix(file, "web/"):
		return web
	case path.Ext(file) == ".md":
		return documents
	case file == "go.mod" || file == "go.sum":
		return engines
	case path.Ext(file) != ".go":
		// The makefile, the container, the chart, the generated document, an
		// asset, a test fixture. Each of these can break something no narrower
		// tier covers, and there are few enough of them that being generous
		// costs little.
		return everything
	}
	// The gate programs themselves, and the reader they share. A change here
	// can stop any check looking at part of the tree, and no narrower tier
	// covers that: the walk holds no SQL and registers no operation, so it
	// would otherwise land in the code tier, which does not run `reserved`.
	// Widening the skip set would then make the quoting gate read less while
	// this reported green.
	if strings.HasPrefix(file, "internal/tools/") {
		return everything
	}
	for _, dir := range storage {
		if strings.HasPrefix(file, dir) {
			return engines
		}
	}
	content, err := os.ReadFile(file) //nolint:gosec // G304: a path git reported as changed in this checkout
	if err != nil {
		// Deleted, or unreadable. Either way this is not the place to decide
		// what it used to hold.
		return everything
	}
	switch {
	case query.Match(content):
		return engines
	case operation.Match(content):
		return api
	default:
		return code
	}
}

// changed lists every path this checkout differs from its last commit by:
// staged, unstaged and untracked alike. All three are the change about to be
// committed, and reading only one of them is how a gate misses the file
// somebody just added.
func changed() ([]string, error) {
	out, err := exec.Command("git", "status", "--porcelain=v1", "-z", "--untracked-files=all").Output()
	if err != nil {
		return nil, fmt.Errorf("ask git what changed: %w", err)
	}
	seen := map[string]bool{}
	var files []string
	// Records are NUL-separated, each "XY path"; a rename or copy is followed
	// by a second record holding the path it came from, which matters as much
	// as the one it went to.
	fields := strings.Split(string(out), "\x00")
	for i := 0; i < len(fields); i++ {
		record := fields[i]
		if len(record) < 4 {
			continue
		}
		status, file := record[:2], record[3:]
		if strings.ContainsAny(status, "RC") && i+1 < len(fields) {
			i++
			if from := fields[i]; from != "" && !seen[from] {
				seen[from] = true
				files = append(files, from)
			}
		}
		if !seen[file] {
			seen[file] = true
			files = append(files, file)
		}
	}
	sort.Strings(files)
	return files, nil
}
