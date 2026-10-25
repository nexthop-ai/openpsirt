// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"regexp"
	"strings"
)

// advisory matches a rule identifier that is an advisory database's name
// for a vulnerability, each scheme in its own identifier shape. A result
// named that way is a dependency finding, which matching the build's
// inventory already finds.
var advisory = regexp.MustCompile(`(?i)^(` +
	`CVE-\d{4}-\d{4,}` +
	`|GHSA(-[23456789cfghjmpqrvwx]{4}){3}` +
	`|GO-\d{4}-\d{4,}` +
	`|RUSTSEC-\d{4}-\d{4,}` +
	`|PYSEC-\d{4}-\d+` +
	`|OSV-\d{4}-\d+` +
	`|SNYK-[A-Z0-9]+(-[A-Z0-9._]+)*-\d+` +
	`|DSA-\d+(-\d+)?` +
	`|DLA-\d+(-\d+)?` +
	`|RHSA-\d{4}:\d+` +
	`|ALAS\d*-\d{4}-\d+` +
	`|MAL-\d{4}-\d+` +
	`)$`)

// scanners is the dependency and secret scanners that write SARIF, by the
// name a run gives its driver, in lower case. A dependency scanner's results
// are found again by matching the inventory, and a secret scanner's carry
// the secret.
var scanners = map[string]bool{
	// Dependency scanners.
	"govulncheck":            true,
	"cargo-audit":            true,
	"trivy":                  true,
	"grype":                  true,
	"osv-scanner":            true,
	"snyk open source":       true,
	"dependency-check":       true,
	"owasp dependency-check": true,
	"npm audit":              true,
	"pip-audit":              true,
	"bundler-audit":          true,
	"retire.js":              true,
	// Secret scanners.
	"gitleaks":       true,
	"trufflehog":     true,
	"detect-secrets": true,
	"ggshield":       true,
	"secretlint":     true,
	"nosey parker":   true,
	"kingfisher":     true,
}

// Scanner is whether a run's driver is a dependency or secret scanner, whose
// runs are dropped whole.
func Scanner(name string) bool {
	return scanners[strings.ToLower(strings.TrimSpace(name))]
}

// Placed is one result, with each path made relative to the checkout.
type Placed struct {
	RuleID  string
	Level   string
	Message string
	// Path is the file the result is about, and Line and Column where in it.
	Path                   string
	StartLine, StartColumn int
	EndLine, EndColumn     int
	Function               string
	Steps                  []PlacedStep
	Related                []PlacedStep
	Fingerprints           map[string]string
	// Snippet is the source at the result, where the product keeps source
	// under its path, and SnippetLine the line it starts at.
	Snippet     string `json:",omitempty"`
	SnippetLine int    `json:",omitempty"`
	// Module is the position in the run's repository list of the one Path
	// falls in, and -1 where it falls in none.
	Module int
}

// PlacedStep is one step of a result's path, or one related place. Its path
// is empty where the step's file is outside the checkout.
type PlacedStep struct {
	Path              string
	StartLine, Column int
	Function          string
	Message           string
	Depth             *int
	Snippet           string `json:",omitempty"`
	SnippetLine       int    `json:",omitempty"`
}

// Dropped counts the results that preparing a run left out, by reason.
type Dropped struct {
	// Advisory is the results whose rule is an advisory's identifier.
	Advisory int
	// Failure is the results that are the analyzer reporting a failure of
	// its own run, wherever they are.
	Failure int
	// NotAProblem is the results whose kind reports no problem.
	NotAProblem int
	// Suppressed is the results a suppression in force covers.
	Suppressed int
	// Absent is the results the tool says are no longer found.
	Absent int
	// Outside is the results whose file is outside the checkout, or that
	// name no file.
	Outside int
	// Repeats is the results identical to one already kept: one rule, path,
	// line, column and message. A header's result recurs once per unit that
	// includes it.
	Repeats int
}

// Placer places the results of one upload's runs in the checkout, leaving
// out what the deployment does not keep. A result repeated in another run of
// the same upload is a repeat as much as one repeated within a run: clang
// writes a document per unit, and a header's result is in each.
type Placer struct {
	seen     map[string]bool
	dropped  Dropped
	keep     func(path string) bool
	snippets int
}

// NewPlacer is a placer that has seen nothing. keep is whether source under
// a path is kept, and a nil keep keeps none.
func NewPlacer(keep func(path string) bool) *Placer {
	return &Placer{seen: map[string]bool{}, keep: keep}
}

// Dropped is what the placer has left out so far.
func (pl *Placer) Dropped() Dropped { return pl.dropped }

// Snippets is how many locations' source the placer has discarded so far,
// because the product keeps no source under their paths.
func (pl *Placer) Snippets() int { return pl.snippets }

// snippet is a location's source where it is kept, and nothing otherwise. A
// location outside the checkout keeps none.
func (pl *Placer) snippet(path string, loc Location) (string, int) {
	if loc.Snippet == "" {
		return "", 0
	}
	if path == "" || pl.keep == nil || !pl.keep(path) {
		pl.snippets++
		return "", 0
	}
	return loc.Snippet, loc.SnippetLine
}

// Place places one run's results. root is the checkout's absolute path where
// the pipeline states one.
func (pl *Placer) Place(run *Run, root string) []Placed {
	paths := PathsOf(run, root)
	var out []Placed
	for _, res := range run.Results {
		switch {
		case advisory.MatchString(res.RuleID):
			pl.dropped.Advisory++
			continue
		case failureSignal(res.RuleID):
			pl.dropped.Failure++
			continue
		case !problem(res.Kind):
			pl.dropped.NotAProblem++
			continue
		case res.Suppressed:
			pl.dropped.Suppressed++
			continue
		case res.Absent:
			pl.dropped.Absent++
			continue
		}
		if len(res.Locations) == 0 {
			pl.dropped.Outside++
			continue
		}
		first := res.Locations[0]
		rel, ok := paths.Relative(first.URI, first.Base)
		if !ok {
			pl.dropped.Outside++
			continue
		}
		key := strings.Join([]string{res.RuleID, rel, itoa(first.StartLine), itoa(first.StartColumn), res.Message}, "\x00")
		if pl.seen[key] {
			pl.dropped.Repeats++
			continue
		}
		pl.seen[key] = true
		p := Placed{
			RuleID: res.RuleID, Level: res.Level, Message: res.Message,
			Path: rel, StartLine: first.StartLine, StartColumn: first.StartColumn,
			EndLine: first.EndLine, EndColumn: first.EndColumn,
			Function: first.Function, Fingerprints: res.Fingerprints, Module: -1,
		}
		p.Snippet, p.SnippetLine = pl.snippet(rel, first)
		if m, ok := paths.Module(rel); ok {
			p.Module = m
		}
		for _, s := range res.Steps {
			p.Steps = append(p.Steps, pl.placedStep(paths, s.Location, s.Depth))
		}
		for _, loc := range res.Related {
			p.Related = append(p.Related, pl.placedStep(paths, loc, nil))
		}
		out = append(out, p)
	}
	return out
}

// Prepare places one run's results on their own, and says what it left out.
func Prepare(run *Run, root string) ([]Placed, Dropped) {
	pl := NewPlacer(nil)
	placed := pl.Place(run, root)
	return placed, pl.Dropped()
}

// failureSignals is the rules whose results say the analyzer failed on part
// of what it was given rather than found a flaw in it: a unit that would not
// compile, a file that would not parse.
var failureSignals = map[string]bool{
	"clang-diagnostic-error":     true,
	"syntaxError":                true,
	"internalAstError":           true,
	"cppcheckError":              true,
	"preprocessorErrorDirective": true,
}

// failureSignal is whether a result is the analyzer reporting a failure of its
// own run.
func failureSignal(ruleID string) bool { return failureSignals[ruleID] }

// problem is whether a result's kind reports a problem: a failed check, or
// one a person is asked to review or settle.
func problem(kind string) bool { return kind == "fail" || kind == "review" || kind == "open" }

func (pl *Placer) placedStep(paths Paths, loc Location, depth *int) PlacedStep {
	rel, _ := paths.Relative(loc.URI, loc.Base)
	step := PlacedStep{
		Path: rel, StartLine: loc.StartLine, Column: loc.StartColumn,
		Function: loc.Function, Message: loc.Message, Depth: depth,
	}
	step.Snippet, step.SnippetLine = pl.snippet(rel, loc)
	return step
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
