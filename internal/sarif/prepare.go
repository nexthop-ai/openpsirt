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
}

// Dropped counts the results that preparing a run left out, by reason.
type Dropped struct {
	// Advisory is the results whose rule is an advisory's identifier.
	Advisory int
	// Outside is the results whose file is outside the checkout, or that
	// name no file.
	Outside int
	// Repeats is the results identical to one already kept: one rule, path,
	// line, column and message. A header's result recurs once per unit that
	// includes it.
	Repeats int
}

// Prepare places a run's results in the checkout and leaves out what the
// deployment does not keep. root is the checkout's absolute path where the
// pipeline states one.
func Prepare(run *Run, root string) ([]Placed, Dropped) {
	paths := PathsOf(run, root)
	var out []Placed
	var dropped Dropped
	seen := map[string]bool{}
	for _, res := range run.Results {
		if advisory.MatchString(res.RuleID) {
			dropped.Advisory++
			continue
		}
		if len(res.Locations) == 0 {
			dropped.Outside++
			continue
		}
		first := res.Locations[0]
		rel, ok := paths.Relative(first.URI, first.Base)
		if !ok {
			dropped.Outside++
			continue
		}
		key := strings.Join([]string{res.RuleID, rel, itoa(first.StartLine), itoa(first.StartColumn), res.Message}, "\x00")
		if seen[key] {
			dropped.Repeats++
			continue
		}
		seen[key] = true
		p := Placed{
			RuleID: res.RuleID, Level: res.Level, Message: res.Message,
			Path: rel, StartLine: first.StartLine, StartColumn: first.StartColumn,
			EndLine: first.EndLine, EndColumn: first.EndColumn,
			Function: first.Function, Fingerprints: res.Fingerprints, Module: -1,
		}
		if m, ok := paths.Module(rel); ok {
			p.Module = m
		}
		for _, s := range res.Steps {
			p.Steps = append(p.Steps, placedStep(paths, s.Location, s.Depth))
		}
		for _, loc := range res.Related {
			p.Related = append(p.Related, placedStep(paths, loc, nil))
		}
		out = append(out, p)
	}
	return out, dropped
}

func placedStep(paths Paths, loc Location, depth *int) PlacedStep {
	rel, _ := paths.Relative(loc.URI, loc.Base)
	return PlacedStep{
		Path: rel, StartLine: loc.StartLine, Column: loc.StartColumn,
		Function: loc.Function, Message: loc.Message, Depth: depth,
	}
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
