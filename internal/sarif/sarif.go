// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package sarif reads static analysis results written as SARIF 2.1.0.
//
// A SARIF document is somebody else's output arriving over a link nobody here
// controls, so it is read as hostile input: bounded in size before and after
// decompression, in nesting, and in how many runs, results, locations and
// steps it may hold. What the deployment does not store — the source text a
// document may carry, whole files and proposed replacements — is discarded as
// it is read and counted, so a sender can be told what was left out.
//
// Only the parts the analysis kind reads are kept. Everything else a document
// states is walked past.
package sarif

import (
	"strings"
)

// Version is the one version of the format read.
const Version = "2.1.0"

// Log is one document: the runs it holds.
type Log struct {
	Runs []Run
}

// Run is one run of one tool.
type Run struct {
	Tool Tool
	// Results is what the tool reported. Ran says whether the document
	// states a list at all: absent or null is a tool that failed to start,
	// and an empty list is one that ran and found nothing.
	Results []Result
	Ran     bool
	// AutomationID is what the run calls itself across runs, where it says.
	AutomationID string
	// Invocations is how the tool was run and how that ended.
	Invocations []Invocation
	// Modules is the repositories the run says its files came from.
	Modules []Module
	// Bases is the run's named starting points for relative paths.
	Bases map[string]ArtifactLocation
	// Properties is the run's own properties that this deployment reads,
	// the ones under the openpsirt/ prefix.
	Properties RunProperties
	// Discarded counts what was left out as the run was read.
	Discarded Discarded
}

// Tool is what produced a run.
type Tool struct {
	Name    string
	Version string
	// Rules is every rule the tool's components describe, in the order they
	// are listed.
	Rules []Rule
}

// Rule is one check a tool runs.
type Rule struct {
	ID          string
	Name        string
	Description string
	HelpURI     string
	// Tags is the rule's tags, CWE tags among them.
	Tags []string
	// SecuritySeverity and Precision are the tool's own rating of a rule's
	// results, where it gives one.
	SecuritySeverity string
	Precision        string
	// DefaultLevel is the level a result of the rule has where it states
	// none.
	DefaultLevel string
	// messages is the rule's message strings, by identifier, which a result
	// citing one by identifier is worded from.
	messages map[string]string
	// component is the tool component the rule belongs to: 0 for the
	// driver, and an extension's position among the extensions from 1 on.
	component int
}

// Result is one thing a tool reported.
type Result struct {
	RuleID string
	Level  string
	// Kind is what the result says of its rule: fail where it says nothing,
	// and pass, notApplicable or informational where it reports no problem.
	Kind string
	// Suppressed is whether a suppression in force covers the result: one
	// accepted, or one stating no status.
	Suppressed bool
	// Absent is whether the result says it was in the tool's own baseline
	// and is no longer found.
	Absent bool
	// Message is the result's text, with any markdown left out and any
	// message string it cites filled in.
	Message string
	// Locations is where the result is; the first is the one it is about.
	Locations []Location
	// Related is the other places it names.
	Related []Location
	// Steps is the path the tool took to it, in order: the steps of its
	// first code flow's first thread.
	Steps []Step
	// Fingerprints is every fingerprint the result carries, partial ones
	// included, by scheme.
	Fingerprints map[string]string
}

// Location is one place in one file.
type Location struct {
	// URI and Base are the file as the document names it: an address, and
	// the starting point it is relative to.
	URI  string
	Base string
	// Region is the lines and columns, zero where unstated.
	StartLine, StartColumn, EndLine, EndColumn int
	// Function is the enclosing function, where the document names one.
	Function string
	Message  string
}

// Step is one step of the path a tool took to a result.
type Step struct {
	Location
	// Depth is how deep in calls the step is, where the document says.
	Depth *int
}

// Invocation is one run of the tool, as the tool records it.
type Invocation struct {
	ExitCode   *int
	Successful *bool
	// Errors counts the notifications the tool raised at error level about
	// its own run.
	Errors int
	// Notified is the descriptors those notifications name.
	Notified []string
}

// Module is one repository a run's files came from.
type Module struct {
	Repository string
	Revision   string
	// Base is the starting point its files are named relative to, and URI
	// where that point is in the checkout.
	Base string
	URI  string
}

// ArtifactLocation is a starting point for relative paths: an address, and
// the starting point it is itself relative to.
type ArtifactLocation struct {
	URI  string
	Base string
}

// RunProperties is what a run says about itself under this deployment's
// prefix: what the upload client wrote.
type RunProperties struct {
	UnitsExpected *int
	UnitsAnalyzed *int
	Client        string
	// Changed is the paths of repositories whose working tree differed from
	// their commit when they were analyzed.
	Changed []string
	// Series and Built are the run's series and build time, where the run
	// states them in properties rather than in its automation identifier.
	Series string
	Built  string
	Commit string
}

// Discarded counts what reading left out: source text and proposed changes,
// none of which this deployment stores.
type Discarded struct {
	// Snippets is the regions whose source text was dropped.
	Snippets int
	// Markdown is the messages reduced to their text.
	Markdown int
	// Contents is the files whose whole contents the document carried.
	Contents int
	// Fixes is the proposed replacements.
	Fixes int
}

// Add totals another count into this one.
func (d *Discarded) Add(other Discarded) {
	d.Snippets += other.Snippets
	d.Markdown += other.Markdown
	d.Contents += other.Contents
	d.Fixes += other.Fixes
}

// RuleOf is the rule a result cites, where the run describes it.
func (r Run) RuleOf(id string) (Rule, bool) {
	for _, rule := range r.Tool.Rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}

// worded is a message's text: its own, or the message string it cites with
// its arguments filled in, up to most bytes.
func worded(text, id string, arguments []string, strings map[string]string, most int) string {
	if text == "" && id != "" {
		text = strings[id]
	}
	if len(arguments) == 0 || !containsPlaceholder(text) {
		return text
	}
	return fill(text, arguments, most)
}

func containsPlaceholder(text string) bool { return strings.Contains(text, "{") }

// fill replaces each {n} with the nth argument, leaving a placeholder with no
// argument as written. It stops once most bytes are written, since a message
// cut to that length is all that is kept and filling past it costs memory
// for nothing.
func fill(text string, arguments []string, most int) string {
	var b strings.Builder
	for i := 0; i < len(text) && b.Len() < most; i++ {
		if text[i] == '{' {
			end := strings.IndexByte(text[i:], '}')
			if end > 1 {
				n, ok := index(text[i+1 : i+end])
				if ok && n < len(arguments) {
					b.WriteString(arguments[n])
					i += end
					continue
				}
			}
		}
		b.WriteByte(text[i])
	}
	return b.String()
}

func index(s string) (int, bool) {
	if s == "" || len(s) > 4 {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
