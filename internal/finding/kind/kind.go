// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package kind declares the sorts of finding there are, what each one is, and
// which of them each consumer of findings includes.
//
// It sits below every package that reads findings, the dependency graph
// included, so a query anywhere names the kinds it reads from one list.
//
// A kind is the extension point of the finding model. Assignment, notes,
// approval, the trail, queues and notifications are one implementation over
// every kind; what differs is declared here, and a consumer names the kinds it
// takes rather than the ones it leaves out. A list of exclusions is a list
// somebody forgets to extend, and a kind nothing names reaches nothing.
package kind

import (
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Kind says what sort of finding this is, meaning what produced it.
type Kind string

const (
	// Vulnerability is a component that ships with a known issue. A scan of
	// the build's inventory opens it, and a scan closes it.
	Vulnerability Kind = "vulnerability"
	// Entered is a flaw somebody recorded here, usually before anybody
	// outside knows about it. No scan reports it and no scan closes it.
	Entered Kind = "entered"
	// Analysis is one result a static analyzer reported in our own code, at
	// one place, tracked across builds: a lead. It is unconfirmed, and most
	// are false positives.
	Analysis Kind = "analysis"
)

// Issue says what sort of issue a finding is filed under.
type Issue string

const (
	// Advisory is a published vulnerability: a CVE, or an advisory database's
	// identifier, with every name it goes by.
	Advisory Issue = "vulnerability"
	// Flaw is a flaw in our own product, filed under an identifier this
	// deployment minted.
	Flaw Issue = "flaw"
	// Rule is an analyzer's rule. Every result the rule reports is a finding
	// filed under it, so "this rule at this place" is keyed as "this issue at
	// this place" is.
	Rule Issue = "rule"
)

// Issues is every sort of issue, in the order a list of them reads.
func Issues() []Issue { return []Issue{Advisory, Flaw, Rule} }

// Absence says what it means that a finding's producer stopped reporting it.
type Absence string

const (
	// Closes is a finding the run that no longer reports it closes, with a
	// reason worked out from what the build now holds.
	Closes Absence = "closes"
	// Stated is a finding no run has an opinion about. A person opened it
	// and a person closes it.
	Stated Absence = "stated"
	// NotReproduced is a finding a comparable run no longer reports. It stays
	// open and is marked, because the analyzer reacting to a change nearby
	// looks the same as a fix.
	NotReproduced Absence = "not-reproduced"
)

// Declaration is what one kind of finding is.
type Declaration struct {
	Kind Kind
	// Issues is the sorts of issue its findings are filed under. A name a
	// producer of this kind reports is resolved among issues of these sorts
	// and no other, so an analyzer's rule never merges with a CVE. The first
	// is the sort an issue it introduces is filed as.
	Issues []Issue
	// Absence is what a producer no longer reporting one means.
	Absence Absence
	// Visibilities is every visibility a finding of this kind may hold, the
	// one it arrives at first.
	Visibilities []access.Visibility
}

// Declarations is every kind of finding there is.
func Declarations() []Declaration {
	return []Declaration{
		{
			Kind: Vulnerability, Issues: []Issue{Advisory, Flaw}, Absence: Closes,
			Visibilities: []access.Visibility{access.Public, access.Private},
		},
		{
			Kind: Entered, Issues: []Issue{Flaw}, Absence: Stated,
			Visibilities: []access.Visibility{access.Private, access.Public},
		},
		{
			Kind: Analysis, Issues: []Issue{Rule}, Absence: NotReproduced,
			Visibilities: []access.Visibility{access.Internal, access.Private},
		},
	}
}

// Of is the declaration of one kind. A kind nothing declares has none, and
// reads as declaring nothing.
func Of(k Kind) Declaration {
	for _, d := range Declarations() {
		if d.Kind == k {
			return d
		}
	}
	return Declaration{Kind: k}
}

// Known reports whether k is a kind this deployment declares.
func Known(k Kind) bool { return len(Of(k).Issues) > 0 }

// Consumer is something that reads findings. Each states the kinds it
// includes, and a kind it does not name never reaches it.
type Consumer string

const (
	// Closure is a run's sweep: what it opens, updates and closes.
	Closure Consumer = "closure"
	// VersionCarry is a decision lapsing when a version it was about moved
	// (REQ-25), and a decision carried to a build whose versions match.
	VersionCarry Consumer = "version-carry"
	// Ranking is urgency and deadlines: what a finding's order and due date
	// are worked out from, and the passes that rewrite them.
	Ranking Consumer = "ranking"
	// Triage is the shared finding model as people work it: the findings
	// lists and their counts, one finding's page, assignment and routing,
	// decisions and their approvals, notes, queues and disclosure.
	Triage Consumer = "triage"
	// Inventory is the screens about what a build contains: its tree, a
	// component and the places it sits at.
	Inventory Consumer = "inventory"
	// Statistics is every figure about findings: trends, comparisons of two
	// builds, coverage, the reports and the home page's numbers.
	Statistics Consumer = "statistics"
	// Exports is every list written out as a file.
	Exports Consumer = "exports"
	// VEX is the documents stating what affects a build.
	VEX Consumer = "vex"
	// Advisories is the documents about flaws recorded here.
	Advisories Consumer = "advisories"
	// Notifications is what is said to people about findings.
	Notifications Consumer = "notifications"
)

// Consumers is every consumer of findings.
func Consumers() []Consumer {
	return []Consumer{
		Closure, VersionCarry, Ranking, Triage, Inventory, Statistics, Exports,
		VEX, Advisories, Notifications,
	}
}

// Kinds is the kinds this consumer includes.
//
// A run's sweep covers what a scan of the inventory produces, and nothing a
// person recorded: a flaw written by hand and swept by the first run after it
// would be closed silently, with a reason reading as though it went away.
// Analysis results are read by the consumers built for them and by no other;
// the vulnerability figures, documents and lists are about what a build ships,
// and a lead nobody has judged is not that.
func (c Consumer) Kinds() []Kind {
	switch c {
	case Closure:
		return []Kind{Vulnerability}
	case VersionCarry, Ranking, Triage, Inventory, Statistics, Exports, VEX,
		Advisories, Notifications:
		return []Kind{Vulnerability, Entered}
	}
	return nil
}

// Includes reports whether this consumer reads findings of kind k.
func (c Consumer) Includes(k Kind) bool {
	for _, have := range c.Kinds() {
		if have == k {
			return true
		}
	}
	return false
}

// Where is the condition keeping a query to the kinds this consumer includes,
// over a column holding a finding's kind — `"f"."kind"`, quoted as the query
// names it. A consumer including nothing is a condition nothing satisfies.
func (c Consumer) Where(column string) (string, []any) {
	return In(column, c.Kinds())
}

// In is the condition keeping a query to the kinds given, over a column
// holding a finding's kind. None is a condition nothing satisfies.
func In(column string, kinds []Kind) (string, []any) {
	switch len(kinds) {
	case 0:
		return "1 = 0", nil
	case 1:
		return column + " = ?", []any{kinds[0]}
	}
	return column + " IN (?)", []any{bun.List(kinds)}
}

// IssuesOf is every sort of issue a finding of one of these kinds may be filed
// under, each once, in the order the kinds name them.
func IssuesOf(kinds ...Kind) []Issue {
	seen := map[Issue]bool{}
	var out []Issue
	for _, k := range kinds {
		for _, issue := range Of(k).Issues {
			if !seen[issue] {
				seen[issue] = true
				out = append(out, issue)
			}
		}
	}
	return out
}
