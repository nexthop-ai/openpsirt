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

// Declaration is what one kind of finding is.
type Declaration struct {
	Kind Kind
	// Issues is the sorts of issue its findings are filed under. A name a
	// producer of this kind reports is resolved among issues of these sorts
	// and no other, so an analyzer's rule never merges with a CVE. The first
	// is the sort an issue it introduces is filed as.
	Issues []Issue
}

// Declarations is every kind of finding there is.
func Declarations() []Declaration {
	return []Declaration{
		{Kind: Vulnerability, Issues: []Issue{Advisory, Flaw}},
		{Kind: Entered, Issues: []Issue{Flaw}},
		{Kind: Analysis, Issues: []Issue{Rule}},
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
	// lists and their counts, one finding's page, notes on an issue, and
	// disclosure.
	Triage Consumer = "triage"
	// Assignment is who deals with a finding: the write that gives work to a
	// person or a team or hands it back, handing over everything one person
	// holds, the routing rules' sweep and preview, and the lists of who holds
	// what. It names leads, which Triage does not, so a lead is held, routed
	// and listed as held work by the one implementation a finding is without
	// reaching the findings lists or disclosure.
	Assignment Consumer = "assignment"
	// Decisions is the claims people make about findings: their rows, the
	// reasoning and its revisions, approvals, comments on a claim, the review
	// queue, every read of one claim, and the record of judgments and its file.
	Decisions Consumer = "decisions"
	// Inventory is the screens about what a build contains: its tree, a
	// component and the places it sits at.
	Inventory Consumer = "inventory"
	// Statistics is every figure about findings: trends, comparisons of two
	// builds, coverage, the reports and the home page's numbers.
	Statistics Consumer = "statistics"
	// Exports is the findings lists written out as files: the rows the
	// list reads, then the leads of the same selection as the lead queue
	// reads them.
	Exports Consumer = "exports"
	// Register is the disposition register: what was decided at every place
	// of one build, its screen and its file. It states what a build ships,
	// beside its VEX document, and a lead nobody has judged is not that.
	Register Consumer = "register"
	// VEX is the documents stating what affects a build.
	VEX Consumer = "vex"
	// Advisories is the documents about flaws recorded here.
	Advisories Consumer = "advisories"
	// Notifications is what is said to people about findings.
	Notifications Consumer = "notifications"
	// Evidence is one lead's evidence: where it is, the path the analyzer
	// took to it, links into the source and the source kept beside it.
	Evidence Consumer = "evidence"
	// Leads is the lead queue: the leads a product holds, by where they
	// stand, with how many each list leaves out, the queue's file, the leads
	// a findings list's file carries, and the counts by analyzer series. The counts are here rather than
	// under Statistics, which feeds the vulnerability figures.
	Leads Consumer = "leads"
)

// consumers is every consumer of findings.
func consumers() []Consumer {
	return []Consumer{
		Closure, VersionCarry, Ranking, Triage, Assignment, Decisions, Inventory, Statistics,
		Exports, Register, VEX, Advisories, Notifications, Evidence, Leads,
	}
}

// Kinds is the kinds this consumer includes.
//
// A run's sweep covers what a scan of the inventory produces, and nothing a
// person recorded: a flaw written by hand and swept by the first run after it
// would be closed silently, with a reason reading as though it went away.
// Analysis results are read by the consumers built for them, by the claims
// about them, and by the findings lists' files, which write out everything the
// reader may read. The vulnerability figures, documents and lists are about
// what a build ships, and a lead nobody has judged is not that.
func (c Consumer) Kinds() []Kind {
	switch c {
	case Closure:
		return []Kind{Vulnerability}
	case VersionCarry, Ranking, Triage, Inventory, Statistics, Register, VEX,
		Advisories, Notifications:
		return []Kind{Vulnerability, Entered}
	case Assignment, Decisions, Exports:
		return []Kind{Vulnerability, Entered, Analysis}
	case Evidence, Leads:
		return []Kind{Analysis}
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
