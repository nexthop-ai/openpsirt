// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"strconv"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// A reader's view of a finding, worked out from its occurrences.
//
// The two rules here are asked of different populations and reading them the
// same way is the mistake: what a scanner matched on is one line of its report
// written to every occurrence, so any occurrence answers — and whether anything
// is undisclosed is a question about all of them, because one undisclosed
// occurrence among fifty makes the whole of it undisclosed for anybody deciding
// what may be said about it.
func TestDisclosureIsAskedOfEveryOccurrenceAndTheMatchOfAny(t *testing.T) {
	soon := time.Now().UTC().Add(48 * time.Hour)
	later := soon.Add(30 * 24 * time.Hour)
	rows := []evidenceRow{
		{
			Component: "curl", Visibility: string(access.Public),
			Matched: "identifier", MatchedFrom: "nvd", FixState: string(FixedUpstream),
			OpenedAt: time.Now().UTC(),
		},
		{
			Component: "libcurl4t64", Visibility: string(access.Private),
			DiscloseAt: &later,
			OpenedAt:   time.Now().UTC(),
		},
		{
			Component: "libcurl3t64", Visibility: string(access.Public),
			DiscloseAt: &soon,
			OpenedAt:   time.Now().UTC(),
		},
	}
	issue := Vulnerability{Identifier: "CVE-2026-1", Severity: "high"}
	evidence := evidenceFrom(rows, issue, graph.Component{Name: "curl"}, nil, nil, nil)

	if !evidence.Undisclosed {
		t.Error("a fold with one undisclosed occurrence among three reads as disclosed")
	}
	// The soonest, because that is the date the whole of it is bound by.
	if evidence.DiscloseAt == nil || !evidence.DiscloseAt.Equal(soon) {
		t.Errorf("the disclosure date is %v, want the soonest of the occurrences", evidence.DiscloseAt)
	}
	// Off the first occurrence, which is the same line of the report as the rest.
	if evidence.Matched != Matched("identifier") || evidence.MatchedFrom != "nvd" {
		t.Errorf("what the scanner matched on came back as %q from %q",
			evidence.Matched, evidence.MatchedFrom)
	}
}

// A fold of one public occurrence says nothing is undisclosed, which is the other
// direction and the one a wrong reading of the rule above would also pass.
func TestAFoldWithNothingUndisclosedSaysSo(t *testing.T) {
	rows := []evidenceRow{
		{Component: "curl", Visibility: string(access.Public), OpenedAt: time.Now().UTC()},
		{Component: "libcurl4t64", Visibility: string(access.Public), OpenedAt: time.Now().UTC()},
	}
	evidence := evidenceFrom(rows, Vulnerability{Identifier: "CVE-2026-2"},
		graph.Component{Name: "curl"}, nil, nil, nil)
	if evidence.Undisclosed {
		t.Error("a fold whose every occurrence is public reads as undisclosed")
	}
	if evidence.DiscloseAt != nil {
		t.Errorf("a disclosure date was invented: %v", evidence.DiscloseAt)
	}
}

// An inventory that describes one consumer twice — as the source package and as
// the distribution's package, two components by content and one pair of names —
// leaves two rows sharing one occurrence. An occurrence is what a decision is
// recorded at, so the screen reads one row, with the way down of whichever of
// the two the graph could walk.
func TestTwoRowsSharingOneOccurrenceReadAsOneOccurrence(t *testing.T) {
	occurrence := OccurrenceIdentity("linux-image", "opennsl-modules")
	unplaced, walkable := int64(20), int64(21)
	rows := []evidenceRow{
		// The copy nothing placed: the walk up from the first of the two
		// reaches nothing, so that row alone would read as unplaced.
		{
			OccurrenceIdentity: occurrence, Component: "linux-image", Consumer: "opennsl-modules",
			ComponentID: 10, ConsumerID: &unplaced,
		},
		{
			OccurrenceIdentity: occurrence, Component: "linux-image", Consumer: "opennsl-modules",
			ComponentID: 10, ConsumerID: &walkable,
		},
	}
	chains := map[int64][]graph.Step{
		walkable: {{Name: "sonic-broadcom"}, {Name: "host-image"}, {Name: "opennsl-modules"}},
	}
	occurrences := occurrencesOf(rows, chains, map[int64]graph.Step{10: {Version: "6.12.41-1"}}, nil)

	if len(occurrences) != 1 {
		t.Fatalf("%d occurrences for one pair of names, want 1", len(occurrences))
	}
	if got := len(occurrences[0].Chain); got != 4 {
		t.Fatalf("the way down is %d steps, want the walkable one of the two", got)
	}
	if last := occurrences[0].Chain[3]; last.Name != "linux-image" || last.Version != "6.12.41-1" {
		t.Errorf("the way down ends at %q %q, want the component this occurrence is",
			last.Name, last.Version)
	}
}

// The build's own argument covers an occurrence only where it covers every row
// the key folds: a VEX statement about one of two components of the same name
// is not a statement about the occurrence a decision is recorded against.
func TestAnOccurrenceIsSuppressedOnlyWhereEveryRowOfItIs(t *testing.T) {
	occurrence := OccurrenceIdentity("linux-image", "opennsl-modules")
	unplaced, walkable := int64(20), int64(21)
	rows := []evidenceRow{
		{OccurrenceIdentity: occurrence, Component: "linux-image", Consumer: "opennsl-modules",
			ComponentID: 10, ConsumerID: &unplaced, Suppressed: true},
		{OccurrenceIdentity: occurrence, Component: "linux-image", Consumer: "opennsl-modules",
			ComponentID: 10, ConsumerID: &walkable, Suppressed: false},
	}
	occurrences := occurrencesOf(rows, nil, nil, nil)
	if len(occurrences) != 1 {
		t.Fatalf("%d occurrences for one pair of names, want 1", len(occurrences))
	}
	if occurrences[0].Suppressed {
		t.Error("an occurrence reads as argued away by the build where only one of its rows is")
	}
}

// A decision stands at an occurrence, and the rows of an occurrence need not
// hold the same versions: a decision occurrence is keyed on the occurrence and
// expires on the versions, so it matches one row and not its twin. Keeping the
// first row's answer dropped a decision somebody had just made and offered the
// occurrence again.
func TestADecisionStandingOnEitherRowStandsAtTheOccurrence(t *testing.T) {
	occurrence := OccurrenceIdentity("linux-image", "opennsl-modules")
	row, decision := int64(7), int64(3)
	rows := []evidenceRow{
		{OccurrenceIdentity: occurrence, Component: "linux-image", Consumer: "opennsl-modules"},
		{
			OccurrenceIdentity: occurrence, Component: "linux-image", Consumer: "opennsl-modules",
			DecisionOccurrence: &row, Decision: &decision,
		},
	}
	occurrences := occurrencesOf(rows, nil, nil, nil)
	if len(occurrences) != 1 {
		t.Fatalf("%d occurrences for one pair of names, want 1", len(occurrences))
	}
	if occurrences[0].DecisionOccurrence == nil || *occurrences[0].DecisionOccurrence != row {
		t.Error("an occurrence whose second row carries the standing decision reads as undecided")
	}
	if occurrences[0].Decision == nil || *occurrences[0].Decision != decision {
		t.Error("the decision the decision occurrence is a row of was not carried with it")
	}
}

// Lowest identifier, so two engines returning the rows in either order answer
// the same way.
func TestWhereBothRowsAreDecidedTheEarlierDecisionAnswers(t *testing.T) {
	occurrence := OccurrenceIdentity("linux-image", "opennsl-modules")
	later, earlier := int64(9), int64(4)
	laterDecision, earlierDecision := int64(9), int64(4)
	rows := []evidenceRow{
		{OccurrenceIdentity: occurrence, Component: "linux-image", Consumer: "opennsl-modules",
			DecisionOccurrence: &later, Decision: &laterDecision},
		{OccurrenceIdentity: occurrence, Component: "linux-image", Consumer: "opennsl-modules",
			DecisionOccurrence: &earlier, Decision: &earlierDecision},
	}
	occurrences := occurrencesOf(rows, nil, nil, nil)
	if occurrences[0].DecisionOccurrence == nil || *occurrences[0].DecisionOccurrence != earlier {
		t.Errorf("the occurrence reads decision occurrence %s, want the lowest identifier",
			numbered(occurrences[0].DecisionOccurrence))
	}
	if occurrences[0].Decision == nil || *occurrences[0].Decision != earlierDecision {
		t.Error("the decision came from a different row than the decision occurrence did")
	}
}

// numbered is an identifier as a failure should read it, or the word for there
// not being one.
func numbered(id *int64) string {
	if id == nil {
		return "nothing"
	}
	return strconv.FormatInt(*id, 10)
}
