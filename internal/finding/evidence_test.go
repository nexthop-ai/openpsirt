package finding

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// What a reader is shown about a finding, worked out from its places.
//
// The two rules here are asked of different populations and reading them the
// same way is the mistake: what a scanner matched on is one line of its report
// written to every place, so any place answers — and whether anything is
// undisclosed is a question about all of them, because one undisclosed place
// among fifty makes the whole of it undisclosed for anybody deciding what may
// be said about it.
func TestDisclosureIsAskedOfEveryPlaceAndTheMatchOfAny(t *testing.T) {
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
		t.Error("a fold with one undisclosed place among three reads as disclosed")
	}
	// The soonest, because that is the date the whole of it is bound by.
	if evidence.DiscloseAt == nil || !evidence.DiscloseAt.Equal(soon) {
		t.Errorf("the disclosure date is %v, want the soonest of the places", evidence.DiscloseAt)
	}
	// Off the first place, which is the same line of the report as the rest.
	if evidence.Matched != Matched("identifier") || evidence.MatchedFrom != "nvd" {
		t.Errorf("what the scanner matched on came back as %q from %q",
			evidence.Matched, evidence.MatchedFrom)
	}
}

// A fold of one public place says nothing is undisclosed, which is the other
// direction and the one a wrong reading of the rule above would also pass.
func TestAFoldWithNothingUndisclosedSaysSo(t *testing.T) {
	rows := []evidenceRow{
		{Component: "curl", Visibility: string(access.Public), OpenedAt: time.Now().UTC()},
		{Component: "libcurl4t64", Visibility: string(access.Public), OpenedAt: time.Now().UTC()},
	}
	evidence := evidenceFrom(rows, Vulnerability{Identifier: "CVE-2026-2"},
		graph.Component{Name: "curl"}, nil, nil, nil)
	if evidence.Undisclosed {
		t.Error("a fold whose every place is public reads as undisclosed")
	}
	if evidence.DiscloseAt != nil {
		t.Errorf("a disclosure date was invented: %v", evidence.DiscloseAt)
	}
}
