package finding

import (
	"strconv"
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

// An inventory that describes one consumer twice — as the source package and
// as the distribution's package, two components by content and one pair of
// names — leaves two rows sharing one place. A place is what a decision is
// keyed on, so the screen reads one row, with the way down of whichever of the
// two the graph could walk.
func TestTwoRowsSharingOnePlaceReadAsOnePlace(t *testing.T) {
	place := PlaceIdentity("linux-image", "opennsl-modules")
	unplaced, walkable := int64(20), int64(21)
	rows := []evidenceRow{
		// The copy nothing placed: the walk up from the first of the two
		// reaches nothing, so that row alone would read as unplaced.
		{
			PlaceIdentity: place, Component: "linux-image", Consumer: "opennsl-modules",
			ComponentID: 10, ConsumerID: &unplaced,
		},
		{
			PlaceIdentity: place, Component: "linux-image", Consumer: "opennsl-modules",
			ComponentID: 10, ConsumerID: &walkable,
		},
	}
	chains := map[int64][]graph.Step{
		walkable: {{Name: "sonic-broadcom"}, {Name: "host-image"}, {Name: "opennsl-modules"}},
	}
	places := placesOf(rows, chains, map[int64]string{10: "6.12.41-1"})

	if len(places) != 1 {
		t.Fatalf("%d places for one pair of names, want 1", len(places))
	}
	if got := len(places[0].Chain); got != 4 {
		t.Fatalf("the way down is %d steps, want the walkable one of the two", got)
	}
	if last := places[0].Chain[3]; last.Name != "linux-image" || last.Version != "6.12.41-1" {
		t.Errorf("the way down ends at %q %q, want the component this place is",
			last.Name, last.Version)
	}
}

// The build's own argument covers a place only where it covers every row the
// key folds: a VEX statement about one of two components of the same name is
// not a statement about the place a decision is recorded against.
func TestAPlaceIsSuppressedOnlyWhereEveryRowOfItIs(t *testing.T) {
	place := PlaceIdentity("linux-image", "opennsl-modules")
	unplaced, walkable := int64(20), int64(21)
	rows := []evidenceRow{
		{PlaceIdentity: place, Component: "linux-image", Consumer: "opennsl-modules",
			ComponentID: 10, ConsumerID: &unplaced, Suppressed: true},
		{PlaceIdentity: place, Component: "linux-image", Consumer: "opennsl-modules",
			ComponentID: 10, ConsumerID: &walkable, Suppressed: false},
	}
	places := placesOf(rows, nil, nil)
	if len(places) != 1 {
		t.Fatalf("%d places for one pair of names, want 1", len(places))
	}
	if places[0].Suppressed {
		t.Error("a place reads as argued away by the build where only one of its rows is")
	}
}

// A decision stands at a place, and the rows of a place need not hold the same
// versions: a decision is keyed on the place and expires on the versions, so it
// matches one row and not its twin. Keeping the first row's answer dropped a
// claim somebody had just made and offered the place again.
func TestAClaimStandingOnEitherRowStandsAtThePlace(t *testing.T) {
	place := PlaceIdentity("linux-image", "opennsl-modules")
	decision, claim := int64(7), int64(3)
	rows := []evidenceRow{
		{PlaceIdentity: place, Component: "linux-image", Consumer: "opennsl-modules"},
		{
			PlaceIdentity: place, Component: "linux-image", Consumer: "opennsl-modules",
			Decision: &decision, Claim: &claim,
		},
	}
	places := placesOf(rows, nil, nil)
	if len(places) != 1 {
		t.Fatalf("%d places for one pair of names, want 1", len(places))
	}
	if places[0].Decision == nil || *places[0].Decision != decision {
		t.Error("a place whose second row carries the standing claim reads as undecided")
	}
	if places[0].Claim == nil || *places[0].Claim != claim {
		t.Error("the claim the decision is a row of was not carried with it")
	}
}

// Lowest identifier, so two engines returning the rows in either order answer
// the same way.
func TestWhereBothRowsAreDecidedTheEarlierDecisionAnswers(t *testing.T) {
	place := PlaceIdentity("linux-image", "opennsl-modules")
	later, earlier := int64(9), int64(4)
	laterClaim, earlierClaim := int64(9), int64(4)
	rows := []evidenceRow{
		{PlaceIdentity: place, Component: "linux-image", Consumer: "opennsl-modules",
			Decision: &later, Claim: &laterClaim},
		{PlaceIdentity: place, Component: "linux-image", Consumer: "opennsl-modules",
			Decision: &earlier, Claim: &earlierClaim},
	}
	places := placesOf(rows, nil, nil)
	if places[0].Decision == nil || *places[0].Decision != earlier {
		t.Errorf("the place reads decision %s, want the lowest identifier",
			numbered(places[0].Decision))
	}
	if places[0].Claim == nil || *places[0].Claim != earlierClaim {
		t.Error("the claim came from a different row than the decision did")
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
