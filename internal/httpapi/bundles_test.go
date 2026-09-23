// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// bundled is the fix-bundle list.
type bundled struct {
	Items []struct {
		Upstream   string   `json:"upstream"`
		From       string   `json:"from"`
		To         string   `json:"to"`
		Components []string `json:"components"`
		Issues     int      `json:"issues"`
		Places     int      `json:"places"`
		Severity   string   `json:"severity"`
		Exploited  bool     `json:"exploited"`
	} `json:"items"`
	Total int `json:"total"`
}

// aheadOfUs is a date still to come and inside the deadline anything in these
// fixtures already has, so a promise landing on it stands rather than waiting.
//
// A date typed in goes past, and a promise landing on a date already gone is
// refused — so every test about promising work would start failing on a day
// that has nothing to do with what it pins.
//
// Two days rather than one: read as a date, tomorrow is midnight tonight, and
// a run that starts before midnight and reaches these tests after it finds
// tomorrow already behind it. Two days rather than a month, because a promise
// past the deadline it covers is gated and these tests are about what a
// promise reaches — the shortest window in the fixture is three days.
var aheadOfUs = time.Now().UTC().AddDate(0, 0, 2).Format(time.DateOnly)

func TestOneBumpIsOneRowHoweverManyPackagesItMoves(t *testing.T) {
	// The same bump answers thousands of rows and there was no unit for
	// it. Keyed on the source package rather than on the component, so
	// packages built from one source collapse into one row — which also
	// makes the same issue at sibling packages one row rather than
	// several.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)

		var page bundled
		read(t, r, "triager", "/v1/products/mine/fix-bundles", &page)
		if page.Total != 1 || len(page.Items) != 1 {
			t.Fatalf("two packages of one source bumping once are %d bundles: %+v",
				page.Total, page.Items)
		}
		one := page.Items[0]
		if one.Upstream != "curl" || one.To != "8.5.0-1" {
			t.Errorf("the bundle is %q moving to %q", one.Upstream, one.To)
		}
		if len(one.Components) != 2 {
			t.Errorf("the bundle moves %v, want both packages", one.Components)
		}
		// Two issues across two packages is two distinct vulnerabilities and
		// four findings: the row says both, because they answer different
		// questions.
		if one.Issues != 2 || one.Places != 4 {
			t.Errorf("the bundle closes %d issues at %d places, want 2 and 4",
				one.Issues, one.Places)
		}
		// Worth doing for its worst member.
		if one.Severity != "critical" || !one.Exploited {
			t.Errorf("the bundle reads %q exploited=%v, want its worst member",
				one.Severity, one.Exploited)
		}

		// Nothing without a fix is in a bundle: a bundle is a version to move
		// to, and one keyed on an empty version would hold everything
		// unfixable.
		var all struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings", &all)
		// Three rows rather than five: the list groups on the fold, so the two
		// binaries of one source package are one row wherever they carry the
		// same issue. That is the same collapse the bundle makes, which is why
		// the two are one query read from either end.
		if all.Total != 3 {
			t.Fatalf("the fixture lists %d rows, want its three folds", all.Total)
		}
		// The whole point: three rows to answer one at a time, or one
		// bump to declare. The one with no fix is in neither the bundle nor
		// its issue count.
	})
}

// scannedSiblings puts two packages built from one source into a build, each
// carrying the same two issues, plus one issue nothing has released a fix for.
//
// The shape the fix bundle is about: curl, libcurl4t64 and libcurl3t64 are one
// source package bumping once, and keying on the component would make that
// three rows that all say the same thing.
func (r *reach) scannedSiblings(t *testing.T) {
	t.Helper()
	r.siblingsIn(t, "broadcom")
}

// siblingsAlsoIn puts the same two packages, at the same versions, in a second
// variant of the same branch. A decision is keyed on the place and the two
// upstream versions and on no build at all, so this is the fixture in which
// one decision covers two findings — and the one in which proposing per
// finding writes the same key twice.
func (r *reach) siblingsAlsoIn(t *testing.T, variant string) {
	t.Helper()
	if _, err := catalog.NewStore(r.db.DB).DeclareVariant(t.Context(),
		r.productID(t), variant, true); err != nil {
		t.Fatal(err)
	}
	r.siblingsIn(t, variant)
}

func (r *reach) productID(t *testing.T) int64 {
	t.Helper()
	product, err := catalog.NewStore(r.db.DB).ProductByName(t.Context(), "mine")
	if err != nil {
		t.Fatal(err)
	}
	return product.ID
}

// scannedTwoSources puts two packages of two different source packages in the
// build, both carrying one issue.
//
// The fixture for anything about two answers to one issue: one judgment covers
// a whole fold, so two different answers within one fold is not a state
// anything can reach.
func (r *reach) scannedTwoSources(t *testing.T) {
	t.Helper()
	r.siblingsIn(t, "broadcom", graph.Described{
		Purl: "pkg:deb/debian/libexpat1@2.5.0-1", Name: "libexpat1", Version: "2.5.0-1",
		UpstreamName: "expat", UpstreamVersion: "2.5.0-1",
	})
}

func (r *reach) siblingsIn(t *testing.T, variant string, also ...graph.Described) {
	t.Helper()
	ctx := t.Context()

	names := catalog.NewStore(r.db.DB)
	located, err := names.Locate(ctx, "mine", "master", variant)
	if err != nil {
		t.Fatal(err)
	}
	target, err := names.TargetFor(ctx, located.StreamID, located.VariantID)
	if err != nil {
		t.Fatal(err)
	}
	scan, outcome, err := ingest.NewStore(r.db.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "siblings-" + variant, BuiltAt: time.Now().UTC(),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}

	product := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
	// Two binary packages of one source, which is what the key collapses.
	four := graph.Described{
		Purl: "pkg:deb/debian/libcurl4t64@8.4.0-1", Name: "libcurl4t64", Version: "8.4.0-1",
		UpstreamName: "curl", UpstreamVersion: "8.4.0-1",
	}
	three := graph.Described{
		Purl: "pkg:deb/debian/libcurl3t64@8.4.0-1", Name: "libcurl3t64", Version: "8.4.0-1",
		UpstreamName: "curl", UpstreamVersion: "8.4.0-1",
	}
	shipped := append([]graph.Described{four, three}, also...)
	edges := make([]graph.Dependency, 0, len(shipped))
	for _, one := range shipped {
		edges = append(edges, graph.Dependency{Parent: product, Child: one})
	}
	if _, err := graph.NewStore(r.db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
		Root: product, Components: shipped, Dependencies: edges,
	}); err != nil {
		t.Fatal(err)
	}

	findings := finding.NewStore(r.db.DB)
	run, err := findings.Begin(ctx, finding.Run{
		TargetID: target.ID, Scanner: "grype", ScannerVersion: "0.112.0",
		DatabaseVersion: "2026-08-28", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var reported []finding.Reported
	for _, at := range shipped {
		reported = append(reported,
			finding.Reported{
				Issue: finding.Named{
					Identifier: "CVE-2026-CURL1", Severity: "critical", Exploited: true,
				},
				Component: at, FixState: finding.FixedUpstream, FixedIn: "8.5.0-1",
			},
			finding.Reported{
				Issue:     finding.Named{Identifier: "CVE-2026-CURL2", Severity: "low"},
				Component: at, FixState: finding.FixedUpstream, FixedIn: "8.5.0-1",
			},
		)
	}
	// And one nothing has released a fix for, which is in no bundle.
	reported = append(reported, finding.Reported{
		Issue:     finding.Named{Identifier: "CVE-2026-CURL3", Severity: "high"},
		Component: four, FixState: finding.NoFix,
	})
	if _, err := findings.Apply(ctx, target.ID, run.ID, reported); err != nil {
		t.Fatal(err)
	}
}

func TestPlanningAnUpgradeAnswersEveryBinaryOfTheSourcePackage(t *testing.T) {
	// An upgrade is the unit a remediation is done in, and answering it a
	// row at a time is one page per row it covers. Coverage follows the
	// source package: curl, libcurl4t64 and libcurl3t64 are one package
	// bumping once, so naming any of them reaches all of them — and it
	// covers everything open on them, not only what records this version
	// as its fix, because deciding that would need an ordering nothing
	// here has.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)

		const at = "/v1/products/mine/components/libcurl4t64/upgrade"
		// A judgment with no reasoning is refused like every other.
		if got := asPerson(t, r, "triager", http.MethodPost, at,
			`{"to":"8.5.0-1","by":"`+aheadOfUs+`"}`); got.Code < 400 {
			t.Errorf("a bump with no reasoning answered %d", got.Code)
		}

		// One act, one transaction. A release past end-of-life cannot be a fix
		// target, and that refusal comes from the half that writes the intent
		// — after the judgments have been written. Nothing may survive it: a
		// bump half declared is a release plan that says a bump is declared
		// for a release it is not.
		gone := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
		if set := asPerson(t, r, "admin", http.MethodPut,
			"/v1/products/mine/streams/master/end-of-life",
			`{"on":"`+gone+`"}`); set.Code >= 300 {
			t.Fatalf("retiring the release answered %d: %s", set.Code, set.Body.String())
		}
		refused := asPerson(t, r, "triager", http.MethodPost, at,
			`{"to":"8.5.0-1","by":"`+aheadOfUs+`",`+
				`"reasoning":"Taking the bump.",`+
				`"builds":[{"stream":"master","variant":"broadcom"}]}`)
		if refused.Code < 400 {
			t.Fatalf("declaring a fix in a retired release answered %d", refused.Code)
		}
		var left struct {
			Total int `json:"total"`
		}
		// Asked of both states of support: the release was just retired, and
		// the list keeps to what is in support unless told otherwise. What is
		// being checked is that the rows are still undecided, wherever they
		// sit.
		read(t, r, "triager",
			"/v1/products/mine/findings?state=undecided&support=in-support&support=past-eol",
			&left)
		if left.Total != 3 {
			t.Fatalf("a refused bump left %d of three rows undecided, so half of it stood",
				left.Total)
		}
		if set := asPerson(t, r, "admin", http.MethodPut,
			"/v1/products/mine/streams/master/end-of-life", `{"on":""}`); set.Code >= 300 {
			t.Fatalf("putting the release back answered %d: %s", set.Code, set.Body.String())
		}
		// Putting a release back puts what is open in it back on the clock,
		// and that rewrite happens away from the request. Run here as well so
		// what follows is asked of a settled state rather than of a race: it
		// computes the same deadlines, so the pass that is still in flight
		// writes the same values.
		if _, err := finding.NewStore(r.db.DB).Recompute(t.Context(),
			finding.DefaultWindows()); err != nil {
			t.Fatal(err)
		}

		got := asPerson(t, r, "triager", http.MethodPost, at,
			`{"to":"8.5.0-1","by":"`+aheadOfUs+`",`+
				`"reasoning":"Taking the 8.5.0 bump in the next build.",`+
				`"builds":[{"stream":"master","variant":"broadcom"}]}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("declaring a bump answered %d: %s", got.Code, got.Body.String())
		}
		var done struct {
			ClaimID    int64 `json:"claim_id"`
			Decisions  int   `json:"decisions"`
			Targets    int   `json:"targets"`
			Issues     int   `json:"issues"`
			Components int   `json:"components"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &done); err != nil {
			t.Fatal(err)
		}
		// Everything open across both binaries of the source package, not
		// only what named this version — five places, three issues, both
		// packages, under one claim.
		if done.Decisions != 5 || done.Issues != 3 || done.Components != 2 {
			t.Errorf("one upgrade wrote %+v, want five places across three issues"+
				" and both packages of the source", done)
		}
		if done.ClaimID == 0 {
			t.Error("an upgrade recorded no claim")
		}
		// One commitment per build and fold, which is the grain the work is
		// done in and what the pending-upgrades screen reads. It was one per
		// issue and per component and per target version, so changing the
		// version meant rewriting every row of it.
		if done.Targets != 1 {
			t.Errorf("one upgrade recorded %d commitments, want the one bump it is",
				done.Targets)
		}

		// Everything it reached now carries a claim, and the one nothing has
		// fixed does not. "Waiting" rather than "agreed": every decision here
		// is written as proposed and this outcome simply needs nobody to agree
		// to it, which is the state an ordinary affected decision lands in
		// too.
		var decided struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?state=waiting", &decided)
		if decided.Total != 3 {
			t.Errorf("%d rows carry a claim after the upgrade, want the three it covered",
				decided.Total)
		}

		// And what it covers is derived rather than marked: the same rows come
		// back when the list is asked for what a planned upgrade covers, with
		// nothing written to say so.
		read(t, r, "triager", "/v1/products/mine/findings?planned=planned", &decided)
		if decided.Total != 3 {
			t.Errorf("%d rows read as planned, want the three the upgrade covers", decided.Total)
		}
		read(t, r, "triager", "/v1/products/mine/findings?planned=unplanned", &decided)
		if decided.Total != 0 {
			t.Errorf("%d rows read as unplanned, want none left", decided.Total)
		}
		// And a word for asking neither, which is what the by-issue list needs
		// to be told once it leaves planned work out by default: deleting the
		// filter is how the address asks for the default, so turning it off
		// has to be something the address can spell.
		var everything struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings", &everything)
		read(t, r, "triager", "/v1/products/mine/findings?planned=either", &decided)
		if decided.Total != everything.Total {
			t.Errorf("asking for covered or not returned %d of %d rows",
				decided.Total, everything.Total)
		}
	})
}

func TestABuildSaysWhichUpgradesItIsWaitingOnAndWhatHasLanded(t *testing.T) {
	// The fix-bundle query read from the other end: a triager reads a bump
	// and the issues it closes, a coordinator reads a build and the bumps
	// it is waiting on. One query, so the two cannot come to disagree.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		if got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/components/libcurl4t64/upgrade",
			`{"to":"8.5.0-1","by":"`+aheadOfUs+`",`+
				`"reasoning":"Taking the 8.5.0 bump.",`+
				`"builds":[{"stream":"master","variant":"broadcom"}]}`); got.Code != http.StatusCreated {
			t.Fatalf("declaring answered %d: %s", got.Code, got.Body.String())
		}

		const plan = "/v1/products/mine/streams/master/variants/broadcom/pending-upgrades"
		var waiting struct {
			Items []struct {
				Upstream   string   `json:"upstream"`
				To         string   `json:"to"`
				Components []string `json:"components"`
				Issues     int      `json:"issues"`
				Places     int      `json:"places"`
				State      string   `json:"state"`
			} `json:"items"`
		}
		read(t, r, "triager", plan, &waiting)
		if len(waiting.Items) != 1 {
			t.Fatalf("the release is waiting on %d bumps: %+v", len(waiting.Items), waiting.Items)
		}
		one := waiting.Items[0]
		// Three issues across two sibling packages, at five places, none
		// landed — an upgrade covers everything open on the fold, not only
		// what named this version as its fix.
		if one.Upstream != "curl" || one.Issues != 3 || one.Places != 5 {
			t.Errorf("the plan says %+v, want the three issues it covers at five places", one)
		}
		if len(one.Components) != 2 {
			t.Errorf("the bump moves %v here, want both packages", one.Components)
		}

		// Nothing is declared done by hand: what has landed is what the scans
		// stopped reporting. Closing the findings is what moves the number.
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("closed_at = ?", time.Now().UTC()).
			Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-CURL2").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		var after struct {
			Items []struct {
				Issues int    `json:"issues"`
				Places int    `json:"places"`
				State  string `json:"state"`
			} `json:"items"`
		}
		read(t, r, "triager", plan, &after)
		if len(after.Items) != 1 || after.Items[0].Issues != 2 {
			t.Errorf("after one issue of three closed the plan says %+v, want two left",
				after.Items)
		}
	})
}

func TestAnUpgradeIsOneDecisionPerPlaceHoweverManyBuildsShipIt(t *testing.T) {
	// A decision is keyed on the product, the issue, the place and the two
	// upstream versions — no build appears in that key, deliberately, so the
	// same claim is recognized across variants. A component shipped at the
	// same version by two builds is therefore one thing to decide about and
	// two findings, and proposing per finding wrote the same key twice: the
	// second collided with the index that keeps one claim standing per place
	// and took the whole act down with it, so every product with more than
	// one build refused every bundle it was asked to declare.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		r.siblingsAlsoIn(t, "mellanox")

		var before struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?state=undecided", &before)

		got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/components/libcurl4t64/upgrade",
			`{"to":"8.5.0-1","by":"`+aheadOfUs+`",`+
				`"reasoning":"Taking the 8.5.0 bump in the next build.",`+
				`"builds":[{"stream":"master","variant":"broadcom"},`+
				`{"stream":"master","variant":"mellanox"}]}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("declaring a bump across two builds answered %d: %s",
				got.Code, got.Body.String())
		}
		var out struct {
			Decisions int `json:"decisions"`
			Issues    int `json:"issues"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		// Five places at two sibling packages of one source, and five
		// decisions however many builds ship them: a decision is keyed on the
		// place, and no build appears in that key.
		if out.Decisions != 5 {
			t.Errorf("an upgrade over two builds wrote %d decisions, want the five "+
				"places it covers", out.Decisions)
		}

		var after struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?state=undecided", &after)
		if after.Total >= before.Total {
			t.Errorf("after the bump %d rows are still undecided, from %d",
				after.Total, before.Total)
		}
	})
}

func TestABuildHasOneCommitmentPerFold(t *testing.T) {
	// A release moves a package to one version, so a build carries one
	// commitment per fold however many binaries that source package ships and
	// whatever version each finding names as its fix. What the commitment
	// covers follows from the fold, because coverage is a match rather than a
	// list.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)

		// The two curl issues name different versions as their fix, which is
		// what would split the plan in two if the version decided coverage.
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("fixed_in = ?", "8.6.0-1").
			Where(`vulnerability_id IN (SELECT id FROM "vulnerability" WHERE identifier = ?)`,
				"CVE-2026-CURL2").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		// One bump, declared against one of the two binaries. The other is
		// the same source package, so nothing is declared against it.
		ahead := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
		if got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/components/libcurl4t64/upgrade",
			`{"to":"8.6.0-1","by":"`+ahead+`",`+
				`"reasoning":"Taking the 8.6.0 bump in the next build.",`+
				`"builds":[{"stream":"master","variant":"broadcom"}]}`); got.Code != http.StatusCreated {
			t.Fatalf("declaring answered %d: %s", got.Code, got.Body.String())
		}

		var plan struct {
			Items []struct {
				Upstream string `json:"upstream"`
				To       string `json:"to"`
				Issues   int    `json:"issues"`
			} `json:"items"`
		}
		read(t, r, "triager",
			"/v1/products/mine/streams/master/variants/broadcom/pending-upgrades", &plan)

		curl := 0
		for _, row := range plan.Items {
			if row.Upstream == "curl" {
				curl++
			}
		}
		if curl != 1 {
			t.Fatalf("the plan reports curl %d times, want the one bump the release is: %+v",
				curl, plan.Items)
		}
		// And it covers everything open on the fold, not only what named the
		// version it is moving to: three issues across both binaries.
		for _, row := range plan.Items {
			if row.Upstream == "curl" && row.Issues != 3 {
				t.Errorf("the curl bump covers %d issues, want everything open on the fold",
					row.Issues)
			}
		}
	})
}

func TestAPromisedUpgradeSaysWhereItStandsAndLapsesAsOneItem(t *testing.T) {
	// Planned, landed, lapsed — derived on every read from the scans and
	// the date, and set by nobody.
	//
	// A lapsed promise returns the *upgrade*, not its findings: deciding
	// them again one at a time is the thing the promise was made instead
	// of, so what comes back is one item to whoever holds it. There is no
	// "replanned": re-promising writes a new date, and a replanned upgrade
	// is a planned one with a later date.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		const plan = "/v1/products/mine/streams/master/variants/broadcom/pending-upgrades"
		standing := func(t *testing.T) struct {
			By     string `json:"by"`
			HeldBy string `json:"held_by"`
			State  string `json:"state"`
			Issues int    `json:"issues"`
		} {
			t.Helper()
			var waiting struct {
				Items []struct {
					By     string `json:"by"`
					HeldBy string `json:"held_by"`
					State  string `json:"state"`
					Issues int    `json:"issues"`
				} `json:"items"`
			}
			read(t, r, "triager", plan, &waiting)
			if len(waiting.Items) != 1 {
				t.Fatalf("%d rows on the plan: %+v", len(waiting.Items), waiting.Items)
			}
			return waiting.Items[0]
		}

		// Inside the deadline of the worst thing it covers, so it stands
		// without a second person and actually covers what it says it does —
		// past that it is a deferral of the worst thing in the set, waits for
		// an approver, and covers nothing in the meantime.
		ahead := time.Now().UTC().AddDate(0, 0, 1).Format(time.DateOnly)
		if got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/components/libcurl4t64/upgrade",
			`{"to":"8.5.0-1","by":"`+ahead+`",`+
				`"reasoning":"Taking the 8.5.0 bump in the next build.",`+
				`"builds":[{"stream":"master","variant":"broadcom"}]}`); got.Code != http.StatusCreated {
			t.Fatalf("declaring answered %d: %s", got.Code, got.Body.String())
		}
		if one := standing(t); one.State != "planned" || one.By != ahead {
			t.Errorf("a promise for %s reads as %+v, want planned", ahead, one)
		}

		// The party carrying it, which is what a lapsed one comes back
		// to. Held only where one party holds all of what is still
		// open under it: a bump split between two people is nobody's,
		// and naming one of them would hand somebody work that is half
		// theirs.
		if got := asPerson(t, r, "assigner", http.MethodPut,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-CURL1/components/libcurl4t64/assignment",
			`{"person":"triager"}`); got.Code >= 300 {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		if one := standing(t); one.HeldBy != "" {
			t.Errorf("one piece of five held reads as carried by %q", one.HeldBy)
		}

		// The date passes with work outstanding, and nothing else changes.
		// Moved on the commitment rather than by asking the application to
		// believe a different today: what lapses it is the date it named.
		if _, err := r.db.DB.NewUpdate().Table("upgrade").
			Set("committed_to = ?", time.Now().UTC().AddDate(0, 0, -2)).
			Where("committed_to IS NOT NULL").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if one := standing(t); one.State != "lapsed" {
			t.Errorf("a promise two days past reads as %q", one.State)
		}
		// And the findings it covers are still covered: what returns is the
		// upgrade, not five rows for somebody to answer one at a time.
		var covered struct {
			Total int `json:"total"`
		}
		read(t, r, "triager", "/v1/products/mine/findings?planned=planned", &covered)
		if covered.Total != 3 {
			t.Errorf("%d rows are still covered by the lapsed promise, want its three",
				covered.Total)
		}

		// Everything it covers gone is landed, whatever the date said.
		if _, err := r.db.DB.NewUpdate().Table("finding").
			Set("closed_at = ?", time.Now().UTC()).
			Where("closed_at IS NULL").
			Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if one := standing(t); one.State != "landed" || one.Issues != 0 {
			t.Errorf("everything closed reads as %+v, want landed", one)
		}
	})
}

func TestChangingWhatAReleaseIsMovingToTakesBackTheAgreement(t *testing.T) {
	// An approver agreed to a version by a date. A coordinator quietly
	// rewriting either half would leave the agreement standing over a promise
	// nobody read, which is the failure the second person exists to prevent.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		got := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/components/libcurl4t64/upgrade",
			`{"to":"8.5.0-1","by":"2030-01-01",`+
				`"reasoning":"Taking the 8.5.0 bump.",`+
				`"builds":[{"stream":"master","variant":"broadcom"}]}`)
		if got.Code != http.StatusCreated {
			t.Fatalf("declaring answered %d: %s", got.Code, got.Body.String())
		}
		var made struct {
			ClaimID int64 `json:"claim_id"`
			Waiting bool  `json:"waiting"`
		}
		if err := json.Unmarshal(got.Body.Bytes(), &made); err != nil || made.ClaimID == 0 {
			t.Fatalf("declaring answered %s (%v)", got.Body.String(), err)
		}
		// A failure rather than a skip. Waiting is derived from the
		// deployment's approval threshold, which is a setting: a change that
		// stopped a promise of this size needing a second person would make
		// this test pass by not running, and the invariant it is named for —
		// editing what a release is moving to withdraws the standing
		// agreement — would stop being checked with nothing reporting red.
		if !made.Waiting {
			t.Fatal("a bump this size no longer needs a second person, so the " +
				"agreement this test takes back was never given")
		}
		if ok := asPerson(t, r, "reviewer", http.MethodPost,
			fmt.Sprintf("/v1/claims/%d/approval", made.ClaimID), `{}`); ok.Code != http.StatusOK {
			t.Fatalf("approving answered %d: %s", ok.Code, ok.Body.String())
		}

		const plan = "/v1/products/mine/streams/master/variants/broadcom/pending-upgrades"
		var waiting struct {
			Items []struct {
				To string `json:"to"`
				By string `json:"by"`
			} `json:"items"`
		}
		read(t, r, "triager", plan, &waiting)
		if len(waiting.Items) != 1 || waiting.Items[0].To != "8.5.0-1" {
			t.Fatalf("the release is waiting on %+v", waiting.Items)
		}

		// Moved, with a reason, which is what a second person reads.
		if moved := asPerson(t, r, "triager", http.MethodPut,
			fmt.Sprintf("/v1/claims/%d/promise", made.ClaimID),
			`{"to":"8.6.0-1","by":"2030-02-01","reasoning":"8.5.0 was pulled; taking 8.6.0."}`,
		); moved.Code != http.StatusNoContent {
			t.Fatalf("re-promising answered %d: %s", moved.Code, moved.Body.String())
		}

		// One row changed, and everything it covers follows.
		read(t, r, "triager", plan, &waiting)
		if len(waiting.Items) != 1 || waiting.Items[0].To != "8.6.0-1" ||
			waiting.Items[0].By != "2030-02-01" {
			t.Errorf("after re-promising the release is waiting on %+v", waiting.Items)
		}

		// And the agreement is gone: it is back in the queue.
		var queue struct {
			Total int `json:"total"`
		}
		read(t, r, "reviewer", "/v1/review-queue", &queue)
		if queue.Total == 0 {
			t.Error("a promise that changed is not waiting for anybody again")
		}
	})
}

func TestAPromiseCarriesNoBoundAndAJudgmentKeepsItsOwn(t *testing.T) {
	// One bound governed two actions with opposite risk profiles. A bulk
	// dismissal is bounded because nothing re-checks it: one sentence
	// answering a thousand findings has to stay a size a reviewer can follow.
	// A promise to upgrade is the one bulk write that verifies itself — the
	// next scan re-checks every row it names — and narrowing one makes the
	// record false, because the bump closes what it closes.
	//
	// In a real image one kernel bump reached 4,485 findings across 44,016
	// places. Held to the shipped two thousand, the highest-value action in
	// the data was refused by a factor of twenty-two, and the only escape was
	// raising a setting that guards the dismissal path.
	twoReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		// One, so anything covering more than a single place is past it. The
		// fold here is five places.
		if got := asPerson(t, r, "admin", http.MethodPut, "/v1/settings/triage.together-cap",
			`{"value":"1"}`); got.Code != http.StatusNoContent {
			t.Fatalf("setting the cap answered %d: %s", got.Code, got.Body.String())
		}

		// The judgment, refused, which is what keeps this test honest: the cap
		// is in force and reaching this path.
		judged := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-CURL1/components/libcurl4t64/decision",
			`{"outcome":"not-applicable","justification":"vulnerable_code_not_in_execute_path",`+
				`"reasoning":"The transfer path is never reached."}`)
		if judged.Code != http.StatusUnprocessableEntity {
			t.Fatalf("a bulk judgment past the cap answered %d: %s",
				judged.Code, judged.Body.String())
		}

		// And the promise, written.
		promised := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/components/libcurl4t64/upgrade",
			`{"to":"8.5.0-1","by":"`+aheadOfUs+`",`+
				`"reasoning":"Taking the 8.5.0 bump.",`+
				`"builds":[{"stream":"master","variant":"broadcom"}]}`)
		if promised.Code != http.StatusCreated {
			t.Fatalf("a promise past the cap answered %d: %s",
				promised.Code, promised.Body.String())
		}
		var done struct {
			Decisions int `json:"decisions"`
			Issues    int `json:"issues"`
		}
		if err := json.Unmarshal(promised.Body.Bytes(), &done); err != nil {
			t.Fatal(err)
		}
		// Everything the fold covers, not one row of it. A promise narrowed to
		// the cap would record a bump answering one place when it answers
		// five.
		if done.Decisions <= 1 || done.Issues != 3 {
			t.Errorf("the promise recorded %+v, want every place of the three issues", done)
		}
	})
}

func TestABulkJudgmentCoversTheFoldTheListShowed(t *testing.T) {
	// The by-issue list folds to the source package: curl, libcurl4t64 and
	// libcurl3t64 are one row. Keyed on the binary that was named, the bulk
	// screen offered a quarter of what that row stood for and the judgment
	// covered a quarter of what the person meant — four claims and four
	// approvals to answer what reads as one thing.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)

		// The candidate list, asked about one binary of the fold.
		var candidates struct {
			Items []struct {
				Vulnerability string `json:"vulnerability"`
				Places        int    `json:"places"`
			} `json:"items"`
			Findings int `json:"findings"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/components/libcurl4t64/issues", &candidates)
		// Both siblings carry the two fixable issues, and the third sits on
		// one of them: three issues, five findings across the fold.
		if len(candidates.Items) != 3 || candidates.Findings != 5 {
			t.Errorf("the candidates are %d issues over %d findings, want 3 over 5: %+v",
				len(candidates.Items), candidates.Findings, candidates.Items)
		}
		for _, item := range candidates.Items {
			if item.Vulnerability == "CVE-2026-CURL1" && item.Places != 2 {
				t.Errorf("an issue at both packages of the fold says %d places", item.Places)
			}
		}

		// And the judgment written from it covers the fold, in one claim.
		decided := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/components/libcurl4t64/decisions",
			`{"vulnerabilities":["CVE-2026-CURL1"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_in_execute_path",`+
				`"selected_by":"the whole fold",`+
				`"reasoning":"The transfer path is never reached from this image."}`)
		if decided.Code != http.StatusCreated {
			t.Fatalf("deciding together answered %d: %s", decided.Code, decided.Body.String())
		}
		var written struct {
			Recorded int     `json:"recorded"`
			IDs      []int64 `json:"ids"`
		}
		if err := json.Unmarshal(decided.Body.Bytes(), &written); err != nil {
			t.Fatal(err)
		}
		// Both packages of the fold carry that issue, so one act answers both.
		// Keyed on the named binary it answered one and reported that it had
		// covered what the list showed.
		if written.Recorded != 2 || len(written.IDs) != 2 {
			t.Errorf("one judgment wrote %d decisions, want the two places of the fold",
				written.Recorded)
		}
	})
}

func TestABulkClaimRecordsANarrowingAnApproverCanCheck(t *testing.T) {
	// The server resolves the places itself, correctly and for exactly this
	// reason, and took the claimant's word for how the issue list was chosen.
	// A claim reading "drivers this image does not build" over a set picked by
	// ticking everything is indistinguishable in the record from an honest
	// one, and what is asked for is how the set was chosen — which an approver
	// has to be able to act on.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/libcurl4t64/decisions"

		// Everything the component holds, described as though it were a subset.
		everything := asPerson(t, r, "triager", http.MethodPost, at,
			`{"vulnerabilities":["CVE-2026-CURL1","CVE-2026-CURL2"],`+
				`"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_in_execute_path",`+
				`"selected_by":"only the ones in the transfer path",`+
				`"reasoning":"The transfer path is never reached from this image."}`)
		if everything.Code != http.StatusCreated {
			t.Fatalf("deciding together answered %d: %s",
				everything.Code, everything.Body.String())
		}
		var made struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(everything.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}

		var detail struct {
			Claim struct {
				SelectedBy string `json:"selected_by"`
				Selection  *struct {
					Contains string `json:"contains"`
					Matched  int    `json:"matched"`
					Named    int    `json:"named"`
				} `json:"selection"`
			} `json:"claim"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d", made.ClaimID), &detail)
		claim := detail.Claim
		if claim.Selection == nil {
			t.Fatal("a bulk claim records no narrowing an approver could re-run")
		}
		// Three issues are open at the fold and none was narrowed away, so the
		// sentence claiming a subset is visible as one: named two of the three
		// with no narrowing at all.
		if claim.Selection.Contains != "" {
			t.Errorf("the claim says it narrowed by %q", claim.Selection.Contains)
		}
		if claim.Selection.Matched != 3 || claim.Selection.Named != 2 {
			t.Errorf("the narrowing reached %d and named %d, want 3 and 2",
				claim.Selection.Matched, claim.Selection.Named)
		}
		// And the prose is kept, because it is what the person meant to say.
		if claim.SelectedBy != "only the ones in the transfer path" {
			t.Errorf("the claimant's own words are %q", claim.SelectedBy)
		}
	})
}

func TestANarrowedClaimRecordsWhatThatNarrowingReaches(t *testing.T) {
	// The empty-term path proves the record exists; this one proves the term
	// is re-run. Without it the escaped match that produces the number an
	// approver checks the claim against could be deleted and every test would
	// still pass, while the screen sends it on every narrowed claim.
	eachReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scannedSiblings(t)
		// One of the three issues says something the others do not. A percent
		// sign in the text as well, because the escape is what stops a term
		// holding one from selecting far more than the box said — and this is
		// the set a bulk judgment is then recorded against.
		if _, err := r.db.DB.NewUpdate().Table("vulnerability").
			Set("description = ?", "A 100% reachable fault in the transfer driver.").
			Where("identifier = ?", "CVE-2026-CURL1").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		const at = "/v1/products/mine/streams/master/variants/broadcom" +
			"/components/libcurl4t64/decisions"
		decided := asPerson(t, r, "triager", http.MethodPost, at,
			`{"vulnerabilities":["CVE-2026-CURL1"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_in_execute_path",`+
				`"selected_by":"the transfer driver","contains":"driver",`+
				`"reasoning":"The transfer path is never reached from this image."}`)
		if decided.Code != http.StatusCreated {
			t.Fatalf("deciding together answered %d: %s", decided.Code, decided.Body.String())
		}
		var made struct {
			ClaimID int64 `json:"claim_id"`
		}
		if err := json.Unmarshal(decided.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		var detail struct {
			Claim struct {
				Selection *struct {
					Contains string `json:"contains"`
					Matched  int    `json:"matched"`
					Named    int    `json:"named"`
				} `json:"selection"`
			} `json:"claim"`
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d", made.ClaimID), &detail)
		if detail.Claim.Selection == nil {
			t.Fatal("a narrowed claim records no narrowing")
		}
		one := detail.Claim.Selection
		// One of the three matches that word, and one was claimed about: the
		// sentence describes the set, which is what the two numbers say.
		if one.Contains != "driver" || one.Matched != 1 || one.Named != 1 {
			t.Errorf("the narrowing reads %+v, want driver reaching 1 and naming 1", one)
		}

		// And a term holding a percent matches the text that holds one rather
		// than everything. Spliced raw it is a wildcard, and the claim would
		// record three where the person saw one.
		escaped := asPerson(t, r, "triager", http.MethodPost, at,
			`{"vulnerabilities":["CVE-2026-CURL2"],"outcome":"not-applicable",`+
				`"justification":"vulnerable_code_not_in_execute_path",`+
				`"selected_by":"the ones mentioning a percentage","contains":"100%",`+
				`"reasoning":"The transfer path is never reached from this image."}`)
		if escaped.Code != http.StatusCreated {
			t.Fatalf("deciding together answered %d: %s", escaped.Code, escaped.Body.String())
		}
		if err := json.Unmarshal(escaped.Body.Bytes(), &made); err != nil {
			t.Fatal(err)
		}
		read(t, r, "triager", fmt.Sprintf("/v1/claims/%d", made.ClaimID), &detail)
		if detail.Claim.Selection == nil {
			t.Fatal("a narrowed claim records no narrowing")
		}
		if got := detail.Claim.Selection.Matched; got != 1 {
			t.Errorf("a term holding a percent reached %d issues, want the one whose "+
				"text holds it", got)
		}
	})
}
