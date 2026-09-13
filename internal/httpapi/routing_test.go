package httpapi_test

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// swept runs the routing sweep the way the worker does.
func (r *reach) swept(t *testing.T) int {
	t.Helper()
	work := queue.New(r.db, queue.DefaultOptions())
	placed, err := finding.NewSweeper(r.db, work,
		slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Once(t.Context())
	if err != nil {
		t.Fatalf("sweeping: %v", err)
	}
	return placed
}

func TestARuleRoutesWorkNobodyHoldsAndTakesNothingFromAnybody(t *testing.T) {
	// A rule places only work nobody holds: a human assignment always
	// wins, and turning a rule on never performs the act the assigner
	// right is named for on behalf of whoever wrote the rule.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}

		// One of the four is already somebody's, and stays theirs.
		if got := asPerson(t, r, "assigner", http.MethodPut,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-CURL1/components/libcurl4t64/assignment",
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}

		// A rule naming the source package, which catches both binary
		// packages built from it — the whole point of keying on it.
		made := asPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/routing-rules",
			`{"name":"curl to the curlers","team":"curlers","upstream":"curl"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("adding a rule answered %d: %s", made.Code, made.Body.String())
		}

		if placed := r.swept(t); placed == 0 {
			t.Fatal("the sweep placed nothing")
		}

		var holding struct {
			Items []struct {
				Person string `json:"person"`
				Team   bool   `json:"team"`
				Open   int    `json:"open"`
			} `json:"items"`
		}
		read(t, r, "assigner", "/v1/assignments", &holding)
		var queued, held int
		for _, one := range holding.Items {
			if one.Team {
				queued = one.Open
			} else {
				held = one.Open
			}
		}
		// Two issues across two packages is four findings; one was already
		// somebody's, so the rule placed the rest and took nothing.
		if held != 1 {
			t.Errorf("the person holds %d after the rule ran, want what they had", held)
		}
		if queued == 0 {
			t.Errorf("the team's queue holds nothing: %+v", holding.Items)
		}

		// And the finding says which rule placed it, which is what
		// makes a placement correctable rather than mysterious.
		var detail struct {
			AssignedTo string `json:"assigned_to"`
			RoutedBy   string `json:"routed_by"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-CURL2/components/libcurl3t64", &detail)
		if detail.RoutedBy != "curl to the curlers" {
			t.Errorf("the finding says %q placed it", detail.RoutedBy)
		}
		// The one a person took stays a person's, and names no rule.
		var byHand struct {
			RoutedBy string `json:"routed_by"`
		}
		read(t, r, "triager", "/v1/products/mine/streams/master/variants/broadcom"+
			"/findings/CVE-2026-CURL1/components/libcurl4t64", &byHand)
		if byHand.RoutedBy != "" {
			t.Errorf("something a person took names the rule %q", byHand.RoutedBy)
		}

		// A triager may see the rules but not write one: a rule hands work to
		// somebody, which is the act the assigner right names.
		if refused := asPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/routing-rules",
			`{"name":"mine","team":"curlers","upstream":"curl"}`); refused.Code < 400 {
			t.Errorf("a triager wrote a routing rule, answering %d", refused.Code)
		}
		// And a rule that matches nothing is refused rather than recorded.
		if empty := asPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/routing-rules",
			`{"name":"nothing","team":"curlers"}`); empty.Code != http.StatusUnprocessableEntity {
			t.Errorf("a rule matching nothing answered %d", empty.Code)
		}
	})
}

func TestRetiringARuleLeavesWhatItPlaced(t *testing.T) {
	// Changing a rule never takes something out of somebody's hands, and
	// that holds for a team's queue as much as for a person.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers"}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		made := asPerson(t, r, "assigner", http.MethodPost, "/v1/products/mine/routing-rules",
			`{"name":"curl","team":"curlers","upstream":"curl"}`)
		if made.Code != http.StatusCreated {
			t.Fatalf("adding answered %d: %s", made.Code, made.Body.String())
		}
		r.swept(t)

		var rules struct {
			Items []struct {
				ID    int64  `json:"id"`
				Team  string `json:"team"`
				Order int    `json:"order"`
			} `json:"items"`
		}
		read(t, r, "assigner", "/v1/products/mine/routing-rules", &rules)
		if len(rules.Items) != 1 || rules.Items[0].Order != 1 {
			t.Fatalf("the rules read %+v", rules.Items)
		}

		var before struct {
			Items []struct {
				Open int `json:"open"`
			} `json:"items"`
		}
		read(t, r, "assigner", "/v1/assignments", &before)
		if len(before.Items) != 1 {
			t.Fatalf("after the sweep %d parties hold work", len(before.Items))
		}
		placed := before.Items[0].Open

		if gone := asPerson(t, r, "assigner", http.MethodDelete,
			"/v1/products/mine/routing-rules/"+itoa(rules.Items[0].ID),
			""); gone.Code != http.StatusNoContent {
			t.Fatalf("retiring answered %d: %s", gone.Code, gone.Body.String())
		}
		var after struct {
			Items []struct {
				Open int `json:"open"`
			} `json:"items"`
		}
		read(t, r, "assigner", "/v1/assignments", &after)
		if len(after.Items) != 1 || after.Items[0].Open != placed {
			t.Errorf("retiring a rule took back what it placed: %+v", after.Items)
		}
	})
}

func TestARuleSaysWhatItWouldCatchBeforeItIsSaved(t *testing.T) {
	// A rule whose reach nobody can see before saving is a rule that sweeps
	// the estate on a guess, and one naming something nothing is called places
	// nothing — silently, which is the worst way for it to be wrong, because
	// it still looks like a rule.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)

		caught := r.preview(t, "upstream=curl")
		if caught.Total != 2 || len(caught.Components) != 2 {
			t.Fatalf("the source package catches %d components: %+v", caught.Total, caught)
		}
		// One rule, both binary packages: the whole reason the key is the
		// source package.
		if !contains(caught.Components[0]+" "+caught.Components[1], "libcurl4t64") {
			t.Errorf("it does not name what it matches: %v", caught.Components)
		}
		if caught.Work == 0 || caught.Unheld != caught.Work {
			t.Errorf("nothing is held yet, so all of it should be unheld: %+v", caught)
		}

		// A name nothing is called catches nothing, and says so.
		if none := r.preview(t, "upstream=libcurl"); none.Total != 0 || none.Work != 0 {
			t.Errorf("a name nothing is called catches %+v", none)
		}

		// A pattern catches what the exact name cannot: two binary packages
		// with no source package recorded between them would otherwise be two
		// rules.
		starred := r.preview(t, "beneath=libcurl*")
		if starred.Total != 2 {
			t.Errorf("a pattern over the tree catches %d components: %+v",
				starred.Total, starred.Components)
		}

		// What SQL treats as special does not leak through. A pattern with no
		// star is matched exactly, so an underscore is an underscore.
		if literal := r.preview(t, "beneath=libcurl_t64"); literal.Total != 0 {
			t.Errorf("an underscore matched as a wildcard: %+v", literal.Components)
		}

		// And the count of what nobody holds moves when somebody takes one.
		if got := asPerson(t, r, "assigner", http.MethodPut,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-CURL1/components/libcurl4t64/assignment",
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		after := r.preview(t, "upstream=curl")
		if after.Work != caught.Work || after.Unheld >= caught.Unheld {
			t.Errorf("taking one did not change what a rule may place: %+v then %+v",
				caught, after)
		}
	})
}

type caught struct {
	Components []string `json:"components"`
	Total      int      `json:"total"`
	Work       int      `json:"work"`
	Unheld     int      `json:"unheld"`
}

func (r *reach) preview(t *testing.T, query string) caught {
	t.Helper()
	var out caught
	read(t, r, "triager", "/v1/products/mine/routing-rules/preview?"+query, &out)
	return out
}

func TestASweepDoesNotStopBecauseSomebodyTookOneRow(t *testing.T) {
	// The batch is bounded on what it reads and the write re-checks the
	// holder, so one assignment made by a person inside the window leaves a
	// row of the batch already somebody's. Reading "wrote fewer than the cap"
	// as "reached the end" therefore stopped the sweep one human action in,
	// with the rest of the estate unrouted and the job reported successful.
	//
	// A batch of two against four matching findings, one of them held: the
	// first batch reads two and writes one, which is what the old reading
	// called the end.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedSiblings(t)
		if made := asPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"curlers","members":["triager"]}`); made.Code != http.StatusCreated {
			t.Fatal(made.Body.String())
		}
		if got := asPerson(t, r, "assigner", http.MethodPut,
			"/v1/products/mine/streams/master/variants/broadcom"+
				"/findings/CVE-2026-CURL1/components/libcurl4t64/assignment",
			`{"person":"triager"}`); got.Code != http.StatusNoContent {
			t.Fatalf("assigning answered %d: %s", got.Code, got.Body.String())
		}
		if made := asPerson(t, r, "assigner", http.MethodPost,
			"/v1/products/mine/routing-rules",
			`{"name":"curl to the curlers","team":"curlers","upstream":"curl"}`,
		); made.Code != http.StatusCreated {
			t.Fatalf("adding a rule answered %d: %s", made.Code, made.Body.String())
		}

		work := queue.New(r.db, queue.DefaultOptions())
		sweeper := finding.NewSweeperOfSize(r.db, work,
			slog.New(slog.NewTextHandler(io.Discard, nil)), "test", 2)
		for range 20 {
			placed, err := sweeper.Once(t.Context())
			if err != nil {
				t.Fatalf("sweeping: %v", err)
			}
			if placed == 0 {
				break
			}
		}

		var left int
		if err := r.db.DB.NewSelect().Table("finding").
			ColumnExpr("COUNT(*)").
			Where("assigned_to IS NULL").
			Where("closed_at IS NULL").
			Where(`component_id IN (SELECT id FROM "component" WHERE upstream_name = ?)`, "curl").
			Scan(t.Context(), &left); err != nil {
			t.Fatal(err)
		}
		if left != 0 {
			t.Errorf("%d findings the rule matches are still unrouted after the "+
				"sweep ran to the end", left)
		}
	})
}

func TestMarkingAndAssigningResolveANameTheBuildHoldsTwice(t *testing.T) {
	// The three routes built on the shared lookup carry no version to choose
	// with, and the lookup answered "no open finding is recorded there" for a
	// name the build ships at two versions. The finding is there — the caller
	// had just read it on a screen that resolved the same name — so a 404 was
	// wrong twice over. Narrowed to the versions carrying the issue first,
	// exactly as the finding's own route does it, since most versions of a
	// name carry nothing.
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedWithEvidence(t)
		r.shipsTwice(t)

		at := "/v1/products/mine/streams/master/variants/broadcom" +
			"/findings/CVE-2026-9999/components/libnl-3-200"

		// The finding is readable under the bare name.
		if got := asPerson(t, r, "triager", http.MethodGet, at, ""); got.Code != http.StatusOK {
			t.Fatalf("reading the finding answered %d: %s", got.Code, got.Body.String())
		}
		// So marking it must not answer that it is not there.
		if got := asPerson(t, r, "triager", http.MethodPut,
			at+"/tags/waiting-on-vendor", ""); got.Code == http.StatusNotFound {
			t.Errorf("marking a finding the same name resolves to answered 404: %s",
				got.Body.String())
		} else if got.Code >= 300 && got.Code != http.StatusConflict {
			t.Errorf("marking answered %d: %s", got.Code, got.Body.String())
		}
	})
}
