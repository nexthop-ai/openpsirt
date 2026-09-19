package httpapi_test

import (
	"slices"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The report answers, says why of each, and carries what it matched against.
//
// The three answers, because they are recorded identically. A held-back
// name and one no index knows are both "asked, no version" in the database on
// purpose — the pass must record both or starve its own window on them — so a
// test with only one arm would pass against a reader that returned that word
// for everything.
func TestWhatUpstreamCouldNotAnswerIsReachableAndSaysWhy(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		// The deployment publishes as "https://example.test", so "example" is
		// one of the names it calls its own.
		ours := graph.Described{
			Purl: "pkg:npm/%40example/agent@1.0.0", Name: "@example/agent", Version: "1.0.0",
		}
		// Published under whoever publishes the thing the build declared
		// itself to be, which is the second source the default is derived
		// from and the one that cannot be read off the configuration.
		alsoOurs := graph.Described{
			Purl: "pkg:golang/github.com/other-corp/lib@v1.0.0",
			Name: "lib", Version: "1.0.0",
		}
		theirs := graph.Described{
			Purl: "pkg:npm/private-fork@0.1.0", Name: "private-fork", Version: "0.1.0",
		}
		// Answered, so it is not unanswered and must not be on the list.
		answered := graph.Described{
			Purl: "pkg:cargo/serde@1.0.0", Name: "serde", Version: "1.0.0",
		}
		root := graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"}
		r.scan(t, "upstream-test", graph.Snapshot{
			Root:       root,
			Components: []graph.Described{ours, alsoOurs, theirs, answered},
			Dependencies: []graph.Dependency{
				{Parent: root, Child: ours},
				{Parent: root, Child: alsoOurs},
				{Parent: root, Child: theirs},
				{Parent: root, Child: answered},
			},
		}, nil)

		// The document's own name for itself. It lives on the scan rather than
		// on a component, because the component standing for the product is
		// stored by its name alone so that a version on it does not give the
		// product a new identity every night.
		if _, err := r.db.DB.NewUpdate().Table("scan").
			Set("root_identifier = ?", "pkg:golang/github.com/other-corp/product@v2.0.0").
			Where("content_hash = ?", "upstream-test").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		// The rows a pass leaves behind. Written here rather than by
		// running one, because what the pass does is its own package's test
		// and what this one asks is whether the answer can be read back.
		asked := time.Now().UTC().Add(-time.Hour)
		if _, err := r.db.DB.NewUpdate().Table("component").
			Set("latest_checked_at = ?", asked).
			Where("purl <> ?", "").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.DB.NewUpdate().Table("component").
			Set("latest_version = ?", "1.0.230").
			Where("purl = ?", answered.Purl).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		var body struct {
			Items []struct {
				Purl      string `json:"purl"`
				Ecosystem string `json:"ecosystem"`
				Why       string `json:"why"`
				Checked   string `json:"checked"`
			} `json:"items"`
			Total int      `json:"total"`
			Ours  []string `json:"ours"`
			Whole bool     `json:"whole"`
		}
		read(t, r, "triager", "/v1/upstream/unanswered", &body)

		if !body.Whole {
			t.Error("a handful of rows was reported as past the ceiling")
		}
		// The names, drawn beside the list. A derived default nobody can see
		// is one an operator turns the whole feature off to escape.
		for _, name := range []string{"example", "example.test", "test.example", "other-corp"} {
			if !slices.Contains(body.Ours, name) {
				t.Errorf("%q is not among the names held back: %v", name, body.Ours)
			}
		}
		why := map[string]string{}
		for _, row := range body.Items {
			why[row.Purl] = row.Why
			if row.Checked == "" {
				t.Errorf("%s says nothing about when it was reached", row.Purl)
			}
		}
		for purl, want := range map[string]string{
			ours.Purl:     "ours",
			alsoOurs.Purl: "ours",
			theirs.Purl:   "unknown",
		} {
			if why[purl] != want {
				t.Errorf("%s reads as %q, expected %q", purl, why[purl], want)
			}
		}
		if _, on := why[answered.Purl]; on {
			t.Errorf("%s has an answer and is on the list anyway", answered.Purl)
		}
		if body.Total != 3 {
			t.Errorf("reported %d in all, expected 3: %v", body.Total, why)
		}
	})
}

// A reader holding nothing on the product reads none of it.
//
// A package identifier says what a build is made of, so this is an answer
// about a product rather than about the deployment (REQ-42). The narrowing is
// the store's, and this is what says the route hands it the asker rather than
// reading unnarrowed and filtering afterwards.
func TestWhatUpstreamCouldNotAnswerIsNarrowedToWhatMayBeRead(t *testing.T) {
	twoReach(t, func(t *testing.T, r *reach) {
		theirs := graph.Described{
			Purl: "pkg:npm/private-fork@0.1.0", Name: "private-fork", Version: "0.1.0",
		}
		r.scan(t, "upstream-narrowing", graph.Snapshot{
			Root:       graph.Described{Purl: "pkg:deb/debian/mine@1.0", Name: "mine", Version: "1.0"},
			Components: []graph.Described{theirs},
		}, nil)
		if _, err := r.db.DB.NewUpdate().Table("component").
			Set("latest_checked_at = ?", time.Now().UTC().Add(-time.Hour)).
			Where("purl <> ?", "").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		// The build's own declaration, which is a product's own name.
		if _, err := r.db.DB.NewUpdate().Table("scan").
			Set("root_identifier = ?", "pkg:golang/github.com/unannounced-corp/product@v1").
			Where("content_hash = ?", "upstream-narrowing").Exec(t.Context()); err != nil {
			t.Fatal(err)
		}

		var body struct {
			Items []struct {
				Purl string `json:"purl"`
			} `json:"items"`
			Total int      `json:"total"`
			Ours  []string `json:"ours"`
		}
		read(t, r, "outsider", "/v1/upstream/unanswered", &body)
		if body.Total != 0 || len(body.Items) != 0 {
			t.Fatalf("somebody holding nothing here read %d of %d", len(body.Items), body.Total)
		}
		// The names travel back narrowed as well as the rows. A label derived
		// from a root is the name a product is published under, so the whole
		// list tells a reader the scope of a product nobody announced to them
		// — the exact name this change exists to keep out of an index's logs.
		if slices.Contains(body.Ours, "unannounced-corp") {
			t.Errorf("somebody holding nothing here was told about %q: %v",
				"unannounced-corp", body.Ours)
		}
		// The deployment's own configuration is not product data and stays, so
		// an empty list would pass this test for the wrong reason.
		if !slices.Contains(body.Ours, "example") {
			t.Errorf("the deployment's own namespace is missing from %v", body.Ours)
		}
	})
}
