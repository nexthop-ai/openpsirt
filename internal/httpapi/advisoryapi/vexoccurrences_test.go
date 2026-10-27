// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisoryapi_test

import (
	"encoding/json"
	"net/http"
	"sort"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

// A VEX document names the build the way its inventory names the root, and
// states a dismissal at some occurrences of a component one occurrence at a time, naming
// what pulls the component in as the product. A reader applies such a
// statement beneath the product it names, so it is made only where everything
// beneath that product was decided the same way.

const placedAt = "/v1/products/mine/branches-and-tags/master/variants/broadcom/vex"

// dismissedUnder agrees a dismissal at the occurrences where the consumers named pull the
// library in, the build itself named by the empty string.
func dismissedUnder(t *testing.T, r *httpapitest.Reach, consumers ...string) {
	t.Helper()
	var occurrences struct {
		Occurrences []struct {
			Occurrence string `json:"occurrence"`
			Consumer   string `json:"consumer"`
		} `json:"occurrences"`
	}
	httpapitest.Read(t, r, "triager", httpapitest.FindingAt("CVE-2026-9999"), &occurrences)
	wanted := map[string]bool{}
	for _, consumer := range consumers {
		wanted[consumer] = true
	}
	found := 0
	for _, occurrence := range occurrences.Occurrences {
		if !wanted[occurrence.Consumer] {
			continue
		}
		found++
		made := httpapitest.AsPerson(t, r, "triager", http.MethodPost,
			"/v1/products/mine/branches-and-tags/master/variants/broadcom"+
				"/findings/CVE-2026-9999/occurrences/"+occurrence.Occurrence+"/decision", httpapitest.Dismissal)
		if made.Code != http.StatusCreated {
			t.Fatalf("deciding the occurrence under %q answered %d: %s", occurrence.Consumer, made.Code,
				made.Body.String())
		}
		var decision struct {
			DecisionID int64 `json:"decision_id"`
		}
		if err := json.Unmarshal(made.Body.Bytes(), &decision); err != nil {
			t.Fatal(err)
		}
		r.Agreed(t, decision.DecisionID)
	}
	if found != len(consumers) {
		t.Fatalf("decided %d occurrences, want %d", found, len(consumers))
	}
}

// statedAbout is each product a statement about the issue names, with the
// component beneath it.
func statedAbout(t *testing.T, r *httpapitest.Reach) []string {
	t.Helper()
	var doc struct {
		Statements []struct {
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
			Products []struct {
				ID            string `json:"@id"`
				Subcomponents []struct {
					ID string `json:"@id"`
				} `json:"subcomponents"`
			} `json:"products"`
		} `json:"statements"`
	}
	httpapitest.Read(t, r, "triager", placedAt, &doc)
	var out []string
	for _, one := range doc.Statements {
		if one.Vulnerability.Name != "CVE-2026-9999" {
			continue
		}
		for _, product := range one.Products {
			for _, inside := range product.Subcomponents {
				out = append(out, product.ID+" > "+inside.ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

const library = "pkg:deb/debian/libnl-3-200@3.7.0"

func TestAnOccurrenceIsStatedOnlyWhereEverythingBeneathItsProductAgrees(t *testing.T) {
	// The library under curl is dismissed and the one under libssh, which only
	// curl pulls in, is not. A reader applying "the library inside curl"
	// beneath curl would answer the occurrence under libssh too.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedBeneathAProduct(t, "")
		dismissedUnder(t, r, "curl")
		if got := statedAbout(t, r); len(got) != 0 {
			t.Errorf("stated %v, want nothing while the occurrence under libssh is undecided", got)
		}
	})
}

func TestEachOccurrenceBeneathAnAgreedProductIsStatedAboutItsConsumer(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedBeneathAProduct(t, "")
		dismissedUnder(t, r, "curl", "libssh")
		want := []string{
			"pkg:deb/debian/curl@8.5.0 > " + library,
			"pkg:deb/debian/libssh@0.10.6 > " + library,
		}
		if got := statedAbout(t, r); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Errorf("stated %v, want %v", got, want)
		}
	})
}

func TestAnOccurrenceTheBuildPullsInDirectlyIsNeverStatedAlone(t *testing.T) {
	// A statement naming the build as the product is about the whole build.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedBeneathAProduct(t, "pkg:generic/mine@1.0")
		dismissedUnder(t, r, "")
		if got := statedAbout(t, r); len(got) != 0 {
			t.Errorf("stated %v, want nothing for an occurrence the build holds directly", got)
		}
	})
}

func TestAComponentAgreedEverywhereIsStatedAboutTheBuildsRoot(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedBeneathAProduct(t, "pkg:generic/mine@1.0")
		dismissedUnder(t, r, "", "curl", "libssh", "app")
		want := "pkg:generic/mine@1.0 > " + library
		if got := statedAbout(t, r); len(got) != 1 || got[0] != want {
			t.Errorf("stated %v, want the one statement about the build", got)
		}
	})
}

func TestARootNamingNoVersionIsNotWhatTheDocumentNames(t *testing.T) {
	// An identifier naming no version names every release, and a reader would
	// apply this release's dismissals to the next.
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedBeneathAProduct(t, "pkg:generic/mine")
		dismissedUnder(t, r, "", "curl", "libssh", "app")
		want := "mine:master:broadcom > " + library
		if got := statedAbout(t, r); len(got) != 1 || got[0] != want {
			t.Errorf("stated %v, want the one statement naming the build by its names", got)
		}
	})
}
