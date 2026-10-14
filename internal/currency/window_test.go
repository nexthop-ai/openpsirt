// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package currency_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

func TestAWindowReadAgainAfterAFailingIndexKeepsToWhatIsLeftOfThePass(t *testing.T) {
	// The failing index's component is the head of the window, and two
	// hundred others are due behind it. Read again without the failing
	// index, the window is cut to what the pass has left, so the pass asks
	// no more than its bound in all.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		old := time.Now().Add(-48 * time.Hour).UTC()
		of := []component{{purl: "pkg:nuget/Thing@1.0.0"}}
		for i := range currency.MostPerPass {
			of = append(of, component{purl: fmt.Sprintf("pkg:cargo/thing-%03d@1.0.0", i),
				checked: &old, version: ptr("1.0.0")})
		}
		r, _ := seed(t, db, of, nil, nil)
		asked := &[]string{}
		r.Index = func(ecosystem string) currency.Asker {
			switch ecosystem {
			case "nuget":
				return failingFor{down: true, asked: asked}
			case "cargo":
				return failingFor{asked: asked}
			}
			return nil
		}
		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		if len(*asked) != currency.MostPerPass {
			t.Errorf("asked %d names in one pass, want the %d a pass is bounded at",
				len(*asked), currency.MostPerPass)
		}
		if (*asked)[0] != "Thing" {
			t.Errorf("the failing index was not the head of the window: %v", (*asked)[:1])
		}
	})
}

func TestAPassStillHoldingTheLeaseAsksAboutEveryComponent(t *testing.T) {
	// The lease is asked for again part way through. Still held, the pass
	// carries on past the renewal rather than stopping at it.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		var of []component
		says := map[string]currency.Latest{}
		for i := range currency.RenewEvery*2 + 1 {
			name := fmt.Sprintf("thing-%03d", i)
			of = append(of, component{purl: "pkg:cargo/" + name + "@1.0.0"})
			says[name] = currency.Latest{Version: "2.0.0"}
		}
		r, asked := seed(t, db, of, says, nil)
		currency.Asking(r, time.Hour)
		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		if len(*asked) != len(of) {
			t.Errorf("asked about %d of %d components while holding the lease", len(*asked), len(of))
		}
	})
}

func TestEveryIndexFailingLeavesNothingToReadAgain(t *testing.T) {
	// With every askable ecosystem left out, the window read again is
	// empty: a condition naming no ecosystem is one that matches nothing,
	// never one that matches everything.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		var of []component
		for _, ecosystem := range currency.Askable() {
			for _, which := range []string{"a", "b"} {
				name := "thing-" + ecosystem + "-" + which
				switch ecosystem {
				case "maven":
					name = "org.example/" + name
				case "golang":
					name = "example.com/" + name
				}
				of = append(of, component{purl: "pkg:" + ecosystem + "/" + name + "@1.0.0"})
			}
		}
		r, _ := seed(t, db, of, nil, nil)
		asked := &[]string{}
		r.Index = func(string) currency.Asker { return failingFor{down: true, asked: asked} }
		if _, err := r.Once(t.Context()); err != nil {
			t.Fatalf("once: %v", err)
		}
		times := map[string]int{}
		for _, name := range *asked {
			for _, ecosystem := range currency.Askable() {
				if strings.Contains(name, "thing-"+ecosystem+"-") {
					times[ecosystem]++
				}
			}
		}
		if len(times) == 0 {
			t.Fatal("no index was asked, so this checked nothing")
		}
		for ecosystem, n := range times {
			if n != 1 {
				t.Errorf("the failing %s index was asked %d times in one pass, want once", ecosystem, n)
			}
		}
	})
}
