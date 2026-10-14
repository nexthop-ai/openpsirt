// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier_test

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// A publisher's content delivery network answering a rate limit, a timeout or
// "too early" is asking to be asked again. Stepped over, every document in
// that pass is lost for good while the supplier reads as healthy.
func TestADocumentThePublisherAsksToBeAskedForLaterHoldsTheMark(t *testing.T) {
	for _, code := range []int{http.StatusRequestTimeout, http.StatusTooEarly,
		http.StatusTooManyRequests} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			shipping(t, func(t *testing.T, f *ships) {
				ctx := t.Context()
				p := serving(t)
				p.publishes("/2026/EL-41.json", "2026-09-20T00:00:00Z",
					advisory("EL-2026-0041", "libnl-3-200", "3.7.1", "CVE-2026-5201"))
				p.publishes("/2026/EL-42.json", "2026-09-21T00:00:00Z",
					advisory("EL-2026-0042", "libnl-3-200", "3.7.1", "CVE-2026-5202"))
				p.failing["/2026/EL-41.json"] = code

				took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
				if err == nil {
					t.Fatalf("a document answering %d was stepped over: %+v", code, took)
				}
				if took.Refused != 0 || took.Documents != 0 {
					t.Errorf("read %+v, want nothing past the document asked for later", took)
				}
				if !took.CaughtUpTo.IsZero() {
					t.Errorf("the mark moved to %v", took.CaughtUpTo)
				}
			})
		})
	}
}

// A refusal saying the request is not authorized or is forbidden is answered
// the same way on every pass by a document the publisher restricted, and it is
// also what a bot filter answers. Stepped over, so nothing holds for ever, and
// recorded as what stopped the attempt, so nothing is lost silently.
func TestADocumentThePublisherForbidsIsSteppedOverAndTheSupplierFails(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			shipping(t, func(t *testing.T, f *ships) {
				ctx := t.Context()
				p := serving(t)
				p.publishes("/2026/EL-43.json", "2026-09-20T00:00:00Z", "")
				p.failing["/2026/EL-43.json"] = code
				p.publishes("/2026/EL-44.json", "2026-09-21T00:00:00Z",
					advisory("EL-2026-0044", "libnl-3-200", "3.7.1", "CVE-2026-5204"))

				store, row, pass := passOver(t, f, p, "test")
				took, err := pass.Once(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if took.Refused != 1 || took.Documents != 1 {
					t.Errorf("read %+v, want the forbidden document stepped over and the "+
						"next one read", took)
				}
				rows, err := store.For(ctx, f.by, f.product)
				if err != nil {
					t.Fatal(err)
				}
				if len(rows) != 1 || rows[0].ID != row.ID {
					t.Fatalf("the supplier reads as %+v", rows)
				}
				if !strings.Contains(rows[0].Failed, "/2026/EL-43.json") {
					t.Errorf("the supplier records %q as what stopped it, want the "+
						"forbidden document named", rows[0].Failed)
				}
				if rows[0].ReachedAt != nil {
					t.Errorf("a pass the publisher refused documents in reads as one "+
						"that worked, at %v", rows[0].ReachedAt)
				}
				want := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
				if rows[0].CaughtUpTo == nil || !rows[0].CaughtUpTo.Equal(want) {
					t.Errorf("the mark stopped at %v, want past both documents",
						rows[0].CaughtUpTo)
				}
			})
		})
	}
}

// A withdrawn advisory still listed answers 404 on every pass. It is stepped
// over and says nothing about the publisher, which stays healthy.
func TestAWithdrawnDocumentIsSteppedOverAndTheSupplierStaysHealthy(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-45.json", "2026-09-20T00:00:00Z", "")
		p.failing["/2026/EL-45.json"] = http.StatusNotFound
		p.publishes("/2026/EL-46.json", "2026-09-21T00:00:00Z",
			advisory("EL-2026-0046", "libnl-3-200", "3.7.1", "CVE-2026-5206"))

		store, _, pass := passOver(t, f, p, "test")
		took, err := pass.Once(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if took.Refused != 1 || took.Documents != 1 {
			t.Errorf("read %+v, want the withdrawn document stepped over", took)
		}
		rows, err := store.For(ctx, f.by, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Failed != "" || rows[0].ReachedAt == nil {
			t.Errorf("a withdrawn document marked the supplier as failing: %+v", rows)
		}
	})
}

// The mark is shared by every listing a publisher names. A listing that could
// not be reached holds it: moved on the strength of the others, it passes
// everything the unreached one listed before it, and those are never read.
func TestAListingThatCouldNotBeReachedHoldsTheMark(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-47.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0047", "libnl-3-200", "3.7.1", "CVE-2026-5207"))
		p.feeds = []string{"/second.json"}
		p.failing["/second.json"] = http.StatusBadGateway

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err == nil {
			t.Fatalf("a listing answering 502 was stepped over: %+v", took)
		}
		if took.Documents != 0 || !took.CaughtUpTo.IsZero() {
			t.Errorf("read %+v, want the mark held where it was", took)
		}
	})
}

// A listing refused the same way on every pass is stepped over, and the
// listing beside it is still read.
func TestAListingRefusedEveryPassDoesNotStopTheOthers(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-48.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0048", "libnl-3-200", "3.7.1", "CVE-2026-5208"))
		p.feeds = []string{"/gone.json"}

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatalf("a listing answering 404 stopped the supplier: %v", err)
		}
		if took.Documents != 1 {
			t.Errorf("read %+v, want the document the other listing names", took)
		}
		if took.Barred != 0 {
			t.Errorf("a listing that is gone was counted as forbidden: %+v", took)
		}
	})
}

// A listing the publisher forbids is stepped over like one that is gone, and
// counted so the supplier is recorded as failing.
func TestAListingThePublisherForbidsIsCounted(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-49.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0049", "libnl-3-200", "3.7.1", "CVE-2026-5209"))
		p.feeds = []string{"/restricted.json"}
		p.failing["/restricted.json"] = http.StatusForbidden

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatalf("a forbidden listing stopped the supplier: %v", err)
		}
		if took.Documents != 1 || took.Barred != 1 ||
			!strings.Contains(took.BarredBy, "/restricted.json") {
			t.Errorf("read %+v, want the other listing read and the forbidden one counted", took)
		}
	})
}
