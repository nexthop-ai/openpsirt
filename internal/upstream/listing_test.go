// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/upstream"
)

// entriesListed is where a feed lists its entries.
var entriesListed = regexp.MustCompile(`("entry"\s*:\s*\[)`)

// feedListing has the upstream's feed list one more entry, at the top.
func (s *served) feedListing(entry string) {
	s.change(publish.FeedPath, func(body []byte) []byte {
		return entriesListed.ReplaceAll(body, []byte(`${1}`+entry+`,`))
	})
}

// failed is what the fork records as having stopped its last read.
func (w *world) failed() string {
	w.t.Helper()
	up, err := upstream.NewStore(w.DB.DB).For(w.t.Context(), w.admin, w.fork.ID)
	if err != nil {
		w.t.Fatal(err)
	}
	return up.Failed
}

// An entry naming a document on another host is refused alone: the read goes
// on to every other document, and records what it could not read.
func TestAnEntryOnAnotherHostIsRefusedAlone(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		listed := len(w.server.documents(t))
		w.server.feedListing(`{"id":"cdn","updated":"2026-01-01T00:00:00Z",` +
			`"content":{"src":"https://0cdn.example.test/elsewhere.json"}}`)
		if took := w.read(); took.Documents != listed {
			t.Errorf("a read with an entry on another host took %+v, want all %d documents", took, listed)
		}
		if failed := w.failed(); !strings.Contains(failed, "name no document this can read") {
			t.Errorf("the read records %q, want the entry it could not read", failed)
		}
	})
}

// A document answered with a redirect is refused alone, as one on another
// host is, and the read goes on past it.
func TestADocumentAnsweredWithARedirectIsRefusedAlone(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		documents := w.server.documents(t)
		w.server.redirect(documents[0])
		took := w.read()
		if took.Refused != 1 || took.Documents != len(documents)-1 {
			t.Errorf("a read with one document redirected took %+v, want it refused and the rest taken", took)
		}
	})
}

// A listing holding an entry that cannot be read keeps it with its validator,
// so a next read hearing that nothing moved records again what stopped it,
// rather than clearing the failure.
func TestAnEntryThatCannotBeReadStaysRecordedWhileNothingMoves(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		w.server.feedListing(`{"id":"junk","content":{"src":"junk.json"}}`)
		w.read()
		if w.failed() == "" {
			t.Fatal("a read with an entry it could not read records nothing")
		}
		w.read()
		if failed := w.failed(); !strings.Contains(failed, "name no document this can read") {
			t.Errorf("the next read records %q, want the entry it still cannot read", failed)
		}
	})
}

// A description naming more listings than are read is refused before any is
// fetched, and listings naming more entries than are held are refused whole.
func TestListingsPastTheirBoundsAreRefused(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		upstream.ListingAtMost(w.reader, 1)
		if took := w.read(); took.Documents != 0 {
			t.Errorf("listings past their bound were read: %+v", took)
		}
		if failed := w.failed(); !strings.Contains(failed, "more than the 1 documents") {
			t.Errorf("the read records %q, want the entries refused", failed)
		}

		feeds := regexp.MustCompile(`("feeds"\s*:\s*\[)`)
		var many []string
		for i := range 40 {
			many = append(many, `{"tlp_label":"WHITE","url":"`+w.server.base+publish.DirectoryPath+
				"feed-"+strings.Repeat("x", i+1)+`.json"}`)
		}
		w.server.change(publish.MetadataPath, func(body []byte) []byte {
			return feeds.ReplaceAll(body, []byte(`${1}`+strings.Join(many, ",")+`,`))
		})
		w.server.mu.Lock()
		w.server.asked = nil
		w.server.mu.Unlock()
		w.read()
		if failed := w.failed(); !strings.Contains(failed, "listings, and this reads at most") {
			t.Errorf("the read records %q, want the listings refused", failed)
		}
		w.server.mu.Lock()
		defer w.server.mu.Unlock()
		for _, path := range w.server.asked {
			if strings.Contains(path, "feed") {
				t.Errorf("a description naming too many listings had %s fetched", path)
			}
		}
	})
}

// A document refused every time is tried after the rest, so documents
// refused at the head of the list never take a whole pass and starve the ones
// listed after them.
func TestADocumentRefusedEveryTimeStarvesNoOther(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		upstream.TakingAtMost(w.reader, 1)
		w.trust()
		w.server.drop(w.server.documents(t)[0])
		if took := w.read(); took.Refused != 1 || took.Documents != 0 {
			t.Fatalf("the first read took %+v, want the first document refused", took)
		}
		if took := w.read(); took.Documents != 1 {
			t.Errorf("the next read took %+v, want a document listed after the refused one", took)
		}
	})
}

// A document listed at two addresses keeps what it says while one of them
// still serves it, when the other comes to hold another document.
func TestADocumentStillServedElsewhereKeepsItsStatements(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		const copied = publish.DirectoryPath + "copy.json"
		w.server.serveAs(copied, w.server.pathOf(t, portable))
		w.server.feedListing(`{"id":"copy","updated":"2026-01-01T00:00:00Z",` +
			`"content":{"src":"` + w.server.base + copied + `"}}`)
		w.read()
		if w.statement(portable, finding.PlacedAnybody) == nil {
			t.Fatal("the upstream's statement was not taken")
		}

		w.server.serveAs(copied, w.server.pathOf(t, ownBuild))
		w.server.feedListing(`{"id":"copy","updated":"2026-02-01T00:00:00Z",` +
			`"content":{"src":"` + w.server.base + copied + `"}}`)
		if _, err := w.DB.DB.NewUpdate().Model((*upstream.Upstream)(nil)).
			Set(`"listings" = NULL`).Where(`"product_id" = ?`, w.fork.ID).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		w.read()
		if w.statement(portable, finding.PlacedAnybody) == nil {
			t.Error("a statement was set aside while another address still serves its document")
		}
	})
}

// A pass that lost the lease reads no listing and records nothing, leaving the
// upstream to the replica that holds it.
func TestAReadThatLostTheLeaseReadsNoListing(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		upstream.Keeping(w.reader, func(context.Context) (bool, error) { return false, nil })
		w.server.mu.Lock()
		w.server.asked = nil
		w.server.mu.Unlock()
		if took := w.read(); took.Documents != 0 || !took.Filled {
			t.Errorf("a read that lost the lease took %+v", took)
		}
		w.server.mu.Lock()
		defer w.server.mu.Unlock()
		for _, path := range w.server.asked {
			if path == publish.FeedPath {
				t.Error("a read that lost the lease fetched the feed")
			}
		}
		up, err := upstream.NewStore(w.DB.DB).For(t.Context(), w.admin, w.fork.ID)
		if err != nil {
			t.Fatal(err)
		}
		if up.FetchedAt != nil {
			t.Error("a read that lost the lease recorded an attempt")
		}
	})
}

// A pass that cannot ask for the lease failed here, so it records nothing
// against the upstream and leaves it due.
func TestAReadThatCannotAskForTheLeaseRecordsNothing(t *testing.T) {
	fixture.Each(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.trust()
		upstream.Keeping(w.reader, func(context.Context) (bool, error) {
			return false, errors.New("the database went away")
		})
		up, err := upstream.NewStore(w.DB.DB).For(t.Context(), w.admin, w.fork.ID)
		if err != nil || up == nil {
			t.Fatalf("the fork trusts no upstream: %v", err)
		}
		if _, err := w.reader.From(t.Context(), *up); err == nil {
			t.Fatal("a read that could not ask for the lease reported nothing")
		}
		up, err = upstream.NewStore(w.DB.DB).For(t.Context(), w.admin, w.fork.ID)
		if err != nil {
			t.Fatal(err)
		}
		if up.FetchedAt != nil || up.Failed != "" {
			t.Errorf("a read that could not ask for the lease recorded an attempt: failed %q", up.Failed)
		}
	})
}
