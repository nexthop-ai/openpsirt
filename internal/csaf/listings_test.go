// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package csaf_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/csaf"
)

// The list of changes is newest first, which is what lets a reader who
// fetched yesterday stop reading.
func TestTheListOfChangesIsNewestFirst(t *testing.T) {
	rows := strings.Split(strings.TrimSpace(string(csaf.Changes([]csaf.Listed{
		{Path: "2026/b.json", Released: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Path: "2026/c.json", Released: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)},
		{Path: "2026/a.json", Released: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
	}))), "\n")
	want := []string{"2026/c.json", "2026/a.json", "2026/b.json"}
	if len(rows) != len(want) {
		t.Fatalf("%d rows, want %d: %v", len(rows), len(want), rows)
	}
	for at := range want {
		if !strings.HasPrefix(rows[at], `"`+want[at]+`",`) {
			t.Errorf("row %d is %q, want %s first", at, rows[at], want[at])
		}
	}
}

// A feed names every file beside a document in that document's entry, and is
// dated from the newest document rather than from the clock.
func TestAFeedNamesWhatSitsBesideEachDocument(t *testing.T) {
	at := func(path string) string { return "https://example.com/" + path }
	newest := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	feed := csaf.FeedOf("example-feed", "Example", at("feed.json"), at,
		[]csaf.Beside{{Rel: "hash", Suffix: ".sha256"}, {Rel: "signature", Suffix: ".asc"}},
		[]csaf.Listed{
			{Path: "2026/a.json", ID: "A", Released: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
			{Path: "2026/b.json", ID: "B", Released: newest},
		})
	if feed.Feed.Updated != csaf.Stamp(newest) {
		t.Errorf("the feed is dated %s, want the newest document's %s", feed.Feed.Updated,
			csaf.Stamp(newest))
	}
	if len(feed.Feed.Entries) != 2 || feed.Feed.Entries[0].ID != "B" {
		t.Fatalf("entries %+v, want B first", feed.Feed.Entries)
	}
	links := feed.Feed.Entries[0].Links
	want := []csaf.Link{{Rel: "self", Href: at("2026/b.json")},
		{Rel: "hash", Href: at("2026/b.json.sha256")}, {Rel: "signature", Href: at("2026/b.json.asc")}}
	if len(links) != len(want) {
		t.Fatalf("links %+v, want %+v", links, want)
	}
	for i := range want {
		if links[i] != want[i] {
			t.Errorf("link %d is %+v, want %+v", i, links[i], want[i])
		}
	}
}

// Two documents released in the same moment are listed by path, so an
// unchanged list is the same bytes on every request.
func TestChangesReleasedTogetherAreOrderedByPath(t *testing.T) {
	same := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	got := string(csaf.Changes([]csaf.Listed{
		{Path: "2026/b.json", Released: same},
		{Path: "2026/a.json", Released: same},
	}))
	want := `"2026/a.json","2026-03-01T00:00:00Z"` + "\n" +
		`"2026/b.json","2026-03-01T00:00:00Z"` + "\n"
	if got != want {
		t.Errorf("changes are\n%s\nwant\n%s", got, want)
	}
}

// Two documents released in the same moment are entered by identifier, so an
// unchanged feed is the same bytes on every request.
func TestFeedEntriesReleasedTogetherAreOrderedByIdentifier(t *testing.T) {
	at := func(path string) string { return "https://example.com/" + path }
	same := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	feed := csaf.FeedOf("example-feed", "Example", at("feed.json"), at, nil,
		[]csaf.Listed{
			{Path: "2026/b.json", ID: "B", Released: same},
			{Path: "2026/a.json", ID: "A", Released: same},
		})
	var ids []string
	for _, entry := range feed.Feed.Entries {
		ids = append(ids, entry.ID)
	}
	if strings.Join(ids, ",") != "A,B" {
		t.Errorf("entries are %v, want A then B", ids)
	}
}

// A feed is named with the deployment's prefix in lower case, and with the
// bare name where there is no prefix.
func TestAFeedIsNamedForTheDeploymentsPrefix(t *testing.T) {
	for prefix, want := range map[string]string{
		"":      "csaf-feed-tlp-white",
		"EXNET": "exnet-csaf-feed-tlp-white",
	} {
		if got := csaf.FeedName(prefix); got != want {
			t.Errorf("a prefix of %q names the feed %q, want %q", prefix, got, want)
		}
	}
}
