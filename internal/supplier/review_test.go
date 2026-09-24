// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package supplier_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
)

// The behaviours a review found missing, each pinned by the case that showed it.

func TestDocumentsSharingAStampAreAllReadEventually(t *testing.T) {
	// A publisher stamps a batch with one moment, and a date-only stamp gives
	// a whole day the same one. On the moment alone, a pass that stopped
	// inside such a group left the mark on that moment and skipped the rest of
	// the group for ever — and no bound test could see it, because every entry
	// in those had a day to itself.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		const stamp = "2026-05-01T00:00:00Z"
		for i := range supplier.MostPerPass + 6 {
			p.publishes(fmt.Sprintf("/batch/%02d.json", i), stamp,
				advisory(fmt.Sprintf("EL-2026-3%03d", i), "libnl-3-200", "3.7.1",
					fmt.Sprintf("CVE-2026-31%02d", i)))
		}

		source := from(t, f, p)
		fetch := fetching(t, f, p)
		took, err := fetch.From(ctx, f.by, source)
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != supplier.MostPerPass {
			t.Fatalf("the first pass read %d, want the bound", took.Documents)
		}

		// The next pass starts from the pair the first one left, which is
		// inside the group. Everything after it in that group is still due.
		source.CaughtUpTo, source.CaughtUpMark = &took.CaughtUpTo, took.Mark
		again, err := fetch.From(ctx, f.by, source)
		if err != nil {
			t.Fatal(err)
		}
		if again.Documents != 6 {
			t.Errorf("the second pass read %d of the 6 left in the group", again.Documents)
		}
	})
}

func TestUploadingAnAdvisoryTheFetchNarrowedStillRecordsIt(t *testing.T) {
	// The store treats a document whose digest it already holds as one that
	// changes nothing. Keyed on the bytes alone, a fetch that narrowed a
	// document to nothing left the upload path — which DESIGN-ingest names as
	// the remedy — writing nothing and reporting success.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		// Two packages, one of which this product ships. The fetch keeps that
		// one and drops the other, so what is recorded is a subset of the
		// document — which is the case the digest has to tell apart.
		body := twoPackages("EL-2026-0020", "libnl-3-200", "not-shipped-here",
			"CVE-2026-4000")
		p.publishes("/2026/EL-20.json", "2026-09-20T00:00:00Z", body)

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Recorded != 1 {
			t.Fatalf("the fetch recorded %+v, want the one package this ships", took)
		}

		// The same bytes, uploaded whole the way an operator would once a
		// build ships the other package too. It has to write: the narrowing is
		// what kept the second claim out, and an upload does not narrow.
		read, err := sbom.ReadAdvisory(strings.NewReader(body), sbom.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		recorded, _, err := finding.NewStore(f.db.DB).RecordStatements(ctx, f.by, f.product,
			finding.Supplied{
				Source: finding.FromAdvisory, Identifier: read.Identifier,
				Publisher: read.Publisher, Document: "uploaded.json",
				Digest: digestOf(body),
			}, everything(read))
		if err != nil {
			t.Fatal(err)
		}
		if recorded != 2 {
			t.Errorf("uploading the advisory the fetch had narrowed wrote %d claims, "+
				"want both of them", recorded)
		}
	})
}

func TestADocumentThatCannotBeReadDoesNotStopTheSupplier(t *testing.T) {
	// A withdrawn advisory still listed, one over the size read, or malformed
	// CSAF is refused the same way every time. Held as though the publisher
	// were unreachable, one of them stopped everything issued after it for
	// ever, and the only way out was to withdraw the supplier and add it
	// again — which starts from today and loses the gap.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-21.json", "2026-09-20T00:00:00Z", "{ this is not json")
		p.publishes("/2026/EL-22.json", "2026-09-21T00:00:00Z",
			advisory("EL-2026-0022", "libnl-3-200", "3.7.1", "CVE-2026-4100"))

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatalf("one unreadable document failed the whole supplier: %v", err)
		}
		if took.Refused != 1 {
			t.Errorf("%d documents were refused, want the one that is not readable",
				took.Refused)
		}
		if took.Documents != 1 || took.Recorded != 1 {
			t.Errorf("the document after it was not read: %+v", took)
		}
		// And the mark is past both, so neither is fetched again.
		if !took.CaughtUpTo.Equal(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("the mark stopped at %v", took.CaughtUpTo)
		}
	})
}

func TestAPublisherThatCannotBeReachedHoldsTheMark(t *testing.T) {
	// The other half of the rule above: a refusal about the publisher rather
	// than about one document leaves everything behind the mark unseen, so the
	// mark stays where it was.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-23.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0023", "libnl-3-200", "3.7.1", "CVE-2026-4200"))
		p.publishes("/2026/EL-24.json", "2026-09-21T00:00:00Z", "")
		p.failing["/2026/EL-24.json"] = http.StatusBadGateway

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err == nil {
			t.Fatal("a publisher answering 502 read as a document that cannot be read")
		}
		if took.Refused != 0 {
			t.Errorf("it was counted as a refusal about the document: %+v", took)
		}
		// The mark stands at the one that was read, not past the one that
		// was not.
		if !took.CaughtUpTo.Equal(time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("the mark reached %v", took.CaughtUpTo)
		}
	})
}

func TestARevisionThatNarrowsToNothingSetsAsideWhatCameBefore(t *testing.T) {
	// A publisher correcting an advisory by dropping the component we ship
	// leaves the old claim standing as evidence and a prefill, unless the
	// revision is recorded — and the write is the only thing that sets the
	// earlier one aside.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-25.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0025", "libnl-3-200", "3.7.1", "CVE-2026-4300"))

		fetch := fetching(t, f, p)
		source := from(t, f, p)
		took, err := fetch.From(ctx, f.by, source)
		if err != nil || took.Recorded != 1 {
			t.Fatalf("the first revision recorded %+v (%v)", took, err)
		}

		// The same advisory, revised to name something else, listed again.
		p.publishes("/2026/EL-25.json", "2026-09-22T00:00:00Z",
			advisory("EL-2026-0025", "something-else", "9.9", "CVE-2026-4300"))
		source.CaughtUpTo, source.CaughtUpMark = &took.CaughtUpTo, took.Mark
		if _, err := fetch.From(ctx, f.by, source); err != nil {
			t.Fatal(err)
		}

		said, err := finding.NewStore(f.db.DB).SaidAbout(ctx,
			access.Everything("the test"), f.product, 0,
			[]string{"CVE-2026-4300"}, "libnl-3-200", "pkg:deb/debian/libnl-3-200@3.7.0")
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 0 {
			t.Errorf("the revision left the earlier claim standing: %+v", said)
		}
	})
}

func TestAStampFarInTheFutureIsNotRead(t *testing.T) {
	// The mark moves forward only, so one entry stamped in 2099 would carry it
	// past everything the publisher issues between now and then — and because
	// the fetch itself succeeds, the supplier reads as healthy while it takes
	// nothing.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2099/EL-99.json", "2099-01-01T00:00:00Z",
			advisory("EL-2099-0099", "libnl-3-200", "3.7.1", "CVE-2099-0001"))
		p.publishes("/2026/EL-26.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0026", "libnl-3-200", "3.7.1", "CVE-2026-4400"))

		fetch := fetching(t, f, p)
		fetch.Now = func() time.Time { return time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC) }
		took, err := fetch.From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 1 {
			t.Fatalf("%d documents were read, want the one that is not in the future",
				took.Documents)
		}
		if took.CaughtUpTo.Year() != 2026 {
			t.Errorf("the mark reached %v", took.CaughtUpTo)
		}
	})
}

func TestADirectoryWithoutAFeedIsRead(t *testing.T) {
	// The format offers two shapes and a publisher may serve either. The
	// largest publisher of these documents serves only the second, so a reader
	// that knows one takes their description, finds nothing, and reports that
	// it worked.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/csaf/2026/EL-27.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0027", "libnl-3-200", "3.7.1", "CVE-2026-4500"))
		p.override = func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/csaf/provider-metadata.json":
				_, _ = fmt.Fprintf(w, `{"distributions":[{"directory_url":%q}]}`,
					p.server.URL+"/csaf/")
			case "/csaf/changes.csv":
				_, _ = fmt.Fprint(w, "\"2026/EL-27.json\",\"2026-09-20T00:00:00Z\"\n")
			default:
				_, _ = fmt.Fprint(w, p.documents[r.URL.Path])
			}
		}

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 1 || took.Recorded != 1 {
			t.Errorf("a directory-only publisher read as %+v", took)
		}
	})
}

func TestOnlyWhatAPublisherServesToEverybodyIsRead(t *testing.T) {
	// One listing per label, and only the public ones have to be reachable
	// without arranging access. Read, a restricted one answers a refusal on
	// every pass — and failing the supplier on it means the public one beside
	// it is never reached.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-28.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0028", "libnl-3-200", "3.7.1", "CVE-2026-4600"))
		p.override = func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/csaf/provider-metadata.json":
				_, _ = fmt.Fprintf(w, `{"distributions":[{"rolie":{"feeds":[
					{"tlp_label":"AMBER","url":%q},{"tlp_label":"WHITE","url":%q}]}}]}`,
					p.server.URL+"/amber.json", p.server.URL+"/feed.json")
			case "/amber.json":
				http.Error(w, "not yours", http.StatusUnauthorized)
			case "/feed.json":
				_, _ = fmt.Fprintf(w, `{"feed":{"id":"f","title":"t","entry":[
					{"link":[{"rel":"self","href":%q}],"updated":"2026-09-20T00:00:00Z",
					 "content":{"type":"application/json","src":%q}}]}}`,
					p.server.URL+"/2026/EL-28.json", p.server.URL+"/2026/EL-28.json")
			default:
				_, _ = fmt.Fprint(w, p.documents[r.URL.Path])
			}
		}

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 1 {
			t.Errorf("the public listing was not read: %+v", took)
		}
		for _, path := range p.asked {
			if path == "/amber.json" {
				t.Error("a listing this deployment has no access to was fetched")
			}
		}
	})
}

func TestASupplierWithdrawnMidPassStopsBeingRead(t *testing.T) {
	// A pass takes minutes. One withdrawn during it goes on fetching and
	// recording, which is the request leaving this deployment that withdrawing
	// it was meant to stop.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-29.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0029", "libnl-3-200", "3.7.1", "CVE-2026-4700"))
		p.publishes("/2026/EL-30.json", "2026-09-21T00:00:00Z",
			advisory("EL-2026-0030", "libnl-3-200", "3.7.2", "CVE-2026-4800"))

		store := supplier.NewStore(f.db.DB)
		row, err := store.Add(ctx, f.by, f.product, "Example Linux", p.described())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*supplier.Source)(nil)).
			Set("caught_up_to = ?", long).Where("id = ?", row.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		source := *row
		source.CaughtUpTo = &long

		// Withdrawn as the pass runs, which is what the first document's write
		// reads back.
		fetch := fetching(t, f, p)
		fetch.Pause = time.Millisecond
		if err := store.Retire(ctx, f.by, f.product, "example linux"); err != nil {
			t.Fatal(err)
		}
		took, err := fetch.From(ctx, f.by, source)
		if err != nil {
			t.Fatal(err)
		}
		if took.Recorded != 0 || took.Documents != 0 {
			t.Errorf("a withdrawn supplier recorded %+v", took)
		}
	})
}

func TestASupplierOnARetiredProductIsNotRead(t *testing.T) {
	// A product taken out of use offers nothing and accepts no scan, and
	// nothing lists it — so a supplier configured against one goes on being
	// fetched with no screen left that could withdraw it.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)
		if _, err := store.Add(ctx, f.by, f.product, "Example Linux",
			"https://supplier.example/.well-known/csaf/provider-metadata.json"); err != nil {
			t.Fatal(err)
		}
		if err := catalog.NewStore(f.db.DB).RetireProduct(ctx, f.product); err != nil {
			t.Fatal(err)
		}
		due, err := store.Due(ctx, access.Everything("the pass"), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if len(due) != 0 {
			t.Errorf("a supplier on a product out of use is still read: %+v", due)
		}
		// And no new one is taken on.
		if _, err := store.Add(ctx, f.by, f.product, "Another", described); err == nil {
			t.Error("a product out of use took a supplier")
		}
	})
}

func TestASupplierIsMatchedWithoutRegardToCapitals(t *testing.T) {
	// A name people type is matched without regard to capitals. Stored as
	// typed, "SUSE" and "suse" are two suppliers on one product, and
	// withdrawing one answers 404 for the other — on every engine, because the
	// collation here is pinned.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)
		if _, err := store.Add(ctx, f.by, f.product, "SUSE", described); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Add(ctx, f.by, f.product, "suse", described); err == nil {
			t.Error("the same supplier was taken on twice under two spellings")
		}
		if err := store.Retire(ctx, f.by, f.product, "SuSE"); err != nil {
			t.Errorf("withdrawing it by another spelling: %v", err)
		}
		// And the spelling somebody typed is what comes back.
		if _, err := store.Add(ctx, f.by, f.product, "SUSE", described); err != nil {
			t.Fatal(err)
		}
		rows, err := store.For(ctx, f.by, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Display != "SUSE" {
			t.Errorf("the supplier reads as %+v", rows)
		}
	})
}

func TestAnAttemptIsRecordedEvenWhereTheMarkDoesNotMove(t *testing.T) {
	// Written as one condition on the statement, a mark that did not advance
	// took the record of the attempt with it — and the supplier was tried
	// again on every wake.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)
		row, err := store.Add(ctx, f.by, f.product, "Example Linux", described)
		if err != nil {
			t.Fatal(err)
		}
		// Two addresses, ordered by the digests they actually hash to rather
		// than by how they read. Which of two letters sorts first says nothing
		// about which of their digests does, and a test that assumed it would
		// write the pair in the advancing order and prove nothing.
		high, low := supplier.Mark("a"), supplier.Mark("b")
		if high < low {
			high, low = low, high
		}
		at := time.Now().UTC().Truncate(time.Microsecond)
		first := at.Add(-time.Hour)
		second := at.Add(-time.Minute)
		if err := store.At(func() time.Time { return first }).
			Reached(ctx, row.ID, at, high, nil); err != nil {
			t.Fatal(err)
		}
		// The same moment and an address whose digest sorts earlier, which is
		// a mark that does not advance. The attempt still happened, and the
		// moment it happened at is what says whether this supplier is being
		// tried.
		if err := store.At(func() time.Time { return second }).
			Reached(ctx, row.ID, at, low, nil); err != nil {
			t.Fatal(err)
		}
		rows, err := store.For(ctx, f.by, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].FetchedAt == nil {
			t.Fatalf("no attempt was recorded at all: %+v", rows)
		}
		if got := rows[0].FetchedAt.UTC(); !got.Equal(second) {
			t.Errorf("the second attempt reads as having happened at %v, want %v: a mark "+
				"that did not move took the record of the attempt with it", got, second)
		}
		if rows[0].CaughtUpMark != high {
			t.Errorf("the mark moved back to %q", rows[0].CaughtUpMark)
		}
	})
}

func TestAPassThatFilledItsBoundLeavesTheSupplierDue(t *testing.T) {
	// The bound is per wake and the interval is a day. Left to the interval, a
	// publisher issuing more in a day than one pass takes falls further behind
	// every day and never catches up.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		day := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
		for i := range supplier.MostPerPass + 4 {
			p.publishes(fmt.Sprintf("/busy/%02d.json", i),
				day.AddDate(0, 0, i).Format(time.RFC3339),
				advisory(fmt.Sprintf("EL-2026-5%03d", i), "libnl-3-200", "3.7.1",
					fmt.Sprintf("CVE-2026-51%02d", i)))
		}
		store := supplier.NewStore(f.db.DB)
		row, err := store.Add(ctx, f.by, f.product, "Example Linux", p.described())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*supplier.Source)(nil)).
			Set("caught_up_to = ?", long).Where("id = ?", row.ID).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		pass := supplier.NewPass(f.db.DB, quiet(), "test", sbom.Limits{}, outward.Excluded{})
		supplier.FetchForTest(pass, fetching(t, f, p))
		if _, err := pass.Once(ctx); err != nil {
			t.Fatal(err)
		}
		// Still due a moment later, because the bound is what stopped it.
		due, err := store.Due(ctx, access.Everything("the pass"), time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if len(due) != 1 {
			t.Fatalf("a supplier with a backlog is not due again for a day")
		}
		// And the second wake takes the rest.
		if took, err := pass.Once(ctx); err != nil || took.Documents != 4 {
			t.Errorf("the second wake read %+v (%v)", took, err)
		}
	})
}

func TestAPublisherNamingMorePlacesThanThisReadsIsRefused(t *testing.T) {
	// Nothing in the format bounds how many a description may name, and one
	// within the size bound can name tens of thousands of addresses on the
	// pinned host — which is a pass running for hours, holding every entry it
	// has read, and outliving the lease that says it is the one reading.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.override = func(w http.ResponseWriter, _ *http.Request) {
			feeds := make([]string, 0, supplier.MostFeeds+1)
			for i := range supplier.MostFeeds + 1 {
				feeds = append(feeds, fmt.Sprintf(
					`{"tlp_label":"WHITE","url":%q}`, fmt.Sprintf("%s/f%d.json", p.server.URL, i)))
			}
			_, _ = fmt.Fprintf(w, `{"distributions":[{"rolie":{"feeds":[%s]}}]}`,
				strings.Join(feeds, ","))
		}

		_, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err == nil {
			t.Fatal("a publisher naming more places than this reads was accepted")
		}
		if !strings.Contains(err.Error(), "past the") {
			t.Errorf("it was refused for the wrong reason: %v", err)
		}
		// And nothing was fetched from any of them.
		for _, path := range p.asked {
			if strings.HasPrefix(path, "/f") {
				t.Errorf("a listing was read anyway: %s", path)
			}
		}
	})
}

func TestWhatAPublisherSaysAboutAFailureIsKeptBounded(t *testing.T) {
	// The text carries a publisher's own address and a server's own reason
	// phrase, neither of which they have agreed to bound. Unbounded, the write
	// fails on two of the four engines — which leaves the attempt unrecorded
	// and the supplier fetched again on every wake.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		store := supplier.NewStore(f.db.DB)
		row, err := store.Add(ctx, f.by, f.product, "Example Linux", described)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Reached(ctx, row.ID, time.Time{}, "",
			errNothing(strings.Repeat("a publisher said so. ", 2000))); err != nil {
			t.Fatal(err)
		}
		rows, err := store.For(ctx, f.by, f.product)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].FetchedAt == nil {
			t.Fatalf("the attempt was not recorded: %+v", rows)
		}
		if held := len([]rune(rows[0].Failed)); held > supplier.MostReason {
			t.Errorf("%d characters of a publisher's own text were stored", held)
		}
		if rows[0].Failed == "" {
			t.Error("nothing was kept of why it failed")
		}
	})
}

// digestOf is the document's own digest, the way an upload records one: over
// the bytes and nothing else.
func digestOf(body string) string { return supplier.Mark(body) }

// everything is how an upload takes a document — all of it, with none of the
// narrowing this path does.
func everything(read sbom.Advisory) []finding.Statement {
	var out []finding.Statement
	for _, claim := range read.Claims {
		for _, at := range claim.Targets {
			out = append(out, finding.Statement{
				Vulnerability: claim.Vulnerability, Purl: at.Purl,
				About: at.VersionNamed(), Component: at.ComponentNamed(),
				Status: string(claim.Status), Justification: claim.Justification,
				Statement: claim.Statement,
			})
		}
	}
	return out
}
