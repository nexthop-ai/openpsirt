package directory_test

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	fixtures "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/directory"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
)

var issuer = publisher.Named{
	Name: "Example Networks", Namespace: "https://example.test",
	Category: "vendor", Prefix: "EXNET",
}

const served = "https://psirt.example.test/.well-known/csaf"

// TestWhatWentOutIsWhatIsWritten walks the whole of it: an advisory is
// recorded, agreed to and issued, and the directory that comes out is the
// shape the standard asks for.
func TestWhatWentOutIsWhatIsWritten(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		named := f.issued(t, "A flaw in the recovery console")
		written := f.write(t)
		if written.Documents != 1 || written.Held != 0 {
			t.Fatalf("wrote %+v, want the one advisory that went out", written)
		}

		// A folder per year, and the filename the standard's rule gives.
		at := filepath.Join(time.Now().UTC().Format("2006"), strings.ToLower(named)+".json")
		body := f.read(t, at)

		// The bytes are the ones the issuance recorded, rather than a
		// document generated again now.
		gone, err := f.store.Issuances(t.Context(), f.who, named)
		if err != nil {
			t.Fatal(err)
		}
		if len(gone) != 1 {
			t.Fatalf("%d issuances, want one", len(gone))
		}
		var doc advisory.Document
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("what was written is not a document: %v", err)
		}
		if doc.Document.Tracking.ID != named {
			t.Errorf("the file is tracked as %q, want %q", doc.Document.Tracking.ID, named)
		}
		// Dated when it went out rather than when it was written, which is
		// what keeps the file still between passes.
		if !doc.Document.Tracking.CurrentReleaseDate.Equal(gone[0].IssuedAt) {
			t.Errorf("the file is dated %s, want the moment it went out, %s",
				doc.Document.Tracking.CurrentReleaseDate, gone[0].IssuedAt)
		}
		// And it says it is the publisher's settled word rather than
		// something still being generated: the last revision entry is the
		// issuance, not a document nobody has published.
		history := doc.Document.Tracking.RevisionHistory
		if len(history) == 0 {
			t.Fatal("the file carries no revision history")
		}
		if last := history[len(history)-1]; last.Summary == "Generated, not yet issued" {
			t.Errorf("the published file describes itself as unpublished: %+v", last)
		}
		if doc.Document.Tracking.Version != history[len(history)-1].Number {
			t.Errorf("version %q against a history ending at %q",
				doc.Document.Tracking.Version, history[len(history)-1].Number)
		}

		// The hash beside it answers for those bytes, and the list of
		// documents and the list of changes both name the file.
		f.checksums(t, at, body)
		if index := string(f.read(t, "index.txt")); !strings.Contains(index, at) {
			t.Errorf("the list of documents does not name %s: %q", at, index)
		}
		rows, err := csv.NewReader(strings.NewReader(string(f.read(t, "changes.csv")))).ReadAll()
		if err != nil {
			t.Fatalf("the list of changes is not readable: %v", err)
		}
		if len(rows) != 1 || rows[0][0] != at {
			t.Fatalf("the list of changes is %v, want one row naming %s", rows, at)
		}
		if rows[0][1] != doc.Document.Tracking.CurrentReleaseDate.Format(time.RFC3339Nano) {
			t.Errorf("the list of changes says %q and the document says %q",
				rows[0][1], doc.Document.Tracking.CurrentReleaseDate.Format(time.RFC3339Nano))
		}
	})
}

// A revised advisory is published as its newest revision, and the file says
// it has been published rather than generated.
//
// Two issuances, because that is what it takes to reach it: the document
// assembled for a reader carries a last entry saying it has been generated
// and not issued, and that entry exists only once something has gone out
// before. Written into the directory, it is a published file announcing that
// it was never published.
func TestARevisedAdvisoryIsPublishedAsItsNewestRevision(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		named := f.issued(t, "A flaw in the recovery console")
		if _, err := f.store.Issued(t.Context(), f.who, issuer, named,
			"Named the fixed releases."); err != nil {
			t.Fatalf("recording the second issuance: %v", err)
		}
		f.write(t)

		at := filepath.Join(time.Now().UTC().Format("2006"), strings.ToLower(named)+".json")
		var doc advisory.Document
		if err := json.Unmarshal(f.read(t, at), &doc); err != nil {
			t.Fatal(err)
		}
		// The recording, and one entry per issuance, numbered without a gap.
		history := doc.Document.Tracking.RevisionHistory
		want := []string{"1", "2", "3"}
		if len(history) != len(want) {
			t.Fatalf("the history is %+v, want an entry per revision", history)
		}
		for at := range want {
			if history[at].Number != want[at] {
				t.Errorf("entry %d is numbered %q, want %q", at, history[at].Number, want[at])
			}
			if history[at].Summary == "Generated, not yet issued" {
				t.Errorf("entry %d says the published file was never published", at)
			}
		}
		if history[len(history)-1].Summary != "Named the fixed releases." {
			t.Errorf("the newest entry says %q, want what was said about that revision",
				history[len(history)-1].Summary)
		}
		if doc.Document.Tracking.Version != "3" {
			t.Errorf("the file is version %q, want the number its history ends at",
				doc.Document.Tracking.Version)
		}
	})
}

// The feed names every document, the hash beside it, and the address a reader
// fetches it from.
func TestTheFeedNamesEachDocumentAndTheHashBesideIt(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		named := f.issued(t, "A flaw in the recovery console")
		f.write(t)

		var feed struct {
			Feed struct {
				ID       string `json:"id"`
				Title    string `json:"title"`
				Category []struct {
					Scheme string `json:"scheme"`
					Term   string `json:"term"`
				} `json:"category"`
				Updated string `json:"updated"`
				Entry   []struct {
					ID   string `json:"id"`
					Link []struct {
						Rel  string `json:"rel"`
						Href string `json:"href"`
					} `json:"link"`
					Content struct {
						Type   string `json:"type"`
						Source string `json:"src"`
					} `json:"content"`
					Format struct {
						Version string `json:"version"`
					} `json:"format"`
				} `json:"entry"`
			} `json:"feed"`
		}
		if err := json.Unmarshal(f.read(t, "feed-tlp-white.json"), &feed); err != nil {
			t.Fatalf("the feed is not readable: %v", err)
		}
		if len(feed.Feed.Entry) != 1 {
			t.Fatalf("%d entries, want the one advisory", len(feed.Feed.Entry))
		}
		one := feed.Feed.Entry[0]
		if one.ID != named {
			t.Errorf("the entry is %q, want %q", one.ID, named)
		}
		links := map[string]string{}
		for _, link := range one.Link {
			links[link.Rel] = link.Href
		}
		at := served + "/" + time.Now().UTC().Format("2006") + "/" + strings.ToLower(named) + ".json"
		if links["self"] != at {
			t.Errorf("the entry points at %q, want %q", links["self"], at)
		}
		// The standard requires the hash file to be named wherever one
		// exists, so a reader checking integrity does not have to guess.
		if links["hash"] != at+".sha256" {
			t.Errorf("the entry names the hash as %q, want %q", links["hash"], at+".sha256")
		}
		if one.Content.Source != at || one.Content.Type != "application/json" {
			t.Errorf("the entry's content is %+v", one.Content)
		}
		if len(feed.Feed.Category) != 1 ||
			feed.Feed.Category[0].Scheme != "urn:ietf:params:rolie:category:information-type" ||
			feed.Feed.Category[0].Term != "csaf" {
			t.Errorf("the feed states its subject as %+v", feed.Feed.Category)
		}
	})
}

// The provider description carries what an aggregator reads, and points at
// files that are there.
func TestTheProviderDescriptionSaysWhoThisIsAndWhereTheDocumentsAre(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.issued(t, "A flaw in the recovery console")
		f.write(t)

		var described struct {
			CanonicalURL  string `json:"canonical_url"`
			Distributions []struct {
				DirectoryURL string `json:"directory_url"`
				ROLIE        struct {
					Feeds []struct {
						TLPLabel string `json:"tlp_label"`
						URL      string `json:"url"`
					} `json:"feeds"`
				} `json:"rolie"`
			} `json:"distributions"`
			LastUpdated string `json:"last_updated"`
			Listed      bool   `json:"list_on_CSAF_aggregators"`
			Mirrored    bool   `json:"mirror_on_CSAF_aggregators"`
			Version     string `json:"metadata_version"`
			Publisher   struct {
				Category  string `json:"category"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"publisher"`
			Role string `json:"role"`
		}
		if err := json.Unmarshal(f.read(t, "provider-metadata.json"), &described); err != nil {
			t.Fatalf("the provider description is not readable: %v", err)
		}
		if described.CanonicalURL != served+"/provider-metadata.json" {
			t.Errorf("it calls itself %q", described.CanonicalURL)
		}
		if described.Version != "2.0" || described.Role != "csaf_provider" {
			t.Errorf("version %q, role %q", described.Version, described.Role)
		}
		if described.Publisher.Name != issuer.Name ||
			described.Publisher.Namespace != issuer.Namespace ||
			described.Publisher.Category != issuer.Category {
			t.Errorf("it names the publisher as %+v", described.Publisher)
		}
		// The standard reads an answer it cannot get as listed and not
		// mirrored, and these are the deployment's own answers.
		if !described.Listed || described.Mirrored {
			t.Errorf("listed %v, mirrored %v", described.Listed, described.Mirrored)
		}
		if len(described.Distributions) != 1 {
			t.Fatalf("%d distributions", len(described.Distributions))
		}
		at := described.Distributions[0]
		if at.DirectoryURL != served+"/" {
			t.Errorf("the directory is at %q, want %q", at.DirectoryURL, served+"/")
		}
		if len(at.ROLIE.Feeds) != 1 || at.ROLIE.Feeds[0].TLPLabel != "WHITE" ||
			at.ROLIE.Feeds[0].URL != served+"/feed-tlp-white.json" {
			t.Errorf("the feed is described as %+v", at.ROLIE.Feeds)
		}
	})
}

// An advisory nobody has published is not in the directory, and neither is
// anything else: there is nothing to date a directory from.
func TestAnAdvisoryThatHasNotGoneOutIsNotWritten(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		identifier := f.recorded(t)
		named := f.minted(t, "A flaw in the recovery console")
		if _, err := f.store.Add(t.Context(), f.who, named,
			fixtures.ProductName, identifier); err != nil {
			t.Fatal(err)
		}
		written := f.write(t)
		if written.Documents != 0 {
			t.Errorf("wrote %d documents for an advisory nobody published", written.Documents)
		}
		if _, err := os.Stat(filepath.Join(f.where, "provider-metadata.json")); !os.IsNotExist(err) {
			t.Error("a directory was described with nothing in it")
		}
	})
}

// A second pass over an unchanged record writes the bytes it wrote before.
//
// What a reader re-fetches is decided by the file having moved, so a pass
// that rewrites every file with the moment it ran makes every reader fetch
// the whole directory every hour.
func TestWritingTwiceWritesTheSameBytes(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		f.issued(t, "A flaw in the recovery console")
		f.write(t)
		was := map[string][]byte{}
		for _, at := range f.every(t) {
			was[at] = f.read(t, at)
		}
		f.write(t)
		for _, at := range f.every(t) {
			if string(f.read(t, at)) != string(was[at]) {
				t.Errorf("%s moved between two passes over an unchanged record", at)
			}
		}
	})
}

// A deployment that configured nowhere to write writes nothing, and says so
// by answering with no writer at all rather than with a pass that does
// nothing every hour.
func TestNoAddressAndNoStoreIsNoWriter(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		for _, one := range []struct {
			what     string
			store    attach.Storage
			settings directory.Config
		}{
			{"no store", nil, directory.Config{URL: served}},
			{"no address", f.files, directory.Config{}},
		} {
			writer, err := directory.New(f.db, one.store, issuer, one.settings, f.logger)
			if err != nil {
				t.Errorf("%s: %v", one.what, err)
			}
			if writer != nil {
				t.Errorf("%s: a writer was started anyway", one.what)
			}
		}
	})
}

// An address the documents could not be fetched over is refused where it is
// configured, rather than producing a directory that fails the first check
// anybody makes of it.
func TestAnAddressThatIsNotOverTLSIsRefused(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		for _, where := range []string{
			"http://psirt.example.test/csaf",
			"/csaf",
		} {
			writer, err := directory.New(f.db, f.files, issuer,
				directory.Config{URL: where}, f.logger)
			if err == nil {
				t.Errorf("%q was accepted", where)
			}
			if writer != nil {
				t.Errorf("%q started a writer", where)
			}
			if err != nil && !strings.Contains(err.Error(), "OPENPSIRT_DIRECTORY_URL") {
				t.Errorf("%q: the refusal does not name the setting: %v", where, err)
			}
		}
	})
}

// A deployment that has not been told who it publishes as writes no
// directory: every document in it and the description of it name a publisher.
func TestADirectoryNamesItsPublisher(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		writer, err := directory.New(f.db, f.files, publisher.Named{Prefix: "EXNET"},
			directory.Config{URL: served}, f.logger)
		if err == nil {
			t.Error("a directory was configured with no publisher")
		}
		if writer != nil {
			t.Error("a writer was started with no publisher")
		}
	})
}

// fixture is a world with one product, somebody to write an advisory and
// somebody else to agree to it, and a directory on disk to write into.
type fixture struct {
	db     *bun.DB
	store  *advisory.Store
	finds  *finding.Store
	graph  *graph.Store
	scans  *ingest.Store
	target int64
	who    access.Subject
	agrees access.Subject
	files  attach.Storage
	where  string
	logger *slog.Logger
	seq    int
}

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	fixtures.Each(t, func(t *testing.T, w *fixtures.World) {
		second := w.DeclarePerson("reader", "A Reader", false)
		roles := map[int64][]access.Role{
			w.Product.ID: {access.PublicRead, access.PrivateRead, access.PrivateTriage},
		}
		where := t.TempDir()
		files, err := attach.NewFiles(where)
		if err != nil {
			t.Fatal(err)
		}
		f := &fixture{
			db: w.DB.DB, store: advisory.NewStore(w.DB.DB),
			finds: finding.NewStore(w.DB.DB), graph: graph.NewStore(w.DB.DB),
			scans: ingest.NewStore(w.DB.DB), target: w.Target.ID,
			who: access.NewPerson(w.Person.ID, w.Person.Identity, false, roles, 0),
			agrees: access.NewPerson(second.ID, second.Identity, false,
				map[int64][]access.Role{
					w.Product.ID: {access.PublicRead, access.PrivateRead, access.PrivateTriage},
				}, 0),
			files: files, where: where,
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		f.shipped(t)
		fn(t, f)
	})
}

// write runs one pass.
func (f *fixture) write(t *testing.T) directory.Written {
	t.Helper()
	writer, err := directory.New(f.db, f.files, issuer, directory.Config{
		URL: served, List: true, Mirror: false,
	}, f.logger)
	if err != nil {
		t.Fatalf("configuring the directory: %v", err)
	}
	if writer == nil {
		t.Fatal("no writer was started")
	}
	written, err := writer.Write(t.Context())
	if err != nil {
		t.Fatalf("writing the directory: %v", err)
	}
	return written
}

// read is one file out of the directory.
func (f *fixture) read(t *testing.T, at string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(f.where, filepath.FromSlash(at)))
	if err != nil {
		t.Fatalf("reading %s out of the directory: %v", at, err)
	}
	return body
}

// every is every file the directory holds, by the path it holds it under.
func (f *fixture) every(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(f.where, func(at string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		under, err := filepath.Rel(f.where, at)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(under))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("the directory holds nothing, so this compared nothing")
	}
	return out
}

// checksums reads the hash file beside a document and checks it against the
// bytes that were written.
func (f *fixture) checksums(t *testing.T, at string, body []byte) {
	t.Helper()
	stated := strings.Fields(string(f.read(t, at+".sha256")))
	if len(stated) != 2 {
		t.Fatalf("the hash file beside %s reads %q", at, stated)
	}
	sum := sha256Of(body)
	if stated[0] != sum {
		t.Errorf("the hash file says %s and the bytes hash to %s", stated[0], sum)
	}
	if _, name := filepath.Split(at); stated[1] != name {
		t.Errorf("the hash file names %q, want %q", stated[1], name)
	}
}

// issued records a flaw, writes an advisory about it, has the second person
// agree, and publishes it. The name it went out under comes back.
func (f *fixture) issued(t *testing.T, title string) string {
	t.Helper()
	identifier := f.recorded(t)
	named := f.minted(t, title)
	if _, err := f.store.Add(t.Context(), f.who, named,
		fixtures.ProductName, identifier); err != nil {
		t.Fatalf("naming the flaw on the advisory: %v", err)
	}
	if _, err := f.store.Approve(t.Context(), f.agrees, named); err != nil {
		t.Fatalf("agreeing to the advisory: %v", err)
	}
	if _, err := f.store.Issued(t.Context(), f.who, issuer, named,
		"Published."); err != nil {
		t.Fatalf("recording that it went out: %v", err)
	}
	return named
}

func (f *fixture) minted(t *testing.T, title string) string {
	t.Helper()
	made, err := f.store.Mint(t.Context(), f.who, issuer, title)
	if err != nil {
		t.Fatalf("starting an advisory: %v", err)
	}
	return made.Identifier
}

// recorded enters a flaw in what this deployment ships, which is the only
// kind an advisory is written about.
func (f *fixture) recorded(t *testing.T) string {
	t.Helper()
	_, identifier, err := f.finds.Enter(t.Context(), f.who, finding.Entering{
		TargetIDs: []int64{f.target}, Component: carrier.Name, Severity: "high",
		Summary:   "The management socket answers before anyone authenticated.",
		Disclosed: true,
	})
	if err != nil {
		t.Fatalf("recording a flaw: %v", err)
	}
	return identifier
}

// shipped stores an inventory against the build, so the advisory has a
// release to name.
func (f *fixture) shipped(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	f.seq++
	scan, outcome, err := f.scans.Record(ctx, ingest.Arriving{
		TargetID: f.target, ContentHash: "hash-1", BuiltAt: time.Now().UTC().Add(-time.Hour),
		ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record scan: %v %v", outcome, err)
	}
	if _, err := f.graph.Apply(ctx, f.target, scan.ID, graph.Snapshot{
		Root: root, Components: []graph.Described{carrier},
		Dependencies: []graph.Dependency{{Parent: root, Child: carrier}},
	}); err != nil {
		t.Fatalf("apply graph: %v", err)
	}
	if err := f.scans.Made(ctx, scan.ID, 1, 1, root.Purl); err != nil {
		t.Fatalf("record what the document declared: %v", err)
	}
}

// sha256Of is the hash the directory writes, computed here rather than asked
// of the code under test: a helper that called the same function would pass
// against any hash it happened to take.
func sha256Of(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

var (
	root    = graph.Described{Purl: "pkg:deb/debian/sonic@1.0", Name: "sonic", Version: "1.0"}
	carrier = graph.Described{
		Purl: "pkg:deb/debian/libswsscommon@1.0.0", Name: "libswsscommon", Version: "1.0.0",
	}
)
