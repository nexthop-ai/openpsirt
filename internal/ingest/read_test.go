package ingest_test

import (
	"io"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

const anInventory = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6",
  "metadata": {"timestamp": "2026-08-01T00:00:00Z",
    "component": {"bom-ref": "root", "name": "sonic-broadcom.bin", "version": "1.0"}},
  "components": [
    {"bom-ref": "a", "name": "libc6", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"},
    {"bom-ref": "b", "name": "zlib1g", "version": "1.3", "purl": "pkg:deb/debian/zlib1g@1.3"}],
  "dependencies": [{"ref": "root", "dependsOn": ["a", "b"]}, {"ref": "a", "dependsOn": ["b"]}]
}`

const aSuppression = `{"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:x", "version": 1,
 "statements": [{"vulnerability": {"name": "CVE-2026-1"}, "status": "not_affected",
 "products": [{"@id": "pkg:deb/debian/libc6"}]}]}`

// readerFixture is a migrated database with a declared branch and tag, a
// queue, and a reader over both.
type readerFixture struct {
	db     *database.DB
	queue  *queue.Queue
	reader *ingest.Reader
	branch int64
	tag    int64
}

// accept records a scan and stores what a build sent with it, the way an
// upload does, and leaves the work behind.
func (f *readerFixture) accept(t *testing.T, targetID int64, builtAt time.Time, inventory string, suppressions ...string) int64 {
	t.Helper()
	ctx := t.Context()
	scan, outcome, err := ingest.NewStore(f.db.DB).Record(ctx, ingest.Arriving{
		TargetID: targetID, ContentHash: inventory[:16] + builtAt.String(),
		BuiltAt: builtAt, ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record: %v %v", outcome, err)
	}
	docs := ingest.NewDocuments(f.db.DB)
	if _, err := docs.Write(ctx, scan.ID, ingest.InventoryKind, 0, strings.NewReader(inventory)); err != nil {
		t.Fatal(err)
	}
	for i, s := range suppressions {
		if _, err := docs.Write(ctx, scan.ID, ingest.SuppressionsKind, i, strings.NewReader(s)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.queue.Add(ctx, queue.Parse, strconv.FormatInt(scan.ID, 10)); err != nil {
		t.Fatal(err)
	}
	return scan.ID
}

// store records a scan and what came with it, leaving the caller to decide
// when — and in what order — it gets read.
func (f *readerFixture) store(t *testing.T, targetID int64, builtAt time.Time, inventory string) int64 {
	t.Helper()
	ctx := t.Context()
	scan, outcome, err := ingest.NewStore(f.db.DB).Record(ctx, ingest.Arriving{
		TargetID: targetID, ContentHash: inventory[:16] + builtAt.String(),
		BuiltAt: builtAt, ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		t.Fatalf("record: %v %v", outcome, err)
	}
	if _, err := ingest.NewDocuments(f.db.DB).Write(ctx, scan.ID, ingest.InventoryKind, 0,
		strings.NewReader(inventory)); err != nil {
		t.Fatal(err)
	}
	return scan.ID
}

func eachReader(t *testing.T, fn func(t *testing.T, f *readerFixture)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		branch, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		// One variant, declared once for the product. Both releases are built
		// as it, which is two targets over one variant — the shape that used
		// to need the name typed twice.
		variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		branchTarget, err := cat.TargetFor(ctx, branch.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}
		tag, err := cat.DeclareStream(ctx, product.ID, "2.4.0", catalog.Tag, &branch.ID)
		if err != nil {
			t.Fatal(err)
		}
		tagTarget, err := cat.TargetFor(ctx, tag.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}

		q := queue.New(db, queue.DefaultOptions())
		fn(t, &readerFixture{
			db: db, queue: q, branch: branchTarget.ID, tag: tagTarget.ID,
			reader: ingest.NewReader(db, q, sbom.Limits{}, quiet, "test"),
		})
	})
}

func TestAnAcceptedScanBecomesStoredGraph(t *testing.T) {
	eachReader(t, func(t *testing.T, f *readerFixture) {
		scanID := f.accept(t, f.branch, time.Now().UTC().Add(-time.Hour), anInventory, aSuppression)

		result, err := f.reader.Once(t.Context())
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if result == nil {
			t.Fatal("there was work waiting and nothing was done")
		}
		if result.ScanID != scanID {
			t.Errorf("read scan %d, want %d", result.ScanID, scanID)
		}
		// The root is stored like any other node, so three components plus it.
		if result.Applied.NodesOpened != 3 || result.Applied.EdgesOpened != 3 {
			t.Errorf("applied %+v, want 3 nodes and 3 edges", result.Applied)
		}
		if result.Suppressions != 1 {
			t.Errorf("read %d suppressions, want 1", result.Suppressions)
		}

		nodes, err := graph.NewStore(f.db.DB).CurrentNodes(t.Context(), f.branch)
		if err != nil || len(nodes) != 3 {
			t.Errorf("%d nodes are present, want 3 (%v)", len(nodes), err)
		}
		// Reading an inventory leaves scanning to be done. The two are
		// separate work because they happen at different times: an inventory
		// is read once, and scanned again and again as the vulnerability data
		// moves under it.
		waiting, err := f.queue.Claim(t.Context(), "test", queue.Scan)
		if err != nil || waiting == nil {
			t.Fatalf("no scan was left to be done (%v)", err)
		}
		if waiting.Kind != queue.Scan {
			t.Errorf("left %q to be done, want a scan", waiting.Kind)
		}
		if waiting.Reference != strconv.FormatInt(f.branch, 10) {
			t.Errorf("left a scan of %q, want the target just read", waiting.Reference)
		}
	})
}

func TestABranchScanKeepsTheRecordAndNotTheContents(t *testing.T) {
	// The next night supersedes what it was sent, so keeping the files
	// grows storage with the calendar rather than with what is being
	// tracked. The record of what arrived stays: without it the upload
	// reads back as one that arrived with nothing, which is what a failed
	// one looks like, and the hash a re-parse would check a resent file
	// against is gone.
	eachReader(t, func(t *testing.T, f *readerFixture) {
		scanID := f.accept(t, f.branch, time.Now().UTC().Add(-time.Hour), anInventory, aSuppression)
		result, err := f.reader.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if result.Retained {
			t.Error("a branch scan kept what it was sent")
		}
		docs := ingest.NewDocuments(f.db.DB)
		held, err := docs.List(t.Context(), scanID)
		if err != nil || len(held) != 0 {
			t.Errorf("%d documents survived a branch scan (%v)", len(held), err)
		}
		sent, err := docs.Sent(t.Context(), []int64{scanID})
		if err != nil {
			t.Fatal(err)
		}
		if len(sent[scanID]) != 2 {
			t.Fatalf("the scan reads back as %d documents sent, want the inventory and its "+
				"suppressions", len(sent[scanID]))
		}
		for _, doc := range sent[scanID] {
			if doc.ContentHash == "" {
				t.Errorf("the %s document reads back with no hash of what arrived", doc.Kind)
			}
			if doc.DiscardedAt == nil {
				t.Errorf("the %s document does not say its contents were let go", doc.Kind)
			}
		}
	})
}

func TestATaggedReleaseKeepsWhatItWasSent(t *testing.T) {
	// Re-scanning a release years from now needs both what it contained and
	// what the build had already argued about its own patches. Keeping only
	// the first would undo every one of those arguments on the next re-scan.
	eachReader(t, func(t *testing.T, f *readerFixture) {
		scanID := f.accept(t, f.tag, time.Now().UTC().Add(-time.Hour), anInventory, aSuppression)
		result, err := f.reader.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !result.Retained {
			t.Error("a tagged release threw away what it was sent")
		}
		held, err := ingest.NewDocuments(f.db.DB).List(t.Context(), scanID)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != 2 {
			t.Errorf("%d documents kept, want the inventory and its suppressions", len(held))
		}
	})
}

func TestAScanThatCannotBeReadSaysSoOnTheScan(t *testing.T) {
	// A producer sending files nothing can read has to be visible as that,
	// rather than as a scan that was accepted and then quietly did nothing.
	eachReader(t, func(t *testing.T, f *readerFixture) {
		scanID := f.accept(t, f.branch, time.Now().UTC().Add(-time.Hour),
			`{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"version": "1"}]}`)

		if _, err := f.reader.Once(t.Context()); err == nil {
			t.Fatal("an unreadable inventory was read successfully")
		}
		scan, err := ingest.NewStore(f.db.DB).ByID(t.Context(), scanID)
		if err != nil {
			t.Fatal(err)
		}
		if scan.Status != ingest.Failed {
			t.Errorf("scan status is %q, want %q", scan.Status, ingest.Failed)
		}
		if !strings.Contains(scan.Failure, "no name") {
			t.Errorf("the scan does not say why it failed: %q", scan.Failure)
		}
		// Nothing partial: a half-applied graph is indistinguishable from
		// components having been removed.
		nodes, _ := graph.NewStore(f.db.DB).CurrentNodes(t.Context(), f.branch)
		if len(nodes) != 0 {
			t.Errorf("%d nodes were stored from a scan that failed", len(nodes))
		}
	})
}

func TestThereIsNothingToDoWhenNothingIsWaiting(t *testing.T) {
	eachReader(t, func(t *testing.T, f *readerFixture) {
		result, err := f.reader.Once(t.Context())
		if err != nil || result != nil {
			t.Errorf("an empty queue produced %+v (%v)", result, err)
		}
	})
}

func TestWhatWasToleratedIsReported(t *testing.T) {
	// Each of these is a number that should be stable build to build, so a
	// change in one says the producer changed. Computing them and then
	// discarding them is how that goes unnoticed.
	eachReader(t, func(t *testing.T, f *readerFixture) {
		// One component under nothing, one with no version, one edge naming
		// something the document never describes.
		f.accept(t, f.branch, time.Now().UTC().Add(-time.Hour), `{
		  "bomFormat": "CycloneDX", "specVersion": "1.6",
		  "metadata": {"timestamp": "2026-08-01T00:00:00Z",
		    "component": {"bom-ref": "root", "name": "sonic", "version": "1.0"}},
		  "components": [
		    {"bom-ref": "a", "name": "libc6", "version": "2.41", "purl": "pkg:deb/debian/libc6@2.41"},
		    {"bom-ref": "b", "name": "orphan", "version": "1.0", "purl": "pkg:deb/debian/orphan@1.0"},
		    {"bom-ref": "c", "name": "unversioned", "purl": "pkg:deb/debian/unversioned"}],
		  "dependencies": [{"ref": "root", "dependsOn": ["a", "ghost"]}]
		}`)

		result, err := f.reader.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if result.Unversioned != 1 {
			t.Errorf("%d components stated no version, want 1", result.Unversioned)
		}
		if result.DanglingEdges != 1 {
			t.Errorf("%d edges went nowhere, want 1", result.DanglingEdges)
		}
		// The orphan and the unversioned one both sit under nothing.
		if result.Unrooted != 2 {
			t.Errorf("%d components sit under nothing, want 2", result.Unrooted)
		}
	})
}

func TestAScanOvertakenByANewerOneIsNotApplied(t *testing.T) {
	// Uploads are accepted in arrival order and read in whatever order workers
	// pick them up, so an older scan can reach the reader after a newer one
	// has already been applied. Applying it then replaces today's picture with
	// yesterday's and reopens everything the newer one closed — the harm the
	// arrival check prevents at the door, arriving from behind.
	eachReader(t, func(t *testing.T, f *readerFixture) {
		now := time.Now().UTC()
		older := f.store(t, f.branch, now.Add(-2*time.Hour), anInventory)
		newer := f.store(t, f.branch, now.Add(-time.Hour), anInventory)

		// The newer one is read first, which is what a queue handing two jobs
		// to two workers can produce.
		for _, id := range []int64{newer, older} {
			if _, err := f.queue.Add(t.Context(), queue.Parse, strconv.FormatInt(id, 10)); err != nil {
				t.Fatal(err)
			}
		}
		var applied, skipped int
		for range 4 {
			result, err := f.reader.Once(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if result == nil {
				break
			}
			switch {
			case result.Superseded:
				skipped++
				if result.ScanID != older {
					t.Errorf("skipped scan %d, expected the older one", result.ScanID)
				}
			default:
				applied++
			}
		}
		if skipped != 1 {
			t.Errorf("%d scans were skipped as overtaken, want 1", skipped)
		}

		// And what is present is the newer picture, not the older one.
		nodes, err := graph.NewStore(f.db.DB).CurrentNodes(t.Context(), f.branch)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 3 {
			t.Errorf("%d nodes present, want the graph the newer scan described", len(nodes))
		}
	})
}

func TestAScanOvertakenByOneThatThenFailsIsReadAgain(t *testing.T) {
	// An older scan is set aside on the strength of the newer one's row alone
	// — the newer one may not have been read yet. If it then cannot be read,
	// the build would be left showing whatever came before both: the older
	// scan's job is done and nothing reads it again, and its receipt waits
	// for a scan run that never comes.
	eachReader(t, func(t *testing.T, f *readerFixture) {
		now := time.Now().UTC()
		older := f.store(t, f.branch, now.Add(-2*time.Hour), anInventory)
		newer := f.store(t, f.branch, now.Add(-time.Hour),
			`{"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"version": "1"}]}`)

		// The older one is read first and set aside; then the newer one
		// fails.
		for _, id := range []int64{older, newer} {
			if _, err := f.queue.Add(t.Context(), queue.Parse, strconv.FormatInt(id, 10)); err != nil {
				t.Fatal(err)
			}
		}
		result, err := f.reader.Once(t.Context())
		if err != nil || result == nil || !result.Superseded || result.ScanID != older {
			t.Fatalf("the older scan was not set aside as overtaken: %+v %v", result, err)
		}
		if _, err := f.reader.Once(t.Context()); err == nil {
			t.Fatal("the unreadable newer scan was read successfully")
		}

		// The older one is read again, and it is what the build now shows.
		result, err = f.reader.Once(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if result == nil {
			t.Fatal("nothing brought the overtaken scan back")
		}
		if result.Superseded || result.ScanID != older {
			t.Fatalf("read %+v, want the older scan applied", result)
		}
		nodes, err := graph.NewStore(f.db.DB).CurrentNodes(t.Context(), f.branch)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 3 {
			t.Errorf("%d nodes present, want the graph the older scan described", len(nodes))
		}
		// And once, not every time something fails.
		if result, err := f.reader.Once(t.Context()); err != nil || result != nil {
			t.Errorf("more work was left behind: %+v %v", result, err)
		}
	})
}
