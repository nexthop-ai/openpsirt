// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package attach_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// fixture is one migrated database with a product, an issue, and a place the
// issue sits at — which is the least that makes an attachment reachable, since
// what may read one is what may read the issue.
type fixture struct {
	db      *database.DB
	store   *attach.Store
	files   attach.Storage
	root    string
	product int64
	issue   int64
	target  int64
}

const (
	// A limit and a quota generous enough not to be what a test is about,
	// except in the two tests that are about them.
	roomy    = 1 << 20
	plenty   = 1 << 30
	identity = "CVE-2026-4242"
)

func each(t *testing.T, fn func(t *testing.T, f *fixture)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		stream, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil)
		if err != nil {
			t.Fatal(err)
		}
		variant, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true)
		if err != nil {
			t.Fatal(err)
		}
		target, err := cat.TargetFor(ctx, stream.ID, variant.ID)
		if err != nil {
			t.Fatal(err)
		}

		root := t.TempDir()
		files, err := attach.NewFiles(root)
		if err != nil {
			t.Fatal(err)
		}
		f := &fixture{
			db: db, store: attach.NewStore(db.DB, files), files: files, root: root,
			product: product.ID, target: target.ID,
		}
		f.issue = f.anIssue(t, identity, access.Public)
		fn(t, f)
	})
}

// anIssue records a vulnerability and one place it sits at, at a visibility.
//
// The visibility is on the finding rather than on the issue, which is where it
// lives: what an attachment inherits is worked out from the places, not stored
// anywhere of its own.
func (f *fixture) anIssue(t *testing.T, name string, visibility access.Visibility) int64 {
	t.Helper()
	ctx := t.Context()
	issue := &finding.Vulnerability{
		Identifier: name, IdentifierFolded: strings.ToLower(name), Severity: "high",
	}
	if _, err := f.db.DB.NewInsert().Model(issue).Exec(ctx); err != nil {
		t.Fatalf("record an issue: %v", err)
	}
	component := &graph.Component{
		Identity: "component-" + name, Name: "libnl-3-200", Version: "3.7.0",
		Purl: "pkg:deb/debian/libnl@3.7.0",
	}
	if _, err := f.db.DB.NewInsert().Model(component).Exec(ctx); err != nil {
		t.Fatalf("record a component: %v", err)
	}
	row := &finding.Finding{
		TargetID: f.target, Kind: "dependency", VulnerabilityID: issue.ID,
		Visibility: visibility, ComponentID: component.ID,
		PlaceIdentity: "place-" + name, Urgency: 1, OpenedAt: time.Now().UTC(),
	}
	if _, err := f.db.DB.NewInsert().Model(row).Exec(ctx); err != nil {
		t.Fatalf("record a finding: %v", err)
	}
	return issue.ID
}

// who is somebody holding roles on the fixture's product.
func (f *fixture) who(t *testing.T, roles ...access.Role) access.Subject {
	t.Helper()
	person, err := access.NewStore(f.db.DB).Ensure(t.Context(),
		"them"+string(roles[0])+"@example.com", "Them", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPerson(person.ID, person.Identity, false,
		map[int64][]access.Role{f.product: roles}, 0)
}

func (f *fixture) admin(t *testing.T) access.Subject {
	t.Helper()
	person, err := access.NewStore(f.db.DB).Ensure(t.Context(), "boss@example.com", "Boss",
		access.Stated(true), nil)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPerson(person.ID, person.Identity, true,
		map[int64][]access.Role{f.product: {access.PublicRead, access.PrivateRead}}, 0)
}

// upload puts one file against the fixture's issue.
func (f *fixture) upload(t *testing.T, who access.Subject, name string, body []byte) *attach.Attachment {
	t.Helper()
	row, err := f.store.Upload(t.Context(), who, attach.Against{ProductID: f.product, VulnerabilityID: f.issue}, name,
		strings.NewReader(string(body)), int64(len(body)), roomy, plenty, plenty, false)
	if err != nil {
		t.Fatalf("upload %s: %v", name, err)
	}
	return row
}

// A one-pixel PNG, so that the type is decided from real bytes rather than
// from something that happens to sniff as one.
var onePixelPNG = []byte{
	0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
	0, 0, 0, 0x0d, 'I', 'H', 'D', 'R',
	0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89,
	0, 0, 0, 0x0a, 'I', 'D', 'A', 'T', 0x78, 0x9c, 0x63, 0, 1, 0, 0, 5, 0, 1,
	0x0d, 0x0a, 0x2d, 0xb4, 0, 0, 0, 0, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
}

func TestAFileGoesInAndComesBack(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		who := f.who(t, access.PublicTriage)
		stored := f.upload(t, who, "evidence.png", onePixelPNG)

		if stored.Token == "" || len(stored.Token) != 32 {
			t.Errorf("the reference is %q, want something a text can carry", stored.Token)
		}
		row, address, body, err := f.store.Fetch(t.Context(), who, stored.Token, time.Minute)
		if err != nil {
			t.Fatalf("fetch: %v", err)
		}
		// The local store signs nothing, so everything comes from here.
		if address != "" {
			t.Errorf("the local store handed out an address: %q", address)
		}
		defer func() { _ = body.Close() }()
		got, _ := io.ReadAll(body)
		if len(got) != len(onePixelPNG) {
			t.Errorf("came back as %d bytes, want %d", len(got), len(onePixelPNG))
		}
		if row.SizeBytes != int64(len(onePixelPNG)) {
			t.Errorf("recorded %d bytes, want %d", row.SizeBytes, len(onePixelPNG))
		}
	})
}

func TestWhatItIsIsDecidedHereAndNotByWhoeverUploadedIt(t *testing.T) {
	// A browser asked to render text/html from our own origin runs
	// whatever is in it, and the content type is the whole of what decides
	// that — so it is never the one that arrived.
	each(t, func(t *testing.T, f *fixture) {
		who := f.who(t, access.PublicTriage)
		for _, c := range []struct {
			what   string
			name   string
			body   []byte
			served string
			inline bool
		}{
			{"a png", "shot.png", onePixelPNG, "image/png", true},
			{"a page calling itself a png", "shot.png",
				[]byte("<html><script>alert(1)</script></html>"), attach.Octet, false},
			{"an svg, which is a document with a scripting engine", "logo.svg",
				[]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
				attach.Octet, false},
			{"a log", "run.log", []byte("nothing interesting happened\n"), attach.Octet, false},
		} {
			t.Run(c.what, func(t *testing.T) {
				stored := f.upload(t, who, c.name, c.body)
				if stored.ContentType != c.served {
					t.Errorf("%s is served as %q, want %q", c.what, stored.ContentType, c.served)
				}
				if stored.Inline() != c.inline {
					t.Errorf("%s displays inline = %v, want %v", c.what, stored.Inline(), c.inline)
				}
				if want := "attachment"; !c.inline &&
					!strings.HasPrefix(attach.Disposition(stored), want) {
					t.Errorf("%s is not served as a download: %q", c.what, attach.Disposition(stored))
				}
			})
		}
	})
}

func TestAFileIsAsReadableAsTheIssueItHangsOff(t *testing.T) {
	// The reason a fetch is authorized before any URL is issued, and the
	// reason the visibility is not stored on the attachment: whoever may read
	// the text may read what it refers to, and nobody else.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		undisclosed := f.anIssue(t, "CVE-2026-9001", access.Private)

		reader := f.who(t, access.PublicRead)
		trusted := f.who(t, access.PublicTriage, access.PrivateTriage)

		public := f.upload(t, f.who(t, access.PublicTriage), "public.log",
			[]byte("open knowledge"))
		hidden, err := f.store.Upload(ctx, trusted, attach.Against{ProductID: f.product, VulnerabilityID: undisclosed}, "hidden.log",
			strings.NewReader("not announced"), 13, roomy, plenty, plenty, false)
		if err != nil {
			t.Fatalf("upload against an undisclosed issue: %v", err)
		}

		// Somebody who may read the public issue may read its file.
		if _, err := f.store.Find(ctx, reader, public.Token); err != nil {
			t.Errorf("a reader could not reach a public issue's file: %v", err)
		}
		// And may not read the undisclosed one's — with the same answer as a
		// file that is not there, so the refusal says nothing about it.
		_, err = f.store.Find(ctx, reader, hidden.Token)
		if err == nil {
			t.Fatal("a public reader reached an undisclosed issue's file")
		}
		_, missing := f.store.Find(ctx, reader, strings.Repeat("0", 32))
		if err.Error() != missing.Error() {
			t.Errorf("a file they may not see answers %q and one that is not there %q;"+
				" the two have to be the same", err, missing)
		}
		// Whoever may see undisclosed work reaches it.
		if _, err := f.store.Find(ctx, trusted, hidden.Token); err != nil {
			t.Errorf("somebody who may see undisclosed work could not: %v", err)
		}
	})
}

func TestAnEmbargoEndingCarriesTheFileWithTheWords(t *testing.T) {
	// The reason visibility is derived and never stored. A copy taken at
	// upload would say "private" forever, describing a moment that has passed.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		undisclosed := f.anIssue(t, "CVE-2026-9002", access.Private)
		trusted := f.who(t, access.PublicTriage, access.PrivateTriage)
		reader := f.who(t, access.PublicRead)

		stored, err := f.store.Upload(ctx, trusted, attach.Against{ProductID: f.product, VulnerabilityID: undisclosed}, "evidence.log",
			strings.NewReader("embargoed"), 9, roomy, plenty, plenty, false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Find(ctx, reader, stored.Token); err == nil {
			t.Fatal("an undisclosed issue's file was readable before the embargo ended")
		}

		// The embargo ends: the findings become public, and nothing about the
		// attachment is touched.
		if _, err := f.db.DB.NewUpdate().Model((*finding.Finding)(nil)).
			Set("visibility = ?", access.Public).
			Where("vulnerability_id = ?", undisclosed).Exec(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Find(ctx, reader, stored.Token); err != nil {
			t.Errorf("the file did not become readable when its issue did: %v", err)
		}
	})
}

func TestRedactionTakesTheBytesAndLeavesTheRecord(t *testing.T) {
	// Somebody will attach a credential, and the answer to that cannot be
	// a hole in the record: the text that pointed at the file goes on
	// pointing at something, and that something says what happened.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.who(t, access.PublicTriage)
		stored := f.upload(t, who, "oops.txt", []byte("AKIAIOSFODNN7EXAMPLE"))

		// Not something whoever uploaded it can do quietly.
		if err := f.store.Redact(ctx, who, stored.Token, "a credential"); err == nil {
			t.Error("somebody who is not an administrator redacted a file")
		}
		// And not without saying why.
		if err := f.store.Redact(ctx, f.admin(t), stored.Token, "   "); err == nil {
			t.Error("a file was removed with no reason given")
		}
		if err := f.store.Redact(ctx, f.admin(t), stored.Token, "a credential"); err != nil {
			t.Fatalf("redact: %v", err)
		}

		row, err := f.store.Find(ctx, who, stored.Token)
		if err != nil {
			t.Fatalf("the record went with the bytes: %v", err)
		}
		if !row.Redacted() || row.RedactedReason == nil || *row.RedactedReason != "a credential" {
			t.Errorf("the record does not say what happened: %+v", row)
		}
		if _, _, _, err := f.store.Fetch(ctx, who, stored.Token, time.Minute); err == nil {
			t.Error("the bytes came back after a redaction")
		}
		// And the file itself is gone from the store, not merely hidden.
		if _, err := f.files.Open(ctx, row.ObjectKey); err == nil {
			t.Error("the bytes are still in the store")
		}
	})
}

func TestUploadsNothingRefersToAreCollected(t *testing.T) {
	// Somebody drags a file in and closes the tab.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.who(t, access.PublicTriage)
		abandoned := f.upload(t, who, "abandoned.log", []byte("nothing points here"))
		referred := f.upload(t, who, "referred.log", []byte("something points here"))

		// Text naming one of them is saved.
		if err := attach.Attached(ctx, f.db.DB, []string{referred.Token}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		// Both are made old enough to be looked at.
		if _, err := f.db.DB.NewUpdate().Model((*attach.Attachment)(nil)).
			Set("uploaded_at = ?", time.Now().UTC().Add(-48*time.Hour)).
			Where("1 = 1").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		gone, err := f.store.Sweep(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if gone != 1 {
			t.Errorf("the sweep took %d files, want the one nothing refers to", gone)
		}
		if _, err := f.store.Find(ctx, who, referred.Token); err != nil {
			t.Errorf("the sweep took a file text refers to: %v", err)
		}
		if _, err := f.store.Find(ctx, who, abandoned.Token); err == nil {
			t.Error("the sweep left an upload nothing refers to")
		}
	})
}

func TestAnUploadTooBigOrWithNoRoomIsRefused(t *testing.T) {
	// Storage somebody else fills on our behalf needs a ceiling, and the
	// two limits answer different questions.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.who(t, access.PublicTriage)
		body := strings.Repeat("x", 4096)

		_, err := f.store.Upload(ctx, who, attach.Against{ProductID: f.product, VulnerabilityID: f.issue}, "big.log",
			strings.NewReader(body), int64(len(body)), 1024, plenty, plenty, false)
		if err != attach.ErrTooLarge {
			t.Errorf("a file over the limit answered %v, want it named as too large", err)
		}
		_, err = f.store.Upload(ctx, who, attach.Against{ProductID: f.product, VulnerabilityID: f.issue}, "big.log",
			strings.NewReader(body), int64(len(body)), roomy, 1024, plenty, false)
		if err != attach.ErrNoRoom {
			t.Errorf("an upload with no room answered %v, want it named as full", err)
		}
		// And the refused bytes are not sitting in the store.
		entries, err := os.ReadDir(f.root)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("a refused upload left %d entries behind", len(entries))
		}
	})
}

func TestADeploymentWithNoStoreHoldsNothingAndSaysSo(t *testing.T) {
	// An operator who wants no object store should not have to run one,
	// and everything else has to work.
	each(t, func(t *testing.T, f *fixture) {
		none := attach.NewStore(f.db.DB, nil)
		if none.Configured() {
			t.Fatal("a store with nowhere to put anything reports itself configured")
		}
		_, err := none.Upload(t.Context(), f.who(t, access.PublicTriage),
			attach.Against{ProductID: f.product, VulnerabilityID: f.issue},
			"x.log", strings.NewReader("x"), 1, roomy, plenty, plenty, false)
		if err != attach.ErrNotConfigured {
			t.Errorf("uploading with no store answered %v", err)
		}
		// Listing answers empty rather than failing, so a screen renders.
		rows, err := none.ForIssue(t.Context(), f.who(t, access.PublicRead), f.product, f.issue)
		if err != nil || len(rows) != 0 {
			t.Errorf("listing with no store answered %v, %v", rows, err)
		}
	})
}

func TestAKeyNeverComesFromWhatSomebodyTyped(t *testing.T) {
	// The name is used for a header and nothing else; where the bytes
	// go is ours.
	each(t, func(t *testing.T, f *fixture) {
		who := f.who(t, access.PublicTriage)
		stored := f.upload(t, who, "../../etc/passwd", []byte("root:x:0:0"))
		if strings.Contains(stored.ObjectKey, "..") {
			t.Errorf("the object key carries what was typed: %q", stored.ObjectKey)
		}
		if strings.Contains(stored.Filename, "/") || strings.Contains(stored.Filename, "..") {
			t.Errorf("the filename kept a path in it: %q", stored.Filename)
		}
		if strings.Contains(attach.Disposition(stored), `"`+"\n") {
			t.Errorf("the disposition can be broken out of: %q", attach.Disposition(stored))
		}
	})
}

// Attaching is triage work, and a share of the store is one person's.
//
// It was authorized with the read test, so a role granting nothing but the
// ability to read disclosed findings on one product could write files into
// the deployment's store — and what filling it costs is not the uploader's,
// it is every other upload in every product afterwards. Nothing bounded any
// one person's part of the total either.
func TestReadingIsNotAttachingAndAShareIsOnePersons(t *testing.T) {
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		body := strings.Repeat("x", 512)

		reader := f.who(t, access.PublicRead)
		if _, err := f.store.Upload(ctx, reader, attach.Against{ProductID: f.product, VulnerabilityID: f.issue}, "theirs.log",
			strings.NewReader(body), int64(len(body)), roomy, plenty, plenty,
			false); err == nil {
			t.Error("somebody who may only read wrote a file into the store")
		}

		// A collaborator brought onto this issue may still attach: evidence
		// is usually why they were brought in.
		person, err := access.NewStore(f.db.DB).Ensure(ctx, "guest@example.com", "Guest", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		guest := access.NewPerson(person.ID, person.Identity, false, nil, 0).
			OnCases(map[int64][]int64{f.product: {f.issue}})
		if _, err := f.store.Upload(ctx, guest, attach.Against{ProductID: f.product, VulnerabilityID: f.issue}, "theirs.log",
			strings.NewReader(body), int64(len(body)), roomy, plenty, plenty,
			false); err != nil {
			t.Errorf("a collaborator on the case could not attach to it: %v", err)
		}

		// And one person's share bounds them, whatever room the deployment
		// has left in total.
		who := f.who(t, access.PublicTriage)
		if _, err := f.store.Upload(ctx, who, attach.Against{ProductID: f.product, VulnerabilityID: f.issue}, "mine.log",
			strings.NewReader(body), int64(len(body)), roomy, plenty, 256,
			false); err != attach.ErrNoRoom {
			t.Errorf("an upload past one person's share answered %v, want it named as full", err)
		}
	})
}

func TestARecentUploadAndARedactedOneSurviveTheSweep(t *testing.T) {
	// The two predicates the sweep's own test cannot reach. It ages every row
	// past the window with one update, so "older than" is true of everything
	// in the fixture and there is never a redacted row at sweep time —
	// deleting either line leaves that test green.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.who(t, access.PublicTriage)

		// Somebody is still writing the justification the file belongs to.
		// The window is a grace period, not a formality: sweeping here takes
		// the file out from under its author mid-sentence.
		recent := f.upload(t, who, "still-writing.log", []byte("uploaded a moment ago"))

		// And a redacted row, which is a record of a removal rather than an
		// upload nobody referred to. Sweeping it loses the record of what was
		// taken and why.
		redacted := f.upload(t, who, "a-credential.log", []byte("removed on purpose"))
		if err := f.store.Redact(ctx, f.admin(t), redacted.Token, "a credential"); err != nil {
			t.Fatalf("redact: %v", err)
		}
		if _, err := f.db.DB.NewUpdate().Model((*attach.Attachment)(nil)).
			Set("uploaded_at = ?", time.Now().UTC().Add(-48*time.Hour)).
			Where("token = ?", redacted.Token).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		gone, err := f.store.Sweep(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if gone != 0 {
			t.Errorf("the sweep took %d file(s), and neither was its to take", gone)
		}
		if _, err := f.store.Find(ctx, who, recent.Token); err != nil {
			t.Errorf("an upload from a moment ago was swept: %v", err)
		}
		row, err := f.store.Find(ctx, who, redacted.Token)
		if err != nil {
			t.Fatalf("the record of a redaction was swept: %v", err)
		}
		if !row.Redacted() {
			t.Error("the row came back without its redaction")
		}
	})
}

func TestTheKeeperSweepsOnItsOwnAndIsNothingWhereNoFilesAreKept(t *testing.T) {
	// NewKeeper supplies both production defaults for the attachment sweep:
	// how long an upload is left, and how often the pass runs. Nothing else
	// reads either, so a test that drives Sweep directly says nothing about
	// what a deployment actually sweeps with.
	//
	// Nil where the deployment holds no files, which is the arm that keeps a
	// worker from being started for a feature nobody configured: a goroutine
	// and a log line an operator then has to work out the meaning of.
	if keeper := attach.NewKeeper(nil, nil, hush(), 0); keeper != nil {
		t.Error("a deployment that keeps no files was given a sweep to run")
	}

	each(t, func(t *testing.T, f *fixture) {
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		who := f.who(t, access.PublicTriage)
		abandoned := f.upload(t, who, "abandoned.log", []byte("nothing points here"))
		if _, err := f.db.DB.NewUpdate().Model((*attach.Attachment)(nil)).
			Set("uploaded_at = ?", time.Now().UTC().Add(-48*time.Hour)).
			Where("token = ?", abandoned.Token).Exec(ctx); err != nil {
			t.Fatal(err)
		}

		keeper := attach.NewKeeper(f.db.DB, f.files, hush(), 24*time.Hour)
		if keeper == nil {
			t.Fatal("a deployment that keeps files was given no sweep to run")
		}
		returned := make(chan struct{})
		go func() {
			defer close(returned)
			// Longer than this test runs for, so the first wake is what does
			// the work.
			keeper.Run(ctx, time.Hour)
		}()

		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := f.store.Find(ctx, who, abandoned.Token); err != nil {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if _, err := f.store.Find(ctx, who, abandoned.Token); err == nil {
			t.Error("the sweep ran and left an upload nothing refers to")
		}

		stop()
		select {
		case <-returned:
		case <-time.After(10 * time.Second):
			t.Fatal("the loop did not return when its context ended")
		}
	})
}

// hush is a logger that writes nothing, for the background pass.
func hush() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestAFileAttachedWhileTheSweepRunsKeepsItsBytes(t *testing.T) {
	// The guard ran after the loss it exists to prevent: the bytes were
	// unlinked, the delete then matched nothing because the file had just
	// been referred to, and the row stood pointing at bytes that were gone —
	// counted as a collection that happened.
	//
	// The window is not contrived: text naming an attachment is saved after
	// the transaction that wrote it, so a comment landing between the sweep's
	// page and its delete loop is the ordinary race.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		who := f.who(t, access.PublicTriage)
		racing := f.upload(t, who, "racing.log", []byte("text is about to point here"))
		if _, err := f.db.DB.NewUpdate().Model((*attach.Attachment)(nil)).
			Set("uploaded_at = ?", time.Now().UTC().Add(-48*time.Hour)).
			Where("1 = 1").Exec(ctx); err != nil {
			t.Fatal(err)
		}
		// Referred to between the sweep reading its page and acting on it,
		// which is the window rather than a moment either side of it.
		attach.AfterPage(f.store, func() {
			if err := attach.Attached(ctx, f.db.DB, []string{racing.Token}, time.Now().UTC()); err != nil {
				t.Error(err)
			}
		})

		gone, err := f.store.Sweep(ctx, 24*time.Hour)
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if gone != 0 {
			t.Errorf("the sweep reported collecting %d, and the file is referred to", gone)
		}
		// The record stands, and so do the bytes behind it.
		found, err := f.store.Find(ctx, who, racing.Token)
		if err != nil {
			t.Fatalf("the sweep took a file text refers to: %v", err)
		}
		// Asked of the store rather than through Fetch, which for a file
		// this size answers with an address and never opens anything — so a
		// record standing over bytes that are gone reads as a working fetch
		// until somebody follows the address.
		body, err := f.files.Open(ctx, found.ObjectKey)
		if err != nil {
			t.Fatalf("the record stands and its bytes are gone: %v", err)
		}
		_ = body.Close()
	})
}

func TestARowACollectionPassCouldNotClaimIsNamed(t *testing.T) {
	// The pass counted what it could not read and threw the error away, in
	// the one writer here that destroys somebody's data. Counted alone the
	// row is left standing with nothing naming it: the same number comes back
	// every pass, and nobody can tell whether it is one row stuck or a
	// different one each time, or what is wrong with it.
	each(t, func(t *testing.T, f *fixture) {
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		who := f.who(t, access.PublicTriage)
		stuck := f.upload(t, who, "stuck.log", []byte("nothing will ever point here"))
		if _, err := f.db.DB.NewUpdate().Model((*attach.Attachment)(nil)).
			Set("uploaded_at = ?", time.Now().UTC().Add(-48*time.Hour)).
			Where("1 = 1").Exec(ctx); err != nil {
			t.Fatal(err)
		}

		var said bytes.Buffer
		store := attach.NewStore(f.db.DB, f.files).
			Reporting(slog.New(slog.NewTextHandler(&said, nil)))
		// Taken away between the page and the loop, so the claim on a row the
		// pass has in hand is the statement that fails.
		attach.AfterPage(store, stop)

		if _, err := store.Sweep(ctx, 24*time.Hour); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		wrote := said.String()
		for _, want := range []string{stuck.ObjectKey, "stuck.log", "error="} {
			if !strings.Contains(wrote, want) {
				t.Errorf("a row the pass could not claim was reported without %q: %s",
					want, wrote)
			}
		}
	})
}

func TestALongNameIsShortenedBetweenCharacters(t *testing.T) {
	// The bound on a served and stored filename was a byte slice, so a name
	// whose hundred-and-twentieth byte falls inside a character was stored as
	// something three engines of four refuse — and the refusal lands on the
	// upload rather than on the name.
	for _, most := range []int{118, 119, 120, 121} {
		name := strings.Repeat("a", most-1) + strings.Repeat("é", 40) + ".log"
		got := attach.SafeName(name)
		if len(got) > 120 {
			t.Errorf("a name of %d bytes was kept at %d", most, len(got))
		}
		if !utf8.ValidString(got) {
			t.Errorf("a name cut at %d is not storable: %q", most, got)
		}
	}
}
