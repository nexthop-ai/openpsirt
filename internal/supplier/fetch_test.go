package supplier_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
)

// publisher is a supplier serving the three things a directory holds: a
// description of what they offer, a feed listing it, and the documents.
type publisher struct {
	server *httptest.Server
	// documents is what is served at each path, and stamped when the feed says
	// each was last released.
	documents map[string]string
	stamped   map[string]string
	// failing answers a status instead of a body at these paths, so a test can
	// tell a refusal about one document from a publisher having a bad day.
	failing map[string]int
	// linked names a digest file in a document's feed entry, by the
	// document's path.
	linked map[string]string
	asked  []string
	// override answers everything where a test needs a directory this
	// publisher would not serve. Set before the first request.
	override http.HandlerFunc
}

func serving(t *testing.T) *publisher {
	t.Helper()
	p := &publisher{
		documents: map[string]string{}, stamped: map[string]string{},
		failing: map[string]int{}, linked: map[string]string{},
	}
	// https, because the fetcher refuses anything else: what comes back is
	// read as a publisher's own judgment, and over plain http it is read as
	// whoever is between us and them.
	p.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.asked = append(p.asked, r.URL.Path)
		if p.override != nil {
			p.override(w, r)
			return
		}
		if code, refusing := p.failing[r.URL.Path]; refusing {
			http.Error(w, http.StatusText(code), code)
			return
		}
		switch r.URL.Path {
		case "/.well-known/csaf/provider-metadata.json":
			_, _ = fmt.Fprintf(w, `{"distributions":[{"rolie":{"feeds":[{"tlp_label":"WHITE","url":%q}]}}]}`,
				p.server.URL+"/feed.json")
		case "/feed.json":
			entries := make([]string, 0, len(p.documents))
			for path, stamp := range p.stamped {
				hash := ""
				if sum, named := p.linked[path]; named {
					hash = fmt.Sprintf(`,{"rel":"hash","href":%q}`, p.server.URL+sum)
				}
				entries = append(entries, fmt.Sprintf(
					`{"link":[{"rel":"self","href":%q}%s],"updated":%q,"content":{"type":"application/json","src":%q}}`,
					p.server.URL+path, hash, stamp, p.server.URL+path))
			}
			_, _ = fmt.Fprintf(w, `{"feed":{"id":"f","title":"t","entry":[%s]}}`,
				strings.Join(entries, ","))
		default:
			body, held := p.documents[r.URL.Path]
			if !held {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprint(w, body)
		}
	}))
	t.Cleanup(p.server.Close)
	return p
}

// described is where this publisher says what they offer.
func (p *publisher) described() string {
	return p.server.URL + "/.well-known/csaf/provider-metadata.json"
}

// publishes lists one document in the feed, stamped when it says.
func (p *publisher) publishes(path, stamp, body string) {
	p.documents[path] = body
	p.stamped[path] = stamp
}

// reaching is a client that talks to one host and nowhere else, which is the
// rule internal/outward enforces for real.
//
// A stand-in rather than the real guarded client, because that one refuses an
// address inside this network and a test server has no other kind. What it
// pins is what this package is responsible for: handing one client one host,
// so that a feed or a document served from anywhere else is refused rather
// than followed. The guard itself is internal/outward's to test.
//
// It trusts the certificate every test server here presents, which is one
// certificate for all of them — so a request refused in these tests is refused
// by the host pin and never by the handshake.
func (p *publisher) reaching() func(string) *http.Client {
	trusting := p.server.Client()
	return func(host string) *http.Client {
		return &http.Client{
			Transport: pinned{host: host, inner: trusting.Transport},
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				return fmt.Errorf("refused a redirect to %s", req.URL.Host)
			},
		}
	}
}

type pinned struct {
	host  string
	inner http.RoundTripper
}

func (p pinned) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.EqualFold(req.URL.Hostname(), p.host) {
		return nil, fmt.Errorf("refused a request to %s: not a configured provider host",
			req.URL.Hostname())
	}
	return p.inner.RoundTrip(req)
}

// advisory is one CSAF security advisory about a package at a version.
func advisory(identifier, component, version, issue string) string {
	return fmt.Sprintf(`{
	  "document": {
	    "category": "csaf_security_advisory",
	    "csaf_version": "2.0",
	    "publisher": {"category":"vendor","name":"Example Linux","namespace":"https://supplier.example"},
	    "title": "%[2]s update",
	    "tracking": {"id": %[1]q, "current_release_date":"2026-09-20T00:00:00Z",
	                 "initial_release_date":"2026-09-20T00:00:00Z","status":"final","version":"1"}
	  },
	  "product_tree": {"branches":[{"category":"vendor","name":"Example Linux","branches":[
	    {"category":"product_name","name":%[2]q,"branches":[
	      {"category":"product_version","name":%[3]q,
	       "product":{"name":"%[2]s %[3]s","product_id":"p1",
	                  "product_identification_helper":{"purl":"pkg:deb/debian/%[2]s@%[3]s"}}}]}]}]},
	  "vulnerabilities": [{"cve": %[4]q,
	    "product_status": {"fixed": ["p1"]},
	    "notes": [{"category":"description","text":"Fixed in %[3]s."}]}]
	}`, identifier, component, version, issue)
}

// twoPackages is one advisory naming two packages at one issue, which is the
// ordinary shape: a distribution fixes a source package and ships several
// binaries of it.
func twoPackages(identifier, first, second, issue string) string {
	return fmt.Sprintf(`{
	  "document": {
	    "category": "csaf_security_advisory",
	    "csaf_version": "2.0",
	    "publisher": {"category":"vendor","name":"Example Linux","namespace":"https://supplier.example"},
	    "title": "update",
	    "tracking": {"id": %[1]q, "current_release_date":"2026-09-20T00:00:00Z",
	                 "initial_release_date":"2026-09-20T00:00:00Z","status":"final","version":"1"}
	  },
	  "product_tree": {"branches":[{"category":"vendor","name":"Example Linux","branches":[
	    {"category":"product_name","name":%[2]q,"branches":[
	      {"category":"product_version","name":"3.7.1",
	       "product":{"name":"%[2]s","product_id":"p1",
	                  "product_identification_helper":{"purl":"pkg:deb/debian/%[2]s@3.7.1"}}}]},
	    {"category":"product_name","name":%[3]q,"branches":[
	      {"category":"product_version","name":"3.7.1",
	       "product":{"name":"%[3]s","product_id":"p2",
	                  "product_identification_helper":{"purl":"pkg:deb/debian/%[3]s@3.7.1"}}}]}]}]},
	  "vulnerabilities": [{"cve": %[4]q,
	    "product_status": {"fixed": ["p1","p2"]},
	    "notes": [{"category":"description","text":"Fixed in 3.7.1."}]}]
	}`, identifier, first, second, issue)
}

// vexDocument is a publisher's statement set, which belongs in the same feed
// and is not this path's to read.
const vexDocument = `{
  "document": {
    "category": "csaf_vex", "csaf_version": "2.0",
    "publisher": {"category":"vendor","name":"Example Linux","namespace":"https://supplier.example"},
    "title": "Statement set",
    "tracking": {"id":"EL-VEX-1","current_release_date":"2026-09-20T00:00:00Z",
                 "initial_release_date":"2026-09-20T00:00:00Z","status":"final","version":"1"}
  },
  "product_tree": {"branches":[{"category":"product_name","name":"libnl-3-200","branches":[
    {"category":"product_version","name":"3.7.0",
     "product":{"name":"libnl","product_id":"p1",
                "product_identification_helper":{"purl":"pkg:deb/debian/libnl-3-200@3.7.0"}}}]}]},
  "vulnerabilities": [{"cve":"CVE-2026-4444","product_status":{"known_not_affected":["p1"]}}]
}`

// ships is a product holding two components, which is what a claim has to name
// to be recorded.
type ships struct {
	db      *database.DB
	product int64
	target  int64
	by      access.Subject
}

func shipping(t *testing.T, fn func(t *testing.T, f *ships)) {
	t.Helper()
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)

		cat := catalog.NewStore(db.DB)
		product, err := cat.DeclareProduct(ctx, "sonic", "SONiC")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareStream(ctx, product.ID, "master", catalog.Branch, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := cat.DeclareVariant(ctx, product.ID, "broadcom", true); err != nil {
			t.Fatal(err)
		}
		target, err := cat.Resolve(ctx, "sonic", "master", "broadcom")
		if err != nil {
			t.Fatal(err)
		}
		scan, outcome, err := ingest.NewStore(db.DB).Record(ctx, ingest.Arriving{
			TargetID: target.ID, ContentHash: "hash-1",
			BuiltAt: time.Now().UTC().Add(-time.Hour), ParserVersion: "test",
		})
		if err != nil || outcome != ingest.Accept {
			t.Fatalf("record scan: %v %v", outcome, err)
		}
		root := graph.Described{Purl: "pkg:deb/debian/sonic@1.0", Name: "sonic", Version: "1.0"}
		held := graph.Described{
			Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0",
		}
		if _, err := graph.NewStore(db.DB).Apply(ctx, target.ID, scan.ID, graph.Snapshot{
			Root: root, Components: []graph.Described{held},
			Dependencies: []graph.Dependency{{Parent: root, Child: held}},
		}); err != nil {
			t.Fatal(err)
		}
		who, err := access.NewStore(db.DB).Ensure(ctx, "ana@example.com", "Ana",
			access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		fn(t, &ships{db: db, product: product.ID, target: target.ID, by: access.Subject{
			Kind: access.Person, ID: who.ID, Identity: who.Email, Admin: true,
		}})
	})
}

// reported leaves one finding open at a component this product ships, the way
// a scan does, and answers which row it is.
func (f *ships) reported(t *testing.T, issue, component, version string) int64 {
	t.Helper()
	ctx := t.Context()
	store := finding.NewStore(f.db.DB)
	run, err := store.Begin(ctx, finding.Run{
		TargetID: f.target, Scanner: "test",
		ScannerVersion: "0", DatabaseVersion: "0", RanHere: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Apply(ctx, f.target, run.ID, []finding.Reported{{
		Issue: finding.Named{Identifier: issue, Severity: "high"},
		Component: graph.Described{
			Purl: "pkg:deb/debian/" + component + "@" + version,
			Name: component, Version: version,
		},
		FixState: finding.NoFix,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(ctx, run.ID, "0", "0", "", nil); err != nil {
		t.Fatal(err)
	}
	var id int64
	if err := f.db.DB.NewSelect().Model((*finding.Finding)(nil)).
		ColumnExpr("f.id").Where("f.target_id = ?", f.target).
		Limit(1).Scan(ctx, &id); err != nil {
		t.Fatal(err)
	}
	return id
}

// fetching is a fetcher pointed at one publisher, with the politeness pause
// taken off so a test does not spend real seconds on it.
func fetching(t *testing.T, f *ships, p *publisher) *supplier.Fetcher {
	t.Helper()
	fetch := supplier.NewFetcher(f.db.DB, sbom.Limits{})
	fetch.Client = p.reaching()
	fetch.Pause = 0
	return fetch
}

// long ago is where a test's source starts reading from, so that documents
// dated in these tests are ahead of it.
var long = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// from is the source row for one publisher.
func from(t *testing.T, f *ships, p *publisher) supplier.Source {
	t.Helper()
	row, err := supplier.NewStore(f.db.DB).Add(t.Context(), f.by, f.product, "Example Linux",
		p.described())
	if err != nil {
		t.Fatal(err)
	}
	// A supplier reads from the moment it was configured, and every document
	// in these tests carries a date of its own. Wound back so those dates are
	// after the mark, which is what a supplier configured before a publication
	// looks like.
	row.CaughtUpTo = &long
	row.CaughtUpMark = ""
	row.CreatedAt = long
	return *row
}

func TestAnAdvisoryAboutSomethingThisProductShipsIsRecordedAsEvidence(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-1.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0001", "libnl-3-200", "3.7.1", "CVE-2026-1111"))

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 1 || took.Recorded != 1 {
			t.Fatalf("the pass read %d documents and recorded %d claims", took.Documents, took.Recorded)
		}

		said, err := finding.NewStore(f.db.DB).SaidAbout(ctx,
			access.Everything("the test"), f.product, 0,
			[]string{"CVE-2026-1111"}, "libnl-3-200", "pkg:deb/debian/libnl-3-200@3.7.0")
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 1 {
			t.Fatalf("what the publisher said reads as %+v", said)
		}
		if said[0].Status != "fixed" || said[0].About != "3.7.1" {
			t.Errorf("the claim reads as %q at %q", said[0].Status, said[0].About)
		}
		// Recorded as the document it came from, which for a fetched one is
		// the address rather than a file name a client chose.
		if said[0].Document != p.server.URL+"/2026/EL-1.json" {
			t.Errorf("it is recorded as having arrived as %q", said[0].Document)
		}
		if said[0].Identifier != "EL-2026-0001" {
			t.Errorf("it is recorded under %q", said[0].Identifier)
		}
	})
}

func TestWhatAPublisherSaysIsFixedDecidesNothingHere(t *testing.T) {
	// A third party's judgment is evidence and a prefill, never a decision
	// (REQ-31). A pass on a timer makes that easier to violate by accident than
	// an upload does, because nobody is watching each document arrive — so this
	// asks the one question that would show it: a publisher announcing a fix
	// must not close, suppress or re-state the finding at that place.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		open := f.reported(t, "CVE-2026-1111", "libnl-3-200", "3.7.0")

		p := serving(t)
		p.publishes("/2026/EL-11.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0011", "libnl-3-200", "3.7.1", "CVE-2026-1111"))
		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Recorded != 1 {
			t.Fatalf("the claim was not recorded at all, so this asks nothing: %+v", took)
		}

		var after finding.Finding
		if err := f.db.DB.NewSelect().Model(&after).
			Where("id = ?", open).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if after.ClosedAt != nil {
			t.Errorf("a publisher's fix closed the finding at %v", after.ClosedAt)
		}
		if after.SuppressedBy != nil {
			t.Errorf("a publisher's fix suppressed the finding")
		}
		// The finding's own fix state is still what the scan reported. A
		// publisher naming the version that carries the fix is a claim about
		// their product, and writing it here would make it ours.
		if after.FixState != finding.NoFix || after.FixedIn != "" {
			t.Errorf("a publisher's version reached the finding's own fix state: %q at %q",
				after.FixState, after.FixedIn)
		}
	})
}

func TestAnAdvisoryAboutNothingThisProductShipsIsNotRecorded(t *testing.T) {
	// A publisher's feed is about their whole catalog. One real advisory about
	// a kernel carries 95,139 claims, so a deployment taking them whole would
	// store a supplier's catalog rather than evidence about its own.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-2.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0002", "some-other-package", "9.9.9", "CVE-2026-2222"))

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Recorded != 0 {
			t.Fatalf("%d claims about something nothing ships were recorded", took.Recorded)
		}
		var held int
		if held, err = f.db.DB.NewSelect().Model((*finding.Statement)(nil)).Count(ctx); err != nil {
			t.Fatal(err)
		}
		if held != 0 {
			t.Errorf("%d claims are stored", held)
		}
	})
}

func TestAVexDocumentInAPublishersFeedIsLeftAlone(t *testing.T) {
	// A statement set replaces a publisher's whole answer for a product.
	// Setting that aside is a judgment, and a pass on a timer makes none.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-VEX-1.json", "2026-09-20T00:00:00Z", vexDocument)
		p.publishes("/2026/EL-3.json", "2026-09-21T00:00:00Z",
			advisory("EL-2026-0003", "libnl-3-200", "3.7.1", "CVE-2026-3333"))

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Skipped != 1 {
			t.Errorf("%d documents were left alone, want the one statement set", took.Skipped)
		}
		// And the advisory beside it was still read: a statement set in the
		// feed is stepped over rather than stopping the pass.
		if took.Documents != 1 || took.Recorded != 1 {
			t.Errorf("the pass read %d documents and recorded %d claims",
				took.Documents, took.Recorded)
		}
		said, err := finding.NewStore(f.db.DB).SaidAbout(ctx,
			access.Everything("the test"), f.product, 0,
			[]string{"CVE-2026-4444"}, "libnl-3-200", "pkg:deb/debian/libnl-3-200@3.7.0")
		if err != nil {
			t.Fatal(err)
		}
		if len(said) != 0 {
			t.Errorf("the statement set was taken: %+v", said)
		}
	})
}

func TestADocumentServedFromAnotherHostIsRefusedRatherThanFetched(t *testing.T) {
	// The addresses inside a publisher's directory come from outside. Fetching
	// whatever they name is the request-forgery primitive the guarded client
	// exists to refuse, and this pins the half this package is responsible
	// for: one client, one host, so a document the publisher's own feed points
	// somewhere else is never reached.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.override = func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/.well-known/csaf/provider-metadata.json" {
				_, _ = fmt.Fprintf(w, `{"distributions":[{"rolie":{"feeds":[{"tlp_label":"WHITE","url":%q}]}}]}`,
					p.server.URL+"/feed.json")
				return
			}
			// The shape of the attack: a publisher's own document telling us
			// to fetch somewhere else.
			const elsewhere = "https://elsewhere.example/2026/EL-4.json"
			_, _ = fmt.Fprintf(w, `{"feed":{"id":"f","title":"t","entry":[
				{"link":[{"rel":"self","href":%q}],"updated":"2026-09-20T00:00:00Z",
				 "content":{"type":"application/json","src":%q}}]}}`, elsewhere, elsewhere)
		}

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err == nil {
			t.Fatal("a document on another host was fetched")
		}
		// The reason matters rather than the failure: without the pin this
		// request goes on to fail at DNS, which would let the test pass while
		// the rule it names does nothing.
		if !strings.Contains(err.Error(), "not a configured provider host") {
			t.Errorf("it was refused for the wrong reason: %v", err)
		}
		if took.Recorded != 0 {
			t.Errorf("%d claims were recorded from it", took.Recorded)
		}
	})
}

func TestTheFetcherAsBuiltWillNotReachInsideThisNetwork(t *testing.T) {
	// Every other test here replaces the client with a pinned stand-in, so
	// none of them touches the wiring a deployment actually runs: swapping the
	// guarded client for an ordinary one leaves them all green. This one
	// drives the fetcher as NewFetcher builds it.
	//
	// A test server is on loopback, which is exactly what the guard refuses —
	// so the refusal is the assertion, and the reason is checked rather than
	// the failure, because an unguarded client fails here too, on the
	// certificate.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)

		fetch := supplier.NewFetcher(f.db.DB, sbom.Limits{})
		fetch.Pause = 0
		_, err := fetch.From(ctx, f.by, from(t, f, p))
		if err == nil {
			t.Fatal("the fetcher reached a server inside this network")
		}
		if !strings.Contains(err.Error(), "not reached inside this network") {
			t.Errorf("it was refused for the wrong reason: %v", err)
		}
	})
}

func TestOnlyWhatThePublisherStampedAfterTheMarkIsRead(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		p.publishes("/2026/EL-5.json", "2026-09-20T00:00:00Z",
			advisory("EL-2026-0005", "libnl-3-200", "3.7.1", "CVE-2026-6666"))
		p.publishes("/2026/EL-6.json", "2026-09-22T00:00:00Z",
			advisory("EL-2026-0006", "libnl-3-200", "3.7.2", "CVE-2026-7777"))

		source := from(t, f, p)
		at := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
		source.CaughtUpTo = &at

		took, err := fetching(t, f, p).From(ctx, f.by, source)
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != 1 {
			t.Fatalf("%d documents were read, want the one stamped after the mark", took.Documents)
		}
		if !took.CaughtUpTo.Equal(time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)) {
			t.Errorf("the mark reached %v", took.CaughtUpTo)
		}
		for _, path := range p.asked {
			if path == "/2026/EL-5.json" {
				t.Error("a document stamped before the mark was fetched")
			}
		}
	})
}

func TestAPublishersBacklogIsBoundedPerCycle(t *testing.T) {
	// A publisher having a busy week is not a reason to make a hundred
	// requests of them in a minute. What is not taken this cycle is taken
	// next, because the mark only moves past what was read.
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		day := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		for i := range supplier.MostPerPass + 5 {
			p.publishes(fmt.Sprintf("/2026/EL-%d.json", i),
				day.AddDate(0, 0, i).Format(time.RFC3339),
				advisory(fmt.Sprintf("EL-2026-%04d", i), "libnl-3-200", "3.7.1",
					fmt.Sprintf("CVE-2026-%04d", 8000+i)))
		}

		took, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err != nil {
			t.Fatal(err)
		}
		if took.Documents != supplier.MostPerPass {
			t.Fatalf("%d documents were read in one cycle, want %d",
				took.Documents, supplier.MostPerPass)
		}
		// Oldest first, so the mark lands where the reading stopped rather
		// than past everything the cycle did not reach.
		want := day.AddDate(0, 0, supplier.MostPerPass-1)
		if !took.CaughtUpTo.Equal(want) {
			t.Errorf("the mark reached %v, want %v", took.CaughtUpTo, want)
		}
	})
}

func TestAPublisherWhoseDirectoryNamesNothingIsReportedRatherThanSilent(t *testing.T) {
	shipping(t, func(t *testing.T, f *ships) {
		ctx := t.Context()
		p := serving(t)
		// Neither shape: no ROLIE feed and no directory of documents. A
		// publisher offering nothing readable is a fault an operator has to be
		// told about, not an empty answer.
		p.override = func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprint(w, `{"distributions":[{}]}`)
		}

		_, err := fetching(t, f, p).From(ctx, f.by, from(t, f, p))
		if err == nil {
			t.Fatal("a directory naming nothing was read as empty")
		}
		if !strings.Contains(err.Error(), "names nothing to read") {
			t.Errorf("it was reported as %v", err)
		}
	})
}
