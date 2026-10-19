// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/published"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
	"github.com/nexthop-ai/openpsirt/internal/signing"
	"github.com/nexthop-ai/openpsirt/internal/triage"
	"github.com/nexthop-ai/openpsirt/internal/upstream"
)

// The components the upstream's build and the fork's build ship.
var (
	openssl     = graph.Described{Purl: "pkg:deb/debian/openssl@3.0.11-1", Name: "openssl", Version: "3.0.11-1"}
	opensslNext = graph.Described{Purl: "pkg:deb/debian/openssl@3.0.11-2", Name: "openssl", Version: "3.0.11-2"}
	libnl       = graph.Described{Purl: "pkg:deb/debian/libnl-3-200@3.7.0", Name: "libnl-3-200", Version: "3.7.0"}
	swss        = graph.Described{Purl: "pkg:deb/sonic/swss@1.0.0", Name: "swss", Version: "1.0.0"}
	sonicRoot   = graph.Described{Purl: "pkg:generic/sonic@master.42", Name: "sonic", Version: "master.42"}
	forkRoot    = graph.Described{Purl: "pkg:generic/fork-os@1.0", Name: "fork-os", Version: "1.0"}
	forkNext    = graph.Described{Purl: "pkg:generic/fork-os@2.0", Name: "fork-os", Version: "2.0"}
)

// The two issues the upstream decided: one whose reason holds for anybody
// shipping the component, and one whose reason is its own build's.
const (
	portable = "CVE-2026-1001"
	ownBuild = "CVE-2026-1002"
)

// world is two products in one deployment: the upstream, publishing what it
// decided, and a fork that trusts it and reads it over the network.
type world struct {
	*fixture.World
	t         *testing.T
	findings  *finding.Store
	decisions *triage.Store
	built     time.Time
	proposer  access.Subject
	approver  access.Subject
	server    *served
	fork      *catalog.Product
	// forkBuild ships the upstream's openssl, and forkLater a later one.
	forkBuild *catalog.Target
	forkLater *catalog.Target
	admin     access.Subject
	reader    *upstream.Reader
}

// newWorld seeds the upstream deciding both issues and publishing, signed,
// and a fork shipping the same components in two builds, one of them at a
// later openssl, with both issues reported.
func newWorld(t *testing.T, f *fixture.World) *world {
	t.Helper()
	w := bare(t, f)
	w.ship(w.Target, sonicRoot, sonicRoot, openssl, sonicRoot, swss, swss, libnl)
	w.report(w.Target, portable, openssl, ownBuild, libnl)
	w.decide(w.Target, portable, openssl.Name, triage.CodeNotPresent)
	w.decide(w.Target, ownBuild, libnl.Name, triage.CodeNotInExecutePath)
	if err := w.Catalog.SetPublishes(t.Context(), w.Product.ID, true); err != nil {
		t.Fatal(err)
	}
	w.write()

	w.ship(w.forkBuild, forkRoot, forkRoot, openssl, forkRoot, swss, swss, libnl)
	w.ship(w.forkLater, forkNext, forkNext, opensslNext, forkNext, swss, swss, libnl)
	w.rescan()
	return w
}

// bare is the two products, the people, the fork's two builds declared and
// nothing shipped, and the upstream's surface standing.
func bare(t *testing.T, f *fixture.World) *world {
	t.Helper()
	db := f.DB.DB
	w := &world{
		World: f, t: t, findings: finding.NewStore(db), decisions: triage.NewStore(db),
		built: time.Now().UTC().Add(-48 * time.Hour),
	}
	w.fork = w.DeclareProduct("fork-os", "Fork OS")
	roles := map[int64][]access.Role{}
	for _, id := range []int64{w.Product.ID, w.fork.ID} {
		roles[id] = []access.Role{access.PublicRead, access.PublicTriage, access.Approver}
	}
	person := func(identity string, admin bool) access.Subject {
		account, err := w.Access.Ensure(t.Context(), identity, identity, new(admin), nil)
		if err != nil {
			t.Fatal(err)
		}
		return access.NewPerson(account.ID, identity, admin, roles, 0)
	}
	w.proposer, w.approver = person("ana@example.com", false), person("ben@example.com", false)
	w.admin = person("root@example.com", true)
	w.server = serve(t, w)
	w.forkBuild = w.TargetFor(w.DeclareStream(w.fork, "main", catalog.Branch, nil),
		w.DeclareVariant(w.fork, "x86", true))
	w.forkLater = w.TargetFor(w.DeclareStream(w.fork, "next", catalog.Branch, nil),
		w.DeclareVariant(w.fork, "arm", true))
	w.reader = upstream.NewReader(db, sbom.Limits{}, w.server.roots)
	return w
}

// ship records a scan of a build: its root and the edges beneath it, given as
// parent and child in turn.
func (w *world) ship(target *catalog.Target, root graph.Described, edges ...graph.Described) {
	w.t.Helper()
	ctx := w.t.Context()
	w.built = w.built.Add(time.Minute)
	scan, outcome, err := ingest.NewStore(w.DB.DB).Record(ctx, ingest.Arriving{
		TargetID: target.ID, ContentHash: "hash-" + w.built.Format(time.RFC3339Nano),
		BuiltAt: w.built, ParserVersion: "test",
	})
	if err != nil || outcome != ingest.Accept {
		w.t.Fatalf("record a scan: %v %v", outcome, err)
	}
	snap := graph.Snapshot{Root: root}
	seen := map[string]bool{}
	for i := 0; i+1 < len(edges); i += 2 {
		for _, part := range edges[i : i+2] {
			if part != root && !seen[part.Purl] {
				seen[part.Purl] = true
				snap.Components = append(snap.Components, part)
			}
		}
		snap.Dependencies = append(snap.Dependencies, graph.Dependency{Parent: edges[i], Child: edges[i+1]})
	}
	if _, err := fixture.ApplyGraph(ctx, w.DB.DB, target.ID, scan.ID, snap); err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.DB.DB.NewUpdate().TableExpr(`"scan"`).Set(`"root_identifier" = ?`, root.Purl).
		Where(`"id" = ?`, scan.ID).Exec(ctx); err != nil {
		w.t.Fatal(err)
	}
}

// report runs a scanner over a build, reporting these issues at these
// components, given as issue and component in turn.
func (w *world) report(target *catalog.Target, found ...any) {
	w.t.Helper()
	ctx := w.t.Context()
	run, err := w.findings.Begin(ctx, finding.Run{TargetID: target.ID, Scanner: "grype", RanHere: true})
	if err != nil {
		w.t.Fatal(err)
	}
	var rows []finding.Reported
	for i := 0; i+1 < len(found); i += 2 {
		rows = append(rows, finding.Reported{
			Issue:     finding.Named{Identifier: found[i].(string), Severity: "high"},
			Component: found[i+1].(graph.Described),
		})
	}
	if _, err := w.findings.Apply(ctx, target.ID, run.ID, rows); err != nil {
		w.t.Fatal(err)
	}
}

// rescan runs the scanner over both of the fork's builds, reporting both
// issues at what each ships, which is when what the upstream says is applied.
func (w *world) rescan() {
	w.t.Helper()
	w.report(w.forkBuild, portable, openssl, ownBuild, libnl)
	w.report(w.forkLater, portable, opensslNext, ownBuild, libnl)
}

// decide records an approved claim of not applicable, for the reason given,
// at every open place of an issue in one component of a build.
func (w *world) decide(target *catalog.Target, issue, component string, why triage.Justification) {
	w.t.Helper()
	w.claim(target, issue, component, triage.NotApplicable, why)
}

// claim records one claim at every open place of an issue in one component of
// a build, agreed by the second person where it needs one.
func (w *world) claim(target *catalog.Target, issue, component string, outcome triage.Outcome,
	why triage.Justification) {

	w.t.Helper()
	w.claimCiting(target, issue, component, outcome, why, nil)
}

// claimCiting is claim, started from the statement cited where one is.
func (w *world) claimCiting(target *catalog.Target, issue, component string, outcome triage.Outcome,
	why triage.Justification, cited *int64) {

	w.t.Helper()
	ctx := w.t.Context()
	vulnerability, err := finding.NewVulnerabilities(w.DB.DB).ByName(ctx, issue)
	if err != nil {
		w.t.Fatal(err)
	}
	var open []finding.Finding
	if err := w.DB.DB.NewSelect().Model(&open).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		Where(`"f"."target_id" = ?`, target.ID).
		Where(`"f"."vulnerability_id" = ?`, vulnerability).
		Where(`"c"."name" = ?`, component).
		Where(`"f"."closed_at" IS NULL`).
		Scan(ctx); err != nil || len(open) == 0 {
		w.t.Fatalf("%s is open at %d places of %s: %v", issue, len(open), component, err)
	}
	var proposals []triage.Proposal
	placed := map[string]bool{}
	for _, one := range open {
		if placed[one.PlaceIdentity] {
			continue
		}
		placed[one.PlaceIdentity] = true
		at, err := w.findings.PlaceFor(ctx, w.proposer, target.ID, vulnerability, one.PlaceIdentity)
		if err != nil {
			w.t.Fatal(err)
		}
		proposals = append(proposals, triage.Proposal{
			Place: triage.Place{
				ProductID: at.ProductID, VulnerabilityID: at.VulnerabilityID,
				PlaceIdentity: at.PlaceIdentity, Visibility: at.Visibility,
				ComponentUpstream: at.ComponentUpstream, ConsumerUpstream: at.ConsumerUpstream,
				OnTag: at.OnTag,
			},
			Outcome: outcome, Justification: why, FromStatement: cited,
			Reasoning: "Read the code.", By: w.proposer.ID, MadeOn: []int64{target.ID},
			BindingAcross: []int64{target.ID},
		})
	}
	recorded, err := w.decisions.ProposeMany(ctx, w.proposer, proposals)
	if err != nil {
		w.t.Fatal(err)
	}
	if recorded[0].NeedsApproval {
		if _, err := w.decisions.ApproveClaim(ctx, w.approver, recorded[0].ClaimID, "", nil, ""); err != nil {
			w.t.Fatal(err)
		}
	}
}

// write runs the upstream's publishing pass once.
func (w *world) write() {
	w.t.Helper()
	pass := publish.NewPass(w.DB.DB, publish.NewGenerator(w.DB.DB, w.server.who, w.server.base), "test",
		slog.New(slog.DiscardHandler))
	if _, err := pass.Once(w.t.Context()); err != nil {
		w.t.Fatal(err)
	}
}

// trust has the fork trust the upstream, confirming the key it names.
func (w *world) trust() *upstream.Upstream {
	w.t.Helper()
	address := w.server.base + publish.MetadataPath
	parsed, err := upstream.Address(address)
	if err != nil {
		w.t.Fatal(err)
	}
	described, err := upstream.Inspect(w.t.Context(), upstream.Client(parsed, w.server.roots), address)
	if err != nil {
		w.t.Fatal(err)
	}
	up, err := upstream.NewStore(w.DB.DB).Trust(w.t.Context(), w.admin, w.fork.ID, upstream.Trusting{
		URL: address, Publisher: described.Publisher,
		Fingerprint: described.Fingerprint, PublicKey: described.PublicKey,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return up
}

// read reads the fork's upstream once, as the pass would.
func (w *world) read() upstream.Read {
	w.t.Helper()
	up, err := upstream.NewStore(w.DB.DB).For(w.t.Context(), w.admin, w.fork.ID)
	if err != nil || up == nil {
		w.t.Fatalf("the fork trusts no upstream: %v", err)
	}
	took, err := w.reader.From(w.t.Context(), *up)
	if err != nil {
		w.t.Fatal(err)
	}
	return took
}

// at is how the latest row of an issue at a component of a build stands:
// whether it is open, why it closed, and the statement that closed it.
type at struct {
	open     bool
	because  string
	statedBy *int64
}

// state reads how an issue stands at a component of a build.
func (w *world) state(target *catalog.Target, issue string, component graph.Described) at {
	w.t.Helper()
	ctx := w.t.Context()
	vulnerability, err := finding.NewVulnerabilities(w.DB.DB).ByName(ctx, issue)
	if err != nil {
		w.t.Fatal(err)
	}
	var row struct {
		ClosedAt *time.Time `bun:"closed_at"`
		Because  string     `bun:"closed_because"`
		StatedBy *int64     `bun:"stated_by"`
	}
	if err := w.DB.DB.NewSelect().TableExpr(`"finding" AS "f"`).
		Join(`JOIN "component" AS "c" ON "c"."id" = "f"."component_id"`).
		ColumnExpr(`"f"."closed_at", COALESCE("f"."closed_because", '') AS "closed_because", "f"."stated_by"`).
		Where(`"f"."target_id" = ?`, target.ID).
		Where(`"f"."vulnerability_id" = ?`, vulnerability).
		Where(`"c"."purl" = ?`, component.Purl).
		OrderExpr(`"f"."id" DESC`).Limit(1).
		Scan(ctx, &row); err != nil {
		w.t.Fatalf("read how %s stands at %s: %v", issue, component.Name, err)
	}
	return at{open: row.ClosedAt == nil, because: row.Because, statedBy: row.StatedBy}
}

// statement is the fork's standing record of what the upstream says about an
// issue, at a placement, or nil where none stands.
func (w *world) statement(issue, placement string) *finding.Statement {
	w.t.Helper()
	var said []finding.Statement
	q := w.DB.DB.NewSelect().Model(&said).
		Where(`"ss"."product_id" = ?`, w.fork.ID).
		Where(`"ss"."source" = ?`, finding.FromUpstream).
		Where(`"ss"."vulnerability" = ?`, strings.ToLower(issue)).
		Where(`"ss"."superseded_at" IS NULL`)
	if placement == "" {
		q = q.Where(`"ss"."placement" IS NULL`)
	} else {
		q = q.Where(`"ss"."placement" = ?`, placement)
	}
	if err := q.Scan(w.t.Context()); err != nil {
		w.t.Fatal(err)
	}
	if len(said) == 0 {
		return nil
	}
	return &said[0]
}

// served is the upstream's published surface, over TLS, as another
// deployment reaches it, with a hand on what it answers.
type served struct {
	server *httptest.Server
	roots  *x509.CertPool
	base   string
	who    publisher.Named
	signer *signing.Signer
	// mu guards what the hand changes: a document's bytes, a file left out,
	// and what the provider description says about the key.
	mu      sync.Mutex
	tamper  map[string]func([]byte) []byte
	missing map[string]bool
	asked   []string
	// answered is each path asked for and the status it was answered with.
	answered map[string]int
}

// serve stands the upstream's surface up over TLS, signing with a key made
// for the test.
func serve(t *testing.T, w *world) *served {
	t.Helper()
	signer, err := signing.Read(testKey(t), "")
	if err != nil {
		t.Fatal(err)
	}
	s := &served{signer: signer, tamper: map[string]func([]byte) []byte{}, missing: map[string]bool{},
		answered: map[string]int{}}
	var handler http.Handler
	s.server = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		s.mu.Lock()
		s.asked = append(s.asked, req.URL.Path)
		missing, tamper := s.missing[req.URL.Path], s.tamper[req.URL.Path]
		s.mu.Unlock()
		if missing {
			http.NotFound(rw, req)
			return
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		s.mu.Lock()
		s.answered[req.URL.Path] = rec.Code
		s.mu.Unlock()
		body := rec.Body.Bytes()
		if tamper != nil {
			body = tamper(body)
		}
		for name, values := range rec.Header() {
			if name != "Content-Length" {
				rw.Header()[name] = values
			}
		}
		rw.WriteHeader(rec.Code)
		_, _ = rw.Write(body)
	}))
	s.server.StartTLS()
	t.Cleanup(s.server.Close)
	s.base = s.server.URL
	s.roots = x509.NewCertPool()
	s.roots.AddCert(s.server.Certificate())
	s.who = publisher.Named{
		Name: "SONiC Project", Namespace: "https://sonic.example.test", Category: "vendor",
		Prefix: "SONIC", Served: s.base + publish.DirectoryPath,
	}
	handler = published.Handler(published.Config{
		DB: w.DB.DB, Who: s.who, Base: s.base, Rate: 100000, Signer: signer, List: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return s
}

// change has the surface answer one path with what alter makes of it.
func (s *served) change(path string, alter func([]byte) []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tamper[path] = alter
}

// drop has the surface answer one path as nothing published there.
func (s *served) drop(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.missing[path] = true
}

// documents is every CSAF document the upstream lists, by path.
func (s *served) documents(t *testing.T) []string {
	t.Helper()
	res, err := s.server.Client().Get(s.base + publish.IndexPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if line != "" {
			out = append(out, publish.DirectoryPath+line)
		}
	}
	return out
}

// pathOf is the path the upstream serves its document about an issue at.
func (s *served) pathOf(t *testing.T, issue string) string {
	t.Helper()
	for _, path := range s.documents(t) {
		if strings.Contains(path, strings.ToLower(issue)) {
			return path
		}
	}
	t.Fatalf("the upstream lists no document about %s", issue)
	return ""
}

// testKey is a signing key made for one test, never committed.
func testKey(t *testing.T) string {
	t.Helper()
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity("SONiC PSIRT", "", "psirt@sonic.example.test", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writer, err := armor.Encode(&out, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(writer, cfg); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// otherSignature is a detached signature another key made, over nothing in
// particular.
func otherSignature(t *testing.T) []byte {
	t.Helper()
	other, err := signing.Read(testKey(t), "")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := other.Sign([]byte("something else"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// mirrored is another upstream address serving the upstream's documents,
// unsigned, each altered or left out as a test says, with a digest beside
// every one it serves.
type mirrored struct {
	server *httptest.Server
	base   string
	mu     sync.Mutex
	gone   bool
}

// address is where the mirror describes what it publishes.
func (m *mirrored) address() string { return m.base + publish.MetadataPath }

// fail has the mirror answer its description as nothing published there.
func (m *mirrored) fail() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gone = true
}

// mirror stands up another address serving what the upstream publishes now,
// with alter applied to the documents about the issues it names and the
// documents about the issues in omit left out. corrupt names issues whose
// digest is served wrong.
func mirror(t *testing.T, w *world, alter map[string]func([]byte) []byte, omit, corrupt []string) *mirrored {
	t.Helper()
	return mirrorWith(t, w, mirroring{alter: alter, omit: omit, corrupt: corrupt})
}

// mirroring is how a mirror differs from what the upstream publishes: the
// documents about the issues alter names changed, those about the issues omit
// names left out, those about the issues corrupt names served a wrong digest,
// every document changed by every where it is set, and a feed entry naming no
// moment beside the rest where junk is.
type mirroring struct {
	alter         map[string]func([]byte) []byte
	omit, corrupt []string
	every         func([]byte) []byte
	junk          bool
}

// mirrorWith is mirror, differing as it says.
func mirrorWith(t *testing.T, w *world, how mirroring) *mirrored {
	t.Helper()
	alter, omit, corrupt := how.alter, how.omit, how.corrupt
	bodies := map[string][]byte{}
	sums := map[string]string{}
	for _, path := range w.server.documents(t) {
		res, err := w.server.server.Client().Get(w.server.base + path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		skip := false
		for _, issue := range omit {
			skip = skip || strings.Contains(path, strings.ToLower(issue))
		}
		if skip {
			continue
		}
		for issue, change := range alter {
			if strings.Contains(path, strings.ToLower(issue)) {
				body = change(body)
			}
		}
		if how.every != nil {
			body = how.every(body)
		}
		bodies[path] = body
		sum := sha256.Sum256(body)
		sums[path] = hex.EncodeToString(sum[:])
		for _, issue := range corrupt {
			if strings.Contains(path, strings.ToLower(issue)) {
				sums[path] = strings.Repeat("0", 64)
			}
		}
	}
	m := &mirrored{}
	m.server = httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		m.mu.Lock()
		gone := m.gone
		m.mu.Unlock()
		switch path := req.URL.Path; {
		case path == publish.MetadataPath && !gone:
			_, _ = io.WriteString(rw, `{"canonical_url":"`+m.address()+`","publisher":{"category":"vendor",`+
				`"name":"SONiC Project","namespace":"https://sonic.example.test"},"distributions":[{"rolie":`+
				`{"feeds":[{"tlp_label":"WHITE","url":"`+m.base+`/feed.json"}]}}],"role":"csaf_provider"}`)
		case path == "/feed.json" && !gone:
			var entries []string
			if how.junk {
				entries = append(entries, `{"id":"junk","content":{"src":"`+m.base+`/junk.json"}}`)
			}
			for _, doc := range slices.Sorted(maps.Keys(bodies)) {
				entries = append(entries, `{"id":"`+doc+`","updated":"`+sums[doc]+`",`+
					`"content":{"src":"`+m.base+doc+`"}}`)
			}
			_, _ = io.WriteString(rw, `{"feed":{"id":"feed","entry":[`+strings.Join(entries, ",")+`]}}`)
		case strings.HasSuffix(path, publish.SHA256Suffix):
			sum, ok := sums[strings.TrimSuffix(path, publish.SHA256Suffix)]
			if !ok {
				http.NotFound(rw, req)
				return
			}
			_, _ = io.WriteString(rw, sum+"\n")
		default:
			body, ok := bodies[path]
			if !ok || gone {
				http.NotFound(rw, req)
				return
			}
			_, _ = rw.Write(body)
		}
	}))
	m.server.StartTLS()
	t.Cleanup(m.server.Close)
	m.base = m.server.URL
	return m
}

// readingBoth points the fork's reader at certificate authorities trusting
// the upstream's surface and the mirrors given.
func (w *world) readingBoth(mirrors ...*mirrored) {
	roots := x509.NewCertPool()
	roots.AddCert(w.server.server.Certificate())
	for _, m := range mirrors {
		roots.AddCert(m.server.Certificate())
	}
	w.server.roots = roots
	w.reader = upstream.NewReader(w.DB.DB, sbom.Limits{}, roots)
}

// trustAt has the fork trust the upstream at an address, confirming the key
// that address names, as the API does for a first address or the same one;
// for another address the key trusted already stays.
func (w *world) trustAt(address string) *upstream.Upstream {
	w.t.Helper()
	parsed, err := upstream.Address(address)
	if err != nil {
		w.t.Fatal(err)
	}
	described, err := upstream.Inspect(w.t.Context(), upstream.Client(parsed, w.server.roots), address)
	if err != nil {
		w.t.Fatal(err)
	}
	up, err := upstream.NewStore(w.DB.DB).Trust(w.t.Context(), w.admin, w.fork.ID, upstream.Trusting{
		URL: address, Publisher: described.Publisher,
		Fingerprint: described.Fingerprint, PublicKey: described.PublicKey,
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return up
}
