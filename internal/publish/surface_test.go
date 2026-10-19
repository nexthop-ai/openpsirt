// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package publish_test

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/csaf"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/published"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/signing"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// surface is the published surface over a world, answering requests in
// process.
type surface struct {
	t *testing.T
	h http.Handler
}

// surfaceOver is the surface a deployment publishing this world serves.
func surfaceOver(w *world, rate int, signer *signing.Signer) *surface {
	return surfaceBehind(w, rate, signer, access.Trust{})
}

// surfaceBehind is the same, trusting the proxies given to name the client.
func surfaceBehind(w *world, rate int, signer *signing.Signer, proxies access.Trust) *surface {
	return &surface{t: w.t, h: published.Handler(published.Config{
		DB: w.DB.DB, Who: who, Base: base, Rate: rate, Proxies: proxies, Signer: signer,
		List: true, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})}
}

// get asks for path, carrying the headers given.
func (s *surface) get(method, path string, headers map[string]string) *httptest.ResponseRecorder {
	s.t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "203.0.113.9:4000"
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec
}

// body is what path answers, failing the test on anything but a 200.
func (s *surface) body(path string) []byte {
	s.t.Helper()
	rec := s.get(http.MethodGet, path, nil)
	if rec.Code != http.StatusOK {
		s.t.Fatalf("GET %s = %d: %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.Bytes()
}

// published is a world publishing a disclosed advisory and the VEX documents
// of its default build.
func publishedWorld(t *testing.T, f *fixture.World) (*world, string) {
	t.Helper()
	w := newWorld(t, f)
	w.shipped()
	w.report(w.Target, reported{"CVE-2026-1001", openssl}, reported{"CVE-2026-1002", libnl})
	w.decide(w.Target, "CVE-2026-1001", openssl,
		claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
	w.decide(w.Target, "CVE-2026-1002", libnl,
		claim{outcome: triage.NotApplicable, justification: triage.CodeNotInExecutePath})
	named, _ := w.issued(true)
	w.publishes(w.Product, true)
	w.write()
	return w, named
}

// two runs fn on SQLite and PostgreSQL: what it pins is routing and the shape
// of an answer, which no engine changes.
func two(t *testing.T, fn func(t *testing.T, f *fixture.World)) {
	dbtest.Two(t, func(t *testing.T, db *database.DB) { fn(t, fixture.New(t, db)) })
}

// The surface is a standard CSAF provider: a description at the well-known
// address naming one distribution that is a folder of documents with its two
// lists and a feed, every document beside a digest of each kind, and a folder
// of OpenVEX documents with a list of its own.
func TestTheSurfaceIsAStandardProvider(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w, named := publishedWorld(t, f)
		s := surfaceOver(w, 1000, nil)

		var described csaf.ProviderMetadata
		if err := json.Unmarshal(s.body(publish.MetadataPath), &described); err != nil {
			t.Fatal(err)
		}
		if described.Role != csaf.Provider || described.CanonicalURL != base+publish.MetadataPath ||
			len(described.Distributions) != 1 ||
			described.Distributions[0].DirectoryURL != base+publish.DirectoryPath ||
			described.Distributions[0].ROLIE == nil ||
			described.Distributions[0].ROLIE.Feeds[0].URL != base+publish.FeedPath ||
			described.Publisher.Name != who.Name {
			t.Errorf("the provider describes itself as %+v", described)
		}

		index := strings.Fields(string(s.body(publish.IndexPath)))
		if len(index) < 3 {
			t.Fatalf("the index lists %v, want the advisory and a VEX document per issue", index)
		}
		advisoryPath := ""
		for _, path := range index {
			if strings.Contains(path, strings.ToLower(named)) {
				advisoryPath = path
			}
			doc := s.body(publish.DirectoryPath + path)
			sum256 := sha256.Sum256(doc)
			sum512 := sha512.Sum512(doc)
			name := path[strings.LastIndex(path, "/")+1:]
			if got := string(s.body(publish.DirectoryPath + path + publish.SHA256Suffix)); got !=
				hex.EncodeToString(sum256[:])+"  "+name+"\n" {
				t.Errorf("the SHA-256 beside %s reads %q", path, got)
			}
			if got := string(s.body(publish.DirectoryPath + path + publish.SHA512Suffix)); got !=
				hex.EncodeToString(sum512[:])+"  "+name+"\n" {
				t.Errorf("the SHA-512 beside %s reads %q", path, got)
			}
			if !strings.Contains(string(s.body(publish.ChangesPath)), `"`+path+`",`) {
				t.Errorf("the list of changes does not name %s", path)
			}
		}
		if advisoryPath == "" {
			t.Errorf("the index %v does not list the advisory %s", index, named)
		}

		var feed csaf.Feed
		if err := json.Unmarshal(s.body(publish.FeedPath), &feed); err != nil {
			t.Fatal(err)
		}
		if len(feed.Feed.Entries) != len(index) {
			t.Errorf("the feed has %d entries and the index %d", len(feed.Feed.Entries), len(index))
		}
		for _, entry := range feed.Feed.Entries {
			hashes := 0
			for _, link := range entry.Links {
				if link.Rel == "hash" {
					hashes++
				}
			}
			if hashes != 2 {
				t.Errorf("the feed entry for %s names %d digests, want both", entry.ID, hashes)
			}
		}

		openvex := strings.Fields(string(s.body(publish.OpenVEXIndex)))
		if len(openvex) != 1 || openvex[0] != w.Product.Name+"/"+w.Branch.Name+".json" {
			t.Fatalf("the OpenVEX list is %v", openvex)
		}
		s.body(publish.OpenVEXPath + openvex[0])
	})
}

// A reader keeping a copy is told it has not moved, by the tag and by the
// date, and fetches only what changed.
func TestAReaderKeepingACopyFetchesOnlyWhatChanged(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w, _ := publishedWorld(t, f)
		signer, err := signing.Read(testKey(t), "")
		if err != nil {
			t.Fatal(err)
		}
		s := surfaceOver(w, 1000, signer)
		document := publish.OpenVEXPath + w.Product.Name + "/" + w.Branch.Name + ".json"
		for _, one := range []struct {
			path  string
			dated bool
		}{
			{publish.MetadataPath, false}, {publish.FeedPath, false}, {publish.IndexPath, false},
			{publish.OpenVEXIndex, false}, {document, true}, {document + publish.SignatureSuffix, true},
		} {
			first := s.get(http.MethodGet, one.path, nil)
			tag, modified := first.Header().Get("ETag"), first.Header().Get("Last-Modified")
			if tag == "" {
				t.Fatalf("GET %s carries no tag", one.path)
			}
			if rec := s.get(http.MethodGet, one.path, map[string]string{"If-None-Match": tag}); rec.Code != http.StatusNotModified {
				t.Errorf("GET %s with its tag = %d, want 304", one.path, rec.Code)
			}
			if !one.dated {
				// A list that shrank is newer than its newest document, so it
				// is revalidated by its tag alone.
				if modified != "" {
					t.Errorf("GET %s carries the date %q, which a list that shrank would not move",
						one.path, modified)
				}
				if again := s.get(http.MethodGet, one.path, nil); !bytes.Equal(again.Body.Bytes(), first.Body.Bytes()) {
					t.Errorf("GET %s twice over nothing that moved answered two different bodies", one.path)
				}
				continue
			}
			if modified == "" {
				t.Fatalf("GET %s carries no date", one.path)
			}
			if rec := s.get(http.MethodGet, one.path, map[string]string{"If-Modified-Since": modified}); rec.Code != http.StatusNotModified {
				t.Errorf("GET %s since its date = %d, want 304", one.path, rec.Code)
			}
		}
	})
}

// Only GET and HEAD are answered. Everything else is refused before anything
// is read.
func TestOnlyGetAndHeadAreAnswered(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w, _ := publishedWorld(t, f)
		s := surfaceOver(w, 1000, nil)
		if rec := s.get(http.MethodHead, publish.MetadataPath, nil); rec.Code != http.StatusOK ||
			rec.Body.Len() != 0 {
			t.Errorf("HEAD = %d with %d bytes, want 200 and none", rec.Code, rec.Body.Len())
		}
		for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch,
			http.MethodDelete, http.MethodOptions} {
			rec := s.get(method, publish.MetadataPath, nil)
			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("%s = %d allowing %q, want 405 allowing GET and HEAD", method, rec.Code,
					rec.Header().Get("Allow"))
			}
		}
	})
}

// Where nothing is published every path answers alike, whichever reason it
// is: publishing off, no product publishing, a product that stopped, a
// document never written.
func TestNothingPublishedAnswersAlikeEverywhere(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w, _ := publishedWorld(t, f)
		on := surfaceOver(w, 1000, nil)
		doc := publish.OpenVEXPath + w.Product.Name + "/" + w.Branch.Name + ".json"
		on.body(doc)
		never := on.get(http.MethodGet, publish.DirectoryPath+"2026/vex-nothing.json", nil)
		if never.Code != http.StatusNotFound {
			t.Fatalf("a document never written = %d", never.Code)
		}
		answers := map[string]*httptest.ResponseRecorder{"a document never written": never}

		off := &surface{t: t, h: published.Off()}
		answers["publishing off"] = off.get(http.MethodGet, publish.MetadataPath, nil)
		w.publishes(w.Product, false)
		answers["a product that stopped, its document"] = on.get(http.MethodGet, doc, nil)
		answers["no product publishing, the description"] = on.get(http.MethodGet, publish.MetadataPath, nil)
		for name, rec := range answers {
			if rec.Code != never.Code || rec.Body.String() != never.Body.String() ||
				rec.Header().Get("Content-Type") != never.Header().Get("Content-Type") {
				t.Errorf("%s answers %d %q, unlike a document never written: %d %q", name,
					rec.Code, rec.Body.String(), never.Code, never.Body.String())
			}
		}
	})
}

// A client asking faster than the rate is told to wait, and one at another
// address is not.
func TestAClientAskingTooFastIsToldToWait(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w, _ := publishedWorld(t, f)
		s := surfaceOver(w, 2, nil)
		for i := range 2 {
			if rec := s.get(http.MethodGet, publish.MetadataPath, nil); rec.Code != http.StatusOK {
				t.Fatalf("request %d = %d, inside the rate", i+1, rec.Code)
			}
		}
		rec := s.get(http.MethodGet, publish.MetadataPath, nil)
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
			t.Errorf("past the rate = %d, Retry-After %q, want 429 and when to ask again", rec.Code,
				rec.Header().Get("Retry-After"))
		}
		req := httptest.NewRequest(http.MethodGet, publish.MetadataPath, nil)
		req.RemoteAddr = "198.51.100.4:4000"
		other := httptest.NewRecorder()
		s.h.ServeHTTP(other, req)
		if other.Code != http.StatusOK {
			t.Errorf("another client = %d, want it answered", other.Code)
		}
	})
}

// Behind a trusted proxy each client it forwards for has an allowance of its
// own, and a client reaching the deployment directly cannot name another
// client to spend theirs.
func TestEachClientBehindATrustedProxyIsCountedApart(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w, _ := publishedWorld(t, f)
		_, proxies, err := net.ParseCIDR("10.0.0.0/8")
		if err != nil {
			t.Fatal(err)
		}
		s := surfaceBehind(w, 2, nil, access.Trust{From: []net.IPNet{*proxies}})
		ask := func(remote, forwarded string) int {
			req := httptest.NewRequest(http.MethodGet, publish.MetadataPath, nil)
			req.RemoteAddr = remote
			if forwarded != "" {
				req.Header.Set("X-Forwarded-For", forwarded)
			}
			rec := httptest.NewRecorder()
			s.h.ServeHTTP(rec, req)
			return rec.Code
		}
		for range 2 {
			if code := ask("10.0.0.5:4000", "203.0.113.1"); code != http.StatusOK {
				t.Fatalf("the first client inside its allowance = %d", code)
			}
		}
		if code := ask("10.0.0.5:4000", "203.0.113.1"); code != http.StatusTooManyRequests {
			t.Errorf("the first client past its allowance = %d, want 429", code)
		}
		if code := ask("10.0.0.5:4000", "203.0.113.2"); code != http.StatusOK {
			t.Errorf("a second client through the same proxy = %d, want its own allowance", code)
		}

		// Directly, naming the second client: counted as itself.
		for range 2 {
			if code := ask("198.51.100.7:4000", "203.0.113.2"); code != http.StatusOK {
				t.Fatalf("a direct client inside its allowance = %d", code)
			}
		}
		if code := ask("198.51.100.7:4000", "203.0.113.9"); code != http.StatusTooManyRequests {
			t.Errorf("a direct client naming yet another client = %d, want it counted as itself", code)
		}
		if code := ask("10.0.0.5:4000", "203.0.113.2"); code != http.StatusOK {
			t.Errorf("the second client after a direct one named it = %d, want its allowance untouched", code)
		}
	})
}

// With a key, the provider says it signs, names the key, serves it, and every
// document carries a signature that verifies against it.
func TestASignedProviderSignsEveryDocument(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w, _ := publishedWorld(t, f)
		armored := testKey(t)
		signer, err := signing.Read(armored, "")
		if err != nil {
			t.Fatal(err)
		}
		s := surfaceOver(w, 1000, signer)
		var described csaf.ProviderMetadata
		if err := json.Unmarshal(s.body(publish.MetadataPath), &described); err != nil {
			t.Fatal(err)
		}
		if described.Role != csaf.TrustedProvider || len(described.PublicKeys) != 1 ||
			described.PublicKeys[0].Fingerprint != signer.Fingerprint() {
			t.Fatalf("the provider describes itself as %+v", described)
		}
		key := s.body(strings.TrimPrefix(described.PublicKeys[0].URL, base))
		keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(key))
		if err != nil {
			t.Fatal(err)
		}
		if keyring[0].PrivateKey != nil {
			t.Fatal("the key served holds the private half")
		}
		paths := strings.Fields(string(s.body(publish.IndexPath)))
		for _, path := range paths {
			doc := s.body(publish.DirectoryPath + path)
			signature := s.body(publish.DirectoryPath + path + publish.SignatureSuffix)
			if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(doc),
				bytes.NewReader(signature), nil); err != nil {
				t.Errorf("the signature beside %s does not verify: %v", path, err)
			}
		}
		var feed csaf.Feed
		if err := json.Unmarshal(s.body(publish.FeedPath), &feed); err != nil {
			t.Fatal(err)
		}
		for _, entry := range feed.Feed.Entries {
			signed := false
			for _, link := range entry.Links {
				signed = signed || link.Rel == "signature"
			}
			if !signed {
				t.Errorf("the feed entry for %s names no signature", entry.ID)
			}
		}

		unsigned := surfaceOver(w, 1000, nil)
		if rec := unsigned.get(http.MethodGet, publish.DirectoryPath+paths[0]+publish.SignatureSuffix, nil); rec.Code != http.StatusNotFound {
			t.Errorf("a signature from a provider holding no key = %d, want 404", rec.Code)
		}
	})
}

// testKey is a signing key made for one test, never committed.
func testKey(t *testing.T) string {
	t.Helper()
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: func() time.Time { return created }}
	entity, err := openpgp.NewEntity("Example PSIRT", "", "psirt@example.test", cfg)
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

// An advisory is served only where it may travel and every product it covers
// publishes: one about a flaw nobody has disclosed is not, and nor is one
// whose product stopped publishing.
func TestAnAdvisoryIsServedOnlyWhereItMayTravel(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w, disclosed := publishedWorld(t, f)
		held, flaw := w.issued(false)
		s := surfaceOver(w, 1000, nil)
		index := string(s.body(publish.IndexPath))
		if !strings.Contains(index, strings.ToLower(disclosed)) {
			t.Errorf("the index %q does not list the disclosed advisory %s", index, disclosed)
		}
		for _, path := range []string{publish.IndexPath, publish.ChangesPath, publish.FeedPath,
			publish.MetadataPath} {
			body := string(s.body(path))
			for _, secret := range []string{strings.ToLower(held), held, flaw} {
				if strings.Contains(body, secret) {
					t.Errorf("%s names %q, about a flaw nobody has disclosed", path, secret)
				}
			}
		}
		heldPath := publish.DirectoryPath + advisory.PathOf(held, time.Now())
		if rec := s.get(http.MethodGet, heldPath, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want the advisory about an undisclosed flaw not served", heldPath, rec.Code)
		}

		w.publishes(w.Product, false)
		if rec := s.get(http.MethodGet, publish.IndexPath, nil); rec.Code != http.StatusNotFound {
			t.Errorf("the index of a deployment whose one product stopped publishing = %d", rec.Code)
		}
	})
}

// An advisory states the address this deployment serves it at only where
// every product it covers publishes and is in use when it goes out; otherwise
// it states none, since this surface would answer that address with nothing.
func TestAnAdvisoryStatesTheServedAddressOnlyWhereItIsServed(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w := newWorld(t, f)
		w.shipped()
		unpublished, _ := w.issued(true)
		w.publishes(w.Product, true)
		served, _ := w.issued(true)
		if err := w.Catalog.RetireProduct(t.Context(), w.Product.ID); err != nil {
			t.Fatal(err)
		}
		retired, _ := w.issued(true)
		sent, err := advisory.NewStore(w.DB.DB).Sent(t.Context(), access.Everything("reading what went out"))
		if err != nil {
			t.Fatal(err)
		}
		self := map[string]string{}
		for _, one := range sent {
			var doc advisory.Document
			if err := json.Unmarshal([]byte(one.Document), &doc); err != nil {
				t.Fatal(err)
			}
			for _, ref := range doc.Document.References {
				if ref.Category == "self" {
					self[one.Advisory] = ref.URL
				}
			}
		}
		if want := base + publish.DirectoryPath; !strings.HasPrefix(self[served], want) {
			t.Errorf("an advisory issued while its product publishes states %q, want an address under %s",
				self[served], want)
		}
		if got, ok := self[unpublished]; ok {
			t.Errorf("an advisory issued while its product did not publish states %q", got)
		}
		if got, ok := self[retired]; ok {
			t.Errorf("an advisory issued while its publishing product was retired states %q", got)
		}
	})
}

// The surface reads as anybody at all, built from the products that publish
// at that moment: with two publishing and one turned off, the one turned off
// is in no answer — not its documents, not a list, not the feed — before
// anything is written again.
func TestTheSurfaceReadsOnlyTheProductsThatPublishNow(t *testing.T) {
	two(t, func(t *testing.T, f *fixture.World) {
		w, _ := publishedWorld(t, f)
		other := w.DeclareProduct("other-os", "Other OS")
		w.hold(other)
		target := w.TargetFor(w.DeclareStream(other, "main", catalog.Branch, nil),
			w.DeclareVariant(other, "x86", true))
		root := graph.Described{Purl: "pkg:generic/other-os@1.0", Name: "other-os", Version: "1.0"}
		w.ship(target, root, edge{root, zlib})
		w.report(target, reported{"CVE-2026-2001", zlib})
		w.decide(target, "CVE-2026-2001", zlib,
			claim{outcome: triage.NotApplicable, justification: triage.CodeNotPresent})
		w.publishes(other, true)
		w.write()
		s := surfaceOver(w, 1000, nil)
		lists := []string{publish.IndexPath, publish.ChangesPath, publish.FeedPath, publish.OpenVEXIndex}
		docs := []string{pathOf(t, s, "CVE-2026-2001"), publish.OpenVEXPath + "other-os/main.json"}
		for _, path := range lists {
			if !strings.Contains(string(s.body(path)), "other-os") {
				t.Fatalf("%s does not list the second product while it publishes", path)
			}
		}
		for _, path := range docs {
			s.body(path)
		}
		nothing := s.get(http.MethodGet, publish.DirectoryPath+"2026/vex-nothing.json", nil).Body.String()

		w.publishes(other, false)
		for _, path := range lists {
			if strings.Contains(string(s.body(path)), "other-os") {
				t.Errorf("%s still lists the product that stopped publishing", path)
			}
		}
		for _, path := range docs {
			if rec := s.get(http.MethodGet, path, nil); rec.Code != http.StatusNotFound ||
				rec.Body.String() != nothing {
				t.Errorf("%s answers %d %q, want the answer for nothing", path, rec.Code, rec.Body.String())
			}
		}
	})
}
