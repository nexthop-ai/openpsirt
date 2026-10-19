// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package published serves the security documents this deployment publishes
// to anybody who asks, as a standard CSAF provider and beside it a folder of
// OpenVEX documents.
//
// A surface of its own rather than part of the API. It takes no credential and
// looks at none, so a request carrying a session or a key is answered exactly
// as one carrying nothing; it answers GET and HEAD and refuses every other
// method; it names nothing by an identifier of this deployment's own; and what
// it reads it reads as anybody at all, a subject built per request from the
// products whose documents are published at that moment. Off, every path
// answers as a path nothing is published at.
package published

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/csaf"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/signing"
)

// Prefixes are the paths this surface answers below. Every other path belongs
// to somebody else.
func Prefixes() []string { return []string{publish.WellKnown, publish.OpenVEXPath} }

// Config is what the surface serves and how.
type Config struct {
	DB *bun.DB
	// Who is the publisher every document names, with the address documents
	// are published at.
	Who publisher.Named
	// Base is the address this deployment is reached at, with no trailing
	// slash.
	Base string
	// Rate is how many requests a minute one client may make, and Proxies
	// the sources whose forwarded client address names the client.
	Rate    int
	Proxies access.Trust
	// Signer signs every document, where a key was supplied.
	Signer *signing.Signer
	// List and Mirror are what the provider description tells aggregators
	// the deployment is content with.
	List   bool
	Mirror bool
	Logger *slog.Logger
}

// Off is the surface of a deployment that publishes nothing: every path is
// one nothing is published at.
func Off() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { notFound(w) })
}

// Handler is the surface of a deployment that publishes.
func Handler(c Config) http.Handler {
	s := &server{Config: c, limits: newLimiter(c.Rate, time.Now)}
	return http.HandlerFunc(s.serve)
}

// server answers one request at a time from what is published now.
type server struct {
	Config
	limits *limiter
}

// serve answers one request.
func (s *server) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		problem(w, http.StatusMethodNotAllowed, "only GET and HEAD are answered here")
		return
	}
	if wait, ok := s.limits.allow(s.Proxies.Client(r)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		problem(w, http.StatusTooManyRequests, "too many requests from this address; try again shortly")
		return
	}
	file, err := s.find(r.Context(), r.URL.EscapedPath(), r.Header.Get("If-None-Match"))
	switch {
	case errors.Is(err, publish.ErrNotPublished):
		notFound(w)
		return
	case err != nil:
		s.Logger.ErrorContext(r.Context(), "a published document could not be served",
			"path", r.URL.EscapedPath(), "error", err)
		problem(w, http.StatusInternalServerError, "this could not be answered just now; try again shortly")
		return
	}
	h := w.Header()
	h.Set("Content-Type", file.kind)
	tag := file.tag
	if tag == "" {
		tag = tagOf(file.body)
	}
	h.Set("ETag", tag)
	// Asked again every time, and answered "not modified" where nothing
	// moved: a reader keeping a copy fetches only what changed.
	h.Set("Cache-Control", "public, no-cache")
	http.ServeContent(w, r, "", file.modified, bytes.NewReader(file.body))
}

// tagOf is the entity tag of a body: a digest of its bytes.
func tagOf(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// file is one answer: its bytes, what they are, and when they last moved,
// which is zero for a list, and its tag where the bytes do not decide it.
type file struct {
	tag      string
	body     []byte
	kind     string
	modified time.Time
}

// The kinds of file served.
const (
	jsonKind      = "application/json"
	textKind      = "text/plain; charset=utf-8"
	csvKind       = "text/csv; charset=utf-8"
	signatureKind = "application/pgp-signature"
	keyKind       = "application/pgp-keys"
)

// find is the file served at path, or ErrNotPublished.
//
// A list reads every document's name and dates; a VEX document reads itself,
// and an advisory is looked for only where no VEX document is. A reader taking
// a provider whole asks for every document and the files beside it, so a
// request for one is answered without listing the rest.
//
// asked is the entity tag the request already holds, which a signature is
// answered from without signing again.
func (s *server) find(ctx context.Context, path, asked string) (*file, error) {
	now, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	lists := map[string]func(*view) (*file, error){
		publish.MetadataPath: s.described,
		publish.IndexPath:    func(v *view) (*file, error) { return listing(v.csaf, csaf.Index, textKind) },
		publish.ChangesPath:  func(v *view) (*file, error) { return listing(v.csaf, csaf.Changes, csvKind) },
		publish.FeedPath:     s.feed,
		publish.OpenVEXIndex: func(v *view) (*file, error) { return listing(v.openvex, csaf.Index, textKind) },
	}
	if list, ok := lists[path]; ok {
		// The OpenVEX list names no advisory, so it reads none.
		if path != publish.OpenVEXIndex {
			if err := s.travelling(ctx, now); err != nil {
				return nil, err
			}
		}
		if err := s.list(ctx, now); err != nil {
			return nil, err
		}
		return list(now)
	}
	if strings.HasPrefix(path, publish.KeysPath) {
		return s.key(path)
	}
	for _, beside := range []struct {
		suffix string
		answer func(*file) (*file, error)
	}{
		{publish.SHA256Suffix, func(f *file) (*file, error) { return digestFile(f, path, sha256Of), nil }},
		{publish.SHA512Suffix, func(f *file) (*file, error) { return digestFile(f, path, sha512Of), nil }},
		{publish.SignatureSuffix, func(f *file) (*file, error) { return s.signature(f, asked) }},
	} {
		if named, ok := strings.CutSuffix(path, beside.suffix); ok {
			document, err := s.document(ctx, now, named)
			if err != nil {
				return nil, err
			}
			return beside.answer(document)
		}
	}
	return s.document(ctx, now, path)
}

// view is what anybody at all may be handed at this moment: the subject that
// reads it, the statuses published, and every document as a list names it.
type view struct {
	subject  access.Subject
	statuses string
	// csaf is every CSAF document, at paths below the folder of documents
	// that may travel, and openvex every OpenVEX document, at paths below
	// theirs.
	csaf    []csaf.Listed
	openvex []csaf.Listed
	// advisories is the bytes of every advisory that may travel, by its path
	// below the folder.
	advisories map[string]advisory.Travels
}

// read is who anybody at all is at this moment and what statuses are
// published.
func (s *server) read(ctx context.Context) (*view, error) {
	products, err := catalog.NewStore(s.DB).Publishing(ctx)
	if err != nil {
		return nil, err
	}
	if len(products) == 0 {
		return nil, publish.ErrNotPublished
	}
	statuses, err := publish.Statuses(ctx, s.DB)
	if err != nil {
		return nil, err
	}
	return &view{subject: access.Published(products), statuses: statuses}, nil
}

// travelling adds every advisory that may travel to the view.
//
// Read only by the CSAF lists and by a path in their folder that holds no VEX
// document, because it reads every advisory's issued bytes: a VEX document,
// the files beside one, an OpenVEX path and a key ask none of it.
func (s *server) travelling(ctx context.Context, v *view) error {
	v.advisories = map[string]advisory.Travels{}
	sent, err := advisory.NewStore(s.DB).Sent(ctx, v.subject)
	if err != nil {
		return err
	}
	travels, _, unread := advisory.Travelling(sent)
	for _, one := range unread {
		s.Logger.ErrorContext(ctx, "a published advisory could not be read back", "error", one)
	}
	for _, one := range travels {
		v.advisories[one.Path] = one
		v.csaf = append(v.csaf, one.Listed)
	}
	return nil
}

// list adds every VEX document to the view, as the lists name them.
func (s *server) list(ctx context.Context, v *view) error {
	listed, err := publish.NewStore(s.DB).Listed(ctx, v.subject, v.statuses)
	if err != nil {
		return err
	}
	for _, one := range listed {
		entry := csaf.Listed{Released: one.CurrentAt, Opened: one.FirstAt, Title: one.Title,
			ID: one.TrackingID, Summary: one.Title}
		switch one.Kind {
		case publish.CSAFVEX:
			entry.Path = strings.TrimPrefix(one.Path, publish.DirectoryPath)
			if _, taken := v.advisories[entry.Path]; taken {
				continue
			}
			v.csaf = append(v.csaf, entry)
		case publish.OpenVEX:
			entry.Path = strings.TrimPrefix(one.Path, publish.OpenVEXPath)
			v.openvex = append(v.openvex, entry)
		}
	}
	return nil
}

// listing is one of the lists, or nothing where it would list nothing.
func listing(listed []csaf.Listed, write func([]csaf.Listed) []byte, kind string) (*file, error) {
	if len(listed) == 0 {
		return nil, publish.ErrNotPublished
	}
	// No date: a list that shrank, by a document withdrawn or a product
	// turned off, is newer than its newest document, and a reader asking
	// whether it moved since a date would be told it had not. The tag
	// answers that.
	return &file{body: write(listed), kind: kind}, nil
}

// described is the provider description.
//
// It names the publisher every document names, built the same way, one
// distribution that is both of the standard's shapes at once, and the key the
// documents are signed with where they are. Nothing where there is no CSAF
// document to describe, since it states when the newest was released.
func (s *server) described(v *view) (*file, error) {
	if len(v.csaf) == 0 {
		return nil, publish.ErrNotPublished
	}
	newest := csaf.Newest(v.csaf)
	role := csaf.Provider
	var keys []csaf.PublicKey
	if s.Signer != nil {
		role = csaf.TrustedProvider
		keys = []csaf.PublicKey{{Fingerprint: s.Signer.Fingerprint(),
			URL: s.Base + publish.KeysPath + s.Signer.Fingerprint() + ".asc"}}
	}
	return jsonFile(csaf.ProviderMetadata{
		CanonicalURL: s.Base + publish.MetadataPath,
		Distributions: []csaf.Distribution{{
			DirectoryURL: s.Base + publish.DirectoryPath,
			ROLIE: &csaf.ROLIE{Feeds: []csaf.FeedDescription{{
				Summary:  "Security documents " + s.Who.Name + " publishes, TLP:" + advisory.Travelable + ".",
				TLPLabel: advisory.Travelable,
				URL:      s.Base + publish.FeedPath,
			}}},
		}},
		LastUpdated: csaf.Stamp(newest),
		Listed:      s.List,
		Mirrored:    s.Mirror,
		Version:     csaf.MetadataVersion,
		Publisher:   advisory.IssuerOf(s.Who),
		PublicKeys:  keys,
		Role:        role,
	}, time.Time{})
}

// feed is every CSAF document as one ROLIE feed, each entry naming the files
// beside the document.
func (s *server) feed(v *view) (*file, error) {
	if len(v.csaf) == 0 {
		return nil, publish.ErrNotPublished
	}
	beside := []csaf.Beside{
		{Rel: "hash", Suffix: publish.SHA256Suffix}, {Rel: "hash", Suffix: publish.SHA512Suffix},
	}
	if s.Signer != nil {
		beside = append(beside, csaf.Beside{Rel: "signature", Suffix: publish.SignatureSuffix})
	}
	at := func(path string) string { return s.Base + publish.DirectoryPath + path }
	return jsonFile(csaf.FeedOf(csaf.FeedName(s.Who.Prefix),
		s.Who.Name+" CSAF documents (TLP:"+advisory.Travelable+")",
		s.Base+publish.FeedPath, at, beside, v.csaf), time.Time{})
}

// key is the public key the documents are signed with, served under its
// fingerprint, and dated when it became valid.
func (s *server) key(path string) (*file, error) {
	if s.Signer == nil || path != publish.KeysPath+s.Signer.Fingerprint()+".asc" {
		return nil, publish.ErrNotPublished
	}
	return &file{body: s.Signer.PublicKey(), kind: keyKind, modified: s.Signer.From()}, nil
}

// document is one document by its path.
func (s *server) document(ctx context.Context, v *view, path string) (*file, error) {
	below, inFolder := strings.CutPrefix(path, publish.DirectoryPath)
	if !inFolder && !strings.HasPrefix(path, publish.OpenVEXPath) {
		return nil, publish.ErrNotPublished
	}
	doc, err := publish.NewStore(s.DB).At(ctx, v.subject, path, v.statuses)
	switch {
	case err == nil:
		return &file{body: []byte(doc.Body), kind: jsonKind, modified: doc.CurrentAt}, nil
	case !errors.Is(err, publish.ErrNotPublished) || !inFolder:
		return nil, err
	}
	if err := s.travelling(ctx, v); err != nil {
		return nil, err
	}
	if one, ok := v.advisories[below]; ok {
		return &file{body: one.Body, kind: jsonKind, modified: one.Released}, nil
	}
	return nil, publish.ErrNotPublished
}

// signature is the detached signature over one document, dated when the
// document was released.
//
// Tagged by the document it signs rather than by its own bytes, which carry a
// random salt and differ every time: a reader holding the signature of an
// unchanged document is told so, without the key being used again.
func (s *server) signature(document *file, asked string) (*file, error) {
	if s.Signer == nil {
		return nil, publish.ErrNotPublished
	}
	tag := strings.TrimSuffix(tagOf(document.body), `"`) + `.asc"`
	if asked == tag {
		return &file{tag: tag, kind: signatureKind, modified: document.modified}, nil
	}
	signed, err := s.Signer.Sign(document.body, document.modified)
	if err != nil {
		return nil, err
	}
	return &file{tag: tag, body: signed, kind: signatureKind, modified: document.modified}, nil
}

// digestFile is the file holding a document's digest: the value and then the
// filename, which is what the standard asks for and what the ordinary
// command-line checker reads.
func digestFile(document *file, path string, sum func([]byte) string) *file {
	name := path[strings.LastIndex(path, "/")+1:]
	name = name[:strings.LastIndex(name, ".")]
	return &file{body: []byte(sum(document.body) + "  " + name + "\n"), kind: textKind,
		modified: document.modified}
}

func sha256Of(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func sha512Of(body []byte) string {
	sum := sha512.Sum512(body)
	return hex.EncodeToString(sum[:])
}

// jsonFile is a value written as indented JSON.
func jsonFile(value any, modified time.Time) (*file, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("write a published list: %w", err)
	}
	return &file{body: append(body, '\n'), kind: jsonKind, modified: modified}, nil
}

// notFound is the one answer for every path nothing is published at.
func notFound(w http.ResponseWriter) {
	problem(w, http.StatusNotFound, "nothing is published here")
}

// problem writes a refusal in the shape every refusal of this deployment
// takes.
func problem(w http.ResponseWriter, status int, detail string) {
	body, _ := json.Marshal(struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
	}{http.StatusText(status), status, detail})
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(append(body, '\n'))
}
