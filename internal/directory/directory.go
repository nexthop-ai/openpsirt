// Package directory writes the advisories that have gone out as a static CSAF
// provider directory.
//
// Files, never a route. This deployment writes them into a store an operator
// configured and somebody else's web server serves them, which is what keeps
// the application with no unauthenticated route on it (REQ-63). Nothing here
// answers a request, and nothing in the API reaches this package.
//
// What is written is what went out. A document is generated when an advisory
// is issued and kept as the bytes it was, so the file a reader fetches today
// is the file that was published — not what the record would produce now,
// which is a different document the moment a release is added or a fix lands.
//
// Only a document that may travel. The directory is the freely accessible
// half of the standard's distribution, so a document held back while anything
// it covers is undisclosed is not written into it, whatever its editorial
// state says.
package directory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/background"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
)

// betweenWrites is how often the directory is written again.
//
// Slow, because what it publishes is rare: an advisory is the deliberate
// document, written for a flaw recorded here or an embargo reaching its date,
// and a deployment issues single or low double digits of them a year. The pass
// is a read that finds nothing new nearly every time it runs.
const betweenWrites = time.Hour

// travels is the one label this directory carries.
//
// The standard puts anything above it under a different path, behind an
// authentication this deployment does not do: a document nobody outside has
// been told about must not be reachable, and a directory that is served
// without a credential cannot hold one.
const travels = "WHITE"

// The names the standard gives the files beside the documents, and the terms
// it gives the feed. Written out rather than assembled, because each of them
// is an address somebody else's tooling asks for by name.
const (
	metadataFile = "provider-metadata.json"
	indexFile    = "index.txt"
	changesFile  = "changes.csv"
	feedFile     = "feed-tlp-white.json"
	// hashSuffix is appended to a document's own filename, which is what
	// says which file a hash is of.
	hashSuffix = ".sha256"
)

// Config is what the directory says about itself beyond who wrote it.
//
// A struct rather than two arguments, because they are booleans sitting beside
// one another: positional, an operator's answer about being listed becomes
// their answer about being mirrored.
type Config struct {
	// List and Mirror are what the deployment tells aggregators it is
	// content with. The standard reads a missing answer as listed and not
	// mirrored, which is what these default to.
	List   bool
	Mirror bool
}

// Writer writes the directory on a timer.
type Writer struct {
	advisories *advisory.Store
	files      attach.Storage
	who        publisher.Named
	settings   Config
	logger     *slog.Logger
}

// New returns the writer, or nil where this deployment publishes no directory.
//
// Nil rather than a pass that does nothing, the way the sweep over unattached
// files is: a worker started for something a deployment did not configure is a
// goroutine and a log line an operator has to work out the meaning of.
//
// Three things are needed and none implies the others. A store with no address
// writes files that describe themselves by addresses nobody can resolve; an
// address with no store describes files nothing wrote; and the description the
// directory writes about itself names the publisher, as does every document in
// it, so one configured without a publisher describes an organization nobody
// can identify.
//
// The address is not checked here. It is checked and given its trailing slash
// where the setting is read, because a document states it too and reaches that
// without passing through here.
func New(db *bun.DB, files attach.Storage, who publisher.Named, settings Config,
	logger *slog.Logger) *Writer {

	if files == nil || !who.Publishes() || !who.Stated() {
		return nil
	}
	return &Writer{
		advisories: advisory.NewStore(db), files: files, who: who,
		settings: settings, logger: logger,
	}
}

// Written is what one pass wrote.
type Written struct {
	// Documents is how many advisories the directory holds, and Held how
	// many went out under a label this directory may not carry.
	Documents int
	Held      int
}

// Run writes the directory until the context ends.
func (w *Writer) Run(ctx context.Context, interval time.Duration) {
	background.Every(ctx, interval, betweenWrites, func(ctx context.Context) {
		// Logged and carried on, like every other background pass here. A
		// store that cannot be reached is not a reason to stop serving, and
		// what could not be written is written by the next pass.
		written, err := w.Write(ctx)
		switch {
		case err != nil:
			w.logger.ErrorContext(ctx, "writing the published advisory directory",
				"error", err)
		case written.Held > 0:
			w.logger.InfoContext(ctx, "wrote the published advisory directory",
				"documents", written.Documents, "held back", written.Held)
		case written.Documents > 0:
			w.logger.InfoContext(ctx, "wrote the published advisory directory",
				"documents", written.Documents)
		}
	})
}

// Write writes the whole directory.
//
// Everything, every time, rather than what changed since the last pass. What
// it writes is the bytes that went out, so a file it writes twice is the same
// file twice — and working out what moved would mean keeping a record of what
// the store holds, which the store itself already is.
//
// The documents go first and the lists that name them last. A list naming a
// file that is not there yet is a reader fetching a 404; a file nothing names
// yet is a reader who has not heard of it, and the next line fixes it.
func (w *Writer) Write(ctx context.Context) (Written, error) {
	// The deployment looking at itself. It holds no role, so it decides
	// nothing and may only read — and what it reads is what has already been
	// published, narrowed by the same clauses every other read of an
	// issuance carries.
	sent, err := w.advisories.Sent(ctx,
		access.Everything("writing the published advisory directory"))
	if err != nil {
		return Written{}, err
	}

	published, held, err := publishable(sent)
	if err != nil {
		return Written{}, err
	}
	// Nothing to serve. A directory describing a feed with no entries would
	// have to date itself, and there is no moment to date it from: nothing
	// has been published. Written once something is.
	if len(published) == 0 {
		return Written{Held: held}, nil
	}

	for _, one := range published {
		if err := w.document(ctx, one); err != nil {
			return Written{}, err
		}
	}
	if err := w.listings(ctx, published); err != nil {
		return Written{}, err
	}
	return Written{Documents: len(published), Held: held}, nil
}

// entry is one published document, as every file that names it reads it.
type entry struct {
	// Body is the bytes as they went out, and is what the hash is taken
	// over. The document is re-read from them rather than re-marshaled from
	// what was parsed: what a reader fetches and what the hash answers for
	// have to be one string of bytes.
	Body []byte
	// Path is where the file sits in the directory, which is the year folder
	// and the filename the standard's rule gives.
	Path string
	// Released is when the document says this revision was released, which
	// is what the list of changes is ordered by.
	Released time.Time
	// Opened is when the document says the flaw was first recorded here.
	Opened time.Time
	Title  string
	ID     string
	// Summary is what the document's newest revision says about itself,
	// which is the one sentence somebody wrote about these exact bytes.
	Summary string
}

// publishable is the newest document of each advisory that this directory may
// carry, and how many were held back.
//
// Walked per advisory rather than taking the newest of each outright. Whether
// a document may be served is a property of the bytes, and an advisory whose
// newest revision went to a coordinating body under embargo has a revision
// before it that is already public — so the directory keeps carrying that one
// rather than dropping the advisory out of every list it is in.
func publishable(sent []advisory.Sent) (out []entry, held int, err error) {
	seen := map[string]bool{}
	for _, one := range sent {
		if seen[one.Advisory] {
			continue
		}
		var doc advisory.Document
		if err := json.Unmarshal([]byte(one.Document), &doc); err != nil {
			return nil, 0, fmt.Errorf(
				"read what %s issuance %d published: %w", one.Advisory, one.Ordinal, err)
		}
		if !mayTravel(&doc) {
			held++
			continue
		}
		seen[one.Advisory] = true
		out = append(out, entry{
			Body:     []byte(one.Document),
			Path:     advisory.PathFor(&doc),
			Released: doc.Document.Tracking.CurrentReleaseDate,
			Opened:   doc.Document.Tracking.InitialReleaseDate,
			Title:    doc.Document.Title,
			ID:       doc.Document.Tracking.ID,
			Summary:  newestRevision(&doc),
		})
	}
	return out, held, nil
}

// mayTravel reports whether these bytes may be served from a directory
// anybody can read.
//
// Asked of the label the document carries rather than of the record it came
// from. The record moves and the bytes do not, and what a reader is handed is
// the bytes — so a document that said it may be passed on says so for ever,
// and one that says nothing at all is not read as permission.
func mayTravel(doc *advisory.Document) bool {
	at := doc.Document.Distribution
	return at != nil && at.TLP != nil && at.TLP.Label == travels
}

// newestRevision is what the document's last revision entry says about itself.
func newestRevision(doc *advisory.Document) string {
	history := doc.Document.Tracking.RevisionHistory
	if len(history) == 0 {
		return ""
	}
	return history[len(history)-1].Summary
}

// document writes one advisory and the hash beside it.
func (w *Writer) document(ctx context.Context, one entry) error {
	if err := w.put(ctx, one.Path, one.Body, "application/json"); err != nil {
		return err
	}
	return w.put(ctx, one.Path+hashSuffix, checksum(one), "text/plain; charset=utf-8")
}

// checksum is the hash file's contents.
//
// Over the delivered bytes, every volatile field included. It answers whether
// the file a reader fetched arrived intact, which is a different question
// from the digest recorded against the issuance — that one is over what the
// document says, with the moment and the version left out, and answers
// whether what is published is still what this deployment would generate.
// Neither is a duplicate of the other.
//
// The hexadecimal value first and the filename after two spaces, which is
// what the standard asks for and also what the ordinary command-line checker
// reads, so a reader can verify the file with the tool they already have.
func checksum(one entry) []byte {
	sum := sha256.Sum256(one.Body)
	_, name := split(one.Path)
	return []byte(fmt.Sprintf("%x  %s\n", sum, name))
}

// put writes one file.
func (w *Writer) put(ctx context.Context, key string, body []byte, kind string) error {
	if err := w.files.Put(ctx, key, bytes.NewReader(body), int64(len(body)), kind); err != nil {
		return fmt.Errorf("write %s into the advisory directory: %w", key, err)
	}
	return nil
}

// split is a path's folder and its filename.
func split(key string) (folder, name string) {
	cut := strings.LastIndex(key, "/")
	if cut < 0 {
		return "", key
	}
	return key[:cut], key[cut+1:]
}
