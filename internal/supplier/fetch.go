package supplier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// MostPerPass bounds how many documents are taken from one supplier in one
// cycle.
//
// A publisher's feed lists everything they have ever issued, and a supplier
// having a busy week is not a reason to make a hundred requests of them in a
// minute. What is not taken this cycle is taken next: the mark only moves past
// documents that were read, so a backlog drains rather than being skipped.
const MostPerPass = 20

// mostListingBytes bounds the two documents that describe what a publisher
// offers.
//
// Separate from the bound on a document, because they are different shapes of
// thing. A feed is one entry per advisory a publisher has ever issued, so a
// distribution's runs to tens of thousands of entries; an advisory is one
// announcement. Neither bound protects the other.
const mostListingBytes = 64 << 20

// betweenAsks is the pause between one request to a supplier and the next.
//
// Deliberate politeness rather than a rate limit anybody gave us. A publisher
// serves their directory as a courtesy, and a tool that walks it as fast as it
// can is the reason such things end up behind an authenticating proxy.
const betweenAsks = 250 * time.Millisecond

// Reachable refuses an address that is not a supplier's published directory.
//
// The transport refuses this too, and that refusal arrives on the cycle rather
// than at the person typing. Asked here, an address nobody can fetch is a
// message at the moment it is configured instead of evidence that never shows
// up.
func Reachable(address string) error {
	parsed, err := url.Parse(strings.TrimSpace(address))
	if err == nil && parsed.User != nil {
		return fmt.Errorf("an address here carries no name or password in it: a " +
			"publisher's directory is what they publish to everybody")
	}
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		return fmt.Errorf("a supplier is an https address: what comes back is read as " +
			"a publisher's own judgment, and over anything else it is read as whoever " +
			"is between us and them")
	}
	return nil
}

// Taken is what one pass over one supplier did.
type Taken struct {
	// Documents is how many advisories were read and Recorded how many claims
	// they left behind. The two differ by a lot: most of a publisher's
	// catalog is about components no product here ships.
	Documents int
	Recorded  int
	// Skipped is how many documents in the feed were not security advisories.
	Skipped int
	// CaughtUpTo is the newest feed moment this pass reached, which is where
	// the next one starts.
	CaughtUpTo time.Time
}

// Fetcher reads what a supplier publishes and records it as evidence.
type Fetcher struct {
	db     bun.IDB
	limits sbom.Limits
	// Client returns the client to reach one host with. A field so a test can
	// answer without a network, which is the only way to test this at all: a
	// real supplier's directory is somebody else's service and its contents
	// change.
	Client func(host string) *http.Client
	// Pause is how long to wait between one request and the next. A field so
	// a test does not spend real seconds being polite to a fake.
	Pause time.Duration
	Now   func() time.Time
}

// NewFetcher returns a fetcher over db, reaching real suppliers.
func NewFetcher(db bun.IDB, limits sbom.Limits) *Fetcher {
	return &Fetcher{
		db: db, limits: limits.OrDefault(),
		Client: func(host string) *http.Client { return outward.Guarded(host) },
		Pause:  betweenAsks,
		Now:    func() time.Time { return time.Now().UTC() },
	}
}

// From reads one supplier and records what is about a component this product
// ships.
//
// The whole pass is bounded twice over: at most MostPerPass documents, and only
// those the publisher stamped after the last one taken. What comes back is
// evidence and a prefill and decides nothing (REQ-31).
func (f *Fetcher) From(ctx context.Context, by access.Subject, source Source) (Taken, error) {
	var took Taken
	if err := Reachable(source.URL); err != nil {
		return took, err
	}
	at, err := url.Parse(source.URL)
	if err != nil {
		return took, err
	}
	// One client per supplier, pinned to the host their directory is served
	// from. A feed or a document somewhere else is refused rather than
	// followed: the addresses inside a publisher's directory come from
	// outside, and fetching whatever they name is the request-forgery
	// primitive the guarded client exists to refuse (REQ-69).
	client := f.Client(at.Hostname())

	feeds, err := f.feeds(ctx, client, source.URL)
	if err != nil {
		return took, err
	}
	if len(feeds) == 0 {
		return took, fmt.Errorf("that publisher's directory describes no feed of " +
			"advisories, so there is nothing at it to read")
	}

	from := source.From()
	due, err := f.due(ctx, client, feeds, from)
	if err != nil {
		return took, err
	}
	if len(due) == 0 {
		return took, nil
	}

	// Read once for the pass rather than once per document. What a product
	// ships does not move during a pass in any way that matters: a component
	// that arrives during it is matched by the next one.
	ships, err := f.shipped(ctx, source.ProductID)
	if err != nil {
		return took, err
	}

	for _, entry := range due {
		if ctx.Err() != nil {
			return took, nil
		}
		if err := f.wait(ctx); err != nil {
			return took, nil
		}
		recorded, err := f.document(ctx, client, by, source, entry, ships)
		switch {
		case errors.Is(err, sbom.ErrWrongProfile):
			// A publisher issues more than one kind of document and lists them
			// in one feed. A VEX statement set is read by the upload path and
			// not here: it replaces a publisher's whole answer for a product,
			// and a pass on a timer setting that aside is a judgment nobody
			// made.
			took.Skipped++
		case err != nil:
			// The mark stops where the failure is. Moved past a document that
			// could not be read, a publisher having one bad file would lose
			// everything they issued after it.
			return took, fmt.Errorf("read %s: %w", entry.address, err)
		default:
			took.Documents++
			took.Recorded += recorded
		}
		took.CaughtUpTo = entry.updated
	}
	return took, nil
}

// wait pauses between requests, answering early if the context ends.
func (f *Fetcher) wait(ctx context.Context) error {
	if f.Pause <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(f.Pause)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// feeds is where a publisher says their advisories are listed.
func (f *Fetcher) feeds(ctx context.Context, client *http.Client, address string) ([]string, error) {
	var described providerMetadata
	if err := f.json(ctx, client, address, &described); err != nil {
		return nil, fmt.Errorf("read what that publisher offers: %w", err)
	}
	var feeds []string
	for _, one := range described.Distributions {
		if one.ROLIE == nil {
			continue
		}
		for _, feed := range one.ROLIE.Feeds {
			if strings.TrimSpace(feed.URL) != "" {
				feeds = append(feeds, feed.URL)
			}
		}
	}
	return feeds, nil
}

// entry is one advisory a publisher lists, and when they last stamped it.
type entry struct {
	address string
	updated time.Time
}

// due is the entries stamped after the last one taken, oldest first and
// bounded.
//
// Oldest first, because the mark moves as each is read: taken newest first, a
// pass that stopped at its bound would leave the mark past everything it had
// not read.
func (f *Fetcher) due(ctx context.Context, client *http.Client, feeds []string,
	from time.Time) ([]entry, error) {

	var due []entry
	seen := map[string]bool{}
	for _, address := range feeds {
		if err := f.wait(ctx); err != nil {
			return nil, err
		}
		var feed rolieFeed
		if err := f.json(ctx, client, address, &feed); err != nil {
			return nil, fmt.Errorf("read that publisher's feed: %w", err)
		}
		for _, one := range feed.Feed.Entries {
			stamped, err := time.Parse(time.RFC3339, strings.TrimSpace(one.Updated))
			if err != nil {
				// An entry nobody can date cannot be placed against the mark,
				// so taking it would mean taking it again on every pass for
				// ever. Left alone rather than failing the feed: one
				// malformed entry is not a reason to stop reading a
				// publisher.
				continue
			}
			if !stamped.After(from) {
				continue
			}
			where := documentIn(one)
			if where == "" || seen[where] {
				continue
			}
			seen[where] = true
			due = append(due, entry{address: where, updated: stamped})
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].updated.Equal(due[j].updated) {
			return due[i].updated.Before(due[j].updated)
		}
		return due[i].address < due[j].address
	})
	if len(due) > MostPerPass {
		due = due[:MostPerPass]
	}
	return due, nil
}

// documentIn is where one feed entry says the document itself is.
//
// The content source first and the self link second. The standard asks for
// both and real feeds carry both, and where a publisher carries only one it is
// as often the one as the other.
func documentIn(one feedEntry) string {
	if address := strings.TrimSpace(one.Content.Source); address != "" {
		return address
	}
	for _, link := range one.Links {
		if strings.EqualFold(link.Rel, "self") && strings.TrimSpace(link.Href) != "" {
			return strings.TrimSpace(link.Href)
		}
	}
	return ""
}

// document reads one advisory and records what it says about a component this
// product ships.
func (f *Fetcher) document(ctx context.Context, client *http.Client, by access.Subject,
	source Source, one entry, ships map[string]bool) (int, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, one.address, nil)
	if err != nil {
		return 0, err
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("that publisher answered %s", res.Status)
	}

	most := f.limits.OrDefault().MaxBytes
	digest := sha256.New()
	counted := &counting{r: io.TeeReader(io.LimitReader(res.Body, most+1), digest)}
	advisory, err := sbom.ReadAdvisory(counted, f.limits)
	if counted.n > most {
		return 0, fmt.Errorf("that document is larger than the %d bytes this reads", most)
	}
	if err != nil {
		return 0, err
	}
	// The digest is the whole document by definition, so whatever the parser
	// left is read past exactly once. Drained into nothing, because the reader
	// above already tees into the digest.
	if _, err := io.Copy(io.Discard, counted); err != nil {
		return 0, fmt.Errorf("that document could not be read whole: %w", err)
	}
	if counted.n > most {
		return 0, fmt.Errorf("that document is larger than the %d bytes this reads", most)
	}

	statements := ours(advisory, ships)
	if len(statements) == 0 {
		// Nothing this product ships. Not recorded and not an error: most of
		// what a publisher issues is about the rest of their catalog, and a
		// row per claim would store a supplier's catalog rather than evidence
		// about ours.
		return 0, nil
	}
	if err := shaped(advisory); err != nil {
		return 0, err
	}

	var recorded int
	err = database.Within(ctx, f.db, func(ctx context.Context, tx bun.IDB) error {
		var err error
		recorded, _, err = finding.NewStore(tx).RecordStatements(ctx, by, source.ProductID,
			finding.Supplied{
				Source:     finding.FromAdvisory,
				Identifier: advisory.Identifier,
				Publisher:  advisory.Publisher,
				// The address it was fetched from, where an upload records the
				// name a client gave the file. Both answer "which document was
				// this", and for a fetched one the address is the answer that
				// can be checked.
				Document: one.address,
				Digest:   hex.EncodeToString(digest.Sum(nil)),
			}, statements)
		return err
	})
	if err != nil {
		return 0, err
	}
	return recorded, nil
}

// shaped refuses an advisory whose two names do not fit what a claim records.
//
// Both are part of the key a later revision supersedes on and both are stored
// in a column of a fixed width. Refused rather than shortened: two advisories
// agreeing for the width of the column would collapse into one, and a revision
// of one would set aside claims it has nothing to do with.
func shaped(advisory sbom.Advisory) error {
	if len([]rune(advisory.Publisher)) > finding.MostPublisher {
		return fmt.Errorf("who published it is longer than the %d characters this records",
			finding.MostPublisher)
	}
	if len([]rune(advisory.Identifier)) > finding.MostDocumentName {
		return fmt.Errorf("the name the publisher gave it is longer than the %d "+
			"characters this records", finding.MostDocumentName)
	}
	return nil
}

// ours is the claims in one advisory that name a component this product ships.
//
// The narrowing this path has that the upload path does not. An upload is one
// document somebody decided was worth reading; this is every document a
// publisher issues, and one real advisory about a kernel carries 95,139
// claims about a distribution's whole catalog.
//
// Matched on the component's name, folded, which is the name a claim is stored
// under and the name a finding is matched by. A claim about a component that
// arrives here tomorrow is not kept today — evidence follows what a product
// ships, and what it ships is the thing that moves slowly.
func ours(advisory sbom.Advisory, ships map[string]bool) []finding.Statement {
	statements := make([]finding.Statement, 0, len(advisory.Claims))
	for _, claim := range advisory.Claims {
		for _, at := range claim.Targets {
			named := at.ComponentNamed()
			if named == "" || !ships[graph.Folded(named)] {
				continue
			}
			statements = append(statements, finding.Statement{
				Vulnerability: claim.Vulnerability,
				Purl:          at.Purl,
				About:         at.VersionNamed(),
				Component:     named,
				Status:        string(claim.Status),
				Justification: claim.Justification,
				Statement:     claim.Statement,
			})
		}
	}
	return statements
}

// shipped is every component name this product holds, folded.
//
// One statement for the product rather than one per build: a product with
// forty builds shares nearly all of its components between them, and asking
// per build would be forty scans for one set.
func (f *Fetcher) shipped(ctx context.Context, productID int64) (map[string]bool, error) {
	var names []string
	err := f.db.NewSelect().
		Distinct().
		TableExpr(`"component" AS "c"`).
		ColumnExpr(`"c"."name_folded"`).
		Join(`JOIN "graph_node" AS "n" ON n.component_id = c.id`).
		Join(`JOIN "target" AS "tg" ON tg.id = n.target_id`).
		Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
		Where("st.product_id = ?", productID).
		Where("n.closed_scan_id IS NULL").
		Where("n.is_root = ?", false).
		Scan(ctx, &names)
	if err != nil {
		return nil, fmt.Errorf("read what this product ships: %w", err)
	}
	ships := make(map[string]bool, len(names))
	for _, name := range names {
		ships[name] = true
	}
	return ships, nil
}

// json fetches one document and reads it as the shape given.
func (f *Fetcher) json(ctx context.Context, client *http.Client, address string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("that publisher answered %s", res.Status)
	}
	counted := &counting{r: io.LimitReader(res.Body, mostListingBytes+1)}
	if err := json.NewDecoder(counted).Decode(into); err != nil {
		if counted.n > mostListingBytes {
			return fmt.Errorf("that listing is larger than the %d bytes this reads",
				mostListingBytes)
		}
		return err
	}
	if counted.n > mostListingBytes {
		return fmt.Errorf("that listing is larger than the %d bytes this reads",
			mostListingBytes)
	}
	return nil
}

// counting says how much was read, so a document cut off at a bound is
// reported as too large rather than as malformed.
type counting struct {
	r io.Reader
	n int64
}

func (c *counting) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// The two JSON files a publisher serves to say what they offer and where. The
// field names are the standard's rather than ours, which is why they are
// spelled as it spells them.

type providerMetadata struct {
	Distributions []distribution `json:"distributions"`
}

type distribution struct {
	ROLIE *rolie `json:"rolie,omitempty"`
}

type rolie struct {
	Feeds []feedDescription `json:"feeds"`
}

type feedDescription struct {
	URL string `json:"url"`
}

type rolieFeed struct {
	Feed feedBody `json:"feed"`
}

type feedBody struct {
	Entries []feedEntry `json:"entry"`
}

type feedEntry struct {
	Links   []link  `json:"link"`
	Updated string  `json:"updated"`
	Content content `json:"content"`
}

type link struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type content struct {
	Source string `json:"src"`
}
