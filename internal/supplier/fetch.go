package supplier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
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
// wake.
//
// A publisher's listing holds everything they have ever issued, and a supplier
// having a busy week is not a reason to make a hundred requests of them in a
// minute. What is not taken this time is taken on the next wake rather than
// waiting for the interval: a pass that filled its bound leaves the supplier
// due, so a backlog drains at this rate instead of at this rate per day.
const MostPerPass = 20

// MostFeeds bounds how many listings one publisher may point at.
//
// Nothing in the format bounds it, and a description within the size bound can
// name tens of thousands of addresses on the pinned host — which is a pass
// running for hours, holding every entry it has read, and outliving the lease
// that says it is the one reading (REQ-69). A publisher serves one listing per
// label they publish under, so this is far above any real directory.
const MostFeeds = 16

// mostListingBytes bounds each document that describes what a publisher offers.
//
// Separate from the bound on an advisory, because they are different shapes of
// thing. A listing is one entry per advisory a publisher has ever issued, so a
// distribution's runs to tens of thousands of entries; an advisory is one
// announcement. Neither bound protects the other.
const mostListingBytes = 64 << 20

// fetchTimeout bounds one request to a publisher.
//
// Scaled to what is being fetched rather than to somebody watching a page. The
// interactive budget the guarded client ships with is ten seconds, and a
// document bound at hundreds of megabytes cannot arrive inside it over an
// ordinary egress — which would make a large advisory one that fails on every
// pass for ever rather than one that is slow.
const fetchTimeout = 5 * time.Minute

// betweenAsks is the pause between one request to a supplier and the next.
//
// Deliberate politeness rather than a rate limit anybody gave us. A publisher
// serves their directory as a courtesy, and a tool that walks it as fast as it
// can is the reason such things end up behind an authenticating proxy.
const betweenAsks = 250 * time.Millisecond

// aheadBy is how far past now a publisher's stamp may be and still be read.
//
// A clock that is a little out is ordinary and a stamp in 2099 is not. The mark
// moves forward only, so one entry stamped far ahead would carry it past
// everything the publisher issues between now and then — and because the fetch
// itself succeeds, the supplier goes on reading as healthy while it takes
// nothing.
const aheadBy = time.Hour

// travels are the labels a publisher serves to everybody.
//
// One listing per label, and only these two have to be reachable without
// arranging access. A publisher listing a restricted one beside a public one is
// ordinary, and reading it answers a refusal on every pass.
var travels = map[string]bool{"WHITE": true, "CLEAR": true}

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
	// Skipped is how many documents were not security advisories, and Refused
	// how many could not be read at all. A refusal is about one document and
	// the pass steps over it; what holds the mark is a failure to reach the
	// publisher.
	Skipped int
	Refused int
	// Checked is how many of the documents read were compared against a
	// digest the publisher serves beside them. The rest came from a publisher
	// serving none.
	Checked int
	// Filled says the pass stopped at its bound rather than because there was
	// nothing left, which is what leaves the supplier due for the next wake.
	Filled bool
	// CaughtUpTo and Mark are how far this pass read, which is where the next
	// one starts.
	CaughtUpTo time.Time
	Mark       string
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
	// Now is the clock a publisher's own stamps are judged against, so a test
	// can hand one a date in the future without waiting for the future.
	Now func() time.Time
	// History is how far before its configuration a supplier is first read
	// from. The pass sets it from the deployment's setting on every wake; a
	// fetcher built by hand reads nothing from before its configuration.
	History time.Duration
}

// NewFetcher returns a fetcher over db, reaching real suppliers.
func NewFetcher(db bun.IDB, limits sbom.Limits) *Fetcher {
	return &Fetcher{
		db: db, limits: limits.OrDefault(),
		Client: func(host string) *http.Client {
			return outward.GuardedWithin(fetchTimeout, host)
		},
		Pause: betweenAsks,
		Now:   func() time.Time { return time.Now().UTC() },
	}
}

// unreadable says a document could not be read, as against the publisher
// serving it could not be reached.
//
// The two are different facts and the pass does different things with them. A
// document that is refused the same way every time — withdrawn and answering
// 404, larger than what is read, malformed, naming a publisher longer than a
// claim records — is stepped over and the mark moves past it. A publisher that
// cannot be reached holds the mark, because what is behind it has not been
// seen.
//
// Read the other way round, one permanently unreadable document stops a
// supplier for ever.
type unreadable struct{ err error }

func (u unreadable) Error() string { return u.err.Error() }
func (u unreadable) Unwrap() error { return u.err }

// From reads one supplier and records what is about a component this product
// ships.
//
// The whole pass is bounded twice over: at most MostPerPass documents, and only
// those the publisher listed past the mark. What comes back is evidence and a
// prefill and decides nothing (REQ-31).
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
	// from. A listing or a document somewhere else is refused rather than
	// followed: the addresses inside a publisher's directory come from
	// outside, and fetching whatever they name is the request-forgery
	// primitive the guarded client exists to refuse (REQ-69).
	client := f.Client(at.Hostname())

	listed, err := f.listings(ctx, client, source.URL)
	if err != nil {
		return took, err
	}
	if len(listed) == 0 {
		return took, fmt.Errorf("that publisher's directory names nothing to read: it " +
			"describes neither a feed of advisories nor a directory of them")
	}

	at2, mark := source.From(f.History)
	due, filled, err := f.due(ctx, client, listed, at2, mark)
	if err != nil {
		return took, err
	}
	took.Filled = filled
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

	sums := &digests{}
	for _, one := range due {
		if ctx.Err() != nil {
			return took, nil
		}
		if err := f.wait(ctx); err != nil {
			return took, nil
		}
		recorded, checked, err := f.document(ctx, client, by, source, one, ships, sums)
		switch {
		case errors.Is(err, errWithdrawn):
			// The supplier was withdrawn while this pass was running. Nothing
			// after it is fetched, and the mark stays where the last recorded
			// document left it.
			return took, nil
		case errors.Is(err, sbom.ErrWrongProfile):
			// A publisher issues more than one kind of document and lists them
			// in one directory. A VEX statement set is read by the upload path
			// and not here: it replaces a publisher's whole answer for a
			// product, and a pass on a timer setting that aside is a judgment
			// nobody made.
			took.Skipped++
		case errors.As(err, &unreadable{}):
			// About this document rather than about the publisher, so the pass
			// steps over it. Held instead, one withdrawn advisory still listed
			// would stop everything issued after it, for ever.
			took.Refused++
		case ctx.Err() != nil:
			return took, nil
		case err != nil:
			// The publisher could not be reached. The mark stops here: moved
			// past, everything behind it would be skipped without having been
			// seen.
			return took, fmt.Errorf("read %s: %w", one.address, err)
		default:
			took.Documents++
			took.Recorded += recorded
			if checked {
				took.Checked++
			}
		}
		took.CaughtUpTo, took.Mark = one.updated, Mark(one.address)
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

// listing is one place a publisher lists what they have issued.
//
// The format offers two shapes and a publisher may serve either: a ROLIE feed,
// which is JSON and carries a stamp per entry, and a directory, which is a list
// of changes beside the documents. Both are read, because the largest publisher
// of these documents serves only the second and a reader that knows one takes
// the other's description, finds nothing, and reports that it worked.
type listing struct {
	address string
	// feed says which of the two shapes this is.
	feed bool
}

// listings is where a publisher says their advisories are listed.
//
// Only what travels to everybody. The format has one listing per label, and a
// publisher offering a restricted one beside a public one is ordinary — read,
// it answers a refusal on every pass and the public one beside it is never
// reached.
func (f *Fetcher) listings(ctx context.Context, client *http.Client,
	address string) ([]listing, error) {

	var described providerMetadata
	if err := f.json(ctx, client, address, &described); err != nil {
		return nil, fmt.Errorf("read what that publisher offers: %w", err)
	}
	var out []listing
	for _, one := range described.Distributions {
		if one.ROLIE != nil {
			for _, feed := range one.ROLIE.Feeds {
				if strings.TrimSpace(feed.URL) == "" ||
					!travels[strings.ToUpper(strings.TrimSpace(feed.TLPLabel))] {
					continue
				}
				out = append(out, listing{address: feed.URL, feed: true})
			}
			continue
		}
		if where := strings.TrimSpace(one.DirectoryURL); where != "" {
			out = append(out, listing{address: strings.TrimRight(where, "/") + "/" + changesFile})
		}
	}
	if len(out) > MostFeeds {
		return nil, fmt.Errorf("that publisher lists %d places to read from, past the %d "+
			"this reads", len(out), MostFeeds)
	}
	return out, nil
}

// changesFile is what a directory calls its list of what moved and when.
const changesFile = "changes.csv"

// entry is one advisory a publisher lists, and when they last stamped it.
type entry struct {
	address string
	updated time.Time
	// sums is where a feed entry says the digests of the document are. A
	// directory names none, and its digests are found beside the document.
	sums []string
}

// due is the entries the publisher listed past the mark, oldest first and
// bounded, and whether the bound is what stopped it.
//
// Oldest first, because the mark moves as each is read: taken newest first, a
// pass that stopped at its bound would leave the mark past everything it had
// not read.
//
// A listing that cannot be read is stepped over rather than failing the
// supplier. A publisher serves one per label and only the public ones are read,
// but a label being unreadable today is not a reason to read none of the
// others.
func (f *Fetcher) due(ctx context.Context, client *http.Client, listed []listing,
	from time.Time, mark string) ([]entry, bool, error) {

	var due []entry
	var refused error
	read := 0
	seen := map[string]bool{}
	ceiling := f.now().Add(aheadBy)
	for _, one := range listed {
		if err := f.wait(ctx); err != nil {
			return nil, false, err
		}
		entries, err := f.entries(ctx, client, one)
		if err != nil {
			refused = err
			continue
		}
		read++
		for _, listedAt := range entries {
			// A stamp far in the future would carry the forward-only mark past
			// everything the publisher issues between now and then, and the
			// fetch itself succeeds — so the supplier reads as healthy while
			// it takes nothing.
			if listedAt.updated.After(ceiling) {
				continue
			}
			// Past the mark, where the mark is the pair the entries are
			// ordered by. On the moment alone, a publisher who stamps a batch
			// with one moment — or dates to the day — would have the rest of
			// that group skipped for ever by a pass that stopped inside it.
			where := Mark(listedAt.address)
			if listedAt.updated.Before(from) ||
				(listedAt.updated.Equal(from) && where <= mark) {
				continue
			}
			if seen[listedAt.address] {
				continue
			}
			seen[listedAt.address] = true
			due = append(due, listedAt)
		}
	}
	if read == 0 && refused != nil {
		return nil, false, fmt.Errorf("read what that publisher lists: %w", refused)
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].updated.Equal(due[j].updated) {
			return due[i].updated.Before(due[j].updated)
		}
		return Mark(due[i].address) < Mark(due[j].address)
	})
	if len(due) > MostPerPass {
		return due[:MostPerPass], true, nil
	}
	return due, false, nil
}

// now is the clock, defaulting where a caller built a fetcher by hand.
func (f *Fetcher) now() time.Time {
	if f.Now == nil {
		return time.Now().UTC()
	}
	return f.Now().UTC()
}

// entries is what one listing says a publisher has issued.
func (f *Fetcher) entries(ctx context.Context, client *http.Client,
	one listing) ([]entry, error) {

	if one.feed {
		return f.fromFeed(ctx, client, one.address)
	}
	return f.fromChanges(ctx, client, one.address)
}

// fromFeed reads a ROLIE feed.
func (f *Fetcher) fromFeed(ctx context.Context, client *http.Client,
	address string) ([]entry, error) {

	var feed rolieFeed
	if err := f.json(ctx, client, address, &feed); err != nil {
		return nil, err
	}
	out := make([]entry, 0, len(feed.Feed.Entries))
	for _, one := range feed.Feed.Entries {
		stamped, err := time.Parse(time.RFC3339, strings.TrimSpace(one.Updated))
		if err != nil {
			// An entry nobody can date cannot be placed against the mark, so
			// taking it would mean taking it again on every pass for ever.
			// Left alone rather than failing the listing: one malformed entry
			// is not a reason to stop reading a publisher.
			continue
		}
		where := documentIn(one)
		if !listable(where) {
			continue
		}
		out = append(out, entry{address: where, updated: stamped, sums: sumsIn(one)})
	}
	return out, nil
}

// sumsIn is where one feed entry says the digests of its document are.
func sumsIn(one feedEntry) []string {
	var out []string
	for _, link := range one.Links {
		if strings.EqualFold(link.Rel, "hash") && strings.TrimSpace(link.Href) != "" {
			out = append(out, strings.TrimSpace(link.Href))
		}
	}
	return out
}

// fromChanges reads a directory's list of what moved and when.
//
// Two columns, the path of a document relative to the directory and the moment
// it was released. The path is resolved against the list's own address rather
// than joined as text, because a publisher writes it the way a link on their
// own page is written.
func (f *Fetcher) fromChanges(ctx context.Context, client *http.Client,
	address string) ([]entry, error) {

	body, err := f.fetch(ctx, client, address, mostListingBytes)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(address)
	if err != nil {
		return nil, err
	}
	rows := csv.NewReader(strings.NewReader(string(body)))
	// A publisher writing a header, a comment or a third column is writing a
	// file this still reads: what is needed is the first two fields.
	rows.FieldsPerRecord = -1
	var out []entry
	for {
		row, err := rows.Read()
		switch {
		case errors.Is(err, io.EOF):
			return out, nil
		case err != nil:
			return nil, fmt.Errorf("read that publisher's list of changes: %w", err)
		case len(row) < 2:
			continue
		}
		stamped, err := time.Parse(time.RFC3339, strings.TrimSpace(row[1]))
		if err != nil {
			continue
		}
		where, err := base.Parse(strings.TrimSpace(row[0]))
		if err != nil || !listable(where.String()) {
			continue
		}
		out = append(out, entry{address: where.String(), updated: stamped})
	}
}

// listable refuses an address a claim could not be recorded against.
//
// The address is stored on every claim the document leaves behind, and it comes
// from a listing a publisher writes. One past the width a claim records would
// fail that write on two of the four engines, after the document had been
// fetched and read (REQ-69).
func listable(address string) bool {
	address = strings.TrimSpace(address)
	return address != "" && len(address) <= MostURL
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

// errWithdrawn says the supplier stopped being configured while a pass ran.
var errWithdrawn = errors.New("that supplier is no longer read from")

// document reads one advisory and records what it says about a component this
// product ships, answering how many claims it left and whether a digest the
// publisher serves was compared against it.
func (f *Fetcher) document(ctx context.Context, client *http.Client, by access.Subject,
	source Source, one entry, ships map[string]bool, sums *digests) (int, bool, error) {

	body, err := f.fetch(ctx, client, one.address, f.limits.OrDefault().MaxBytes)
	if err != nil {
		return 0, false, err
	}
	checked, err := f.matches(ctx, client, one, body, sums)
	if err != nil {
		return 0, false, err
	}
	recorded, err := f.record(ctx, by, source, one, body, ships)
	return recorded, checked, err
}

// record reads one fetched advisory and writes what it says about a component
// this product ships.
func (f *Fetcher) record(ctx context.Context, by access.Subject, source Source, one entry,
	body []byte, ships map[string]bool) (int, error) {

	sum := sha256.Sum256(body)
	advisory, err := sbom.ReadAdvisory(strings.NewReader(string(body)), f.limits)
	if err != nil {
		// A document that cannot be parsed is refused the same way every time,
		// including the one this reader refuses on purpose — a statement set,
		// which is told apart above so it can be counted as what it is.
		if errors.Is(err, sbom.ErrWrongProfile) {
			return 0, err
		}
		return 0, unreadable{err}
	}
	if err := shaped(advisory); err != nil {
		return 0, unreadable{err}
	}

	statements := ours(advisory, ships)
	var recorded int
	err = database.Within(ctx, f.db, func(ctx context.Context, tx bun.IDB) error {
		// Asked inside the transaction rather than trusted from before it. A
		// pass takes minutes, and a supplier withdrawn during one goes on
		// fetching and recording — which is the request leaving this
		// deployment that withdrawing it was meant to stop.
		standing, err := NewStore(tx).Standing(ctx, tx, source.ID)
		if err != nil {
			return err
		}
		if standing == nil {
			return errWithdrawn
		}
		// Recorded even where nothing was kept. The write is the only thing
		// that sets aside what an earlier revision of this same advisory said,
		// so a publisher who corrects one by dropping the component we ship
		// would otherwise leave the old claim standing as evidence.
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
				Digest:   recording(sum[:], statements),
			}, statements)
		return err
	})
	if err != nil {
		return 0, err
	}
	return recorded, nil
}

// mostSumBytes bounds a digest file. One line holding a digest and a file name
// is well under it.
const mostSumBytes = 4 << 10

// algorithms are the digests a publisher may serve beside a document, by the
// suffix the format gives each file.
//
// Both, because publishers split between them. Measured on 2026-09-23: Red Hat
// and SUSE serve a SHA-256 file and no SHA-512 file; Cisco, NCSC-NL and Siemens
// serve a SHA-512 file and no SHA-256 file.
var algorithms = []struct {
	suffix string
	sum    func() hash.Hash
}{
	{".sha256", sha256.New},
	{".sha512", sha512.New},
}

// digests remembers, across one pass over one publisher, which digest file
// answered last, so it is asked for first.
//
// A publisher serves the same kind beside every document. Remembered, the file
// that is not there is asked for once a pass rather than once a document.
type digests struct{ first int }

// order is the algorithms in the order to ask for them.
func (d *digests) order() []int {
	if d.first == 0 {
		return []int{0, 1}
	}
	return []int{1, 0}
}

// matches compares a fetched document against the digest its publisher serves
// beside it, answering whether one was found.
//
// Where a feed entry names its digest files, those are read. Otherwise the
// file is looked for where the format puts it: the document's own address with
// the algorithm's suffix. A publisher serving neither is read without the
// check, which is what the format allows everybody short of its trusted
// provider role.
//
// A digest that does not match is about this document, so the pass steps over
// it. What was fetched is not what the publisher says they published, whether
// the transfer was cut, a mirror is behind, or the file was replaced; recorded,
// it would stand as the publisher's judgment.
func (f *Fetcher) matches(ctx context.Context, client *http.Client, one entry,
	body []byte, sums *digests) (bool, error) {

	for _, where := range one.sums {
		kind := algorithmOf(where)
		if kind < 0 {
			continue
		}
		found, err := f.compare(ctx, client, where, kind, body)
		if found || err != nil {
			return found, err
		}
	}
	for _, kind := range sums.order() {
		found, err := f.compare(ctx, client, one.address+algorithms[kind].suffix, kind, body)
		if err != nil {
			return false, err
		}
		if found {
			sums.first = kind
			return true, nil
		}
	}
	return false, nil
}

// algorithmOf is which algorithm a digest file's address names, or -1.
func algorithmOf(address string) int {
	for i, one := range algorithms {
		if strings.HasSuffix(strings.ToLower(address), one.suffix) {
			return i
		}
	}
	return -1
}

// compare fetches one digest file and checks the document against it,
// answering whether the file was there to compare.
//
// A refusal naming the file says the publisher does not serve that one, which
// is ordinary; a missing file is answered 404 by some and 403 by others. A
// file past the size of a digest file is not one either. A
// publisher that cannot be reached holds the mark, the way it does for the
// document.
func (f *Fetcher) compare(ctx context.Context, client *http.Client, address string,
	kind int, body []byte) (bool, error) {

	if err := f.wait(ctx); err != nil {
		return false, err
	}
	served, err := f.fetch(ctx, client, address, mostSumBytes)
	var refused unreadable
	switch {
	case errors.As(err, &refused):
		return false, nil
	case err != nil:
		return false, err
	}
	want, held := stated(served, kind)
	if !held {
		// A server answering every address with a page of its own serves no
		// digest, whatever status it gives. Refused, every document such a
		// publisher issues would be stepped over.
		return false, nil
	}
	sum := algorithms[kind].sum()
	sum.Write(body)
	if !bytes.Equal(sum.Sum(nil), want) {
		return true, unreadable{fmt.Errorf(
			"that document does not match the digest its publisher serves beside it")}
	}
	return true, nil
}

// stated is the digest a digest file holds, and whether it holds one.
//
// The file is what the usual checksum tools write: the digest in hexadecimal,
// then optionally the file name. Only the first field is read, because the name
// is the publisher's own and says nothing about the bytes.
func stated(served []byte, kind int) ([]byte, bool) {
	fields := strings.Fields(string(served))
	if len(fields) == 0 {
		return nil, false
	}
	want, err := hex.DecodeString(strings.ToLower(fields[0]))
	if err != nil || len(want) != algorithms[kind].sum().Size() {
		return nil, false
	}
	return want, true
}

// recording is what identifies this recording of a document.
//
// The bytes and what was kept of them, rather than the bytes alone. The store
// treats a document whose digest it already holds as one that changes nothing,
// and for a fetched document the bytes are not the whole of what decides which
// claims get written — the components the product ships that day are the other
// half. Keyed on the bytes alone, uploading the same advisory once a build
// ships a component the fetch had narrowed away is a no-op reporting success,
// and the claim the upload exists to add is never written.
func recording(document []byte, kept []finding.Statement) string {
	sum := sha256.New()
	sum.Write(document)
	names := make([]string, 0, len(kept))
	for _, one := range kept {
		names = append(names, one.Component+"@"+one.About)
	}
	sort.Strings(names)
	for _, name := range names {
		sum.Write([]byte{0})
		sum.Write([]byte(name))
	}
	return hex.EncodeToString(sum.Sum(nil))
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

// fetch reads one address, bounded, and answers what came back.
func (f *Fetcher) fetch(ctx context.Context, client *http.Client, address string,
	most int64) ([]byte, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		// A refusal that names this one address is about the document. A
		// publisher's listing still naming a withdrawn advisory is the
		// ordinary case, and a server having a bad day answers 5xx, which is
		// about reaching them.
		answered := fmt.Errorf("that publisher answered %s", res.Status)
		if res.StatusCode >= 400 && res.StatusCode < 500 {
			return nil, unreadable{answered}
		}
		return nil, answered
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, most+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > most {
		return nil, unreadable{fmt.Errorf(
			"that document is larger than the %d bytes this reads", most)}
	}
	return body, nil
}

// json fetches one document and reads it as the shape given.
func (f *Fetcher) json(ctx context.Context, client *http.Client, address string, into any) error {
	body, err := f.fetch(ctx, client, address, mostListingBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, into)
}

// The two JSON files a publisher serves to say what they offer and where. The
// field names are the standard's rather than ours, which is why they are
// spelled as it spells them.

type providerMetadata struct {
	Distributions []distribution `json:"distributions"`
}

type distribution struct {
	DirectoryURL string `json:"directory_url,omitempty"`
	ROLIE        *rolie `json:"rolie,omitempty"`
}

type rolie struct {
	Feeds []feedDescription `json:"feeds"`
}

type feedDescription struct {
	TLPLabel string `json:"tlp_label"`
	URL      string `json:"url"`
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
