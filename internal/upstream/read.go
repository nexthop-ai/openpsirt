// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/advisory"
	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/csaf"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/outward"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sbom"
)

// fetchTimeout bounds one request to an upstream. A listing or a document is
// read whole within it.
const fetchTimeout = 2 * time.Minute

// MostPerPass is how many documents one pass reads from one upstream. A pass
// that filled it leaves the upstream due, so a large first read drains over
// several passes rather than in one burst at the upstream's expense.
const MostPerPass = 200

// travels is the labels of a listing read: the ones served to everybody.
var travels = map[string]bool{"WHITE": true, "CLEAR": true}

// Client is the client every request to an upstream goes through: to the host
// its address names and nowhere else. roots are the certificate authorities
// the host is checked against, nil for the system's.
func Client(address *url.URL, roots *x509.CertPool) *http.Client {
	return outward.Pinned(fetchTimeout, address.Host, roots)
}

// Described is what an upstream's provider description says about itself:
// whose statements they are, and the key its documents are signed with.
type Described struct {
	Publisher   string
	Fingerprint string
	PublicKey   string
}

// Inspect reads an upstream's provider description and the key it names, for
// an administrator to confirm before trusting it.
//
// The key is fetched from the address the description gives and must carry
// the fingerprint the description names, so what is shown is the key the
// documents are checked against.
func Inspect(ctx context.Context, client *http.Client, address string) (Described, error) {
	meta, err := described(ctx, client, address)
	if err != nil {
		return Described{}, err
	}
	out := Described{Publisher: strings.TrimSpace(meta.Publisher.Name)}
	if out.Publisher == "" {
		return Described{}, refusal.New("that provider description names no publisher")
	}
	named, at := keyIn(meta)
	if named == "" {
		return out, nil
	}
	var armored []string
	for _, one := range at {
		where, err := resolve(address, one)
		if err != nil {
			return Described{}, refusal.Errorf("a key that provider description names is at no address: %v", err)
		}
		body, err := fetch(ctx, client, where, mostKeyBytes, nil)
		if err != nil {
			return Described{}, fmt.Errorf("read a key the upstream names: %w", err)
		}
		armored = append(armored, string(body))
	}
	_, fingerprint, err := keyringOf(strings.Join(armored, "\n"))
	if err != nil {
		return Described{}, err
	}
	if fingerprint != named {
		return Described{}, refusal.Errorf("the keys served are %s, and the provider description names %s",
			fingerprint, named)
	}
	out.Fingerprint, out.PublicKey = fingerprint, strings.Join(armored, "\n")
	return out, nil
}

// described fetches and reads a provider description.
func described(ctx context.Context, client *http.Client, address string) (*csaf.ProviderMetadata, error) {
	body, err := fetch(ctx, client, address, mostDescriptionBytes, nil)
	if err != nil {
		return nil, err
	}
	meta := new(csaf.ProviderMetadata)
	if err := json.Unmarshal(body, meta); err != nil {
		return nil, unreadable{err: refusal.Errorf("that provider description does not read: %v", err)}
	}
	bound.TextIn(meta)
	return meta, nil
}

// keyIn is the set of keys a provider description names, as FingerprintOf
// writes it, and where each is, or empty where it names none.
func keyIn(meta *csaf.ProviderMetadata) (fingerprints string, at []string) {
	var named []string
	for _, key := range meta.PublicKeys {
		if one := FingerprintOf(key.Fingerprint); one != "" {
			named = append(named, one)
			at = append(at, key.URL)
		}
	}
	return FingerprintOf(strings.Join(named, ",")), at
}

// resolve is an address a document names, read against the document's own
// address the way a link on a page is.
func resolve(base, named string) (string, error) {
	from, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	to, err := from.Parse(strings.TrimSpace(named))
	if err != nil {
		return "", err
	}
	return to.String(), nil
}

// cached is what one listing last answered with.
type cached struct {
	Tag      string `json:"tag,omitempty"`
	Modified string `json:"modified,omitempty"`
}

// listed is one document a listing names, and the moment it says the document
// last moved, as the listing wrote it.
type listed struct {
	address string
	at      string
	// skipped is an entry naming no document this can read.
	skipped bool
}

// Read is what reading one upstream did.
type Read struct {
	// Documents is how many documents were read and recorded, Withdrawn how
	// many the upstream stopped listing, and Refused how many failed their
	// digest or signature or could not be read.
	Documents int
	Withdrawn int
	Refused   int
	// Moved says something the upstream says changed, so its product's
	// builds are run again.
	Moved bool
	// Filled says the pass took as many documents as it reads at once.
	Filled bool
}

// Reader reads what upstreams publish.
type Reader struct {
	db     bun.IDB
	limits sbom.Limits
	// roots are the certificate authorities an upstream is checked against,
	// nil for the system's.
	roots *x509.CertPool
	// keep reports whether this replica still holds the lease on reading, and
	// is asked before each document. Nil reads without asking.
	keep func(context.Context) (bool, error)
	// most is how many documents one read takes: MostPerPass.
	most int
	now  func() time.Time
}

// NewReader returns a reader over db, checking an upstream's certificate
// against roots, nil for the system's authorities.
func NewReader(db bun.IDB, limits sbom.Limits, roots *x509.CertPool) *Reader {
	return &Reader{db: db, limits: limits, roots: roots, most: MostPerPass,
		now: func() time.Time { return time.Now().UTC() }}
}

// From reads one upstream: its description, its listings, and every document
// listed that moved since it was last read. What it read is recorded however
// the read went.
func (r *Reader) From(ctx context.Context, up Upstream) (Read, error) {
	var took Read
	address, err := Address(up.URL)
	if err != nil {
		return took, err
	}
	client := Client(address, r.roots)
	meta, err := described(ctx, client, up.URL)
	if err != nil {
		// However the description failed — not found, refused, a TLS fault,
		// a timeout — nothing is withdrawn. What the upstream said stands
		// until a read that succeeds says otherwise.
		return took, NewStore(r.db).reached(ctx, up, up.Listings, up.KeyOffered, err, false)
	}
	if offered, _ := keyIn(meta); offered != up.Fingerprint {
		recorded := offered
		if recorded == "" {
			recorded = NoKey
		}
		return took, NewStore(r.db).reached(ctx, up, up.Listings, recorded, describe(offered, up.Fingerprint), false)
	}
	var keyring openpgp.EntityList
	if up.PublicKey != "" {
		if keyring, _, err = keyringOf(up.PublicKey); err != nil {
			return took, NewStore(r.db).reached(ctx, up, up.Listings, "", err, false)
		}
	}

	held := map[string]cached{}
	if up.Listings != "" {
		_ = json.Unmarshal([]byte(up.Listings), &held)
	}
	entries, kept, moved, skipped, err := r.listings(ctx, client, up.URL, meta, held)
	if err != nil {
		return took, NewStore(r.db).reached(ctx, up, up.Listings, "", err, false)
	}
	if !moved {
		return took, NewStore(r.db).reached(ctx, up, up.Listings, "", nil, false)
	}

	var documents []Document
	if err := r.db.NewSelect().Model(&documents).Where(`"ud"."upstream_id" = ?`, up.ID).
		Scan(ctx); err != nil {
		return took, fmt.Errorf("read what was read of an upstream: %w", err)
	}
	recorded := make(map[string]Document, len(documents))
	for _, one := range documents {
		recorded[one.URL] = one
	}
	current := make(map[string]bool, len(entries))
	var refused []error
	for _, one := range entries {
		current[one.address] = true
		if was, ok := recorded[one.address]; ok && was.ListedAt == one.at {
			continue
		}
		if took.Documents+took.Refused >= r.most {
			took.Filled = true
			break
		}
		// The lease is asked for again before each document, so a slow read
		// never runs on past it beside a second replica's. One lost leaves the
		// read incomplete and the upstream due.
		if r.keep != nil {
			if mine, err := r.keep(ctx); err != nil || !mine {
				took.Filled = true
				break
			}
		}
		changed, err := r.document(ctx, client, up, one, keyring)
		var refusedDoc unreadable
		switch {
		case errors.As(err, &refusedDoc):
			took.Refused++
			refused = append(refused, fmt.Errorf("%s: %w", one.address, err))
			continue
		case err != nil:
			return took, NewStore(r.db).reached(ctx, up, up.Listings, "", err, false)
		}
		took.Documents++
		took.Moved = took.Moved || changed
	}
	// Withdrawn only from a complete read: every listing read whole and every
	// document that moved taken and checked. A pass that left any behind
	// withdraws nothing, so a document cannot read as absent because the
	// pass stopped short of it. In order, so two reads withdrawing the same
	// documents do it alike.
	complete := !took.Filled && took.Refused == 0 && skipped == 0
	for _, address := range slices.Sorted(maps.Keys(recorded)) {
		if current[address] || !complete {
			continue
		}
		if err := r.withdraw(ctx, up, address); err != nil {
			return took, NewStore(r.db).reached(ctx, up, up.Listings, "", err, false)
		}
		took.Withdrawn++
		took.Moved = true
	}

	// A pass that left documents unread or refused keeps no validator, so
	// the next pass reads the listings whole and comes back for them.
	listings := kept
	if took.Filled || took.Refused > 0 {
		listings = ""
	}
	var failed error
	switch {
	case len(refused) > 0:
		failed = refusal.Errorf("%d of what the upstream lists could not be taken; the last: %v",
			len(refused), refused[len(refused)-1])
	case skipped > 0:
		failed = refusal.Errorf("%d entries of what the upstream lists name no document this can read, "+
			"so nothing it stopped listing is withdrawn", skipped)
	}
	return took, NewStore(r.db).reached(ctx, up, listings, "", failed, took.Filled)
}

// listings reads every listing a provider description names, answering the
// documents listed, the validators to ask with next time, and whether any
// listing moved since it was last read.
//
// A feed where the description names one, and the directory's list of
// changes where it names none. Only the labels served to everybody. Where any
// listing moved, every listing is read whole, because a document no listing
// names any more is withdrawn and that is only known from all of them.
func (r *Reader) listings(ctx context.Context, client *http.Client, base string,
	meta *csaf.ProviderMetadata, held map[string]cached) ([]listed, string, bool, int, error) {

	var addresses []string
	for _, dist := range meta.Distributions {
		if dist.ROLIE == nil {
			continue
		}
		for _, feed := range dist.ROLIE.Feeds {
			if !travels[strings.ToUpper(strings.TrimSpace(feed.TLPLabel))] {
				continue
			}
			if where, err := resolve(base, feed.URL); err == nil {
				addresses = append(addresses, where)
			}
		}
	}
	feeds := len(addresses) > 0
	if !feeds {
		for _, dist := range meta.Distributions {
			if strings.TrimSpace(dist.DirectoryURL) == "" {
				continue
			}
			directory := strings.TrimSuffix(strings.TrimSpace(dist.DirectoryURL), "/") + "/"
			if where, err := resolve(base, directory+"changes.csv"); err == nil {
				addresses = append(addresses, where)
			}
		}
	}
	if len(addresses) == 0 {
		return nil, "", false, 0, refusal.New("that provider description names no feed and no directory served to everybody")
	}
	slices.Sort(addresses)
	addresses = slices.Compact(addresses)

	read := func(validators bool) ([]listed, map[string]cached, int, error) {
		kept := map[string]cached{}
		var out []listed
		unchanged := 0
		for _, address := range addresses {
			validator := &cached{}
			if validators {
				if was, ok := held[address]; ok {
					validator.Tag, validator.Modified = was.Tag, was.Modified
				}
			}
			body, err := fetch(ctx, client, address, mostListingBytes, validator)
			switch {
			case errors.Is(err, errNotModified):
				kept[address] = held[address]
				unchanged++
				continue
			case err != nil:
				return nil, nil, 0, err
			}
			kept[address] = *validator
			var entries []listed
			if feeds {
				entries, err = fromFeed(address, body)
			} else {
				entries, err = fromChanges(address, body)
			}
			if err != nil {
				return nil, nil, 0, err
			}
			out = append(out, entries...)
		}
		return out, kept, unchanged, nil
	}
	out, kept, unchanged, err := read(true)
	switch {
	case err != nil:
		return nil, "", false, 0, err
	case unchanged == len(addresses):
		return nil, encoded(kept), false, 0, nil
	case unchanged > 0:
		// One listing answered that nothing moved and another that something
		// did: every one is read whole.
		if out, kept, _, err = read(false); err != nil {
			return nil, "", false, 0, err
		}
	}
	skipped := 0
	out = slices.DeleteFunc(out, func(one listed) bool {
		if one.skipped {
			skipped++
		}
		return one.skipped
	})
	slices.SortFunc(out, func(a, b listed) int { return strings.Compare(a.address, b.address) })
	out = slices.CompactFunc(out, func(a, b listed) bool { return a.address == b.address })
	return out, encoded(kept), true, skipped, nil
}

// encoded is the validators as they are stored.
func encoded(kept map[string]cached) string {
	if len(kept) == 0 {
		return ""
	}
	body, err := json.Marshal(kept)
	if err != nil || len(body) > mostListingValidators {
		return ""
	}
	return string(body)
}

// mostListingValidators bounds what is kept of the validators.
const mostListingValidators = 64 << 10

// fromFeed reads the documents one feed lists.
func fromFeed(address string, body []byte) ([]listed, error) {
	var feed csaf.Feed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, unreadable{err: refusal.Errorf("that feed does not read: %v", err)}
	}
	bound.TextIn(&feed)
	var out []listed
	for _, entry := range feed.Feed.Entries {
		at := strings.TrimSpace(entry.Updated)
		named := strings.TrimSpace(entry.Content.Source)
		if named == "" {
			for _, link := range entry.Links {
				if strings.EqualFold(link.Rel, "self") {
					named = strings.TrimSpace(link.Href)
					break
				}
			}
		}
		out = append(out, entryOf(address, named, at))
	}
	return out, nil
}

// entryOf is one document a listing names, or an entry that cannot be read
// where it names no document or no moment, or an address this cannot record.
// An entry that cannot be read leaves the listing unread in full.
func entryOf(listing, named, at string) listed {
	if at == "" || named == "" {
		return listed{skipped: true}
	}
	where, err := resolve(listing, named)
	if err != nil || len(where) > MostURL {
		return listed{skipped: true}
	}
	return listed{address: where, at: bound.HeadRunes(at, database.NameWidth)}
}

// fromChanges reads the documents a directory's list of changes names: a path
// relative to the directory, and the moment it last moved.
func fromChanges(address string, body []byte) ([]listed, error) {
	rows := csv.NewReader(bytes.NewReader(body))
	rows.FieldsPerRecord = -1
	var out []listed
	for {
		row, err := rows.Read()
		switch {
		case errors.Is(err, io.EOF):
			return out, nil
		case err != nil:
			return nil, unreadable{err: refusal.Errorf("that list of changes does not read: %v", err)}
		case len(row) < 2:
			out = append(out, listed{skipped: true})
			continue
		}
		out = append(out, entryOf(address, strings.TrimSpace(row[0]), strings.TrimSpace(row[1])))
	}
}

// errWithdrawn says the upstream stopped being trusted as it was while a pass
// ran.
var errWithdrawn = refusal.New("that upstream is no longer trusted as it was")

// document reads one document, checks it against the digest and the signature
// served beside it, and records what it says, answering whether what it says
// moved.
func (r *Reader) document(ctx context.Context, client *http.Client, up Upstream, one listed,
	keyring openpgp.EntityList) (bool, error) {

	body, err := fetch(ctx, client, one.address, mostDocumentBytes, nil)
	if err != nil {
		return false, err
	}
	if err := checkDigest(ctx, client, one.address, body); err != nil {
		return false, err
	}
	if keyring != nil {
		if err := checkSignature(ctx, client, one.address, body, keyring); err != nil {
			return false, err
		}
	}
	tracking, ours, err := trackingOf(body)
	if err != nil {
		return false, err
	}
	// A security advisory is listed beside the VEX documents and says
	// nothing this reads, so it is recorded as read with nothing kept.
	said, err := sbom.ReadSuppressions(bytes.NewReader(body), r.limits)
	switch {
	case errors.Is(err, sbom.ErrWrongProfile):
		said = nil
	case err != nil:
		return false, unreadable{err: err}
	}
	statements := statementsOf(said, ours)
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	moved := false
	err = database.Within(ctx, r.db, func(ctx context.Context, tx bun.IDB) error {
		still, err := standing(ctx, tx, up)
		if err != nil {
			return err
		}
		if still == nil {
			return errWithdrawn
		}
		was, err := recordedAt(ctx, tx, up, one.address)
		if err != nil {
			return err
		}
		moved = was.Digest != digest
		if was.ID != 0 && was.TrackingID != tracking {
			// The address now holds another document: what the one
			// before it said is set aside.
			if _, _, err := finding.NewStore(tx).RecordStatements(ctx, recordedAs(up), up.ProductID,
				supplied(up, was.TrackingID, was.URL, was.Digest), nil); err != nil {
				return err
			}
		}
		if _, _, err := finding.NewStore(tx).RecordStatements(ctx, recordedAs(up), up.ProductID,
			supplied(up, tracking, one.address, digest), statements); err != nil {
			return err
		}
		now := r.now().Truncate(time.Microsecond)
		if was.ID == 0 {
			_, err = tx.NewInsert().Model(&Document{
				UpstreamID: up.ID, URL: one.address, URLDigest: digestOf(one.address),
				TrackingID: tracking, ListedAt: one.at, Digest: digest, RecordedAt: now,
			}).Exec(ctx)
		} else {
			_, err = tx.NewUpdate().Model((*Document)(nil)).
				Set(`"tracking_id" = ?`, tracking).Set(`"listed_at" = ?`, one.at).
				Set(`"digest" = ?`, digest).Set(`"recorded_at" = ?`, now).
				Where(`"id" = ?`, was.ID).Exec(ctx)
		}
		if err != nil {
			return fmt.Errorf("record a document read from an upstream: %w", err)
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return moved, nil
}

// recordedAt is what was last recorded of the document at an address, read
// inside the transaction that replaces it; empty where nothing was.
func recordedAt(ctx context.Context, tx bun.IDB, up Upstream, address string) (Document, error) {
	var was Document
	err := tx.NewSelect().Model(&was).
		Where(`"ud"."upstream_id" = ?`, up.ID).
		Where(`"ud"."url_digest" = ?`, digestOf(address)).
		Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Document{}, nil
	case err != nil:
		return Document{}, fmt.Errorf("read what was recorded of a document: %w", err)
	}
	return was, nil
}

// withdraw sets aside everything a document the upstream stopped listing said,
// and forgets it was read.
func (r *Reader) withdraw(ctx context.Context, up Upstream, address string) error {
	return database.Within(ctx, r.db, func(ctx context.Context, tx bun.IDB) error {
		still, err := standing(ctx, tx, up)
		if err != nil {
			return err
		}
		if still == nil {
			return errWithdrawn
		}
		was, err := recordedAt(ctx, tx, up, address)
		if err != nil || was.ID == 0 {
			return err
		}
		// The same document read at another address — an upstream that
		// moved — already replaced what this one said, so only the record
		// of where it was read goes.
		elsewhere, err := tx.NewSelect().Model((*Document)(nil)).
			Where(`"ud"."upstream_id" = ?`, up.ID).
			Where(`"ud"."tracking_id" = ?`, was.TrackingID).
			Where(`"ud"."id" <> ?`, was.ID).
			Exists(ctx)
		if err != nil {
			return fmt.Errorf("read whether a document moved: %w", err)
		}
		if elsewhere {
			_, err := tx.NewDelete().Model((*Document)(nil)).Where(`"id" = ?`, was.ID).Exec(ctx)
			return err
		}
		if _, _, err := finding.NewStore(tx).RecordStatements(ctx, recordedAs(up), up.ProductID,
			supplied(up, was.TrackingID, was.URL, was.Digest), nil); err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*Document)(nil)).Where(`"id" = ?`, was.ID).Exec(ctx); err != nil {
			return fmt.Errorf("forget a document an upstream withdrew: %w", err)
		}
		return nil
	})
}

// supplied is where an upstream's statements came from: one of its documents.
func supplied(up Upstream, tracking, address, digest string) finding.Supplied {
	return finding.Supplied{
		Source: finding.FromUpstream, Identifier: tracking, Publisher: up.Publisher,
		Document: address, Digest: digest,
	}
}

// recordedAs is who an upstream's statements are recorded as brought in by:
// the administrator who trusted it, which is the one decision anybody made.
func recordedAs(up Upstream) access.Subject {
	return access.Subject{Kind: access.Person, ID: up.TrustedBy}
}

// trackingOf is the tracking identifier a document names itself by, and
// whether it names this deployment's software as what generated it.
func trackingOf(body []byte) (string, bool, error) {
	var named struct {
		Document struct {
			Tracking struct {
				ID        string `json:"id"`
				Generator struct {
					Engine struct {
						Name string `json:"name"`
					} `json:"engine"`
				} `json:"generator"`
			} `json:"tracking"`
		} `json:"document"`
	}
	if err := json.Unmarshal(body, &named); err != nil {
		return "", false, unreadable{err: refusal.Errorf("that document does not read: %v", err)}
	}
	tracking := strings.TrimSpace(bound.Text(named.Document.Tracking.ID))
	if tracking == "" || len([]rune(tracking)) > finding.MostDocumentName {
		return "", false, unreadable{err: refusal.Errorf("that document names itself in none of the "+
			"%d characters this records", finding.MostDocumentName)}
	}
	ours := strings.EqualFold(strings.TrimSpace(named.Document.Tracking.Generator.Engine.Name),
		advisory.EngineName)
	return tracking, ours, nil
}

// statementsOf is what an upstream's document says, as it is recorded.
//
// A statement naming a component alone, by its package identifier, holds for
// anybody shipping that component, and is applied at that component and
// version (REQ-84) — where the document was written by this deployment's
// software, whose convention that is. The format has no word for whom a
// statement holds for, so the same shape from any other software says nothing
// about it, and is offered for review. A statement naming the component
// inside something of the upstream's — its build, or what pulls the component
// in there — depends on that, and places nothing here: it is offered for
// review.
func statementsOf(said []sbom.Suppression, ours bool) []finding.Statement {
	var out []finding.Statement
	for _, claim := range said {
		for _, at := range claim.Targets {
			one := finding.StatementOf(claim, at)
			one.Placement = ""
			if ours && at.Within == nil && graph.PartsOfPurl(at.Purl).Name != "" {
				one.Placement = finding.PlacedAnybody
			}
			out = append(out, one)
		}
	}
	return out
}
