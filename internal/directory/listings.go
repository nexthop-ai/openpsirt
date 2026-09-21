package directory

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The addresses the standard defines rather than leaves to a publisher: the
// schema a reader validates a document against, the scheme a feed states its
// subject under, and the term for a feed of these documents.
const (
	documentSchema  = "https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json"
	documentVersion = "2.0"
	feedScheme      = "urn:ietf:params:rolie:category:information-type"
	feedTerm        = "csaf"
	// metadataVersion is the version of the provider description's own
	// shape, which is the standard's and not this deployment's.
	metadataVersion = "2.0"
	// role is what this deployment claims to be. A provider writes the
	// documents, the lists and the feed; a trusted provider signs them, and
	// nothing here holds a key.
	role = "csaf_provider"
)

// listings writes the three files that say what the directory holds and the
// one that says what the directory is.
func (w *Writer) listings(ctx context.Context, published []entry) error {
	// The newest moment any of them was released, which is what the feed and
	// the provider description date themselves from. Taken from the documents
	// rather than from the clock, so that a pass over an unchanged directory
	// writes the bytes it wrote last time: dated now, every file would move
	// every hour and every reader would fetch the lot again.
	newest := published[0].Released
	for _, one := range published {
		if one.Released.After(newest) {
			newest = one.Released
		}
	}

	if err := w.put(ctx, indexFile, index(published), "text/plain; charset=utf-8"); err != nil {
		return err
	}
	if err := w.put(ctx, changesFile, changes(published), "text/csv; charset=utf-8"); err != nil {
		return err
	}
	feed, err := json.MarshalIndent(w.feed(published, newest), "", "  ")
	if err != nil {
		return fmt.Errorf("write the advisory feed: %w", err)
	}
	if err := w.put(ctx, feedFile, append(feed, '\n'), "application/json"); err != nil {
		return err
	}
	described, err := json.MarshalIndent(w.described(newest), "", "  ")
	if err != nil {
		return fmt.Errorf("write the provider description: %w", err)
	}
	return w.put(ctx, metadataFile, append(described, '\n'), "application/json")
}

// index is every document in the directory, one path per line.
//
// Ordered by path, which orders by year and then by identifier. The standard
// asks for a list rather than an order, and one an engine chose is a file
// that differs between two passes that found the same documents.
func index(published []entry) []byte {
	paths := make([]string, 0, len(published))
	for _, one := range published {
		paths = append(paths, one.Path)
	}
	sort.Strings(paths)
	return []byte(strings.Join(paths, "\n") + "\n")
}

// changes is every document and when its current revision was released,
// newest first.
//
// The order is the standard's and is what makes the file useful: a reader
// who fetched yesterday reads until the dates stop being new to them. The
// path breaks a tie, because two advisories published in the same moment
// would otherwise come back in either order.
//
// Each field is quoted, which the standard's own example does. Nothing in
// either field can carry a quote: a path is a year and a name the filename
// rule has already reduced to letters, digits, a plus, a hyphen and an
// underscore, and a date is a date.
func changes(published []entry) []byte {
	rows := make([]entry, len(published))
	copy(rows, published)
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].Released.Equal(rows[j].Released) {
			return rows[i].Released.After(rows[j].Released)
		}
		return rows[i].Path < rows[j].Path
	})
	var out strings.Builder
	for _, one := range rows {
		fmt.Fprintf(&out, "%q,%q\n", one.Path, stamp(one.Released))
	}
	return []byte(out.String())
}

// stamp is a moment as every file here writes one.
//
// The same spelling the documents use, so that a date in the list of changes
// and the date inside the document it names are the same string rather than
// two renderings a reader has to decide are equal.
func stamp(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }

// feed is the directory as a ROLIE feed.
//
// One feed, because the directory carries one label. The standard asks that
// every document of a label be in a single feed, and a second feed here would
// be a second label this deployment does not serve.
func (w *Writer) feed(published []entry, newest time.Time) rolieFeed {
	entries := make([]feedEntry, 0, len(published))
	for _, one := range published {
		address := w.who.At(one.Path)
		entries = append(entries, feedEntry{
			ID:    one.ID,
			Title: one.Title,
			Links: []link{
				{Rel: "self", Href: address},
				// The hash beside the document, which the standard requires
				// the feed to name wherever one exists. A reader checking
				// integrity should not have to guess the address of the file
				// that answers for it.
				{Rel: "hash", Href: w.who.At(one.Path + hashSuffix)},
			},
			released:  one.Released,
			Published: stamp(one.Opened),
			Updated:   stamp(one.Released),
			Summary:   summary{Content: one.Summary},
			Content:   content{Type: "application/json", Source: address},
			Format:    format{Schema: documentSchema, Version: documentVersion},
		})
	}
	// On the moment rather than on the way it is written. The spelling trims
	// trailing zeros, so a half second and fifty-one hundredths differ first
	// at a digit against the letter that ends the one without it, and the
	// later of the two sorts first.
	sort.Slice(entries, func(i, j int) bool {
		if !entries[i].released.Equal(entries[j].released) {
			return entries[i].released.After(entries[j].released)
		}
		return entries[i].ID < entries[j].ID
	})
	where := w.who.At(feedFile)
	return rolieFeed{Feed: feedBody{
		ID:         w.feedName(),
		Title:      w.who.Name + " CSAF advisories (TLP:" + travels + ")",
		Links:      []link{{Rel: "self", Href: where}},
		Categories: []category{{Scheme: feedScheme, Term: feedTerm}},
		Updated:    stamp(newest),
		Entries:    entries,
	}}
}

// feedName is what the feed calls itself.
//
// A token rather than the feed's own address, which would be the obvious
// unique name and is refused: the shape a reader validates a feed against
// allows letters, digits, a plus, a hyphen, an underscore and a dot, and an
// address carries a colon and two slashes.
//
// The prefix a deployment mints its advisories under goes in front of it,
// because a reader collecting feeds from several publishers holds several of
// these and the prefix is the short name this publisher is already recognized
// by. A deployment with no prefix mints no advisory and so publishes no feed,
// which leaves the bare name for a reader who somehow has one.
func (w *Writer) feedName() string {
	if w.who.Prefix == "" {
		return "csaf-feed-tlp-white"
	}
	return strings.ToLower(w.who.Prefix) + "-csaf-feed-tlp-white"
}

// described is the provider's description of itself.
//
// One distribution rather than two. The directory is both of the standard's
// shapes at once — year folders with a list and a list of changes, and a feed
// naming the same documents — and they describe one set of files.
func (w *Writer) described(newest time.Time) providerMetadata {
	return providerMetadata{
		CanonicalURL: w.who.At(metadataFile),
		Distributions: []distribution{{
			DirectoryURL: w.who.Published,
			ROLIE: &rolie{Feeds: []feedDescription{{
				Summary:  "Advisories " + w.who.Name + " has published, TLP:" + travels + ".",
				TLPLabel: travels,
				URL:      w.who.At(feedFile),
			}}},
		}},
		LastUpdated: stamp(newest),
		Listed:      w.settings.List,
		Mirrored:    w.settings.Mirror,
		Version:     metadataVersion,
		Publisher: issuer{
			Category:  w.who.Category,
			Name:      w.who.Name,
			Namespace: w.who.Namespace,
		},
		Role: role,
	}
}

// The shapes of the two JSON files this writes. The field names are the
// standard's, not ours, which is why they are spelled as it spells them — the
// same exemption the field names inside a document have.

// providerMetadata is what a reader fetches to find out what this publisher
// offers and where.
type providerMetadata struct {
	CanonicalURL  string         `json:"canonical_url"`
	Distributions []distribution `json:"distributions"`
	LastUpdated   string         `json:"last_updated"`
	Listed        bool           `json:"list_on_CSAF_aggregators"`
	Version       string         `json:"metadata_version"`
	Mirrored      bool           `json:"mirror_on_CSAF_aggregators"`
	Publisher     issuer         `json:"publisher"`
	Role          string         `json:"role"`
}

// issuer is the publisher as the description carries it, which is the same
// object a document carries.
type issuer struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// distribution is one way the documents are reachable.
type distribution struct {
	DirectoryURL string `json:"directory_url,omitempty"`
	ROLIE        *rolie `json:"rolie,omitempty"`
}

type rolie struct {
	Feeds []feedDescription `json:"feeds"`
}

type feedDescription struct {
	Summary  string `json:"summary,omitempty"`
	TLPLabel string `json:"tlp_label"`
	URL      string `json:"url"`
}

// rolieFeed is the feed document, whose one member is the feed itself.
type rolieFeed struct {
	Feed feedBody `json:"feed"`
}

type feedBody struct {
	ID         string      `json:"id"`
	Title      string      `json:"title"`
	Links      []link      `json:"link"`
	Categories []category  `json:"category"`
	Updated    string      `json:"updated"`
	Entries    []feedEntry `json:"entry"`
}

type link struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type category struct {
	Scheme string `json:"scheme"`
	Term   string `json:"term"`
}

type feedEntry struct {
	// released is the moment Updated spells, kept so that the order is
	// decided by the moment rather than by its spelling.
	released  time.Time
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Links     []link  `json:"link"`
	Published string  `json:"published"`
	Updated   string  `json:"updated"`
	Summary   summary `json:"summary"`
	Content   content `json:"content"`
	Format    format  `json:"format"`
}

type summary struct {
	Content string `json:"content"`
}

type content struct {
	Type   string `json:"type"`
	Source string `json:"src"`
}

type format struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
}
