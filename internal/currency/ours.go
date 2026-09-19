package currency

import (
	"context"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// Ours is the set of names this deployment does not send to a public index.
//
// Asking is the one thing here that reaches the network, and what it sends
// is a component's name. For an open-source dependency that is public
// knowledge. For something built here it is not: the name of an internal
// module is the name of a project, a team, or a product nobody has announced,
// and a public index records every request made of it.
//
// A better default rather than a control. An operator who needs certainty
// leaves the whole feature off, which is where it ships; this is what stops
// the ordinary deployment leaking its own names by turning something on that
// reads as harmless.
//
// Biased toward holding back, and it says what it held. Over-excluding
// loses an answer, which is visible on the screen that would have shown it and
// in the report beside it. Under-excluding sends a name to somebody else's
// service, which is visible nowhere and cannot be taken back.
type Ours struct {
	// labels is what a name is matched against, lowercased and deduplicated.
	// Sorted so the report and the test both read the same order twice.
	labels []string
}

// Ourselves derives what is ours from the publisher's namespace, and unions
// what the deployment stated.
//
// The namespace is already required for CSAF and VEX and already means "who we
// are", so a deployment that publishes anything has said this once. Nothing is
// derived from the publisher's *name*: it is prose for a person to read — "Example
// Networks, Inc." — and the indexes are keyed on identifiers.
func Ourselves(namespace string, stated []string) Ours {
	var o Ours
	o.add(fromNamespace(namespace)...)
	o.add(stated...)
	return o
}

// With returns what is ours plus the owners of these package identifiers,
// which is how the roots a scan was about are folded in.
//
// A method rather than another argument to Ourselves, because the roots come
// from the database and change as builds arrive while the other two come from
// configuration and change on a redeploy.
func (o Ours) With(purls ...string) Ours {
	next := Ours{labels: append([]string(nil), o.labels...)}
	for _, purl := range purls {
		if owner := Owner(purl); owner != "" {
			next.add(owner)
		}
	}
	return next
}

// Labels is what a name is matched against, for a report saying why something
// was held back.
func (o Ours) Labels() []string { return append([]string(nil), o.labels...) }

// HeldBack reports whether this component's name stays inside.
//
// Matched a segment at a time rather than anywhere in the string, so "nexthop"
// holds back `pkg:npm/nexthop-agent` and leaves `pkg:npm/phone-next-hop`
// alone. A segment matches a label where it is that label, or where the label
// is followed by one of the characters a name is built from — so one label
// covers an organization's whole family of names without covering a different
// organization whose name begins the same way.
func (o Ours) HeldBack(purl string) bool {
	_, name, ok := Asked(purl)
	if !ok {
		return false
	}
	for _, segment := range segments(name) {
		for _, label := range o.labels {
			if matches(segment, label) {
				return true
			}
		}
	}
	return false
}

// add records labels, lowercased, trimmed, deduplicated and sorted.
func (o *Ours) add(labels ...string) {
	for _, label := range labels {
		label = strings.ToLower(strings.TrimSpace(label))
		if label == "" {
			continue
		}
		o.labels = append(o.labels, label)
	}
	// Sorted before the duplicates are dropped, because dropping them is a
	// walk over neighbours. Searched first, the search ran against a slice
	// this loop had already left unsorted, and a name stated twice in two
	// spellings reached the report twice.
	sort.Strings(o.labels)
	o.labels = slices.Compact(o.labels)
}

// separators are what a name is built from between one word and the next.
//
// A label matches up to one of these, so "nexthop" covers "nexthop-ai",
// "nexthop.tools" and "nexthop_internal" and not "nexthopper".
const separators = "-._"

// matches reports whether one segment of a name is this label, is a name
// beginning with it, or sits under it as a host.
//
// The third only applies to a label that is itself a host, which is what the
// dot tells it. A vanity import path and a self-hosted forge both put the
// organization's host in front of the package — "go.example.test/team/agent" —
// and a label matched only where it begins a segment covers neither. Bounded
// to a dot so that "example" does not take "notexample".
func matches(segment, label string) bool {
	if segment == label {
		return true
	}
	if strings.Contains(label, ".") && strings.HasSuffix(segment, "."+label) {
		return true
	}
	rest, begins := strings.CutPrefix(segment, label)
	return begins && rest != "" && strings.ContainsRune(separators, rune(rest[0]))
}

// segments splits a package's name into the parts a label is matched against.
//
// The name an index is keyed on, from Asked, rather than the whole identifier:
// the ecosystem and the version are ours to send whatever the name is. A
// leading "@" is cut because an npm scope is written with one and the
// organization behind it is not.
func segments(name string) []string {
	parts := strings.Split(strings.ToLower(name), "/")
	for i, part := range parts {
		parts[i] = strings.TrimPrefix(part, "@")
	}
	return parts
}

// Owner is the part of a package identifier that says who publishes it.
//
// The segment beside the name rather than the whole namespace. A forge host is
// shared by everybody — taking "github.com" out of
// `pkg:golang/github.com/example/thing` would hold back most of an ecosystem
// while saying it was protecting one organization — and the segment next to
// the name is the account, the scope or the group in every convention here.
//
// Empty where the identifier carries no namespace, which is what an image and
// a bare package both look like. Nothing is derived from the root's own name:
// a product called "core" would hold back every package whose name starts that
// way, and a default that wrong is one an operator turns the whole feature off
// to escape.
func Owner(purl string) string {
	_, name, ok := Asked(purl)
	if !ok {
		return ""
	}
	parts := segments(name)
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}

// generic are labels that name a kind of registration rather than an
// organization.
//
// A closed handful rather than a list of where each country's registrations
// start, which is a file somebody maintains and this does not have. Without
// them a deployment publishing under "example.co.uk" would hold back
// everything named "co", which is an ecosystem's worth of answers lost in
// exchange for protecting nobody's name.
//
// This is the one place the bias does not run toward holding back, and it
// is not an exception to it: the bias is toward holding back names that could
// be ours, and "com" is not a name anybody has.
var generic = map[string]bool{
	"ac": true, "co": true, "com": true, "edu": true,
	"gov": true, "net": true, "org": true,
	// A forge names nobody's organization either. Publishing at
	// "example.github.io" yields the bare label "github", which matches
	// "github.com" because a dot is a separator — and that holds back most of
	// a Go estate while reporting that it protects one name. The rule against
	// taking a shared forge already holds where an owner is read out of an
	// identifier; this is the other path to the same mistake.
	"github": true, "gitlab": true, "bitbucket": true, "sourceforge": true,
}

// fromNamespace reads an organization out of the identifier this deployment
// publishes under.
//
// The ecosystems spell an organization three ways and a deployment states it
// once, so all three are derived: the host as it is written, which is what a
// module path segment looks like; the host reversed, which is what a Maven
// group and a Java package are; and each label short of the last on its own,
// which is what an npm scope and a forge account usually are.
//
// Each label rather than the first. A coordination address is very often a
// name in front of the organization's own — "psirt.example.test" — and taking
// the first alone would hold back everything called "psirt" and nothing called
// "example", which is the opposite of what was wanted from both.
func fromNamespace(namespace string) []string {
	host := publisherHost(namespace)
	if host == "" {
		return nil
	}
	labels := strings.Split(host, ".")
	reversed := make([]string, 0, len(labels))
	for at := len(labels) - 1; at >= 0; at-- {
		reversed = append(reversed, labels[at])
	}
	found := []string{host, strings.Join(reversed, ".")}
	// Short of the last, which is the top-level domain and names an
	// organization nowhere.
	for _, label := range labels[:max(len(labels)-1, 0)] {
		if !generic[label] {
			found = append(found, label)
		}
	}
	if len(labels) == 1 {
		found = append(found, labels[0])
	}
	return found
}

// publisherHost reads the host out of what a deployment configured as its
// namespace.
//
// A URL is what the formats require and what an operator usually writes, and a
// bare host is what several write anyway, so both are read. "www." is cut
// because it names a web server rather than an organization.
func publisherHost(namespace string) string {
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	if namespace == "" {
		return ""
	}
	host := ""
	if parsed, err := url.Parse(namespace); err == nil {
		host = parsed.Hostname()
		if host == "" {
			// Written without a scheme, where the whole thing lands in the
			// path. Taken up to the first separator, so "example.test/psirt"
			// answers the same as "https://example.test/psirt".
			host, _, _ = strings.Cut(parsed.Path, "/")
		}
	}
	if host == "" {
		host, _, _ = strings.Cut(namespace, "/")
	}
	return strings.TrimPrefix(host, "www.")
}

// RootOwners reads who publishes the things the scans were about.
//
// From what each document called itself, not from the stored root. The
// component standing for the product is stored by its name alone — a version
// on it would give the product a new identity every night — so the package
// identifier a build declared for itself lives on the scan record instead.
// That identifier is the one this needs: a root is the product this deployment
// builds, so the account, scope or group it is published under is this
// deployment's own by construction.
//
// Read each pass rather than at startup, because a product declared this
// morning is one whose name should not leave this afternoon.
func RootOwners(ctx context.Context, db bun.IDB) ([]string, error) {
	return rootOwners(ctx, db, nil, true)
}

// RootOwnersFor is RootOwners narrowed to the products a subject may read.
//
// What a build declared itself to be is a product's name, so the labels
// derived from it are an answer about products rather than about the
// deployment (REQ-42). The pass holds a name back against every root; what
// travels back to a reader is only the part of that they may be told.
func RootOwnersFor(ctx context.Context, db bun.IDB,
	subject access.Subject) ([]string, error) {

	products, all := subject.Products()
	if !all && len(products) == 0 {
		return nil, nil
	}
	return rootOwners(ctx, db, products, all)
}

// MostRoots bounds how many declared identifiers one derivation reads.
//
// Identifiers, not products. What a build declares itself to be carries
// its version, so a product built nightly states a new one every night and a
// handful of products cross this inside a year. Taken newest first, so the
// bound falls on identifiers nothing has built in a long time and never on
// what a deployment is shipping now.
//
// Ordered as well as bounded, because two callers derive this separately — the
// pass that asks and the report that says what was held back — and an
// unordered limit lets the engine hand them different thousands. A name held
// back yesterday would go to a public index today.
const MostRoots = 1000

// rootOwners is both readings of the same question.
func rootOwners(ctx context.Context, db bun.IDB, products []int64,
	all bool) ([]string, error) {

	q := db.NewSelect().
		TableExpr(`"scan" AS "sc"`).
		ColumnExpr(`sc.root_identifier AS "root_identifier"`).
		Where("sc.root_identifier IS NOT NULL").
		Where("sc.root_identifier <> ''").
		GroupExpr("sc.root_identifier").
		OrderExpr("MAX(sc.id) DESC").
		Limit(MostRoots)
	if !all {
		q = q.Join(`JOIN "target" AS "tg" ON tg.id = sc.target_id`).
			Join(`JOIN "stream" AS "st" ON st.id = tg.stream_id`).
			Where("st.product_id IN (?)", bun.List(products))
	}
	var declared []string
	if err := q.Scan(ctx, &declared); err != nil {
		return nil, err
	}
	return declared, nil
}
