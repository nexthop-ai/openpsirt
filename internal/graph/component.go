// Package graph stores the dependency graph a scan describes, and the
// components in it.
//
// The graph is held as nodes and edges with validity intervals, not as one set
// of rows per scan. A nightly rebuild changes very little, so recording only
// what changed keeps stored volume tracking change rather than tracking scans
// — which is the difference between a table that grows with real events and
// one that grows with the calendar.
package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/bound"
	"github.com/nexthop-ai/openpsirt/internal/database"
)

// Component is a package at a version, shared across every product that ships
// it.
type Component struct {
	bun.BaseModel `bun:"table:component,alias:c"`

	ID int64 `bun:"id,pk,autoincrement"`
	// Identity is derived from the component's own content, never from an
	// identifier the scan file supplied. Nothing guarantees those are stable
	// between builds or consistent between producers, and an identity that
	// moves would reset every triage decision attached to it.
	Identity string `bun:"identity,notnull"`
	Purl     string `bun:"purl"`
	// CPE is the other identifier scheme in circulation. It is not part of
	// identity — that is derived from the package identifier where there is
	// one, and a second basis would move the identity of everything carrying
	// both — but it is what the national vulnerability database keys on, so a
	// scanner given it matches things a package identifier alone misses.
	CPE     string `bun:"cpe"`
	Name    string `bun:"name,notnull"`
	Version string `bun:"version,notnull"`
	// NameFolded and UpstreamFolded are the two names lowered once, on the
	// way in, so that matching one is an equality test rather than
	// something an engine is asked to fold. The four do not fold alike
	// outside ASCII, so asking them to made whether a routing rule swept a
	// component — or a VEX statement reached it — depend on which engine
	// was running. It also leaves the comparison able to use an index,
	// which wrapping the column in a function did not.
	NameFolded     string `bun:"name_folded"`
	UpstreamFolded string `bun:"upstream_folded"`
	// FoldKey groups the binary packages one source package was built at one
	// version into the thing a person acts on. It groups; it does not
	// identify — Identity above is what a finding, a decision and a node hang
	// off, and none of them moves when this does.
	FoldKey string `bun:"fold_key,notnull"`
	// UpstreamName and UpstreamVersion carry what a patched fork was forked
	// from. A shipped build often carries a version string of its own, and the
	// vulnerability identity lives on the upstream one — so dropping this
	// makes findings unexplainable, and it is what expiry compares.
	UpstreamName    string    `bun:"upstream_name"`
	UpstreamVersion string    `bun:"upstream_version"`
	FirstSeenAt     time.Time `bun:"first_seen_at,notnull"`
	// LatestVersion is what the ecosystem's own index says is newest, and
	// when it shipped . Null where nothing has asked, where asking is
	// turned off, and where the index has never heard of the component — a
	// private module and a vendored fork both look like that, and none of
	// the three is a fault.
	//
	// LatestCheckedAt is when we last asked, whatever came back, so that
	// "we asked and there is nothing" is distinguishable from "we have not
	// asked".
	//
	// Null for ever on a component of an ecosystem there is no index for,
	// which is the second of those and is true: those are not selected to be
	// asked about at all.
	LatestVersion    *string    `bun:"latest_version"`
	LatestReleasedAt *time.Time `bun:"latest_released_at"`
	LatestCheckedAt  *time.Time `bun:"latest_checked_at"`
	// Summary is one line saying what the package is, for somebody reading a
	// dependency of a dependency they have never heard of. ProjectURL is where
	// the index says it is developed, which is better than an address worked
	// out from the name because the publisher stated it.
	//
	// Both are absent for plenty of components and that is not a fault: one
	// index serves no summary at all, and no index is asked about a
	// distribution package. A screen shows what there is.
	Summary    string `bun:"summary"`
	ProjectURL string `bun:"project_url"`
	// Supplier is who the scan said supplied it. From the inventory rather
	// than from an index, and often absent: a producer states it for some of
	// what it describes and not the rest.
	Supplier string `bun:"supplier"`
}

// Described is a component as a scan describes it, before it has been matched
// to a row.
type Described struct {
	Purl            string
	CPE             string
	Name            string
	Version         string
	UpstreamName    string
	UpstreamVersion string
	// Supplier is who a producer says supplied the component — a
	// distribution, a vendor, a project. Not part of identity: two producers
	// describing one component name it differently or not at all, and an
	// identity that moved with it would reset every decision attached.
	Supplier string
}

// Identity returns the content-derived key for a described component.
//
// The package identifier is used when there is one, because it already
// encodes ecosystem, name and version unambiguously. Where a producer emits
// none — and some do not — name and version stand in. Hashing keeps the key a
// fixed width whatever the identifier's length, which some engines need for an
// index and all of them benefit from.
//
// The identifier is reduced to the parts that say what a package *is* before
// it is hashed. A real inventory spells one package several ways, and taking
// the identifier verbatim makes each spelling a component of its own.
func (d Described) Identity() string {
	basis := canonicalPurl(d.Purl)
	if basis == "" {
		basis = strings.TrimSpace(d.Name) + "@" + strings.TrimSpace(d.Version)
	}
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// canonicalPurl reduces a package identifier to what identifies the package.
//
// Three reductions, each for something a real inventory does.
//
// **Qualifiers are dropped.** They qualify rather than identify — an
// architecture, a distribution, the source package a binary came from — and a
// build that merges two sources emits one package with them and the same
// package without. Measured on a public switch operating-system image: 8,373
// identifiers spelling 7,857 packages, and every one of the 516 collisions was
// the same name at the same version. None merged a different package.
//
// Architecture is the one that looks like it belongs and does not. What a
// product is built as is already a dimension of the model — a variant — so
// putting it in a component's identity states it twice, and the same package
// then reads as two in a report that has already separated them by variant. In
// this image the two spellings even disagree about it: one source called a
// package "all" and the other "amd64".
//
// **Escapes are decoded.** The same version arrives as `2.3.2-2%2Bb1` and
// `2.3.2-2+b1` from the two sources, which byte comparison calls two packages.
//
// **The type is lowercased**, which the specification requires and which
// nothing else here relies on.
func canonicalPurl(purl string) string {
	purl = strings.TrimSpace(purl)
	if purl == "" {
		return ""
	}

	// Cut before decoding. A name or version may legitimately contain an
	// escaped separator, and decoding first would turn it into one.
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}

	scheme, rest, found := strings.Cut(purl, ":")
	if !found {
		return decoded(purl)
	}
	// The type is the first segment after the scheme, not the scheme itself,
	// and it is the part the specification calls case-insensitive.
	kind, path, split := strings.Cut(rest, "/")
	if !split {
		return strings.ToLower(scheme) + ":" + decoded(rest)
	}
	return strings.ToLower(scheme) + ":" + strings.ToLower(kind) + "/" + decoded(path)
}

// UpstreamFromPurl reads what a package identifier says it was built from.
//
// Producers state this two ways and mean the same thing. The format has a
// place for it — a pedigree naming what a component descends from — and
// several producers instead hang it off the identifier as a qualifier, which
// is where a distribution's source package ends up. Measured on a public
// switch operating-system image: 30 components state it the first way and 537
// the second, 16 of them both, out of 551 that say anything. Reading only the
// first captures a twentieth of it.
//
// It matters more than its size suggests. A shipped package usually carries a
// version of its own while the vulnerability lives on what it was built from ,
// so this is what a finding is explained by and what expiry compares. It is
// also the name a build's own suppressions use, because a patch is written
// against a source tree rather than against the binaries cut from it.
//
// The qualifier comes as a bare name or as name and version, and both occur —
// 459 and 76 in that image. A bare name is not a lesser answer: for a binary
// cut from a differently named source package it is the whole of what is
// knowable, and it is the half that matching a claim needs.
func UpstreamFromPurl(purl string) (name, version string) {
	_, qs, found := strings.Cut(strings.TrimSpace(purl), "?")
	if !found || qs == "" {
		return "", ""
	}
	// The subpath, if any, follows the qualifiers and is not one of them.
	qs, _, _ = strings.Cut(qs, "#")

	for _, pair := range strings.Split(qs, "&") {
		key, value, found := strings.Cut(pair, "=")
		if !found || !strings.EqualFold(key, "upstream") {
			continue
		}
		stated := decoded(value)
		// A version, where one is stated. Cut from the right: a name may
		// contain no "@", but a version can, and the separator is the last.
		if at := strings.LastIndex(stated, "@"); at > 0 {
			return stated[:at], stated[at+1:]
		}
		return stated, ""
	}
	return "", ""
}

// decoded resolves percent-escapes, leaving the text alone where they are
// malformed — a producer's identifier is not ours to reject over spelling.
func decoded(s string) string {
	unescaped, err := url.PathUnescape(s)
	if err != nil {
		return s
	}
	return unescaped
}

// AsRoot returns how the product itself is stored: its name, and nothing that
// moves.
//
// The version is dropped deliberately. It changes on every build, and identity
// is derived from what a component is — so keeping it would give the product a
// new identity every night, close the node standing for it, and close and
// reopen every edge hanging off it. A build in which nothing changed would
// write thousands of rows, which is the one thing the interval shape exists to
// prevent.
//
// Which build this was is not lost by dropping it. That is what the scan
// record holds: when it was built, what it hashed to, and who sent it.
func (d Described) AsRoot() Described { return Described{Name: d.Name} }

// Valid reports whether a described component can be stored.
//
// A name is the whole requirement. A version is not: the format only requires
// a type and a name, so a component without one is ordinary output rather than
// a broken file, and refusing it would throw away every other component in the
// document alongside it.
//
// What a component with no version costs is matching — nothing can say whether
// a vulnerability applies to a version nobody stated. It still ships, so it is
// better held and visible than dropped.
func (d Described) Valid() error {
	if strings.TrimSpace(d.Name) == "" {
		return fmt.Errorf("component has no name")
	}
	return nil
}

// Components reads and writes the shared component catalog.
type Components struct {
	db  bun.IDB
	now func() time.Time
}

// NewComponents returns a catalog over db.
func NewComponents(db bun.IDB) *Components {
	return &Components{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// Intern returns the identifiers for these components, inserting any that are
// new.
//
// Deduplication is the point. The same library at the same version is one row
// however many products ship it; without that, a component shared across a
// portfolio is stored once per variant per scan and the table grows with the
// catalog rather than with reality.
func (c *Components) Intern(ctx context.Context, described []Described) (map[string]int64, error) {
	byIdentity := make(map[string]Described, len(described))
	for _, d := range described {
		if err := d.Valid(); err != nil {
			return nil, err
		}
		byIdentity[d.Identity()] = d
	}
	if len(byIdentity) == 0 {
		return map[string]int64{}, nil
	}

	identities := make([]string, 0, len(byIdentity))
	for identity := range byIdentity {
		identities = append(identities, identity)
	}

	known, err := c.byIdentities(ctx, identities)
	if err != nil {
		return nil, err
	}

	var missing []Component
	now := c.now().Truncate(time.Microsecond)
	for identity, d := range byIdentity {
		if _, have := known[identity]; have {
			continue
		}
		missing = append(missing, Component{
			Identity: identity, Purl: d.Purl, CPE: d.CPE, Name: d.Name, Version: d.Version,
			NameFolded:   Folded(d.Name),
			UpstreamName: d.UpstreamName, UpstreamVersion: d.UpstreamVersion,
			UpstreamFolded: Folded(d.UpstreamName),
			FoldKey:        d.FoldKey(),
			Supplier:       d.Supplier,
			FirstSeenAt:    now,
		})
	}
	// Anything a later report knows and an earlier one did not. A component row is
	// content-addressed and not edited, but a column nobody has filled in is
	// not an edit: a producer stating a supplier where the producer that wrote
	// the row stated none is the merge rule every other field here follows, and
	// filling it in overwrites nothing.
	if err := c.fillSuppliers(ctx, byIdentity, known); err != nil {
		return nil, err
	}
	if len(missing) > 0 {
		// **Two writers describing the same component are agreeing.** The
		// read above is inside the caller's transaction, which satisfies the
		// rule about reading outside one — but it says nothing about another
		// transaction, against another target, finding the same component
		// absent at the same moment. A unique violation is not a retryable
		// failure, so the loser did not retry: the whole scan apply failed
		// and the producer was told its upload could not be read, for a
		// component that is now present. Two replicas reading two scans at
		// once is the shipped arrangement, and a portfolio first meeting a
		// shared dependency is when it happens.
		//
		// A component row is content-addressed and never edited, so leaving
		// somebody else's alone loses nothing.
		if err := database.InBatchesKeeping(ctx, c.db, missing); err != nil {
			return nil, fmt.Errorf("record %d new components: %w", len(missing), err)
		}
		// Read back rather than taken from the rows. A row another writer
		// wrote carries their identifier, and a row this statement skipped
		// carries none at all.
		written := make([]string, 0, len(missing))
		for _, added := range missing {
			written = append(written, added.Identity)
		}
		found, err := c.byIdentities(ctx, written)
		if err != nil {
			return nil, err
		}
		for identity, id := range found {
			known[identity] = id
		}
		if len(found) != len(written) {
			return nil, fmt.Errorf("recorded %d new components and %d came back",
				len(written), len(found))
		}
	}
	return known, nil
}

// byIdentities looks up components in batches.
//
// Batched because a scan can describe tens of thousands of components, and one
// query with that many bound parameters exceeds what some engines accept.
func (c *Components) byIdentities(ctx context.Context, identities []string) (map[string]int64, error) {
	const batch = database.BatchSize
	found := make(map[string]int64, len(identities))

	for start := 0; start < len(identities); start += batch {
		end := min(start+batch, len(identities))

		var rows []Component
		err := c.db.NewSelect().Model(&rows).
			Column("id", "identity").
			Where("identity IN (?)", bun.List(identities[start:end])).
			Scan(ctx)
		if err != nil {
			return nil, fmt.Errorf("look up components: %w", err)
		}
		for _, row := range rows {
			found[row.Identity] = row.ID
		}
	}
	return found, nil
}

// FillFrom takes into a description anything it does not state and another
// description of the same component does.
//
// Nothing already stated is overwritten. Two producers describing one package
// differently is not something this can adjudicate, and the first answer is
// the one everything downstream has already been given — so the later one
// fills gaps and nothing else.
func (d *Described) FillFrom(other Described) {
	if d.CPE == "" {
		d.CPE = other.CPE
	}
	if d.Version == "" {
		d.Version = other.Version
	}
	if d.UpstreamName == "" {
		d.UpstreamName, d.UpstreamVersion = other.UpstreamName, other.UpstreamVersion
	} else if d.UpstreamVersion == "" && d.UpstreamName == other.UpstreamName {
		d.UpstreamVersion = other.UpstreamVersion
	}
}

// Parts is what a package identifier says about a package, split into the
// pieces a reader needs to find it again: which kind of package it is, who
// publishes it, what it is called, at which version, and — for a distribution
// package — which release of that distribution it was built for.
//
// Separate from the identity reductions above, which exist to make one package
// compare equal to itself. This keeps what those deliberately throw away: a
// distribution qualifier says nothing about what a package *is*, and is
// exactly what somebody needs to look the package up.
type Parts struct {
	Type      string
	Namespace string
	Name      string
	Version   string
	// Distro is the distribution release the package was built for, as the
	// identifier spells it — "alpine-3.24.1", "debian-12". Absent for
	// everything that is not a distribution's package, and absent from plenty
	// that is: it is a qualifier, and a producer need not state it.
	Distro string
}

// PartsOfPurl splits a package identifier into what it says.
//
// Everything is returned decoded and the type lowercased, which is what the
// specification says the type is. A malformed identifier yields whatever could
// be read rather than an error: this feeds somewhere to look a package up, and
// half an answer there costs a reader nothing.
func PartsOfPurl(purl string) Parts {
	purl = strings.TrimSpace(purl)
	if purl == "" {
		return Parts{}
	}
	// The subpath follows the qualifiers and is neither.
	purl, _, _ = strings.Cut(purl, "#")
	body, qualifiers, _ := strings.Cut(purl, "?")

	var parts Parts
	for _, pair := range strings.Split(qualifiers, "&") {
		key, value, found := strings.Cut(pair, "=")
		if found && strings.EqualFold(key, "distro") {
			parts.Distro = decoded(value)
			break
		}
	}

	// The scheme is fixed by the specification and is compared without regard
	// to capitals, which is what the specification says of it — and what the
	// canonical form beside this does. Matched against two spellings, `Pkg:`
	// takes a real identity from one and an empty fold basis from the other,
	// and the same component is two things depending on which asked.
	scheme, rest, found := strings.Cut(body, ":")
	if !found || !strings.EqualFold(scheme, "pkg") {
		return Parts{}
	}
	// Cut the version from the right: a name contains no "@" and a version
	// can.
	path := rest
	if at := strings.LastIndex(rest, "@"); at > 0 {
		path, parts.Version = rest[:at], decoded(rest[at+1:])
	}

	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) < 2 {
		return Parts{}
	}
	parts.Type = strings.ToLower(decoded(segments[0]))
	parts.Name = decoded(segments[len(segments)-1])
	if len(segments) > 2 {
		namespace := make([]string, 0, len(segments)-2)
		for _, segment := range segments[1 : len(segments)-1] {
			namespace = append(namespace, decoded(segment))
		}
		parts.Namespace = strings.Join(namespace, "/")
	}
	return parts
}

// FoldKey is the key the binary packages of one source package share.
//
// **What it groups.** A distribution cuts many binary packages from one source
// package and they move together: curl, libcurl4t64 and libcurl3t64 are one
// bump, and treating them as three is three acts that can disagree with each
// other. The key is what makes them one row, one judgment and one upgrade.
//
// **Four parts, because the source package name alone is not enough.** Measured
// on a public switch operating-system image: keyed on the name alone, 47 groups
// fold and six of them hold binaries that disagree about which issues they
// carry and which version fixes them. Keyed on all four, 41 groups fold and
// every one has an identical issue set and an identical fix version.
//
// The six the name alone got wrong are all collisions it cannot see:
//
//   - linux — an image at source version 6.12.41-1 with 5,088 issues beside
//     the perf and header packages at 6.12.107-1 with 607 and none. One source,
//     two versions in one build, one of them already carrying the fix.
//   - protobuf — four Debian binaries at 3.21.12-11 and three PyPI packages of
//     the same name at 4.21.12, 5.29.6 and 7.35.1.
//   - busybox — Debian's at 1:1.37.0-6+b8 and Alpine's three at 1.37.0-r31.
//   - setuptools, lxml, requests — the Debian python3- package and the PyPI
//     package of the same name, at different versions.
//
// So the key carries the package type, the distribution release, the source
// package and the version it was built at. The type separates two ecosystems
// that use one word; the distribution separates two distributions that do; the
// version separates one source shipped twice.
//
// **It groups, and it does not identify.** A component's identity stays derived
// from its own content, a finding stays keyed on its place, and a decision
// stays keyed on that place and expires on its own version — so when a producer
// starts stating a source package for something it did not, the grouping moves
// and no record does. That is the whole reason this can be recomputed and
// folding at ingest cannot.
//
// **Hashed rather than spelled out.** A readable composite would have to be
// bounded to carry an index, and two keys agreeing to that bound would merge
// two source packages into one row — which under one judgment for the whole
// fold writes decisions across both. A name is not a candidate either: the
// protobuf and busybox rows above are two packages with one name.
func (d Described) FoldKey() string {
	parts := PartsOfPurl(d.Purl)
	name, version := d.Source()
	basis := strings.Join([]string{
		Folded(parts.Type),
		Folded(parts.Distro),
		Folded(name),
		Folded(version),
	}, "\x00")
	sum := sha256.Sum256([]byte(basis))
	return hex.EncodeToString(sum[:])
}

// Source is the package a component was built from, and the version it was
// built at: what the producer stated, or the component's own where it stated
// nothing.
//
// The fallback is not a guess. A component that names no source package is its
// own source as far as anything here can tell, and the alternative — leaving it
// out of every grouping — hides the majority: coverage is producer-supplied and
// thin, at 564 of 786 Debian packages, 10 of 18 Alpine, 2 of 188 PyPI and none
// at all of 1,684 Go modules and 3,880 generic components.
func (d Described) Source() (name, version string) {
	// The two fall back independently, which is the rule the version a
	// decision expires on already applies: one fold and one expiry
	// disagreeing about which version a component is at is the shape worth
	// not having.
	name, version = d.UpstreamName, d.UpstreamVersion
	if strings.TrimSpace(name) == "" {
		name = d.Name
	}
	if strings.TrimSpace(version) == "" {
		version = d.Version
	}
	return name, version
}

// Folded is how a name is stored so that every engine compares it alike.
//
// Done here rather than by the engine because the four do not agree: SQLite's
// LOWER folds ASCII and nothing else, while the three servers fold the whole
// character set. A component named with any letter outside ASCII therefore
// matched a routing rule, a search, or a published VEX statement on three
// engines and not on the fourth — and which one a deployment ran decided the
// answer, with nothing reporting the difference, because both look correct.
//
// The same answer matching a typed name without capitals gives for every other
// name people type, and the same one the VEX statement already uses on its
// side of the comparison.
func Folded(name string) string {
	folded := strings.ToLower(strings.TrimSpace(name))
	// Truncated to the width of the column that holds it, which is bounded
	// because it carries an index. The name itself is stored unbounded, so
	// nothing is lost — this is the lookup key, and two names agreeing for a
	// hundred and ninety-one characters are the same name by any reading.
	//
	// Characters rather than bytes, which is how the column is declared. Cut
	// at the same number of bytes, a name written in a script taking three
	// bytes a character kept a third of them — and this feeds the fold key's
	// hash, so two components differing only past that third folded together.
	return bound.HeadRunes(folded, foldedWidth)
}

// foldedWidth is the column's width, which is what every indexed name column
// in this schema is bounded to: the widest a unique index stays inside on
// every engine.
const foldedWidth = 191

// fillSuppliers writes a supplier onto rows that have none.
//
// Only where a report states one and the stored row does not, so a later report
// fills in what an earlier one did not know and overwrites nothing — the rule
// `DESIGN-findings.md` states for every other field two reports can disagree
// about. Without it a component first interned through a producer that states no
// supplier never gets one, however many later scans say who it is.
//
// Grouped by what the supplier is, so the number of statements is the number of
// distinct suppliers in the scan rather than the number of components: a night's
// apply issues enough statements already, and a real image names a few dozen
// suppliers across thousands of rows.
func (c *Components) fillSuppliers(ctx context.Context, described map[string]Described,
	known map[string]int64) error {

	byName := map[string][]int64{}
	for identity, d := range described {
		said := strings.TrimSpace(d.Supplier)
		if said == "" {
			continue
		}
		// Only rows that already exist: one being written this moment carries
		// its supplier on the insert.
		id, have := known[identity]
		if !have {
			continue
		}
		byName[said] = append(byName[said], id)
	}
	// Batched, and on identifiers rather than on identity strings. A Debian
	// inventory names one supplier for nearly every component, so a group here
	// is the whole inventory — measured at 8,373 — and one statement binding
	// that many parameters is refused by two of the four engines, inside the
	// transaction the scan applies in. The read ten lines above batches for
	// exactly this reason; the write beside it did not.
	for said, ids := range byName {
		err := database.IDsInBatches(ctx, ids, func(ctx context.Context, batch []int64) error {
			_, err := c.db.NewUpdate().Model((*Component)(nil)).
				Set("supplier = ?", said).
				Where("id IN (?)", bun.List(batch)).
				Where(`"supplier" IS NULL OR "supplier" = ?`, "").
				Exec(ctx)
			return err
		})
		if err != nil {
			return fmt.Errorf("record who supplied %d components: %w", len(ids), err)
		}
	}
	return nil
}
