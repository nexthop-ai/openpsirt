package sbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The major version read. 2.2 and 2.3 share one vocabulary — 2.3 adds fields
// and adds nothing this reads — so one reader covers both, and a document
// stating either is read. The third major version is a different document
// entirely rather than a revision of this one, and is refused by name.
const spdxMajor = "2"

// The identifier a document uses for itself. What it describes is stated as a
// relationship from this, which is why it has to be recognized rather than
// resolved: nothing describes it, so it resolves to nothing.
const spdxDocumentRef = "SPDXRef-DOCUMENT"

// spdxTop routes this format's top-level keys. See cyclonedxTop for why this
// is a table.
var spdxTop = map[string]func(*reader) error{
	"spdxVersion":       (*reader).spdxFormatVersion,
	"documentNamespace": (*reader).spdxNamespace,
	"creationInfo":      (*reader).spdxCreationInfo,
	"documentDescribes": (*reader).spdxDocumentDescribes,
	"packages":          (*reader).spdxPackages,
	"files":             (*reader).spdxFiles,
	"relationships":     (*reader).spdxRelationships,
}

// spdxDirection says which end of a relationship holds the other.
type spdxDirection bool

const (
	// holder means the element the relationship is stated from holds the one
	// it points at.
	holder spdxDirection = false
	// held means the reverse.
	held spdxDirection = true
)

// spdxEdges are the relationship types that say one thing is part of another,
// and which way round each states it.
//
// **The test is whether the relationship describes what shipped.** A format
// with a hundred and forty relationship types states far more than a
// dependency graph: what generated what, what documents what, what a file
// amends. Only the ones below put one component inside another in the sense
// the graph is walked in, which is the same question a CycloneDX `dependsOn`
// answers and the same one the tree on screen is asking.
//
// The types stated the other way round are read rather than dropped. A
// producer may say either that a library is contained by a program or that the
// program contains the library, and the two are the same edge.
var spdxEdges = map[string]spdxDirection{
	"CONTAINS":               holder,
	"CONTAINED_BY":           held,
	"DEPENDS_ON":             holder,
	"DEPENDENCY_OF":          held,
	"DYNAMIC_LINK":           holder,
	"STATIC_LINK":            holder,
	"HAS_PREREQUISITE":       holder,
	"PREREQUISITE_FOR":       held,
	"OPTIONAL_DEPENDENCY_OF": held,
	"PROVIDED_DEPENDENCY_OF": held,
	"RUNTIME_DEPENDENCY_OF":  held,
	"BUILD_DEPENDENCY_OF":    held,
	"DEV_DEPENDENCY_OF":      held,
}

// spdxScopes are the relationship types that name a lifecycle phase as well as
// an edge, and the phase each names.
//
// The third version states this as a scope on an ordinary dependency; this
// version has a relationship type per phase, saying the same thing. Recorded in
// the words the third version uses, because they are one fact under two
// spellings and a filter cannot ask for the same thing twice.
//
// **`TEST_DEPENDENCY_OF` is not here and is not an edge either.** A test
// dependency is not part of what ships, which is what this relationship says
// and what the other version's `test` scope says, and the edge is dropped in
// both readers for that reason. The component is still held, stored and
// scanned — what is dropped is where it sits, not the component.
//
// Nothing is inferred from the two that are here. A build-phase dependency in
// a compiled language is routinely linked into the shipped artifact, so
// reading "build" as "does not ship" is wrong for every one of them.
var spdxScopes = map[string]string{
	"BUILD_DEPENDENCY_OF": "build",
	"DEV_DEPENDENCY_OF":   "development",
}

// spdxAncestors are the relationship types that say one component was derived
// from another, and which way round.
//
// This is the nearest the format comes to a pedigree. It is a pointer rather
// than a description — it can only name something the document also
// describes — so it fills in an upstream nothing else stated and never
// replaces one.
var spdxAncestors = map[string]spdxDirection{
	"ANCESTOR_OF":   holder,
	"DESCENDANT_OF": held,
}

// spdxFormatVersion refuses a version this reader was not written against.
//
// Checked where it is read rather than at the end, so a file that was never
// going to be read is dropped before the rest of it is walked.
func (c *reader) spdxFormatVersion() error {
	var stated string
	if err := c.into(&stated); err != nil {
		return err
	}
	version, ok := strings.CutPrefix(strings.TrimSpace(stated), "SPDX-")
	if !ok {
		return fmt.Errorf("scan file is not %s: it says %q", SPDX, trim(stated))
	}
	if major, _, _ := strings.Cut(version, "."); major != spdxMajor {
		return fmt.Errorf("%s version %q is not one this reads", SPDX, trim(stated))
	}
	c.declared = SPDX
	return nil
}

// spdxNamespace reads the identity the document carries for itself.
//
// The format's own document identifier, which is what the other format's
// serial number is: a value that survives the file being copied away from the
// build tree, where a filename and an upload order do not.
func (c *reader) spdxNamespace() error { return c.into(&c.doc.Serial) }

// spdxCreationInfo reads when the producer says the document was made.
func (c *reader) spdxCreationInfo() error {
	return c.b.object(func(key string) error {
		if key != "created" {
			return c.b.skip()
		}
		raw, err := c.b.str()
		if err != nil {
			return err
		}
		if raw == "" {
			return nil
		}
		built, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return fmt.Errorf("build time %q is not a time: %w", trim(raw), err)
		}
		c.doc.BuiltAt = built.UTC()
		return nil
	})
}

// spdxDocumentDescribes reads what the document says it is about, by
// identifier.
//
// The other format states the root inline, with everything it says about it;
// this one points at one of the packages. So it cannot be resolved here — the
// packages may not have been read yet — and a document may point at several
// things, which is settled once everything is in hand.
func (c *reader) spdxDocumentDescribes() error {
	if c.headerOnly {
		return c.b.skip()
	}
	return c.b.array(func() error {
		// Charged as each is read. This is a top-level array, so on the header
		// pass — which runs inside the upload request — it was the one array
		// with neither a skip above nor a bound here, which is exactly what
		// count's own comment says the component bound was moved to prevent.
		if err := c.count(); err != nil {
			return err
		}
		ref, err := c.b.str()
		if err != nil {
			return err
		}
		c.rootRefs = append(c.rootRefs, ref)
		return nil
	})
}

// spdxPackages reads what the document ships, unless only the header was asked
// for.
func (c *reader) spdxPackages() error {
	if c.headerOnly {
		return c.b.skip()
	}
	return c.b.array(func() error {
		described, ref, err := c.spdxPackage()
		if err != nil {
			return err
		}
		if err := c.add(described); err != nil {
			return err
		}
		return c.bind(ref, described)
	})
}

// spdxPackage reads one package.
func (c *reader) spdxPackage() (graph.Described, string, error) {
	var (
		described graph.Described
		ref       string
		// Who supplied it, stated two ways. Resolved after the object rather
		// than during it, because a producer chooses the order of its own
		// keys and which field wins must not.
		supplier   string
		originator string
	)
	if err := c.count(); err != nil {
		return graph.Described{}, "", err
	}
	err := c.b.object(func(key string) error {
		switch key {
		case "SPDXID":
			return c.into(&ref)
		case "name":
			return c.into(&described.Name)
		case "versionInfo":
			var stated string
			if err := c.into(&stated); err != nil {
				return err
			}
			described.Version = sentinel(stated)
			return nil
		case "supplier":
			// One string, prefixed with what kind of party it is:
			// "Organization: Debian". The prefix is the format's and says
			// nothing a reader wants, so the name after it is what is kept.
			return c.into(&supplier)
		case "originator":
			// The weaker of the two, and kept aside rather than written
			// straight in: which field wins must not depend on which one the
			// producer happened to write first, and key order is the
			// producer's choice. Read first-key-wins, a package stating both
			// took whichever the producer put nearer the top.
			return c.into(&originator)
		case "externalRefs":
			return c.spdxExternalRefs(&described)
		default:
			return c.b.skip()
		}
	})
	if err != nil {
		return graph.Described{}, "", err
	}
	if err := described.Valid(); err != nil {
		return graph.Described{}, "", fmt.Errorf("%w, so it cannot be tracked", err)
	}

	// The supplier where a producer stated one, whatever order it wrote the
	// two fields in — the same precedence the other format's supplier and
	// publisher get, and for the same reason. The prefix saying what kind of
	// party it is belongs to the format and says nothing a reader wants, so
	// the name after it is what is kept.
	described.Supplier = partyName(supplier)
	if described.Supplier == "" {
		described.Supplier = partyName(originator)
	}

	// The format has no field saying what a package was built from — what it
	// offers is prose about where the source came from — so the identifier is
	// the only place left to ask, and it is where most producers put it.
	described.UpstreamName, described.UpstreamVersion = graph.UpstreamFromPurl(described.Purl)
	return described, ref, nil
}

// spdxExternalRefs reads the identifiers a package carries.
//
// The two this reads are the package identifier a scanner matches on and the
// national database key, which the other format states as fields of their own.
// The category is not consulted: what a reference is is its type, and a
// producer filing a package identifier under one category or another does not
// change what it is.
//
// The first of each stands. A real producer emits up to twelve spellings of
// one database key on a single package, differing in where it put a hyphen,
// and nothing here can say which spelling an advisory used — so this takes the
// same answer everything downstream has already been given rather than
// inventing a preference.
func (c *reader) spdxExternalRefs(described *graph.Described) error {
	return c.b.array(func() error {
		var kind, locator string
		if err := c.b.object(func(key string) error {
			switch key {
			case "referenceType":
				return c.into(&kind)
			case "referenceLocator":
				return c.into(&locator)
			default:
				return c.b.skip()
			}
		}); err != nil {
			return err
		}
		locator = sentinel(locator)
		if locator == "" {
			return nil
		}
		switch kind {
		case "purl":
			if described.Purl == "" {
				described.Purl = locator
			}
		case "cpe23Type", "cpe22Type":
			if described.CPE == "" {
				described.CPE = locator
			}
		}
		return nil
	})
}

// spdxFiles records the identifiers the document gave things that are not
// packages.
//
// **The files themselves are not components.** A file is a path rather than a
// package: nothing matches a vulnerability against one, and a scan of a real
// image describes five files for every package it found. Holding them would
// grow the graph with nodes no finding can ever hang off.
//
// The identifiers are kept because the structure a producer states is mostly
// between a package and the files it installed, and an edge naming one has to
// be dropped knowingly. Dropped without knowing, it reads as a graph with a
// hole in it, and a count that should say the producer's derivation changed
// moves instead with how much file detail it was configured to emit.
//
// Charged against the component bound, because what a bound has to stop is the
// walk, and an unbounded array is an unbounded walk whatever it holds.
func (c *reader) spdxFiles() error {
	if c.headerOnly {
		return c.b.skip()
	}
	return c.b.array(func() error {
		if err := c.file(); err != nil {
			return err
		}
		var ref string
		if err := c.b.object(func(key string) error {
			if key != "SPDXID" {
				return c.b.skip()
			}
			return c.into(&ref)
		}); err != nil {
			return err
		}
		if ref == "" {
			return nil
		}
		// The same rule bind applies, across the two arrays rather than within
		// one: an edge naming an identifier two things share is a coin toss,
		// and here it would resolve to the package and invent a dependency the
		// producer never stated.
		if _, clash := c.byRef[ref]; clash {
			return fmt.Errorf("a file and a component share the identifier %q, so every edge naming it is ambiguous", trim(ref))
		}
		c.files[ref] = true
		return nil
	})
}

// spdxRelationships reads the declared edges, the root, and what a component
// was derived from — all three of which this format states the same way.
func (c *reader) spdxRelationships() error {
	if c.headerOnly {
		return c.b.skip()
	}
	return c.b.array(func() error {
		var from, kind, to string
		if err := c.b.object(func(key string) error {
			switch key {
			case "spdxElementId":
				return c.into(&from)
			case "relationshipType":
				return c.into(&kind)
			case "relatedSpdxElement":
				return c.into(&to)
			default:
				return c.b.skip()
			}
		}); err != nil {
			return err
		}
		return c.spdxRelate(from, kind, to)
	})
}

// describes records one more thing the document says it is about, charged
// against the edge bound: this is read from the relationships array, and an
// unbounded array of them is the same hazard as an unbounded array of edges.
func (c *reader) describes(ref string) error {
	if err := c.charge(); err != nil {
		return err
	}
	c.rootRefs = append(c.rootRefs, ref)
	return nil
}

// spdxRelate records what one relationship states, where it states something
// this reads.
//
// A relationship type in none of the tables is not an edge and is not an
// error. The format states what generated a file, what a document amends and
// what a package was evidenced by, alongside the structure — so the ones that
// are not structure are as ordinary here as a CycloneDX composition is there.
func (c *reader) spdxRelate(from, kind, to string) error {
	// The format's words for nothing are allowed at either end — "contains
	// nothing" is a statement a producer makes. Read literally they are an
	// identifier nothing describes, so the edge is charged and then lands in
	// the count that says the producer's derivation changed.
	from, to = sentinel(from), sentinel(to)
	if from == "" || to == "" {
		return nil
	}
	switch {
	case kind == "DESCRIBES" && from == spdxDocumentRef:
		return c.describes(to)
	case kind == "DESCRIBED_BY" && to == spdxDocumentRef:
		return c.describes(from)
	}
	if direction, structural := spdxEdges[kind]; structural {
		if direction == held {
			from, to = to, from
		}
		return c.edge(from, to, spdxScopes[kind])
	}
	if direction, derivation := spdxAncestors[kind]; derivation {
		if direction == holder {
			from, to = to, from
		}
		// Charged against the claim bound rather than the edge one: this is
		// not an edge, and an unbounded array of them is the same hazard
		// under a different name.
		if err := c.claim(); err != nil {
			return err
		}
		if _, stated := c.upstream[from]; !stated {
			c.upstream[from] = to
			c.upstreamOrder = append(c.upstreamOrder, from)
		}
	}
	return nil
}

// partyName drops the kind a party is stated as, keeping who it is.
//
// The format spells a supplier "Organization: Debian" or "Person: somebody",
// and one of the two words is a label rather than a name. "NOASSERTION" is the
// format's way of saying nobody stated one, which is the same as absent.
func partyName(stated string) string {
	said := strings.TrimSpace(stated)
	if said == "" || strings.EqualFold(said, "NOASSERTION") {
		return ""
	}
	for _, kind := range []string{"Organization:", "Person:", "Tool:"} {
		if rest, found := strings.CutPrefix(said, kind); found {
			return strings.TrimSpace(rest)
		}
	}
	return said
}
