package sbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The second format read.
const spdxName = "SPDX"

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
		return fmt.Errorf("scan file is not %s: it says %q", spdxName, trim(stated))
	}
	if major, _, _ := strings.Cut(version, "."); major != spdxMajor {
		return fmt.Errorf("%s version %q is not one this reads", spdxName, trim(stated))
	}
	c.declared = spdxName
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
	return c.b.array(func() error {
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

	// The format has no field saying what a package was built from — what it
	// offers is prose about where the source came from — so the identifier is
	// the only place left to ask, and it is where most producers put it.
	described.UpstreamName, described.UpstreamVersion = graph.UpstreamFromPurl(described.Purl)
	if strings.TrimSpace(described.Version) == "" {
		c.doc.Unversioned++
	}
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
// The first of each stands. A real producer emits eight spellings of one
// database key, differing in where it put a hyphen, and nothing here can say
// which spelling an advisory used — so this takes the same answer everything
// downstream has already been given rather than inventing a preference.
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
		if err := c.count(); err != nil {
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
		if ref != "" {
			c.files[ref] = true
		}
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

// spdxRelate records what one relationship states, where it states something
// this reads.
//
// A relationship type in none of the tables is not an edge and is not an
// error. The format states what generated a file, what a document amends and
// what a package was evidenced by, alongside the structure — so the ones that
// are not structure are as ordinary here as a CycloneDX composition is there.
func (c *reader) spdxRelate(from, kind, to string) error {
	if from == "" || to == "" {
		return nil
	}
	switch {
	case kind == "DESCRIBES" && from == spdxDocumentRef:
		c.rootRefs = append(c.rootRefs, to)
		return nil
	case kind == "DESCRIBED_BY" && to == spdxDocumentRef:
		c.rootRefs = append(c.rootRefs, from)
		return nil
	}
	if direction, structural := spdxEdges[kind]; structural {
		if direction == held {
			from, to = to, from
		}
		return c.edge(from, to)
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
		}
	}
	return nil
}
