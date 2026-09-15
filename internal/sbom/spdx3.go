package sbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// The third major version of SPDX, which is a different document rather than a
// revision of the second — so it is a vocabulary of its own rather than a
// branch in that one.
const spdx3Major = "3"

// The prefix the format's own context carries. The version is in it, which is
// what lets a document be refused before its contents are walked.
const spdx3ContextPrefix = "https://spdx.org/rdf/"

// Element types this reads. A type it does not know is skipped, which is most
// of them: the format describes people, tools, licenses, builds and
// vulnerabilities in the same array as the software.
const (
	spdx3Package  = "software_Package"
	spdx3File     = "software_File"
	spdx3Document = "SpdxDocument"
	spdx3Sbom     = "software_Sbom"
	spdx3Creation = "CreationInfo"
)

// spdx3Top routes this format's top-level keys. See cyclonedxTop for why this
// is a table.
var spdx3Top = map[string]func(*reader) error{
	"@context": (*reader).spdx3Context,
	"@graph":   (*reader).spdx3Graph,
}

// spdx3Edges are the relationship types that say one thing is part of another.
//
// The third version dropped the reversed spellings the second one carried —
// every relationship reads from its subject to its object — so this is a set
// rather than a set with directions.
//
// The test applied is the one the second version's table applies: does the
// relationship say one component is part of another in the sense the graph is
// walked in. What is left out is what the format states about a build rather
// than about a product — the tool it used, the input it took, the host it ran
// on, the test it has — alongside licensing, documentation and the whole
// vulnerability profile.
var spdx3Edges = map[string]bool{
	"contains":              true,
	"dependsOn":             true,
	"hasDynamicLink":        true,
	"hasStaticLink":         true,
	"hasPrerequisite":       true,
	"hasOptionalComponent":  true,
	"hasOptionalDependency": true,
	"hasProvidedDependency": true,
}

// spdx3Ancestors are the relationship types that say one component was derived
// from another. `ancestorOf` points from the ancestor; `descendantOf` points at
// it.
var spdx3Ancestors = map[string]bool{"ancestorOf": true, "descendantOf": true}

// spdx3TestScope is the one lifecycle phase whose relationship does not place
// its target under anything.
//
// It drops the edge and not the component: what the scope says is about the
// relationship, and the package is in the document either way. So it is held,
// counted as sitting under nothing, stored and scanned — which is what a
// component the producer could not place gets too.
//
// **A scope is when a relationship matters, not whether the target ships**, and
// the specification says nothing about the second. Reading `build` as "does not
// ship" is the inference that looks obvious and is wrong for every compiled
// language: a crate or a module linked into a binary is stated as a build-phase
// dependency and is inside what the product ships, so dropping it hides
// findings that are somebody's problem. The format's own example states one
// application's three dependencies as `DEPENDS_ON` in the second version and as
// `dependsOn` scoped `build` in the third, which is the same application
// described twice.
//
// A test is the exception, and it is the exception in the second version's
// table too: a test dependency is not part of what ships, which is what
// `TEST_DEPENDENCY_OF` says there and what this scope says here.
const spdx3TestScope = "test"

// spdx3Element is one entry of the graph, collected before its type is known.
//
// **The type may arrive after the fields it governs**, because the order of an
// object's keys is the producer's business, so an element is read into one
// neutral shape and interpreted when it closes. That is the same thing a
// component read from the other formats does — every field is gathered before
// the component is validated — and it holds one element rather than a document,
// which is what keeps the walk bounded.
type spdx3Element struct {
	id      string
	kind    string
	name    string
	version string
	purl    string
	cpe     string

	// What a creation-information element states.
	created     string
	specVersion string

	// What a document or an inventory element points at, and which creation
	// information it was made under.
	rootElements []string
	creationInfo string

	// What a relationship states.
	from  string
	to    []string
	kinds string
	scope string
}

// spdx3Context refuses a version this reader was not written against, from the
// only place the third version states one outside its own graph.
func (c *reader) spdx3Context() error {
	return c.b.each(func(context string) error {
		rest, ours := strings.CutPrefix(strings.TrimSpace(context), spdx3ContextPrefix)
		if !ours {
			return nil
		}
		if major, _, _ := strings.Cut(rest, "."); major != spdx3Major {
			return fmt.Errorf("%s version %q is not one this reads", SPDX, trim(context))
		}
		c.declared = SPDX
		return nil
	})
}

// spdx3Graph reads the one array the format puts everything in.
//
// Packages, files, relationships, people, tools, licenses and the document's
// own record sit in it together, in no stated order. Every entry is charged
// against the component bound on the way in: what a bound has to stop is the
// walk, and which entries turn out to be components is not known until each one
// has been read.
func (c *reader) spdx3Graph() error {
	return c.b.array(func() error {
		if err := c.count(); err != nil {
			return err
		}
		element, err := c.spdx3Element()
		if err != nil {
			return err
		}
		return c.spdx3Record(element)
	})
}

// spdx3Element reads one entry of the graph into a neutral shape.
func (c *reader) spdx3Element() (spdx3Element, error) {
	var e spdx3Element
	err := c.b.object(func(key string) error {
		switch key {
		case "spdxId", "@id":
			return c.into(&e.id)
		case "type", "@type":
			return c.into(&e.kind)
		case "name":
			return c.into(&e.name)
		case "software_packageVersion":
			return c.into(&e.version)
		case "software_packageUrl":
			return c.into(&e.purl)
		case "externalIdentifier":
			return c.spdx3ExternalIdentifiers(&e)
		case "created":
			return c.into(&e.created)
		case "specVersion":
			return c.into(&e.specVersion)
		case "creationInfo":
			return c.into(&e.creationInfo)
		case "rootElement":
			// Charged per element, as its twin in the other version is. One
			// graph entry costs one component on the way in, and without this
			// that single entry carries an array as long as the byte bound
			// allows — in the synchronous upload request, on the header pass
			// too.
			return c.b.each(func(ref string) error {
				if err := c.count(); err != nil {
					return err
				}
				e.rootElements = append(e.rootElements, ref)
				return nil
			})
		case "from":
			return c.into(&e.from)
		case "relationshipType":
			return c.into(&e.kinds)
		case "scope":
			return c.into(&e.scope)
		case "to":
			// One relationship reaches many elements, so the edge bound is
			// charged here rather than per relationship. Charged as each is
			// read: a count taken after the array has already done the work
			// the bound exists to stop.
			return c.b.each(func(ref string) error {
				if err := c.charge(); err != nil {
					return err
				}
				e.to = append(e.to, ref)
				return nil
			})
		default:
			return c.b.skip()
		}
	})
	return e, err
}

// spdx3ExternalIdentifiers reads the identifiers an element carries beside its
// own, which is the other place a package identifier and the national database
// key are stated.
func (c *reader) spdx3ExternalIdentifiers(e *spdx3Element) error {
	return c.b.array(func() error {
		var kind, value string
		if err := c.b.object(func(key string) error {
			switch key {
			case "externalIdentifierType":
				return c.into(&kind)
			case "identifier":
				return c.into(&value)
			default:
				return c.b.skip()
			}
		}); err != nil {
			return err
		}
		switch kind {
		case "packageUrl":
			if e.purl == "" {
				e.purl = value
			}
		case "cpe23", "cpe22":
			if e.cpe == "" {
				e.cpe = value
			}
		}
		return nil
	})
}

// spdx3Record acts on one element, now that what it is has been read.
func (c *reader) spdx3Record(e spdx3Element) error {
	switch e.kind {
	case spdx3Creation:
		return c.spdx3Created(e)
	case spdx3Document:
		c.doc.Serial = e.id
		c.spdx3DocumentCreation = e.creationInfo
		c.spdx3DocumentRefs[e.id] = true
		if c.headerOnly {
			return nil
		}
		c.rootRefs = append(c.rootRefs, e.rootElements...)
		return nil
	case spdx3Sbom:
		c.spdx3DocumentRefs[e.id] = true
		if c.headerOnly {
			return nil
		}
		c.rootRefs = append(c.rootRefs, e.rootElements...)
		return nil
	case spdx3File:
		if err := c.refile(); err != nil {
			return err
		}
		// Charged and then walked past on a header read. The bound has to hold
		// on both paths — it is the walk it stops — but holding half a million
		// identifiers to answer a question about the document's own record is
		// work nobody asked for, and every handler in the other two formats
		// skips its contents outright.
		if e.id == "" || c.headerOnly {
			return nil
		}
		// The same rule the other version's arrays are held to, across a
		// single array rather than two: an edge naming an identifier a path
		// and a package share resolves to the package and invents a
		// dependency nobody stated.
		if _, clash := c.byRef[e.id]; clash {
			return fmt.Errorf("a file and a component share the identifier %q, so every edge naming it is ambiguous", trim(e.id))
		}
		c.files[e.id] = true
		return nil
	case spdx3Package:
		return c.spdx3Package(e)
	}
	// A relationship, where it carries what one is. The format has a scoped
	// subtype as well as the plain one, and both state the same three fields,
	// so what identifies a relationship here is having them rather than being
	// named in a list of type names that grows with the profiles.
	if e.kinds != "" && e.from != "" {
		// The ends were charged against the edge bound where they were read,
		// so the component charge levied on the way in is handed back —
		// including on a header read, since both passes charged it. Kept, it
		// would have a document's relationships spend the ceiling meant for
		// its packages, and this format states file membership as a
		// relationship, so that is the ordinary shape rather than a hostile
		// one.
		c.stated--
		return c.spdx3Relate(e)
	}
	return nil
}

// spdx3Created records what one creation-information element states, and
// refuses a version this reader was not written against.
//
// This is where the version lives for a document whose context did not carry
// it. Checked as it is read, so a file that was never going to be read is
// dropped before the rest of the graph is walked.
func (c *reader) spdx3Created(e spdx3Element) error {
	if e.specVersion != "" {
		if major, _, _ := strings.Cut(e.specVersion, "."); major != spdx3Major {
			return fmt.Errorf("%s version %q is not one this reads", SPDX, trim(e.specVersion))
		}
		c.declared = SPDX
	}
	if e.id == "" || e.created == "" {
		return nil
	}
	if c.spdx3Creations == nil {
		c.spdx3Creations = map[string]string{}
	}
	if _, held := c.spdx3Creations[e.id]; !held {
		c.spdx3Order = append(c.spdx3Order, e.id)
	}
	c.spdx3Creations[e.id] = e.created
	return nil
}

// spdx3Package records one package.
func (c *reader) spdx3Package(e spdx3Element) error {
	// Nothing is built or checked on a header read, which is what the other
	// two formats do by skipping their contents outright. Validating here
	// would refuse a nameless package inside the upload request, where the
	// same document in either other format is answered 202 and fails later in
	// the background reader — the same fault, reported at two different times
	// depending on which format a build happens to emit.
	if c.headerOnly {
		return nil
	}
	described := graph.Described{
		Name:    e.name,
		Version: sentinel(e.version),
		Purl:    sentinel(e.purl),
		CPE:     sentinel(e.cpe),
	}
	if err := described.Valid(); err != nil {
		return fmt.Errorf("%w, so it cannot be tracked", err)
	}
	described.UpstreamName, described.UpstreamVersion = graph.UpstreamFromPurl(described.Purl)
	if strings.TrimSpace(described.Version) == "" {
		c.doc.Unversioned++
	}
	if err := c.add(described); err != nil {
		return err
	}
	return c.bind(e.id, described)
}

// spdx3Relate records what one relationship states, where it states something
// this reads.
func (c *reader) spdx3Relate(e spdx3Element) error {
	if c.headerOnly {
		return nil
	}
	switch {
	case e.kinds == "describes":
		// From the document itself, and from nothing else. The second version
		// names a constant for the document's own identifier precisely so
		// that a describes relationship from anything else is not taken as a
		// root claim, and without the same test here any element could make
		// itself the build's root and re-parent the whole inventory under it.
		//
		// A relationship this refuses is not a fault in the document: it is a
		// statement about something other than what the build ships, which
		// this reader has nothing to do with.
		//
		// Kept until the walk is over rather than tested here: which element
		// is the document is stated by an element, in no fixed position, so
		// a relationship can be read before the answer exists.
		//
		// Already charged where the ends were read, so these are recorded
		// rather than charged a second time.
		c.spdx3Describes = append(c.spdx3Describes,
			spdx3Describes{from: e.from, to: e.to})
		return nil
	case spdx3Edges[e.kinds]:
		if e.scope == spdx3TestScope {
			return nil
		}
		for _, to := range e.to {
			// Already charged where the ends were read, so the edge is
			// recorded rather than charged twice.
			c.edges = append(c.edges, refEdge{parent: e.from, child: to})
		}
		return nil
	case spdx3Ancestors[e.kinds]:
		for _, to := range e.to {
			from, ancestor := e.from, to
			if e.kinds == "ancestorOf" {
				from, ancestor = to, e.from
			}
			if err := c.claim(); err != nil {
				return err
			}
			if _, stated := c.upstream[from]; !stated {
				c.upstream[from] = ancestor
				c.upstreamOrder = append(c.upstreamOrder, from)
			}
		}
		return nil
	}
	return nil
}

// spdx3Describes is one describes relationship as it was read.
type spdx3Describes struct {
	from string
	to   []string
}

// spdx3Roots folds the describes relationships that came from the document
// into what the build's roots are.
//
// From the document itself, and from nothing else. The second version names a
// constant for the document's own identifier precisely so that a describes
// relationship from anything else is not taken as a root claim, and without
// the same test here any element could make itself the build's root and
// re-parent the whole inventory under it.
//
// A relationship this leaves out is not a fault in the document: it is a
// statement about something other than what the build ships, which this
// reader has nothing to do with.
func (c *reader) spdx3Roots() {
	for _, one := range c.spdx3Describes {
		if c.spdx3DocumentRefs[one.from] {
			c.rootRefs = append(c.rootRefs, one.to...)
		}
	}
}

// spdx3Settle fills in the build time from the creation information the
// document pointed at.
//
// **The third version puts the header inside the contents**, so this cannot be
// answered by the pass that skips them — a document's creation information is
// one entry of the same array its packages are in, in no stated position. The
// header read therefore walks the whole graph and builds nothing from it, which
// is as cheap as this format allows rather than as cheap as the others are.
//
// A document carries more than one creation-information element, because
// anything it imported brought its own. The one the document points at is the
// document's, and where it points at nothing **the document has not said when
// it was built**: an imported document's time is a value that does not move
// between builds, so standing it in has the first scan taken and every later
// one refused as not newer, for good. Saying nothing is refused at the door
// instead, which is a message about this upload rather than a target that
// quietly stops accepting them.
func (c *reader) spdx3Settle() {
	if len(c.spdx3Creations) == 0 || !c.doc.BuiltAt.IsZero() {
		return
	}
	raw, ours := c.spdx3Creations[c.spdx3DocumentCreation]
	if !ours {
		return
	}
	built, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		c.settleErr = fmt.Errorf("build time %q is not a time: %w", trim(raw), err)
		return
	}
	c.doc.BuiltAt = built.UTC()
}
