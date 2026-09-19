package sbom

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// refEdge is one declared dependency, still named by the identifiers the file
// used. Those identifiers never leave this package: nothing guarantees a
// producer keeps them stable between builds, so they are good for joining a
// document to itself and for nothing else.
type refEdge struct{ parent, child, kind string }

// declaredScopes are the words the two formats define for what a dependency's
// scope is, and the whole of what is recorded.
//
// The producer's own word, from whichever vocabulary it wrote in. One
// format states a scope on the component and the other on the relationship,
// and the two do not use the same words for the same idea — "required" and
// "run" both say the target is there when the product runs. Folding them onto
// one vocabulary would be a reading, and a reading is the thing this is
// deliberately not doing.
//
// `test` is absent because a test relationship places nothing: its edge is
// dropped, so there is no edge for a word to sit on. The component is still
// held, stored and scanned.
//
// A word neither format defines is not recorded. A producer inventing one has
// said something no reader of this can interpret, and a column of arbitrary
// strings is a filter nobody can offer.
var declaredScopes = map[string]bool{
	// A CycloneDX component scope.
	"required": true,
	"optional": true,
	"excluded": true,
	// An SPDX lifecycle scope, which SPDX 2 spells as a relationship type.
	"build":       true,
	"design":      true,
	"development": true,
	"other":       true,
	"runtime":     true,
}

// scopeWord keeps what a producer declared where the format defines it, and
// nothing otherwise.
func scopeWord(stated string) string {
	word := strings.ToLower(strings.TrimSpace(stated))
	if !declaredScopes[word] {
		return ""
	}
	return word
}

// reader accumulates what a document describes, whatever format described it.
//
// Everything here is shared between the formats read, because the shapes it
// builds are the ones the graph is stored in rather than either format's. A
// vocabulary knows which keys its format uses and what they mean; it does not
// know how a component is deduplicated, how an edge is resolved or where a
// bound is charged, and neither of those halves is allowed to learn the
// other's business.
type reader struct {
	b          *bounded
	lim        Limits
	headerOnly bool

	// declared is the format the document stated for itself, and stating one
	// is what makes a document readable at all. fired records which
	// vocabularies actually read a key, which is not the same question: a
	// handler runs before anything has checked what the document is.
	declared Format
	// fired is keyed by vocabulary rather than by format, because two
	// vocabularies can be two major versions of one format — and a document
	// carrying keys from both of those is as unreadable as one carrying keys
	// from two formats, for the same reason.
	fired map[int]bool
	// named and versioned are the two halves of a CycloneDX declaration.
	// Either alone leaves the other unstated, and an unstated version is one
	// this was not written against.
	named     bool
	versioned bool

	doc Document
	// byRef resolves a document's own identifiers to the components they
	// named, for the length of the read.
	byRef map[string]graph.Described
	// files are the identifiers the document gave things that are not
	// packages. An edge naming one is dropped knowingly rather than counted
	// as naming nothing, which is a different fault and a different number.
	files map[string]bool
	// described is every component in document order, one entry per identity.
	described []graph.Described
	// stated counts what the document says, deduplicated or not, and charged
	// counts every edge however it was stated. Both are the bounds; the slices
	// above are only what survived.
	stated  int
	charged int
	// filed counts the paths a document catalogs, against a bound of their
	// own.
	filed int
	// claimed counts the patch claims a document makes, against the same bound
	// the two VEX readers charge their statements against. It is not covered
	// by the component bound: the claims hang off one component's pedigree, so
	// a document of one component can carry millions of them, and this is read
	// in full inside the upload request.
	claimed int
	seen    map[string]int
	edges   []refEdge
	// contained is the structure a producer declared by nesting one component
	// inside another. It resolves without the document's identifiers, since a
	// nested component often carries none.
	contained []graph.Dependency
	// scopes is what a producer said a component's scope is, by the component's
	// identity, for the format that states it on the component rather than on
	// the relationship. It reaches the edges that arrive at that component.
	scopes map[string]string
	// rootRefs are the identifiers the document offered as the thing it is
	// about, resolved once everything has been read. One format names the root
	// inline and the other points at it, and a pointer cannot be followed
	// until the thing it points at has arrived.
	rootRefs []string
	// upstream is what one component was said to be derived from, by the
	// document's own identifiers. Resolved at the end for the same reason.
	upstream map[string]string
	// upstreamOrder is the order the document stated them in, so resolving
	// them does not depend on what a map felt like doing.
	upstreamOrder []string
	// spdx3Creations is when each creation-information element says a document
	// was made, and spdx3Order is the order they were read in. A format that
	// puts the header inside the contents states several, because anything the
	// document imported brought its own.
	spdx3Creations map[string]string
	spdx3Order     []string
	// spdx3DocumentCreation is the one the document itself points at.
	spdx3DocumentCreation string
	// spdx3DocumentRefs are the identifiers of the elements that are the
	// document itself, which is what a relationship naming the build's roots
	// has to come from. The second version names a constant for this; the
	// third states it as an element, and there can be more than one because
	// a document may carry an inventory element beside its own.
	spdx3DocumentRefs map[string]bool
	// spdx3Describes are the describes relationships as they were read, kept
	// until the walk is over. Which element is the document is itself stated
	// by an element, in no fixed position, so whether a relationship came
	// from the document cannot be answered where it is read.
	spdx3Describes []spdx3Describes
	// settleErr is a fault found after the walk, where the format states
	// something by pointing at an element rather than by carrying it.
	settleErr error
}

func newReader(r io.Reader, lim Limits, headerOnly bool) *reader {
	lim = lim.OrDefault()
	return &reader{
		b:          newBounded(&capped{r: r, left: lim.MaxBytes}, lim.MaxDepth),
		lim:        lim,
		headerOnly: headerOnly,
		fired:      map[int]bool{},
		byRef:      map[string]graph.Described{},
		scopes:     map[string]string{},
		files:      map[string]bool{},
		seen:       map[string]int{},
		upstream:   map[string]string{},

		spdx3DocumentRefs: map[string]bool{},
	}
}

// bind records what one of the document's own identifiers refers to.
//
// Nothing is bound on a header-only read. That read answers a question about
// the document's own record and runs synchronously inside the upload request,
// and the whole point of it is that the contents cost a walk rather than a
// structure per component.
//
// What it costs is the duplicate-identifier refusal, which a header read no
// longer makes: a document carrying one is answered 202 and fails later in the
// background reader. That is already how the other two formats behave, and a
// fault reported at two different times depending on which format a build
// emits is the worse of the two.
func (c *reader) bind(ref string, described graph.Described) error {
	if c.headerOnly {
		return nil
	}
	if ref == "" {
		return nil
	}
	if _, clash := c.byRef[ref]; clash {
		return fmt.Errorf("two components share the identifier %q, so every edge naming it is ambiguous", trim(ref))
	}
	// Checked against the other array too, and checked here as well as there
	// because which of the two a format puts first is the producer's business.
	if c.files[ref] {
		return fmt.Errorf("a file and a component share the identifier %q, so every edge naming it is ambiguous", trim(ref))
	}
	c.byRef[ref] = described
	return nil
}

// add records a component, once per identity.
//
// The bound is charged where a component is read rather than here, so that it
// counts what the document states on every path rather than what this one
// keeps. Counting the survivors would mean a file of one component repeated
// is unbounded — every copy is read, held and discarded, and the count that
// was supposed to stop it never moves.
func (c *reader) add(described graph.Described) error {
	if c.headerOnly {
		return nil
	}
	// One package described twice is one package, and the two descriptions are
	// not always the same description. A build that merges two sources emits
	// one with a vulnerability-database identifier and what it was built from,
	// and one with neither — so keeping whichever arrived first throws away
	// whatever only the other one knew, which is the identifier a scanner
	// matches on about half the time.
	//
	// So they are combined rather than deduplicated: the first statement of
	// something stands, and anything it did not state is taken from the next
	// description that does. Nothing is overwritten, because two producers
	// disagreeing is not something this can settle, and the first answer is at
	// least the one everything downstream already saw.
	identity := described.Identity()
	if at, seen := c.seen[identity]; seen {
		c.described[at].FillFrom(described)
		return nil
	}
	c.seen[identity] = len(c.described)
	c.described = append(c.described, described)
	return nil
}

// count charges one more thing the document describes against the component
// bound.
//
// Charged on the way in, before anything is held. Charged where components are
// recorded instead, the header-only read returns at once and a document
// putting its components inside the root component's own array is walked in
// full during a read that happens synchronously inside the upload request,
// binding every one of them with nothing but the byte limit saying how many
// there could be. Ten million of them at twenty-six bytes each is a quarter of
// a gigabyte of file and several gigabytes of process — the failure this bound
// exists to prevent, arriving in the request rather than in a background
// reader.
func (c *reader) count() error {
	c.stated++
	if c.stated > c.lim.MaxComponents {
		return fmt.Errorf("scan file describes more than the %d component limit", c.lim.MaxComponents)
	}
	return nil
}

// file counts one more cataloged path against its own limit.
//
// Its own rather than the component one, because the two differ by a factor of
// fifty in a real document and by more than that in what they cost to hold.
func (c *reader) file() error {
	c.filed++
	if c.filed > c.lim.MaxFiles {
		return fmt.Errorf("scan file catalogs more than the %d file limit", c.lim.MaxFiles)
	}
	return nil
}

// refile moves a charge from the component bound to the file bound, once an
// element has turned out to be a path rather than a package.
//
// The charge has to happen on the way in — what a bound stops is the walk, and
// a format that states everything in one array does not say what an element is
// until the element has been read. So every entry is charged as a component
// and the ones that turn out to be paths are moved, which leaves the walk
// bounded throughout and still sizes the two the way they actually differ.
func (c *reader) refile() error {
	c.stated--
	return c.file()
}

// claim counts one more patch claim against the limit.
//
// Charged as each one is read rather than after the array, for the reason the
// edge count is: what a bound has to stop is the walk, and a count taken after
// the walk has already done the work.
func (c *reader) claim() error {
	c.claimed++
	if c.claimed > c.lim.MaxStatements {
		return fmt.Errorf("scan file carries more than the %d claim limit", c.lim.MaxStatements)
	}
	return nil
}

// charge counts one more edge against the limit.
func (c *reader) charge() error {
	c.charged++
	if c.charged > c.lim.MaxEdges {
		return fmt.Errorf("scan file declares more than the %d dependency limit", c.lim.MaxEdges)
	}
	return nil
}

// contain records one component holding another, which a producer declares by
// nesting rather than by naming an edge.
func (c *reader) contain(parent, child graph.Described) error {
	// Charged and then walked past on a header read. The charge is what stops
	// the walk and the append is what holds memory, so the bound still holds
	// on both paths while the header read holds nothing.
	if err := c.charge(); err != nil {
		return err
	}
	if c.headerOnly {
		return nil
	}
	c.contained = append(c.contained, graph.Dependency{Parent: parent, Child: child})
	return nil
}

// edge records one declared dependency by the identifiers the document used
// for its ends, charged as it is read.
func (c *reader) edge(parent, child, kind string) error {
	if err := c.charge(); err != nil {
		return err
	}
	c.edges = append(c.edges, refEdge{parent: parent, child: child, kind: kind})
	return nil
}

// scopeFor is what the producer said about one dependency: the word the
// relationship carried, or where the format states it on the component
// instead, the word that component carried.
func (c *reader) scopeFor(stated string, child graph.Described) string {
	if stated != "" {
		return stated
	}
	return c.scopes[child.Identity()]
}

// scoped records what a producer said one component's scope is, for the format
// that states it there.
func (c *reader) scoped(described graph.Described, stated string) {
	if word := scopeWord(stated); word != "" {
		c.scopes[described.Identity()] = word
	}
}

// finish resolves the document's own identifiers into components.
func (c *reader) finish() (*Document, error) {
	c.spdx3Roots()
	c.resolveRoot()
	c.resolveUpstream()
	rootIdentity := c.doc.Root.Identity()

	c.doc.Components = make([]graph.Described, 0, len(c.described))
	for _, described := range c.described {
		if described.Identity() == rootIdentity {
			continue
		}
		c.doc.Components = append(c.doc.Components, described)
	}
	c.doc.Unversioned = countUnversioned(c.doc.Components)

	declared := make([]graph.Dependency, 0, len(c.edges)+len(c.contained))
	for _, e := range c.edges {
		// An edge naming something the document never describes is dropped
		// rather than taken as a malformed file. Producers differ in how
		// completely they state a graph, and one unresolvable edge is not a
		// reason to reject every component in a document of tens of
		// thousands. Inventing the missing component is still not done: the
		// edge simply goes nowhere and is counted.
		parent, ok := c.byRef[e.parent]
		if !ok {
			c.drop(e.parent)
			continue
		}
		child, ok := c.byRef[e.child]
		if !ok {
			c.drop(e.child)
			continue
		}
		declared = append(declared, graph.Dependency{
			Parent: parent, Child: child, Kind: c.scopeFor(e.kind, child),
		})
	}
	for _, dep := range c.contained {
		// Nesting states no scope of its own, so what the child was declared
		// as is what the edge into it carries.
		dep.Kind = c.scopeFor("", dep.Child)
		declared = append(declared, dep)
	}

	reached := map[string]bool{}
	pairs := map[[2]string]int{}
	for _, dep := range declared {
		parent, child := dep.Parent.Identity(), dep.Child.Identity()
		if parent == child {
			// Two of a document's own identifiers turned out to describe the
			// same component. The producer could not have known — its
			// identifiers differ — and an edge from a component to itself
			// says nothing.
			c.doc.SelfReferences++
			continue
		}
		pair := [2]string{parent, child}
		if at, already := pairs[pair]; already {
			// The same pair declared twice. Where one of the two states a
			// scope and the other does not, what the producer said is the
			// stated one — a document naming a dependency plainly and then
			// again with a scope has said the scope. Where both state one and
			// they differ, the first is kept: the producer said two things and
			// this records one of them.
			if c.doc.Dependencies[at].Kind == "" {
				c.doc.Dependencies[at].Kind = dep.Kind
			}
			continue
		}
		pairs[pair] = len(c.doc.Dependencies)
		reached[child] = true
		c.doc.Dependencies = append(c.doc.Dependencies, dep)
	}

	for _, described := range c.doc.Components {
		if !reached[described.Identity()] {
			c.doc.Unrooted++
		}
	}
	return &c.doc, nil
}

// drop records an edge that resolved to nothing, under the reason it did.
//
// An edge naming a file the document describes and an edge naming nothing at
// all are both dropped and are not the same fault: the first is a producer
// stating structure below the level anything here tracks, and the second is a
// graph with a hole in it. Counting them together makes a number that should
// be stable build to build move with how much file detail a producer was
// configured to emit.
func (c *reader) drop(ref string) {
	if c.files[ref] {
		c.doc.FileReferences++
		return
	}
	c.doc.DanglingEdges++
}

// resolveRoot settles which component the document is about.
//
// A format may name the root inline or point at it by identifier, and a
// document may point at several things — a package and the file built from it,
// say. Exactly one of them resolving to a component makes it the root; several
// leave the document with none, and what the scan was filed against stands in.
// Picking one of several would be inventing a hierarchy the producer did not
// state.
func (c *reader) resolveRoot() {
	if c.doc.RootDeclared || c.headerOnly {
		return
	}
	var found graph.Described
	seen := map[string]bool{}
	for _, ref := range c.rootRefs {
		described, ok := c.byRef[ref]
		if !ok {
			continue
		}
		// Counted by what they resolve to rather than by how many times the
		// document said it. A format states the root in more than one place —
		// a list beside the contents and a relationship saying the same
		// thing — and a producer that fills in both has named one component
		// twice, not two components.
		seen[described.Identity()] = true
		found = described
	}
	if len(seen) != 1 {
		return
	}
	c.doc.Root = found
	c.doc.RootDeclared = true
}

// resolveUpstream fills in what a component was derived from, where the
// document stated that by pointing at another component rather than by
// describing it in place.
//
// Nothing already stated is overwritten: a description carrying its own
// ancestor knows more than a pointer does, since a pointer can only name
// something the document also describes.
func (c *reader) resolveUpstream() {
	if len(c.upstream) == 0 || c.headerOnly {
		return
	}
	// Walked in the order the document stated them rather than over the map.
	// Two identifiers can resolve to one component — the merging case add
	// describes — and ranging a map would let a Go runtime decide which of
	// their ancestors is stored, so the same bytes would read two ways.
	for _, ref := range c.upstreamOrder {
		ancestorRef := c.upstream[ref]
		described, ok := c.byRef[ref]
		if !ok {
			continue
		}
		ancestor, ok := c.byRef[ancestorRef]
		if !ok {
			continue
		}
		at, seen := c.seen[described.Identity()]
		if !seen {
			continue
		}
		// What is already there may be a qualifier rather than a
		// description. Where no pedigree is stated the upstream name is
		// taken from the package identifier, which carries a name and no
		// version in 459 of 535 cases — and the version is what expiry
		// compares. A pointer naming a package the document fully describes
		// knows the version, so it fills that in rather than losing to a
		// half-answer. This is the refinement FillFrom already makes for the
		// same reason.
		if c.described[at].UpstreamName != "" {
			if c.described[at].UpstreamVersion == "" && c.described[at].UpstreamName == ancestor.Name {
				c.described[at].UpstreamVersion = ancestor.Version
			}
			continue
		}
		c.described[at].UpstreamName = ancestor.Name
		c.described[at].UpstreamVersion = ancestor.Version
	}
}

// into reads one string into dst.
func (c *reader) into(dst *string) error {
	value, err := c.b.str()
	if err != nil {
		return err
	}
	*dst = value
	return nil
}

// trim bounds what a message quotes back.
//
// Everything in a scan file was written by somebody else, and an error is one
// of the few places it reaches a person. A name the length of the file would
// make a log unreadable and a response unbounded.
func trim(s string) string {
	const most = 120
	if utf8.RuneCountInString(s) <= most {
		return s
	}
	return string([]rune(s)[:most]) + "…"
}
