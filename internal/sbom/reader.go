package sbom

import (
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/graph"
)

// refEdge is one declared dependency, still named by the identifiers the file
// used. Those identifiers never leave this package: nothing guarantees a
// producer keeps them stable between builds, so they are good for joining a
// document to itself and for nothing else.
type refEdge struct{ parent, child string }

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
	// is what makes a document readable at all.
	declared string

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
	// rootRefs are the identifiers the document offered as the thing it is
	// about, resolved once everything has been read. One format names the root
	// inline and the other points at it, and a pointer cannot be followed
	// until the thing it points at has arrived.
	rootRefs []string
	// upstream is what one component was said to be derived from, by the
	// document's own identifiers. Resolved at the end for the same reason.
	upstream map[string]string
}

func newReader(r io.Reader, lim Limits, headerOnly bool) *reader {
	lim = lim.OrDefault()
	return &reader{
		b:          newBounded(&capped{r: r, left: lim.MaxBytes}, lim.MaxDepth),
		lim:        lim,
		headerOnly: headerOnly,
		byRef:      map[string]graph.Described{},
		files:      map[string]bool{},
		seen:       map[string]int{},
		upstream:   map[string]string{},
	}
}

// bind records what one of the document's own identifiers refers to.
func (c *reader) bind(ref string, described graph.Described) error {
	if ref == "" {
		return nil
	}
	if _, clash := c.byRef[ref]; clash {
		return fmt.Errorf("two components share the identifier %q, so every edge naming it is ambiguous", trim(ref))
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
// Charged on the way in, before anything is held. The bound used to be charged
// where components are recorded, which returns at once on the header-only read
// — so a document putting its components inside the root component's own array
// was walked in full during a read that happens synchronously inside the
// upload request, binding every one of them, with nothing but the byte limit
// saying how many there could be. Ten million of them at twenty-six bytes each
// is a quarter of a gigabyte of file and several gigabytes of process, which is
// the failure this bound exists to prevent, arriving in the request rather than
// in a background reader.
func (c *reader) count() error {
	c.stated++
	if c.stated > c.lim.MaxComponents {
		return fmt.Errorf("scan file describes more than the %d component limit", c.lim.MaxComponents)
	}
	return nil
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
	if err := c.charge(); err != nil {
		return err
	}
	c.contained = append(c.contained, graph.Dependency{Parent: parent, Child: child})
	return nil
}

// edge records one declared dependency by the identifiers the document used
// for its ends, charged as it is read.
func (c *reader) edge(parent, child string) error {
	if err := c.charge(); err != nil {
		return err
	}
	c.edges = append(c.edges, refEdge{parent: parent, child: child})
	return nil
}

// finish resolves the document's own identifiers into components.
func (c *reader) finish() (*Document, error) {
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
		declared = append(declared, graph.Dependency{Parent: parent, Child: child})
	}
	declared = append(declared, c.contained...)

	reached := map[string]bool{}
	pairs := map[[2]string]bool{}
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
		if pairs[pair] {
			continue
		}
		pairs[pair] = true
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
	seen := 0
	for _, ref := range c.rootRefs {
		described, ok := c.byRef[ref]
		if !ok {
			continue
		}
		seen++
		found = described
	}
	if seen != 1 {
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
	for ref, ancestorRef := range c.upstream {
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
		if c.described[at].UpstreamName != "" {
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
