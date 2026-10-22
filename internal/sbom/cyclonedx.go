// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Only the first major version exists, and every field read here has been in
// it throughout. A second major version would move things, so it is refused
// rather than read on the assumption that it did not.
const cyclonedxMajor = "1"

// cyclonedxTop routes this format's top-level keys.
//
// The table is the vocabulary: a key in it belongs to CycloneDX and a key in
// no vocabulary's table is skipped. It is a table rather than a switch so that
// a test can assert the vocabularies claim no key in common — which is what
// makes reading a key without knowing the format yet safe, and a producer that
// sorts its keys makes that ordinary rather than exotic.
var cyclonedxTop = map[string]func(*reader) error{
	"bomFormat":    (*reader).cyclonedxFormatName,
	"specVersion":  (*reader).cyclonedxFormatVersion,
	"serialNumber": (*reader).cyclonedxSerial,
	"metadata":     (*reader).metadata,
	"components":   (*reader).cyclonedxComponents,
	"dependencies": (*reader).cyclonedxDependencies,
}

// cyclonedxSerial reads the identity the document carries for itself.
func (c *reader) cyclonedxSerial() error { return c.into(&c.doc.Serial) }

// cyclonedxComponents reads what the document ships, unless only the header
// was asked for.
func (c *reader) cyclonedxComponents() error {
	if c.headerOnly {
		return c.b.skip()
	}
	_, err := c.componentArray()
	return err
}

// cyclonedxDependencies reads the declared edges, unless only the header was
// asked for.
func (c *reader) cyclonedxDependencies() error {
	if c.headerOnly {
		return c.b.skip()
	}
	return c.dependencies()
}

// cyclonedxFormatName refuses a document that says it is something else.
//
// Checked where it is read rather than at the end, so a file that was never
// going to be read is dropped before the rest of it is walked.
func (c *reader) cyclonedxFormatName() error {
	var name string
	if err := c.into(&name); err != nil {
		return err
	}
	if !strings.EqualFold(name, string(CycloneDX)) {
		return refusal.Errorf("scan file is not %s: it says %q", CycloneDX, trim(name))
	}
	c.declared, c.named = CycloneDX, true
	return nil
}

// cyclonedxFormatVersion refuses a version this reader was not written
// against.
func (c *reader) cyclonedxFormatVersion() error {
	var spec string
	if err := c.into(&spec); err != nil {
		return err
	}
	if err := cyclonedxRevision(spec); err != nil {
		return err
	}
	c.declared, c.versioned = CycloneDX, true
	return nil
}

// cyclonedxRevision refuses a revision this reader was not written against,
// however the document stated it: in a key of its own, or in the namespace its
// elements are in.
func cyclonedxRevision(spec string) error {
	if major, _, _ := strings.Cut(spec, "."); major != cyclonedxMajor {
		return refusal.Errorf("%s version %q is not one this reads", CycloneDX, trim(spec))
	}
	return nil
}

// metadata reads what the document says about itself.
func (c *reader) metadata() error {
	return c.b.object(func(key string) error {
		switch key {
		case "timestamp":
			return c.builtAt()
		case "component":
			return c.rootComponent()
		default:
			return c.b.skip()
		}
	})
}

// rootComponent reads the component the document is about.
//
// It is stored like any other and marked, which is what lets anything walking
// upwards stop at it. Its version changes on every build and its name differs
// per variant, so it stays out of identity and out of expiry.
func (c *reader) rootComponent() error {
	described, ref, nested, err := c.component()
	if err != nil {
		return err
	}
	return c.holdRoot(described, ref, nested)
}

// holdRoot records the component the document is about, however it was
// encoded.
func (c *reader) holdRoot(described graph.Described, ref string, nested []graph.Described) error {
	c.doc.Root = described
	c.doc.RootDeclared = true
	return c.hold(described, ref, nested)
}

// componentArray reads an array of components and returns the ones directly in
// it. Anything nested deeper has already been recorded by the time it returns.
//
// A header-only read gathers no members and holds nothing it walks past. A
// document may put its components inside the root component's own array, so
// the header read walks them, inside the upload request.
func (c *reader) componentArray() ([]graph.Described, error) {
	var members []graph.Described
	err := c.b.array(func() error {
		described, ref, nested, err := c.component()
		if err != nil {
			return err
		}
		return c.member(&members, described, ref, nested)
	})
	return members, err
}

// member records one component of a list, however it was encoded, and adds it
// to the members the list returns.
func (c *reader) member(members *[]graph.Described, described graph.Described, ref string, nested []graph.Described) error {
	if err := c.add(described); err != nil {
		return err
	}
	if err := c.hold(described, ref, nested); err != nil {
		return err
	}
	if c.headerOnly {
		return nil
	}
	*members = append(*members, described)
	return nil
}

// hold binds a component's own identifier and records the components the
// producer nested inside it.
func (c *reader) hold(described graph.Described, ref string, nested []graph.Described) error {
	if err := c.bind(ref, described); err != nil {
		return err
	}
	for _, member := range nested {
		if err := c.contain(described, member); err != nil {
			return err
		}
	}
	return nil
}

// component reads one component and any nested underneath it.
//
// Nested components are read here rather than gathered afterwards so that a
// document is only ever walked once, and so that the containment a producer
// declared by nesting survives.
func (c *reader) component() (graph.Described, string, []graph.Described, error) {
	var s cdxComponent
	// Charged on the way in, before anything is held, for the reason the
	// count itself records.
	if err := c.count(); err != nil {
		return graph.Described{}, "", nil, err
	}
	err := c.b.object(func(key string) error {
		switch key {
		case "bom-ref":
			return c.into(&s.ref)
		case "name":
			return c.into(&s.described.Name)
		case "version":
			return c.into(&s.described.Version)
		case "purl":
			return c.into(&s.described.Purl)
		case "cpe":
			return c.into(&s.described.CPE)
		case "type":
			// The format's word for what kind of thing this is. Only one is
			// read: a container image is identified by its name (IsImage).
			var kind string
			if err := c.into(&kind); err != nil {
				return err
			}
			s.described.Container = kind == "container"
			return nil
		case "supplier":
			// An object naming who supplied it.
			return c.b.object(func(field string) error {
				if field == "name" {
					return c.into(&s.supplier)
				}
				return c.b.skip()
			})
		case "publisher":
			return c.into(&s.publisher)
		case "licenses":
			return c.cdxLicenses(&s.declared, &s.concluded)
		case "scope":
			return c.into(&s.scope)
		case "pedigree":
			return c.pedigree(&s.described, &s.carried)
		case "components":
			members, err := c.componentArray()
			if err != nil {
				return err
			}
			s.nested = append(s.nested, members...)
			return nil
		default:
			return c.b.skip()
		}
	})
	if err != nil {
		return graph.Described{}, "", nil, err
	}
	return c.settle(s)
}

// cdxComponent is what one CycloneDX component states, whichever encoding
// stated it, gathered before any of it is acted on.
type cdxComponent struct {
	described graph.Described
	ref       string
	nested    []graph.Described
	carried   []Suppression
	// The supplier, stated two ways. Resolved after the component rather than
	// during it, because a producer chooses the order of its own keys and
	// which field wins must not.
	supplier string
	// A plain string, and the weaker of the two. Kept aside rather than
	// written straight in: which field wins must not depend on which one the
	// producer happened to write first.
	publisher string
	// The producer's own words about the component, which is where this format
	// states it: "required", "optional", or "excluded", which the
	// specification defines as not distributed. Recorded against the component
	// and carried to the edges arriving at it, because the graph is where a
	// scope can be asked about. Read like the two above rather than acted on
	// during the component: key order is the producer's choice.
	scope string
	// The licenses, split by what the producer says it did: declared, or
	// concluded by somebody reading the source. Resolved after the component
	// like the others.
	declared, concluded []string
}

// settle turns what one component stated into the component, once all of it
// has been read.
//
// Shared by the two encodings, so that what a component means is decided in
// one place: an encoding decides where a producer wrote each fact, and nothing
// else.
func (c *reader) settle(s cdxComponent) (graph.Described, string, []graph.Described, error) {
	described := s.described
	printable(&described)
	if err := described.Valid(); err != nil {
		return graph.Described{}, "", nil, refusal.Errorf("%w, so it cannot be tracked", err)
	}

	// The supplier where a producer stated one, whatever order it wrote the two
	// fields in. Resolved during the scan instead, whichever came first won.
	described.Supplier = strings.TrimSpace(s.supplier)
	if described.Supplier == "" {
		described.Supplier = strings.TrimSpace(s.publisher)
	}
	// The license the component declares, and what somebody concluded where
	// it declares none.
	described.License = conjunction(s.declared)
	if described.License == "" {
		described.License = conjunction(s.concluded)
	}

	// Where a pedigree states what this was built from, it stands: it is the
	// format's own way of saying so, and it carries more than a name. Where
	// there is none, the identifier is asked — which is where most producers
	// actually put it.
	if described.UpstreamName == "" {
		described.UpstreamName, described.UpstreamVersion = graph.UpstreamFromPurl(described.Purl)
	}
	// A claim the pedigree carries is about the component it was read from,
	// which is only fully known now: key order is the producer's business, so
	// the patches may well have been read before the name they belong to. A
	// header-only read keeps none: a header carries no claims.
	for _, claim := range s.carried {
		if c.headerOnly {
			break
		}
		claim.Targets = []Target{{Purl: described.Purl, Name: described.Name}}
		c.doc.Suppressions = append(c.doc.Suppressions, claim)
	}
	// Recorded once the component is fully read, for the same reason the
	// supplier is: identity is what it is keyed by, and identity is not known
	// until the fields it is derived from have all arrived.
	c.scoped(described, s.scope)
	return described, s.ref, s.nested, nil
}

// cdxLicenses reads the licenses a component states.
//
// Each entry is an SPDX expression, a license by its SPDX identifier, or a
// license by a name of the producer's own — a distribution's copyright file
// says "GPL-2+" rather than an identifier. An entry marked as concluded is kept
// apart from one declared or unmarked, because the format's default is a
// declaration.
func (c *reader) cdxLicenses(declared, concluded *[]string) error {
	return c.b.array(func() error {
		var said, acknowledged string
		if err := c.b.object(func(key string) error {
			switch key {
			case "expression":
				return c.into(&said)
			case "acknowledgement":
				return c.into(&acknowledged)
			case "license":
				return c.b.object(func(field string) error {
					switch field {
					case "id":
						return c.into(&said)
					case "name":
						// An identifier stands where both are given: it is
						// the one another tool can match.
						if said != "" {
							return c.b.skip()
						}
						return c.into(&said)
					case "acknowledgement":
						return c.into(&acknowledged)
					default:
						return c.b.skip()
					}
				})
			default:
				return c.b.skip()
			}
		}); err != nil {
			return err
		}
		return c.cdxLicense(said, acknowledged, declared, concluded)
	})
}

// cdxLicense keeps one license entry, however it was encoded.
//
// Charged as each entry is kept. Without a charge one component can hold as
// many as the byte bound allows.
func (c *reader) cdxLicense(said, acknowledged string, declared, concluded *[]string) error {
	if err := c.license(); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(acknowledged), "concluded") {
		*concluded = append(*concluded, said)
	} else {
		*declared = append(*declared, said)
	}
	return nil
}

// pedigree reads where a component came from, and what its patches say they
// fix.
//
// A shipped fork carries a version string of its own while the vulnerability
// lives on the version it was forked from, so dropping the ancestor makes
// findings unexplainable. The first ancestor is the one the producer forked
// from; anything further back is history rather than identity.
func (c *reader) pedigree(described *graph.Described, carried *[]Suppression) error {
	return c.b.object(func(key string) error {
		switch key {
		case "ancestors":
			return c.ancestor(described)
		case "patches":
			return c.patches(carried)
		default:
			return c.b.skip()
		}
	})
}

// ancestor reads what a component was forked from.
func (c *reader) ancestor(described *graph.Described) error {
	first := true
	return c.b.array(func() error {
		if !first {
			return c.b.skip()
		}
		first = false
		return c.b.object(func(field string) error {
			switch field {
			case "name":
				return c.into(&described.UpstreamName)
			case "version":
				return c.into(&described.UpstreamVersion)
			default:
				return c.b.skip()
			}
		})
	})
}

// patches reads what a component's carried patches say they resolve.
//
// This is the build's judgment about its own patches, arriving attached to
// the component it is about rather than in a separate document that has to be
// matched back to one. A patch only claims a vulnerability where it says so —
// in its own name, or in a header declaring what it fixes — so what is read
// here is a claim rather than a mention.
func (c *reader) patches(carried *[]Suppression) error {
	return c.b.array(func() error {
		var (
			diff    string
			claimed []Suppression
		)
		err := c.b.object(func(key string) error {
			switch key {
			case "diff":
				return c.b.object(func(field string) error {
					if field != "url" {
						return c.b.skip()
					}
					return c.into(&diff)
				})
			case "resolves":
				return c.b.array(func() error {
					if err := c.claim(); err != nil {
						return err
					}
					claim, err := c.resolved()
					if err != nil {
						return err
					}
					if claim.Vulnerability != "" {
						claimed = append(claimed, claim)
					}
					return nil
				})
			default:
				return c.b.skip()
			}
		})
		if err != nil {
			return err
		}
		patched(diff, claimed, carried)
		return nil
	})
}

// patched carries what one patch claims, however it was encoded, saying which
// patch claimed it.
func patched(diff string, claimed []Suppression, carried *[]Suppression) {
	for _, claim := range claimed {
		claim.Statement = "resolved by a patch the build carries: " + trim(diff)
		*carried = append(*carried, claim)
	}
}

// resolved reads one thing a patch says it fixes.
//
// A patch may resolve a defect or an improvement as readily as a
// vulnerability, and only the last of those is a claim about security.
func (c *reader) resolved() (Suppression, error) {
	var kind, id string
	err := c.b.object(func(key string) error {
		switch key {
		case "type":
			return c.into(&kind)
		case "id":
			return c.into(&id)
		default:
			return c.b.skip()
		}
	})
	if err != nil {
		return Suppression{}, err
	}
	return resolvedClaim(kind, id), nil
}

// resolvedClaim is what one issue a patch resolves claims, however it was
// encoded: that a vulnerability is already fixed, where the issue is a
// security one, and nothing where it is not.
func resolvedClaim(kind, id string) Suppression {
	if kind != "security" {
		return Suppression{}
	}
	return Suppression{Status: AlreadyFixed, Origin: FromPedigree, Vulnerability: id}
}

// dependencies reads the declared edges.
func (c *reader) dependencies() error {
	return c.b.array(func() error {
		var (
			ref      string
			children []string
		)
		err := c.b.object(func(key string) error {
			switch key {
			case "ref":
				return c.into(&ref)
			case "dependsOn":
				return c.b.array(func() error {
					child, err := c.b.str()
					if err != nil {
						return err
					}
					// Charged against the limit as it is read. Collecting the
					// whole list first and checking afterwards means the
					// memory is already spent by the time the bound is
					// consulted, which is what the bound exists to prevent.
					if err := c.charge(); err != nil {
						return err
					}
					children = append(children, child)
					return nil
				})
			default:
				return c.b.skip()
			}
		})
		if err != nil {
			return err
		}
		for _, child := range children {
			c.edges = append(c.edges, refEdge{parent: ref, child: child})
		}
		return nil
	})
}
