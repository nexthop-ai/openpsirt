package sbom

import (
	"fmt"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/graph"
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
		return fmt.Errorf("scan file is not %s: it says %q", CycloneDX, trim(name))
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
	if major, _, _ := strings.Cut(spec, "."); major != cyclonedxMajor {
		return fmt.Errorf("%s version %q is not one this reads", CycloneDX, trim(spec))
	}
	c.declared, c.versioned = CycloneDX, true
	return nil
}

// metadata reads what the document says about itself.
func (c *reader) metadata() error {
	return c.b.object(func(key string) error {
		switch key {
		case "timestamp":
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
	c.doc.Root = described
	c.doc.RootDeclared = true
	if c.headerOnly {
		return nil
	}
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

// componentArray reads an array of components and returns the ones directly in
// it. Anything nested deeper has already been recorded by the time it returns.
func (c *reader) componentArray() ([]graph.Described, error) {
	var members []graph.Described
	err := c.b.array(func() error {
		described, ref, nested, err := c.component()
		if err != nil {
			return err
		}
		if err := c.add(described); err != nil {
			return err
		}
		if err := c.bind(ref, described); err != nil {
			return err
		}
		for _, member := range nested {
			if err := c.contain(described, member); err != nil {
				return err
			}
		}
		members = append(members, described)
		return nil
	})
	return members, err
}

// component reads one component and any nested underneath it.
//
// Nested components are read here rather than gathered afterwards so that a
// document is only ever walked once, and so that the containment a producer
// declared by nesting survives.
func (c *reader) component() (graph.Described, string, []graph.Described, error) {
	var (
		described graph.Described
		ref       string
		nested    []graph.Described
		carried   []Suppression
		// Who supplied it, stated two ways. Resolved after the object rather
		// than during it, because a producer chooses the order of its own keys
		// and which field wins must not.
		supplier  string
		publisher string
	)
	// Charged on the way in, before anything is held, for the reason the
	// count itself records.
	if err := c.count(); err != nil {
		return graph.Described{}, "", nil, err
	}
	err := c.b.object(func(key string) error {
		switch key {
		case "bom-ref":
			return c.into(&ref)
		case "name":
			return c.into(&described.Name)
		case "version":
			return c.into(&described.Version)
		case "purl":
			return c.into(&described.Purl)
		case "cpe":
			return c.into(&described.CPE)
		case "supplier":
			// An object naming who supplied it.
			return c.b.object(func(field string) error {
				if field == "name" {
					return c.into(&supplier)
				}
				return c.b.skip()
			})
		case "publisher":
			// A plain string, and the weaker of the two. Kept aside rather
			// than written straight in: which field wins must not depend on
			// which one the producer happened to write first, and key order is
			// the producer's choice.
			return c.into(&publisher)
		case "pedigree":
			return c.pedigree(&described, &carried)
		case "components":
			members, err := c.componentArray()
			if err != nil {
				return err
			}
			nested = append(nested, members...)
			return nil
		default:
			return c.b.skip()
		}
	})
	if err != nil {
		return graph.Described{}, "", nil, err
	}
	if err := described.Valid(); err != nil {
		return graph.Described{}, "", nil, fmt.Errorf("%w, so it cannot be tracked", err)
	}

	// The supplier where a producer stated one, whatever order it wrote the two
	// fields in. Resolved during the scan instead, whichever came first won.
	described.Supplier = strings.TrimSpace(supplier)
	if described.Supplier == "" {
		described.Supplier = strings.TrimSpace(publisher)
	}

	// Where a pedigree said what this was built from, it stands: it is the
	// format's own way of saying so, and it carries more than a name. Where
	// there was none, the identifier is asked — which is where most producers
	// actually put it.
	if described.UpstreamName == "" {
		described.UpstreamName, described.UpstreamVersion = graph.UpstreamFromPurl(described.Purl)
	}
	if strings.TrimSpace(described.Version) == "" {
		c.doc.Unversioned++
	}
	// A claim the pedigree carries is about the component it was read from,
	// which is only fully known now: key order is the producer's business, so
	// the patches may well have been read before the name they belong to.
	for _, claim := range carried {
		claim.Targets = []Target{{Purl: described.Purl, Name: described.Name}}
		c.doc.Suppressions = append(c.doc.Suppressions, claim)
	}
	return described, ref, nested, nil
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
		for _, claim := range claimed {
			claim.Statement = "resolved by a patch the build carries: " + trim(diff)
			*carried = append(*carried, claim)
		}
		return nil
	})
}

// resolved reads one thing a patch says it fixes.
//
// A patch may resolve a defect or an improvement as readily as a
// vulnerability, and only the last of those is a claim about security.
func (c *reader) resolved() (Suppression, error) {
	var (
		kind  string
		claim = Suppression{Status: AlreadyFixed, Origin: FromPedigree}
	)
	err := c.b.object(func(key string) error {
		switch key {
		case "type":
			return c.into(&kind)
		case "id":
			return c.into(&claim.Vulnerability)
		default:
			return c.b.skip()
		}
	})
	if err != nil {
		return Suppression{}, err
	}
	if kind != "security" {
		return Suppression{}, nil
	}
	return claim, nil
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
