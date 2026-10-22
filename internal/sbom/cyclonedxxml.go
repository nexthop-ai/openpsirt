// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"encoding/xml"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// cyclonedxNamespace is the namespace a CycloneDX document's elements are in,
// less the revision it was written against: a 1.6 document's elements are in
// http://cyclonedx.org/schema/bom/1.6.
const cyclonedxNamespace = "http://cyclonedx.org/schema/bom/"

// readXML reads a CycloneDX document encoded as XML.
//
// What is read is what the JSON encoding's reader reads, from the elements and
// attributes the schema puts the same facts in. Everything a fact means once
// it is read — which of two suppliers wins, how licenses combine, what a
// patch claims, where a bound is charged — is the JSON reader's, called from
// here, so the two encodings of one inventory read as one inventory.
//
// The declaration cannot arrive late, as it can in JSON: the top-level
// element's namespace states the format and its revision, and nothing comes
// before it.
func (c *reader) readXML() error {
	if err := c.cyclonedxXML(); err != nil {
		return c.x.refused("reading scan file", err)
	}
	return c.checkFormat()
}

// cyclonedxXML walks the document.
func (c *reader) cyclonedxXML() error {
	root, err := c.x.root()
	if err != nil {
		return err
	}
	if err := c.cyclonedxXMLDeclared(root); err != nil {
		return err
	}
	err = c.x.children(func(el xml.StartElement) error {
		switch el.Name.Local {
		case "metadata":
			return c.xmlMetadata()
		case "components":
			if c.headerOnly {
				return c.x.skip()
			}
			_, err := c.xmlComponents()
			return err
		case "dependencies":
			if c.headerOnly {
				return c.x.skip()
			}
			return c.xmlDependencies()
		default:
			return c.x.skip()
		}
	})
	if err != nil {
		return err
	}
	return c.x.end()
}

// cyclonedxXMLDeclared reads what the top-level element says the document is,
// and refuses anything else.
//
// SPDX has an XML encoding too, as RDF. It is refused here by name rather
// than read: one was seen among 41 public inventories, and that one was a
// conversion.
func (c *reader) cyclonedxXMLDeclared(root xml.StartElement) error {
	revision, ours := strings.CutPrefix(root.Name.Space, cyclonedxNamespace)
	if root.Name.Local != "bom" || !ours {
		return refusal.Errorf("scan file is XML and not %s: its top-level element is %q in the namespace %q, "+
			"and only %s is read as XML", CycloneDX, trim(root.Name.Local), trim(root.Name.Space), CycloneDX)
	}
	if err := cyclonedxRevision(revision); err != nil {
		return err
	}
	c.x.space = root.Name.Space
	c.declared, c.named, c.versioned = CycloneDX, true, true
	c.doc.Serial = attr(root, "serialNumber")
	return nil
}

// xmlMetadata reads what the document says about itself.
func (c *reader) xmlMetadata() error {
	return c.x.children(func(el xml.StartElement) error {
		switch el.Name.Local {
		case "timestamp":
			var raw string
			if err := c.x.into(&raw); err != nil {
				return err
			}
			return c.dated(raw)
		case "component":
			described, ref, nested, err := c.xmlComponent(el)
			if err != nil {
				return err
			}
			return c.holdRoot(described, ref, nested)
		default:
			return c.x.skip()
		}
	})
}

// xmlComponents reads a list of components and returns the ones directly in
// it, as componentArray does.
func (c *reader) xmlComponents() ([]graph.Described, error) {
	var members []graph.Described
	err := c.x.children(func(el xml.StartElement) error {
		if el.Name.Local != "component" {
			return c.x.skip()
		}
		described, ref, nested, err := c.xmlComponent(el)
		if err != nil {
			return err
		}
		return c.member(&members, described, ref, nested)
	})
	return members, err
}

// xmlComponent reads one component and any nested underneath it. Its own
// identifier and its kind are attributes; the rest are elements.
func (c *reader) xmlComponent(el xml.StartElement) (graph.Described, string, []graph.Described, error) {
	var s cdxComponent
	// Charged on the way in, as component is.
	if err := c.count(); err != nil {
		return graph.Described{}, "", nil, err
	}
	s.ref = attr(el, "bom-ref")
	s.described.Container = attr(el, "type") == "container"
	err := c.x.children(func(field xml.StartElement) error {
		switch field.Name.Local {
		case "name":
			return c.x.into(&s.described.Name)
		case "version":
			return c.x.into(&s.described.Version)
		case "purl":
			return c.x.into(&s.described.Purl)
		case "cpe":
			return c.x.into(&s.described.CPE)
		case "supplier":
			return c.x.children(func(f xml.StartElement) error {
				if f.Name.Local == "name" {
					return c.x.into(&s.supplier)
				}
				return c.x.skip()
			})
		case "publisher":
			return c.x.into(&s.publisher)
		case "licenses":
			return c.xmlLicenses(&s.declared, &s.concluded)
		case "scope":
			return c.x.into(&s.scope)
		case "pedigree":
			return c.xmlPedigree(&s.described, &s.carried)
		case "components":
			members, err := c.xmlComponents()
			if err != nil {
				return err
			}
			s.nested = append(s.nested, members...)
			return nil
		default:
			return c.x.skip()
		}
	})
	if err != nil {
		return graph.Described{}, "", nil, err
	}
	return c.settle(s)
}

// xmlLicenses reads the licenses a component states: a license element naming
// an identifier or a name, or an expression element. Whether one was concluded
// is an attribute of either.
func (c *reader) xmlLicenses(declared, concluded *[]string) error {
	return c.x.children(func(el xml.StartElement) error {
		var said string
		switch el.Name.Local {
		case "expression":
			if err := c.x.into(&said); err != nil {
				return err
			}
		case "license":
			err := c.x.children(func(field xml.StartElement) error {
				switch field.Name.Local {
				case "id":
					return c.x.into(&said)
				case "name":
					// An identifier stands where both are given, as in
					// cdxLicenses.
					if said != "" {
						return c.x.skip()
					}
					return c.x.into(&said)
				default:
					return c.x.skip()
				}
			})
			if err != nil {
				return err
			}
		default:
			return c.x.skip()
		}
		return c.cdxLicense(said, attr(el, "acknowledgement"), declared, concluded)
	})
}

// xmlPedigree reads where a component came from, and what its patches say they
// fix, as pedigree does.
func (c *reader) xmlPedigree(described *graph.Described, carried *[]Suppression) error {
	return c.x.children(func(el xml.StartElement) error {
		switch el.Name.Local {
		case "ancestors":
			return c.xmlAncestor(described)
		case "patches":
			return c.xmlPatches(carried)
		default:
			return c.x.skip()
		}
	})
}

// xmlAncestor reads what a component was forked from: the first ancestor, as
// ancestor does.
func (c *reader) xmlAncestor(described *graph.Described) error {
	first := true
	return c.x.children(func(el xml.StartElement) error {
		if !first || el.Name.Local != "component" {
			return c.x.skip()
		}
		first = false
		return c.x.children(func(field xml.StartElement) error {
			switch field.Name.Local {
			case "name":
				return c.x.into(&described.UpstreamName)
			case "version":
				return c.x.into(&described.UpstreamVersion)
			default:
				return c.x.skip()
			}
		})
	})
}

// xmlPatches reads what a component's carried patches say they resolve, as
// patches does. Each issue a patch resolves is charged as it is read.
func (c *reader) xmlPatches(carried *[]Suppression) error {
	return c.x.children(func(el xml.StartElement) error {
		if el.Name.Local != "patch" {
			return c.x.skip()
		}
		var (
			diff    string
			claimed []Suppression
		)
		err := c.x.children(func(field xml.StartElement) error {
			switch field.Name.Local {
			case "diff":
				return c.x.children(func(f xml.StartElement) error {
					if f.Name.Local != "url" {
						return c.x.skip()
					}
					return c.x.into(&diff)
				})
			case "resolves":
				return c.x.children(func(issue xml.StartElement) error {
					if issue.Name.Local != "issue" {
						return c.x.skip()
					}
					if err := c.claim(); err != nil {
						return err
					}
					var id string
					err := c.x.children(func(f xml.StartElement) error {
						if f.Name.Local != "id" {
							return c.x.skip()
						}
						return c.x.into(&id)
					})
					if err != nil {
						return err
					}
					if claim := resolvedClaim(attr(issue, "type"), id); claim.Vulnerability != "" {
						claimed = append(claimed, claim)
					}
					return nil
				})
			default:
				return c.x.skip()
			}
		})
		if err != nil {
			return err
		}
		patched(diff, claimed, carried)
		return nil
	})
}

// xmlDependencies reads the declared edges.
func (c *reader) xmlDependencies() error {
	return c.x.children(func(el xml.StartElement) error {
		if el.Name.Local != "dependency" {
			return c.x.skip()
		}
		return c.xmlDependency(el)
	})
}

// xmlDependency reads what one component depends on: the dependency elements
// nested inside its own, each naming one by the identifier its ref attribute
// carries, and each charged as it is read.
//
// The schema nests the element in itself without saying where that stops, and
// a dependency nested in a nested one can only mean an edge from the one it is
// nested in. How deep that goes is the depth bound's business.
func (c *reader) xmlDependency(el xml.StartElement) error {
	parent := attr(el, "ref")
	return c.x.children(func(child xml.StartElement) error {
		if child.Name.Local != "dependency" {
			return c.x.skip()
		}
		if err := c.edge(parent, attr(child, "ref"), ""); err != nil {
			return err
		}
		return c.xmlDependency(child)
	})
}
