// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"io"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// The exchange format suppressions arrive in. Its namespace is what a document
// states, and versions of it differ in ways the fields read here do not.
const suppressionNamespace = "openvex.dev/ns"

// ReadSuppressions reads the claims a build makes about vulnerabilities in
// what it ships.
//
// These are not results a producer already filtered. We take the claims and
// apply them to our own scan, which is what makes a suppressed finding a thing
// that can be seen and accounted for rather than one that simply never
// appeared.
//
// Two shapes, one reading. OpenVEX and CSAF-VEX say the same
// thing differently — one puts the status on a statement, the other puts it in
// which list a product identifier appears in — and both become the same claim
// here, because what a build is telling us does not depend on which file it
// wrote it in. Which of the two a document is decides itself: the keys are
// disjoint, so the walk reads whichever it finds and says so at the end.
//
// Anything else is refused with a sentence rather than half-read. Restricting
// it to two conforming shapes is what keeps the hostile-input surface to two
// parsers rather than one per distribution's own format.
func ReadSuppressions(r io.Reader, lim Limits) ([]Suppression, error) {
	lim = lim.OrDefault()
	b := newBounded(&capped{r: r, left: lim.MaxBytes}, lim.MaxDepth)
	v := &suppressions{b: b, lim: lim}
	if err := v.read(); err != nil {
		return nil, refusal.Errorf("reading suppressions: %w", err)
	}
	// A document that fired both vocabularies is not either of them. Read as
	// one, the other's statements would be dropped without a word while the
	// upload reports success. The inventory side refuses the same and says
	// why.
	if v.csaf != nil && len(v.claims) > 0 {
		return nil, refusal.Errorf("suppressions state both OpenVEX and CSAF-VEX, " +
			"so which format the document is cannot be settled")
	}
	if v.csaf != nil {
		claims, err := v.csaf.finish()
		if err != nil {
			return nil, refusal.Errorf("reading suppressions: %w", err)
		}
		return claims, nil
	}
	if !strings.Contains(v.namespace, suppressionNamespace) {
		return nil, refusal.Errorf("suppressions are not in a format this reads: they say %q", trim(v.namespace))
	}
	return v.claims, nil
}

type suppressions struct {
	b         *bounded
	lim       Limits
	namespace string
	claims    []Suppression
	// named counts every identifier this document makes the reader hold: a
	// product a claim points at, and an identifier an issue also goes by.
	// Charged as each is read.
	named int
	// csaf is set once a key only CSAF has is seen. The two formats share no
	// top-level key, so which one a document is decides itself rather than
	// being sniffed at from the first bytes.
	csaf *csafReader
}

// name charges one more identifier this document makes the reader hold.
//
// The same bound and the same reason as the CSAF reader's: the claim count
// counts statements, so one statement pointing at ten million products is
// under it. Charged on the way in, because what a bound has to stop is the
// walk.
func (v *suppressions) name() error {
	v.named++
	if v.named > v.lim.MaxComponents {
		return refusal.Errorf("suppression document names more than the %d product limit",
			v.lim.MaxComponents)
	}
	return nil
}

func (v *suppressions) read() error {
	return v.b.object(func(key string) error {
		switch key {
		case "@context":
			value, err := v.b.str()
			if err != nil {
				return err
			}
			v.namespace = value
			return nil
		case "statements":
			return v.b.array(func() error {
				// Compared before the element is read, so that the claim past
				// the limit is refused rather than walked in full first.
				if len(v.claims) >= v.lim.MaxStatements {
					return refusal.Errorf("more claims than the %d limit", v.lim.MaxStatements)
				}
				claim, err := v.statement()
				if err != nil {
					return err
				}
				v.claims = append(v.claims, claim)
				return nil
			})
		case "document", "product_tree", "vulnerabilities":
			return v.asCSAF(key)
		default:
			return v.b.skip()
		}
	})
}

// asCSAF hands one key to the CSAF reader, starting it on the first key that
// only CSAF has.
func (v *suppressions) asCSAF(key string) error {
	if v.csaf == nil {
		v.csaf = newCSAF(v.b, v.lim)
	}
	return v.csaf.key(key)
}

// statement reads one claim.
func (v *suppressions) statement() (Suppression, error) {
	claim := Suppression{Origin: FromStatement}
	err := v.b.object(func(key string) error {
		switch key {
		case "vulnerability":
			return v.vulnerability(&claim)
		case "status":
			return v.into(&claim.Status)
		case "justification":
			value, err := v.b.str()
			claim.Justification = value
			return err
		case "impact_statement", "action_statement":
			value, err := v.b.str()
			if claim.Statement == "" {
				claim.Statement = value
			}
			return err
		case "products":
			return v.products(&claim)
		default:
			return v.b.skip()
		}
	})
	if err != nil {
		return Suppression{}, err
	}
	if claim.Vulnerability == "" {
		return Suppression{}, refusal.Errorf("a claim names no vulnerability, so there is nothing it could be about")
	}
	if !claim.Status.known() {
		// Ignoring a claim we cannot read would let a build's judgment go
		// missing silently, which is the failure this arrangement exists to
		// remove.
		return Suppression{}, refusal.Errorf("claim about %s says %q, which is not a status this reads",
			trim(claim.Vulnerability), trim(string(claim.Status)))
	}
	return claim, nil
}

// vulnerability reads which issue a claim is about, and the other identifiers
// the same issue goes by.
func (v *suppressions) vulnerability(claim *Suppression) error {
	name, err := v.b.stringOrObject(func(key string) error {
		switch key {
		case "name":
			value, err := v.b.str()
			claim.Vulnerability = value
			return err
		case "aliases":
			return v.b.array(func() error {
				alias, err := v.b.str()
				if err != nil {
					return err
				}
				if alias != "" {
					if err := v.name(); err != nil {
						return err
					}
					claim.Aliases = append(claim.Aliases, alias)
				}
				return nil
			})
		default:
			return v.b.skip()
		}
	})
	if err != nil {
		return err
	}
	if name != "" {
		claim.Vulnerability = name
	}
	return nil
}

// products reads what a claim points at.
//
// A product with subcomponents is a claim about those components inside it:
// the product is what shipped, and the subcomponents are what the statement
// is about. So the subcomponents are the targets where there are any, each
// carrying the product it ships inside, and the product only where there are
// none. This deployment's own export states
// every claim that way, with the build as the product.
//
// A subcomponent is read only as a package identifier. Anything else names a
// component and no version, and a bare name matches every version of it and
// every fork of it, which is a claim nobody made. A product whose
// subcomponents are all of that kind targets nothing, because the statement
// was about them and never about the product.
func (v *suppressions) products(claim *Suppression) error {
	return v.b.array(func() error {
		var (
			inside []Target
			stated bool
		)
		product, err := v.product(func() error {
			return v.b.array(func() error {
				one, err := v.product(nil)
				if err != nil || one.Purl == "" {
					return err
				}
				stated = true
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(one.Purl)), "pkg:") {
					return nil
				}
				if err := v.name(); err != nil {
					return err
				}
				inside = append(inside, Target{Purl: one.Purl, Name: nameOf(one.Purl)})
				return nil
			})
		})
		if err != nil {
			return err
		}
		if stated {
			// The product the subcomponents ship inside, kept beside each of
			// them: a statement about zlib inside Y is not one about every
			// zlib. A product named by something other than a package
			// identifier is still the product, so its name is what it is
			// called.
			if product.Purl != "" {
				within := Target{Purl: product.Purl, Name: nameOf(product.Purl)}
				for i := range inside {
					inside[i].Within = &within
				}
			}
			claim.Targets = append(claim.Targets, inside...)
			return nil
		}
		if product.Purl == "" {
			return nil
		}
		if err := v.name(); err != nil {
			return err
		}
		product.Name = nameOf(product.Purl)
		claim.Targets = append(claim.Targets, product)
		return nil
	})
}

// product reads one product or subcomponent: its identifier, written as a
// string or as an object carrying it, and the subcomponents where the caller
// reads them.
func (v *suppressions) product(subcomponents func() error) (Target, error) {
	var target Target
	id, err := v.b.stringOrObject(func(key string) error {
		switch {
		case key == "@id":
			value, err := v.b.str()
			target.Purl = value
			return err
		case key == "identifiers":
			return v.b.object(func(kind string) error {
				if kind != "purl" {
					return v.b.skip()
				}
				value, err := v.b.str()
				if target.Purl == "" {
					target.Purl = value
				}
				return err
			})
		case key == "subcomponents" && subcomponents != nil:
			return subcomponents()
		default:
			return v.b.skip()
		}
	})
	if target.Purl == "" {
		target.Purl = id
	}
	return target, err
}

// into reads one string into a status.
func (v *suppressions) into(dst *Status) error {
	value, err := v.b.str()
	if err != nil {
		return err
	}
	*dst = Status(value)
	return nil
}
