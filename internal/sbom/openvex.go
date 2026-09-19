package sbom

import (
	"fmt"
	"io"
	"strings"
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
		return nil, fmt.Errorf("reading suppressions: %w", err)
	}
	// A document that fired both vocabularies is not either of them. Half-read
	// it was accepted and the OpenVEX statements were dropped without a word,
	// because the CSAF result is returned and the other list is discarded —
	// the operator is told the upload worked and the claims are simply absent.
	// The inventory side already refuses this and says why.
	if v.csaf != nil && len(v.claims) > 0 {
		return nil, fmt.Errorf("suppressions state both OpenVEX and CSAF-VEX, " +
			"so which format the document is cannot be settled")
	}
	if v.csaf != nil {
		claims, err := v.csaf.finish()
		if err != nil {
			return nil, fmt.Errorf("reading suppressions: %w", err)
		}
		return claims, nil
	}
	if !strings.Contains(v.namespace, suppressionNamespace) {
		return nil, fmt.Errorf("suppressions are not in a format this reads: they say %q", trim(v.namespace))
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
// counts statements, so one statement pointing at ten million products was
// under it. Charged on the way in, because what a bound has to stop is the
// walk.
func (v *suppressions) name() error {
	v.named++
	if v.named > v.lim.MaxComponents {
		return fmt.Errorf("suppression document names more than the %d product limit",
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
					return fmt.Errorf("more claims than the %d limit", v.lim.MaxStatements)
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
		return Suppression{}, fmt.Errorf("a claim names no vulnerability, so there is nothing it could be about")
	}
	if !claim.Status.known() {
		// Ignoring a claim we cannot read would let a build's judgment go
		// missing silently, which is the failure this arrangement exists to
		// remove.
		return Suppression{}, fmt.Errorf("claim about %s says %q, which is not a status this reads",
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
func (v *suppressions) products(claim *Suppression) error {
	return v.b.array(func() error {
		var target Target
		purl, err := v.b.stringOrObject(func(key string) error {
			switch key {
			case "@id":
				value, err := v.b.str()
				target.Purl = value
				return err
			case "identifiers":
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
			default:
				return v.b.skip()
			}
		})
		if err != nil {
			return err
		}
		if target.Purl == "" {
			target.Purl = purl
		}
		if target.Purl == "" {
			return nil
		}
		if err := v.name(); err != nil {
			return err
		}
		base, _ := purlParts(target.Purl)
		if slash := strings.LastIndex(base, "/"); slash >= 0 {
			target.Name = base[slash+1:]
		}
		claim.Targets = append(claim.Targets, target)
		return nil
	})
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
