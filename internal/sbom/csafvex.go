package sbom

import (
	"fmt"
	"strings"
)

// Reading CSAF-VEX, the second of the two shapes a supplier's VEX as evidence
// names alongside OpenVEX.
//
// The two formats say the same thing in different shapes. OpenVEX puts a
// status, a justification and the products on one statement; CSAF puts the
// status in *which list a product identifier appears in*, the justification in
// a flag beside it, and the products in a tree somewhere else in the document.
// Read into the same claim either way, because what a build is telling us is
// the same either way — and one internal shape is what keeps the rest of the
// application from having to know which file it came from.
//
// The tree may arrive after the claims that refer to it, and often does
// not, but nothing in the format promises an order. So identifiers are
// collected as they are read and resolved once the document is closed, which
// is the same thing the inventory reader does for a component's patches.
//
// A product identifier that resolves to nothing is dropped, and a claim left
// pointing at nothing is refused. A claim we cannot place is a build's
// judgment going missing quietly, which is the failure this whole arrangement
// exists to remove.

// csafCategory is what a document says it is. Only the VEX profile is read: a
// full advisory is a different document about our own flaws, and reading one
// as though it were a set of claims about what a build ships would take
// somebody else's advisory as our build's argument.
const csafCategory = "csaf_vex"

// named is one product the tree defines: what to call it, and the package
// identifier where the document gave one.
type named struct {
	purl string
	name string
}

// claimed is one vulnerability's claims before the tree has been resolved.
type claimed struct {
	vulnerability string
	aliases       []string
	// byProduct is the status each product identifier was listed under, and
	// flagged the justification a flag gave it.
	byProduct map[string]Status
	flagged   map[string]string
	// said is the prose, per status: an impact statement belongs to the
	// products called not affected and an action statement to the affected
	// ones, and reading either into both would attach an argument to a claim
	// it was not made about.
	said map[Status]string
}

type csafReader struct {
	b        *bounded
	lim      Limits
	saw      bool
	tree     map[string]named
	claims   []*claimed
	statuses map[string]Status
	// named counts every identifier this document makes the reader hold: a
	// product the tree defines, a product a claim lists, and an identifier an
	// issue also goes by. Charged as each is read.
	named int
}

// name charges one more identifier this document makes the reader hold.
//
// Charged on the way in, before anything is kept. The claim count is the only
// other bound either VEX reader carries, and it counts vulnerability objects —
// so one claim listing ten million product identifiers is under it, and the
// map holding them is charged against nothing. What a bound has to stop is
// the
// walk, and a count taken after the walk has already done the work.
//
// Against the component bound, because these are what a suppression document
// describes and they cost what a component costs to hold. A ceiling of its own
// would be a setting nobody could reason about separately.
func (r *csafReader) name() error {
	r.named++
	if r.named > r.lim.MaxComponents {
		return fmt.Errorf("suppression document names more than the %d product limit",
			r.lim.MaxComponents)
	}
	return nil
}

// csafStatuses maps a product-status list to what it claims. The four the
// format defines that this application has a word for; anything else is a list
// we would be guessing about, and a guess here is a suppression nobody made.
var csafStatuses = map[string]Status{
	"known_not_affected":  NotAffected,
	"known_affected":      Affected,
	"fixed":               AlreadyFixed,
	"under_investigation": UnderInvestigation,
	// A product the document says was never affected is not a claim about a
	// version we ship: it is a statement about a different product entirely,
	// and treating it as "not affected here" would suppress on the strength of
	// something about something else.
}

func newCSAF(b *bounded, lim Limits) *csafReader {
	return &csafReader{b: b, lim: lim, tree: map[string]named{}, statuses: csafStatuses}
}

// key reads one of the document's top-level keys. Driven from the outer walk
// rather than opening the object itself, because which format a document is
// is not known until one of these keys turns up.
func (r *csafReader) key(key string) error {
	switch key {
	case "document":
		return r.document()
	case "product_tree":
		return r.productTree()
	case "vulnerabilities":
		return r.b.array(func() error { return r.vulnerability() })
	}
	return r.b.skip()
}

// finish is the claims once the whole document has been read and the tree is
// whole.
func (r *csafReader) finish() ([]Suppression, error) {
	if !r.saw {
		return nil, fmt.Errorf("a CSAF document that is not the VEX profile: this reads " +
			"claims about what a build ships, and an advisory is a different document")
	}
	return r.resolve()
}

func (r *csafReader) document() error {
	return r.b.object(func(key string) error {
		if key != "category" {
			return r.b.skip()
		}
		said, err := r.b.str()
		if err != nil {
			return err
		}
		r.saw = strings.EqualFold(strings.TrimSpace(said), csafCategory)
		return nil
	})
}

// productTree collects what each product identifier is. Branches nest to any
// depth and a product may be defined at any level of them, so the walk is the
// same at every level and only the `product` objects are read.
func (r *csafReader) productTree() error {
	return r.b.object(func(key string) error {
		switch key {
		case "branches":
			return r.branches()
		case "full_product_names":
			return r.b.array(func() error { return r.product() })
		default:
			return r.b.skip()
		}
	})
}

func (r *csafReader) branches() error {
	return r.b.array(func() error {
		return r.b.object(func(key string) error {
			switch key {
			case "branches":
				return r.branches()
			case "product":
				return r.product()
			default:
				return r.b.skip()
			}
		})
	})
}

func (r *csafReader) product() error {
	var (
		id  string
		one named
	)
	err := r.b.object(func(key string) error {
		switch key {
		case "product_id":
			value, err := r.b.str()
			id = value
			return err
		case "name":
			value, err := r.b.str()
			one.name = value
			return err
		case "product_identification_helper":
			return r.b.object(func(field string) error {
				if field != "purl" {
					return r.b.skip()
				}
				value, err := r.b.str()
				one.purl = value
				return err
			})
		default:
			return r.b.skip()
		}
	})
	if err != nil {
		return err
	}
	if id != "" && (one.purl != "" || one.name != "") {
		if err := r.name(); err != nil {
			return err
		}
		r.tree[id] = one
	}
	return nil
}

func (r *csafReader) vulnerability() error {
	// Compared before the object is read, so that the claim past the limit is
	// refused rather than walked in full and then refused.
	if len(r.claims) >= r.lim.MaxStatements {
		return fmt.Errorf("more claims than the %d limit", r.lim.MaxStatements)
	}
	one := &claimed{
		byProduct: map[string]Status{},
		flagged:   map[string]string{},
		said:      map[Status]string{},
	}
	err := r.b.object(func(key string) error {
		switch key {
		case "cve":
			value, err := r.b.str()
			if one.vulnerability == "" {
				one.vulnerability = value
			}
			return err
		case "ids":
			return r.ids(one)
		case "product_status":
			return r.productStatus(one)
		case "flags":
			return r.flags(one)
		case "threats":
			return r.prose(one, NotAffected, "details")
		case "remediations":
			return r.prose(one, Affected, "details")
		default:
			return r.b.skip()
		}
	})
	if err != nil {
		return err
	}
	if one.vulnerability == "" {
		return fmt.Errorf("a claim names no vulnerability, so there is nothing it could be about")
	}
	r.claims = append(r.claims, one)
	return nil
}

// ids reads the other names one issue goes by. The first is taken as the
// issue's own name where no CVE was given: a document about something with no
// CVE still names it something, and refusing it would drop the claim.
func (r *csafReader) ids(one *claimed) error {
	return r.b.array(func() error {
		var text string
		if err := r.b.object(func(key string) error {
			if key != "text" {
				return r.b.skip()
			}
			value, err := r.b.str()
			text = value
			return err
		}); err != nil {
			return err
		}
		if text == "" {
			return nil
		}
		if one.vulnerability == "" {
			one.vulnerability = text
			return nil
		}
		if err := r.name(); err != nil {
			return err
		}
		one.aliases = append(one.aliases, text)
		return nil
	})
}

// productStatus is where the claim actually lives: which list a product
// identifier appears in is the status, which is the whole shape difference
// from OpenVEX.
func (r *csafReader) productStatus(one *claimed) error {
	return r.b.object(func(list string) error {
		status, known := r.statuses[list]
		if !known {
			return r.b.skip()
		}
		return r.b.array(func() error {
			id, err := r.b.str()
			if err != nil {
				return err
			}
			if id != "" {
				if err := r.name(); err != nil {
					return err
				}
				one.byProduct[id] = status
			}
			return nil
		})
	})
}

// flags are the justifications, each naming the products it applies to. A flag
// with no products applies to all of this vulnerability's, which is how the
// format spells "the whole claim".
func (r *csafReader) flags(one *claimed) error {
	return r.b.array(func() error {
		var (
			label string
			ids   []string
		)
		if err := r.b.object(func(key string) error {
			switch key {
			case "label":
				value, err := r.b.str()
				label = value
				return err
			case "product_ids":
				return r.b.array(func() error {
					id, err := r.b.str()
					if err != nil {
						return err
					}
					if id != "" {
						if err := r.name(); err != nil {
							return err
						}
						ids = append(ids, id)
					}
					return nil
				})
			default:
				return r.b.skip()
			}
		}); err != nil {
			return err
		}
		if label == "" {
			return nil
		}
		if len(ids) == 0 {
			one.flagged[""] = label
			return nil
		}
		for _, id := range ids {
			one.flagged[id] = label
		}
		return nil
	})
}

// prose reads the words attached to a claim, kept apart by which status they
// belong to: an impact statement argues that something is not affected and an
// action statement says what to do about something that is, and reading either
// into both would attach an argument to a claim it was not made about.
func (r *csafReader) prose(one *claimed, to Status, field string) error {
	return r.b.array(func() error {
		var said string
		if err := r.b.object(func(key string) error {
			if key != field {
				return r.b.skip()
			}
			value, err := r.b.str()
			said = value
			return err
		}); err != nil {
			return err
		}
		if said != "" && one.said[to] == "" {
			one.said[to] = said
		}
		return nil
	})
}

// resolve turns the collected claims into the one shape the rest of this reads,
// once the tree is whole.
//
// One suppression per (vulnerability, status), carrying every product listed
// under that status: the same grouping an OpenVEX statement has, so what
// reaches the store is identical whichever file it came from.
func (r *csafReader) resolve() ([]Suppression, error) {
	out := make([]Suppression, 0, len(r.claims))
	for _, one := range r.claims {
		byStatus := map[Status]*Suppression{}
		order := make([]Status, 0, 4)
		for id, status := range one.byProduct {
			at, held := r.tree[id]
			if !held {
				// A product identifier the tree never defined names nothing we
				// can match against a component. Dropped rather than guessed
				// at: the identifier is somebody else's key, not a name.
				continue
			}
			claim, held := byStatus[status]
			if !held {
				claim = &Suppression{
					Vulnerability: one.vulnerability, Aliases: one.aliases,
					Status: status, Origin: FromStatement,
					Statement: one.said[status],
				}
				byStatus[status] = claim
				order = append(order, status)
			}
			// The justification for this product, or the one the document
			// gave for the whole claim.
			if claim.Justification == "" {
				if said, held := one.flagged[id]; held {
					claim.Justification = said
				} else if said, held := one.flagged[""]; held {
					claim.Justification = said
				}
			}
			claim.Targets = append(claim.Targets, targetOf(at))
		}
		if len(order) == 0 {
			return nil, fmt.Errorf("the claim about %s points at no product this document "+
				"defines, so there is nothing it could be about", trim(one.vulnerability))
		}
		for _, status := range order {
			out = append(out, *byStatus[status])
		}
	}
	return out, nil
}

// targetOf is what a claim points at, in the shape the matcher takes: the
// package identifier where the document gave one, and the name otherwise.
func targetOf(at named) Target {
	target := Target{Purl: at.purl, Name: at.name}
	if target.Purl == "" {
		return target
	}
	// The name off the identifier where the document gave one, for the same
	// reason the OpenVEX reader takes it: a name a person wrote beside a purl
	// is prose, and the identifier is the key.
	base, _ := purlParts(target.Purl)
	if slash := strings.LastIndex(base, "/"); slash >= 0 {
		target.Name = base[slash+1:]
	}
	return target
}
