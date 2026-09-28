// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package sbom

import (
	"fmt"
	"strings"

	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
)

// Reading CSAF-VEX, the second of the two shapes a supplier's VEX as evidence
// names alongside OpenVEX. The same walk reads a supplier's security advisory,
// which states the same claims inside a document that means something else
// (see csafadvisory.go).
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
// A distribution names a product as a package inside a platform, joined by a
// relationship: the claims point at a composite identifier, the tree defines
// the package under one branch and the platform under another, and neither is
// what a claim names. The package is what we ship, so a composite resolves to
// the package it refers to.
//
// A product identifier that resolves to nothing is dropped, and a claim left
// pointing at nothing is refused. A claim we cannot place is a build's
// judgment going missing quietly, which is the failure this whole arrangement
// exists to remove.

// vexProfile is what a CSAF-VEX document says it is.
//
// The profile a document states is what decides how it is read. A VEX document
// is a publisher's statement set about what a build ships; an advisory is an
// announcement about the publisher's own flaws, superseded by name and read
// through a route of its own. Each refuses the other rather than reading it
// under the wrong meaning.
const vexProfile = "csaf_vex"

// named is one product the tree defines: what to call it, the package
// identifier where the document gave one, and the version where it stated one
// as a branch rather than inside an identifier.
type named struct {
	purl    string
	name    string
	version string
}

// joins is what a relationship says: the package the composite identifier
// stands for, and whatever the relationship named the composite itself.
type joins struct {
	reference string
	own       named
}

// claimed is one vulnerability's claims before the tree has been resolved.
type claimed struct {
	vulnerability string
	aliases       []string
	// byProduct is the status each product identifier was listed under, and
	// listed the order they were read in. A map has no first, so which of
	// several sentences stands for a claim, which order its products are
	// carried in and which order the claims come back would all be whatever
	// the runtime chose that minute — and the same document uploaded twice
	// would store different reasoning under a digest saying nothing moved.
	byProduct map[string]Status
	listed    []string
	// whole is the justification the document gave the whole claim, in a flag
	// naming no product. A later one wins, so only the last is kept.
	whole string
	// flags are the justifications naming products, in the order the document
	// gave them, each with the products it names. A later flag naming a
	// product wins over an earlier one.
	flags []scoped
	// said is the prose, per status, for the words that named no product. An
	// impact statement belongs to the products called not affected and an
	// action statement to the affected ones, and reading either into both
	// would attach an argument to a claim it was not made about.
	said map[Status]string
	// told is the prose that named the products it was about, which is the
	// precise answer where a document gives one. An advisory's remediation
	// names the packages to upgrade, and those are listed as fixed rather than
	// as affected — so the category alone puts the one useful sentence in an
	// advisory on a claim that does not exist. The first sentence naming a
	// product is the one it keeps.
	told []scoped
}

// scoped is words the document wrote and the products it wrote them about,
// by identifier and by group.
//
// Groups are kept as named rather than expanded as they are read. The tree
// that defines them may arrive after the claims, and a group expanded before
// it is read holds nothing — which turns words about some products into
// words about the whole claim.
type scoped struct {
	words  string
	ids    []string
	groups []string
}

// names reports whether the words were scoped to any product at all. A list
// of groups is a scope even where no group it names holds anything: the
// document said which products it meant, and none of them is the whole claim.
func (s scoped) names() bool { return len(s.ids) > 0 || len(s.groups) > 0 }

type csafReader struct {
	b   *bounded
	lim Limits
	// profile is which kind of document this reader was opened for and
	// category what the document states. A document of the other profile is
	// refused naming where it does belong.
	profile  string
	category string
	// publisher, identifier and title are what the document says about
	// itself. An advisory is superseded on its own name, so these are read
	// on both paths rather than only where they are used.
	publisher  string
	identifier string
	title      string
	tree       map[string]named
	// joined is a composite product identifier and the package it refers to.
	// Kept apart from the tree because the package it names may be defined
	// after it, and because a relationship may carry an identifier of its own
	// that is better than the one on the package.
	joined map[string]joins
	// groups is what each product group holds. A flag, a remediation or a
	// threat names the products it is about by identifier or by group, and
	// the two mean the same thing.
	groups map[string][]string
	// defined is which products the branch being walked has defined, so the
	// branch that names a version can reach them once it closes.
	defined  []string
	claims   []*claimed
	statuses map[string]Status
	// charged is every identifier this document has made the reader hold: a
	// product the tree defines, a product a claim lists, a product a sentence
	// names, and an identifier an issue also goes by.
	//
	// Kept as a set rather than a count because one identifier is named in
	// several places — a product listed under a status and again in the
	// remediation about it — and what this bound is for is how many distinct
	// things the document describes.
	charged map[string]struct{}
	// held is every entry the reader keeps, one per mention: a product the
	// tree defines, a group, a member of a group, a product a claim lists, a product or
	// group a sentence names, an identifier an issue also goes by, and each
	// member a group stands for once a reference to it is expanded. The set
	// above charges a re-mention nothing, and a re-mention is still an entry
	// held.
	held int
}

// name charges one more distinct identifier this document describes.
//
// Charged on the way in, before anything is kept. The claim count counts
// vulnerability objects, so one claim listing ten million product identifiers
// is under it. What a bound has to stop is the walk, and a count taken after
// the walk has already done the work.
//
// Against the component bound, because these are what a suppression document
// describes and they cost what a component costs to hold. A ceiling of its own
// would be a setting nobody could reason about separately.
func (r *csafReader) name(id string) error {
	if _, held := r.charged[id]; held {
		return nil
	}
	if len(r.charged) >= r.lim.MaxComponents {
		return refusal.Errorf("the document names more than the %d product limit",
			r.lim.MaxComponents)
	}
	r.charged[id] = struct{}{}
	return nil
}

// mentionsPerProduct is how many entries the reader may hold for each
// product the component bound allows.
//
// A real advisory names each product many times — under a status and again
// in the remediation about it, once per issue. A distribution's kernel
// advisory names 794 products 220,088 times, a fifth of the million entries
// the default bound allows. Measured, an entry held costs about 170 bytes
// through to the claims returned, so a million is about 170 MB, inside the
// budget one document is read in. Without the ceiling, one group of fifty
// thousand products referenced four thousand times is two hundred million
// entries from under a megabyte.
const mentionsPerProduct = 10

// hold charges entries the reader is about to keep, before it keeps them.
//
// Called with a group's size before a reference to it is expanded, so a
// reference costs what it stands for rather than the one identifier it is
// written as.
func (r *csafReader) hold(n int) error {
	ceiling := r.lim.MaxComponents * mentionsPerProduct
	if n > ceiling-r.held {
		return refusal.Errorf("the document names its products more than the %d times "+
			"the %d product limit allows", ceiling, r.lim.MaxComponents)
	}
	r.held += n
	return nil
}

// csafStatuses maps a product-status list to what it claims.
//
// Every list the format defines states something definite about the versions
// it names, and each is read at those versions and no further. The range
// reading is the one that would be a guess — that everything after a first
// fixed version is fixed, or everything before a last affected one is affected
// — and nothing here takes it: a claim names the versions it names, and a
// component at any other version is not what the publisher spoke about.
//
// A distribution's advisory says nothing else. Two of these lists are the only
// status it carries: SUSE states a recommended version and nothing more, and
// Siemens states the affected ones.
var csafStatuses = map[string]Status{
	"known_not_affected": NotAffected,
	"known_affected":     Affected,
	// The first and last affected versions are affected versions. What is not
	// read is the range between them, which the document does not enumerate.
	"first_affected": Affected,
	"last_affected":  Affected,
	"fixed":          AlreadyFixed,
	// A first fixed version carries the fix, and a recommended one carries it
	// and is the one to take. Both are a fixed version at the version named.
	"first_fixed":         AlreadyFixed,
	"recommended":         AlreadyFixed,
	"under_investigation": UnderInvestigation,
}

func newCSAF(b *bounded, lim Limits) *csafReader {
	return &csafReader{
		b: b, lim: lim, profile: vexProfile,
		tree: map[string]named{}, joined: map[string]joins{},
		groups: map[string][]string{}, charged: map[string]struct{}{},
		statuses: csafStatuses,
	}
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
	if !strings.EqualFold(strings.TrimSpace(r.category), r.profile) {
		return nil, r.wrongProfile()
	}
	return r.resolve()
}

// ErrWrongProfile says a CSAF document is not the kind the reader was opened
// for.
//
// A sentinel because a caller reading a whole directory has to tell it from a
// document that could not be read at all: one is a publisher issuing more than
// one kind of document, which is ordinary, and the other is something wrong.
// The two read identically as text.
var ErrWrongProfile = refusal.New("a CSAF document of another kind")

// wrongProfile is the refusal for a document this reader was not opened for,
// which names the path that does read it.
//
// A VEX document read as an advisory is superseded under a name it does not
// carry, and an advisory read as a VEX document takes a publisher's
// announcement about their own flaws as claims about what a build ships —
// every product it names becoming a suppression.
func (r *csafReader) wrongProfile() error {
	said := strings.TrimSpace(r.category)
	switch {
	case said == "":
		return fmt.Errorf("%w: a document that states no CSAF category, so which kind of "+
			"document it is cannot be settled", ErrWrongProfile)
	case strings.EqualFold(said, advisoryProfile):
		return fmt.Errorf("%w: that is a security advisory rather than a VEX document. "+
			"It is read as a supplier advisory, where its claims are evidence about the "+
			"versions it names", ErrWrongProfile)
	case strings.EqualFold(said, vexProfile):
		return fmt.Errorf("%w: that is a VEX document rather than a security advisory. "+
			"It is read as VEX statements, where a publisher's whole statement set "+
			"supersedes what they said before", ErrWrongProfile)
	default:
		return fmt.Errorf("%w: a CSAF document of category %q, which is not one this reads",
			ErrWrongProfile, trim(said))
	}
}

// document is what the document says about itself: which profile it is, who
// issued it, what they called it and the name a revision of it replaces.
func (r *csafReader) document() error {
	return r.b.object(func(key string) error {
		switch key {
		case "category":
			value, err := r.b.str()
			r.category = value
			return err
		case "title":
			value, err := r.b.str()
			r.title = value
			return err
		case "publisher":
			return r.b.object(func(field string) error {
				if field != "name" {
					return r.b.skip()
				}
				value, err := r.b.str()
				r.publisher = value
				return err
			})
		case "tracking":
			return r.b.object(func(field string) error {
				if field != "id" {
					return r.b.skip()
				}
				value, err := r.b.str()
				r.identifier = value
				return err
			})
		default:
			return r.b.skip()
		}
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
			return r.b.array(func() error {
				id, err := r.product()
				if id != "" {
					r.defined = append(r.defined, id)
				}
				return err
			})
		case "relationships":
			return r.b.array(func() error { return r.relationship() })
		case "product_groups":
			return r.b.array(func() error { return r.productGroup() })
		default:
			return r.b.skip()
		}
	})
}

// productGroup reads one named set of products.
//
// A flag, a remediation or a threat says which products it is about with
// either a list of identifiers or a list of groups, and the two mean the same
// thing. Read only the first and a sentence scoped by group falls through to
// the words written about the status at large — so an upgrade instruction
// lands on a claim the document never made it about.
func (r *csafReader) productGroup() error {
	var (
		id  string
		has []string
	)
	err := r.b.object(func(key string) error {
		switch key {
		case "group_id":
			value, err := r.b.str()
			id = value
			return err
		case "product_ids":
			return r.b.array(func() error {
				product, err := r.b.str()
				if err != nil {
					return err
				}
				if product != "" {
					if err := r.name(product); err != nil {
						return err
					}
					if err := r.hold(1); err != nil {
						return err
					}
					has = append(has, product)
				}
				return nil
			})
		default:
			return r.b.skip()
		}
	})
	if err != nil {
		return err
	}
	if id != "" {
		// The group's own entry, which a group holding no product would
		// otherwise keep for nothing.
		if err := r.hold(1); err != nil {
			return err
		}
		r.groups[id] = has
	}
	return nil
}

// relationship reads one join between a package and the platform it ships in.
//
// The claims point at the composite identifier, which names neither the
// package nor the platform on its own. What we ship is the package, so the
// composite stands for the package it refers to — and where the relationship
// carries an identifier of its own it is the better one, because it describes
// the package as that platform ships it.
//
// Which kind of relationship it is does not change the answer. All five
// categories the format defines are the same shape — the reference names the
// thing and what it relates to names the context it is in — so the reference
// is the half a component here can be, whether it is a component of a
// product, installed on one, or shipped with one.
func (r *csafReader) relationship() error {
	var (
		id   string
		join joins
	)
	err := r.b.object(func(key string) error {
		switch key {
		case "product_reference":
			value, err := r.b.str()
			join.reference = value
			return err
		case "full_product_name":
			return r.b.object(func(field string) error {
				switch field {
				case "product_id":
					value, err := r.b.str()
					id = value
					return err
				case "name":
					value, err := r.b.str()
					join.own.name = value
					return err
				case "product_identification_helper":
					return r.b.object(func(helper string) error {
						if helper != "purl" {
							return r.b.skip()
						}
						value, err := r.b.str()
						join.own.purl = value
						return err
					})
				default:
					return r.b.skip()
				}
			})
		default:
			return r.b.skip()
		}
	})
	if err != nil {
		return err
	}
	if id == "" || join.reference == "" {
		return nil
	}
	if err := r.name(id); err != nil {
		return err
	}
	r.joined[id] = join
	return nil
}

// branches walks the tree, and carries the version an enclosing branch names
// down to the products defined under it.
//
// A publisher that states no package identifier states the version as a
// branch: the branch is categorized `product_version` and its name is the
// version, with the product defined inside it. Read without it, a claim about
// one version of an appliance is a claim about the name alone — it offers its
// prefill at every version, and the screen has no version to show beside the
// status. That is the ordinary shape for an equipment vendor rather than an
// exception.
//
// Applied after the branch closes rather than as it opens, because nothing in
// the format promises that a branch names itself before it names what is
// inside it. The innermost version wins: an inner branch fills its products
// first, and an outer one only fills what is still empty.
func (r *csafReader) branches() error {
	return r.b.array(func() error {
		var (
			category string
			name     string
			within   []string
		)
		err := r.b.object(func(key string) error {
			switch key {
			case "category":
				value, err := r.b.str()
				category = value
				return err
			case "name":
				value, err := r.b.str()
				name = value
				return err
			case "branches":
				defined, err := r.branchesDefining()
				within = append(within, defined...)
				return err
			case "product":
				id, err := r.product()
				if id != "" {
					within = append(within, id)
				}
				return err
			default:
				return r.b.skip()
			}
		})
		if err != nil {
			return err
		}
		if category == "product_version" && name != "" {
			for _, id := range within {
				at := r.tree[id]
				if at.version == "" {
					at.version = name
					r.tree[id] = at
				}
			}
		}
		r.defined = append(r.defined, within...)
		return nil
	})
}

// branchesDefining walks a nested set of branches and answers which products
// it defined, so the branch above can name their version.
func (r *csafReader) branchesDefining() ([]string, error) {
	was := r.defined
	r.defined = nil
	err := r.branches()
	defined := r.defined
	r.defined = was
	return defined, err
}

func (r *csafReader) product() (string, error) {
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
		return "", err
	}
	if id == "" || (one.purl == "" && one.name == "") {
		return "", nil
	}
	if err := r.name(id); err != nil {
		return "", err
	}
	// Held once per definition as well: the branch walk keeps every product
	// it defined, so a product defined again is another entry.
	if err := r.hold(1); err != nil {
		return "", err
	}
	// The version inside the identifier where there is one, so that a branch
	// above cannot overwrite what the document already stated precisely.
	_, one.version = graph.PackageOf(one.purl)
	r.tree[id] = one
	return id, nil
}

func (r *csafReader) vulnerability() error {
	// Compared before the object is read, so that the claim past the limit is
	// refused rather than walked in full and then refused.
	if len(r.claims) >= r.lim.MaxStatements {
		return refusal.Errorf("more claims than the %d limit", r.lim.MaxStatements)
	}
	one := &claimed{
		byProduct: map[string]Status{},
		said:      map[Status]string{},
	}
	var (
		cve string
		ids []string
	)
	err := r.b.object(func(key string) error {
		switch key {
		case "cve":
			value, err := r.b.str()
			if cve == "" {
				cve = value
			}
			return err
		case "ids":
			return r.ids(&ids)
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
	// Settled once the object is closed, because the producer chooses the key
	// order. The CVE is the issue's name wherever the document states one, and
	// the other identifiers are what the same issue also goes by.
	switch {
	case cve != "":
		one.vulnerability, one.aliases = cve, ids
	case len(ids) > 0:
		one.vulnerability, one.aliases = ids[0], ids[1:]
	default:
		return refusal.Errorf("a claim names no vulnerability, so there is nothing it could be about")
	}
	r.claims = append(r.claims, one)
	return nil
}

// ids reads the other names one issue goes by. The first is the issue's own
// name where no CVE is given: a document about something with no CVE still
// names it something, and refusing it would drop the claim.
func (r *csafReader) ids(into *[]string) error {
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
		if err := r.name(text); err != nil {
			return err
		}
		if err := r.hold(1); err != nil {
			return err
		}
		*into = append(*into, text)
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
			if id == "" {
				return nil
			}
			if err := r.name(id); err != nil {
				return err
			}
			if _, held := one.byProduct[id]; !held {
				if err := r.hold(1); err != nil {
					return err
				}
				one.listed = append(one.listed, id)
			}
			one.byProduct[id] = status
			return nil
		})
	})
}

// scope reads the products one set of words is about, by identifier or by
// group — the two ways the format allows, which mean the same thing. It
// reports whether the key was one of those two.
func (r *csafReader) scope(key string, into *scoped) (bool, error) {
	switch key {
	case "product_ids":
		return true, r.b.array(func() error {
			id, err := r.b.str()
			if err != nil || id == "" {
				return err
			}
			if err := r.name(id); err != nil {
				return err
			}
			if err := r.hold(1); err != nil {
				return err
			}
			into.ids = append(into.ids, id)
			return nil
		})
	case "group_ids":
		return true, r.b.array(func() error {
			group, err := r.b.str()
			if err != nil || group == "" {
				return err
			}
			if err := r.hold(1); err != nil {
				return err
			}
			into.groups = append(into.groups, group)
			return nil
		})
	}
	return false, nil
}

// flags are the justifications, each naming the products it applies to. A flag
// with no products applies to all of this vulnerability's, which is how the
// format spells "the whole claim".
func (r *csafReader) flags(one *claimed) error {
	return r.b.array(func() error {
		var flag scoped
		if err := r.b.object(func(key string) error {
			if key == "label" {
				value, err := r.b.str()
				flag.words = value
				return err
			}
			if read, err := r.scope(key, &flag); read {
				return err
			}
			return r.b.skip()
		}); err != nil {
			return err
		}
		switch {
		case flag.words == "":
		case !flag.names():
			// Overwritten rather than kept, so a document repeating an
			// unscoped flag holds one of them.
			one.whole = flag.words
		default:
			one.flags = append(one.flags, flag)
		}
		return nil
	})
}

// prose reads the words attached to a claim.
//
// Kept with the products they name where they name any, because that is the
// document saying which claim it is arguing about. An advisory's remediation
// names the packages to upgrade and lists those same packages as fixed, so
// read by category alone the sentence a triager wants lands on an affected
// claim the document never made.
//
// Where the words name no product, the category decides: an impact statement
// argues that something is not affected and an action statement says what to
// do about something that is, and reading either into both would attach an
// argument to a claim it was not made about.
func (r *csafReader) prose(one *claimed, to Status, field string) error {
	return r.b.array(func() error {
		var words scoped
		if err := r.b.object(func(key string) error {
			if key == field {
				value, err := r.b.str()
				words.words = value
				return err
			}
			if read, err := r.scope(key, &words); read {
				return err
			}
			return r.b.skip()
		}); err != nil {
			return err
		}
		switch {
		case words.words == "":
		case words.names():
			one.told = append(one.told, words)
		case one.said[to] == "":
			one.said[to] = words.words
		}
		return nil
	})
}

// expand is every product a set of words names, with each group reference
// replaced by what the group holds.
//
// Asked once the document is closed, so a group defined after the words that
// name it holds what the tree says it holds. Each member is charged before it
// is visited.
func (r *csafReader) expand(words scoped, visit func(id string)) error {
	for _, id := range words.ids {
		visit(id)
	}
	for _, group := range words.groups {
		members := r.groups[group]
		if err := r.hold(len(members)); err != nil {
			return err
		}
		for _, id := range members {
			visit(id)
		}
	}
	return nil
}

// scopedWords is what a claim's flags and prose say about each product it
// names. A justification the document gave the whole claim is under the empty
// identifier. A later flag wins over an earlier one and the first sentence
// naming a product wins over the rest, which is the order the document gave
// them in.
func (r *csafReader) scopedWords(one *claimed) (flagged, told map[string]string, err error) {
	flagged, told = map[string]string{}, map[string]string{}
	if one.whole != "" {
		flagged[""] = one.whole
	}
	for _, flag := range one.flags {
		if err := r.expand(flag, func(id string) { flagged[id] = flag.words }); err != nil {
			return nil, nil, err
		}
	}
	for _, words := range one.told {
		err := r.expand(words, func(id string) {
			if told[id] == "" {
				told[id] = words.words
			}
		})
		if err != nil {
			return nil, nil, err
		}
	}
	return flagged, told, nil
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
		flagged, told, err := r.scopedWords(one)
		if err != nil {
			return nil, err
		}
		byStatus := map[Status]*Suppression{}
		order := make([]Status, 0, 4)
		for _, id := range one.listed {
			status := one.byProduct[id]
			at, held := r.defines(id)
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
				}
				byStatus[status] = claim
				order = append(order, status)
			}
			// Words that named this product say what the document is arguing
			// about it, and the first of them stands for the claim — one claim
			// carries one sentence and every product under it shares a status.
			if said := told[id]; said != "" && claim.Statement == "" {
				claim.Statement = said
			}
			// The justification for this product, or the one the document
			// gave for the whole claim.
			if claim.Justification == "" {
				if said, held := flagged[id]; held {
					claim.Justification = said
				} else if said, held := flagged[""]; held {
					claim.Justification = said
				}
			}
			claim.Targets = append(claim.Targets, targetOf(at))
		}
		if len(order) == 0 {
			return nil, refusal.Errorf("the claim about %s points at no product this document "+
				"defines, so there is nothing it could be about", trim(one.vulnerability))
		}
		for _, status := range order {
			claim := byStatus[status]
			// The words the document wrote about the status at large, where
			// nothing was written about a product under it. A sentence naming
			// its products is the more precise of the two and wins, which it
			// cannot do if the general one is put in place first.
			if claim.Statement == "" {
				claim.Statement = one.said[status]
			}
			out = append(out, *claim)
		}
	}
	return out, nil
}

// defines is what a product identifier stands for, and whether the document
// defined it at all.
//
// A composite identifier is resolved through the relationship that made it,
// down to the package the platform ships. The package identifier the
// relationship carries wins over the one on the package alone: it describes
// the package as that platform ships it, which is the thing a component here
// actually is.
func (r *csafReader) defines(id string) (named, bool) {
	if at, held := r.tree[id]; held {
		return at, true
	}
	join, held := r.joined[id]
	if !held {
		return named{}, false
	}
	if join.own.purl != "" {
		return join.own, true
	}
	at, held := r.tree[join.reference]
	if !held {
		// A relationship pointing at a package the tree never defines leaves
		// whatever the relationship itself said, which is a name and no more.
		// That covers a reference to another composite as well: the format
		// permits one, and following a chain of them is a walk that can cycle
		// for a name the relationship has already given.
		return join.own, join.own.name != ""
	}
	return at, true
}

// targetOf is what a claim points at, in the shape the matcher takes: the
// package identifier where the document gave one, and the name otherwise.
func targetOf(at named) Target {
	target := Target{Purl: at.purl, Name: at.name, Version: at.version}
	if target.Purl == "" {
		return target
	}
	// The name off the identifier where the document gave one, for the same
	// reason the OpenVEX reader takes it: a name a person wrote beside a purl
	// is prose, and the identifier is the key.
	target.Name = nameOf(target.Purl)
	return target
}
