package httpapi

import (
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// What an operation asks of whoever calls it.
//
// Structured on the document and rendered into the description from the same
// value, so the two cannot disagree. The structure is what a client generator
// or an access review reads; the line is what somebody scanning the reference
// sees. Written twice by hand, one would be wrong within a month.
const requiresExtension = "x-openpsirt-requires"

// Scope says what a right is held against.
const (
	// perProduct is a role granted on the product the request names.
	perProduct = "product"
	// deploymentWide is administrator, which is not held per product.
	deploymentWide = "deployment"
	// anyProduct is a role held on any product at all, for the few acts
	// that are not about a product: a rating is a claim about an issue, so
	// there is no product to hold a role on.
	anyProduct = "any-product"
	// anySubject is any credential this deployment recognizes. It still
	// answers only what that subject may see.
	anySubject = "any"
	// ownSubject is whoever is asking, about themselves.
	ownSubject = "self"
	// noCredential is the handful of operations answered before anybody has
	// one. Named rather than left as anySubject with a note contradicting it:
	// the generated reference said "requires any recognized credential" and
	// then "answered without a credential" one line apart, which is a rule
	// nobody can follow.
	noCredential = "none"
)

// requires describes what an operation asks for.
type requires struct {
	// Scope is what the rights are held against.
	Scope string `json:"scope"`
	// AnyOf lists the roles that satisfy it. Any one is enough; empty means
	// the scope alone is the requirement.
	AnyOf []string `json:"any_of,omitempty"`
	// Note is what a caller must know that the roles do not say — a narrowing
	// that is not a role, or a control that refuses somebody holding every
	// role listed.
	Note string `json:"note,omitempty"`
	// Narrowed says the roles decide what comes back rather than whether the
	// operation answers at all.
	//
	// The distinction was implicit and it is the whole difference between two
	// kinds of rule. A gate refuses somebody who holds none of the roles. A
	// narrowed operation answers everybody and the roles decide what is in the
	// answer — somebody holding none gets an empty list, or a count of zero,
	// which is the correct answer rather than a leak. Read as if it were a
	// gate, an operation of the second kind looks like one whose check is
	// missing; read as if it were narrowed, one of the first kind hides a real
	// hole. So it is stated, and the sweep that checks every gate refuses a
	// stranger reads it to know which operations it is talking about.
	Narrowed bool `json:"narrowed,omitempty"`
}

// said renders the requirement as the line the reference shows: short, and the
// same shape every time, because it is read in a list of ninety.
func (r requires) said() string {
	var what string
	switch {
	case len(r.AnyOf) > 0:
		what = strings.Join(r.AnyOf, " or ")
	case r.Scope == deploymentWide:
		what = "administrator"
	case r.Scope == ownSubject:
		what = "your own credential"
	case r.Scope == noCredential:
		what = "nothing: this is answered before anybody has a credential"
	default:
		what = "any recognized credential"
	}
	switch r.Scope {
	case perProduct:
		what += " on the product"
	case anyProduct:
		what += " on any product"
	case deploymentWide:
		if len(r.AnyOf) > 0 {
			what += ", deployment-wide"
		}
	}
	if r.Narrowed && len(r.AnyOf) > 0 {
		what += ". What you hold decides what comes back rather than whether " +
			"you may ask"
	}
	if r.Note != "" {
		what += ". " + r.Note
	}
	return what
}

// requiring records what an operation asks for, on the operation and in its
// description, from one value.
func requiring(op huma.Operation, scope, note string, roles ...access.Role) huma.Operation {
	return declaring(op, requires{Scope: scope, Note: note}, roles...)
}

// answering is requiring for the operations the roles narrow rather than gate:
// somebody holding none of them is answered, with nothing of theirs in it.
func answering(op huma.Operation, scope, note string, roles ...access.Role) huma.Operation {
	return declaring(op, requires{Scope: scope, Note: note, Narrowed: true}, roles...)
}

func declaring(op huma.Operation, asks requires, roles ...access.Role) huma.Operation {
	stated := make([]string, 0, len(roles))
	for _, role := range roles {
		stated = append(stated, string(role))
	}
	asks.AnyOf = stated

	if op.Extensions == nil {
		op.Extensions = map[string]any{}
	}
	op.Extensions[requiresExtension] = asks
	op.Description = strings.TrimRight(op.Description, "\n ") + "\n\n**Requires:** " + asks.said()
	return op
}

// triageRights is the pair meaning "may argue about findings here". Either is
// enough; which of the two decides what is visible rather than what is allowed.
func triageRights() []access.Role {
	return []access.Role{access.PublicTriage, access.PrivateTriage}
}

// approveRights is who may agree to a claim: the capability, or a triager on
// somebody else's work. That the two are different people is checked
// separately and has no override.
func approveRights() []access.Role {
	return []access.Role{access.Approver, access.PublicTriage, access.PrivateTriage}
}

// privateRights is who may read work nobody has announced.
func privateRights() []access.Role {
	return []access.Role{access.PrivateRead, access.PrivateTriage}
}
