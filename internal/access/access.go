// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Package access answers who is asking and what they may reach.
//
// Two things are kept apart deliberately. Authenticating establishes who
// somebody is; it says nothing about whether they should be here. So no path
// through this package creates an account, and somebody who authenticates
// perfectly well but was never granted anything is turned away with the same
// answer as somebody unknown — telling an outsider which of the two applies is
// free reconnaissance.
//
// Every question of the form "may this person do this" excludes a deactivated
// account. Deactivation leaves the grant rows in place on purpose — it is the
// recorded act of leaving rather than an undoing of what somebody held — so a
// query reading only grants answers that a departed person is still cleared,
// including the one that gates handing an undisclosed finding to a person or a
// team.
//
// Naming somebody in configuration readmits them, because that is the
// documented way back into a deployment nobody can administer and nothing else
// clears the date.
//
// A revocation that matched nothing is ErrNothingMatched, never success. A
// write that binds only the error from the statement and never reads how many
// rows it matched answers the withdrawal of a role nobody holds as though it
// had been withdrawn — and the caller then writes a trail row saying so and
// hands back every finding the person was dealing with in that product. A
// grant, an estate grant, a group binding, a group's administration and a team
// membership all take access away, and all five read what they matched.
package access

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Role is what somebody may do with a product.
type Role string

const (
	// Approver is a capability rather than a grant of visibility: what it
	// reaches is still bounded by what the person may read. Otherwise
	// handing somebody the ability to approve would quietly hand them
	// everything there is to approve.
	//
	// A reporting role beside it grants nothing. What it reaches for is
	// breadth of view, and statistics are what breadth looks like once
	// aggregated, so saying breadth directly leaves nothing for it to be.
	Approver Role = "approver"
	// Assigner is deciding who deals with something, which is a different
	// act from deciding what it is. Taking unowned work, and handing back
	// your own, are triage; giving work to somebody else, or taking what
	// they hold, is this.
	Assigner Role = "assigner"

	// The reading and triage roles, per visibility.
	PublicRead    Role = "public-read"
	PrivateRead   Role = "private-read"
	PublicTriage  Role = "public-triage"
	PrivateTriage Role = "private-triage"
)

// Roles are the baseline set. It is a floor, not a ceiling.
func Roles() []Role {
	return []Role{
		Approver, Assigner,
		PublicRead, PrivateRead, PublicTriage, PrivateTriage,
	}
}

// Valid reports whether r is a role we recognize.
func (r Role) Valid() bool {
	for _, known := range Roles() {
		if r == known {
			return true
		}
	}
	return false
}

// Over is something held over the deployment rather than over a product.
//
// Two things are, and a role is not one of them: a role names the product it
// applies to, and these name none because what they reach is the deployment's
// own records. Somebody holding one of these and no role reaches no product at
// all.
type Over string

const (
	// Administers is changing what the deployment is set to and who may reach
	// it. Every write path over the deployment's own records asks for it.
	Administers Over = "admin"
	// Audits is reading those records: the settings, who holds what, and the
	// administrative change log. It grants no product's findings or decisions,
	// so an auditor who reads one product goes on reading one product.
	//
	// The records are read whole rather than narrowed by which products the
	// holder reaches, so holding it means knowing which products exist, what
	// their releases are called and how work routes in them. That is a
	// property of the grant rather than a leak: granting it is a deliberate
	// administrative act.
	Audits Over = "audit"
)

// OverTheDeployment is what may be granted over it.
func OverTheDeployment() []Over { return []Over{Administers, Audits} }

// Valid reports whether o is one this deployment recognizes.
func (o Over) Valid() bool {
	for _, known := range OverTheDeployment() {
		if o == known {
			return true
		}
	}
	return false
}

// Visibility says whether something has been disclosed.
//
// It is about disclosure, not about who may read: every request is
// authenticated either way, so a mistake in these rules exposes something to a
// colleague rather than to the internet.
type Visibility string

const (
	// Public means disclosed.
	Public Visibility = "public"
	// Private means not yet disclosed.
	Private Visibility = "private"
)

// AsVisibility reads a stored value, treating anything unrecognized as not
// disclosed. Unset has to read as private, or a column added later defaults
// every existing row to visible.
func AsVisibility(s string) Visibility {
	if Visibility(s) == Public {
		return Public
	}
	return Private
}

// Kind distinguishes the sorts of thing that can be asking.
type Kind string

const (
	// Person is somebody who signed in.
	Person Kind = "person"
	// Pipeline is a build authenticating with a key. It may send scans and do
	// nothing else — no reading, no triage, no reporting — which is what keeps
	// the visibility rules out of a build server's reach entirely.
	Pipeline Kind = "pipeline"
)

// ErrNoSubject is returned when a query is attempted with nobody attached.
//
// It is an error rather than a denial because it is a fault in this program:
// somewhere a query was written that does not say who is asking, and answering
// it would be answering for everybody.
var ErrNoSubject = errors.New("no subject: a query was attempted without saying who is asking")

// ErrDenied is the answer somebody unauthorized is given.
//
// Deliberately the same whether they are unknown, known but granted nothing, or
// granted something that does not cover this. Telling an outsider which of
// those applies is free reconnaissance.
var ErrDenied = errors.New("not authorized")

// ErrNothingMatched is a write that found nothing to act on.
//
// A revocation is the case it exists for: "this grant does not exist" and
// "this grant has been removed" are different answers, and only one of them
// means the caller should go on to record what it did.
var ErrNothingMatched = errors.New("nothing matched")

// Subject is who is asking.
type Subject struct {
	Kind Kind
	// ID is the person or the key, depending on the kind.
	ID int64
	// Identity is what to call them in a record of what was done.
	Identity string
	// Admin is global and belongs to a person. It is one of the two things
	// held over the deployment rather than against a product.
	Admin bool
	// Audits is the other: reading the deployment's own records and writing
	// none of them. An administrator reads them too, so a check asks for
	// either — but somebody holding this alone can change nothing.
	Audits bool
	// grants is what this person may do, per product.
	grants map[int64][]Role
	// scope is what a pipeline's key allows. Absent for a person.
	scope *Scope
	// unnarrowed is the deployment itself rather than anybody in it: the
	// background passes that report on the tool, which answer nobody and
	// are never reachable from a request. It is what an administrator used
	// to be relied on for, and separating the two is what let an
	// administrator stop holding every role.
	unnarrowed bool
	// delegated says this subject arrived on a credential its owner minted
	// rather than by signing in. What it may reach is already bounded by the
	// owner, but it may not mint another: a credential able to issue
	// credentials narrows to nothing, because the narrow one can always ask
	// for a wide one.
	delegated bool
	// party is this person's own name in the assignable name space, and
	// teams are the names of the teams they are on. Carried on the subject
	// rather than looked up where they are needed, because "assigned to
	// me" appears on the list filter, the counts, the digest, the
	// reminders and the handover, and a phrase resolved five ways means
	// five things.
	party int64
	teams []int64
	// cases is the undisclosed work this person was brought into one case
	// at a time, as the issues they collaborate on per product. It grants
	// reading and arguing about those issues and nothing else — not the
	// rest of the product's embargo list, and not a count of it.
	//
	// Carried on the subject for the reason the teams are: the question
	// "may they reach this issue" is asked by the finding, its decisions,
	// its comments and its attachments, and a lookup at each of those is
	// four answers that can disagree.
	cases map[int64][]int64
	// casesReadOnly takes the write half of a case grant away, for a
	// credential narrowed to roles that do not include triage. Inverted so
	// that the zero value acts, which is what every subject not narrowed this
	// way should do.
	casesReadOnly bool
}

// OnCase reports whether this subject was brought into one case: one issue, in
// one product.
//
// Deliberately not part of Reads. A collaborator does not read the product at
// any visibility — that is the whole of what the grant is for — so a check
// asking about the product must keep answering no, and a check about a named
// issue asks this as well.
func (s Subject) OnCase(productID, vulnerabilityID int64) bool {
	if s.Kind != Person {
		return false
	}
	for _, issue := range s.cases[productID] {
		if issue == vulnerabilityID {
			return true
		}
	}
	return false
}

// OnCaseToAct is OnCase asked where something is about to be written.
//
// A case grant is enough to write on its own: a note, an attachment and a
// decision each accept it in place of triage, because somebody brought onto an
// embargoed issue is brought on to work it rather than to watch. That is right
// for the person and wrong for a credential they narrowed to reading — so a
// token carrying no triage role keeps the case's read half and loses its write
// half.
//
// Inverted on purpose. The zero value of a Subject may act, so a subject built
// anywhere without going through a narrowing behaves as an unnarrowed one, and
// the one place that takes the write half away says so.
func (s Subject) OnCaseToAct(productID, vulnerabilityID int64) bool {
	return !s.casesReadOnly && s.OnCase(productID, vulnerabilityID)
}

// Cases is every issue this subject collaborates on in one product. Empty
// where they are on none, which is the ordinary case.
func (s Subject) Cases(productID int64) []int64 { return s.cases[productID] }

// CaseProducts is every product this subject is on a case in. Their own list
// of nothing else: a product reached this way is not one they may know the
// shape of, so it is kept apart from Products.
func (s Subject) CaseProducts() []int64 {
	products := make([]int64, 0, len(s.cases))
	for id := range s.cases {
		products = append(products, id)
	}
	sort.Slice(products, func(i, j int) bool { return products[i] < products[j] })
	return products
}

// Party is this subject's own name in the assignable space: what work assigned
// to them personally is assigned to. Zero for anything that is not a person.
func (s Subject) Party() int64 { return s.party }

// Mine is every party this subject counts as: themselves, and the teams they
// are on. What "assigned to me" resolves to, everywhere it is asked.
//
// Empty for anything that is not a person. A pipeline holds no work.
func (s Subject) Mine() []int64 {
	if s.party == 0 {
		return nil
	}
	return append([]int64{s.party}, s.teams...)
}

// Delegated reports whether this subject arrived on a credential minted by a
// person rather than on a sign-in.
func (s Subject) Delegated() bool { return s.delegated }

// Scope is the set of constraints on a key.
//
// The product is always required. The release and the variant are independent,
// and either, both or neither may be pinned — so a key covers a product, a
// product and a variant, a product and a release, or all three.
type Scope struct {
	ProductID int64
	StreamID  *int64
	VariantID *int64
}

// NewPerson returns the subject for somebody who signed in.
func NewPerson(id int64, identity string, admin bool, grants map[int64][]Role,
	party int64, teams ...int64) Subject {

	return Subject{
		Kind: Person, ID: id, Identity: identity, Admin: admin, grants: grants,
		party: party, teams: teams,
	}
}

// OnCases returns this subject with the cases they were brought into.
//
// Separate from NewPerson rather than another argument to it, because every
// caller of that constructor is a test or a background pass with no cases, and
// a parameter they all pass nil for is a parameter that gets passed the wrong
// thing eventually.
func (s Subject) OnCases(cases map[int64][]int64) Subject {
	s.cases = cases
	return s
}

// Auditing returns this subject holding the deployment's own records.
//
// Chained rather than another argument to NewPerson, for the reason OnCases is:
// every caller of that constructor is a test or a background pass that holds
// none of this, and a parameter they all pass false for is one that gets passed
// the wrong thing eventually.
func (s Subject) Auditing() Subject {
	s.Audits = true
	return s
}

// ReadsTheDeployment reports whether this subject may read the deployment's own
// records: what it is set to, who holds what, and what has been changed.
//
// Either of the two things held over the deployment satisfies it. An
// administrator is not asked to hold the audit permission as well — they can
// grant themselves anything, so requiring it would be a checkbox rather than a
// control.
func (s Subject) ReadsTheDeployment() bool {
	return s.Kind == Person && (s.Admin || s.Audits)
}

// NewPipeline returns the subject for a build authenticating with a key.
func NewPipeline(id int64, name string, scope Scope) Subject {
	return Subject{Kind: Pipeline, ID: id, Identity: name, scope: &scope}
}

// Everything is the deployment looking at itself, for the passes that report
// on the tool rather than answering a person.
//
// Nothing resolves a credential to this. It is constructed where it is
// needed and never handed out, which is what keeps it from being an
// escalation: no sign-in, no key and no header produces it, so it cannot be
// reached by presenting anything.
//
// It is not confined to background work. One request path builds one: naming
// the products that group bindings already refer to, where the caller has been
// authorized to administer bindings and the answer is a list of names rather
// than anything about what those products hold. Every such use carries a
// sentence saying what it is for, and a use that cannot write one is a use
// that should be asking a subject instead. An administrator's subject does not
// stand here: it stopped meaning "sees everything" when it stopped meaning
// "holds every role", and the two are different questions with only one of
// them about a person.
//
// It holds no role, so it triages, approves and decides nothing. What it may
// do is read, which is all these passes ask for.
func Everything(what string) Subject {
	return Subject{Kind: Person, Identity: what, unnarrowed: true}
}

// Unnarrowed reports whether this is the deployment itself rather than
// anybody in it — what Everything makes, for a background pass that answers
// nobody.
//
// Asked by the stores that refuse a subject outright rather than narrowing a
// query for it. Those cannot express "everything" as a filter, so they need
// the question the filtering ones answer by not narrowing at all.
func (s Subject) Unnarrowed() bool { return s.unnarrowed }

// Holds reports whether this subject holds a role on a product.
//
// An administrator does not hold every role. Administration is people,
// roles, credentials, settings, the catalog, and the two acts on the record
// itself — removing an attached file and supplying a third party's evidence
// about a product; reading and triaging are granted on a product like anybody
// else's, and an administrator who wants them grants them to themselves —
// visibly, in the same record everyone else's grants live in.
//
// Read the other way — `privileges.md` says holding every role does not amount
// to admin and never claims the reverse — it costs separation of duties, since
// one account proposes and approves its own work, and it makes a read-only
// auditor impossible to express: nobody can see everything without also being
// able to change everything.
func (s Subject) Holds(role Role, productID int64) bool {
	if s.Kind != Person {
		return false
	}
	for _, held := range s.grants[productID] {
		if held == role {
			return true
		}
	}
	return false
}

// Reads reports whether this subject may read something of this visibility in
// this product.
//
// Triage implies reading at the same visibility: somebody who may decide about
// a finding can necessarily see it, and a deployment that had to grant both
// would eventually grant one.
func (s Subject) Reads(visibility Visibility, productID int64) bool {
	// The deployment reads everything, which is the whole of what it is for.
	// Products and Sees already answered that way and this did not, so a pass
	// that narrowed its own query correctly was still refused by any check
	// asking the question one product at a time.
	if s.unnarrowed {
		return true
	}
	switch visibility {
	case Public:
		return s.Holds(PublicRead, productID) || s.Holds(PublicTriage, productID) ||
			s.Holds(PrivateRead, productID) || s.Holds(PrivateTriage, productID)
	default:
		return s.Holds(PrivateRead, productID) || s.Holds(PrivateTriage, productID)
	}
}

// Triages reports whether a subject may argue about findings of this
// visibility in this product.
//
// The write-side counterpart of Reads, and the same shape: a claim about an
// undisclosed finding needs the role that reads one, and a claim about a
// disclosed one needs either. Here rather than in each package that asks it —
// it was written out twice, byte for byte, and open-coded at six more sites,
// which is seven places for one rule to be got wrong and no place to correct
// it once.
//
// Not folded into Reads. Triage implies reading and reading does not imply
// triage, so a single question would have to be answered "which of the two do
// you mean" at every call site, which is the ambiguity the two names remove.
func (s Subject) Triages(visibility Visibility, productID int64) bool {
	if s.Kind != Person {
		return false
	}
	if visibility == Private {
		return s.Holds(PrivateTriage, productID)
	}
	return s.Holds(PublicTriage, productID) || s.Holds(PrivateTriage, productID)
}

// VisibleOn is which visibilities this subject may read of one named issue in
// one product: what the product's own grant allows, widened by a case they
// were brought into.
//
// Asked wherever a read is about one issue rather than about a product. A
// collaborator reads that issue at any visibility and reads nothing else of
// the product, so the two questions have different answers and both are real.
func VisibleOn(s Subject, productID, vulnerabilityID int64) []Visibility {
	visible := Visible(s, productID)
	if !s.OnCase(productID, vulnerabilityID) {
		return visible
	}
	for _, want := range []Visibility{Public, Private} {
		held := false
		for _, have := range visible {
			held = held || have == want
		}
		if !held {
			visible = append(visible, want)
		}
	}
	return visible
}

// SeesOn reports whether this subject may know one issue in one product
// exists: because they may read the product, or because they were brought into
// that case.
func SeesOn(s Subject, productID, vulnerabilityID int64) bool {
	return s.Sees(productID) || s.OnCase(productID, vulnerabilityID)
}

// Visible is which visibilities this subject may read in one product.
//
// Here rather than in each package that queries, because it is one rule and a
// second spelling of it is a second rule to keep in step with the first. Every
// read narrows by what comes back from this, so a subject who may read only
// what has been disclosed cannot be handed a row that has not been.
func Visible(s Subject, productID int64) []Visibility {
	var visible []Visibility
	for _, v := range []Visibility{Public, Private} {
		if s.Reads(v, productID) {
			visible = append(visible, v)
		}
	}
	return visible
}

// Sees reports whether this subject may know a product exists.
//
// A product somebody holds nothing on is invisible rather than merely
// unreadable — not listed and not counted — because the list of products is
// itself a statement about what an organization ships.
func (s Subject) Sees(productID int64) bool {
	if s.Kind == Pipeline && s.scope != nil {
		// A pipeline knows the product it may send to exists, because it may
		// send to it. It knows nothing about any other.
		return s.scope.ProductID == productID
	}
	if s.Kind != Person {
		return false
	}
	// An administrator administers the catalog, so they know what is in it.
	// The findings open against it are a different question, answered by
	// Products.
	if s.Admin || s.unnarrowed {
		return true
	}
	// A role that grants reading, not merely any role. A capability is
	// bounded by what its holder may read, so holding one alone is not a way
	// in — otherwise granting somebody the ability to approve would show them
	// every release and variant there is to approve.
	return s.Reads(Public, productID) || s.Reads(Private, productID)
}

// HoldsAnywhere reports whether this subject holds one of these roles on any
// product at all.
//
// A coarse check made before a name in a request is resolved, never the
// whole of an authorization. Where the thing being acted on is named by an
// identifier alone — a rating, by its own number — the product it belongs to
// is not known until the row is read, and reading it first for somebody
// holding nothing anywhere would let them walk identifiers. So this runs
// first, and the question about the right product runs after the row is in
// hand and answers in the words a row that is not there gets.
//
// It is not a rule on its own. Every judgment here belongs to a product,
// including a rating (REQ-29), and "holds the role somewhere" is not "may act
// on this".
//
// An administrator holds nothing here they were not granted, as in Holds.
func (s Subject) HoldsAnywhere(roles ...Role) bool {
	if s.Kind != Person {
		return false
	}
	for _, held := range s.grants {
		for _, role := range held {
			for _, wanted := range roles {
				if role == wanted {
					return true
				}
			}
		}
	}
	return false
}

// Products returns the products whose findings this subject may read.
//
// Not every product, for an administrator. Administering the
// catalog is knowing a product exists, which is what Sees answers; this is
// what narrows findings, counts, aggregates and exports, and an administrator
// reads those only where they hold a role. The "all" flag is kept because the
// queries are written around it, and nothing sets it now.
func (s Subject) Products() (ids []int64, all bool) {
	if s.Kind != Person {
		return nil, false
	}
	if s.unnarrowed {
		return nil, true
	}
	for id := range s.grants {
		// The read roles directly, not Sees. Sees answers "may they know this
		// product exists", which is true for an administrator everywhere and
		// true for anybody holding a bare capability here — so an
		// administrator who granted themselves nothing but the ability to
		// approve or to assign on a product got that product into the set
		// that narrows findings, counts, aggregates and exports, and read
		// every disclosed finding in it. A capability grants no visibility of
		// its own, and this is where that stopped being true.
		if s.Reads(Public, id) || s.Reads(Private, id) {
			ids = append(ids, id)
		}
	}
	return ids, false
}

// Knows returns the products this subject may know exist.
//
// Distinct from Products. Knowing a product exists is administering it and
// reading its findings is not, so an administrator is every product here and
// only what they were granted there. For everybody else the two answer alike,
// because a product somebody holds nothing on is invisible rather than merely
// unreadable.
//
// It narrows the catalog. Products narrows findings, counts,
// aggregates and exports — so an administrator holding no role sees the
// products they administer with nothing open against them, which is the honest
// answer rather than a hidden one.
func (s Subject) Knows() (ids []int64, all bool) {
	if s.Kind == Person && s.Admin {
		return nil, true
	}
	return s.Products()
}

// MaySend reports whether a pipeline's key authorizes an upload against this
// exact target.
//
// Every constraint the key carries must match. A mismatch is refused rather
// than redirected: a key that covers one release must not quietly accept a
// scan of another, and an upload states its full target explicitly so there is
// never anything to infer.
func (s Subject) MaySend(productID, streamID, variantID int64) bool {
	if s.Kind != Pipeline || s.scope == nil {
		return false
	}
	if s.scope.ProductID != productID {
		return false
	}
	if s.scope.StreamID != nil && *s.scope.StreamID != streamID {
		return false
	}
	if s.scope.VariantID != nil && *s.scope.VariantID != variantID {
		return false
	}
	return true
}

// sessionKey carries the browser session a request arrived on, where it
// arrived on one. It is separate from the subject because most requests have
// no session — a pipeline's key and a proxy's header both resolve to a subject
// without one — and because what it is for is narrow: deciding whether a
// state-changing request was made by our own page or by somebody else's.
type sessionKey struct{}

// WithSession attaches the session a request arrived on.
func WithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, session)
}

// SessionFrom returns the session a request arrived on, if it arrived on one.
func SessionFrom(ctx context.Context) *Session {
	session, _ := ctx.Value(sessionKey{}).(*Session)
	return session
}

// contextKey is unexported so nothing outside this package can put a subject
// into a context by accident, or take one out without going through here.
type contextKey struct{}

// With attaches a subject to a context.
func With(ctx context.Context, s Subject) context.Context {
	return context.WithValue(ctx, contextKey{}, s)
}

// From reads the subject a request resolved to.
//
// It fails rather than defaulting. A query that reaches the database without
// saying who is asking is a bug in this program, and the safe-looking
// alternative — treating absence as "nobody, so show nothing" — hides it until
// somebody writes the query that treats absence as "everybody".
func From(ctx context.Context) (Subject, error) {
	s, ok := ctx.Value(contextKey{}).(Subject)
	if !ok {
		return Subject{}, ErrNoSubject
	}
	return s, nil
}

// Identities normalizes a configured list of people.
func Identities(raw string) []string {
	var out []string
	for _, name := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// Denied wraps a refusal with what was being attempted, for the log rather
// than for the person.
func Denied(what string) error { return fmt.Errorf("%w: %s", ErrDenied, what) }
