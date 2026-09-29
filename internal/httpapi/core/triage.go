// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/graph"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// DecisionBody is a claim about a finding.
type DecisionBody struct {
	ID int64 `json:"id,omitempty" doc:"The name for this decision in a later request"`
	// ClaimID is the action this row was written by. The review queue lists
	// claims and approval works on them; a decision is one row of one.
	ClaimID int64   `json:"claim_id,omitempty" doc:"The claim this decision is one row of: the action that wrote it, which is what the review queue lists and what is approved"`
	Outcome Outcome `json:"outcome" doc:"The outcome"`
	// Justification is required for not-applicable and meaningless elsewhere:
	// the claim that something does not affect us names one of the recognized
	// reasons.
	Justification Justification `json:"justification,omitempty" doc:"The reason it does not apply. Required when it does not"`
	// Mitigation is the one claim here that rests on configuration rather
	// than on code, so it is the one thing nothing will notice going away.
	// Naming it does not fix that; it makes the claim checkable.
	Mitigation    string `json:"mitigation,omitempty" maxLength:"65536" doc:"The mitigation that stops it — the rule, the setting, the service that is not exposed. Required when the reason is that mitigations already exist, optional when the outcome is that this will not be fixed, and refused otherwise"`
	DeferredUntil string `json:"deferred_until,omitempty" doc:"The date a deferral returns. Required for a deferral"`
	// FixedVersion makes the already-fixed claim checkable against whoever
	// packages the component, rather than something taken on trust.
	FixedVersion string `json:"fixed_version,omitempty" doc:"The package version whoever packages this states the fix arrived in. Required when the outcome is already-fixed, and refused with any other. Recorded and never compared against the version shipping"`
	// CommittedTo is when the work an outcome promises will be done, for
	// the two that promise work. Without it there is nothing to gate
	// against and nothing to lapse.
	CommittedTo string `json:"committed_to,omitempty" doc:"The date the promised work lands. Required for patch-needed and upgrade-needed, and refused with any other"`
	// UpgradeTo is the version an upgrade moves to. Written by the component
	// screen rather than here: a bump answers a component, not one finding.
	UpgradeTo string `json:"upgrade_to,omitempty" doc:"The version an upgrade moves to. Carried on an upgrade-needed decision, which is recorded from a component rather than from one finding"`
	Reasoning string `json:"reasoning" minLength:"1" doc:"The reasoning, in markdown. Somebody else has to agree with this"`
	// FromStatement cites a VEX statement this was started from. A citation
	// and never an application: their statement is not this claim, and the
	// citation is what lets a later revision be noticed.
	FromStatement int64      `json:"from_statement,omitempty" doc:"A VEX statement this was started from, by its identifier. Recorded as a citation so a later revision to it raises an alert. It is never what the claim rests on"`
	State         ClaimState `json:"state,omitempty" doc:"The state it has reached"`
	// NeedsApproval says whether this is waiting for a second person. A short
	// deferral is not.
	NeedsApproval bool `json:"needs_approval,omitempty" doc:"Whether a second person has to agree before it takes effect"`
	// Places is how many findings this one judgment covers. A kernel issue
	// reaches dozens of modules and the answer is usually the same for all of
	// them, so whoever is deciding is told the size of what they are deciding.
	Places int `json:"places,omitempty" doc:"The number of findings this decision covers"`
	// Versions is how many distinct versions sit at this place. More than one
	// means a single decision cannot honestly cover all of them.
	Versions int `json:"versions,omitempty" doc:"The number of versions of the component here. More than one needs care"`
	// SentBackAt is when an approver last asked for more before they would
	// agree. Reported, because otherwise the only trace of it is a comment,
	// and the author's own list cannot tell a claim waiting on somebody else
	// from one waiting on them.
	SentBackAt string `json:"sent_back_at,omitempty" doc:"The last time an approver asked for more. Empty means nobody has"`
	// SelectedBy is the narrowing behind the set, where this claim was one of
	// many recorded in a single action. Reported so the choice of set has an
	// answer months later.
	SelectedBy string `json:"selected_by,omitempty" doc:"The narrowing behind a claim recorded as one of many. Never part of the claim itself"`
}

// FindingRefBody is the subject of a decision, as the findings list shows it:
// the build to link to, the issue, the component and where it sits.
type FindingRefBody struct {
	Product       string  `json:"product" doc:"The build to link to, by product, branch or tag, and variant. The product by the name that addresses it"`
	ProductName   string  `json:"product_name,omitempty" doc:"The product's display name, or its name where it has none"`
	Stream        string  `json:"stream"`
	StreamName    string  `json:"stream_name,omitempty" doc:"The branch or tag as it was spelled, or its name where no spelling was recorded"`
	Variant       string  `json:"variant"`
	VariantName   string  `json:"variant_name,omitempty" doc:"The variant as it was spelled, or its name where no spelling was recorded"`
	Vulnerability string  `json:"vulnerability" doc:"The issue, under the name it is most widely known by"`
	Component     string  `json:"component"`
	Version       string  `json:"version" doc:"The version that ships"`
	Ecosystem     string  `json:"ecosystem,omitempty" doc:"The kind of package, as its identifier spells it"`
	Namespace     string  `json:"namespace,omitempty" doc:"The namespace its package identifier names, where it names one"`
	Severity      string  `json:"severity,omitempty" doc:"Our rating where one stands, else as published"`
	Score         float64 `json:"score,omitempty"`
	ScoreVersion  string  `json:"score_version,omitempty" doc:"The scoring system the number is on"`
	Exploited     bool    `json:"exploited,omitempty"`
	FixState      string  `json:"fix_state,omitempty" enum:"fixed,none,wont-fix,unknown,mixed"`
	FixedIn       string  `json:"fixed_in,omitempty"`
	Description   string  `json:"description,omitempty" doc:"The first four hundred characters of what the report says, as plain text"`
	Owner         string  `json:"owner,omitempty" doc:"The part of the product this belongs to"`
	Parent        string  `json:"parent,omitempty" doc:"The component that directly pulls it in, which is what the decision is about"`
	Places        int     `json:"places" doc:"The number of places the issue sits at in that component in that build"`
	Decided       int     `json:"decided" doc:"The number of those this claim covers"`
}

// PlaceBody names what a decision is about.
//
// Stated by the caller and checked against what is stored, rather than taken
// on trust: it is assembled from a finding, and a caller that could name a
// place freely would be choosing which decisions apply where.
type PlaceBody struct {
	Product       string `json:"product" minLength:"1" doc:"The product, by the name that addresses it"`
	ProductName   string `json:"product_name,omitempty" readOnly:"true" doc:"The product's display name, or its name where it has none"`
	Vulnerability string `json:"vulnerability" minLength:"1" doc:"The issue, by any name it is known under"`
	Place         string `json:"place" minLength:"1" doc:"The place in the build, as the findings list gives it"`
}

// QueueNarrowing is the filters the review queue and its export both take.
type QueueNarrowing struct {
	Reason     QueueReason `query:"reason" default:"approval" doc:"Which list: claims waiting for your approval, deferrals whose date has passed, or promised upgrades and patches whose date has passed with the finding still open"`
	ProposedBy string      `query:"proposed_by" maxLength:"191" doc:"Keep only claims this person made, by sign-in identity. Somebody who made none, or who is not known here, leaves the queue empty"`
	OlderThan  int         `query:"older_than" minimum:"1" doc:"Keep only claims at least this many days old"`
	Severity   Rating      `query:"severity" doc:"Keep only claims covering an issue rated this badly or worse in its product. 'low' excludes nothing"`
	Outcome    []Outcome   `query:"outcome,explode" uniqueItems:"true" doc:"Keep only claims of these outcomes. Any of them, not all"`
	Release    string      `query:"release" maxLength:"191" doc:"Keep only claims that currently cover an open finding in a branch or tag of this name, matched without regard to capitals"`
}

// Filter turns the queue's parameters into the store's narrowing.
//
// Authorized before the proposer's name is resolved, which the caller has
// done by reaching here: a name nobody holds and a name somebody holds both
// narrow the queue, to nothing where they proposed nothing, so the answer
// says nothing about who has an account.
func (n QueueNarrowing) Filter(ctx context.Context, in Deps, subject access.Subject,
	mine bool, product string) (triage.QueueFilter, error) {

	within, err := NarrowedTo(ctx, in, subject, product)
	if err != nil {
		return triage.QueueFilter{}, err
	}
	filter := triage.QueueFilter{
		Reason: triage.QueueReason(n.Reason), Mine: mine, ProductID: within,
		Severities: finding.AtLeast(string(n.Severity)),
		Release:    n.Release,
	}
	for _, each := range n.Outcome {
		filter.Outcomes = append(filter.Outcomes, triage.Outcome(each))
	}
	if n.OlderThan > 0 {
		before := time.Now().UTC().AddDate(0, 0, -n.OlderThan)
		filter.ProposedBefore = &before
	}
	if who := strings.TrimSpace(n.ProposedBy); who != "" {
		filter.ProposedBy = []int64{}
		person, err := access.NewStore(in.DB.DB).ByIdentity(ctx, who)
		switch {
		case err == nil:
			filter.ProposedBy = append(filter.ProposedBy, person.ID)
		case !errors.Is(err, access.ErrNoSuchPerson):
			return filter, WentWrong(in.Logger, "who proposed these could not be read", err)
		}
	}
	return filter, nil
}

// Triaging resolves who is asking and the store they act through.
func Triaging(ctx context.Context, in Deps) (access.Subject, *triage.Store, error) {
	subject, err := Reading(ctx)
	if err != nil {
		return access.Subject{}, nil, err
	}
	if in.DB == nil {
		return access.Subject{}, nil, NoDatabase(in.Logger)
	}
	return subject, triage.NewStore(in.DB.DB), nil
}

// RefusedDecision turns a store's refusal into an answer.
//
// A decision somebody may not reach answers as one that is not there, so that
// guessing identifiers says nothing. Everything a caller could have got right
// is reported, including where in their text to look.
func RefusedDecision(logger *slog.Logger, err error) error {
	switch {
	case errors.Is(err, triage.ErrNotTheirs):
		return noSuchDecision()
	case errors.Is(err, triage.ErrSamePerson):
		return huma.Error409Conflict("the person who proposed a decision may not agree to it")
	}
	// An authorization refusal is not somebody having asked for the
	// impossible. Without this arm it falls through to the default below and
	// answers 422 carrying access.Denied's own sentence — which names the
	// internal product identifier, so a refusal hands the caller a number
	// nothing else publishes.
	if errors.Is(err, access.ErrDenied) {
		return huma.Error403Forbidden("not authorized")
	}
	var faults markdown.Faults
	if errors.As(err, &faults) {
		return RefusedText(faults)
	}
	// A sentence the store wrote for a person to read: a decision already
	// standing here, a claim covering nothing, a threshold crossed. Those are
	// the caller's to fix, and the message is the answer. Anything else is a
	// fault, and its text is withheld.
	if refusal.In(err) && !database.FromEngine(err) {
		return huma.Error422UnprocessableEntity(err.Error())
	}
	return WentWrong(logger, "that could not be recorded", err)
}

// RefusedText answers a refused piece of writing with where to look.
//
// Each fault travels as its own detail, carrying the line and the text that
// caused it. Flattened into one sentence they leave an interface with nothing
// to point at: "remote images are not allowed" against a forty-line
// justification means somebody hunting for it by eye, which is the whole
// reason positions are gathered in the first place.
func RefusedText(faults markdown.Faults) error {
	details := make([]error, 0, len(faults))
	for _, fault := range faults {
		details = append(details, &huma.ErrorDetail{
			Message: fault.Reason,
			// The position in the submitted text, not in the request body. A
			// client is pointing a cursor at a line somebody typed.
			Location: fmt.Sprintf("line %d", fault.Line),
			Value:    fault.Offending,
		})
	}
	return huma.Error422UnprocessableEntity(
		"that text cannot be stored as written", details...)
}

// DecisionBodyOf renders a decision as the API states it.
func DecisionBodyOf(d triage.Decision) DecisionBody {
	// The judgment's words come from the claim: one act is one argument,
	// and this row says where it lands. A decision read without its claim is
	// a programming error rather than a state a caller can reach, so it is
	// left to fail here rather than rendered as an outcome nobody chose.
	// The argument is drawn the one way a claim's argument is drawn, and the
	// row adds what belongs to it.
	body := ClaimArgument(*d.Claim, "")
	body.ID, body.ClaimID, body.State = d.ID, d.ClaimID, ClaimState(d.State)
	if d.SentBackAt != nil {
		body.SentBackAt = d.SentBackAt.UTC().Format(time.RFC3339)
	}
	if d.SelectedBy != nil {
		body.SelectedBy = *d.SelectedBy
	}
	return body
}

// DeferralThreshold is how long a deferral may run before a second person has
// to agree, as this deployment has it set.
//
// A failure to read it is reported rather than answered with the shipped
// default. This decides which deferrals need a second person, so quietly
// substituting a different threshold substitutes a different control — and a
// deployment that had tightened it would find it loosened at exactly the
// moment its database was in trouble, with nothing saying so. A setting nobody
// has changed is a different matter, and answers with the default.
func DeferralThreshold(ctx context.Context, in Deps) (time.Duration, error) {
	if in.DB == nil {
		return triage.DefaultDeferralThreshold, nil
	}
	// The same shipped span the store falls back to. Written out here as well,
	// the two disagree about what a deployment that has said nothing is
	// doing.
	return setting.NewStore(in.DB.DB).Duration(ctx, setting.DeferralThreshold,
		triage.DefaultDeferralThreshold)
}

// DecisionDetail is a decision with everything needed to understand it without
// asking again: where it applies, what it says, and how far it has got.
type DecisionDetail struct {
	Decision DecisionBody `json:"decision"`
	Place    PlaceBody    `json:"place"`
	// Finding is the decision's subject, where an open finding still sits at
	// its place. Absent where none does.
	Finding        *FindingRefBody `json:"finding,omitempty" doc:"The decision's subject — build, issue, component, where it sits — read from the open finding at its place. Absent where none is open there"`
	Reasoning      string          `json:"reasoning" doc:"The justification as it currently stands, in markdown"`
	ProposedBy     string          `json:"proposed_by" doc:"The person who made the claim, by sign-in identity"`
	ProposedByName string          `json:"proposed_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ProposedAt     string          `json:"proposed_at" doc:"The moment the claim was made"`
	AgeDays        int             `json:"age_days" doc:"The age of the claim. An old judgment should look like one"`
}

// ClaimArgument renders what a claim says, with the reasoning it currently
// rests on.
//
// The argument fields of a decision and none of the row ones. A decision's
// identifier and its state belong to the row, and a claim page that carried
// either would be offering an act at the wrong grain.
func ClaimArgument(c triage.Claim, reasoning string) DecisionBody {
	body := DecisionBody{ClaimID: c.ID, Outcome: Outcome(c.Outcome), Reasoning: reasoning}
	if c.Justification != nil {
		body.Justification = Justification(*c.Justification)
	}
	if c.Mitigation != nil {
		body.Mitigation = *c.Mitigation
	}
	if c.FixedVersion != nil {
		body.FixedVersion = *c.FixedVersion
	}
	if c.DeferredUntil != nil {
		body.DeferredUntil = c.DeferredUntil.Format(time.DateOnly)
	}
	if c.CommittedTo != nil {
		body.CommittedTo = c.CommittedTo.Format(time.DateOnly)
	}
	if c.UpgradeTo != nil {
		body.UpgradeTo = *c.UpgradeTo
	}
	return body
}

// DescribeDecisions fills in the names a decision refers to by identifier.
//
// A row saying product 4, issue 91 is a row somebody has to make two more
// requests to understand, and the lists this feeds are exactly where that
// happens fifty times.
func DescribeDecisions(ctx context.Context, in Deps, store *triage.Store,
	decisions []triage.Decision, reasoning map[int64]string) ([]DecisionDetail, error) {

	people := make([]int64, 0, len(decisions))
	products := make([]int64, 0, len(decisions))
	issues := make([]int64, 0, len(decisions))
	for _, decision := range decisions {
		people = append(people, decision.ProposedBy)
		products = append(products, decision.ProductID)
		issues = append(issues, decision.VulnerabilityID)
	}

	who, err := WhoSigned(ctx, in.DB.DB, people)
	if err != nil {
		return nil, err
	}
	productNames, err := catalog.NewStore(in.DB.DB).ProductsCalled(ctx, products)
	if err != nil {
		return nil, err
	}
	productLabels, err := catalog.NewStore(in.DB.DB).ProductNames(ctx, products)
	if err != nil {
		return nil, err
	}
	issueNames, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
	if err != nil {
		return nil, err
	}
	subject, err := Reading(ctx)
	if err != nil {
		return nil, err
	}
	described, err := store.Describe(ctx, subject, decisions)
	if err != nil {
		return nil, err
	}

	details := make([]DecisionDetail, 0, len(decisions))
	for _, decision := range decisions {
		details = append(details, DecisionDetail{
			Finding:  findingRef(described, decision.ID),
			Decision: DecisionBodyOf(decision),
			Place: PlaceBody{
				Product:       productNames[decision.ProductID],
				ProductName:   productLabels[decision.ProductID],
				Vulnerability: issueNames[decision.VulnerabilityID],
				Place:         decision.PlaceIdentity,
			},
			Reasoning:      reasoning[decision.ID],
			ProposedBy:     who.Identity(decision.ProposedBy),
			ProposedByName: who.Label(decision.ProposedBy),
			ProposedAt:     decision.ProposedAt.UTC().Format(time.RFC3339),
			AgeDays:        int(store.Age(&decision).Hours() / 24),
		})
	}
	return details, nil
}

// findingRef renders a decision's subject, where an open finding sits at its
// place.
func findingRef(described map[int64]triage.Described, decisionID int64) *FindingRefBody {
	d, ok := described[decisionID]
	if !ok {
		return nil
	}
	body := &FindingRefBody{
		Product: d.Product, ProductName: d.ProductName,
		Stream: d.Stream, Variant: d.Variant,
		StreamName:    d.StreamName,
		VariantName:   d.VariantName,
		Vulnerability: d.Issue.Identifier, Component: d.Component, Version: d.Version,
		Ecosystem: graph.EcosystemOf(d.Purl), Namespace: graph.NamespaceOf(d.Purl),
		Severity: d.Issue.InForce(), Exploited: d.Issue.Exploited,
		FixState: d.FixState, FixedIn: d.FixedIn,
		Description: excerpt(d.Issue.Description, 400),
		Owner:       d.Owner, Parent: d.Parent,
		Places: d.Places, Decided: d.Decided,
	}
	if d.Issue.ScoreCenti != nil {
		// The scheme with the number. Two are scorable and their numbers are
		// not comparable, so a card carrying one without the other invites
		// somebody approving a claim to weigh it against the last one.
		body.Score = float64(*d.Issue.ScoreCenti) / 100
		body.ScoreVersion = d.Issue.ScoreVersion
	}
	return body
}

// excerpt shortens text to n characters on a rune boundary.
func excerpt(text string, n int) string {
	runes := []rune(text)
	if len(runes) <= n {
		return text
	}
	return string(runes[:n]) + "\u2026"
}

// WasSaidBody is one version of a comment that has been replaced.
type WasSaidBody struct {
	Version    int    `json:"version" doc:"The version number, counting from one"`
	Body       string `json:"body" doc:"Its text, in markdown"`
	ReplacedAt string `json:"replaced_at" doc:"The moment it stopped saying that"`
}
