// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// AgreedBody is one person agreeing to one decision, and when.
type AgreedBody struct {
	By string `json:"by" doc:"Their sign-in identity"`
	At string `json:"at" doc:"The moment they agreed"`
	// WithdrawnAt is part of the record rather than a reason to leave the
	// agreement out: an agreement somebody made and then took back is what an
	// audit is looking for.
	WithdrawnAt string `json:"withdrawn_at,omitempty" doc:"The moment the agreement was taken back, by the approver or by somebody editing the words it was given for"`
	// Carried says this agreement was given for an earlier decision and carried
	// onto this one, which is what a re-affirmation stands on. The person
	// named read those words rather than these.
	Carried bool `json:"carried,omitempty" doc:"Whether this agreement was carried forward from an earlier decision rather than given for this one"`
}

// AuditedBody is one decision at one occurrence, as an auditor reads it.
type AuditedBody struct {
	ID         int64  `json:"id"`
	DecisionID int64  `json:"decision_id" doc:"The decision this occurrence belongs to. Every occurrence one act covered shares it"`
	Issue      string `json:"issue" doc:"The vulnerability, under the name it is filed here"`
	Product    string `json:"product" doc:"The product, by the name that addresses it"`

	ProductName string `json:"product_name,omitempty" doc:"The product's display name, or its name where it has none"`
	// Component is the decision's subject. Named from a finding at the
	// occurrence, in any state — a decision about something since fixed or removed is
	// exactly what an audit asks for, so it is named rather than left
	// blank.
	Component string `json:"component"`
	Version   string `json:"version,omitempty"`
	Consumer  string `json:"consumer,omitempty" doc:"The consumer that pulls the component in. Absent where the build holds it directly"`

	Outcome       core.Outcome        `json:"outcome"`
	Justification core.Justification  `json:"justification,omitempty" doc:"The recognized reason it does not apply"`
	Reason        core.LeadReason     `json:"reason,omitempty" doc:"Why a lead was dismissed, on a decision about a lead, which states no justification"`
	Mitigation    string              `json:"mitigation,omitempty" doc:"The mitigation a holder can apply. Recorded where the reason is that mitigations already exist, or the outcome is that this will not be fixed, and refused otherwise. Nothing here notices a control being removed, so this is the record somebody checks"`
	Scope         core.StatementScope `json:"scope,omitempty" doc:"Whom a published statement made from the decision holds for, where the decision stated it: portable for anybody shipping the component at that version, build for this product's own build. Absent where the reason decides"`
	DeferredUntil string              `json:"deferred_until,omitempty"`
	FixedVersion  string              `json:"fixed_version,omitempty" doc:"The package version the decision says the fix arrived in, where it says one has. What somebody auditing an already-fixed decision checks against the packager's own record"`
	Reasoning     string              `json:"reasoning" doc:"The words the standing agreement was given for. Editing them withdraws the agreement, so this and what was agreed to cannot drift apart. Empty where you may read only some of the occurrences the decision covers"`

	State    core.DecisionState `json:"state"`
	Standing bool               `json:"standing" doc:"Whether it applies now. A decision can be approved and no longer standing — the code moved out from under it"`

	ProposedBy string       `json:"proposed_by"`
	ProposedAt string       `json:"proposed_at"`
	EndedAt    string       `json:"ended_at,omitempty" doc:"The moment it stopped applying — withdrawn, or lapsed because the code moved"`
	Approvals  []AgreedBody `json:"approvals"`
	// TwoPeople is the separation-of-duties control stated as a fact about
	// this record rather than as a rule that exists. Read from the names: a
	// report that said the rule was satisfied because the rule exists would be
	// reporting on itself.
	TwoPeople bool `json:"two_people" doc:"Whether somebody other than the proposer has a standing agreement on it"`
}

// StatesBody is how many occurrences are in each state.
type StatesBody struct {
	Proposed  int `json:"proposed"`
	Approved  int `json:"approved"`
	Withdrawn int `json:"withdrawn"`
	Lapsed    int `json:"lapsed"`
}

// AuditedDecisionBody is one decision as the audit log lists it. Every count is
// of the occurrences the filters matched and the caller may read.
type AuditedDecisionBody struct {
	Decision int64 `json:"decision" doc:"The decision's identifier"`

	Issue       string `json:"issue" doc:"The vulnerability the earliest matching occurrence is about, under the name it is filed here"`
	Issues      int    `json:"issues" doc:"How many vulnerabilities the matching occurrences are about"`
	Product     string `json:"product" doc:"The product of the earliest matching occurrence, by the name that addresses it"`
	ProductName string `json:"product_name,omitempty" doc:"That product's display name, or its name where it has none"`
	Products    int    `json:"products" doc:"How many products the matching occurrences are in"`
	Component   string `json:"component" doc:"The component the earliest matching occurrence is about"`
	Version     string `json:"version,omitempty"`
	Consumer    string `json:"consumer,omitempty" doc:"The consumer that pulls the component in. Absent where the build holds it directly"`
	Components  int    `json:"components" doc:"How many component names sit at the matching occurrences, counted through the findings you may read"`
	Rows        int    `json:"rows" doc:"How many of its occurrences match, counted once for each issue"`
	Occurrences int    `json:"occurrences" doc:"How many distinct occurrences match"`

	Outcome       core.Outcome        `json:"outcome"`
	Justification core.Justification  `json:"justification,omitempty" doc:"The recognized reason it does not apply"`
	Reason        core.LeadReason     `json:"reason,omitempty" doc:"Why a lead was dismissed, on a decision about a lead, which states no justification"`
	Mitigation    string              `json:"mitigation,omitempty" doc:"The mitigation a holder can apply"`
	Scope         core.StatementScope `json:"scope,omitempty" doc:"Whom a published statement made from the decision holds for, where the decision stated it. Absent where the reason decides"`
	DeferredUntil string              `json:"deferred_until,omitempty"`
	FixedVersion  string              `json:"fixed_version,omitempty" doc:"The package version the decision says the fix arrived in"`
	Reasoning     string              `json:"reasoning" doc:"The words the decision currently rests on. Editing them withdraws every agreement"`

	State    core.DecisionStates `json:"state" doc:"The state the matching occurrences share, or mixed where they differ"`
	States   StatesBody          `json:"states" doc:"How many matching occurrences are in each state"`
	Standing int                 `json:"standing" doc:"How many matching occurrences the decision applies at now"`

	ProposedBy string       `json:"proposed_by"`
	ProposedAt string       `json:"proposed_at"`
	Approvals  []AgreedBody `json:"approvals"`
	TwoPeople  bool         `json:"two_people" doc:"Whether somebody other than the proposer has a standing agreement on it"`
}

// Auditing is the narrowing the audit log takes, for the screen and for the
// file.
//
// One struct because they are one question. An export that took a smaller set
// of filters than the screen would be a file that quietly answers something
// else, which is the failure an export is easiest to make.
type Auditing struct {
	// Repeatable, because "dismissed or deferred" and "waiting or sent back"
	// are the questions somebody reading the audit log has, and one value cannot
	// ask either. Repeat the parameter; any of what is named matches.
	Product   []string             `query:"product,explode" maxItems:"200" maxLength:"191" doc:"Limit to these products, by name. Repeatable; any of them matches"`
	Outcome   []core.Outcome       `query:"outcome,explode" uniqueItems:"true" doc:"Limit to these kinds of decision. Repeatable; any of them matches"`
	State     []core.DecisionState `query:"state,explode" uniqueItems:"true" doc:"Limit to these states. Repeatable; any of them matches"`
	From      string               `query:"from" doc:"Only decisions proposed on or after this date, as YYYY-MM-DD"`
	To        string               `query:"to" doc:"Only decisions proposed before this date, as YYYY-MM-DD"`
	Alone     bool                 `query:"alone" doc:"Only decisions no second person has a standing agreement on. Asked of a dismissal this should answer nothing"`
	InForce   bool                 `query:"in_force" doc:"Only decisions that apply now: agreed to, or standing without needing agreement, and still holding the occurrence they were made about. A decision can be approved and have lapsed since, which is why this is not the same as asking for the approved state. Every outcome that dismisses needs agreement, so asked of one of those this is what has been agreed to"`
	Proposer  string               `query:"proposed_by" doc:"Only decisions this person proposed, by sign-in identity"`
	Approver  string               `query:"approved_by" doc:"Only decisions this person has a standing agreement on, by sign-in identity. An agreement later taken back does not match"`
	Issue     string               `query:"issue" doc:"Only decisions about this vulnerability, under the name it is filed here"`
	Component string               `query:"component" doc:"Only decisions about this component, by name"`
	// A build, for the question a release sign-off asks. A decision names no
	// build — it is keyed on the product, the issue and the occurrence, so
	// that it carries across releases sharing the code — so this asks which
	// decisions are about something one build actually ships.
	Stream  string `query:"stream" doc:"Only decisions about occurrences this branch or tag holds. Needs exactly one product and a variant"`
	Variant string `query:"variant" doc:"The build of that stream. Needs exactly one product and a stream"`
}

// narrow turns the request's parameters into the store's filter, resolving the
// product against what the caller may see.
func (a Auditing) narrow(ctx context.Context, in core.Deps,
	subject access.Subject) (triage.Filter, time.Time, time.Time, error) {

	filter := triage.Filter{
		Alone:     a.Alone,
		InForce:   a.InForce,
		Proposer:  a.Proposer,
		Approver:  a.Approver,
		Issue:     a.Issue,
		Component: a.Component,
	}
	for _, outcome := range a.Outcome {
		if outcome != "" {
			filter.Outcomes = append(filter.Outcomes, triage.Outcome(outcome))
		}
	}
	for _, state := range a.State {
		if state != "" {
			filter.States = append(filter.States, triage.State(state))
		}
	}
	var since, until time.Time
	// Each name resolved against what the caller may see, and one they may
	// not is the whole request refused rather than quietly dropped: a report
	// that answered about two products when three were asked for is a report
	// somebody reads as covering three.
	for _, name := range a.Product {
		if name == "" {
			continue
		}
		named, err := core.ProductNamedVisibly(ctx, in, subject, name)
		if err != nil {
			return filter, since, until, err
		}
		filter.ProductIDs = append(filter.ProductIDs, named.ID)
	}
	// A build is a product, a stream and a variant together. Named without
	// the other two it would narrow to a stream of some other product that
	// happens to share the name, which is a report about somebody else's
	// releases under this one's heading.
	if (a.Stream != "") != (a.Variant != "") {
		return filter, since, until, huma.Error422UnprocessableEntity(
			"a build is a stream and a variant together: name both, or neither")
	}
	if a.Stream != "" {
		if len(filter.ProductIDs) != 1 {
			return filter, since, until, huma.Error422UnprocessableEntity(
				"name exactly one product with a build: a stream belongs to one")
		}
		located, err := core.LocatedVisibly(ctx, in, subject, a.Product[0], a.Stream, a.Variant)
		if err != nil {
			return filter, since, until, err
		}
		target, err := core.TargetRow(ctx, in, located.StreamID, located.VariantID)
		if err != nil {
			return filter, since, until, err
		}
		filter.TargetID = target.ID
	}
	from, err := core.CalendarDate(a.From)
	if err != nil {
		return filter, since, until, err
	}
	to, err := core.CalendarDate(a.To)
	if err != nil {
		return filter, since, until, err
	}
	if from != nil {
		since = *from
	}
	if to != nil {
		until = *to
	}
	return filter, since, until, nil
}

func registerAudit(api huma.API, in core.Deps) {
	registerAuditDecisions(api, in)
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-audit", Method: http.MethodGet, Path: "/v1/audit",
		Summary: "List decisions with who made them and who agreed",
		Description: "Every decision recorded in a period, once for each occurrence it covers, newest first, with what it was " +
			"about, the reasoning it rests on, who proposed it and when, and who agreed and " +
			"when — including agreements later taken back.\n\n" +
			"The period is the date a decision was proposed, not approved: a decision " +
			"belongs to when it was argued, and dating it by its agreement would move it out " +
			"of that period whenever an approval came late, which is the ordinary case.\n\n" +
			"Narrowed by what you may see, like every other list here. Nothing about this view " +
			"is exempt from the visibility rules — a report showing more than the screens it " +
			"summarizes would be a way around them.\n\n" +
			"`alone=true` returns decisions no second person has a standing agreement on. " +
			"That population is large and legitimate on its own — an outcome that hides " +
			"nothing needs no second person, and a short deferral stands alone — so ask it " +
			"with an outcome. Asked of a dismissal it should return nothing: `not-applicable`, " +
			"`mismatched`, `wont-fix` and `already-fixed` all require approval, so a row in " +
			"that answer is a control that failed.\n\n" +
			"`in_force=true` returns what applies now rather than what was once agreed to. " +
			"With `outcome=mismatched` that is the set of standing corrections: the matches " +
			"this deployment has recorded as wrong, which no version bump expires.",
		Tags: []string{"Reports"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Auditing
		Limit  int `query:"limit" default:"100" minimum:"1" maximum:"500"`
		Offset int `query:"offset" minimum:"0"`
	}) (*core.CountedListOutput[AuditedBody], error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		filter, since, until, err := input.narrow(ctx, in, subject)
		if err != nil {
			return nil, err
		}

		rows, total, err := store.Audit(ctx, subject, filter, since, until, input.Limit, input.Offset)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the audit log could not be read", err)
		}
		out := &core.CountedListOutput[AuditedBody]{}
		out.Body.Items = make([]AuditedBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, auditedBody(row))
		}
		out.Body.Total = total
		return out, nil
	})
}

// auditedBody is one decision at one occurrence, as an auditor reads it.
func auditedBody(row triage.AuditedOccurrence) AuditedBody {
	body := AuditedBody{
		ID: row.ID, DecisionID: row.DecisionID, Issue: row.Issue, Product: row.Product,
		ProductName: row.ProductName,
		Component:   row.Component, Version: row.Version, Consumer: row.Consumer,
		Outcome: core.Outcome(row.Decision.Outcome), Reasoning: row.Reasoning,
		State: core.DecisionState(row.State), Standing: row.Standing(),
		ProposedBy: row.ProposedByName, ProposedAt: core.Stamp(row.ProposedAt),
		TwoPeople: row.BySomebodyElse(),
		Approvals: agreedBodies(row.Approvals),
	}
	body.Justification, body.Reason, body.Mitigation, body.DeferredUntil, body.FixedVersion = argued(row.Decision)
	body.Scope = statedScope(row.Decision)
	if row.EndedAt != nil {
		body.EndedAt = core.Stamp(*row.EndedAt)
	}
	return body
}

// argued is what a decision says beyond its outcome, as the audit log writes it.
// A decision about a lead holds its reason where a vulnerability's decision
// holds its justification, and the two are drawn from different vocabularies.
func argued(decision *triage.Decision) (justification core.Justification, reason core.LeadReason,
	mitigation, deferred, fixed string) {
	if decision == nil {
		return "", "", "", "", ""
	}
	if decision.Justification != nil {
		if decision.Outcome.AboutALead() {
			reason = core.LeadReason(*decision.Justification)
		} else {
			justification = core.Justification(*decision.Justification)
		}
	}
	if decision.Mitigation != nil {
		mitigation = *decision.Mitigation
	}
	if decision.DeferredUntil != nil {
		deferred = decision.DeferredUntil.UTC().Format(time.DateOnly)
	}
	if decision.FixedVersion != nil {
		fixed = *decision.FixedVersion
	}
	return justification, reason, mitigation, deferred, fixed
}

// statedScope is whom a decision says its published statement holds for,
// where it says. A decision that widened a public statement is one an auditor
// looks for.
func statedScope(decision *triage.Decision) core.StatementScope {
	if decision == nil || decision.Scope == nil {
		return ""
	}
	return core.StatementScope(*decision.Scope)
}

func registerAuditDecisions(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-audit-decisions", Method: http.MethodGet, Path: "/v1/audit/decisions",
		Summary: "List the audit log by decision",
		Description: "The audit log one decision at a time, newest first: every decision with an " +
			"occurrence the filters match, once, however many occurrences it covers.\n\n" +
			"Takes every filter the per-occurrence list takes, with the same meaning. A decision is " +
			"listed where any of its occurrences match, and every count on it is of the occurrences " +
			"that match and that you may read. Asked for `state=lapsed`, a decision that lapsed " +
			"at one occurrence of forty reads as one occurrence, lapsed. `total` counts decisions.\n\n" +
			"What the decision is about is named from its earliest matching occurrence, beside how " +
			"many issues, products, components and occurrences the matches reach.\n\n" +
			"Each occurrence on its own is `GET /v1/audit`, and the file is one row per occurrence " +
			"with the decision it belongs to.",
		Tags: []string{"Reports"},
	}, core.AnyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Auditing
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0"`
	}) (*core.CountedListOutput[AuditedDecisionBody], error) {
		subject, store, err := core.Triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		filter, since, until, err := input.narrow(ctx, in, subject)
		if err != nil {
			return nil, err
		}
		rows, total, err := store.AuditDecisions(ctx, subject, filter, since, until, input.Limit, input.Offset)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the audit log could not be read", err)
		}
		out := &core.CountedListOutput[AuditedDecisionBody]{}
		out.Body.Items = make([]AuditedDecisionBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, auditedDecisionBody(row))
		}
		out.Body.Total = total
		return out, nil
	})
}

// auditedDecisionBody is one decision as the audit log lists it.
func auditedDecisionBody(row triage.AuditedDecision) AuditedDecisionBody {
	body := AuditedDecisionBody{
		Decision: row.Decision.ID, Issue: row.Issue, Issues: row.Issues,
		Product: row.Product, ProductName: row.ProductName, Products: row.Products,
		Component: row.Component, Version: row.Version, Consumer: row.Consumer,
		Components: row.Components, Rows: row.Rows, Occurrences: row.Occurrences,
		Outcome: core.Outcome(row.Decision.Outcome), Reasoning: row.Reasoning,
		State: core.DecisionStates(row.State()),
		States: StatesBody{
			Proposed: row.States[triage.Proposed], Approved: row.States[triage.Approved],
			Withdrawn: row.States[triage.Withdrawn], Lapsed: row.States[triage.LapsedState],
		},
		Standing:   row.Standing,
		ProposedBy: row.ProposedByName, ProposedAt: core.Stamp(row.ProposedAt),
		TwoPeople: row.BySomebodyElse(),
		Approvals: agreedBodies(row.Approvals),
	}
	body.Justification, body.Reason, body.Mitigation, body.DeferredUntil, body.FixedVersion = argued(&row.Decision)
	body.Scope = statedScope(&row.Decision)
	return body
}

// agreedBodies is every agreement on a decision, taken back or not.
func agreedBodies(approvals []triage.Agreed) []AgreedBody {
	out := make([]AgreedBody, 0, len(approvals))
	for _, agreed := range approvals {
		one := AgreedBody{By: agreed.By, At: core.Stamp(agreed.At), Carried: agreed.Carried}
		if agreed.WithdrawnAt != nil {
			one.WithdrawnAt = core.Stamp(*agreed.WithdrawnAt)
		}
		out = append(out, one)
	}
	return out
}
