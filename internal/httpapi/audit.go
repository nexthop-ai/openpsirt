// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// AgreedBody is one person agreeing to one judgment, and when.
type AgreedBody struct {
	By string `json:"by" doc:"Their sign-in identity"`
	At string `json:"at" doc:"The moment they agreed"`
	// WithdrawnAt is part of the record rather than a reason to leave the
	// agreement out: an agreement somebody made and then took back is what an
	// audit is looking for.
	WithdrawnAt string `json:"withdrawn_at,omitempty" doc:"The moment the agreement was taken back, by the approver or by somebody editing the words it was given for"`
	// Carried says this agreement was given for an earlier claim and carried
	// onto this one, which is what a re-affirmation stands on. The person
	// named read those words rather than these.
	Carried bool `json:"carried,omitempty" doc:"Whether this agreement was carried forward from an earlier claim rather than given for this one"`
}

// JudgedBody is one judgment as an auditor reads it.
type JudgedBody struct {
	ID      int64  `json:"id"`
	Issue   string `json:"issue" doc:"The vulnerability, under the name it is filed here"`
	Product string `json:"product" doc:"The product, by the name that addresses it"`

	ProductName string `json:"product_name,omitempty" doc:"The product's display name, where it has one"`
	// Component is the judgment's subject. Named from a finding at the place,
	// in any state — a judgment about something since fixed or removed is
	// exactly what an audit asks for, so it is named rather than left
	// blank.
	Component string `json:"component"`
	Version   string `json:"version,omitempty"`
	Consumer  string `json:"consumer,omitempty" doc:"The consumer that pulls the component in. Absent where the build holds it directly"`

	Outcome       outcome       `json:"outcome"`
	Justification justification `json:"justification,omitempty" doc:"The recognized reason it does not apply"`
	Mitigation    string        `json:"mitigation,omitempty" doc:"The mitigation a holder can apply. Recorded where the reason is that mitigations already exist, or the outcome is that this will not be fixed, and refused otherwise. Nothing here notices a control being removed, so this is the record somebody checks"`
	DeferredUntil string        `json:"deferred_until,omitempty"`
	FixedVersion  string        `json:"fixed_version,omitempty" doc:"The package version the claim says the fix arrived in, where it claims one has. What somebody auditing an already-fixed claim checks against the packager's own record"`
	Reasoning     string        `json:"reasoning" doc:"The words the standing agreement was given for. Editing them withdraws the agreement, so this and what was agreed to cannot drift apart"`

	State    string `json:"state" enum:"proposed,approved,withdrawn,lapsed"`
	Standing bool   `json:"standing" doc:"Whether it applies now. A judgment can be approved and no longer standing — the code moved out from under it"`

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

// Auditing is the narrowing the record takes, for the screen and for the
// file.
//
// One struct because they are one question. An export that took a smaller set
// of filters than the screen would be a file that quietly answers something
// else, which is the failure an export is easiest to make.
type Auditing struct {
	// Repeatable, because "dismissed or deferred" and "waiting or sent back"
	// are the questions somebody reading the record has, and one value cannot
	// ask either. Repeat the parameter; any of what is named matches.
	Product   []string  `query:"product,explode" doc:"Limit to these products, by name. Repeatable; any of them matches"`
	Outcome   []outcome `query:"outcome,explode" doc:"Limit to these kinds of judgment. Repeatable; any of them matches"`
	State     []string  `query:"state,explode" enum:"proposed,approved,withdrawn,lapsed" doc:"Limit to these states. Repeatable; any of them matches"`
	From      string    `query:"from" doc:"Only judgments proposed on or after this date, as YYYY-MM-DD"`
	To        string    `query:"to" doc:"Only judgments proposed before this date, as YYYY-MM-DD"`
	Alone     bool      `query:"alone" doc:"Only judgments no second person has a standing agreement on. Asked of a dismissal this should answer nothing"`
	InForce   bool      `query:"in_force" doc:"Only judgments that apply now: agreed to, or standing without needing agreement, and still holding the place they were made about. A judgment can be approved and have lapsed since, which is why this is not the same as asking for the approved state. Every outcome that dismisses needs agreement, so asked of one of those this is what has been agreed to"`
	Proposer  string    `query:"proposed_by" doc:"Only judgments this person proposed, by sign-in identity"`
	Approver  string    `query:"approved_by" doc:"Only judgments this person has a standing agreement on, by sign-in identity. An agreement later taken back does not match"`
	Issue     string    `query:"issue" doc:"Only judgments about this vulnerability, under the name it is filed here"`
	Component string    `query:"component" doc:"Only judgments about this component, by name"`
	// A build, for the question a release sign-off asks. A decision names no
	// build — it is keyed on the product, the issue and the place, so that it
	// carries across releases sharing the code — so this asks which judgments
	// are about something one build actually ships.
	Stream  string `query:"stream" doc:"Only judgments about places this branch or tag holds. Needs exactly one product and a variant"`
	Variant string `query:"variant" doc:"The build of that stream. Needs exactly one product and a stream"`
}

// narrow turns the request's parameters into the store's filter, resolving the
// product against what the caller may see.
func (a Auditing) narrow(ctx context.Context, in Ingest,
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
		named, err := productNamedVisibly(ctx, in, subject, name)
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
		located, err := locatedVisibly(ctx, in, subject, a.Product[0], a.Stream, a.Variant)
		if err != nil {
			return filter, since, until, err
		}
		target, err := targetRow(ctx, in, located.StreamID, located.VariantID)
		if err != nil {
			return filter, since, until, err
		}
		filter.TargetID = target.ID
	}
	from, err := aDate(a.From)
	if err != nil {
		return filter, since, until, err
	}
	to, err := aDate(a.To)
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

func registerAudit(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-audit", Method: http.MethodGet, Path: "/v1/audit",
		Summary: "List judgments with who made them and who agreed",
		Description: "Every judgment recorded in a period, newest first, with what it was " +
			"about, the reasoning it rests on, who proposed it and when, and who agreed and " +
			"when — including agreements later taken back.\n\n" +
			"The period is the date a judgment was proposed, not approved: a judgment " +
			"belongs to when it was argued, and dating it by its agreement would move it out " +
			"of that period whenever an approval came late, which is the ordinary case.\n\n" +
			"Narrowed by what you may see, like every other list here. Nothing about this view " +
			"is exempt from the visibility rules — a report showing more than the screens it " +
			"summarizes would be a way around them.\n\n" +
			"`alone=true` returns judgments no second person has a standing agreement on. " +
			"That population is large and legitimate on its own — an outcome that hides " +
			"nothing needs no second person, and a short deferral stands alone — so ask it " +
			"with an outcome. Asked of a dismissal it should return nothing: `not-applicable`, " +
			"`mismatched`, `wont-fix` and `already-fixed` all require approval, so a row in " +
			"that answer is a control that failed.\n\n" +
			"`in_force=true` returns what applies now rather than what was once agreed to. " +
			"With `outcome=mismatched` that is the set of standing corrections: the matches " +
			"this deployment has recorded as wrong, which no version bump expires.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Auditing
		Limit  int `query:"limit" default:"100" minimum:"1" maximum:"500"`
		Offset int `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []JudgedBody `json:"items"`
			Total int          `json:"total"`
		}
	}, error) {
		subject, store, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		filter, since, until, err := input.narrow(ctx, in, subject)
		if err != nil {
			return nil, err
		}

		rows, total, err := store.Audit(ctx, subject, filter, since, until, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "the record could not be read", err)
		}
		out := &struct {
			Body struct {
				Items []JudgedBody `json:"items"`
				Total int          `json:"total"`
			}
		}{}
		out.Body.Items = make([]JudgedBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, judgedBody(row))
		}
		out.Body.Total = total
		return out, nil
	})
}

// judgedBody is one judgment as an auditor reads it.
func judgedBody(row triage.Judged) JudgedBody {
	{
		{
			body := JudgedBody{
				ID: row.ID, Issue: row.Issue, Product: row.Product,
				ProductName: labelBeside(row.ProductName, row.Product),
				Component:   row.Component, Version: row.Version, Consumer: row.Consumer,
				Outcome: outcome(row.Claim.Outcome), Reasoning: row.Reasoning,
				State: string(row.State), Standing: row.Standing(),
				ProposedBy: row.ProposedByName, ProposedAt: stamp(row.ProposedAt),
				TwoPeople: row.BySomebodyElse(),
				Approvals: make([]AgreedBody, 0, len(row.Approvals)),
			}
			if row.Claim.Justification != nil {
				body.Justification = justification(*row.Claim.Justification)
			}
			if row.Claim.Mitigation != nil {
				body.Mitigation = *row.Claim.Mitigation
			}
			if row.Claim.DeferredUntil != nil {
				body.DeferredUntil = row.Claim.DeferredUntil.UTC().Format(time.DateOnly)
			}
			if row.Claim.FixedVersion != nil {
				body.FixedVersion = *row.Claim.FixedVersion
			}
			if row.EndedAt != nil {
				body.EndedAt = stamp(*row.EndedAt)
			}
			for _, agreed := range row.Approvals {
				one := AgreedBody{By: agreed.By, At: stamp(agreed.At), Carried: agreed.Carried}
				if agreed.WithdrawnAt != nil {
					one.WithdrawnAt = stamp(*agreed.WithdrawnAt)
				}
				body.Approvals = append(body.Approvals, one)
			}
			return body
		}
	}
}
