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
	At string `json:"at" doc:"When they agreed"`
	// WithdrawnAt is part of the record rather than a reason to leave the
	// agreement out: what somebody agreed to and then stopped agreeing to is
	// what an audit is looking for.
	WithdrawnAt string `json:"withdrawn_at,omitempty" doc:"When the agreement was taken back, by the approver or by somebody editing the words it was given for"`
	// Carried says this agreement was given for an earlier claim and carried
	// onto this one, which is what a re-affirmation stands on. The person
	// named read those words rather than these.
	Carried bool `json:"carried,omitempty" doc:"Whether this agreement was carried forward from an earlier claim rather than given for this one"`
}

// JudgedBody is one judgment as an auditor reads it.
type JudgedBody struct {
	ID      int64  `json:"id"`
	Issue   string `json:"issue" doc:"The vulnerability, under the name it is filed here"`
	Product string `json:"product"`
	// What it was about. Named from a finding at the place, in any state — a
	// judgment about something since fixed or removed is exactly what an audit
	// asks for, so it is named rather than left blank.
	Component string `json:"component"`
	Version   string `json:"version,omitempty"`
	Consumer  string `json:"consumer,omitempty" doc:"What pulls the component in. Absent where the build holds it directly"`

	Outcome       string `json:"outcome" enum:"affected,not-applicable,deferred,wont-fix,already-fixed,upgrade-needed,patch-needed"`
	Justification string `json:"justification,omitempty" doc:"The recognized reason it does not apply"`
	Mitigation    string `json:"mitigation,omitempty" doc:"What stops it, where the reason is that a control already does. Nothing here notices that control being removed, so this is the record somebody checks"`
	DeferredUntil string `json:"deferred_until,omitempty"`
	FixedVersion  string `json:"fixed_version,omitempty" doc:"The package version the claim says the fix arrived in, where it claims one has. What somebody auditing an already-fixed claim checks against the packager's own record"`
	Reasoning     string `json:"reasoning" doc:"The words the standing agreement was given for. Editing them withdraws the agreement, so this and what was agreed to cannot drift apart"`

	State    string `json:"state" enum:"proposed,approved,withdrawn,lapsed"`
	Standing bool   `json:"standing" doc:"Whether it applies now. A judgment can be approved and no longer standing — the code moved out from under it"`

	ProposedBy string       `json:"proposed_by"`
	ProposedAt string       `json:"proposed_at"`
	EndedAt    string       `json:"ended_at,omitempty" doc:"When it stopped applying — withdrawn, or lapsed because the code moved"`
	Approvals  []AgreedBody `json:"approvals"`
	// TwoPeople is the separation-of-duties control stated as a fact about
	// this record rather than as a rule that exists. Read from the names: a
	// report that said the rule was satisfied because the rule exists would be
	// reporting on itself.
	TwoPeople bool `json:"two_people" doc:"Whether somebody other than the proposer has a standing agreement on it"`
}

// Auditing is what narrows the record, for the screen and for the file.
//
// One struct because they are one question. An export that took a smaller set
// of filters than the screen would be a file that quietly answers something
// else, which is the failure an export is easiest to make.
type Auditing struct {
	// Repeatable, because "dismissed or deferred" and "waiting or sent back"
	// are the questions somebody reading the record has, and one value cannot
	// ask either. Repeat the parameter; any of what is named matches.
	Product   []string `query:"product,explode" doc:"Limit to these products, by name. Repeatable; any of them matches"`
	Outcome   []string `query:"outcome,explode" enum:"affected,not-applicable,deferred,wont-fix,already-fixed,upgrade-needed,patch-needed" doc:"Limit to these kinds of judgment. Repeatable; any of them matches"`
	State     []string `query:"state,explode" enum:"proposed,approved,withdrawn,lapsed" doc:"Limit to these states. Repeatable; any of them matches"`
	From      string   `query:"from" doc:"Only judgments proposed on or after this date, as YYYY-MM-DD"`
	To        string   `query:"to" doc:"Only judgments proposed before this date, as YYYY-MM-DD"`
	Alone     bool     `query:"alone" doc:"Only judgments no second person has a standing agreement on. Asked of a dismissal this should answer nothing"`
	Proposer  string   `query:"proposed_by" doc:"Only judgments this person proposed, by sign-in identity"`
	Approver  string   `query:"approved_by" doc:"Only judgments this person has a standing agreement on, by sign-in identity. An agreement later taken back does not match"`
	Issue     string   `query:"issue" doc:"Only judgments about this vulnerability, under the name it is filed here"`
	Component string   `query:"component" doc:"Only judgments about this component, by name"`
}

// narrow turns what was asked for into what the store reads by, resolving the
// product against what the caller may see.
func (a Auditing) narrow(ctx context.Context, in Ingest,
	subject access.Subject) (triage.Filter, time.Time, time.Time, error) {

	filter := triage.Filter{
		Alone:     a.Alone,
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
			"The period is the date a judgment was **proposed**, not approved: a judgment " +
			"belongs to when it was argued, and dating it by its agreement would move it out " +
			"of that period whenever an approval came late, which is the ordinary case.\n\n" +
			"Narrowed by what you may see, like every other list here. Nothing about this view " +
			"is exempt from the visibility rules — a report showing more than the screens it " +
			"summarizes would be a way around them.\n\n" +
			"`alone=true` returns judgments no second person has a standing agreement on. " +
			"That population is large and legitimate on its own — an outcome that hides " +
			"nothing needs no second person, and a short deferral stands alone — so ask it " +
			"with an outcome. Asked of a dismissal it should return nothing: `not-applicable`, " +
			"`wont-fix` and `already-fixed` all require approval, so a row in that answer is a " +
			"control that failed.",
		Tags: []string{"Reports"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
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
				Component: row.Component, Version: row.Version, Consumer: row.Consumer,
				Outcome: string(row.Claim.Outcome), Reasoning: row.Reasoning,
				State: string(row.State), Standing: row.Standing(),
				ProposedBy: row.ProposedByName, ProposedAt: stamp(row.ProposedAt),
				TwoPeople: row.BySomebodyElse(),
				Approvals: make([]AgreedBody, 0, len(row.Approvals)),
			}
			if row.Claim.Justification != nil {
				body.Justification = *row.Claim.Justification
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
