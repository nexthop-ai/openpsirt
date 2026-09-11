package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// AssessmentBody is what we think of an issue, as against what was published.
type AssessmentBody struct {
	ID            int64  `json:"id,omitempty"`
	Vulnerability string `json:"vulnerability,omitempty" doc:"The issue this is about"`
	Severity      string `json:"severity" enum:"low,medium,high,critical" doc:"What we rate it"`
	Published     string `json:"published,omitempty" doc:"What was published when this was made, kept so a reader can see what we disagreed with"`
	Reasoning     string `json:"reasoning" minLength:"1" doc:"Why. It outlives the version it was made about, so the next person needs the argument"`
	State         string `json:"state,omitempty" enum:"proposed,live,withdrawn"`
	NeedsApproval bool   `json:"needs_approval,omitempty" doc:"Whether a second person has to agree before it takes effect"`
	// What agreeing would do beyond moving things down a list, on the claims
	// that are waiting for somebody to agree. Absent on the rest: it is a
	// question about a decision nobody has taken yet, and answering it for
	// every historical claim would cost a query each to say nothing.
	Open int `json:"open,omitempty" doc:"Open findings of this issue you can see"`
	// InProducts is how many products those sit in. An assessment is about an
	// issue and a line is per product, so what it does depends on where.
	InProducts int `json:"in_products,omitempty" doc:"How many products those sit in"`
	// OffTheList is the number an approver is really being asked about: these
	// stop being work rather than becoming later work, and lose their deadline
	// with it.
	OffTheList          int `json:"off_the_list,omitempty" doc:"How many of them this rating would put below their product's triage line, where they stop being work and carry no deadline"`
	OffTheListInProduct int `json:"off_the_list_in_products,omitempty" doc:"How many products that happens in"`
	// Mine says you made this one, so you may not be the second person. The
	// server refuses it either way; carried so a screen can say why rather
	// than offering a button that answers 422 — which is what the embargo
	// extensions beside these in the queue already do.
	Mine bool `json:"mine,omitempty" doc:"You made this rating, so you may not be the one who agrees"`
}

func registerAssessment(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "assess-issue", Method: http.MethodPost,
		Path:    "/v1/issues/{vulnerability}/assessment",
		Summary: "Record what we think of an issue, as against what was published",
		Description: "Recorded against the **issue**, not against a place. A published rating " +
			"being wrong, or a report being disputed, is one statement about the " +
			"vulnerability — true wherever it appears, including in products it has not " +
			"reached yet, and it does not stop being true because somebody rebuilt " +
			"something.\n\n" +
			"It changes the order, which is what makes it worth having rather than a note " +
			"nobody acts on. Rating something **worse** than published takes effect at " +
			"once: nobody needs protecting from being told something is worse than the " +
			"world says. Rating it **milder** waits for a second person, because that is " +
			"the direction that hides things — and it hides more than a position in a " +
			"list. Severity sets the deadline, so calling a high a low pushes its deadline " +
			"out by months, and where a product has said what is worth triaging at all, a " +
			"downgrade below that line takes the finding off the working list and off any " +
			"clock entirely.\n\n" +
			"The published rating is never overwritten. Ours is what ranks; the world's " +
			"stays beside it, because a rating of ours shown where the world's goes reads " +
			"as the world's.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, anyProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Body          AssessmentBody
	}) (*struct{ Body AssessmentBody }, error) {
		subject, _, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		// Before the name is resolved. Refusing afterwards answers "is
		// this issue known here" for anybody with an account.
		if !subject.HoldsAnywhere(access.PublicTriage, access.PrivateTriage) {
			return nil, huma.Error403Forbidden("not authorized")
		}
		issue, err := finding.NewVulnerabilities(in.DB.DB).ByName(ctx, input.Vulnerability)
		if err != nil {
			return nil, noSuchIssue()
		}
		claim, err := finding.NewStore(in.DB.DB).Assess(ctx, subject, issue,
			input.Body.Severity, input.Body.Reasoning)
		if err != nil {
			// Exactly what an unused name answers. An issue somebody may not
			// be told about is not one they get to learn the severity of by
			// rating it.
			if errors.Is(err, finding.ErrUnknownIssue) {
				return nil, noSuchIssue()
			}
			if errors.Is(err, finding.ErrAlreadyAssessed) {
				return nil, huma.Error409Conflict(
					"something is already claimed about this issue — withdraw that before " +
						"recording another, so there is one answer rather than two")
			}
			return nil, asked(in.Logger, err)
		}
		return &struct{ Body AssessmentBody }{Body: assessmentBody(*claim, input.Vulnerability, subject.ID)}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "agree-assessment", Method: http.MethodPost,
		Path:    "/v1/assessments/{id}/agreement",
		Summary: "Approve a rating assessment",
		Description: "Only a milder rating waits for this. Somebody other than whoever " +
			"proposed it, for the same reason every other second person here is somebody " +
			"else: a control one person can complete alone is not a control.",
		Tags: []string{"Triage"},
	}, anyProduct, "The proposer may not approve their own.", approveRights()...), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*struct{ Body AssessmentBody }, error) {
		subject, _, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		claim, err := finding.NewStore(in.DB.DB).Agree(ctx, subject, input.ID)
		if err != nil {
			if errors.Is(err, finding.ErrNoSuchAssessment) {
				return nil, noSuchAssessment()
			}
			if errors.Is(err, access.ErrDenied) {
				return nil, huma.Error403Forbidden("not authorized")
			}
			return nil, asked(in.Logger, err)
		}
		return &struct{ Body AssessmentBody }{Body: assessmentBody(*claim, "", subject.ID)}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "withdraw-assessment", Method: http.MethodDelete,
		Path:    "/v1/assessments/{id}",
		Summary: "Withdraw an assessment, and take the published rating back",
		Description: "The rating in force returns to the published one, and everything that " +
			"reads it — where a finding sits in the list, how long it has, whether it is " +
			"above the line a product triages — follows it back.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, anyProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*struct{}, error) {
		subject, _, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		if err := finding.NewStore(in.DB.DB).Withdraw(ctx, subject, input.ID); err != nil {
			if errors.Is(err, finding.ErrNoSuchAssessment) {
				return nil, noSuchAssessment()
			}
			if errors.Is(err, access.ErrDenied) {
				return nil, huma.Error403Forbidden("not authorized")
			}
			return nil, asked(in.Logger, err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-assessments", Method: http.MethodGet,
		Path:    "/v1/assessments",
		Summary: "List issue assessments",
		Description: "Every claim about an issue you may be told about, or those in one " +
			"state. The ones waiting are milder ratings somebody has proposed and nobody " +
			"has agreed to yet, which are the ones not yet affecting anything.\n\n" +
			"A claim carries the severity recorded against its issue, so claims about " +
			"findings you cannot read are absent rather than refused.",
		Tags: []string{"Triage"},
	}, anySubject, "Narrowed to issues you may read a finding of somewhere. A rating is about "+
		"an issue rather than a product, but an issue this deployment minted for a flaw "+
		"nobody has announced is not public knowledge."), func(ctx context.Context, input *struct {
		State string `query:"state" enum:"proposed,live,withdrawn" doc:"Limit to one state"`
		Limit int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
	}) (*listOutput[AssessmentBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		claims, named, err := finding.NewStore(in.DB.DB).Assessments(ctx, subject,
			input.State, input.Limit)
		if err != nil {
			return nil, wentWrong(in.Logger, "what we have said could not be read", err)
		}
		store := finding.NewStore(in.DB.DB)
		out := &listOutput[AssessmentBody]{}
		out.Body.Items = make([]AssessmentBody, 0, len(claims))
		for _, claim := range claims {
			body := assessmentBody(claim, named[claim.VulnerabilityID], subject.ID)
			// Only for the ones somebody is being asked to agree to. It is a
			// question about a decision not yet taken, and a query each for
			// every historical claim would buy nothing.
			if claim.State == finding.AssessmentProposed && claim.NeedsApproval {
				would, err := store.WhatAgreeingWouldDo(ctx, subject, claim.ID)
				// A claim that stopped being readable between the list and
				// this loop leaves its counts off rather than failing the
				// whole page.
				if errors.Is(err, finding.ErrNoSuchAssessment) {
					continue
				}
				if err != nil {
					return nil, wentWrong(in.Logger, "what agreeing would do could not be worked out", err)
				}
				body.Open, body.InProducts = would.Findings, would.Products
				body.OffTheList, body.OffTheListInProduct = would.OffTheList, would.ProductsAffected
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}

func assessmentBody(a finding.Assessment, identifier string, asking int64) AssessmentBody {
	return AssessmentBody{
		ID: a.ID, Vulnerability: identifier, Severity: a.Severity,
		Published: a.Published, Reasoning: a.Reasoning,
		State: a.State, NeedsApproval: a.NeedsApproval,
		Mine: a.ProposedBy == asking,
	}
}
