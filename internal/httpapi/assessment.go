package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// AssessmentBody is what one product thinks of an issue, as against what was
// published.
type AssessmentBody struct {
	ID            int64  `json:"id,omitempty"`
	Vulnerability string `json:"vulnerability,omitempty" doc:"The issue this is about"`
	// Product is whose rating it is. Carried on every row because two
	// products may rate one issue differently, so a rating shown without one
	// is a word nobody can act on.
	Product       string `json:"product,omitempty" doc:"The product this rating belongs to"`
	Severity      string `json:"severity" enum:"low,medium,high,critical" doc:"What this product rates it"`
	Published     string `json:"published,omitempty" doc:"What was published when this was made, kept so a reader can see what we disagreed with"`
	Reasoning     string `json:"reasoning" minLength:"1" doc:"Why. It outlives the version it was made about, so the next person needs the argument"`
	State         string `json:"state,omitempty" enum:"proposed,live,withdrawn"`
	NeedsApproval bool   `json:"needs_approval,omitempty" doc:"Whether a second person has to agree before it takes effect"`
	// What agreeing would do beyond moving things down a list, on the claims
	// that are waiting for somebody to agree. Absent on the rest: it is a
	// question about a decision nobody has taken yet, and answering it for
	// every historical claim would cost a query each to say nothing.
	//
	// Counted inside the rating's own product, because that is everywhere the
	// rating reaches.
	Open int `json:"open,omitempty" doc:"Open findings of this issue you can see in this product"`
	// OffTheList is the number an approver is really being asked about: these
	// stop being work rather than becoming later work, and lose their deadline
	// with it.
	OffTheList int `json:"off_the_list,omitempty" doc:"How many of them this rating would put below the product's triage line, where they stop being work and carry no deadline"`
	// Mine says you made this one, so you may not be the second person. The
	// server refuses it either way; carried so a screen can say why rather
	// than offering a button that answers 422 — which is what the embargo
	// extensions beside these in the queue already do.
	Mine bool `json:"mine,omitempty" doc:"You made this rating, so you may not be the one who agrees"`
}

func registerAssessment(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "assess-issue", Method: http.MethodPost,
		Path:    "/v1/products/{product}/issues/{vulnerability}/assessment",
		Summary: "Record what a product thinks of an issue, as against what was published",
		Description: "Recorded against the **issue**, not against a place, and against **one " +
			"product**. A published rating being wrong, or a report being disputed, is one " +
			"statement about the vulnerability in this product — true in every build of it, " +
			"including builds it has not reached yet, and it does not stop being true " +
			"because somebody rebuilt something.\n\n" +
			"It belongs to a product because a rating is a judgment about how a component " +
			"is used, and two products do not use one the same way: one may ship the " +
			"vulnerable configuration and another may not. Two products may record " +
			"different ratings of the same issue, and neither reaches the other. A product " +
			"nobody has rated the issue in reads the published rating.\n\n" +
			"It changes the order, which is what makes it worth having rather than a note " +
			"nobody acts on. Rating something **worse** than published takes effect at " +
			"once: nobody needs protecting from being told something is worse than the " +
			"world says. Rating it **milder** waits for a second person, because that is " +
			"the direction that hides things — and it hides more than a position in a " +
			"list. Severity sets the deadline, so calling a high a low pushes its deadline " +
			"out by months, and where a product has said what is worth triaging at all, a " +
			"downgrade below that line takes the finding off the working list and off any " +
			"clock entirely.\n\n" +
			"The published rating is never overwritten. The product's is what ranks there; " +
			"the world's stays beside it, because a rating of ours shown where the world's " +
			"goes reads as the world's.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Body          AssessmentBody
	}) (*struct{ Body AssessmentBody }, error) {
		subject, _, err := triaging(ctx, in)
		if err != nil {
			return nil, err
		}
		product, err := productNamed(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		// Before the issue name is resolved. Refusing afterwards answers "is
		// this issue known here" for anybody who may read the product.
		if !subject.Triages(access.Public, product.ID) {
			return nil, huma.Error403Forbidden("not authorized")
		}
		issue, err := finding.NewVulnerabilities(in.DB.DB).ByName(ctx, input.Vulnerability)
		if err != nil {
			return nil, noSuchIssue()
		}
		claim, err := finding.NewStore(in.DB.DB).Assess(ctx, subject, product.ID, issue,
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
					"this product already claims something about this issue — withdraw that " +
						"before recording another, so there is one answer rather than two")
			}
			return nil, asked(in.Logger, err)
		}
		body := assessmentBody(*claim, input.Vulnerability, subject.ID)
		body.Product = input.Product
		return &struct{ Body AssessmentBody }{Body: body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "agree-assessment", Method: http.MethodPost,
		Path:    "/v1/assessments/{id}/agreement",
		Summary: "Approve a rating assessment",
		Description: "Only a milder rating waits for this. Somebody other than whoever " +
			"proposed it, for the same reason every other second person here is somebody " +
			"else: a control one person can complete alone is not a control.\n\n" +
			"The second person holds their role **on the product the rating belongs to**. " +
			"Agreeing is what puts a milder rating into force, so it moves that product's " +
			"deadlines and its triage line; a rating in a product you hold nothing on " +
			"answers as one that is not there.",
		Tags: []string{"Triage"},
	}, perProduct, "The proposer may not approve their own. The product is the rating's own, "+
		"not one in the path.", approveRights()...), func(ctx context.Context, input *struct {
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
		Description: "The rating in force in that product returns to the published one, and " +
			"everything that reads it — where a finding sits in the list, how long it has, " +
			"whether it is above the line the product triages — follows it back. No other " +
			"product is touched.\n\n" +
			"Asked of triage **on the product the rating belongs to**: taking a rating back " +
			"is making one.",
		Tags: []string{"Triage"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "The product is the rating's own, not one in the path.",
		triageRights()...), func(ctx context.Context, input *struct {
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
			"state, or those belonging to one product. The ones waiting are milder ratings " +
			"somebody has proposed and nobody has agreed to yet, which are the ones not yet " +
			"affecting anything.\n\n" +
			"A rating belongs to one product, so a row says which. Two products may rate the " +
			"same issue differently and both rows appear, each narrowed by what you may read " +
			"in its own product.\n\n" +
			"A claim carries the severity recorded against its issue, so claims about " +
			"findings you cannot read are absent rather than refused.",
		Tags: []string{"Triage"},
	}, anySubject, "Narrowed to issues you may read a finding of in the product the rating "+
		"belongs to. A rating is about one product, and an issue this deployment minted for a "+
		"flaw nobody has announced is not public knowledge."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"Limit to one product, by name"`
		State   string `query:"state" enum:"proposed,live,withdrawn" doc:"Limit to one state"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
	}) (*listOutput[AssessmentBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		// Resolved before anything is read, and refused in the words an
		// undeclared name gets: a product somebody holds nothing on does not
		// exist as far as they are concerned.
		within := int64(0)
		if input.Product != "" {
			product, err := productNamed(ctx, in, subject, input.Product)
			if err != nil {
				return nil, err
			}
			within = product.ID
		}
		store := finding.NewStore(in.DB.DB)
		claims, named, err := store.Assessments(ctx, subject, within, input.State, input.Limit)
		if err != nil {
			if errors.Is(err, access.ErrDenied) {
				return nil, noSuchProduct()
			}
			return nil, wentWrong(in.Logger, "what we have said could not be read", err)
		}
		// What each rating's product is called, read once for the page rather
		// than per row.
		products, err := productsNamed(ctx, in, claims)
		if err != nil {
			return nil, wentWrong(in.Logger, "what these ratings belong to could not be read", err)
		}
		out := &listOutput[AssessmentBody]{}
		out.Body.Items = make([]AssessmentBody, 0, len(claims))
		for _, claim := range claims {
			body := assessmentBody(claim, named[claim.VulnerabilityID], subject.ID)
			body.Product = products[claim.ProductID]
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
				body.Open, body.OffTheList = would.Findings, would.OffTheList
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

// productsNamed is what each of these ratings' products is called.
//
// One lookup for the page. A rating belongs to a product and the row has to
// say which, because two products may rate one issue differently and a word
// with no product beside it is not actionable.
func productsNamed(ctx context.Context, in Ingest, claims []finding.Assessment) (map[int64]string, error) {
	named := map[int64]string{}
	if len(claims) == 0 {
		return named, nil
	}
	ids := make([]int64, 0, len(claims))
	for _, claim := range claims {
		ids = append(ids, claim.ProductID)
	}
	return catalog.NewStore(in.DB.DB).ProductNames(ctx, ids)
}

// productNamed resolves a product name the caller supplied, refusing one they
// hold nothing on in the words an undeclared name gets.
func productNamed(ctx context.Context, in Ingest, subject access.Subject,
	name string) (*catalog.Product, error) {

	product, err := catalog.NewStore(in.DB.DB).ProductByName(ctx, name)
	if err != nil || !subject.Sees(product.ID) {
		return nil, noSuchProduct()
	}
	return product, nil
}
