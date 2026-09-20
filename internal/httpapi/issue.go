package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// SightingBody is one issue in one component of one build.
type SightingBody struct {
	Product     string `json:"product" doc:"The product's name, as an address takes it"`
	ProductName string `json:"product_name" doc:"Its spelling on screen"`
	Stream      string `json:"stream"`
	Variant     string `json:"variant"`
	Component   string `json:"component"`
	Version     string `json:"version"`
	Places      int    `json:"places" doc:"The number of times that component sits in that build carrying this issue"`
	State       string `json:"state,omitempty" enum:"undecided,waiting,agreed,lapsed" doc:"The decision state here, by the definition the findings list uses"`
	Undisclosed bool   `json:"undisclosed,omitempty"`
	Due         string `json:"due,omitempty" doc:"The earliest deadline among its places"`
	FixedIn     string `json:"fixed_in,omitempty"`
}

// IssueOutput is one issue, everywhere the caller may see it.
type IssueOutput struct {
	Body struct {
		Vulnerability string         `json:"vulnerability"`
		Aliases       []string       `json:"aliases,omitempty" doc:"Every other name it answers to"`
		Severity      string         `json:"severity,omitempty"`
		Score         float64        `json:"score,omitempty"`
		ScoreVersion  string         `json:"score_version,omitempty" doc:"The scoring system the number is on"`
		Exploited     bool           `json:"exploited,omitempty"`
		Description   string         `json:"description,omitempty"`
		Items         []SightingBody `json:"items"`
		// Total counts build-and-component pairs, which is what a row is.
		Total    int `json:"total"`
		Products int `json:"products" doc:"The number of your products carrying it"`
	}
}

// registerIssue answers for one issue across every product.
//
// The work starts from an issue as often as from a product. A critical landing
// in openssl raises the question of which products ship an affected version,
// and answered per product that is a question assembled by hand a dozen
// times.
func registerIssue(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-issue", Method: http.MethodGet, Path: "/v1/issues/{vulnerability}",
		Summary: "List findings for one issue across every product",
		Description: "Every build that carries this issue, across every product you may see, " +
			"with how far it has been decided in each.\n\n" +
			"One row per build and component, not per place: the same component in two " +
			"builds is two things somebody ships, and sixty places of it in one build is one " +
			"piece of work with a count.\n\n" +
			"Narrowed the way every other read is, per product and per visibility. A page " +
			"that spans products is exactly where filtering afterwards gets forgotten, and " +
			"the count is the leak even when no row is shown.\n\n" +
			"Nothing affected is an answer, not a 404: `total` is zero and `items` is " +
			"empty, which is what a customer inquiry is asking for. An identifier nobody " +
			"here has seen answers the same way as one that sits only in products you " +
			"cannot read — told apart, the pair would say which issues this deployment " +
			"holds, one guess at a time.\n\n" +
			"Answers by any name the issue goes by.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Vulnerability string `path:"vulnerability" doc:"The issue, by any name it is known under"`
		Limit         int    `query:"limit" default:"200" minimum:"1" maximum:"500"`
	}) (*IssueOutput, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		out := &IssueOutput{}
		out.Body.Vulnerability = input.Vulnerability
		out.Body.Items = []SightingBody{}

		issues := finding.NewVulnerabilities(in.DB.DB)
		id, err := issues.ByName(ctx, input.Vulnerability)
		if err != nil {
			// A read that could not be made is not an answer about what this
			// reader is affected by. The sentinel is what tells the two
			// apart, which is what it is for.
			if !errors.Is(err, finding.ErrNoSuchIssue) {
				return nil, wentWrong(in.Logger, "what issue this is could not be read", err)
			}
			// Not affected is an answer, and it is the one a customer
			// inquiry asks for. Refused with a 404, the question of whether
			// we are affected can be answered yes-here and never no — and the
			// case somebody is under time pressure to answer is the second
			// one.
			//
			// An identifier nobody here has ever seen answers the same way as
			// one that affects only products this reader cannot see. Told
			// apart, the pair says which issues the deployment holds, one
			// guess at a time, about products somebody may not read — and an
			// issue is here because some scan somewhere reported it.
			return out, nil
		}
		store := finding.NewStore(in.DB.DB)
		rows, total, err := store.Everywhere(ctx, subject, id, input.Limit)
		if err != nil {
			return nil, wentWrong(in.Logger, "where this issue sits could not be read", err)
		}
		if total == 0 {
			// Nothing about the issue itself, for the reason above: what is
			// said about it is said to somebody who can see it somewhere.
			return out, nil
		}
		known, err := issues.Describe(ctx, id)
		if err != nil {
			return nil, wentWrong(in.Logger, "what this issue is could not be read", err)
		}

		out.Body.Vulnerability = known.Identifier
		out.Body.Aliases = known.Aliases
		out.Body.Severity = known.Severity
		out.Body.Score = known.Score
		out.Body.ScoreVersion = known.ScoreVersion
		out.Body.Exploited = known.Exploited
		out.Body.Description = known.Description
		out.Body.Items = make([]SightingBody, 0, len(rows))
		products := map[string]bool{}
		for _, row := range rows {
			products[row.Product] = true
			body := SightingBody{
				Product: row.Product, ProductName: row.ProductName,
				Stream: row.Stream, Variant: row.Variant,
				Component: row.Component, Version: row.Version,
				Places: row.Places, State: row.State,
				Undisclosed: row.Undisclosed, FixedIn: row.FixedIn,
			}
			if row.DueAt != nil {
				body.Due = row.DueAt.Format(time.DateOnly)
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		out.Body.Total = total
		out.Body.Products = len(products)
		return out, nil
	})
}
