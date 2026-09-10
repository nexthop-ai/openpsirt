package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// SightingBody is one issue in one component of one build.
type SightingBody struct {
	Product     string `json:"product" doc:"The product's name, as an address takes it"`
	ProductName string `json:"product_name" doc:"How it is spelled on screen"`
	Stream      string `json:"stream"`
	Variant     string `json:"variant"`
	Component   string `json:"component"`
	Version     string `json:"version"`
	Places      int    `json:"places" doc:"How many times that component sits in that build carrying this issue"`
	State       string `json:"state,omitempty" enum:"undecided,waiting,agreed,lapsed" doc:"How far it has been decided here, by the definition the findings list uses"`
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
		Exploited     bool           `json:"exploited,omitempty"`
		Description   string         `json:"description,omitempty"`
		Items         []SightingBody `json:"items"`
		// Total counts build-and-component pairs, which is what a row is.
		Total    int `json:"total"`
		Products int `json:"products" doc:"How many of your products carry it"`
	}
}

// registerIssue answers for one issue across every product.
//
// **The work starts from an issue as often as from a product.** "A critical
// just landed in openssl — which of our products ship an affected version" was
// a question asked a dozen times and assembled by hand, because findings are
// answered per product.
func registerIssue(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-issue", Method: http.MethodGet, Path: "/v1/issues/{vulnerability}",
		Summary: "List findings for one issue across every product",
		Description: "Every build that carries this issue, across every product you may see, " +
			"with how far it has been decided in each.\n\n" +
			"**One row per build and component**, not per place: the same component in two " +
			"builds is two things somebody ships, and sixty places of it in one build is one " +
			"piece of work with a count.\n\n" +
			"**Narrowed the way every other read is**, per product and per visibility. A page " +
			"that spans products is exactly where filtering afterwards gets forgotten, and " +
			"the count is the leak even when no row is shown.\n\n" +
			"Answers by any name the issue goes by.",
		Tags: []string{"Findings"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
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
		issues := finding.NewVulnerabilities(in.DB.DB)
		id, err := issues.ByName(ctx, input.Vulnerability)
		if err != nil {
			return nil, noSuchIssue()
		}
		store := finding.NewStore(in.DB.DB)
		rows, total, err := store.Everywhere(ctx, subject, id, input.Limit)
		if err != nil {
			return nil, wentWrong(in.Logger, "where this issue sits could not be read", err)
		}
		// Nothing they may see is the same answer as no such issue,
		// deliberately: an issue that exists somewhere they hold nothing is
		// not something this should confirm.
		if total == 0 {
			return nil, noSuchIssue()
		}
		known, err := issues.Describe(ctx, id)
		if err != nil {
			return nil, wentWrong(in.Logger, "what this issue is could not be read", err)
		}

		out := &IssueOutput{}
		out.Body.Vulnerability = known.Identifier
		out.Body.Aliases = known.Aliases
		out.Body.Severity = known.Severity
		out.Body.Score = known.Score
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
