package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// AnywhereOutput is a page of what is open across every product.
type AnywhereOutput struct {
	Body struct {
		Items []FindingBody `json:"items"`
		// Total is how many things there are to decide about across every
		// product the caller may see, counted through the same filter as the
		// page.
		Total int `json:"total"`
	}
}

// registerAnywhere is the findings list across products.
func registerAnywhere(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-findings-anywhere", Method: http.MethodGet, Path: "/v1/findings",
		Summary: "List findings across every product",
		Description: "The findings list, without a product picked.\n\n" +
			"One row per product, issue and component. The same library carrying the same " +
			"issue in two products is two pieces of work, decided separately by different " +
			"people; in three builds of one product it is one row, and `builds` says how " +
			"many. Each row names one of those builds so there is somewhere to link to.\n\n" +
			"Every product's own triage line still applies. `severity` raises the line " +
			"for the whole page and never lowers it below what a product decided; " +
			"`below_floor` turns every line off, which is how the rows a line keeps out are " +
			"asked for.\n\n" +
			"An issue that exists only in products you hold nothing on answers as an " +
			"issue that does not exist, and `total` says the same.\n\n" +
			"`beneath` is not offered: a subtree is a walk over one build's edges. Neither is " +
			"`differs`, which is a statement about a selection of builds. Both are on the " +
			"per-product list, which is where a build can be named.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Narrowing
		Paging
	}) (*AnywhereOutput, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		// The line is per product and is applied per row inside the store, so
		// what is handed over here is only what the caller asked to raise it
		// to — never a number chosen for a page that spans products.
		narrowed, err := input.filter(finding.Floor{Word: input.Severity})
		if err != nil {
			return nil, err
		}
		// Severity is the line here rather than a second filter beside it.
		// Asked as both, a product line of "high" and a request for "medium"
		// would narrow twice and answer neither question.
		narrowed.MinSeverity = ""
		groups, total, err := finding.NewStore(in.DB.DB).Anywhere(ctx, subject,
			input.Limit, input.Offset, narrowed)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read what is open")
		}
		out := &AnywhereOutput{}
		out.Body.Total = total
		out.Body.Items = make([]FindingBody, 0, len(groups))
		now := time.Now().UTC()
		for _, group := range groups {
			out.Body.Items = append(out.Body.Items, findingBody(group, now))
		}
		return out, nil
	})
}
