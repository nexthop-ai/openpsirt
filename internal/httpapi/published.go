package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/advisory"
)

// WentBody is one advisory that went out.
type WentBody struct {
	Product string `json:"product"`
	Issue   string `json:"issue" doc:"The flaw it was written about, under the identifier it is filed here"`
	// Ordinal is which issuance this was, counting from one. Anything above
	// one is a revision, which is what somebody reading a period is looking
	// for.
	Ordinal  int    `json:"ordinal" doc:"Which issuance this was, counting from one. Above one is a revision"`
	Summary  string `json:"summary,omitempty"`
	IssuedBy string `json:"issued_by"`
	IssuedAt string `json:"issued_at"`
	Digest   string `json:"digest" doc:"What the document hashed to when it went out. The published document belongs to whoever published it; this is what makes comparing it possible"`
}

// registerPublished answers what advisories went out over a period.
//
// The per-flaw list answers "has one gone out for this, and is what is
// published still what we would generate" — which is what somebody about to
// publish a revision asks. A period asks something else: what went out at all,
// and what went out more than once.
func registerPublished(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-published-advisories", Method: http.MethodGet,
		Path:    "/v1/advisories",
		Summary: "List advisories that have gone out",
		Description: "Every advisory published from this deployment in a period, newest first, " +
			"with which flaw it was about, which revision it was, who published it and what " +
			"the document hashed to at the time.\n\n" +
			"**Advisories are about flaws in our own product**, recorded here by hand. Known " +
			"issues in third-party components are tracked and fixed rather than published " +
			"about, and the document for those is a VEX statement per build.\n\n" +
			"`ordinal` above one is a revision of an advisory already out, which is the entry " +
			"a period is usually read for.\n\n" +
			"Narrowed by what you may see: a flaw nobody has disclosed is absent for anybody " +
			"who may not read it, and a count is as much a disclosure as a row.",
		Tags: []string{"Reports"},
	}, anySubject, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"Limit to one product, by name"`
		Days    int    `query:"days" default:"365" minimum:"1" maximum:"3650" doc:"How far back to look, by when the advisory went out"`
	}) (*listOutput[WentBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		var products []int64
		if input.Product != "" {
			named, err := productNamedVisibly(ctx, in, subject, input.Product)
			if err != nil {
				return nil, err
			}
			products = []int64{named.ID}
		}
		since := time.Now().UTC().AddDate(0, 0, -input.Days)

		gone, err := advisory.NewStore(in.DB.DB).Published(ctx, subject, products, since)
		if err != nil {
			return nil, wentWrong(in.Logger, "what has been published could not be read", err)
		}
		out := &listOutput[WentBody]{}
		out.Body.Items = make([]WentBody, 0, len(gone))
		for _, row := range gone {
			out.Body.Items = append(out.Body.Items, WentBody{
				Product: row.Product, Issue: row.Issue, Ordinal: row.Ordinal,
				Summary: row.Summary, IssuedBy: row.IssuedBy,
				IssuedAt: stamp(row.IssuedAt), Digest: row.Digest,
			})
		}
		return out, nil
	})
}
