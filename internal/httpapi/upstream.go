package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/currency"
)

// UnansweredBody is one component with no upstream answer, and why there is
// none.
type UnansweredBody struct {
	Purl      string `json:"purl" doc:"The package identifier, which is the name that would be sent"`
	Ecosystem string `json:"ecosystem,omitempty" doc:"The ecosystem the identifier names, read out of it rather than stored"`
	Why       string `json:"why" enum:"ours,unknown,unreadable" doc:"'ours' was never sent: this deployment calls the name its own. 'unknown' was sent and no index had heard of it. 'unreadable' is an identifier nothing can turn into a request"`
	Checked   string `json:"checked" doc:"The moment the pass last reached it. For a name of ours that is when it was last decided against rather than when anything was asked"`
}

// UnansweredOutput is a page of what has no upstream answer.
type UnansweredOutput struct {
	Body struct {
		Items []UnansweredBody `json:"items"`
		Total int              `json:"total" doc:"The total, through the same filter as the page"`
		// Ours is the list a name is matched against, so a row saying "ours"
		// can be checked rather than taken on trust. It is the whole reason the
		// derived default is safe to ship on: a default nobody can see is one
		// an operator turns the feature off to escape.
		Ours []string `json:"ours" doc:"The names this deployment holds back, from its publisher namespace, from what it stated, and from what the builds you may read declared themselves to be. A name here is matched against each part of a package's name, either exactly or followed by one of - . _, and a name carrying a dot also covers a host under it"`
		// Whole says the classification saw everything. It is false only on
		// an estate past the ceiling one read classifies.
		Whole bool `json:"whole" doc:"Whether every candidate was examined. False means the estate is past what one read classifies, and the total is a floor"`
	}
}

// registerUpstream answers what asking upstream could not answer, and why.
//
// Two questions that are one report. The held-back list says what the derived
// default costs, and the list no index has heard of is what an operator reads
// to decide what else should be held back — a name promoted from the second
// appears in the first afterwards.
//
// Nothing here is a fault. A private module, a vendored fork and a name this
// deployment publishes under all reach it, and the screen says which.
//
// The names travel back narrowed while the classification is not. A row a
// reader may see can be held back by a root they may not, so it says `ours`
// with no label beside it that explains why — which is the answer REQ-42
// leaves, and the alternative is a product name reaching somebody it was never
// announced to.
func registerUpstream(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-unanswered-upstream", Method: http.MethodGet,
		Path:    "/v1/upstream/unanswered",
		Summary: "List components with no upstream answer",
		Description: "What asking public package indexes did not answer, and why of each.\n\n" +
			"Asking sends a component's name to that ecosystem's index, so names this " +
			"deployment calls its own are never sent. `ours` is what they were matched " +
			"against, narrowed to the products you may read.\n\n" +
			"`unknown` is a component no public index has heard of — a private module or a " +
			"vendored fork — and is the candidate list for `OPENPSIRT_UPSTREAM_INTERNAL`. " +
			"`unreadable` is an identifier nothing can turn into a request.\n\n" +
			"A component the pass has not reached is not here. It is waiting rather than " +
			"unanswered.\n\n" +
			"Answers only components in products you may read.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Paging
	}) (*UnansweredOutput, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		// Classified against every root, because that is what the pass held
		// names back against. Read against a narrower list, a name the pass
		// never sent is reported as sent.
		roots, err := currency.RootOwners(ctx, in.DB.DB)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot read who publishes what was scanned", err)
		}
		ours := in.Ours.With(roots...)
		// Answered from the readable ones alone. A label derived from a root
		// is the name a product is published under, so the whole list tells a
		// reader the scope of a product nobody has announced to them —
		// the exact name this exists to keep out of an index's logs (REQ-42).
		// The deployment's own configuration is not product data and stays.
		readable, err := currency.RootOwnersFor(ctx, in.DB.DB, subject)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot read who publishes what was scanned", err)
		}
		rows, total, whole, err := currency.Unanswerable(
			ctx, in.DB.DB, subject, ours, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot read what has no upstream answer", err)
		}
		out := &UnansweredOutput{}
		out.Body.Items = make([]UnansweredBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, UnansweredBody{
				Purl: row.Purl, Ecosystem: row.Ecosystem, Why: string(row.Why),
				Checked: row.Checked.UTC().Format(time.RFC3339),
			})
		}
		out.Body.Total = total
		out.Body.Whole = whole
		// Never null, so a screen may draw it without asking whether a
		// deployment that holds nothing back has an empty list or no list.
		out.Body.Ours = in.Ours.With(readable...).Labels()
		if out.Body.Ours == nil {
			out.Body.Ours = []string{}
		}
		return out, nil
	})
}
