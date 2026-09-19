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
	Ecosystem string `json:"ecosystem,omitempty" doc:"Which ecosystem the identifier names, read out of it rather than stored"`
	Why       string `json:"why" enum:"ours,unknown,unreadable" doc:"'ours' was never sent: this deployment calls the name its own. 'unknown' was sent and no index had heard of it. 'unreadable' is an identifier nothing can turn into a request"`
	Checked   string `json:"checked" doc:"When the pass last reached it. For a name of ours that is when it was last decided against rather than when anything was asked"`
}

// UnansweredOutput is a page of what has no upstream answer.
type UnansweredOutput struct {
	Body struct {
		Items []UnansweredBody `json:"items"`
		Total int              `json:"total" doc:"How many there are in all, through the same filter as the page"`
		// Ours is what a name is matched against, so a row saying "ours" can
		// be checked rather than taken on trust. It is the whole reason the
		// derived default is safe to ship on: a default nobody can see is one
		// an operator turns the feature off to escape.
		Ours []string `json:"ours" doc:"The names this deployment holds back, from its publisher namespace, from what the scans were about, and from what it stated. A name here is matched against each part of a package's name, either exactly or followed by one of - . _"`
		// Whole says the classification saw everything. It is false only on
		// an estate past the ceiling one read classifies.
		Whole bool `json:"whole" doc:"Whether every candidate was examined. False means the estate is past what one read classifies, and the total is a floor"`
	}
}

// registerUpstream answers what asking upstream could not answer, and why.
//
// **Two questions that are one report.** What was held back says what the
// derived default is costing, and what no index has heard of is the list an
// operator reads to decide what else should be held back — a name promoted
// from the second appears in the first afterwards, which is how somebody knows
// the promotion worked.
//
// Nothing here is a fault. A private module, a vendored fork and a name this
// deployment publishes under all reach it, and the screen says which.
func registerUpstream(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-unanswered-upstream", Method: http.MethodGet,
		Path:    "/v1/upstream/unanswered",
		Summary: "List components with no upstream answer",
		Description: "What asking public package indexes did not answer, and why of each.\n\n" +
			"**Asking is the one thing here that reaches the network, and what it sends is a " +
			"component's name.** For an open-source dependency that is public knowledge; for " +
			"something built here it is the name of a project, a team, or a product nobody " +
			"has announced. So names this deployment calls its own are never sent, and `ours` " +
			"is what they were matched against.\n\n" +
			"**Held back is biased toward holding back.** Over-excluding loses an answer, " +
			"which is visible here and on the screen that would have shown it. Under-" +
			"excluding sends a name to somebody else's service, which is visible nowhere.\n\n" +
			"`unknown` is the candidate list: a component no public index has heard of is a " +
			"private module or a vendored fork, and the names on it are what an operator " +
			"promotes into `OPENPSIRT_UPSTREAM_INTERNAL` so they stop being asked about at " +
			"all.\n\n" +
			"**A component the pass has not reached yet is not here.** It is waiting rather " +
			"than unanswered, and reporting a first day's backlog as though the indexes had " +
			"failed would make the list useless on the day somebody reads it.\n\n" +
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
		// The roots are folded in here as well as in the pass, for the same
		// reason and from the same statement: a name is held back because of
		// what this deployment builds, and reading the report against a
		// narrower list than the pass used would report a name as sent when
		// it never was.
		roots, err := currency.RootOwners(ctx, in.DB.DB)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot read who publishes what was scanned", err)
		}
		ours := in.Ours.With(roots...)
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
		out.Body.Ours = ours.Labels()
		if out.Body.Ours == nil {
			out.Body.Ours = []string{}
		}
		return out, nil
	})
}
