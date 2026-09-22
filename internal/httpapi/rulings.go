package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// RulingBody is one act of saying what one or more reports are.
type RulingBody struct {
	ID          int64    `json:"id"`
	Disposition string   `json:"disposition" enum:"duplicate,not-reproducible,out-of-scope,rejected"`
	Reasoning   string   `json:"reasoning,omitempty" doc:"Why, as markdown. Never edited, so an approval is of these words"`
	DuplicateOf string   `json:"duplicate_of,omitempty" doc:"The open issue a duplicate points at"`
	Reports     []string `json:"reports" doc:"The references of the reports it covers, including after it was withdrawn"`
	State       string   `json:"state" enum:"waiting,in-force,withdrawn" doc:"Waiting for a second person, what its reports currently are, or taken back"`
	ProposedBy  string   `json:"proposed_by"`
	ProposedAt  string   `json:"proposed_at"`
	Yours       bool     `json:"yours,omitempty" doc:"Whether you proposed it. The proposer may not approve it"`
	ApprovedBy  string   `json:"approved_by,omitempty" doc:"Who agreed, on a disposition that takes a second person"`
	ApprovedAt  string   `json:"approved_at,omitempty"`
	WithdrawnBy string   `json:"withdrawn_by,omitempty"`
	WithdrawnAt string   `json:"withdrawn_at,omitempty"`
}

// RulingProposedBody is a ruling as somebody submits it.
type RulingProposedBody struct {
	Reports     []string `json:"reports" minItems:"1" maxItems:"10000" doc:"The references of the reports it covers. Naming one twice covers it once"`
	Disposition string   `json:"disposition" enum:"duplicate,not-reproducible,out-of-scope,rejected"`
	Reasoning   string   `json:"reasoning,omitempty" maxLength:"65536" doc:"Why, as markdown. Required on everything but a duplicate"`
	DuplicateOf string   `json:"duplicate_of,omitempty" maxLength:"191" doc:"The open issue a duplicate points at, under any identifier it goes by. Only on a duplicate"`
}

// registerRulings is saying what claims are when the answer is not an issue
// here, and the second person some of those answers take.
func registerRulings(api huma.API, in Ingest) {
	const list = "/v1/products/{product}/report-rulings"
	const one = list + "/{ruling}"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "rule-reports", Method: http.MethodPost, Path: list,
		Summary: "Rule on reports",
		Description: "Says that one or more reports are duplicates, not reproducible, out of " +
			"scope, or rejected. A report that turned out to be an issue here is pointed at " +
			"that issue instead.\n\n" +
			"`out-of-scope` and `rejected` wait for a second person, and nothing changes until " +
			"somebody other than the proposer approves. The other two take effect at once. " +
			"While a ruling waits, its reports cannot be accepted as an issue or ruled on " +
			"again.\n\n" +
			"`reasoning` is required on everything but a duplicate. `duplicate_of` is required " +
			"on a duplicate and refused on anything else, and names an issue open in this " +
			"product. A duplicate of an issue that is not open here is refused: reject the " +
			"report instead.\n\n" +
			"Every report named has to be in this product and unanswered, or nothing is " +
			"written. The number of reports is bounded by `triage.together-cap`, the setting " +
			"that bounds every bulk judgment.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    RulingProposedBody
	}) (*struct{ Body RulingBody }, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		// Authorized before the duplicate's issue is resolved, so a refusal
		// says nothing about which identifiers are here.
		if err := finding.MayWorkReports(subject, product.ID); err != nil {
			return nil, asked(in.Logger, err)
		}
		var target int64
		if input.Body.DuplicateOf != "" {
			// Resolved here and asked again inside the write. An issue this
			// person may not be told of answers exactly as one that is not
			// here.
			target, err = issueHere(ctx, in, subject, product.ID, input.Body.DuplicateOf)
			if err != nil {
				return nil, err
			}
		}
		ruling, err := finding.NewStore(in.DB.DB).Rule(ctx, subject, product.ID, finding.Ruled{
			References:  input.Body.Reports,
			Disposition: finding.Disposition(input.Body.Disposition),
			Reasoning:   input.Body.Reasoning,
			DuplicateOf: target,
		})
		if err != nil {
			return nil, refusedRuling(in, err, "that ruling could not be recorded")
		}
		return rulingOutput(ctx, in, subject, ruling)
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-report-rulings", Method: http.MethodGet, Path: list,
		Summary: "List rulings on reports",
		Description: "Every ruling in this product, newest first, including withdrawn ones. " +
			"`waiting` narrows to those waiting for a second person.",
		Tags: []string{"Findings"},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Waiting bool   `query:"waiting" doc:"Only rulings waiting for a second person"`
		Limit   int    `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset  int    `query:"offset" minimum:"0" default:"0"`
	}) (*listOutput[RulingBody], error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		rows, total, err := finding.NewStore(in.DB.DB).RulingsIn(ctx, subject, product.ID,
			input.Waiting, input.Limit, input.Offset)
		if err != nil {
			return nil, refusedRuling(in, err, "the rulings could not be read")
		}
		out := &listOutput[RulingBody]{}
		out.Body.Items, err = rulingBodies(ctx, in, subject, rows)
		if err != nil {
			return nil, wentWrong(in.Logger, "the rulings could not be read", err)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-report-ruling", Method: http.MethodGet, Path: one,
		Summary: "Show a ruling on reports",
		Description: "What was said, about which reports, by whom, and whether it is waiting, " +
			"in force or withdrawn.",
		Tags: []string{"Findings"},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Ruling  int64  `path:"ruling"`
	}) (*struct{ Body RulingBody }, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		ruling, err := finding.NewStore(in.DB.DB).RulingBy(ctx, subject, product.ID, input.Ruling)
		if err != nil {
			return nil, refusedRuling(in, err, "that ruling could not be read")
		}
		return rulingOutput(ctx, in, subject, ruling)
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "approve-report-ruling", Method: http.MethodPost, Path: one + "/approval",
		Summary: "Approve a ruling on reports",
		Description: "Agrees to a waiting ruling, which is when it takes effect for every " +
			"report it covers.\n\n" +
			"Refused to whoever proposed it, and refused on a ruling that is not waiting.",
		Tags: []string{"Findings"},
	}, perProduct, "The proposer may not approve their own.", access.PrivateTriage),
		func(ctx context.Context, input *struct {
			Product string `path:"product"`
			Ruling  int64  `path:"ruling"`
		}) (*struct{ Body RulingBody }, error) {
			subject, product, err := productForReports(ctx, in, input.Product)
			if err != nil {
				return nil, err
			}
			ruling, err := finding.NewStore(in.DB.DB).ApproveRuling(ctx, subject,
				product.ID, input.Ruling)
			if err != nil {
				return nil, refusedRuling(in, err, "that ruling could not be approved")
			}
			return rulingOutput(ctx, in, subject, ruling)
		})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "withdraw-report-ruling", Method: http.MethodPost, Path: one + "/withdrawal",
		Summary: "Withdraw a ruling on reports",
		Description: "Takes a ruling back, waiting or in force, and returns every report it " +
			"covered to the inbox unanswered. Sending a waiting ruling back and undoing one in " +
			"force are this one act.\n\n" +
			"Needs nobody else, and the proposer may withdraw their own. The ruling stays on " +
			"record as withdrawn.",
		Tags: []string{"Findings"},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Ruling  int64  `path:"ruling"`
	}) (*struct{ Body RulingBody }, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		ruling, err := finding.NewStore(in.DB.DB).WithdrawRuling(ctx, subject,
			product.ID, input.Ruling)
		if err != nil {
			return nil, refusedRuling(in, err, "that ruling could not be withdrawn")
		}
		return rulingOutput(ctx, in, subject, ruling)
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-duplicate-reports", Method: http.MethodGet,
		Path:    "/v1/products/{product}/issues/{vulnerability}/duplicates",
		Summary: "List reports that duplicate an issue",
		Description: "Every report in this product ruled a duplicate of this issue, with the " +
			"ruling in force. What arrived with each is listed on the report's own " +
			"attachments.\n\n" +
			"An issue that is not here and one you may not be told of answer alike.",
		Tags: []string{"Findings"},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
	}) (*listOutput[ReportBody], error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		if err := finding.MayWorkReports(subject, product.ID); err != nil {
			return nil, asked(in.Logger, err)
		}
		issue, err := issueHere(ctx, in, subject, product.ID, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		rows, err := finding.NewStore(in.DB.DB).DuplicatesOf(ctx, subject, product.ID, issue)
		if err != nil {
			return nil, refusedReport(in, err, "the duplicates could not be read")
		}
		out := &listOutput[ReportBody]{}
		out.Body.Items, err = reportBodies(ctx, in, rows)
		if err != nil {
			return nil, wentWrong(in.Logger, "the duplicates could not be read", err)
		}
		out.Body.Total = len(rows)
		return out, nil
	})
}

// rulingOutput renders one ruling as a response.
func rulingOutput(ctx context.Context, in Ingest, subject access.Subject,
	ruling *finding.ReportRuling) (*struct{ Body RulingBody }, error) {

	bodies, err := rulingBodies(ctx, in, subject, []finding.ReportRuling{*ruling})
	if err != nil {
		return nil, wentWrong(in.Logger, "that ruling could not be read back", err)
	}
	return &struct{ Body RulingBody }{Body: bodies[0]}, nil
}

// rulingBodies renders rulings, naming the people and issues they refer to in
// one read each.
func rulingBodies(ctx context.Context, in Ingest, subject access.Subject,
	rows []finding.ReportRuling) ([]RulingBody, error) {

	people := make([]int64, 0, len(rows))
	issues := make([]int64, 0, len(rows))
	for _, row := range rows {
		people = append(people, row.ProposedBy)
		for _, id := range []*int64{row.ApprovedBy, row.WithdrawnBy} {
			if id != nil {
				people = append(people, *id)
			}
		}
		if row.DuplicateOf != nil {
			issues = append(issues, *row.DuplicateOf)
		}
	}
	names, err := access.NewStore(in.DB.DB).Names(ctx, people)
	if err != nil {
		return nil, err
	}
	identifiers, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
	if err != nil {
		return nil, err
	}
	out := make([]RulingBody, 0, len(rows))
	for _, row := range rows {
		body := RulingBody{
			ID: row.ID, Disposition: string(row.Disposition), Reasoning: row.Reasoning,
			Reports: row.References, State: rulingState(row),
			ProposedBy: names[row.ProposedBy], ProposedAt: row.ProposedAt.Format(time.RFC3339),
			Yours: row.ProposedBy == subject.ID,
		}
		if body.Reports == nil {
			body.Reports = []string{}
		}
		if row.DuplicateOf != nil {
			body.DuplicateOf = identifiers[*row.DuplicateOf]
		}
		if row.ApprovedBy != nil {
			body.ApprovedBy = names[*row.ApprovedBy]
		}
		if row.ApprovedAt != nil {
			body.ApprovedAt = row.ApprovedAt.Format(time.RFC3339)
		}
		if row.WithdrawnBy != nil {
			body.WithdrawnBy = names[*row.WithdrawnBy]
		}
		if row.WithdrawnAt != nil {
			body.WithdrawnAt = row.WithdrawnAt.Format(time.RFC3339)
		}
		out = append(out, body)
	}
	return out, nil
}

// rulingState names where a ruling stands.
func rulingState(row finding.ReportRuling) string {
	switch {
	case row.WithdrawnAt != nil:
		return "withdrawn"
	case row.SettledAt != nil:
		return "in-force"
	}
	return "waiting"
}

// refusedRuling turns what the store answers about a ruling into what the
// caller sees.
func refusedRuling(in Ingest, err error, what string) error {
	var faults markdown.Faults
	switch {
	case errors.Is(err, finding.ErrNoSuchRuling):
		return huma.Error404NotFound(finding.ErrNoSuchRuling.Error())
	case errors.Is(err, finding.ErrNoSuchReport):
		return huma.Error404NotFound(finding.ErrNoSuchReport.Error())
	case errors.Is(err, finding.ErrNoSuchIssueHere):
		return noSuchFinding()
	case errors.Is(err, finding.ErrOwnRuling):
		return huma.Error409Conflict(finding.ErrOwnRuling.Error())
	case errors.Is(err, finding.ErrAlreadyJudged),
		errors.Is(err, finding.ErrNotWaiting),
		errors.Is(err, finding.ErrWithdrawn):
		return huma.Error409Conflict(err.Error())
	case errors.As(err, &faults):
		return refusedText(faults)
	case errors.Is(err, finding.ErrNotRulable),
		errors.Is(err, finding.ErrNoReports),
		errors.Is(err, finding.ErrNoReasoning),
		errors.Is(err, finding.ErrNoDuplicateTarget),
		errors.Is(err, finding.ErrNotADuplicate),
		errors.Is(err, finding.ErrDuplicateOfClosed),
		errors.Is(err, finding.ErrTooManyReports):
		return asked(in.Logger, err)
	}
	return refused(in.Logger, err, what)
}
