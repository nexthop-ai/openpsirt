package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// ReportBody is who told us about a flaw, and when.
type ReportBody struct {
	ReportedBy string `json:"reported_by,omitempty"`
	Contact    string `json:"contact,omitempty"`
	Credit     string `json:"credit,omitempty" doc:"The credit they asked for in an advisory"`
	Received   string `json:"received,omitempty" doc:"The day it arrived, which the embargo is counted from"`
	// Acknowledged is when somebody answered them, and by whom. Absent is the
	// state an unacknowledged report is in: prompt acknowledgment is the part
	// of coordinated disclosure a reporter actually judges.
	Acknowledged   string `json:"acknowledged,omitempty"`
	AcknowledgedBy string `json:"acknowledged_by,omitempty"`
	RecordedBy     string `json:"recorded_by"`
}

// registerWhoTold is the record of who told us, and the act of saying we
// answered them.
func registerWhoTold(api huma.API, in Ingest) {
	const path = "/v1/products/{product}/issues/{vulnerability}/report"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-report", Method: http.MethodGet, Path: path,
		Summary: "Show who reported a flaw",
		Description: "Who reported it, how to reach them, when it arrived, when somebody " +
			"answered them, and how they wish to be credited.\n\n" +
			"The received date is what the embargo runs from: a report arriving " +
			"on 1 June and typed in on 15 June otherwise puts our clock two weeks behind the " +
			"one the reporter has a publication scheduled against, and they are the party who " +
			"will publish regardless.\n\n" +
			"Answers 404 where nobody recorded a reporter, which is every flaw we found " +
			"ourselves.",
		Tags: []string{"Findings"},
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
	}) (*struct{ Body ReportBody }, error) {
		subject, _, _, issue, err := caseAtTriaging(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		told, err := finding.NewStore(in.DB.DB).ReportFor(ctx, subject, issue)
		if err != nil {
			return nil, wentWrong(in.Logger, "who told us could not be read", err)
		}
		if told == nil {
			return nil, huma.Error404NotFound("nobody is recorded as having reported this")
		}
		body, err := reportBody(ctx, in, *told)
		if err != nil {
			return nil, wentWrong(in.Logger, "who told us could not be read", err)
		}
		return &struct{ Body ReportBody }{Body: body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "acknowledge-report", Method: http.MethodPost,
		Path:    path + "/acknowledgement",
		Summary: "Record that the reporter was answered",
		Description: "Records that somebody replied to whoever reported this, and when.\n\n" +
			"It records that it happened rather than doing it. What reaches a researcher " +
			"is a mail somebody sends from an address they already have; recording it is what " +
			"turns \"somebody probably replied\" into a date the timeline can be evidenced " +
			"from, and what clears the condition an unanswered report opens.\n\n" +
			"Acknowledging twice keeps the first date: when somebody was answered is a fact " +
			"about the past, and the second person to press it did not change it.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "", triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
	}) (*struct{}, error) {
		subject, _, _, issue, err := caseAtTriaging(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		store := finding.NewStore(in.DB.DB)
		told, err := store.ReportFor(ctx, subject, issue)
		if err != nil {
			return nil, wentWrong(in.Logger, "who told us could not be read", err)
		}
		if told == nil {
			return nil, huma.Error404NotFound("nobody is recorded as having reported this")
		}
		if err := store.Acknowledge(ctx, subject, issue); err != nil {
			return nil, wentWrong(in.Logger, "that could not be recorded", err)
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "add-alias", Method: http.MethodPut,
		Path:    "/v1/products/{product}/issues/{vulnerability}/aliases/{alias}",
		Summary: "Record another name for an issue",
		Description: "Records that this issue is also known by another identifier — a CVE or " +
			"a GHSA assigned after we minted our own.\n\n" +
			"Nothing about the finding, the decisions or the approvals moves, because " +
			"they are keyed on the issue rather than on what it is called. What changes is " +
			"that the name travels with it: a report arriving under the new name resolves " +
			"here rather than opening a second issue, the finding shows it, and the advisory " +
			"carries it in the field a reader looks in — which is the one lookup a published " +
			"advisory exists to serve.\n\n" +
			"A name is identity, and identity is deployment-wide. From here on a scan of " +
			"any product reporting that name resolves to this issue and inherits its " +
			"decisions. So this asks for the right to triage the issue in every product it " +
			"is currently open in, at the visibility each one carries, and is refused rather " +
			"than partly done.\n\n" +
			"Recording a name it already goes by succeeds and changes nothing.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "Also asks for triage in every other product the issue is open in.",
		triageRights()...), func(ctx context.Context, input *struct {
		Product       string `path:"product"`
		Vulnerability string `path:"vulnerability"`
		Alias         string `path:"alias" maxLength:"191" doc:"The other identifier, as it is written"`
	}) (*struct{}, error) {
		subject, _, _, issue, err := caseAtTriaging(ctx, in, input.Product, input.Vulnerability)
		if err != nil {
			return nil, err
		}
		if err := changing(ctx, in.DB, in.logger(), func(ctx context.Context, tx bun.Tx) error {
			// What the issue is filed under, read before the name is added.
			//
			// By the stored name rather than the one typed: a path segment
			// carries no length, and the lookup keeps only the first 191
			// runes of it, so what resolved and what was typed are not the
			// same string. Before, because recording an alias refiles the
			// issue under the more widely recognized of its names — read
			// afterwards, a row would say an issue gained the name it had
			// just been renamed to.
			named, err := finding.NewVulnerabilities(tx).NamesByID(ctx, []int64{issue})
			if err != nil {
				return wentWrong(in.Logger, "that issue could not be looked up", err)
			}
			switch err := finding.NewVulnerabilities(tx).
				AlsoKnownAs(ctx, subject, issue, input.Alias); {
			case errors.Is(err, finding.ErrNameTaken):
				return huma.Error409Conflict(
					"another issue already goes by that name, so this would merge two records")
			case err != nil:
				return asked(in.Logger, err)
			}
			// Recorded deployment-wide, because that is what it is: from here
			// on a scan of any product reporting that name resolves to this
			// issue. The issue it was recorded against is named too, since
			// that is where the right to record it was held.
			if err := noted(ctx, tx, trail.Alias, named[issue],
				nil, trail.Said(input.Alias, true)); err != nil {
				return notRecorded(in.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}

// reportBody names the people a report refers to.
func reportBody(ctx context.Context, in Ingest, told finding.WhoTold) (ReportBody, error) {
	people := []int64{told.RecordedBy}
	if told.AcknowledgedBy != nil {
		people = append(people, *told.AcknowledgedBy)
	}
	names, err := access.NewStore(in.DB.DB).Names(ctx, people)
	if err != nil {
		return ReportBody{}, err
	}
	body := ReportBody{
		ReportedBy: told.ReportedBy, Contact: told.Contact, Credit: told.Credit,
		RecordedBy: names[told.RecordedBy],
	}
	if told.ReceivedOn != nil {
		body.Received = told.ReceivedOn.Format(time.DateOnly)
	}
	if told.AcknowledgedAt != nil {
		body.Acknowledged = told.AcknowledgedAt.Format(time.RFC3339)
	}
	if told.AcknowledgedBy != nil {
		body.AcknowledgedBy = names[*told.AcknowledgedBy]
	}
	return body, nil
}
