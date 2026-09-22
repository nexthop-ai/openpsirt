package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// ClaimedBody is a claim somebody sends us, as it is recorded.
type ClaimedBody struct {
	Summary    string `json:"summary" maxLength:"65536" doc:"What was claimed, in the words it was claimed in"`
	ReportedBy string `json:"reported_by,omitempty" maxLength:"191"`
	Contact    string `json:"contact,omitempty" maxLength:"191"`
	Credit     string `json:"credit,omitempty" maxLength:"191" doc:"The credit they asked for in an advisory"`
	Received   string `json:"received,omitempty" doc:"The day it arrived, as YYYY-MM-DD, which the embargo is counted from"`
}

// ReportIssueBody says what a report turned out to be.
type ReportIssueBody struct {
	Vulnerability string `json:"vulnerability" maxLength:"191" doc:"The issue it turned out to be, under any identifier it goes by"`
}

// registerIntake is the record of what arrived, what it turned out to be,
// and the act of saying the reporter was answered.
func registerIntake(api huma.API, in Ingest) {
	const list = "/v1/products/{product}/reports"
	const one = list + "/{reference}"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "record-report", Method: http.MethodPost, Path: list,
		Summary: "Record a report",
		Description: "Records a claim that arrived, and returns the reference it is reached " +
			"by.\n\n" +
			"No issue is minted. What arrived is a claim, and whether it is a flaw is a " +
			"judgment somebody makes afterwards — so a report nobody believes is answered and " +
			"filed rather than either minting a flaw nobody believes or going unrecorded.\n\n" +
			"`summary` is required and everything else is optional: a claim arriving " +
			"anonymously is an ordinary claim, and a report with nothing in it records only " +
			"that a mail arrived. The summary is stored as markdown and goes through the " +
			"same submission policy a justification does, so raw HTML and link schemes " +
			"outside http, https and mailto are refused naming the line they are on.\n\n" +
			"`received` is the day it arrived, which is what an embargo would be counted " +
			"from. A date that cannot be read is treated as one nobody gave.",
		Tags: []string{"Findings"},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Body    ClaimedBody
	}) (*struct {
		Status int
		Body   ReportBody
	}, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		row, err := finding.NewStore(in.DB.DB).Record(ctx, subject, product.ID, finding.Claimed{
			Summary: input.Body.Summary,
			Told: finding.Told{
				ReportedBy: input.Body.ReportedBy, Contact: input.Body.Contact,
				Credit: input.Body.Credit, Received: input.Body.Received,
			},
		})
		if err != nil {
			return nil, refusedReport(in, err, "that report could not be recorded")
		}
		body, err := reportBody(ctx, in, *row)
		if err != nil {
			return nil, wentWrong(in.Logger, "that report could not be read back", err)
		}
		return &struct {
			Status int
			Body   ReportBody
		}{Status: http.StatusCreated, Body: body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-reports", Method: http.MethodGet, Path: list,
		Summary: "List what was reported",
		Description: "Every claim recorded against this product, newest first, judged or " +
			"not.\n\n" +
			"A report already turned into an issue stays in the list, because it is the " +
			"evidence that the issue came from outside.",
		Tags: []string{"Findings"},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Limit   int    `query:"limit" minimum:"1" maximum:"200" default:"50"`
		Offset  int    `query:"offset" minimum:"0" default:"0"`
	}) (*listOutput[ReportBody], error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		rows, total, err := finding.NewStore(in.DB.DB).ReportsIn(ctx, subject,
			product.ID, input.Limit, input.Offset)
		if err != nil {
			return nil, refusedReport(in, err, "the reports could not be read")
		}
		out := &listOutput[ReportBody]{}
		out.Body.Items, err = reportBodies(ctx, in, rows)
		if err != nil {
			return nil, wentWrong(in.Logger, "the reports could not be read", err)
		}
		out.Body.Total = total
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-recorded-report", Method: http.MethodGet, Path: one,
		Summary: "Show a report",
		Description: "What was claimed, who claimed it, when it arrived, when somebody " +
			"answered them, and what it turned out to be.\n\n" +
			"A reference nobody minted and one recorded against another product answer " +
			"alike, so asking is not a way to find out which references exist.",
		Tags: []string{"Findings"},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"191" doc:"The reference this deployment minted"`
	}) (*struct{ Body ReportBody }, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		row, err := finding.NewStore(in.DB.DB).ReportBy(ctx, subject, product.ID, input.Reference)
		if err != nil {
			return nil, refusedReport(in, err, "that report could not be read")
		}
		body, err := reportBody(ctx, in, *row)
		if err != nil {
			return nil, wentWrong(in.Logger, "that report could not be read", err)
		}
		return &struct{ Body ReportBody }{Body: body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "acknowledge-recorded-report", Method: http.MethodPost,
		Path:    one + "/acknowledgement",
		Summary: "Record that a reporter was answered",
		Description: "Records that somebody replied to whoever sent this, and when.\n\n" +
			"It records that it happened rather than doing it. What reaches a researcher " +
			"is a mail somebody sends from an address they already have; recording it is " +
			"what turns \"somebody probably replied\" into a date the timeline can be " +
			"evidenced from, and what clears the condition an unanswered report opens.\n\n" +
			"Acknowledging twice keeps the first date: when somebody was answered is a fact " +
			"about the past, and the second person to press it did not change it.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"191"`
	}) (*struct{}, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		if err := finding.NewStore(in.DB.DB).AcknowledgeReport(ctx, subject,
			product.ID, input.Reference); err != nil {
			return nil, refusedReport(in, err, "that could not be recorded")
		}
		return &struct{}{}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "judge-report", Method: http.MethodPut, Path: one + "/issue",
		Summary: "Record what a report turned out to be",
		Description: "Points a report at the issue it turned out to be, and records who said " +
			"so and when.\n\n" +
			"The issue is one that already exists here. Recording a flaw is its own act, " +
			"because it carries the builds the flaw ships in, the severity and the embargo — " +
			"so agreeing that a claim is real is not the same keystroke as declaring where it " +
			"lives.\n\n" +
			"Refused where the report has already been judged, and where another report is " +
			"already the record of that issue: one report is one issue's record, and a second " +
			"pointed at the same issue is a duplicate rather than this.\n\n" +
			"An issue this product does not hold, and one you may not be told of, answer " +
			"alike — otherwise this route says which identifiers are open here.",
		Tags: []string{"Findings"},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"191"`
		Body      ReportIssueBody
	}) (*struct{ Body ReportBody }, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		issue, err := issueHere(ctx, in, subject, product.ID, input.Body.Vulnerability)
		if err != nil {
			return nil, huma.Error404NotFound(finding.ErrNoSuchIssueHere.Error())
		}
		row, err := finding.NewStore(in.DB.DB).JudgeAsIssue(ctx, subject,
			product.ID, input.Reference, issue)
		if err != nil {
			return nil, refusedReport(in, err, "that report could not be judged")
		}
		body, err := reportBody(ctx, in, *row)
		if err != nil {
			return nil, wentWrong(in.Logger, "that report could not be read back", err)
		}
		return &struct{ Body ReportBody }{Body: body}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "upload-report-attachment", Method: http.MethodPost,
		Path:    one + "/attachments",
		Summary: "Attach a file to a report",
		Description: "Stores one file against a report and returns the reference to put in " +
			"text. A claim that has not been judged has no issue to hang a screenshot on, and " +
			"the screenshot is often the whole of what was sent.\n\n" +
			"The file stays with the report once the report gains an issue. What was sent is " +
			"a fact about the report, and moving it would lose which of two reports it came " +
			"in.\n\n" +
			"The content type is decided here from the bytes and is never the one that was " +
			"uploaded. Everything outside a small allowlist of raster images is served as an " +
			"attachment download whatever it is.\n\n" +
			"Refused when the file is larger than this deployment accepts, when it has no " +
			"room left, or when it would take you past your own share of the store; all " +
			"three limits are settings.\n\n" +
			"Send `evidence=true` where the file arrived with the report rather than " +
			"hanging off text you are about to write: it is then listed at once and never " +
			"swept.",
		Tags:        []string{"Findings"},
		Middlewares: huma.Middlewares{boundedForm(api, maxAttachmentRequest)},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"191"`
		RawBody   huma.MultipartFormFiles[attachmentParts]
	}) (*struct {
		Status int
		Body   AttachmentBody
	}, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		files := in.attachments()
		if files == nil || !files.Configured() {
			return nil, huma.Error501NotImplemented(attach.ErrNotConfigured.Error())
		}
		row, err := finding.NewStore(in.DB.DB).ReportBy(ctx, subject, product.ID, input.Reference)
		if err != nil {
			return nil, refusedReport(in, err, "that report could not be read")
		}
		maxSize, quota, share, err := attachmentLimits(ctx, in)
		if err != nil {
			return nil, wentWrong(in.Logger, "cannot tell what this deployment accepts", err)
		}
		part := input.RawBody.Data().File
		stored, err := files.Upload(ctx, subject,
			attach.Against{ProductID: product.ID, FlawReportID: row.ID},
			part.Filename, part, part.Size, maxSize, quota, share,
			input.RawBody.Data().Evidence)
		switch {
		case errors.Is(err, attach.ErrTooLarge):
			return nil, huma.Error413RequestEntityTooLarge(fmt.Sprintf(
				"that file is %d bytes and this deployment accepts %d", part.Size, maxSize))
		case errors.Is(err, attach.ErrNoRoom):
			return nil, huma.Error507InsufficientStorage(attach.ErrNoRoom.Error())
		case err != nil:
			return nil, refused(in.Logger, err, "cannot store that file")
		}
		return &struct {
			Status int
			Body   AttachmentBody
		}{Status: http.StatusCreated, Body: attachmentBody(stored)}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-report-attachments", Method: http.MethodGet,
		Path:    one + "/attachments",
		Summary: "List files that arrived with a report",
		Description: "What arrived with this report, and what text about it refers to. An " +
			"upload nothing refers to yet is not listed, because it is not attached to " +
			"anything.\n\n" +
			"A file an administrator removed is still listed, saying so, because the text " +
			"that pointed at it still does.",
		Tags: []string{"Findings"},
	}, perProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"191"`
	}) (*struct {
		Body struct {
			Items []AttachmentBody `json:"items"`
		}
	}, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		files := in.attachments()
		if files == nil {
			return nil, noDatabase(in.Logger)
		}
		row, err := finding.NewStore(in.DB.DB).ReportBy(ctx, subject, product.ID, input.Reference)
		if err != nil {
			return nil, refusedReport(in, err, "that report could not be read")
		}
		rows, err := files.ForReport(ctx, subject, product.ID, row.ID)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read what is attached")
		}
		out := &struct {
			Body struct {
				Items []AttachmentBody `json:"items"`
			}
		}{}
		out.Body.Items = make([]AttachmentBody, 0, len(rows))
		for i := range rows {
			out.Body.Items = append(out.Body.Items, attachmentBody(&rows[i]))
		}
		return out, nil
	})
}

// productForReports resolves the product a report route names.
//
// The narrower of the two product rules: a report is about the product as a
// whole rather than about one named issue, so somebody brought into a single
// case reaches nothing here. Resolved before any reference in the request is,
// so a refusal says nothing about which references exist.
func productForReports(ctx context.Context, in Ingest, name string) (
	access.Subject, *catalog.Product, error) {

	subject, err := reading(ctx)
	if err != nil {
		return access.Subject{}, nil, err
	}
	if in.DB == nil {
		return access.Subject{}, nil, noDatabase(in.Logger)
	}
	product, err := productNamedVisibly(ctx, in, subject, name)
	if err != nil {
		return access.Subject{}, nil, err
	}
	return subject, product, nil
}

// refusedReport turns what the store answers into what the caller sees.
//
// A reference that is not here is a 404 and nothing else: the store gives the
// same answer for one nobody minted, one recorded against another product and
// one the subject may not read, and telling them apart here would undo that.
func refusedReport(in Ingest, err error, what string) error {
	var faults markdown.Faults
	switch {
	case errors.Is(err, finding.ErrNoSuchReport):
		return huma.Error404NotFound(finding.ErrNoSuchReport.Error())
	case errors.As(err, &faults):
		return refusedText(faults)
	case errors.Is(err, finding.ErrNothingClaimed),
		errors.Is(err, finding.ErrAlreadyJudged),
		errors.Is(err, finding.ErrIssueReported):
		return asked(in.Logger, err)
	}
	return refused(in.Logger, err, what)
}
