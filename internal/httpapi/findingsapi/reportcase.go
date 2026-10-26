// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package findingsapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// ReportEditBody is what a report says after an edit.
type ReportEditBody struct {
	Title      string `json:"title,omitempty" maxLength:"191" doc:"A line naming the claim. Empty clears it"`
	Summary    string `json:"summary" maxLength:"65536" doc:"What was claimed, as markdown. Required"`
	ReportedBy string `json:"reported_by,omitempty" maxLength:"191" doc:"The reporter, as they gave their name. Empty clears it"`
	Contact    string `json:"contact,omitempty" maxLength:"191" doc:"The address to reach them at. Empty clears it"`
	Credit     string `json:"credit,omitempty" maxLength:"191" doc:"The credit they asked for in an advisory"`
	Received   string `json:"received,omitempty" doc:"The day it arrived, as YYYY-MM-DD. Empty clears it"`
}

// ReportRevisionBody is what a report said before one edit replaced it.
type ReportRevisionBody struct {
	Version        int    `json:"version" doc:"The version number, counting from one. Version one is the report as it was recorded"`
	Title          string `json:"title,omitempty" doc:"The line naming the claim"`
	Summary        string `json:"summary,omitempty" doc:"What was claimed, as markdown"`
	ReportedBy     string `json:"reported_by,omitempty" doc:"The reporter, as they gave their name"`
	Contact        string `json:"contact,omitempty" doc:"The address to reach them at"`
	Credit         string `json:"credit,omitempty" doc:"The credit they asked for in an advisory"`
	Received       string `json:"received,omitempty" doc:"The day it arrived, as YYYY-MM-DD"`
	ReplacedBy     string `json:"replaced_by" doc:"The person whose edit replaced it, by sign-in identity"`
	ReplacedByName string `json:"replaced_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	ReplacedAt     string `json:"replaced_at" doc:"The moment it stopped saying that"`
}

// MessageDirection is which way a message went.
type MessageDirection string

// Schema lists the two directions.
func (MessageDirection) Schema(huma.Registry) *huma.Schema {
	directions := finding.Directions()
	enum := make([]any, 0, len(directions))
	for _, d := range directions {
		enum = append(enum, string(d))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: enum}
}

// MessageLogBody is a message somebody records.
type MessageLogBody struct {
	Direction MessageDirection `json:"direction" doc:"Whether it was sent to the reporter or received from them"`
	Dated     string           `json:"dated,omitempty" doc:"The day it was sent or received, as YYYY-MM-DD. Empty is today"`
	Body      string           `json:"body" maxLength:"65536" doc:"The message, pasted or summarized, as markdown. A file that came with it is attached to the report and referred to here"`
}

// MessageBody is one message in a report's correspondence.
type MessageBody struct {
	ID           int64            `json:"id"`
	Direction    MessageDirection `json:"direction"`
	Dated        string           `json:"dated" doc:"The day it was sent or received"`
	Body         string           `json:"body,omitempty" doc:"The message, as markdown. Absent on a message an upgrade carried over from an acknowledgement, which holds no text"`
	LoggedBy     string           `json:"logged_by" doc:"The person who recorded it, by sign-in identity"`
	LoggedByName string           `json:"logged_by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	LoggedAt     string           `json:"logged_at" doc:"When it was recorded"`
}

// ReportEventBody is one act in a report's history.
type ReportEventBody struct {
	At          string           `json:"at"`
	Act         ReportActName    `json:"act"`
	By          string           `json:"by,omitempty" doc:"The person who did it, by sign-in identity. Absent where a standing rule placed it, or an administrator's hand-over moved it"`
	ByName      string           `json:"by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	To          string           `json:"to,omitempty" doc:"Who it went to, on an assignment: a person by sign-in identity, or a team by name"`
	ToName      string           `json:"to_name,omitempty" doc:"Their display name, where it differs from the name above"`
	ToTeam      bool             `json:"to_team,omitempty" doc:"Whether it went to a team's queue"`
	Rule        int64            `json:"rule,omitempty" doc:"The standing rule that placed it"`
	Version     int              `json:"version,omitempty" doc:"The version an edit replaced, or a note's earlier version"`
	Note        int64            `json:"note,omitempty" doc:"The note written or changed"`
	Dated       string           `json:"dated,omitempty" doc:"The day a message carries"`
	Ruling      int64            `json:"ruling,omitempty"`
	Disposition core.Disposition `json:"disposition,omitempty"`
	Issue       string           `json:"issue,omitempty" doc:"The issue it was accepted as"`
	Filename    string           `json:"filename,omitempty" doc:"The file attached"`
}

// ReportActName is one kind of act in a report's history.
type ReportActName string

// Schema lists every act.
func (ReportActName) Schema(huma.Registry) *huma.Schema {
	acts := finding.ReportActs()
	enum := make([]any, 0, len(acts))
	for _, a := range acts {
		enum = append(enum, string(a))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: enum}
}

// registerReportCase is a report worked as a case: editing what it says, its
// correspondence, its notes and its history.
func registerReportCase(api huma.API, in core.Deps) {
	const one = "/v1/products/{product}/reports/{reference}"

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "edit-report", Method: http.MethodPut, Path: one,
		Summary: "Edit a vulnerability report",
		Description: "Replaces the title, the claim and what is recorded about the reporter. " +
			"Every field is the whole new value, and one left empty is cleared, apart from " +
			"`summary`, which is required.\n\n" +
			"What it said before is kept, and read back from its revisions, the original " +
			"first. An edit that changes nothing keeps nothing.\n\n" +
			"Refused with 422 once the report has been judged, or while a ruling over it " +
			"waits for a second person. A `received` day that cannot be read is refused " +
			"rather than cleared.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
		Body      ReportEditBody
	}) (*struct{ Body ReportBody }, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		row, err := finding.NewStore(in.DB.DB).Revise(ctx, subject, product.ID, input.Reference,
			finding.Rewritten{
				Title: input.Body.Title, Summary: input.Body.Summary,
				ReportedBy: input.Body.ReportedBy, Contact: input.Body.Contact,
				Credit: input.Body.Credit, Received: input.Body.Received,
			})
		if err != nil {
			return nil, refusedReport(in, err, "that report could not be changed")
		}
		body, err := reportBody(ctx, in, *row)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "that report could not be read back", err)
		}
		return &struct{ Body ReportBody }{Body: body}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-report-revisions", Method: http.MethodGet, Path: one + "/revisions",
		Summary: "List earlier versions of a vulnerability report",
		Description: "Every version of the report an edit replaced, oldest first. The first " +
			"is the report as it was recorded. A report never edited answers an empty list, " +
			"and the report itself is then the original.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "", core.PrivateRights()...), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
	}) (*core.ListOutput[ReportRevisionBody], error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		rows, err := finding.NewStore(in.DB.DB).Revisions(ctx, subject, product.ID, input.Reference)
		if err != nil {
			return nil, refusedReport(in, err, "that report could not be read")
		}
		people := make([]int64, 0, len(rows))
		for _, row := range rows {
			people = append(people, row.ReplacedBy)
		}
		who, err := core.WhoSigned(ctx, in.DB.DB, people)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "that report could not be read", err)
		}
		out := &core.ListOutput[ReportRevisionBody]{}
		out.Body.Items = make([]ReportRevisionBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, ReportRevisionBody{
				Version: row.Ordinal, Title: row.Title, Summary: row.Summary,
				ReportedBy: row.ReportedBy, Contact: row.Contact, Credit: row.Credit,
				Received:   core.DayOf(row.ReceivedOn),
				ReplacedBy: who.Identity(row.ReplacedBy), ReplacedByName: who.Label(row.ReplacedBy),
				ReplacedAt: core.Stamp(row.ReplacedAt),
			})
		}
		out.Body.Total = len(rows)
		return out, nil
	})

	registerReportMessages(api, in, one)
	registerReportNotes(api, in, one)

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-report-history", Method: http.MethodGet, Path: one + "/history",
		Summary: "List what was done to a vulnerability report",
		Description: "Every act on the report, oldest first: recording it, each edit, each " +
			"note and change to one, each message logged, each change of holder, each " +
			"ruling proposed, settled or withdrawn, its acceptance as an issue, and each " +
			"file attached.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "", core.PrivateRights()...), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
	}) (*core.ListOutput[ReportEventBody], error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		events, err := finding.NewStore(in.DB.DB).ReportHistory(ctx, subject, product.ID, input.Reference)
		if err != nil {
			return nil, refusedReport(in, err, "that report's history could not be read")
		}
		var people, parties, issues []int64
		for _, e := range events {
			if e.By != nil {
				people = append(people, *e.By)
			}
			if e.Party != nil {
				parties = append(parties, *e.Party)
			}
			if e.VulnerabilityID != 0 {
				issues = append(issues, e.VulnerabilityID)
			}
		}
		who, err := core.WhoSigned(ctx, in.DB.DB, people)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "that report's history could not be read", err)
		}
		held, err := access.NewStore(in.DB.DB).WhoHolds(ctx, parties)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "that report's history could not be read", err)
		}
		named, err := finding.NewVulnerabilities(in.DB.DB).NamesByID(ctx, issues)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "that report's history could not be read", err)
		}
		out := &core.ListOutput[ReportEventBody]{}
		out.Body.Items = make([]ReportEventBody, 0, len(events))
		for _, e := range events {
			item := ReportEventBody{
				At: core.Stamp(e.At), Act: ReportActName(e.Act), Version: e.Ordinal,
				Note: e.NoteID, Dated: core.DayOf(e.Dated), Ruling: e.RulingID,
				Disposition: core.Disposition(e.Disposition), Filename: e.Filename,
			}
			if e.By != nil {
				item.By, item.ByName = who.Identity(*e.By), who.Label(*e.By)
			}
			if e.Party != nil {
				if h, ok := held[*e.Party]; ok {
					item.To, item.ToName = h.Address, core.LabelBeside(h.Name, h.Address)
					item.ToTeam = h.Team
				}
			}
			if e.RuleID != nil {
				item.Rule = *e.RuleID
			}
			if e.VulnerabilityID != 0 {
				item.Issue = named[e.VulnerabilityID]
			}
			out.Body.Items = append(out.Body.Items, item)
		}
		out.Body.Total = len(events)
		return out, nil
	})
}

// registerReportMessages is a report's correspondence: the messages exchanged
// with whoever sent it, as somebody here recorded them.
func registerReportMessages(api huma.API, in core.Deps, one string) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-report-messages", Method: http.MethodGet, Path: one + "/messages",
		Summary: "List the correspondence on a vulnerability report",
		Description: "Every message recorded as sent to or received from the reporter, in " +
			"order of the day each carries. The first sent is the acknowledgement.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "", core.PrivateRights()...), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
	}) (*core.ListOutput[MessageBody], error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		rows, err := finding.NewStore(in.DB.DB).Messages(ctx, subject, product.ID, input.Reference)
		if err != nil {
			return nil, refusedReport(in, err, "the correspondence could not be read")
		}
		people := make([]int64, 0, len(rows))
		for _, row := range rows {
			people = append(people, row.LoggedBy)
		}
		who, err := core.WhoSigned(ctx, in.DB.DB, people)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "the correspondence could not be read", err)
		}
		out := &core.ListOutput[MessageBody]{}
		out.Body.Items = make([]MessageBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, messageBody(row, who.Identity(row.LoggedBy),
				who.Label(row.LoggedBy)))
		}
		out.Body.Total = len(rows)
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "log-report-message", Method: http.MethodPost, Path: one + "/messages",
		Summary: "Record a message to or from a reporter",
		Description: "Records a message somebody sent to the reporter or received from them, " +
			"elsewhere. Nothing is sent from this deployment.\n\n" +
			"The first message recorded as sent is the acknowledgement: it clears the " +
			"condition an unanswered report opens, and its day is the one the timeline " +
			"evidences.\n\n" +
			"Recorded on a judged report as on an open one. Refused on a flaw found here, " +
			"which has no reporter, and for a day more than one ahead of today.\n\n" +
			"The message is told to the report's audience: whoever holds it, the members of " +
			"the team whose queue it is in who read reports, or everybody who works reports " +
			"here where nobody holds it. Whoever records it is not told.\n\n" +
			"The text is markdown and goes through the policy a report's claim does; a 422 " +
			"names the line and the offending text. Attach a file that came with it to the " +
			"report and refer to it here.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
		Body      MessageLogBody
	}) (*struct{ Body MessageBody }, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		message, row, err := finding.NewStore(in.DB.DB).LogMessage(ctx, subject, product.ID,
			input.Reference, finding.Logged{
				Direction: finding.Direction(input.Body.Direction),
				Dated:     input.Body.Dated, Body: input.Body.Body,
			})
		if err != nil {
			return nil, refusedReport(in, err, "that message could not be recorded")
		}
		told := notify.ReportSent
		if message.Direction == finding.Received {
			told = notify.ReportMessage
		}
		if err := notify.TellReport(ctx, in.DB.DB, notify.ReportAct{
			Kind: told, ProductID: row.ProductID, Product: product.Name, Reference: row.Reference,
			AssignedTo: row.AssignedTo, By: subject.ID,
		}); err != nil {
			in.Log().ErrorContext(ctx, "could not say that a message was recorded", "error", err)
		}
		return &struct{ Body MessageBody }{Body: messageBody(*message, subject.Identity, "")}, nil
	})
}

// messageBody is one message as the API states it.
func messageBody(row finding.ReportMessage, by, name string) MessageBody {
	return MessageBody{
		ID: row.ID, Direction: MessageDirection(row.Direction),
		Dated: row.Dated.UTC().Format(time.DateOnly), Body: row.Body,
		LoggedBy: by, LoggedByName: name, LoggedAt: core.Stamp(row.LoggedAt),
	}
}

// registerReportNotes is the notes people here write on a report, and their
// earlier revisions.
func registerReportNotes(api huma.API, in core.Deps, one string) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-report-notes", Method: http.MethodGet, Path: one + "/notes",
		Summary: "List notes on a vulnerability report",
		Description: "The notes written on this report, oldest first, with who wrote each and " +
			"when. A note is never sent to the reporter and records no judgment.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "", core.PrivateRights()...), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
	}) (*core.ListOutput[core.WrittenBody], error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		notes, err := finding.NewStore(in.DB.DB).ReportNotes(ctx, subject, product.ID, input.Reference)
		if err != nil {
			return nil, refusedReport(in, err, "the notes could not be read")
		}
		rows := make([]core.Writing, 0, len(notes))
		for _, n := range notes {
			rows = append(rows, core.Writing{ID: n.ID, Body: n.Body, WrittenBy: n.WrittenBy,
				WrittenAt: n.WrittenAt, EditedAt: n.EditedAt})
		}
		out, err := core.Written(ctx, in, rows, "the notes could not be read")
		if err != nil {
			return nil, err
		}
		out.Body.Total = len(rows)
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "note-on-report", Method: http.MethodPost, Path: one + "/notes",
		Summary: "Add a note to a vulnerability report",
		Description: "Adds a markdown note on this report, open or judged. It is never sent " +
			"to the reporter.\n\n" +
			"A name written after an `@` is told, where that person may read this product's " +
			"reports; the response lists the names that reached nobody.\n\n" +
			"The note is told to the report's audience: whoever holds it, the members of the " +
			"team whose queue it is in who read reports, or everybody who works reports here " +
			"where nobody holds it. Neither you nor anybody the note names is told of it " +
			"this way.\n\n" +
			"The text is markdown and is validated before it is stored; a 422 names the line " +
			"and the offending text.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusCreated,
	}, core.PerProduct, "", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
		Body      struct {
			Body string `json:"body" minLength:"1" doc:"The text, in markdown"`
		}
	}) (*struct{ Body NoteWritten }, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		note, row, err := finding.NewStore(in.DB.DB).NoteOnReport(ctx, subject, product.ID,
			input.Reference, input.Body.Body)
		if err != nil {
			return nil, refusedReport(in, err, "that note could not be recorded")
		}
		out := &struct{ Body NoteWritten }{}
		out.Body.ID = note.ID
		out.Body.NotNotified = tellReportNamed(ctx, in, subject, *row, product.Name, note.Body)
		named, err := reportReadersNamed(ctx, in, subject, row.ProductID, note.Body)
		if err != nil {
			in.Log().WarnContext(ctx, "could not read who a note named", "error", err)
		}
		if err := notify.TellReport(ctx, in.DB.DB, notify.ReportAct{
			Kind: notify.ReportNoted, ProductID: row.ProductID, Product: product.Name,
			Reference: row.Reference, AssignedTo: row.AssignedTo, By: subject.ID, Named: named,
		}); err != nil {
			in.Log().ErrorContext(ctx, "could not say that a note was written", "error", err)
		}
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "edit-report-note", Method: http.MethodPut, Path: one + "/notes/{note}",
		Summary: "Edit a note on a vulnerability report",
		Description: "Replaces the text of a note. Only its author may do this.\n\n" +
			"What it said before is kept, and read back from the note's history.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "Only the author may edit a note.", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
		Note      int64  `path:"note"`
		Body      struct {
			Body string `json:"body" minLength:"1" doc:"The replacement text, in markdown"`
		}
	}) (*struct{ Body NoteWritten }, error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		note, row, err := finding.NewStore(in.DB.DB).RewordReportNote(ctx, subject, product.ID,
			input.Reference, input.Note, input.Body.Body)
		if err != nil {
			return nil, refusedReport(in, err, "that note could not be changed")
		}
		out := &struct{ Body NoteWritten }{}
		out.Body.ID = note.ID
		out.Body.NotNotified = tellReportNamed(ctx, in, subject, *row, product.Name, note.Body)
		return out, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "get-report-note-history", Method: http.MethodGet,
		Path:    one + "/notes/{note}/history",
		Summary: "List earlier revisions of a note on a vulnerability report",
		Description: "Every version of a note that has been replaced, oldest first. The note " +
			"itself carries what it says now.",
		Tags: []string{"Findings"},
	}, core.PerProduct, "", core.PrivateRights()...), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
		Note      int64  `path:"note"`
	}) (*core.ListOutput[core.WasSaidBody], error) {
		subject, product, err := productForReports(ctx, in, input.Product)
		if err != nil {
			return nil, err
		}
		rows, err := finding.NewStore(in.DB.DB).EarlierReportNote(ctx, subject, product.ID,
			input.Reference, input.Note)
		if err != nil {
			return nil, refusedReport(in, err, "that note could not be read")
		}
		out := &core.ListOutput[core.WasSaidBody]{}
		out.Body.Items = make([]core.WasSaidBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, core.WasSaidBody{
				Version: row.Ordinal, Body: row.Body, ReplacedAt: core.Stamp(row.ReplacedAt),
			})
		}
		out.Body.Total = len(rows)
		return out, nil
	})
}

// tellReportNamed tells whoever a note on a report named, where they read the
// product's reports. Failing to tell somebody never fails the write.
func tellReportNamed(ctx context.Context, in core.Deps, subject access.Subject,
	row finding.FlawReport, product, body string) []string {

	if len(markdown.Mentions(body)) == 0 {
		return nil
	}
	dropped, err := core.Mentioned(ctx, in, subject, core.MentionTarget{
		ProductID: row.ProductID, Visibility: access.Private, About: row.Reference,
	}, body, weblink.InboxReport(product, row.Reference))
	if err != nil {
		in.Log().WarnContext(ctx, "could not tell who was named", "error", err)
	}
	return dropped
}

// reportReadersNamed is everybody a note on a report names who may read the
// product's reports: those the mention reaches.
func reportReadersNamed(ctx context.Context, in core.Deps, subject access.Subject,
	productID int64, body string) ([]int64, error) {

	names := markdown.Mentions(body)
	if len(names) == 0 {
		return nil, nil
	}
	readers, err := access.NewStore(in.DB.DB).ReadersNamed(ctx, subject, productID, access.Private, names)
	if err != nil {
		return nil, err
	}
	out := make([]int64, 0, len(readers))
	for _, reader := range readers {
		out = append(out, reader.ID)
	}
	return out, nil
}
