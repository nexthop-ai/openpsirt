package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
)

// DisposedBody is one known vulnerability in a build and what was decided
// about it, including nothing.
type DisposedBody struct {
	Vulnerability string        `json:"vulnerability"`
	Severity      string        `json:"severity,omitempty"`
	Component     string        `json:"component"`
	Version       string        `json:"version,omitempty"`
	Place         string        `json:"place" doc:"The place in the build, derived from content. It correlates two rows and names no location — consumer is the readable half"`
	Consumer      string        `json:"consumer,omitempty" doc:"The consumer that pulls the component in. Absent where the build holds it directly"`
	State         string        `json:"state" enum:"undecided,waiting,agreed,lapsed" doc:"The decision state. undecided is the row every other report leaves out and the one an auditor is looking for"`
	Outcome       outcome       `json:"outcome,omitempty"`
	Justification justification `json:"justification,omitempty"`
	ProposedBy    string        `json:"proposed_by,omitempty"`
	ProposedAt    string        `json:"proposed_at,omitempty"`
	ApprovedBy    string        `json:"approved_by,omitempty" doc:"The people who agreed. Two different people is the whole of the control, so both names are carried rather than a count"`
	ApprovedAt    string        `json:"approved_at,omitempty"`
	// AgreementCarried says the agreement was given for an earlier claim and
	// carried onto this one, which is what a re-affirmation stands on. The
	// person named read those words rather than these.
	AgreementCarried bool   `json:"agreement_carried,omitempty" doc:"Whether the agreement was carried forward from an earlier claim rather than given for this one"`
	Opened           string `json:"opened"`
	Closed           string `json:"closed,omitempty"`
	// ClosedBecause is the category it closed under and ClosedNote the
	// sentence whoever closed it typed. A closure a scan performed carries a
	// category and no note, because nobody typed one.
	ClosedBecause closure `json:"closed_because,omitempty" doc:"The reason it closed, in the tool's terms. Only on a closed row"`
	ClosedNote    string  `json:"closed_note,omitempty" doc:"The person's own reason for closing it. Only where a person did"`
	Due           string  `json:"due,omitempty"`
	Met           *bool   `json:"met,omitempty" doc:"Whether the deadline was met. Answerable only for something that closed — an open row has not missed its deadline, it has not reached the end of the question"`
}

// closure is the query-side vocabulary of why a finding closed, taken from the
// store rather than written out again: a closure added there is published here
// and in the generated client, instead of shipping in a body that no document
// describes.
type closure string

// Schema answers with the closures the store knows, in its order.
func (closure) Schema(huma.Registry) *huma.Schema {
	offered := make([]any, 0, len(finding.Closures()))
	for _, each := range finding.Closures() {
		offered = append(offered, string(each))
	}
	return &huma.Schema{Type: huma.TypeString, Enum: offered}
}

// measuredWith reads the chain the register stands on: the upload, the
// inventory in it, and the run that produced the findings.
//
// Nothing here fails the register. A provenance block that could refuse would
// make the report a build has not finished scanning unreadable, which is the
// build somebody is most likely asking about — so what cannot be read is
// absent and says so by being absent.
func measuredWith(ctx context.Context, in Ingest, subject access.Subject,
	targetID int64, product, stream, variant string) *MeasuredBody {

	scan, err := ingest.NewStore(in.DB.DB).Newest(ctx, targetID)
	if err != nil || scan == nil {
		return nil
	}
	measured := &MeasuredBody{
		Scan: scan.ID, ScanHash: scan.ContentHash,
		BuiltAt: scan.BuiltAt.UTC().Format(time.RFC3339),
	}
	if last, err := finding.NewStore(in.DB.DB).LatestRun(ctx, subject, targetID); err == nil &&
		last != nil {
		measured.Run, measured.Scanner = last.ID, last.Scanner
		measured.ScannerVersion, measured.DatabaseVersion =
			last.ScannerVersion, last.DatabaseVersion
		measured.RanHere = last.RanHere
		if last.FinishedAt != nil {
			measured.RanAt = last.FinishedAt.UTC().Format(time.RFC3339)
		}
	}
	// What arrived rather than what is still held, so a build whose contents
	// were let go still names the inventory it was read from.
	sent, err := ingest.NewDocuments(in.DB.DB).Sent(ctx, []int64{scan.ID})
	if err != nil {
		return measured
	}
	for _, document := range sent[scan.ID] {
		if document.Kind != ingest.InventoryKind {
			continue
		}
		held := document.DiscardedAt == nil
		measured.Document, measured.DocumentHash = document.ID, document.ContentHash
		measured.DocumentHeld = &held
		if held {
			measured.DocumentAt = fmt.Sprintf(
				"/v1/products/%s/streams/%s/variants/%s/scans/%d/documents/%d",
				url.PathEscape(product), url.PathEscape(stream), url.PathEscape(variant),
				scan.ID, document.ID)
		}
		break
	}
	return measured
}

// stating is the same facts as a file's header.
func (m *MeasuredBody) stating() []Stated {
	if m == nil {
		return nil
	}
	return []Stated{
		{"scan", strconv.FormatInt(m.Scan, 10)},
		{"inventory hash", m.DocumentHash},
		{"scanner", strings.TrimSpace(m.Scanner + " " + m.ScannerVersion)},
		{"vulnerability data", m.DatabaseVersion},
		{"run", stringOrNone(m.Run)},
		{"measured at", m.RanAt},
	}
}

// stringOrNone writes an identifier nothing answered as nothing rather than as
// a zero, which reads as a row that exists.
func stringOrNone(id int64) string {
	if id == 0 {
		return ""
	}
	return strconv.FormatInt(id, 10)
}

// Registering is the narrowing the register takes, for the screen and for the
// file.
//
// One struct, because they are one question: an export taking a smaller set of
// filters than the screen is a file that quietly answers something else.
//
// An auditor's questions, and nothing that would make this a second findings
// list. A register is asked for the undecided, for the dismissals, for one
// component — each a way of reading the same complete answer rather than a
// different question.
type Registering struct {
	State     []string  `query:"state,explode" enum:"undecided,waiting,agreed,lapsed" doc:"Keep rows standing in any of these. Repeatable; any of them matches"`
	Outcome   []outcome `query:"outcome,explode" doc:"Keep rows whose standing judgment is one of these. Repeatable"`
	Component string    `query:"component" doc:"Keep one component, by name"`
	Issue     string    `query:"issue" doc:"Keep one vulnerability, under the name it is filed here"`
	Standing  string    `query:"standing" enum:"open,closed" doc:"Keep one side of the build's history. Neither is the whole register, which is what it is for"`
}

// narrow is the store's own filter, built from the request.
func (r Registering) narrow() finding.Registering {
	only := finding.Registering{
		Component: r.Component, Issue: r.Issue,
		Open: r.Standing == "open", Closed: r.Standing == "closed",
	}
	for _, word := range r.State {
		if word != "" {
			only.States = append(only.States, word)
		}
	}
	for _, word := range r.Outcome {
		if word != "" {
			only.Outcomes = append(only.Outcomes, string(word))
		}
	}
	return only
}

func registerRegister(api huma.API, in Ingest) {
	const path = "/v1/products/{product}/streams/{stream}/variants/{variant}/register"
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-disposition-register", Method: http.MethodGet, Path: path,
		Summary: "List every known vulnerability in a build and its disposition",
		Description: "One row per issue and place in this build, with its state, what was " +
			"claimed, who claimed it, who agreed, when each of those happened, its deadline " +
			"and whether that was met.\n\n" +
			"The complement of the audit list, not a variant of it. The audit list says " +
			"what was decided; an auditor's first question is what was *known*, decided or " +
			"not — so `undecided` rows are in here, and closed ones too. A register of only " +
			"what is still open answers a different question.\n\n" +
			"Current state, and no `as_of`. Reconstructing the view as of a past date was " +
			"asked for and refused: each row already carries the dates that evidence what is " +
			"being checked, and a reconstruction would be a second answer about the past that " +
			"has to be kept honest against the first.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Registering
		Limit  int `query:"limit" default:"200" minimum:"1" maximum:"500"`
		Offset int `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items    []DisposedBody `json:"items"`
			Total    int            `json:"total"`
			Measured *MeasuredBody  `json:"measured,omitempty" doc:"The tools the register was measured with. Absent where nothing has been uploaded to the build"`
		}
	}, error) {
		subject, target, err := browsing(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		rows, total, err := finding.NewStore(in.DB.DB).Register(ctx, subject, target,
			input.narrow(), input.Limit, input.Offset)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := &struct {
			Body struct {
				Items    []DisposedBody `json:"items"`
				Total    int            `json:"total"`
				Measured *MeasuredBody  `json:"measured,omitempty" doc:"The tools the register was measured with. Absent where nothing has been uploaded to the build"`
			}
		}{}
		out.Body.Total = total
		out.Body.Measured = measuredWith(ctx, in, subject, target,
			input.Product, input.Stream, input.Variant)
		out.Body.Items = make([]DisposedBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, disposedBody(row))
		}
		return out, nil
	})

	// And as a file, because a register is the report most likely to be
	// wanted whole.
	huma.Register(api, requiring(huma.Operation{
		OperationID: "export-disposition-register", Method: http.MethodGet,
		Path:    path + ".{format}",
		Summary: "Export the disposition register",
		Description: "The register as a file. Read with your own visibility as it streams, " +
			"like every other export here.",
		Tags: []string{"Reports"},
	}, anyPerson, "Exports only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Format  string `path:"format" enum:"csv,json"`
		Registering
	}) (*huma.StreamResponse, error) {
		subject, target, err := browsing(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		// No triage line is stated, because none is applied. The register is
		// every place in the build with what stands there, which is what makes
		// it answerable to an auditor — narrowing it by what this deployment
		// considers worth triaging would be the omission the document exists
		// to rule out. A header stating a line has been applied where none
		// has is the more dangerous of the two: a file that claims to have
		// left things out reads as complete about what remains.
		store := finding.NewStore(in.DB.DB)
		// Asked before a byte is written. Once the stream has started the
		// status is gone, so a refusal reaching it there can only be stated in
		// the file, as an export that stopped early with a 200 in front of
		// it.
		if err := store.MayReadRegister(ctx, subject, target); err != nil {
			return nil, refusedFinding(in, err)
		}
		out := Exporting{
			What: "disposition register",
			// The build it is about, and nothing about a triage line: the
			// register applies none, and the comment above says why saying so
			// would be worse than silence.
			About: append([]Stated{
				{"build", input.Product + " " + input.Stream + " (" + input.Variant + ")"},
			}, measuredWith(ctx, in, subject, target,
				input.Product, input.Stream, input.Variant).stating()...),
			Header: []string{
				"issue", "severity", "component", "version", "place", "consumer", "state",
				"outcome", "justification", "proposed by", "proposed at",
				"approved by", "approved at", "agreement carried",
				"opened", "closed", "closed because", "closed note", "due", "met",
			},
			// Streamed rather than paged, and neither counted. A file has no
			// column for how many rows there are altogether, and every page
			// re-sorts the build's quarter of a million rows and skips past
			// the ones already written — 52 minutes for a real build, against
			// 1.9 seconds for one cursor over the same rows in the same order.
			Stream: func(ctx context.Context, each func([]string) error) error {
				return store.RegisterEach(ctx, subject, target, input.narrow(),
					func(row finding.Disposed) error {
						body := disposedBody(row)
						met := ""
						if body.Met != nil {
							met = strconv.FormatBool(*body.Met)
						}
						return each([]string{
							body.Vulnerability, body.Severity, body.Component, body.Version,
							body.Place, body.Consumer, body.State, string(body.Outcome), string(body.Justification),
							body.ProposedBy, body.ProposedAt, body.ApprovedBy, body.ApprovedAt,
							strconv.FormatBool(body.AgreementCarried),
							body.Opened, body.Closed, string(body.ClosedBecause), body.ClosedNote,
							body.Due, met,
						})
					})
			},
		}
		name := "register-" + strings.ToLower(input.Product+"-"+input.Stream+"-"+input.Variant)
		return &huma.StreamResponse{Body: func(writer huma.Context) {
			writeExport(writer, input.Format, name, out)
		}}, nil
	})
}

func disposedBody(row finding.Disposed) DisposedBody {
	body := DisposedBody{
		Vulnerability: row.Vulnerability, Severity: row.Severity,
		Component: row.Component, Version: row.Version, Place: row.Place,
		Consumer: row.Consumer,
		State:    row.State, Outcome: outcome(row.Outcome),
		Justification: justification(row.Justification),
		ProposedBy:    row.ProposedBy, ApprovedBy: row.ApprovedBy,
		AgreementCarried: row.AgreementCarried,
		Opened:           row.OpenedAt.Format(time.DateOnly), Met: row.Met,
	}
	if row.ProposedAt != nil {
		body.ProposedAt = row.ProposedAt.Format(time.DateOnly)
	}
	if row.ApprovedAt != nil {
		body.ApprovedAt = row.ApprovedAt.Format(time.DateOnly)
	}
	if row.ClosedAt != nil {
		body.Closed = row.ClosedAt.Format(time.DateOnly)
		body.ClosedBecause, body.ClosedNote = closure(row.ClosedBecause), row.ClosedNote
	}
	if row.DueAt != nil {
		body.Due = row.DueAt.Format(time.DateOnly)
	}
	return body
}

// RateBody is how much of one severity's work met its deadline.
type RateBody struct {
	Severity string `json:"severity"`
	Closed   int    `json:"closed" doc:"The number of issue-and-component groups wholly closed, with a deadline to be judged against"`
	Met      int    `json:"met" doc:"The number of those closed by it. Closed exactly at the deadline met it, because something still open at that instant is not yet overdue"`
	Late     int    `json:"late" doc:"The number that did not"`
	// Deferred is its own number rather than a failure. A rate that
	// counted an approved deferral as one would punish the deliberate act
	// the deferral mechanism exists to make possible, and within a quarter
	// people stop deferring and start letting things run late silently.
	Deferred int `json:"deferred" doc:"Still open with a standing deferral: somebody moved the date deliberately"`
	Overdue  int `json:"overdue" doc:"Still open, past the deadline, with no deferral standing — plainly late"`
	// Open is what the two numbers above are a share of. Without it they are
	// numerators with no denominator, and a rate is a proportion.
	Open int `json:"open" doc:"Still open at all, whatever their deadline. The denominator the deferred and overdue counts are read against"`
}

func registerCompliance(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-compliance-rate", Method: http.MethodGet,
		Path:    "/v1/compliance",
		Summary: "Report what proportion of work met its deadline",
		Description: "By severity: how much closed inside its deadline, how much did not, how " +
			"much is deferred by decision, and how much is plainly late.\n\n" +
			"A deferral is its own number and not a failure, so `deferred` is neither " +
			"met nor late.\n\n" +
			"Counted in the same unit as every other screen: one issue at one component, not " +
			"one row per place. A group is closed when no place is still open, met when none " +
			"of the closed ones was late, deferred when every open place is covered by a " +
			"standing deferral, and overdue when anything open is past its date and " +
			"uncovered.\n\n" +
			"A closed finding keeps the deadline it carried; only open ones lose theirs at " +
			"end of life or below the triage line.\n\n" +
			"A product is required — a place identity carries no product, so this cannot " +
			"be asked across the deployment.\n\n" +
			"A period, or the whole of it. `from` and `to` bound what closed in them, " +
			"which is the number a report on a quarter or a financial year is about; `days` " +
			"is the rolling window, and only one of the two may be sent. Asked for neither, " +
			"this is the lifetime figure.\n\n" +
			"What is open is always now. Deadlines are recomputed as the policy moves and " +
			"dropped below the line and past end of life, so what stood open on a date gone " +
			"by is not recoverable and is not reconstructed.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Period
	}) (*overPeriod[RateBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		scope, err := scoped(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		// Asked for here rather than left to the store. A selection with no
		// product is allowed by the scope helper — most lists here answer
		// across every product somebody may see — and this one cannot, for the
		// reason its description gives. Stated by the store as a plain error
		// nothing recognizes, it falls through to the generic answer for a
		// write that broke: a caller who left out a parameter is told the
		// server has failed, on a read-only endpoint, in a sentence about
		// something not being recorded.
		if scope.ProductID == nil {
			return nil, huma.Error422UnprocessableEntity(
				"name a product: a rate has to be about one, because a place " +
					"identity carries no product and correlating decisions without " +
					"one would reach every product in the deployment")
		}
		// Nothing by default, which is the lifetime figure this has always
		// answered. A default window would quietly change what the number
		// means for everybody already reading it.
		since, until, err := input.window(0, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		rates, err := finding.NewStore(in.DB.DB).Compliance(ctx, subject, scope, since, until)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := &overPeriod[RateBody]{}
		// Said back, like every other report over a stretch of time. Asked for
		// no period this is the lifetime figure, and both sides are then empty
		// — which is the honest answer rather than two invented dates.
		out.Body.From, out.Body.To = stating(since, until)
		out.Body.Items = make([]RateBody, 0, len(rates))
		for _, rate := range rates {
			out.Body.Items = append(out.Body.Items, RateBody{
				Severity: rate.Severity, Closed: rate.Closed, Met: rate.Met,
				Late: rate.Late, Deferred: rate.Deferred, Overdue: rate.Overdue,
				Open: rate.Open,
			})
		}
		return out, nil
	})
}
