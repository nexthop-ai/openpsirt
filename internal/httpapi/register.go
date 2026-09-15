package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// DisposedBody is one known vulnerability in a build and what was decided
// about it, including nothing.
type DisposedBody struct {
	Vulnerability string        `json:"vulnerability"`
	Severity      string        `json:"severity,omitempty"`
	Component     string        `json:"component"`
	Version       string        `json:"version,omitempty"`
	Place         string        `json:"place" doc:"Which place in the build, derived from content. It correlates two rows and names no location — consumer is the readable half"`
	Consumer      string        `json:"consumer,omitempty" doc:"What pulls the component in. Absent where the build holds it directly"`
	State         string        `json:"state" enum:"undecided,waiting,agreed,lapsed" doc:"Where this stands. undecided is the row every other report leaves out and the one an auditor is looking for"`
	Outcome       outcome       `json:"outcome,omitempty"`
	Justification justification `json:"justification,omitempty"`
	ProposedBy    string        `json:"proposed_by,omitempty"`
	ProposedAt    string        `json:"proposed_at,omitempty"`
	ApprovedBy    string        `json:"approved_by,omitempty" doc:"Who agreed. Two different people is the whole of the control, so both names are carried rather than a count"`
	ApprovedAt    string        `json:"approved_at,omitempty"`
	// AgreementCarried says the agreement was given for an earlier claim and
	// carried onto this one, which is what a re-affirmation stands on. The
	// person named read those words rather than these.
	AgreementCarried bool   `json:"agreement_carried,omitempty" doc:"Whether the agreement was carried forward from an earlier claim rather than given for this one"`
	Opened           string `json:"opened"`
	Closed           string `json:"closed,omitempty"`
	Due              string `json:"due,omitempty"`
	Met              *bool  `json:"met,omitempty" doc:"Whether the deadline was met. Answerable only for something that closed — an open row has not missed its deadline, it has not reached the end of the question"`
}

func registerRegister(api huma.API, in Ingest) {
	const path = "/v1/products/{product}/streams/{stream}/variants/{variant}/register"
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-disposition-register", Method: http.MethodGet, Path: path,
		Summary: "List every known vulnerability in a build and its disposition",
		Description: "One row per issue and place in this build, with its state, what was " +
			"claimed, who claimed it, who agreed, when each of those happened, its deadline " +
			"and whether that was met.\n\n" +
			"**The complement of the audit list, not a variant of it.** The audit list says " +
			"what was decided; an auditor's first question is what was *known*, decided or " +
			"not — so `undecided` rows are in here, and closed ones too. A register of only " +
			"what is still open answers a different question.\n\n" +
			"**Current state, and no `as_of`.** Reconstructing the view as of a past date was " +
			"asked for and refused: each row already carries the dates that evidence what is " +
			"being checked, and a reconstruction would be a second answer about the past that " +
			"has to be kept honest against the first.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Product string `path:"product"`
		Stream  string `path:"stream"`
		Variant string `path:"variant"`
		Limit   int    `query:"limit" default:"200" minimum:"1" maximum:"500"`
		Offset  int    `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []DisposedBody `json:"items"`
			Total int            `json:"total"`
		}
	}, error) {
		subject, target, err := browsing(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		rows, total, err := finding.NewStore(in.DB.DB).Register(ctx, subject, target,
			input.Limit, input.Offset)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := &struct {
			Body struct {
				Items []DisposedBody `json:"items"`
				Total int            `json:"total"`
			}
		}{}
		out.Body.Total = total
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
	}) (*huma.StreamResponse, error) {
		subject, target, err := browsing(ctx, in, input.Product, input.Stream, input.Variant)
		if err != nil {
			return nil, err
		}
		// No triage line is stated, because none is applied. The register is
		// every place in the build with what stands there, which is what makes
		// it answerable to an auditor — narrowing it by what this deployment
		// considers worth triaging would be the omission the document exists
		// to rule out. The header said a line had been applied and none had,
		// which is the more dangerous of the two: a file that claims to have
		// left things out reads as complete about what remains.
		store := finding.NewStore(in.DB.DB)
		// Asked before a byte is written. Once the stream has started the
		// status is gone, so a refusal reaching it there could only be said
		// in the file — and what it said was that the export stopped early,
		// with a 200 in front of it.
		if err := store.MayReadRegister(ctx, subject, target); err != nil {
			return nil, refusedFinding(in, err)
		}
		out := Exporting{
			Header: []string{
				"issue", "severity", "component", "version", "place", "consumer", "state",
				"outcome", "justification", "proposed by", "proposed at",
				"approved by", "approved at", "agreement carried",
				"opened", "closed", "due", "met",
			},
			// Streamed rather than paged, and neither counted. A file has no
			// column for how many rows there are altogether, and every page
			// re-sorted the build's quarter of a million rows and skipped past
			// the ones already written — 52 minutes for a real build, against
			// 1.9 seconds for one cursor over the same rows in the same order.
			Stream: func(ctx context.Context, each func([]string) error) error {
				return store.RegisterEach(ctx, subject, target, func(row finding.Disposed) error {
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
						body.Opened, body.Closed, body.Due, met,
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
	}
	if row.DueAt != nil {
		body.Due = row.DueAt.Format(time.DateOnly)
	}
	return body
}

// RateBody is how much of one severity's work met its deadline.
type RateBody struct {
	Severity string `json:"severity"`
	Closed   int    `json:"closed" doc:"How many issue-and-component groups are wholly closed, with a deadline to be judged against"`
	Met      int    `json:"met" doc:"How many of those closed by it. Closed exactly at the deadline met it, because something still open at that instant is not yet overdue"`
	Late     int    `json:"late" doc:"How many did not"`
	// Deferred is its own number rather than a failure. A rate that
	// counted an approved deferral as one would punish the deliberate act
	// the deferral mechanism exists to make possible, and within a quarter
	// people stop deferring and start letting things run late silently.
	Deferred int `json:"deferred" doc:"Still open with a standing deferral: somebody moved the date deliberately"`
	Overdue  int `json:"overdue" doc:"Still open, past the deadline, with no deferral standing — plainly late"`
}

func registerCompliance(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-compliance-rate", Method: http.MethodGet,
		Path:    "/v1/compliance",
		Summary: "Report what proportion of work met its deadline",
		Description: "By severity: how much closed inside its deadline, how much did not, how " +
			"much is deferred by decision, and how much is plainly late.\n\n" +
			"**A deferral is its own number and not a failure**, so `deferred` is neither " +
			"met nor late.\n\n" +
			"Counted in the same unit as every other screen: one issue at one component, not " +
			"one row per place. A group is closed when no place is still open, met when none " +
			"of the closed ones was late, deferred when every open place is covered by a " +
			"standing deferral, and overdue when anything open is past its date and " +
			"uncovered.\n\n" +
			"A closed finding keeps the deadline it carried; only open ones lose theirs at " +
			"end of life or below the triage line.\n\n" +
			"**A product is required** — a place identity carries no product, so this cannot " +
			"be asked across the deployment.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
	}) (*listOutput[RateBody], error) {
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
		// reason its description gives. The store said so with a plain error
		// nothing recognized, which fell through to the generic answer for a
		// write that broke: a caller who left out a parameter was told the
		// server had failed, on a read-only endpoint, in a sentence about
		// something not being recorded.
		if scope.ProductID == nil {
			return nil, huma.Error422UnprocessableEntity(
				"name a product: a rate has to be about one, because a place " +
					"identity carries no product and correlating decisions without " +
					"one would reach every product in the deployment")
		}
		rates, err := finding.NewStore(in.DB.DB).Compliance(ctx, subject, scope)
		if err != nil {
			return nil, refusedFinding(in, err)
		}
		out := &listOutput[RateBody]{}
		out.Body.Items = make([]RateBody, 0, len(rates))
		for _, rate := range rates {
			out.Body.Items = append(out.Body.Items, RateBody{
				Severity: rate.Severity, Closed: rate.Closed, Met: rate.Met,
				Late: rate.Late, Deferred: rate.Deferred, Overdue: rate.Overdue,
			})
		}
		return out, nil
	})
}
