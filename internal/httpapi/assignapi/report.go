// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// HeldReportBody is one open vulnerability report in a list of held work.
type HeldReportBody struct {
	Reference  string `json:"reference" doc:"The name the report is reached by"`
	Product    string `json:"product" doc:"The product it was reported against, by name"`
	Title      string `json:"title,omitempty"`
	ReportedBy string `json:"reported_by,omitempty"`
	Received   string `json:"received,omitempty" doc:"The day it arrived"`
	RecordedAt string `json:"recorded_at"`
	Waiting    bool   `json:"waiting,omitempty" doc:"Whether a ruling over it is waiting for a second person"`
	core.HolderBody
}

// HeldReportsPage is a page of held reports.
type HeldReportsPage = core.ListOutput[HeldReportBody]

// registerReportAssignment is giving a report to somebody, and the lists of
// open reports by who holds them.
func registerReportAssignment(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "assign-report", Method: http.MethodPut,
		Path:    "/v1/products/{product}/reports/{reference}/assignment",
		Summary: "Assign a vulnerability report to somebody",
		Description: "Records who is working this report.\n\n" +
			"Send `person` as an empty string to hand it back to nobody. Send `team` instead to " +
			"route it to a team, which is a queue rather than a holding: it stays unheld until " +
			"somebody takes it.\n\n" +
			"A report is undisclosed, so a person is given one only where they read " +
			"undisclosed work in the product, and a team only where one member does. A judged " +
			"report is refused with 409: its work goes on as the issue it became, or ended " +
			"with its ruling.\n\n" +
			"The person given it is told, where that is not you.",
		Tags: []string{"Findings"}, DefaultStatus: http.StatusNoContent,
	}, core.PerProduct, "Giving a report to somebody else also needs assigner. Taking one nobody "+
		"holds, or handing back your own, does not.", access.PrivateTriage), func(ctx context.Context, input *struct {
		Product   string `path:"product"`
		Reference string `path:"reference" maxLength:"593"`
		Body      struct {
			Person string `json:"person,omitempty" doc:"Their sign-in identity, or empty for nobody"`
			Team   string `json:"team,omitempty" doc:"A team to route it to instead, by name. A queue rather than a holding: it stays unheld until somebody takes it"`
		}
	}) (*struct{}, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		product, err := core.ProductNamedVisibly(ctx, in, subject, input.Product)
		if err != nil {
			return nil, err
		}
		// Authorized before any name in the request is resolved: the report's
		// reference, and the person or team it goes to.
		if err := finding.MayWorkReference(subject, product.ID); err != nil {
			return nil, refusedHolding(in, err)
		}
		if err := mayHandOver(subject, product.ID, input.Body.Person, input.Body.Team); err != nil {
			return nil, err
		}

		var to *int64
		var admits finding.Admits
		rights := access.NewStore(in.DB.DB)
		switch {
		case input.Body.Person != "":
			person, err := core.PersonNamed(ctx, in.Logger, rights, input.Body.Person)
			if err != nil {
				return nil, err
			}
			party := person.PartyID
			to = &party
			admits = personAdmits(person, product.ID)
		case input.Body.Team != "":
			team, err := core.TeamNamed(ctx, in.Logger, rights, input.Body.Team)
			if err != nil {
				return nil, err
			}
			party := team.PartyID
			to = &party
			admits = teamAdmits(team, product.ID)
		}

		row, err := finding.NewStore(in.DB.DB).AssignReport(ctx, subject, product.ID,
			input.Reference, to, admits)
		if err != nil {
			return nil, recipient(err, func(err error) error { return refusedHolding(in, err) })
		}
		// Told on the terms a finding's assignment is: to a person and never a
		// team, never for handing back, and only where they read the product's
		// reports. The line is undisclosed work, so nothing leaving the
		// deployment names the report.
		if to != nil && *to != subject.Party() && input.Body.Person != "" {
			them, err := rights.Resolve(ctx, input.Body.Person)
			if err == nil && them.Reads(access.Private, product.ID) {
				productID := product.ID
				core.Tell(ctx, in, "could not say that a report was assigned", notify.Telling{
					PersonID: them.ID, Kind: notify.Assigned,
					Body:    "Report " + row.Reference + ", in " + product.Name,
					Link:    weblink.VulnerabilityReport(product.Name, row.Reference),
					Private: true, ProductID: &productID,
				}, "person", them.ID)
			}
		}
		return &struct{}{}, nil
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-unassigned-reports", Method: http.MethodGet, Path: "/v1/unassigned/reports",
		Summary: "List vulnerability reports nobody is working",
		Description: "The open vulnerability reports nobody holds, across every product where " +
			"you read reports, oldest first. Open is not yet judged; a report whose ruling " +
			"waits for a second person is still open.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only the products where you read reports."), func(ctx context.Context, input *struct {
		Product string `query:"product" doc:"Limit to one product, by name. Empty means every product where you read reports; a name you cannot see is refused rather than answered empty"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset  int    `query:"offset" minimum:"0"`
	}) (*HeldReportsPage, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		return heldReports(ctx, in, subject, input.Product, nil, input.Limit, input.Offset)
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-assigned-reports", Method: http.MethodGet,
		Path:    "/v1/people/{identity}/assignments/reports",
		Summary: "List the vulnerability reports one person is working",
		Description: "The open vulnerability reports somebody holds, theirs and their teams' " +
			"queues, oldest first. Send `me` as the identity for your own.\n\n" +
			"An identity nobody holds answers an empty list, which is also what an identity " +
			"somebody holds answers when none of their reports are yours to see.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only the products where you read reports."), func(ctx context.Context, input *struct {
		Identity string `path:"identity" doc:"Their sign-in identity, or 'me' for your own"`
		Product  string `query:"product" doc:"Limit to one product, by name. Empty means every product where you read reports; a name you cannot see is refused rather than answered empty"`
		Limit    int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset   int    `query:"offset" minimum:"0"`
	}) (*HeldReportsPage, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		holders := subject.Mine()
		if input.Identity != "me" {
			rights := access.NewStore(in.DB.DB)
			person, err := rights.ByIdentity(ctx, input.Identity)
			switch {
			case errors.Is(err, access.ErrNoSuchPerson):
				holders = []int64{core.Nobody}
			case err != nil:
				return nil, core.WentWrong(in.Logger, "that person could not be looked up", err)
			default:
				teams, err := rights.TeamsOf(ctx, person.ID)
				if err != nil {
					return nil, core.WentWrong(in.Logger, "what they are working could not be read", err)
				}
				holders = []int64{person.PartyID}
				for _, team := range teams {
					holders = append(holders, team.PartyID)
				}
			}
		}
		if len(holders) == 0 {
			holders = []int64{core.Nobody}
		}
		return heldReports(ctx, in, subject, input.Product, holders, input.Limit, input.Offset)
	})

	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-team-assigned-reports", Method: http.MethodGet,
		Path:    "/v1/teams/{team}/assignments/reports",
		Summary: "List the vulnerability reports in one team's queue",
		Description: "The open vulnerability reports routed to a team, oldest first.\n\n" +
			"A team nobody declared answers an empty list, which is also what a team whose " +
			"reports are not yours to see answers.",
		Tags: []string{"Findings"},
	}, core.AnyPerson, "Answers only the products where you read reports."), func(ctx context.Context, input *struct {
		Team    string `path:"team" doc:"The team's name"`
		Product string `query:"product" doc:"Limit to one product, by name. Empty means every product where you read reports; a name you cannot see is refused rather than answered empty"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset  int    `query:"offset" minimum:"0"`
	}) (*HeldReportsPage, error) {
		subject, err := core.Reading(ctx)
		if err != nil {
			return nil, err
		}
		holders := []int64{core.Nobody}
		switch team, err := access.NewStore(in.DB.DB).TeamByName(ctx, input.Team); {
		case err == nil:
			holders = []int64{team.PartyID}
		case !errors.Is(err, access.ErrNoSuchTeam):
			return nil, core.WentWrong(in.Logger, "that team could not be looked up", err)
		}
		return heldReports(ctx, in, subject, input.Product, holders, input.Limit, input.Offset)
	})
}

// heldReports is a page of open reports some parties hold, or nobody does.
func heldReports(ctx context.Context, in core.Deps, subject access.Subject, product string,
	holders []int64, limit, offset int) (*HeldReportsPage, error) {

	within, err := core.NarrowedTo(ctx, in, subject, product)
	if err != nil {
		return nil, err
	}
	rows, total, err := finding.NewStore(in.DB.DB).HeldReports(ctx, subject, within, holders,
		limit, offset)
	if err != nil {
		return nil, core.Refused(in.Logger, err, "the reports could not be read")
	}
	parties := make([]int64, 0, len(rows))
	for _, row := range rows {
		if row.AssignedTo != nil {
			parties = append(parties, *row.AssignedTo)
		}
	}
	who, err := access.NewStore(in.DB.DB).WhoHolds(ctx, parties)
	if err != nil {
		return nil, core.WentWrong(in.Logger, "the reports could not be read", err)
	}
	out := &HeldReportsPage{}
	out.Body.Items = make([]HeldReportBody, 0, len(rows))
	for _, row := range rows {
		item := HeldReportBody{
			Reference: row.Reference, Product: row.Product, Title: row.Title,
			ReportedBy: row.ReportedBy, RecordedAt: core.Stamp(row.RecordedAt),
			Waiting: row.RulingID != nil,
		}
		if row.ReceivedOn != nil {
			item.Received = row.ReceivedOn.UTC().Format(time.DateOnly)
		}
		if row.AssignedTo != nil {
			if held, ok := who[*row.AssignedTo]; ok {
				item.HolderBody = core.HolderOf(held)
			}
		}
		out.Body.Items = append(out.Body.Items, item)
	}
	out.Body.Total = total
	return out, nil
}

// refusedHolding answers a refused report assignment.
func refusedHolding(in core.Deps, err error) error {
	switch {
	case errors.Is(err, finding.ErrNoSuchReport):
		return huma.Error404NotFound(finding.ErrNoSuchReport.Error())
	case errors.Is(err, finding.ErrReportJudged):
		return huma.Error409Conflict(err.Error())
	}
	return core.Refused(in.Logger, err, "that report could not be assigned")
}
