// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// SpentBody is the work spent on one component in one product.
type SpentBody struct {
	Product   string `json:"product"`
	Component string `json:"component" doc:"The subject of the judgments, by name. Empty where nothing in any build carries the place any more"`
	// Claims is the unit somebody works in — one argument, however many rows
	// it wrote — and Decisions how many places those reached.
	Claims    int `json:"claims" doc:"Arguments made about it in the period"`
	Decisions int `json:"decisions" doc:"Places those reached"`
	People    int `json:"people" doc:"The number of different people who argued about it"`
	// Promised is the upgrades that came out of them, counted as claims for
	// the same reason.
	Promised  int `json:"promised" doc:"Claims that promised work: an upgrade or a backport"`
	Dismissed int `json:"dismissed" doc:"Claims that argued it away"`
	Deferred  int `json:"deferred" doc:"Claims that put it off"`
}

// registerEffort answers where the work went.
func registerEffort(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "get-effort", Method: http.MethodGet, Path: "/v1/effort",
		Summary: "Report where triage effort went",
		Description: "What the judgments in a period were about, most argued first: which " +
			"component in which product, how many arguments were made, how many places they " +
			"reached, how many people made them, and what came out of them.\n\n" +
			"Counted in claims, not in the rows they wrote. A claim is one person's act; " +
			"counting its rows measures how far a component fans out through an image. Both " +
			"numbers come back.\n\n" +
			"Dated by when a judgment was proposed. Asked for neither a period nor a window, " +
			"this is the last 90 days.\n\n" +
			"Takes the same period and scope the other reports do, and is narrowed by what " +
			"you may see.",
		Tags: []string{"Reports"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		Period
		Product string `query:"product" doc:"Limit to judgments made in one product, by name"`
		Team    string `query:"team" doc:"Limit to judgments this team's members proposed, by team name"`
		Limit   int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
	}) (*overPeriod[SpentBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		since, until, err := input.window(90, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		only, err := measuring(ctx, in, subject, input.Product, input.Team)
		if err != nil {
			return nil, err
		}
		rows, err := triage.NewStore(in.DB.DB).Effort(ctx, subject, only, since, until, input.Limit)
		if err != nil {
			return nil, refused(in.Logger, err, "cannot read where the work went")
		}
		out := &overPeriod[SpentBody]{}
		out.Body.From, out.Body.To = stating(since, until)
		out.Body.Items = make([]SpentBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, SpentBody{
				Product: row.Product, Component: row.Component,
				Claims: row.Claims, Decisions: row.Decisions, People: row.People,
				Promised: row.Promised, Dismissed: row.Dismissed, Deferred: row.Deferred,
			})
		}
		out.Body.Total = len(out.Body.Items)
		return out, nil
	})
}

// measuring resolves a product and a team into what the store narrows by.
//
// One spelling, because two reports take the same pair and a name resolved two
// ways is two answers about one reader's reach.
func measuring(ctx context.Context, in Ingest, subject access.Subject,
	product, team string) (triage.Measuring, error) {

	var only triage.Measuring
	if product != "" {
		// Resolved against what the caller may see, and a product they may
		// not read answers as one nobody declared — anything else turns a
		// report into a way to ask which products exist.
		named, err := productNamedVisibly(ctx, in, subject, product)
		if err != nil {
			return only, err
		}
		only.Products = []int64{named.ID}
	}
	if team != "" {
		rights := access.NewStore(in.DB.DB)
		found, err := rights.TeamByName(ctx, team)
		if err != nil {
			return only, absent(in.Logger, err, "that team could not be looked up",
				func() error { return huma.Error404NotFound("no such team") })
		}
		members, err := rights.MembersOf(ctx, found.ID)
		if err != nil {
			return only, wentWrong(in.Logger, "who is on that team could not be read", err)
		}
		// A team with nobody on it measures nothing rather than the
		// deployment: a narrowing that silently widens is the one mistake a
		// narrowing must not make.
		only.People = members
		if len(members) == 0 {
			only.People = []int64{0}
		}
	}
	return only, nil
}
