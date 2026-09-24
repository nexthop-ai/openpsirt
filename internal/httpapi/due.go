// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"math"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// LateBody is a finding running out of time with nobody having decided.
type LateBody struct {
	Vulnerability string `json:"vulnerability"`
	Severity      string `json:"severity,omitempty"`
	Exploited     bool   `json:"exploited,omitempty"`
	Component     string `json:"component"`
	Version       string `json:"version,omitempty" doc:"The version, so a link to the finding can name it — a build ships a name at more than one version often enough that a link without it cannot be resolved"`
	Product       string `json:"product"`
	Stream        string `json:"stream"`
	Variant       string `json:"variant"`
	Places        int    `json:"places" doc:"The number of places in that build this sits at"`
	AssignedTo    string `json:"assigned_to,omitempty" doc:"The party dealing with this, by sign-in identity for a person and by name for a team. Empty means nobody, or not everywhere the same person"`
	AssignedName  string `json:"assigned_to_name,omitempty" doc:"Their display name, where they have one"`
	Due           string `json:"due" doc:"The date it is due"`
	DaysLeft      int    `json:"days_left" doc:"Negative once it is overdue"`
}

func registerDue(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-running-out", Method: http.MethodGet, Path: "/v1/running-out",
		Summary: "List findings running out of time that nobody has decided about",
		Description: "Returns open findings whose deadline falls within `days`, where nobody has " +
			"recorded a decision, across every product you can see.\n\n" +
			"A deadline that has been answered is not on this list. A dismissal takes a finding " +
			"off the clock, because the claim is that it will not be fixed, and a deferral " +
			"replaces the deadline with its own date. What is left is time passing with nothing " +
			"said.\n\n" +
			"The window comes from how urgent a finding is. Being known-exploited has its own " +
			"and it is the shortest, whatever the severity says. Anything the reports did not " +
			"rate takes the medium window.\n\n" +
			"One row per issue at a component, however many places it sits at. `days_left` is " +
			"negative once something is overdue.",
		Tags: []string{"Findings"},
	}, anyPerson, "Answers only what you may see."), func(ctx context.Context, input *struct {
		ScopeQuery
		Days   int `query:"days" default:"14" minimum:"0" maximum:"365" doc:"The distance ahead to look"`
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0" doc:"The offset into the list"`
	}) (*listOutput[LateBody], error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		scope, err := scoped(ctx, in, subject, input.ScopeQuery)
		if err != nil {
			return nil, err
		}
		// Paged, because this one grows with the estate: it is a deadline
		// list across every product the subject can see, and with a ceiling
		// and no offset what is past the ceiling could not be read through
		// the API at all — not slowly, not at all.
		rows, total, err := finding.NewStore(in.DB.DB).RunningOutPage(ctx, subject, scope,
			time.Duration(input.Days)*24*time.Hour, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "what is running out of time could not be read", err)
		}

		owners := make([]int64, 0, len(rows))
		for _, row := range rows {
			if row.AssignedTo != nil {
				owners = append(owners, *row.AssignedTo)
			}
		}
		// Whoever holds it, which is a person or a team: the
		// assignment column holds a party, and this screen does not
		// have to know which.
		who, err := access.NewStore(in.DB.DB).WhoHolds(ctx, owners)
		if err != nil {
			return nil, wentWrong(in.Logger, "who is dealing with these could not be read", err)
		}

		now := time.Now().UTC()
		out := &listOutput[LateBody]{}
		// The total, so a tile counting this list says what the list it opens
		// says. Without it the front page reports its own page size as the
		// figure.
		out.Body.Total = total
		out.Body.Items = make([]LateBody, 0, len(rows))
		for _, row := range rows {
			body := LateBody{
				Vulnerability: row.Vulnerability, Severity: row.Severity,
				Exploited: row.Exploited, Component: row.Component, Version: row.Version,
				Product: row.Product, Stream: row.Stream, Variant: row.Variant,
				Places: row.Places,
				Due:    row.Due.Format(time.DateOnly),
				// Rounded down, not toward zero. Truncation reports something
				// twelve hours overdue as having zero days left, which reads
				// as due today rather than as late.
				DaysLeft: int(math.Floor(row.Due.Sub(now).Hours() / 24)),
			}
			if row.AssignedTo != nil {
				held := who[*row.AssignedTo]
				body.AssignedTo, body.AssignedName = held.Address, labelBeside(held.Name, held.Address)
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}
