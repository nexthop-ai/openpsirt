// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// recording answers a store write that is part of an act.
//
// A lost race goes back untouched. A store handed somebody else's
// transaction cannot go again itself — the failed statement has already
// aborted it on one engine — so it says it lost, and the helper that opened
// the transaction takes the whole act again. Reported as a fault instead, the
// sentinel is destroyed: WentWrong builds a fresh refusal that wraps nothing,
// so the retry helper never sees it and the loser of an ordinary race is
// handed a 500 where going round again would have won.
//
// One spelling rather than an arm at each site, because the way this stops
// working again is a third write that forgets it.
func recording(logger *slog.Logger, what string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, database.ErrGoAgain) {
		return err
	}
	return core.WentWrong(logger, what, err)
}

// onDay spells a date for the trail, where absent means there is none.
func onDay(at *time.Time) *string {
	if at == nil {
		return nil
	}
	said := core.DayOf(at)
	return &said
}

// ChangeBody is one administrative act, as an administrator reads it.
type ChangeBody struct {
	At    string `json:"at"`
	Actor string `json:"actor" enum:"person,configuration,merge,upgrade" doc:"What made the change: a person in the application, the deployment's startup configuration, which names administrators, maps groups to roles and sets where roles come from to match, a scan merging two issues its report named together, or an upgrade, which withdraws a key or a token whose name another holds"`
	By    string `json:"by,omitempty" doc:"The person who made the change, by sign-in identity. Absent where no person made it"`
	// ByName is the label beside the identity rather than in its place.
	ByName string `json:"by_name,omitempty" doc:"Their display name, where it differs from their identity"`
	Kind   string `json:"kind" enum:"setting,role,routing,support,release,credential,account,team,case,alias,catalog,exploited-here,merge" doc:"The kind of thing that changed"`
	// About is the subject: the setting's name, the person and product a role
	// was granted on, the release whose support date moved.
	About string `json:"about"`
	// Was and Became are the values before and after. Absent before means
	// nobody had set it; absent after means it was cleared. The two are
	// different acts and a blank cannot tell them apart.
	Was    string `json:"was,omitempty"`
	Became string `json:"became,omitempty"`
	// Unset and Cleared say which of those an absent value is, because a
	// value that is genuinely the empty string is also absent in JSON.
	Unset   bool `json:"unset,omitempty" doc:"Whether nothing had been set before this, as distinct from a value stored empty"`
	Cleared bool `json:"cleared,omitempty" doc:"This change cleared it"`
}

func registerTrail(api huma.API, in core.Deps) {
	huma.Register(api, core.Requiring(huma.Operation{
		OperationID: "list-administrative-changes", Method: http.MethodGet,
		Path:    "/v1/administration/changes",
		Summary: "List administrative changes",
		Description: "Who changed a setting, a role grant, a routing rule, a support date, a " +
			"credential, an account, a team or an issue's names — with what it held " +
			"before and what it holds now.\n\n" +
			"This is the layer above the triage record rather than part of it. Three of the " +
			"things listed here silently rewrite what the tool reports: the deadline windows " +
			"recompute every open finding's deadline, the triage floor takes the deadline off " +
			"everything below it, and an end-of-life date takes it off everything past it.\n\n" +
			"Newest first, and paged: it only grows.\n\n" +
			"Takes a period, because the question an audit asks is what changed in the " +
			"stretch the certificate covers. Asked for none, it answers about everything " +
			"it holds.",
		Tags: []string{"Administration"},
	}, core.DeploymentRecords, ""), func(ctx context.Context, input *struct {
		Kind string `query:"kind" enum:"setting,role,routing,support,release,credential,account,team,case,alias,catalog,exploited-here,merge" doc:"Keep only changes of one kind"`
		core.Period
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []ChangeBody `json:"items"`
			Total int          `json:"total"`
			// From and To say the period back, so a page of rows is never
			// read without the stretch it covers. Empty where that side is
			// unbounded.
			From string `json:"from,omitempty"`
			To   string `json:"to,omitempty"`
		}
	}, error) {
		subject, err := core.Requester(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, core.NoDatabase(in.Logger)
		}
		// No default window. A trail read with one would answer about the
		// last stretch while looking like it answered about everything, which
		// is the reading an audit must not be given.
		since, until, err := input.Window(0, time.Now().UTC())
		if err != nil {
			return nil, err
		}
		// Refused by the store rather than here. A row names who was brought
		// into which case, undisclosed ones among them, so who may read it is
		// a question about the query (REQ-42 and REQ-43).
		changes, total, err := trail.NewStore(in.DB.DB).Changes(ctx, subject,
			trail.Kind(input.Kind), trail.Over{Since: since, Until: until},
			input.Limit, input.Offset)
		if err != nil {
			return nil, core.Refused(in.Logger, err, "what has been changed could not be read")
		}

		who := make([]int64, 0, len(changes))
		for _, change := range changes {
			if person := change.Person(); person != 0 {
				who = append(who, person)
			}
		}
		people, err := core.WhoSigned(ctx, in.DB.DB, who)
		if err != nil {
			return nil, core.WentWrong(in.Logger, "who changed these could not be read", err)
		}

		out := &struct {
			Body struct {
				Items []ChangeBody `json:"items"`
				Total int          `json:"total"`
				From  string       `json:"from,omitempty"`
				To    string       `json:"to,omitempty"`
			}
		}{}
		out.Body.Total = total
		out.Body.From, out.Body.To = core.Stating(since, until)
		out.Body.Items = make([]ChangeBody, 0, len(changes))
		for _, change := range changes {
			body := ChangeBody{
				At: core.Stamp(change.At), Actor: string(change.Actor),
				By: people.Identity(change.Person()), ByName: people.Label(change.Person()),
				Kind: string(change.Kind), About: change.Name,
				Unset: change.Was == nil, Cleared: change.Became == nil,
			}
			if change.Was != nil {
				body.Was = *change.Was
			}
			if change.Became != nil {
				body.Became = *change.Became
			}
			out.Body.Items = append(out.Body.Items, body)
		}
		return out, nil
	})
}
