package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// noteChange records an administrative act against whoever made it.
//
// **A failure to record is not a failure of the change.** The change has
// already happened, and answering with an error would invite a retry that
// makes it twice. It is logged instead, which is the same choice the
// assignment notification makes for the same reason.
//
// Called from the request rather than from the store underneath. The stores
// take no subject — a setting write knows the name and the value and nothing
// about who is asking — and threading one through every one of them to reach
// this would make those signatures about auditing rather than about the thing
// being written. The cost is that a new administrative route can forget, so a
// test walks the routes and asserts each leaves a row.
func noteChange(ctx context.Context, in Ingest, kind trail.Kind, name string, was, became *string) {
	if in.DB == nil {
		return
	}
	noted(ctx, trail.NewStore(in.DB.DB), in.Logger, kind, name, was, became)
}

// noteAdminChange is the same for the administrative routes, which carry their
// dependencies as functions rather than a database.
func noteAdminChange(ctx context.Context, a Administering, kind trail.Kind, name string,
	was, became *string) {

	if a.Trail == nil {
		return
	}
	noted(ctx, a.Trail(), a.Logger, kind, name, was, became)
}

func noted(ctx context.Context, store *trail.Store, logger *slog.Logger, kind trail.Kind,
	name string, was, became *string) {

	if store == nil {
		return
	}
	by, err := reading(ctx)
	if err != nil {
		return
	}
	if err := store.Record(ctx, by, kind, name, was, became); err != nil && logger != nil {
		logger.Error("could not record an administrative change",
			"error", err, "kind", kind, "about", name)
	}
}

// noteDeclared is the same for the catalog routes.
func noteDeclared(ctx context.Context, d Declaring, kind trail.Kind, name string,
	was, became *string) {

	if d.Trail == nil {
		return
	}
	noted(ctx, d.Trail(), d.Logger, kind, name, was, became)
}

// onDay spells a date for the trail, where absent means there is none.
func onDay(at *time.Time) *string {
	if at == nil {
		return nil
	}
	said := at.UTC().Format(time.DateOnly)
	return &said
}

// ChangeBody is one administrative act, as an administrator reads it.
type ChangeBody struct {
	At   string `json:"at"`
	By   string `json:"by" doc:"Who made the change, by sign-in identity"`
	Kind string `json:"kind" enum:"setting,role,routing,support,release,credential,account,team,case,alias" doc:"What sort of thing changed"`
	// About is which one: the setting's name, the person and product a role
	// was granted on, the release whose support date moved.
	About string `json:"about"`
	// Was and Became are what it held before and after. Absent before means
	// nobody had set it; absent after means it was cleared. The two are
	// different acts and a blank cannot tell them apart.
	Was    string `json:"was,omitempty"`
	Became string `json:"became,omitempty"`
	// Unset and Cleared say which of those an absent value is, because a
	// value that is genuinely the empty string is also absent in JSON.
	Unset   bool `json:"unset,omitempty" doc:"Nobody had set it before this"`
	Cleared bool `json:"cleared,omitempty" doc:"This change cleared it"`
}

func registerTrail(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
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
			"Newest first, and paged: it only grows.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Kind   string `query:"kind" enum:"setting,role,routing,support,release,credential,account,team,case,alias" doc:"Keep only changes of one kind"`
		Limit  int    `query:"limit" default:"50" minimum:"1" maximum:"200"`
		Offset int    `query:"offset" minimum:"0"`
	}) (*struct {
		Body struct {
			Items []ChangeBody `json:"items"`
			Total int          `json:"total"`
		}
	}, error) {
		subject, err := requester(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		store := access.NewStore(in.DB.DB)
		// Refused by the store rather than here. A row names who was brought
		// into which case, undisclosed ones among them, so who may read it is
		// a question about the query (REQ-42 and REQ-43).
		changes, total, err := trail.NewStore(in.DB.DB).Changes(ctx, subject,
			trail.Kind(input.Kind), input.Limit, input.Offset)
		if err != nil {
			return nil, refused(in.Logger, err, "what has been changed could not be read")
		}

		who := make([]int64, 0, len(changes))
		for _, change := range changes {
			who = append(who, change.By)
		}
		names, err := store.Names(ctx, who)
		if err != nil {
			return nil, wentWrong(in.Logger, "who changed these could not be read", err)
		}

		out := &struct {
			Body struct {
				Items []ChangeBody `json:"items"`
				Total int          `json:"total"`
			}
		}{}
		out.Body.Total = total
		out.Body.Items = make([]ChangeBody, 0, len(changes))
		for _, change := range changes {
			body := ChangeBody{
				At: change.At.Format("2006-01-02T15:04:05Z"), By: names[change.By],
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
