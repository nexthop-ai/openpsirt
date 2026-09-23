// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"net/url"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// NotificationBody is one thing somebody was told.
type NotificationBody struct {
	ID   int64  `json:"id" doc:"The name for this when acknowledging it"`
	Kind string `json:"kind" doc:"The kind, as a word: assigned, sent-back, build-quiet"`
	// Lifetime says whether acknowledging is the way this goes away. A
	// condition clears itself when what it is about stops being true, so
	// acknowledging one hides it rather than resolving anything.
	Lifetime string `json:"lifetime" enum:"event,condition" doc:"An event happened once and is acknowledged; a condition holds until what it is about changes"`
	About    string `json:"about,omitempty" doc:"A condition's subject. Absent for an event"`
	Body     string `json:"body" doc:"The message. It describes the moment it was written rather than the world now"`
	Link     string `json:"link,omitempty" doc:"The destination, where there is somewhere to go"`
	At       string `json:"at" doc:"The moment it was recorded"`
}

type notificationsOutput struct {
	Body struct {
		Items []NotificationBody `json:"items"`
		// Total is the number waiting, which is what the area draws.
		// Counted through the same conditions as the page, so a badge cannot
		// disagree with the list under it.
		Total int `json:"total" doc:"The number waiting on you"`
	}
}

func registerNotifications(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-notifications", Method: http.MethodGet,
		Path:    "/v1/notifications",
		Summary: "List your notifications",
		Description: "Returns what you have not dealt with, newest first, and how many there " +
			"are.\n\n" +
			"Everyone has one of these, and what appears in it differs by what you hold: work " +
			"arriving, a dismissal sent back, an approval an edit withdrew, or — for an " +
			"administrator — that the tool itself is unwell.\n\n" +
			"Two lifetimes, and the difference matters to a caller. An event happened once " +
			"and goes away when you acknowledge it. A condition is true while something is " +
			"true and clears itself when that stops, so a build that resumes being scanned " +
			"leaves this list without anybody dismissing it.",
		Tags: []string{"Notifications"},
	}, ownSubject, ""), func(ctx context.Context, input *struct {
		Limit  int `query:"limit" default:"50" minimum:"1" maximum:"200" doc:"The number returned"`
		Offset int `query:"offset" minimum:"0" doc:"The number skipped"`
	}) (*notificationsOutput, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		rows, total, err := notify.NewStore(in.DB.DB).
			Waiting(ctx, subject, input.Limit, input.Offset)
		if err != nil {
			return nil, wentWrong(in.Logger, "what is waiting could not be read", err)
		}
		out := &notificationsOutput{}
		out.Body.Items = make([]NotificationBody, 0, len(rows))
		out.Body.Total = total
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, NotificationBody{
				ID: row.ID, Kind: string(row.Kind), Lifetime: string(row.Lifetime),
				About: row.About, Body: row.Body, Link: row.Link,
				At: stamp(row.CreatedAt),
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "acknowledge-notification", Method: http.MethodDelete,
		Path:    "/v1/notifications/{id}",
		Summary: "Acknowledge one notification",
		Description: "Takes one off your list.\n\n" +
			"Yours only. A notification identifier is a number a caller supplies, and one " +
			"belonging to somebody else answers the same way as one that does not exist.\n\n" +
			"Acknowledging a condition hides it rather than resolving it: what it is about is " +
			"still true, and the pass that derives it will not raise it again while it holds.",
		Tags: []string{"Notifications"}, DefaultStatus: http.StatusNoContent,
	}, ownSubject, ""), func(ctx context.Context, input *struct {
		ID int64 `path:"id"`
	}) (*struct{}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		if err := notify.NewStore(in.DB.DB).Acknowledge(ctx, subject, input.ID); err != nil {
			// The same answer whether it is somebody else's or not there,
			// which is what stops this being a way to find out which
			// identifiers exist. A read that could not be made is neither.
			return nil, absent(in.Logger, err, "that notification could not be looked up",
				func() error {
					return huma.Error404NotFound("no notification of yours by that number")
				})
		}
		return nil, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "acknowledge-all-notifications", Method: http.MethodDelete,
		Path:    "/v1/notifications",
		Summary: "Acknowledge everything waiting on you",
		Description: "Takes everything off your list at once, and says how many that was. " +
			"Conditions that are still true will not come back while they hold.",
		Tags: []string{"Notifications"},
	}, ownSubject, ""), func(ctx context.Context, _ *struct{}) (*struct {
		Body struct {
			Acknowledged int `json:"acknowledged" doc:"The number that were waiting"`
		}
	}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if in.DB == nil {
			return nil, noDatabase(in.Logger)
		}
		n, err := notify.NewStore(in.DB.DB).AcknowledgeAll(ctx, subject)
		if err != nil {
			return nil, wentWrong(in.Logger, "they could not be acknowledged", err)
		}
		out := &struct {
			Body struct {
				Acknowledged int `json:"acknowledged" doc:"The number that were waiting"`
			}
		}{}
		out.Body.Acknowledged = n
		return out, nil
	})
}

// registerDigest is the two switches a person sets for themselves.
func registerDigest(api huma.API, in Ingest) {
	huma.Register(api, requiring(huma.Operation{
		OperationID: "set-digest", Method: http.MethodPut, Path: "/v1/session/me/digest",
		Summary: "Choose what is sent to you daily",
		Description: "Turns the daily digest on or off, and says whether it lists findings " +
			"nobody owns as well as your own outstanding work.\n\n" +
			"Both are off until asked for. The digest carries what nothing else told you: " +
			"work that became yours without a message, and — where asked for — findings " +
			"that opened since the last one and nobody has picked up.\n\n" +
			"Asking for the second without the first is refused: a digest listing what " +
			"nobody owns is still a digest.\n\n" +
			"Nothing is sent anywhere without an address recorded against you, which " +
			"`GET /v1/session/me` reports as `reachable`.",
		Tags: []string{"Notifications"}, DefaultStatus: http.StatusNoContent,
	}, ownSubject, ""), func(ctx context.Context, input *struct {
		Body struct {
			Digest     bool `json:"digest" doc:"Send a daily digest"`
			Unassigned bool `json:"unassigned,omitempty" doc:"Include findings nobody owns"`
		}
	}) (*struct{}, error) {
		subject, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if subject.Kind != access.Person || in.DB == nil {
			// A credential is not sent mail, so it has nothing to choose.
			return nil, huma.Error403Forbidden("only a person chooses what is sent to them")
		}
		if err := access.NewStore(in.DB.DB).SetDigest(ctx, subject.ID,
			input.Body.Digest, input.Body.Unassigned); err != nil {
			return nil, asked(in.Logger, err)
		}
		return &struct{}{}, nil
	})
}

// findingPath is where a notification about one finding points.
//
// Spelled once here rather than at each producer: it is the address the
// interface routes on, and three copies of it drift the moment a route moves.
func findingPath(product, stream, variant, vulnerability, component string) string {
	return "/products/" + url.PathEscape(product) +
		"/streams/" + url.PathEscape(stream) +
		"/variants/" + url.PathEscape(variant) +
		"/findings/" + url.PathEscape(vulnerability) +
		"/components/" + url.PathEscape(component)
}
