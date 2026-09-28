// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/catalog"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// OutboundBody is one destination this deployment sends to.
//
// Neither credential is here. The secret signs our requests rather than
// authenticating anybody to us, so it is stored recoverably and never shown.
// The address is the other one: for Slack and for Teams the path carries the
// token and there is no other authentication, so only the host is returned.
// A destination is told apart from another by its name and kind, which is what
// retiring one takes.
type OutboundBody struct {
	Name     string `json:"name" doc:"The name, so a log line and a screen can use it"`
	Kind     string `json:"kind" doc:"The notifications that go here, or * for all of them"`
	Platform string `json:"platform" enum:"webhook,slack,zulip" doc:"How it is reached: a signed request, or a chat platform"`
	Host     string `json:"host,omitempty" doc:"The host a webhook sends to. The rest of the address is never returned"`
	Channel  string `json:"channel,omitempty" doc:"The chat channel it posts to"`
	Topic    string `json:"topic,omitempty" doc:"The topic within a Zulip channel"`
	Product  string `json:"product,omitempty" doc:"The product a chat channel belongs to"`
	Team     string `json:"team,omitempty" doc:"The team a chat channel belongs to"`
	// Sent and Failing say whether it is working, which is the question an
	// operator has about a destination and one nothing else answers.
	Sent    int    `json:"sent" doc:"The number of things delivered there"`
	Failing int    `json:"failing" doc:"The number being retried or given up on"`
	Because string `json:"because,omitempty" doc:"The reason the last one failed, where one did"`
}

// registerOutbound configures where this deployment sends what it has to
// say.
func registerOutbound(api huma.API, in Ingest, a Administering) {
	const path = "/v1/outbound"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-outbound", Method: http.MethodGet, Path: path,
		Summary: "List where this deployment sends things",
		Description: "The destinations configured, which kinds go to each, and whether they " +
			"are working. A destination is a webhook or a chat channel.\n\n" +
			"The signing secret is never returned, and of the address only the host is. A " +
			"destination is told apart by its name and kind.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, _ *struct{}) (*listOutput[OutboundBody], error) {
		if _, _, err := administerable(ctx, a, a.handle()); err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		rows, err := notify.NewStore(in.DB.DB).Destinations(ctx, by)
		if err != nil {
			return nil, wentWrong(a.Logger, "the destinations could not be read", err)
		}
		out := &listOutput[OutboundBody]{}
		out.Body.Items = make([]OutboundBody, 0, len(rows))
		for _, row := range rows {
			out.Body.Items = append(out.Body.Items, OutboundBody{
				Name: row.Name, Kind: row.Kind, Platform: row.Platform, Host: hostOf(row.URL),
				Channel: row.Channel, Topic: row.Topic, Product: row.Product, Team: row.Team,
				Sent: row.Sent, Failing: row.Failing, Because: row.Because,
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "add-outbound", Method: http.MethodPost, Path: path,
		Summary: "Send a kind of notification somewhere",
		Description: "Records a destination: which kinds go there — one kind by name, or `*` for " +
			"all of them — and either a webhook or a chat channel.\n\n" +
			"A webhook takes a URL and a shared secret to sign with. A chat channel takes a " +
			"`platform` this deployment is configured for, the `channel` to post to, and on " +
			"Zulip a `topic`. It may name a `product` or a `team`, and then carries only what " +
			"is about that product or that team.\n\n" +
			"A chat channel carries notifications about a product, a team or the deployment, " +
			"never one addressed to a single person, and a kind addressed to one person is " +
			"refused. What one channel carries is not also posted to a broader one: a team's " +
			"channel takes what is about its team, a product's what is about its product, and " +
			"a deployment's the rest. A channel belonging to a product or a team carries " +
			"nothing about a finding nobody has announced; a deployment's carries that there " +
			"is something, and a link.\n\n" +
			"What a webhook carries is what the channel rules already allow. A notification " +
			"about a finding nobody has announced carries the fact that there is something " +
			"and a link, and nothing else — the same body a mail would carry, composed by the " +
			"same code.\n\n" +
			"`subject` and `text` are escaped as markdown, a backslash before each character " +
			"that would open markup, and carry `&`, `<` and `>` as `&amp;`, `&lt;` and `&gt;`, " +
			"which Slack and Teams read as those characters. Any other receiver decodes the " +
			"three and drops the backslashes. The line of `text` holding the address is not " +
			"escaped as markdown, and `link` is sent as it is.\n\n" +
			"Every webhook request is signed. `X-OpenPSIRT-Timestamp` and " +
			"`X-OpenPSIRT-Signature: sha256=…`, an HMAC over the timestamp, a dot, and the " +
			"body — so a receiver can tell one of ours from one anybody could make, and " +
			"cannot replay yesterday's.\n\n" +
			"The response carries the host of a webhook's address and never the rest of it, " +
			"the same as the listing.\n\n" +
			"A webhook is https only, and a redirect is refused rather than followed.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Body struct {
			Name     string `json:"name" minLength:"1" maxLength:"191"`
			Kind     string `json:"kind" minLength:"1" maxLength:"191" doc:"One notification kind, or * for all of them"`
			Platform string `json:"platform,omitempty" enum:"webhook,slack,zulip" doc:"How it is reached. A webhook where absent"`
			URL      string `json:"url,omitempty" maxLength:"1000" doc:"A webhook's address. https only"`
			Secret   string `json:"secret,omitempty" maxLength:"400" doc:"A webhook's signing secret, at least 16 characters. Never returned by any endpoint"`
			Channel  string `json:"channel,omitempty" maxLength:"191" doc:"The chat channel to post to"`
			Topic    string `json:"topic,omitempty" maxLength:"60" doc:"The topic within a Zulip channel"`
			Product  string `json:"product,omitempty" maxLength:"191" doc:"The product a chat channel belongs to"`
			Team     string `json:"team,omitempty" maxLength:"191" doc:"The team a chat channel belongs to"`
		}
	}) (*struct {
		Status int
		Body   OutboundBody
	}, error) {
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		// Normalized here so the stored value is the address as it parses. The
		// rule for what may be stored is the store's, where the rest of this
		// table's rules live.
		parsed, err := url.Parse(strings.TrimSpace(input.Body.URL))
		address := strings.TrimSpace(input.Body.URL)
		if err == nil {
			address = parsed.String()
		}
		var row *notify.Outbound
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			if _, _, err := administerable(ctx, a, tx); err != nil {
				return err
			}
			want := notify.Destination{
				Name: input.Body.Name, Kind: input.Body.Kind, Platform: input.Body.Platform,
				URL: address, Secret: input.Body.Secret,
				Channel: input.Body.Channel, Topic: input.Body.Topic,
			}
			// Resolved after the administrator is established, so the names
			// a request carries answer nothing to anybody else.
			if name := strings.TrimSpace(input.Body.Product); name != "" {
				product, err := a.Catalog(tx).ProductByName(ctx, name)
				if errors.Is(err, catalog.ErrNotFound) {
					return huma.Error404NotFound("no product is recorded under that name")
				} else if err != nil {
					return wentWrong(a.Logger, "the product could not be read", err)
				}
				want.ProductID = &product.ID
			}
			if name := strings.TrimSpace(input.Body.Team); name != "" {
				team, err := a.Access(tx).TeamByName(ctx, name)
				if errors.Is(err, access.ErrNoSuchTeam) {
					return huma.Error404NotFound("no team is in use under that name")
				} else if err != nil {
					return wentWrong(a.Logger, "the team could not be read", err)
				}
				want.TeamID = &team.ID
			}
			if want.Platform == "" || want.Platform == notify.Webhook {
				if n := len([]rune(want.Secret)); n < 16 {
					return huma.Error422UnprocessableEntity(
						"a webhook's secret is at least 16 characters")
				}
			}
			var err error
			row, err = notify.NewStore(tx).AddDestination(ctx, by, want, in.Chats)
			if err != nil {
				return asked(in.Logger, err)
			}
			// The address is recorded as its host and nothing more. For Slack
			// and for Teams the address *is* the credential — the path carries
			// the token and there is no other authentication — so writing it
			// whole into a record that is deliberately permanent puts a bearer
			// secret somewhere retiring the destination cannot take it out of.
			// The host is what an administrator reading the trail needs: which
			// service this deployment started talking to.
			where := parsed.Hostname()
			if row.Platform != notify.Webhook {
				where = row.Platform + " · " + deref(row.Channel)
			}
			if err := noted(ctx, tx, trail.Setting, "outbound · "+row.Name+" · "+row.Kind,
				nil, trail.Said(where, true)); err != nil {
				return notRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct {
			Status int
			Body   OutboundBody
		}{Status: http.StatusCreated, Body: OutboundBody{
			Name: row.Name, Kind: row.Kind, Platform: row.Platform, Host: hostOf(row.URL),
			Channel: deref(row.Channel), Topic: deref(row.Topic),
			Product: strings.TrimSpace(input.Body.Product), Team: strings.TrimSpace(input.Body.Team),
		}}, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "retire-outbound", Method: http.MethodDelete,
		Path:    path + "/{name}/{kind}",
		Summary: "Stop sending a kind somewhere",
		Description: "Takes a destination out of use. What was already sent stays recorded, " +
			"because where something went is a question asked afterwards.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusNoContent,
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Name string `path:"name"`
		Kind string `path:"kind"`
	}) (*struct{}, error) {
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		if err := changing(ctx, a.DB, a.Logger, func(ctx context.Context, tx bun.Tx) error {
			if _, _, err := administerable(ctx, a, tx); err != nil {
				return err
			}
			// Mapped before the trail row, which would otherwise record a
			// retirement that did not happen — and the destination goes on
			// receiving everything it takes.
			switch err := notify.NewStore(tx).
				RetireDestination(ctx, by, input.Name, input.Kind); {
			case errors.Is(err, access.ErrNothingMatched):
				return huma.Error404NotFound("no destination is recorded under that name and kind")
			case err != nil:
				return wentWrong(a.Logger, "that could not be retired", err)
			}
			if err := noted(ctx, tx, trail.Setting, "outbound · "+input.Name+" · "+input.Kind,
				trail.Said("in use", true), nil); err != nil {
				return notRecorded(a.Logger, err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
		return &struct{}{}, nil
	})
}

// deref is an optional string, or nothing.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
