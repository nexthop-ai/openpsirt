package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/trail"
)

// OutboundBody is one destination this deployment sends to.
//
// The secret is never here. It signs our requests rather than authenticating
// anybody to us, so it is stored recoverably — and a configuration screen that
// showed it would put a shared secret on a page anybody with the settings
// right can read.
type OutboundBody struct {
	Name string `json:"name" doc:"What it is called, so a log line and a screen can name it"`
	Kind string `json:"kind" doc:"Which notifications go here, or * for all of them"`
	URL  string `json:"url"`
	// Sent and Failing say whether it is working, which is the question an
	// operator has about a destination and one nothing else answers.
	Sent    int    `json:"sent" doc:"How many things have gone there"`
	Failing int    `json:"failing" doc:"How many are being retried or have been given up on"`
	Because string `json:"because,omitempty" doc:"Why the last one failed, where one did"`
}

// registerOutbound configures where this deployment sends what it has to say .
func registerOutbound(api huma.API, in Ingest, a Administering) {
	const path = "/v1/outbound"

	huma.Register(api, requiring(huma.Operation{
		OperationID: "list-outbound", Method: http.MethodGet, Path: path,
		Summary: "List where this deployment sends things",
		Description: "The destinations configured, which kinds go to each, and whether they " +
			"are working.\n\n" +
			"**The signing secret is never returned.** It signs our requests rather than " +
			"authenticating anybody to us, so it has to be stored recoverably — and showing " +
			"it would put a shared secret on a page.",
		Tags: []string{"Administration"},
	}, deploymentWide, ""), func(ctx context.Context, _ *struct{}) (*listOutput[OutboundBody], error) {
		if _, _, err := administerable(ctx, a); err != nil {
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
				Name: row.Name, Kind: row.Kind, URL: row.URL,
				Sent: row.Sent, Failing: row.Failing, Because: row.Because,
			})
		}
		return out, nil
	})

	huma.Register(api, requiring(huma.Operation{
		OperationID: "add-outbound", Method: http.MethodPost, Path: path,
		Summary: "Send a kind of notification somewhere",
		Description: "Records a destination: a URL, a shared secret to sign with, and which " +
			"kinds go there — one kind by name, or `*` for all of them.\n\n" +
			"**One signed request, not an adapter each.** Slack, Teams, a tracker driven by " +
			"automation and paging all take an HTTP request with a JSON body, so one shape " +
			"reaches all of them.\n\n" +
			"**What it carries is what the channel rules already allow.** A notification " +
			"about a finding nobody has announced carries the fact that there is something " +
			"and a link, and nothing else — the same body a mail would carry, composed by the " +
			"same code.\n\n" +
			"**Every request is signed.** `X-OpenPSIRT-Timestamp` and " +
			"`X-OpenPSIRT-Signature: sha256=…`, an HMAC over the timestamp, a dot, and the " +
			"body — so a receiver can tell one of ours from one anybody could make, and " +
			"cannot replay yesterday's.\n\n" +
			"**https only, and a redirect is refused rather than followed.** The body is " +
			"signed and not encrypted, and a redirect asks us to send a signed request " +
			"somewhere else, which is what the restriction exists to prevent.",
		Tags: []string{"Administration"}, DefaultStatus: http.StatusCreated,
	}, deploymentWide, ""), func(ctx context.Context, input *struct {
		Body struct {
			Name   string `json:"name" minLength:"1" maxLength:"191"`
			Kind   string `json:"kind" minLength:"1" maxLength:"191" doc:"One notification kind, or * for all of them"`
			URL    string `json:"url" minLength:"1" maxLength:"1000" doc:"Where to send it. https only"`
			Secret string `json:"secret" minLength:"16" maxLength:"400" doc:"What requests are signed with. Never returned by any endpoint"`
		}
	}) (*struct {
		Status int
		Body   OutboundBody
	}, error) {
		_, _, err := administerable(ctx, a)
		if err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		// Normalized here so what is stored is the address as it parses. What
		// may be stored is decided by the store, where the rest of this
		// table's rules live.
		parsed, err := url.Parse(strings.TrimSpace(input.Body.URL))
		address := strings.TrimSpace(input.Body.URL)
		if err == nil {
			address = parsed.String()
		}
		row, err := notify.NewStore(in.DB.DB).AddDestination(ctx, by,
			input.Body.Name, input.Body.Kind, address, input.Body.Secret)
		if err != nil {
			return nil, asked(in.Logger, err)
		}
		// The address is recorded as its host and nothing more. For Slack and
		// for Teams the address *is* the credential — the path carries the
		// token and there is no other authentication — so writing it whole
		// into a record that is deliberately permanent puts a bearer secret
		// somewhere retiring the destination cannot take it out of. The host
		// is what an administrator reading the trail needs: which service this
		// deployment started talking to.
		noteAdminChange(ctx, a, trail.Setting, "outbound · "+row.Name+" · "+row.Kind,
			nil, trail.Said(parsed.Hostname(), true))
		return &struct {
			Status int
			Body   OutboundBody
		}{Status: http.StatusCreated, Body: OutboundBody{
			Name: row.Name, Kind: row.Kind, URL: row.URL,
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
		if _, _, err := administerable(ctx, a); err != nil {
			return nil, err
		}
		by, err := reading(ctx)
		if err != nil {
			return nil, err
		}
		// Mapped before the trail row, which would otherwise record a
		// retirement that did not happen — and the destination goes on
		// receiving everything it takes.
		switch err := notify.NewStore(in.DB.DB).
			RetireDestination(ctx, by, input.Name, input.Kind); {
		case errors.Is(err, access.ErrNothingMatched):
			return nil, huma.Error404NotFound("no destination is recorded under that name and kind")
		case err != nil:
			return nil, wentWrong(a.Logger, "that could not be retired", err)
		}
		noteAdminChange(ctx, a, trail.Setting, "outbound · "+input.Name+" · "+input.Kind,
			trail.Said("in use", true), nil)
		return &struct{}{}, nil
	})
}
