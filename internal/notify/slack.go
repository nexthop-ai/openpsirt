// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// slackAPI is where Slack's web interface is.
const slackAPI = "https://slack.com/api"

// SlackBot carries notes through a Slack app's bot token.
//
// One token reaches both a channel the app has been added to and a person
// directly, and finds a person by the address their workspace holds for them.
// It needs the scopes that do those three things and nothing else.
type SlackBot struct {
	token  string
	api    string
	client *http.Client
}

// NewSlack returns a bot over token, or nil where the deployment configured
// none.
func NewSlack(token string) *SlackBot {
	return newSlack(token, slackAPI, outboundClient())
}

func newSlack(token, api string, client *http.Client) *SlackBot {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	return &SlackBot{token: token, api: strings.TrimRight(api, "/"), client: client}
}

// Platform is what Slack is called in a destination.
func (b *SlackBot) Platform() string { return Slack }

// Timeout bounds one request.
func (b *SlackBot) Timeout() time.Duration { return signalTimeout }

// slackAnswer is the part of every Slack answer that says whether it worked.
type slackAnswer struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	User  struct {
		ID string `json:"id"`
	} `json:"user"`
}

// Find names the Slack account registered to an address.
func (b *SlackBot) Find(ctx context.Context, email string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		b.api+"/users.lookupByEmail?email="+url.QueryEscape(strings.TrimSpace(email)), nil)
	if err != nil {
		return "", fmt.Errorf("build the request: %w", err)
	}
	answer, err := b.ask(request)
	switch {
	case err != nil:
		return "", err
	case answer.OK:
		return answer.User.ID, nil
	case answer.Error == "users_not_found":
		return "", nil
	}
	return "", fmt.Errorf("slack refused to look somebody up: %s", answer.Error)
}

// Direct sends a note to one person, which Slack delivers in the app's own
// conversation with them.
func (b *SlackBot) Direct(ctx context.Context, account string, n Note) error {
	return b.post(ctx, account, n)
}

// Post sends a note to a channel. Slack has no topics.
func (b *SlackBot) Post(ctx context.Context, channel, _ string, n Note) error {
	return b.post(ctx, channel, n)
}

func (b *SlackBot) post(ctx context.Context, channel string, n Note) error {
	body, err := json.Marshal(struct {
		Channel string `json:"channel"`
		Text    string `json:"text"`
		// Unfurling has Slack fetch every address the text carries and show
		// what it finds, which is a request to this deployment made by
		// somebody else's server.
		UnfurlLinks bool `json:"unfurl_links"`
		UnfurlMedia bool `json:"unfurl_media"`
	}{Channel: channel, Text: slackText(n)})
	if err != nil {
		return fmt.Errorf("compose a message: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.api+"/chat.postMessage", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build the request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	answer, err := b.ask(request)
	if err != nil {
		return err
	}
	if !answer.OK {
		return fmt.Errorf("slack refused the message: %s", answer.Error)
	}
	return nil
}

// ask makes one request with the token and reads Slack's answer.
func (b *SlackBot) ask(request *http.Request) (*slackAnswer, error) {
	request.Header.Set("Authorization", "Bearer "+b.token)
	request.Header.Set("User-Agent", "OpenPSIRT")
	response, err := b.client.Do(request)
	if err != nil {
		return nil, withoutTheRequest(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("slack asked to be sent less, for %s seconds",
			response.Header.Get("Retry-After"))
	}
	if response.StatusCode >= 300 {
		return nil, fmt.Errorf("slack answered %d", response.StatusCode)
	}
	answer := new(slackAnswer)
	if err := json.NewDecoder(io.LimitReader(response.Body, mostOfAnAnswer)).Decode(answer); err != nil {
		return nil, fmt.Errorf("read slack's answer: %w", err)
	}
	return answer, nil
}

// mostOfAnAnswer bounds what is read of a platform's answer. Every answer
// read here is a line of JSON, and a server that streams without end would
// otherwise grow the sweep until the process dies.
const mostOfAnAnswer = 1 << 16

// slackMarkup is the three characters Slack reads as its own markup: a link,
// a mention of a person, and a ping for a whole channel all open with `<`.
var slackMarkup = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// slackText is a note in Slack's markup.
//
// Every string in the note is escaped, so nothing a producer named becomes a
// link or a mention. Slack's emphasis has no escape and opens no link, so it
// is left alone rather than shown with a backslash before it.
func slackText(n Note) string {
	var b strings.Builder
	b.WriteString("*" + slackMarkup.Replace(n.Heading) + "*")
	for _, line := range n.Lines {
		b.WriteString("\n• ")
		if line.Link != "" {
			// A label is one line, and ends at the link's closing bracket.
			label := strings.Join(strings.Fields(slackMarkup.Replace(line.Text)), " ")
			b.WriteString("<" + slackMarkup.Replace(line.Link) + "|" + label + ">")
		} else {
			b.WriteString(slackMarkup.Replace(line.Text))
		}
	}
	if n.More > 0 {
		fmt.Fprintf(&b, "\n_and %d more_", n.More)
	}
	if n.Link != "" && len(n.Lines) > 1 {
		b.WriteString("\n<" + slackMarkup.Replace(n.Link) + "|Open OpenPSIRT>")
	}
	return b.String()
}

// withoutTheRequest is why a request failed, without the address it went to.
//
// The standard library writes the whole address into the error, and an
// address that finds a person carries their email address in it.
func withoutTheRequest(err error) error {
	var failed *url.Error
	if errors.As(err, &failed) {
		return fmt.Errorf("reach %s: %w", hostOnly(failed.URL), failed.Err)
	}
	return err
}

// hostOnly is the host an address names, or nothing.
func hostOnly(address string) string {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Host == "" {
		return "the platform"
	}
	return parsed.Host
}
