// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

// defaultTopic is the topic a Zulip channel is posted under where its
// destination names none.
const defaultTopic = "OpenPSIRT"

// ZulipBot carries notes through a Zulip bot's credentials.
//
// A bot's address and key reach a channel it may post in and a person
// directly, and find a person by their address.
type ZulipBot struct {
	site   string
	email  string
	key    string
	client *http.Client
}

// NewZulip returns a bot on the Zulip server at site, or nil where the
// deployment configured none.
func NewZulip(site, email, key string) *ZulipBot {
	return newZulip(site, email, key, outboundClient())
}

func newZulip(site, email, key string, client *http.Client) *ZulipBot {
	site, email, key = strings.TrimSpace(site), strings.TrimSpace(email), strings.TrimSpace(key)
	if site == "" || email == "" || key == "" {
		return nil
	}
	return &ZulipBot{site: strings.TrimRight(site, "/"), email: email, key: key, client: client}
}

// Platform is what Zulip is called in a destination.
func (b *ZulipBot) Platform() string { return Zulip }

// Timeout bounds one request.
func (b *ZulipBot) Timeout() time.Duration { return signalTimeout }

// zulipAnswer is the part of every Zulip answer that says whether it worked.
type zulipAnswer struct {
	Result string `json:"result"`
	Msg    string `json:"msg"`
	User   struct {
		UserID int64 `json:"user_id"`
	} `json:"user"`
}

// Find names the Zulip account registered to an address.
//
// The bot has to be able to see addresses, which an organization may limit;
// an address it cannot see answers as nobody.
func (b *ZulipBot) Find(ctx context.Context, email string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		b.site+"/api/v1/users/"+url.PathEscape(strings.TrimSpace(email)), nil)
	if err != nil {
		return "", fmt.Errorf("build the request: %w", err)
	}
	answer, status, err := b.ask(request)
	switch {
	case err != nil:
		return "", err
	case status == http.StatusBadRequest:
		return "", nil
	case answer.Result != "success":
		return "", fmt.Errorf("zulip refused to look somebody up: %s", answer.Msg)
	}
	return strconv.FormatInt(answer.User.UserID, 10), nil
}

// Direct sends a note to one person.
func (b *ZulipBot) Direct(ctx context.Context, account string, n Note) error {
	id, err := strconv.ParseInt(account, 10, 64)
	if err != nil {
		return fmt.Errorf("a zulip account is a number, and %q is not one", account)
	}
	to, err := json.Marshal([]int64{id})
	if err != nil {
		return err
	}
	return b.send(ctx, url.Values{
		"type": {"direct"}, "to": {string(to)}, "content": {zulipText(n)},
	})
}

// Post sends a note to a channel, under the destination's topic or the
// default one.
func (b *ZulipBot) Post(ctx context.Context, channel, topic string, n Note) error {
	if strings.TrimSpace(topic) == "" {
		topic = defaultTopic
	}
	return b.send(ctx, url.Values{
		"type": {"stream"}, "to": {channel}, "topic": {topic}, "content": {zulipText(n)},
	})
}

func (b *ZulipBot) send(ctx context.Context, form url.Values) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.site+"/api/v1/messages", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("build the request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	answer, status, err := b.ask(request)
	if err != nil {
		return err
	}
	if status >= 300 || answer.Result != "success" {
		return fmt.Errorf("zulip refused the message: %s", answer.Msg)
	}
	return nil
}

// ask makes one request as the bot and reads Zulip's answer, which is JSON
// whether it worked or not.
func (b *ZulipBot) ask(request *http.Request) (*zulipAnswer, int, error) {
	request.SetBasicAuth(b.email, b.key)
	request.Header.Set("User-Agent", "OpenPSIRT")
	response, err := b.client.Do(request)
	if err != nil {
		return nil, 0, withoutTheRequest(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusTooManyRequests {
		return nil, 0, fmt.Errorf("zulip asked to be sent less, for %s seconds",
			response.Header.Get("Retry-After"))
	}
	answer := new(zulipAnswer)
	if err := json.NewDecoder(io.LimitReader(response.Body, mostOfAnAnswer)).Decode(answer); err != nil {
		return nil, 0, fmt.Errorf("zulip answered %d: %w", response.StatusCode, err)
	}
	return answer, response.StatusCode, nil
}

// zulipLink keeps an address whole inside a markdown link, whose end is the
// first closing parenthesis.
var zulipLink = strings.NewReplacer("(", "%28", ")", "%29", " ", "%20")

// zulipText is a note in Zulip's markdown.
//
// Every string in the note is escaped as markdown, by the rule the release
// note uses, so nothing a producer named becomes a link, a mention of
// everybody or a quoted block. Zulip's mentions and channel links open with
// characters that rule escapes.
func zulipText(n Note) string {
	var b strings.Builder
	b.WriteString("**" + markdown.Literal(n.Heading) + "**")
	for _, line := range n.Lines {
		b.WriteString("\n- ")
		if line.Link != "" {
			b.WriteString("[" + markdown.Literal(line.Text) + "](" + zulipLink.Replace(line.Link) + ")")
		} else {
			b.WriteString(markdown.Literal(line.Text))
		}
	}
	if n.More > 0 {
		fmt.Fprintf(&b, "\n*and %d more*", n.More)
	}
	if n.Link != "" && len(n.Lines) > 1 {
		b.WriteString("\n[Open OpenPSIRT](" + zulipLink.Replace(n.Link) + ")")
	}
	return b.String()
}
