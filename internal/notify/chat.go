// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/weblink"
)

// The ways a destination is reached.
const (
	// Webhook is one signed HTTP request per notification.
	Webhook = "webhook"
	// Slack and Zulip are chat platforms this deployment holds a bot's
	// credential for, reaching a channel and a person directly.
	Slack = "slack"
	Zulip = "zulip"
)

// Chat is a chat platform this deployment holds a credential for.
//
// It carries a note and decides nothing about what the note says: that is
// composed once for every platform, so the rule about what may leave this
// deployment is enforced in one place.
type Chat interface {
	// Platform is what the platform is called in a destination and a log line.
	Platform() string
	// Find names the account registered on the platform to an email address,
	// or answers empty where nobody there is.
	Find(ctx context.Context, email string) (string, error)
	// Direct sends a note to one account, as Find named it.
	Direct(ctx context.Context, account string, n Note) error
	// Post sends a note to a channel, under a topic where the platform has
	// them and one is named.
	Post(ctx context.Context, channel, topic string, n Note) error
	// Timeout bounds one request, and is what the sweep's lease is sized from.
	Timeout() time.Duration
}

// Note is one message to a chat platform: a heading, and a line per thing.
//
// Every string in it is plain text. A platform escapes it as its own markup
// requires, because a component name, a publisher's name and a supplier's
// failure text are none of them chosen here.
type Note struct {
	Heading string
	Lines   []NoteLine
	// More is how many lines were left out, so a reader of a bounded note
	// knows it is bounded.
	More int
	// Link is the address the note as a whole points at.
	Link string
}

// NoteLine is one thing a note says, and where it points.
type NoteLine struct {
	Text string
	Link string
}

// sharedKinds is every kind about a product, a team or the deployment rather
// than about one person's own work.
//
// A shared kind goes to the most specific chat channel covering it, and to a
// person directly only where no channel does or they asked for it. Every other
// kind is somebody's own and goes to them directly, never to a channel. Kept
// against Kinds by a test, because this is a hand-maintained table over a
// closed vocabulary.
var sharedKinds = map[Kind]bool{
	Assigned: false, Mentioned: false, SentBack: false,
	BuildQuiet: true, HoldingAbsent: true, CriticalOnRelease: true,
	DisclosureDue: true, DisclosureNear: true, StatementRevised: true,
	ClaimWaiting: false, SentBackWaiting: false, DeferralEnding: false,
	QueueUntaken:   true,
	ApprovalUndone: false, ApprovalWithdrawn: false, ClaimLapsed: false,
	MergeSuperseded: true,
	BroughtIn:       false, Disclosed: false, Unanswered: true,
	VulnerabilityDataStale: true, RiskUnagreed: true, PairsConcentrated: true,
	SupplierSilent: true, InventoryMoved: true,
	ObligationOpen: true, ObligationNear: true, ObligationPassed: true,
}

// isShared says a kind is about a product, a team or the deployment rather
// than about one person's own work.
func isShared(kind Kind) bool { return sharedKinds[kind] }

// shared is every shared kind, for a query to narrow by.
func shared() []string {
	var out []string
	for _, kind := range Kinds() {
		if sharedKinds[kind] {
			out = append(out, string(kind))
		}
	}
	return out
}

// atMostInANote bounds how many lines one note lists.
//
// A note is read in a chat client, where forty lines scroll everything else
// away. What is over the bound is still in the application, and the note says
// how much it left out.
const atMostInANote = 12

// chatHorizon is how old a notification may be and still be carried to chat.
//
// Chat carries what is happening. A backlog from before a platform was
// configured, or from a day the platform was refusing, is in the application
// already, and delivered all at once it would bury whatever is new.
const chatHorizon = 24 * time.Hour

// noting is one notification a note may carry, with the product it names.
type noting struct {
	Notification `bun:",extend"`
	// Product is the name of the product it is about, where it is about one.
	Product string `bun:"product"`
}

// noteOf composes one note from everything one reader is to be told.
//
// One thing is said as itself. Several are grouped: by kind and product,
// because the bursts worth grouping — a night's scans, a feed moving, a rule
// placing work — produce many notifications of one kind in one product.
// Whatever is undisclosed becomes one line with a count, and the way in: what
// Compose allows an undisclosed notification to say outside this deployment
// is that there is something, and that line says it once.
func noteOf(rows []noting, baseURL string) Note {
	if len(rows) == 1 {
		said := Compose(rows[0].Notification, baseURL)
		line := NoteLine{Link: said.Link}
		if rows[0].Private {
			line.Text = "Something that has not been disclosed needs your attention."
		} else {
			line.Text = strings.TrimSpace(rows[0].Body)
		}
		return Note{Heading: said.Subject, Lines: []NoteLine{line}, Link: said.Link}
	}

	front := link(baseURL, weblink.Home())
	type group struct {
		kind    Kind
		product string
		rows    []noting
	}
	var groups []*group
	byKey := map[string]*group{}
	undisclosed := 0
	for _, row := range rows {
		if row.Private {
			undisclosed++
			continue
		}
		key := string(row.Kind) + "\x00" + strconv.FormatInt(value(row.ProductID), 10)
		g := byKey[key]
		if g == nil {
			g = &group{kind: row.Kind, product: row.Product}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.rows = append(g.rows, row)
	}

	note := Note{Heading: fmt.Sprintf("%d notifications", len(rows)), Link: front}
	if undisclosed > 0 {
		text := "1 thing that has not been disclosed needs your attention"
		if undisclosed > 1 {
			text = fmt.Sprintf("%d things that have not been disclosed need your attention",
				undisclosed)
		}
		note.Lines = append(note.Lines, NoteLine{Text: text, Link: front})
	}
	for _, g := range groups {
		if len(note.Lines) == atMostInANote {
			note.More++
			continue
		}
		subject := called[g.kind]
		if subject == "" {
			subject = generalSubject
		}
		if len(g.rows) == 1 {
			said := Compose(g.rows[0].Notification, baseURL)
			note.Lines = append(note.Lines, NoteLine{
				Text: subject + ": " + firstLine(g.rows[0].Body), Link: said.Link,
			})
			continue
		}
		text := fmt.Sprintf("%s: %d", subject, len(g.rows))
		if g.product != "" {
			text = fmt.Sprintf("%s in %s: %d", subject, g.product, len(g.rows))
		}
		note.Lines = append(note.Lines, NoteLine{Text: text, Link: front})
	}
	return note
}

// firstLine is the first line of a body, which is the sentence that says
// what happened.
func firstLine(body string) string {
	body = strings.TrimSpace(body)
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		body = body[:i]
	}
	return strings.TrimSpace(body)
}

// value is an optional identifier, or zero.
func value(id *int64) int64 {
	if id == nil {
		return 0
	}
	return *id
}

// Offering is the platforms a set of chats is, for a destination to be
// checked against.
func Offering(chats []Chat) []string {
	out := make([]string, 0, len(chats))
	for _, chat := range chats {
		if !slices.Contains(out, chat.Platform()) {
			out = append(out, chat.Platform())
		}
	}
	return out
}
