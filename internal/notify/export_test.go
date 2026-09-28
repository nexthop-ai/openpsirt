// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// SweepBatch is how many notifications one sweep carries.
//
// Exported for the test alone, which has to build a backlog of exactly that
// size to show that the sweep reaches past one: a second spelling of the
// number in the test would pass while the sweep used a different one.
const SweepBatch = sweepBatch

// StillToTell is how many notifications one destination's window holds.
//
// Exported so a test can ask the predicate directly. What wedges a sweep is a
// row that can never leave the window, and the window is bounded — so with
// only a handful of rows the sweep still reaches past them and a test that
// watches what was sent cannot tell a settled row from an unsettleable one.
func StillToTell(s *Signal, ctx context.Context, name string) (int, error) {
	var to Outbound
	if err := s.db.NewSelect().Model(&to).Where("name = ?", name).Scan(ctx); err != nil {
		return 0, err
	}
	rows, err := s.window(ctx, to)
	return len(rows), err
}

// TrustForTest points the sweep at a client that trusts a test server's
// certificate.
//
// Doing nothing else: the guard that refuses anything but https and refuses a
// redirect is what is being tested around, not switched off — a test server
// speaks https with a certificate nothing else trusts, and the alternative is
// testing the delivery over plain http, which is the one thing this refuses to
// do.
func TrustForTest(s *Signal, client *http.Client) {
	client.CheckRedirect = s.client.CheckRedirect
	client.Transport = &outboundGuard{inner: client.Transport}
	s.client = client
}

// SlackForTest is a bot pointed at a test server, through a client that
// trusts its certificate and keeps the guard that refuses anything but https.
func SlackForTest(token, api string, client *http.Client) *SlackBot {
	client.Transport = &outboundGuard{inner: client.Transport}
	return newSlack(token, api, client)
}

// ZulipForTest is a bot on a test server, on the same terms.
func ZulipForTest(site, email, key string, client *http.Client) *ZulipBot {
	client.Transport = &outboundGuard{inner: client.Transport}
	return newZulip(site, email, key, client)
}

// SharedKinds is the table of kinds a channel carries, so a test can hold it
// against every kind there is.
func SharedKinds() map[Kind]bool { return sharedKinds }

// NoteOf composes a note from notifications, as a sweep would for one reader.
func NoteOf(rows []Notification, products []string, baseURL string) Note {
	notings := make([]noting, len(rows))
	for i := range rows {
		notings[i] = noting{Notification: rows[i]}
		if i < len(products) {
			notings[i].Product = products[i]
		}
	}
	return noteOf(notings, baseURL)
}

// AtMostInANote is how many lines a note lists.
const AtMostInANote = atMostInANote

// SlackText and ZulipText are a note in each platform's markup.
func SlackText(n Note) string { return slackText(n) }
func ZulipText(n Note) string { return zulipText(n) }

// Plain is a note as plain text, which is what a test reads.
func (n Note) Plain() string {
	var b strings.Builder
	b.WriteString(n.Heading)
	for _, line := range n.Lines {
		b.WriteString("\n" + line.Text)
		if line.Link != "" {
			b.WriteString(" " + line.Link)
		}
	}
	if n.More > 0 {
		fmt.Fprintf(&b, "\nand %d more", n.More)
	}
	return b.String()
}
