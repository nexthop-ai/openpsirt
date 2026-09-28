// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

func TestEveryKindSaysWhetherAChannelCarriesIt(t *testing.T) {
	table := notify.SharedKinds()
	for _, kind := range notify.Kinds() {
		if _, ok := table[kind]; !ok {
			t.Errorf("%s is neither somebody's own nor about a product, a team or the deployment", kind)
		}
	}
	if len(table) != len(notify.Kinds()) {
		t.Errorf("the table names %d kinds and there are %d", len(table), len(notify.Kinds()))
	}
}

// hostile is what a producer or a supplier could put in a component name.
const hostile = "<!channel> <https://evil.example|Download the fix> [fix](https://evil.example) @**all** & more"

func TestSlackCarriesThirdPartyTextAsText(t *testing.T) {
	got := notify.SlackText(notify.Note{
		Heading: "Work assigned to you",
		Lines:   []notify.NoteLine{{Text: hostile, Link: "https://psirt.example/f?a=1&b=2"}},
	})
	for _, bad := range []string{"<!channel>", "<https://evil.example", "|Download the fix>"} {
		if strings.Contains(got, bad) {
			t.Errorf("slack would read %q as markup:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "<https://psirt.example/f?a=1&amp;b=2|") {
		t.Errorf("the address this deployment composed is not a link:\n%s", got)
	}
}

func TestZulipCarriesThirdPartyTextAsText(t *testing.T) {
	got := notify.ZulipText(notify.Note{
		Heading: "Work assigned to you",
		Lines:   []notify.NoteLine{{Text: hostile, Link: "https://psirt.example/p/a(b)"}},
	})
	for _, bad := range []string{"@**all**", "[fix](", "](https://evil"} {
		if strings.Contains(got, bad) {
			t.Errorf("zulip would read %q as markup:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "](https://psirt.example/p/a%28b%29)") {
		t.Errorf("the address this deployment composed is not a whole link:\n%s", got)
	}
}

func TestANoteBoundsWhatItListsAndSaysSo(t *testing.T) {
	var rows []notify.Notification
	var names []string
	for i := 0; i < notify.AtMostInANote+3; i++ {
		product := int64(i + 1)
		rows = append(rows, notify.Notification{
			Kind: notify.BuildQuiet, Body: "quiet", ProductID: &product,
		})
		names = append(names, "product")
	}
	note := notify.NoteOf(rows, names, "https://psirt.example")
	if len(note.Lines) != notify.AtMostInANote || note.More != 3 {
		t.Errorf("listed %d lines and said %d more, want %d and 3",
			len(note.Lines), note.More, notify.AtMostInANote)
	}
}

// slackServer answers as Slack would, and records what it was asked.
type slackServer struct {
	auth    []string
	posted  []map[string]any
	lookups []string
}

func (s *slackServer) handle(w http.ResponseWriter, r *http.Request) {
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/users.lookupByEmail":
		email := r.URL.Query().Get("email")
		s.lookups = append(s.lookups, email)
		if email == "ana@example.com" {
			_, _ = io.WriteString(w, `{"ok":true,"user":{"id":"U123"}}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":false,"error":"users_not_found"}`)
	case "/api/chat.postMessage":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.posted = append(s.posted, body)
		if body["channel"] == "C-GONE" {
			_, _ = io.WriteString(w, `{"ok":false,"error":"channel_not_found"}`)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	default:
		http.NotFound(w, r)
	}
}

func TestSlackFindsPeopleAndSendsWithTheBotToken(t *testing.T) {
	seen := &slackServer{}
	server := httptest.NewTLSServer(http.HandlerFunc(seen.handle))
	defer server.Close()
	bot := notify.SlackForTest("xoxb-test", server.URL+"/api", server.Client())
	ctx := t.Context()

	if who, err := bot.Find(ctx, "ana@example.com"); err != nil || who != "U123" {
		t.Errorf("found %q (%v), want U123", who, err)
	}
	if who, err := bot.Find(ctx, "nobody@example.com"); err != nil || who != "" {
		t.Errorf("somebody Slack does not know was found as %q (%v)", who, err)
	}
	if err := bot.Direct(ctx, "U123", notify.Note{Heading: "Hello"}); err != nil {
		t.Fatal(err)
	}
	if err := bot.Post(ctx, "C-GONE", "", notify.Note{Heading: "Hello"}); err == nil ||
		!strings.Contains(err.Error(), "channel_not_found") {
		t.Errorf("a refusal was read as %v", err)
	}
	for _, auth := range seen.auth {
		if auth != "Bearer xoxb-test" {
			t.Errorf("a request carried %q", auth)
		}
	}
	if len(seen.posted) == 0 || seen.posted[0]["channel"] != "U123" ||
		seen.posted[0]["unfurl_links"] != false || seen.posted[0]["unfurl_media"] != false {
		t.Errorf("the message was posted as %v", seen.posted)
	}
}

func TestZulipFindsPeopleAndSendsAsTheBot(t *testing.T) {
	var forms []url.Values
	var users []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, key, ok := r.BasicAuth(); !ok || name != "bot@zulip.example" || key != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"result":"error","msg":"unauthorized"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/v1/users/"):
			users = append(users, strings.TrimPrefix(r.URL.Path, "/api/v1/users/"))
			if strings.HasSuffix(r.URL.Path, "ana@example.com") {
				_, _ = io.WriteString(w, `{"result":"success","user":{"user_id":42}}`)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"result":"error","msg":"No such user"}`)
		case r.URL.Path == "/api/v1/messages":
			_ = r.ParseForm()
			forms = append(forms, r.PostForm)
			_, _ = io.WriteString(w, `{"result":"success","id":1}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	bot := notify.ZulipForTest(server.URL, "bot@zulip.example", "k", server.Client())
	ctx := t.Context()

	if who, err := bot.Find(ctx, "ana@example.com"); err != nil || who != "42" {
		t.Errorf("found %q (%v), want 42", who, err)
	}
	if who, err := bot.Find(ctx, "nobody@example.com"); err != nil || who != "" {
		t.Errorf("somebody Zulip does not know was found as %q (%v)", who, err)
	}
	if err := bot.Direct(ctx, "42", notify.Note{Heading: "Hello"}); err != nil {
		t.Fatal(err)
	}
	if err := bot.Post(ctx, "security", "", notify.Note{Heading: "Hello"}); err != nil {
		t.Fatal(err)
	}
	if len(forms) != 2 {
		t.Fatalf("sent %d messages, want 2", len(forms))
	}
	if forms[0].Get("type") != "direct" || forms[0].Get("to") != "[42]" {
		t.Errorf("the direct message was sent as %v", forms[0])
	}
	if forms[1].Get("type") != "stream" || forms[1].Get("to") != "security" ||
		forms[1].Get("topic") != "OpenPSIRT" {
		t.Errorf("the channel post was sent as %v", forms[1])
	}
}

func TestAChatDestinationIsRefusedWhatItCouldNeverCarry(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		dbtest.Reset(t, db)
		admin, err := access.NewStore(db.DB).Ensure(ctx, "admin@example.com", "Admin",
			access.Stated(true), nil)
		if err != nil {
			t.Fatal(err)
		}
		store := notify.NewStore(db.DB)
		product, team := int64(1), int64(1)
		for name, d := range map[string]notify.Destination{
			"a platform nobody configured": {Platform: notify.Zulip, Channel: "c"},
			"no channel":                   {Platform: notify.Slack},
			"what is somebody's own":       {Platform: notify.Slack, Channel: "c", Kind: string(notify.Assigned)},
			"a product and a team":         {Platform: notify.Slack, Channel: "c", ProductID: &product, TeamID: &team},
			"a topic on Slack":             {Platform: notify.Slack, Channel: "c", Topic: "t"},
			"an address":                   {Platform: notify.Slack, Channel: "c", URL: "https://x.example"},
			"a webhook with a scope": {URL: "https://x.example", Secret: "a-shared-secret-long-enough",
				ProductID: &product},
			"a webhook with no secret": {URL: "https://x.example"},
		} {
			d.Name = "refused"
			if d.Kind == "" {
				d.Kind = notify.Everything
			}
			if _, err := store.AddDestination(ctx, asks(t, db, admin), d,
				[]string{notify.Slack}); err == nil {
				t.Errorf("%s was accepted", name)
			}
		}
	})
}
