// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package notify_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// A lookup that never reached Slack says which host it could not reach and
// not the address it asked for, which carries the person's email address.
func TestASlackLookupThatFailsDoesNotRepeatTheAddress(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	client := server.Client()
	at := server.URL
	server.Close()
	bot := notify.SlackForTest("xoxb-test", at+"/api", client)
	who, err := bot.Find(t.Context(), "ana@example.com")
	if err == nil || who != "" {
		t.Fatalf("a server that is gone answered %q, %v", who, err)
	}
	for _, leaked := range []string{"ana", "example.com", "lookupByEmail"} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("the failure carries %q: %v", leaked, err)
		}
	}
	if !strings.Contains(err.Error(), strings.TrimPrefix(at, "https://")) {
		t.Errorf("the failure does not say which host: %v", err)
	}
}

// An answer from Slack that is not an answer is a failure, never an account
// or a message sent.
func TestASlackAnswerThatIsNotOneIsAFailure(t *testing.T) {
	for _, c := range []struct {
		what   string
		answer func(w http.ResponseWriter)
		says   string
	}{
		{"asked to slow down", func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
		}, "for 30 seconds"},
		{"a server error", func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) }, "500"},
		{"a page in place of JSON", func(w http.ResponseWriter) { _, _ = io.WriteString(w, "<html>") }, "read slack's answer"},
		{"a refusal", func(w http.ResponseWriter) { _, _ = io.WriteString(w, `{"ok":false,"error":"invalid_auth"}`) }, "invalid_auth"},
	} {
		t.Run(c.what, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				c.answer(w)
			}))
			defer server.Close()
			bot := notify.SlackForTest("xoxb-test", server.URL+"/api", server.Client())
			if who, err := bot.Find(t.Context(), "ana@example.com"); err == nil || who != "" ||
				!strings.Contains(err.Error(), c.says) {
				t.Errorf("a lookup answered %q, %v; want a failure saying %q", who, err, c.says)
			}
			if err := bot.Post(t.Context(), "C1", "", notify.Note{Heading: "Hello"}); err == nil ||
				!strings.Contains(err.Error(), c.says) {
				t.Errorf("a post answered %v; want a failure saying %q", err, c.says)
			}
		})
	}
}

// Zulip answers a lookup it cannot make with 400, which is nobody there; any
// other refusal, an answer that is not JSON and a request to slow down are
// failures.
func TestAZulipAnswerThatIsNotOneIsAFailure(t *testing.T) {
	for _, c := range []struct {
		what   string
		answer func(w http.ResponseWriter)
		says   string
	}{
		{"asked to slow down", func(w http.ResponseWriter) {
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusTooManyRequests)
		}, "for 30 seconds"},
		{"refused", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"result":"error","msg":"Invalid API key"}`)
		}, "Invalid API key"},
		{"a page in place of JSON", func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, "<html>")
		}, "zulip answered 502"},
	} {
		t.Run(c.what, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				c.answer(w)
			}))
			defer server.Close()
			bot := notify.ZulipForTest(server.URL, "bot@zulip.example", "k", server.Client())
			if who, err := bot.Find(t.Context(), "ana@example.com"); err == nil || who != "" ||
				!strings.Contains(err.Error(), c.says) {
				t.Errorf("a lookup answered %q, %v; want a failure saying %q", who, err, c.says)
			}
			if err := bot.Post(t.Context(), "security", "", notify.Note{Heading: "Hello"}); err == nil ||
				!strings.Contains(err.Error(), c.says) {
				t.Errorf("a post answered %v; want a failure saying %q", err, c.says)
			}
		})
	}
}

// A line with no link is escaped too, a note over its bound says how many it
// left out, and a note of several lines ends on a link into the deployment.
func TestANoteOfSeveralLinesIsEscapedBoundedAndLinked(t *testing.T) {
	note := notify.Note{
		Heading: "Things to look at",
		Lines: []notify.NoteLine{
			{Text: hostile},
			{Text: "libfoo", Link: "https://psirt.example/f/1"},
		},
		More: 3,
		Link: "https://psirt.example/",
	}
	slack := notify.SlackText(note)
	for _, want := range []string{"&lt;!channel&gt;", "_and 3 more_", "<https://psirt.example/|Open OpenPSIRT>"} {
		if !strings.Contains(slack, want) {
			t.Errorf("slack is sent %q, want it to carry %q", slack, want)
		}
	}
	if strings.Contains(slack, "<!channel>") {
		t.Errorf("an unlinked line reaches slack as markup: %q", slack)
	}
	zulip := notify.ZulipText(note)
	for _, want := range []string{"*and 3 more*", "[Open OpenPSIRT](https://psirt.example/)"} {
		if !strings.Contains(zulip, want) {
			t.Errorf("zulip is sent %q, want it to carry %q", zulip, want)
		}
	}
	if strings.Contains(zulip, "@**all**") {
		t.Errorf("an unlinked line reaches zulip as markup: %q", zulip)
	}
}
