// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
)

func TestAChatChannelIsAnAdministratorsToConfigure(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		const at = "/v1/outbound"
		const kernel = `{"name":"mine-channel","kind":"*","platform":"slack",` +
			`"channel":"C0123","product":"mine"}`
		for _, who := range []string{"reader", "triager"} {
			if got := httpapitest.AsPerson(t, r, who, http.MethodPost, at, kernel); got.Code != http.StatusForbidden {
				t.Errorf("%s configured a chat channel, answering %d", who, got.Code)
			}
		}
		if got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, at, kernel); got.Code != http.StatusCreated {
			t.Fatalf("configuring a chat channel answered %d: %s", got.Code, got.Body.String())
		}

		listed := httpapitest.AsPerson(t, r, "admin", http.MethodGet, at, "")
		var destinations struct {
			Items []struct {
				Name     string `json:"name"`
				Platform string `json:"platform"`
				Channel  string `json:"channel"`
				Product  string `json:"product"`
				Host     string `json:"host"`
			} `json:"items"`
		}
		if err := json.Unmarshal(listed.Body.Bytes(), &destinations); err != nil {
			t.Fatal(err)
		}
		if len(destinations.Items) != 1 || destinations.Items[0].Platform != "slack" ||
			destinations.Items[0].Channel != "C0123" || destinations.Items[0].Product != "mine" ||
			destinations.Items[0].Host != "" {
			t.Errorf("the channel is listed as %+v", destinations.Items)
		}

		for what, c := range map[string]struct {
			body string
			want int
		}{
			"a product nobody declared": {`{"name":"x","kind":"*","platform":"slack",` +
				`"channel":"C1","product":"nope"}`, http.StatusNotFound},
			"a team nobody declared": {`{"name":"x","kind":"*","platform":"slack",` +
				`"channel":"C1","team":"nope"}`, http.StatusNotFound},
			"a platform not offered": {`{"name":"x","kind":"*","platform":"zulip",` +
				`"channel":"security"}`, http.StatusUnprocessableEntity},
			"a kind addressed to one person": {`{"name":"x","kind":"assigned",` +
				`"platform":"slack","channel":"C1"}`, http.StatusUnprocessableEntity},
			"a webhook with a short secret": {`{"name":"x","kind":"*",` +
				`"url":"https://hooks.example.test/x","secret":"short"}`, http.StatusUnprocessableEntity},
		} {
			if got := httpapitest.AsPerson(t, r, "admin", http.MethodPost, at, c.body); got.Code != c.want {
				t.Errorf("%s answered %d, want %d: %s", what, got.Code, c.want, got.Body.String())
			}
		}
	})
}

func TestWhatSomebodyIsSentInChatIsTheirsToChoose(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		const at = "/v1/session/me/chat"
		if got := httpapitest.AsPerson(t, r, "", http.MethodPut, at, `{"direct":true}`); got.Code != http.StatusUnauthorized {
			t.Errorf("nobody chose, answering %d", got.Code)
		}
		if got := httpapitest.AsPerson(t, r, "reader", http.MethodPut, at,
			`{"direct":false,"shared":true}`); got.Code != http.StatusUnprocessableEntity {
			t.Errorf("what the channels carry with direct messages off answered %d: %s",
				got.Code, got.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "reader", http.MethodPut, at,
			`{"direct":true,"shared":true}`); got.Code != http.StatusNoContent {
			t.Fatalf("choosing answered %d: %s", got.Code, got.Body.String())
		}

		me := httpapitest.AsPerson(t, r, "reader", http.MethodGet, "/v1/session/me", "")
		var who struct {
			Chat *struct {
				Platforms []string `json:"platforms"`
				Direct    bool     `json:"direct"`
				Shared    bool     `json:"shared"`
			} `json:"chat"`
		}
		if err := json.Unmarshal(me.Body.Bytes(), &who); err != nil {
			t.Fatal(err)
		}
		if who.Chat == nil || !who.Chat.Direct || !who.Chat.Shared ||
			len(who.Chat.Platforms) != 1 || who.Chat.Platforms[0] != "slack" {
			t.Errorf("the session says %+v about chat", who.Chat)
		}
	})
}
