// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package assignapi_test

import (
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
)

// queueNotices sweeps, and is what a person's open queue notices say.
//
// Read from the table rather than through the notification area, which
// narrows by the same grants and so would hide a row the sweep had no
// business writing.
func queueNotices(t *testing.T, r *httpapitest.Reach, who string) []string {
	t.Helper()
	ctx := t.Context()
	if _, _, err := notify.NewWatch(r.DB.DB, slog.New(slog.NewTextHandler(io.Discard, nil))).Once(ctx); err != nil {
		t.Fatal(err)
	}
	person, err := r.Rights.Ensure(ctx, who, httpapitest.ShownAs(who), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var rows []notify.Notification
	if err := r.DB.DB.NewSelect().Model(&rows).
		Where(`"person_id" = ?`, person.ID).Where(`"kind" = ?`, notify.QueueUntaken).
		Where(`"cleared_at" IS NULL`).Scan(ctx); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if row.TeamID == nil || !row.Internal {
			t.Errorf("a lead queue notice was written without its team or as disclosed: %+v", row)
		}
		out = append(out, row.Body)
	}
	return out
}

// A lead routed to a team's queue and left there is told to the members who
// read internal work, as any queued work is, and to nobody else on the team.
func TestALeadLeftInATeamsQueueIsToldToTheMembersWhoReadIt(t *testing.T) {
	httpapitest.EachReach(t, func(t *testing.T, r *httpapitest.Reach) {
		occurrence := httpapitest.SeededLead(t, r)
		granted(t, r, "internal-triager", access.Assigner)
		if made := httpapitest.AsPerson(t, r, "admin", http.MethodPost, "/v1/teams",
			`{"name":"analysis-desk","members":["internal-reader","reader"]}`); made.Code != http.StatusCreated {
			t.Fatalf("declaring a team answered %d: %s", made.Code, made.Body.String())
		}
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPut, leadAt(occurrence)+"/assignment",
			`{"team":"analysis-desk"}`); got.Code != http.StatusNoContent {
			t.Fatalf("queueing the lead with the team answered %d: %s", got.Code, got.Body)
		}
		if told := queueNotices(t, r, "internal-reader"); len(told) != 0 {
			t.Fatalf("a lead queued a moment ago was told as untaken: %q", told)
		}
		if _, err := r.DB.DB.NewUpdate().Table("finding").
			Set(`"assigned_at" = ?`, time.Now().UTC().Add(-30*24*time.Hour)).
			Where(`"occurrence_identity" = ?`, occurrence).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		told := queueNotices(t, r, "internal-reader")
		if len(told) != 1 || !strings.Contains(told[0], "1 static analysis lead") {
			t.Errorf("a member reading internal work was told %q; want the one lead waiting", told)
		}
		if told := queueNotices(t, r, "reader"); len(told) != 0 {
			t.Errorf("a member reading only disclosed work was told of internal work: %q", told)
		}
		// Judged, it is being worked on, and no longer waits in the queue.
		if got := httpapitest.AsPerson(t, r, "internal-triager", http.MethodPost, leadAt(occurrence)+"/decision",
			`{"outcome":"confirmed","reasoning":"p leaks on the early return"}`); got.Code != http.StatusCreated {
			t.Fatalf("confirming answered %d: %s", got.Code, got.Body)
		}
		if told := queueNotices(t, r, "internal-reader"); len(told) != 0 {
			t.Errorf("a lead a decision stands on was still told as waiting: %q", told)
		}
	})
}
