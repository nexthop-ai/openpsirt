// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

// TestMeasuresCanBeAskedAboutOneTeamOrOneProduct is the narrowing that made
// per-team figures possible at all.
//
// The report took no scope of any kind, so a manager asking how their own
// people were doing read the deployment's numbers — and in a deployment with
// more than one team that is somebody else's answer with their name on it.
func TestMeasuresCanBeAskedAboutOneTeamOrOneProduct(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		ctx := t.Context()
		r.scannedTwoIssues(t)

		// Two people argue one claim each, and only one of them is on the
		// team. Two, because a narrowing that keeps everybody is
		// indistinguishable from one that works.
		r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		r.claimed(t, "private-triage", "CVE-2026-1000", "linux-image", dismissal)

		rights := access.NewStore(r.db.DB)
		team, err := rights.DeclareTeam(ctx, "platform", "Platform")
		if err != nil {
			t.Fatal(err)
		}
		var member int64
		if err := r.db.DB.NewSelect().Table("person").ColumnExpr("id").
			Where("identity = ?", "triager").Scan(ctx, &member); err != nil {
			t.Fatal(err)
		}
		if err := rights.AddToTeam(ctx, team.ID, member, member); err != nil {
			t.Fatal(err)
		}

		worked := func(t *testing.T, query string) map[string]int {
			t.Helper()
			var body struct {
				Worked []struct {
					Person   string `json:"person"`
					Proposed int    `json:"proposed"`
				} `json:"throughput"`
			}
			read(t, r, "private-triage", "/v1/measures"+query, &body)
			out := map[string]int{}
			for _, one := range body.Worked {
				out[one.Person] = one.Proposed
			}
			return out
		}

		// Everybody, which is what this answered before and still answers
		// when nothing is asked for.
		if all := worked(t, ""); all["triager"] != 1 || all["private-triage"] != 1 {
			t.Fatalf("the deployment's own figures read %v", all)
		}

		// The team's own, which is one of the two.
		theirs := worked(t, "?team=platform")
		if theirs["triager"] != 1 {
			t.Errorf("the team's member proposed %d in the team's figures", theirs["triager"])
		}
		if _, held := theirs["private-triage"]; held {
			t.Errorf("somebody not on the team is in the team's figures: %v", theirs)
		}

		// A product the judgments were made in, and one nobody made any in.
		if mine := worked(t, "?product=mine"); len(mine) != 2 {
			t.Errorf("the product the work happened in reports %v", mine)
		}
		if got := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/measures?product=theirs", ""); got.Code < 400 {
			t.Errorf("a product this reader cannot see answered %d", got.Code)
		}

		// A team nobody declared is a 404 rather than the deployment's
		// figures: a narrowing that silently widens is the one mistake a
		// narrowing must not make.
		if got := asPerson(t, r, "private-triage", http.MethodGet,
			"/v1/measures?team=nobodys", ""); got.Code != http.StatusNotFound {
			t.Errorf("an unknown team answered %d", got.Code)
		}
	})
}

// TestATeamWithNobodyOnItMeasuresNothing is the same rule from the other side.
func TestATeamWithNobodyOnItMeasuresNothing(t *testing.T) {
	eachReach(t, func(t *testing.T, r *reach) {
		r.scannedTwoIssues(t)
		r.claimed(t, "triager", "CVE-2026-9999", "linux-image", dismissal)
		if _, err := access.NewStore(r.db.DB).DeclareTeam(t.Context(),
			"empty", "Nobody"); err != nil {
			t.Fatal(err)
		}
		var body struct {
			Worked []struct {
				Person string `json:"person"`
			} `json:"throughput"`
			Until string `json:"until"`
		}
		read(t, r, "private-triage", "/v1/measures?team=empty", &body)
		if len(body.Worked) != 0 {
			t.Errorf("a team with nobody on it measured %d people", len(body.Worked))
		}
		// And it still says what period it covered, so an empty answer is
		// readable as an empty answer rather than as a failed one.
		if _, err := time.Parse(time.DateOnly, body.Until); err != nil {
			t.Errorf("the report does not say what period it covered: %q", body.Until)
		}
	})
}
