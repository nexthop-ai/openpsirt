// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package reportsapi_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/reportsapi"
)

func TestTheIssueDocumentCountsOnlyTheJudgmentsInForceAsStanding(t *testing.T) {
	// A withdrawn judgment is on the record and stands nowhere, so the
	// sentence over a page of the record counts it as recorded and not as
	// standing.
	defer reportsapi.JudgmentsShown(1)()
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		place := r.Scanned(t)
		taken, _ := r.DecidedAt(t, place)
		if _, err := r.DB.DB.NewUpdate().Table("decision").
			Set(`"state" = ?`, "withdrawn").Set(`"live_key" = NULL`).
			Set(`"ended_at" = ?`, time.Now().UTC()).
			Where(`"id" = ?`, taken).Exec(t.Context()); err != nil {
			t.Fatal(err)
		}
		_, claim := r.DecidedAt(t, place)
		r.Agreed(t, claim)

		got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
			"/v1/issues/CVE-2026-9999/document", "")
		if got.Code != http.StatusOK {
			t.Fatalf("the document answered %d: %s", got.Code, got.Body.String())
		}
		want := "1 judgment stands, of 2 judgments recorded. The most recent is below."
		if !strings.Contains(got.Body.String(), want) {
			t.Errorf("the document does not say %q:\n%s", want, got.Body.String())
		}
	})
}

// Each place in the issue document says where the judgment there stands: one
// that lapsed when the code moved no longer stands, and one nobody judged
// says nobody has.
func TestTheIssueDocumentSaysWhereEachPlacesJudgmentStands(t *testing.T) {
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		r.ScannedSiblings(t)
		r.AgreedThenLapsed(t)
		for issue, want := range map[string]string{
			"CVE-2026-CURL1": "— the judgment here no longer stands",
			"CVE-2026-CURL2": "— nobody has said",
		} {
			got := httpapitest.AsPerson(t, r, "triager", http.MethodGet,
				"/v1/issues/"+issue+"/document", "")
			if got.Code != http.StatusOK {
				t.Fatalf("the document of %s answered %d: %s", issue, got.Code, got.Body.String())
			}
			if !strings.Contains(got.Body.String(), want) {
				t.Errorf("the document of %s does not say %q:\n%s", issue, want, got.Body.String())
			}
		}
	})
}
