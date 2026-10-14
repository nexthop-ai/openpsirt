// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package adminapi_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/httpapi/httpapitest"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

// published is the web tests' copy of what a session answer says about each
// outcome, which a test standing in for the server serves.
const published = "../../../web/src/test/outcomes.json"

var update = flag.Bool("update", false, "rewrite "+published+" from the session answer")

func TestWhatEachOutcomeClaimsIsPublishedFromTheRulesTheServerApplies(t *testing.T) {
	// A screen asking for dismissals, or requiring a justification, reads
	// these. A property published by hand beside the rule would let the two
	// disagree, and the screen would offer what the server refuses.
	httpapitest.TwoReach(t, func(t *testing.T, r *httpapitest.Reach) {
		var who struct {
			Outcomes []struct {
				Outcome            string `json:"outcome"`
				HidesRisk          bool   `json:"hides_risk"`
				Dated              bool   `json:"dated"`
				NeedsJustification bool   `json:"needs_justification"`
				Dismisses          bool   `json:"dismisses"`
			} `json:"outcomes"`
		}
		httpapitest.Read(t, r, "reader", "/v1/session/me", &who)

		every := triage.Outcomes()
		if len(who.Outcomes) != len(every) {
			t.Fatalf("published %d outcomes, the server records %d", len(who.Outcomes), len(every))
		}
		for i, got := range who.Outcomes {
			want := every[i]
			if got.Outcome != string(want) {
				t.Errorf("outcome %d is %q, want %q in the vocabulary's order", i, got.Outcome, want)
				continue
			}
			if got.HidesRisk != want.HidesRisk() || got.Dated != want.Dated() ||
				got.NeedsJustification != want.NeedsJustification() ||
				got.Dismisses != slices.Contains(triage.OutcomesDismissing(), want) {
				t.Errorf("%s is published as %+v, which is not the rule the server applies", want, got)
			}
		}

		// The web tests serve their copy in place of this answer, so it is
		// held to the answer rather than to somebody's reading of the rules.
		answer, err := json.MarshalIndent(who.Outcomes, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		answer = append(answer, '\n')
		if *update {
			if err := os.WriteFile(published, answer, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		kept, err := os.ReadFile(published)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(kept, answer) {
			t.Errorf("%s is not what the session answer publishes; rewrite it with "+
				"go test ./internal/httpapi/adminapi -run %s -update",
				published, t.Name())
		}
	})
}
