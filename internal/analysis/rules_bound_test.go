// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/refusal"
	"github.com/nexthop-ai/openpsirt/internal/sourcelink"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestASuppressionRulePathPastTheLongestPathIsRefused(t *testing.T) {
	eachWorld(t, func(t *testing.T, w *world) {
		triager := w.holding(t, "triager", access.SecurityTestingTriage)
		for _, c := range []struct {
			prefix  string
			refused bool
		}{
			{strings.Repeat("a/", sourcelink.MostPathBytes/2) + "b", true},
			{strings.Repeat("a/", sourcelink.MostPathBytes/2-1) + "b", false},
		} {
			_, err := ProposeRule(t.Context(), w.DB.DB, triager, w.Product.ID, Proposal{
				Prefix: c.prefix, Reason: triage.UsedInTests, Reasoning: "fixtures",
			}, time.Now())
			switch {
			case c.refused && (!refusal.In(err) || !strings.Contains(err.Error(), "at most")):
				t.Errorf("a path of %d bytes was answered %v; want it refused for its length", len(c.prefix), err)
			case !c.refused && err != nil:
				t.Errorf("a path of %d bytes was refused: %v", len(c.prefix), err)
			}
		}
	})
}
