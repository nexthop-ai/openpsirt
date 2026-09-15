package finding_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/markdown"
)

func TestEveryFieldSomebodyTypesGoesThroughTheSubmissionPolicy(t *testing.T) {
	// The policy runs before storage and is the security control: what is in
	// the column is then known to have passed what was in force when it
	// arrived. Five fields a person types skipped it entirely — the only
	// check was that the string was not blank — so a row could hold raw
	// markup, a scheme a browser acts on, and text past the bound a render is
	// kept inside, forever, under an append-only rule.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		f.shipped(t, twoConsumers())
		if _, err := f.store.Apply(ctx, f.target, f.run(t), []finding.Reported{
			found("CVE-2026-1", libnl),
		}); err != nil {
			t.Fatal(err)
		}
		f.recorded(t, 1, "someone")
		who := f.holding(t, access.PrivateTriage)
		issue := f.issue(t, "CVE-2026-1")
		const raw = "Looks fine <script>alert(1)</script>"
		tooLong := strings.Repeat("a", markdown.MaxBytes+1)

		refused := func(name string, err error) {
			t.Helper()
			if err == nil {
				t.Errorf("%s stored text the submission policy refuses", name)
				return
			}
			var faults markdown.Faults
			if !errors.As(err, &faults) {
				t.Errorf("%s refused with %q, which is not the policy talking", name, err)
			}
		}

		_, err := f.store.Assess(ctx, who, f.productID, issue, "critical", raw)
		refused("an assessment", err)
		_, err = f.store.Assess(ctx, who, f.productID, issue, "critical", tooLong)
		refused("an assessment", err)

		_, err = f.store.Extend(ctx, who, f.productID, issue,
			time.Now().UTC().AddDate(0, 0, 30), raw)
		refused("an embargo extension", err)

		open := f.open(t)
		_, err = f.store.Resolve(ctx, who, f.target, open[0].VulnerabilityID, raw)
		refused("a closure by a person", err)
	})
}
