// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// The trend counts as resolved only what the remediation figures count as a
// fix. A record taken back as invalid was never present, so it is in no open
// set; a superseded one left without being fixed, so it is not resolved work.
func TestTheTrendCountsOnlyAFixAsResolved(t *testing.T) {
	for _, one := range []struct {
		because finding.Closure
		present bool
	}{
		{finding.Invalid, false},
		{finding.Unaffected, false},
		{finding.Superseded, true},
	} {
		t.Run(string(one.because), func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				f.shipped(t, twoConsumers())
				now := time.Now().UTC()
				run := f.run(t)
				f.seenAt(t, run, now.Add(-20*24*time.Hour))
				if _, err := f.store.Apply(t.Context(), f.target, run,
					[]finding.Reported{found("CVE-2026-1", libnl)}); err != nil {
					t.Fatal(err)
				}
				f.closeIt(t, "CVE-2026-1", one.because, now.Add(-5*24*time.Hour))

				points, err := f.store.Trend(t.Context(), f.holding(t, access.PublicTriage), finding.Scope{},
					now.Add(-30*24*time.Hour), 24*time.Hour, 30, finding.Within{})
				if err != nil {
					t.Fatal(err)
				}
				resolved, present := 0, false
				for _, point := range points {
					resolved += point.Resolved
					if point.Open > 0 {
						present = true
					}
				}
				if resolved != 0 {
					t.Errorf("a finding closed as %s counted %d as resolved", one.because, resolved)
				}
				if present != one.present {
					t.Errorf("a finding closed as %s is in an open set: %v, want %v", one.because, present, one.present)
				}
			})
		})
	}
}
