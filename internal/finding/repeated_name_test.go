// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"context"
	"slices"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// namesOf is every name recorded for the issue a name resolves to, in the
// order they were recorded.
func (f *fixture) namesOf(t *testing.T, id int64) []string {
	t.Helper()
	var names []string
	if err := f.db.DB.NewSelect().TableExpr(`"vulnerability_alias" AS "va"`).
		ColumnExpr("va.identifier").Where("va.vulnerability_id = ?", id).
		OrderExpr("va.id ASC").Scan(t.Context(), &names); err != nil {
		t.Fatal(err)
	}
	return names
}

// interning is the two ways a run of reports is interned: from one read of
// what is on record about them all, and each report alone.
var interning = []struct {
	name   string
	intern func(v *finding.Vulnerabilities, ctx context.Context, reported []finding.Named) (map[string]int64, error)
}{
	{"together", (*finding.Vulnerabilities).Intern},
	{"alone", (*finding.Vulnerabilities).InternAlone},
}

func TestAReportNamingOneNameTwiceAppliesAsOneIssueWithTheNameOnce(t *testing.T) {
	// A report's identifier can also appear among its aliases, and two of its
	// aliases can be one name. Names are recorded under a unique index once
	// normalized, so a name repeated in any case or spacing is one name.
	each(t, func(t *testing.T, f *fixture) {
		f.shipped(t, twoConsumers())
		reported := finding.Reported{
			Issue: finding.Named{
				Identifier: "CVE-2026-202",
				Aliases: []string{
					"CVE-2026-202", "cve-2026-202", " CVE-2026-202 ",
					"GHSA-aaaa-bbbb-cccc", "ghsa-AAAA-bbbb-cccc", "GHSA-aaaa-bbbb-cccc ",
				},
				Severity: "high",
			},
			Component: libnl, FixState: finding.NoFix,
		}
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{reported}); err != nil {
			t.Fatalf("a report naming one name twice did not apply: %v", err)
		}
		opened := f.open(t)
		if len(opened) != 2 {
			t.Fatalf("opened %d findings, want one per consumer", len(opened))
		}
		if opened[0].VulnerabilityID != opened[1].VulnerabilityID {
			t.Fatalf("the findings are against issues %d and %d, want one",
				opened[0].VulnerabilityID, opened[1].VulnerabilityID)
		}
		got := f.namesOf(t, opened[0].VulnerabilityID)
		slices.Sort(got)
		if want := []string{"CVE-2026-202", "GHSA-AAAA-BBBB-CCCC"}; !slices.Equal(got, want) {
			t.Errorf("the issue is recorded under %q, want %q", got, want)
		}
		// The same report again finds every name recorded and writes none.
		if _, err := f.store.Apply(t.Context(), f.target, f.run(t), []finding.Reported{reported}); err != nil {
			t.Fatalf("the same report again did not apply: %v", err)
		}
	})
}

func TestANameRepeatedInAReportIsRecordedOnceOnEitherInterningPath(t *testing.T) {
	// The read of what is on record answers for an issue already held, and a
	// new issue or one the read cannot answer for is resolved alone. Each
	// path records the names it has not seen, so each is given a report
	// carrying a new name twice, for a new issue and for one already held.
	for _, path := range interning {
		t.Run(path.name, func(t *testing.T) {
			each(t, func(t *testing.T, f *fixture) {
				ctx := t.Context()
				reports := [][]finding.Named{
					{{Identifier: "CVE-2026-303", Aliases: []string{"cve-2026-303", "GHSA-dddd-eeee-ffff",
						"ghsa-dddd-eeee-ffff"}, Severity: "high"}},
					{{Identifier: "CVE-2026-404", Severity: "high"}},
					{{Identifier: "CVE-2026-404", Aliases: []string{"OSV-2026-404", " osv-2026-404",
						"CVE-2026-404"}, Severity: "high"}},
				}
				want := map[string][]string{
					"CVE-2026-303": {"CVE-2026-303", "GHSA-DDDD-EEEE-FFFF"},
					"CVE-2026-404": {"CVE-2026-404", "OSV-2026-404"},
				}
				byName := map[string]int64{}
				for _, reported := range reports {
					got, err := path.intern(finding.NewVulnerabilities(f.db.DB), ctx, reported)
					if err != nil {
						t.Errorf("interning %s with aliases %q: %v", reported[0].Identifier, reported[0].Aliases, err)
						continue
					}
					for name, id := range got {
						byName[name] = id
					}
				}
				for identifier, names := range want {
					id, held := byName[identifier]
					if !held {
						t.Errorf("%s resolved to no issue", identifier)
						continue
					}
					if got := f.namesOf(t, id); !slices.Equal(got, names) {
						t.Errorf("%s is recorded under %q, want %q", identifier, got, names)
					}
				}
				if byName["OSV-2026-404"] != byName["CVE-2026-404"] {
					t.Errorf("OSV-2026-404 resolved to %d and CVE-2026-404 to %d, want one issue",
						byName["OSV-2026-404"], byName["CVE-2026-404"])
				}
			})
		})
	}
}
