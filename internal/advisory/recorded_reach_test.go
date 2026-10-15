// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package advisory_test

import (
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/access"
)

func TestAnotherProductsRecordReachesNoAdvisoryReaderOutsideIt(t *testing.T) {
	// A flaw recorded in one product writes its summary, its minted name and
	// its rating onto the issue. An advisory in a second product holding the
	// same issue is read by people who may not read the first, and neither
	// its list of covered issues nor its document carries the record's words
	// to them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		identifier := f.recorded(t, f.master)
		f.alsoIn(t, identifier, f.other)
		named := f.covering(t, [2]string{"sonic", identifier})
		const summary = "The management socket answers before anyone authenticated."

		inSonic := access.NewPerson(f.second.ID, f.second.Identity, false, map[int64][]access.Role{
			f.product: {access.PublicRead, access.PrivateRead, access.PublicTriage, access.PrivateTriage},
		}, 0)
		said := func(t *testing.T, who access.Subject) (listed, document string) {
			t.Helper()
			_, held, err := f.store.Covers(ctx, who, named)
			if err != nil {
				t.Fatal(err)
			}
			if len(held) != 1 {
				t.Fatalf("the advisory covers %d issues, want 1", len(held))
			}
			made, err := f.store.ForAdvisory(ctx, who, issuer, named)
			if err != nil {
				t.Fatal(err)
			}
			var text []string
			for _, one := range made.Vulnerabilities {
				text = append(text, one.Title)
				for _, note := range one.Notes {
					text = append(text, note.Text)
				}
				text = append(text, one.CVE)
				for _, id := range one.IDs {
					text = append(text, id.Text)
				}
			}
			return held[0].Summary, strings.Join(text, "\n")
		}

		listed, document := said(t, inSonic)
		if listed != "" || strings.Contains(document, summary) {
			t.Errorf("a reader outside the recording product was told the record's summary: %q, %q",
				listed, document)
		}
		listed, document = said(t, f.who)
		if listed != summary || !strings.Contains(document, summary) {
			t.Errorf("a reader of both products was told %q, %q", listed, document)
		}
	})
}
