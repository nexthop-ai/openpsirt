// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package triage_test

import (
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/triage"
)

func TestWhereTheWorkWentNamesOnlyComponentsItsReaderMayRead(t *testing.T) {
	// A place is a pair of names with no product in it. The component a
	// judgment is counted under is read off the findings in its own product
	// that the reader may read, never off the same pair in another product
	// or a finding undisclosed to them.
	each(t, func(t *testing.T, f *fixture) {
		ctx := t.Context()
		here := f.build(t, f.product, "for-effort")
		f.finds(t, here, f.component(t, "libfoo", "1.2.3"), "place-a", access.Public)
		f.finds(t, f.build(t, f.product, "embargoed"), f.component(t, "libhidden", "1.0.0"),
			"place-a", access.Private)
		f.finds(t, f.build(t, f.secondProduct(t), "theirs"), f.component(t, "libtheirs", "2.0.0"),
			"place-a", access.Public)
		f.proposes(t, f.triager, f.placeIn(f.product, "place-a", access.Public))

		spent, _, err := f.store.Effort(ctx, f.reviewer, triage.Measuring{},
			time.Time{}, time.Now().UTC().Add(time.Hour), 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		named := map[string]bool{}
		for _, row := range spent {
			named[row.Component] = true
		}
		if !named["libfoo"] {
			t.Errorf("the component the judgment is about is not named: %v", named)
		}
		for _, hidden := range []string{"libhidden", "libtheirs"} {
			if named[hidden] {
				t.Errorf("%s was named to a reader who may not read a finding of it: %v", hidden, named)
			}
		}
	})
}
