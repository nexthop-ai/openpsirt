// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package ingest_test

import (
	"testing"
	"time"
)

// A take writing the value a row already holds is skipped on MySQL and
// MariaDB, and a cluster never certifies it, so a read asking whether its
// scan was overtaken would not wait out a newer scan applied on another node.
func TestEveryReadTakesItsBuildWithAFreshValue(t *testing.T) {
	eachReader(t, func(t *testing.T, f *readerFixture) {
		var seen []string
		for i, inventory := range []string{anInventory, aSmallerInventory} {
			f.accept(t, f.branch, time.Now().UTC().Add(time.Duration(i-2)*time.Hour), inventory)
			if result, err := f.reader.Once(t.Context()); err != nil || result == nil {
				t.Fatalf("read: %v %v", result, err)
			}
			var by *string
			if err := f.db.DB.NewSelect().Table("build").Column("taken_by").
				Where(`"id" = ?`, f.branch).Scan(t.Context(), &by); err != nil {
				t.Fatal(err)
			}
			value := ""
			if by != nil {
				value = *by
			}
			seen = append(seen, value)
		}
		if seen[0] == "" || seen[0] == seen[1] {
			t.Errorf("the build was taken with %q then %q, want a fresh value each time", seen[0], seen[1])
		}
	})
}
