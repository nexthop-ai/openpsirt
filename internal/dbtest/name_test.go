// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"strings"
	"testing"
)

const schemaOne = "0f0f0f0f0f0f0f0f"

// A database is named for its schema and its slot, and for nothing about the
// package or the checkout it is tested from, so every binary built from one
// schema reuses the same few rather than migrating one of its own.
func TestADatabaseIsNamedForItsSchemaAndSlot(t *testing.T) {
	one := slotName(harnessPrefix, schemaOne, 1)
	two := slotName(harnessPrefix, schemaOne, 2)
	if one == two {
		t.Fatalf("two slots of one schema share the database %q", one)
	}
	for _, name := range []string{one, two, slotName(harnessPrefix, schemaOne, maxSlots)} {
		if !strings.HasPrefix(name, harnessPrefix) {
			t.Errorf("%q is not under the harness's prefix, so the clean never finds it", name)
		}
		// Every engine's identifier limit is at least 63 characters, and a
		// MySQL lock name at most 64.
		if len(name) > 63 {
			t.Errorf("%q is too long for an identifier", name)
		}
		if slotShape(harnessPrefix).FindStringSubmatch(name) == nil {
			t.Errorf("%q is not a slot's name, so a stale one is never collected", name)
		}
	}
	if again := slotName(harnessPrefix, schemaOne, 1); again != one {
		t.Errorf("the name is not stable between runs: %q then %q", one, again)
	}
	// The database and its lock are one name, which is how a clean finds the
	// lock that says whether a database is in use.
	if locks := locksOf(one); locks[0] != one {
		t.Errorf("the database %q is guarded by %v, want its own name first", one, locks)
	}
}

func TestAnEditedMigrationNamesADifferentDatabase(t *testing.T) {
	// A database is kept between runs and reused rather than migrated again,
	// so what stops a run from testing against last week's schema is that the
	// name carries the migrations. The applied version cannot do it: below 1.0
	// a schema change edits what declares the thing rather than adding a
	// migration beside it, so the version stays where it was while the tables
	// underneath are different.
	before := slotName(harnessPrefix, schemaOne, 1)
	after := slotName(harnessPrefix, "abcabcabcabcabca", 1)
	if before == after {
		t.Fatalf("two schemas share the database %q", before)
	}
	shape := slotShape(harnessPrefix)
	if shape.FindStringSubmatch(before)[1] == shape.FindStringSubmatch(after)[1] {
		t.Errorf("%q and %q read as one schema, so the older is never collected", before, after)
	}
}
