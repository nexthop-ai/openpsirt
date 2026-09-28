// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest

import (
	"strings"
	"testing"
)

const schemaOne = "0f0f0f0f0f0f0f0f"

const httpapiPath = "github.com/nexthop-ai/openpsirt/internal/httpapi.test"

// A database is named for its package and its slot, and for nothing about the
// checkout it is tested from, so every checkout reuses the same few rather
// than leaving a set behind each time one is deleted.
func TestADatabaseIsNamedForItsPackageAndSlot(t *testing.T) {
	one := databaseName(httpapiPath, 1, schemaOne)
	two := databaseName(httpapiPath, 2, schemaOne)
	if one == two {
		t.Fatalf("two slots of one package share the database %q", one)
	}
	for _, name := range []string{one, two, databaseName(httpapiPath, maxSlots, schemaOne)} {
		// The readable part stays: somebody listing the server's databases
		// should see which package each belongs to.
		if !strings.HasPrefix(name, "openpsirt_t_httpapi_") {
			t.Errorf("%q does not name its package", name)
		}
		// Every engine's identifier limit is at least 63 characters, and a
		// MySQL lock name at most 64.
		if len(name) > 63 {
			t.Errorf("%q is too long for an identifier", name)
		}
	}
	if again := databaseName(httpapiPath, 1, schemaOne); again != one {
		t.Errorf("the name is not stable between runs: %q then %q", one, again)
	}
	// Two packages whose readable parts are cut to the same text still differ.
	long := "github.com/nexthop-ai/openpsirt/internal/averyveryverylongpackagename"
	if databaseName(long+"one.test", 1, schemaOne) == databaseName(long+"two.test", 1, schemaOne) {
		t.Error("two packages cut to one readable name share a database")
	}
	// The slot's lock is the name up to the fingerprint, which is how a clean
	// finds the lock that says whether a database is in use.
	if got, want := slotOf(one), slotName(httpapiPath, 1); got != want {
		t.Errorf("the database %q belongs to the slot %q, want %q", one, got, want)
	}
}

func TestAnEditedMigrationNamesADifferentDatabase(t *testing.T) {
	// A database is kept between runs and re-used rather than re-migrated, so
	// what stops a run from testing against last week's schema is that the
	// name carries the migrations. The applied version cannot do it: below 1.0
	// a schema change edits what declares the thing rather than adding a
	// migration beside it, so the version stays where it was
	// while the tables underneath are different.
	before := databaseName(httpapiPath, 1, schemaOne)
	after := databaseName(httpapiPath, 1, "abcabcabcabcabca")
	if before == after {
		t.Fatalf("two schemas share the database %q", before)
	}
	// And both sit under one prefix, which is how the older one is found and
	// dropped rather than left on the server for good.
	if packagePrefix(before) != packagePrefix(after) {
		t.Errorf("%q and %q are not under one prefix, so nothing collects the older",
			before, after)
	}
	if !strings.HasPrefix(packagePrefix(before), "openpsirt_t_httpapi_") {
		t.Errorf("the prefix %q does not name the package", packagePrefix(before))
	}
	// Narrow enough to leave another slot of the same package alone: the
	// prefix carries the slot, not only the package.
	elsewhere := databaseName(httpapiPath, 2, schemaOne)
	if strings.HasPrefix(elsewhere, packagePrefix(before)) {
		t.Errorf("%q sits under another slot's prefix %q", elsewhere, packagePrefix(before))
	}
}
