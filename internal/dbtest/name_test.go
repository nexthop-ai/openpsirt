package dbtest

import (
	"strings"
	"testing"
)

const schemaOne = "0f0f0f0f0f0f0f0f"

func TestTwoCheckoutsOfOnePackageGetDifferentDatabases(t *testing.T) {
	// The import path is the same in every checkout of this repository, so a
	// name made from it alone was the same too — and a second worktree run
	// against the same servers dropped the first one's database mid-run.
	// The directory a package is tested from is what tells checkouts apart.
	path := "github.com/nexthop-ai/openpsirt/internal/httpapi.test"
	one := databaseName(path, "/home/somebody/git/openpsirt/internal/httpapi", schemaOne)
	two := databaseName(path, "/home/somebody/git/openpsirt-2/internal/httpapi", schemaOne)
	if one == two {
		t.Fatalf("two checkouts of one package share the database %q", one)
	}
	for _, name := range []string{one, two} {
		// The readable part stays: somebody listing the server's databases
		// should see which package each belongs to.
		if !strings.HasPrefix(name, "openpsirt_t_httpapi_") {
			t.Errorf("%q does not name its package", name)
		}
		// Every engine's identifier limit is at least 63 characters.
		if len(name) > 63 {
			t.Errorf("%q is too long for an identifier", name)
		}
	}
	if again := databaseName(path, "/home/somebody/git/openpsirt/internal/httpapi", schemaOne); again != one {
		t.Errorf("the name is not stable between runs: %q then %q", one, again)
	}
}

func TestAnEditedMigrationNamesADifferentDatabase(t *testing.T) {
	// A database is kept between runs and re-used rather than re-migrated, so
	// what stops a run from testing against last week's schema is that the
	// name carries the migrations. The applied version cannot do it: until the
	// first release a schema change edits the migration that created the thing
	// rather than adding one beside it, so the version stays where it was
	// while the tables underneath are different.
	path := "github.com/nexthop-ai/openpsirt/internal/httpapi.test"
	dir := "/home/somebody/git/openpsirt/internal/httpapi"
	before := databaseName(path, dir, schemaOne)
	after := databaseName(path, dir, "abcabcabcabcabca")
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
	// Narrow enough to leave another checkout of the same package alone: the
	// prefix carries the identity hash, not only the package's name.
	elsewhere := databaseName(path, "/home/somebody/git/openpsirt-2/internal/httpapi", schemaOne)
	if strings.HasPrefix(elsewhere, packagePrefix(before)) {
		t.Errorf("%q sits under another checkout's prefix %q", elsewhere, packagePrefix(before))
	}
}
