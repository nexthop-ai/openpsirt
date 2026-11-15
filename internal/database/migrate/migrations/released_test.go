// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"testing"
	"testing/fstest"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate/released"
)

// recorded is where each tagged release's record of its migrations is kept,
// from this package's directory.
const recorded = "../released"

// Every file a tagged release shipped for its migrations is here as the
// release tagged it, and every file here that belongs to a tagged release is
// one it shipped. A database the release built has applied exactly those, so
// what they do is fixed: an edit to one changes a schema deployments already
// hold without changing what they have recorded.
func TestEveryTaggedReleaseShipsTheFilesItTagged(t *testing.T) {
	records, err := released.All(recorded)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		t.Fatal("no release is recorded, so nothing was checked")
	}
	// A release that changes no schema records no files, and is still held:
	// a file numbered or named for it is a fault. Across every release,
	// though, no file recorded means nothing was compared.
	files := 0
	for _, r := range records {
		files += len(r.Digests)
		faults, err := released.Held(recorded, ".", r)
		if err != nil {
			t.Fatal(err)
		}
		for _, fault := range faults {
			t.Error(fault)
		}
	}
	if files == 0 {
		t.Fatal("no release records a file, so nothing was checked")
	}
}

// The version a build expects is the highest migration by the rule the
// release records read. The embedding includes test files, and one named like
// a migration would otherwise put the build ahead of every database it made.
func TestTheExpectedVersionCountsNoTestFile(t *testing.T) {
	names := []string{"00046_v0120.go", "00047_v0130.go", "00048_v0130_test.go", "fingerprint.go"}
	got, err := highestOf(names)
	if err != nil {
		t.Fatal(err)
	}
	if got != 47 {
		t.Errorf("a build carrying %v expects version %d, want 47", names, got)
	}
}

// A test file builds no schema, so editing one leaves the fingerprint where it
// was, and editing a migration source moves it.
func TestTheFingerprintIgnoresTestFiles(t *testing.T) {
	base := fstest.MapFS{
		"00047_v0130.go":     {Data: []byte("package migrations // 47")},
		"upgrade.go":         {Data: []byte("package migrations // upgrade")},
		"v0130_node_test.go": {Data: []byte("package migrations // test")},
	}
	edited := func(name, content string) fstest.MapFS {
		out := fstest.MapFS{}
		for k, v := range base {
			out[k] = v
		}
		out[name] = &fstest.MapFile{Data: []byte(content)}
		return out
	}
	want, err := fingerprintOf(base)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fingerprintOf(edited("v0130_node_test.go", "package migrations // edited")); err != nil || got != want {
		t.Errorf("editing a test file moved the fingerprint from %s to %s (%v)", want, got, err)
	}
	if got, err := fingerprintOf(edited("upgrade.go", "package migrations // edited")); err != nil || got == want {
		t.Errorf("editing a migration source left the fingerprint at %s (%v)", want, err)
	}
}
