// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"testing"

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
	for _, r := range records {
		if len(r.Digests) == 0 {
			t.Errorf("%s records no files, so nothing of it was checked", r.Version)
		}
		faults, err := released.Held(recorded, ".", r)
		if err != nil {
			t.Fatal(err)
		}
		for _, fault := range faults {
			t.Error(fault)
		}
	}
}
