// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command release freezes a release's migrations and checks that a tag's
// release was frozen.
//
//	release freeze v0.3.0   write the record of the files v0.3.0 ships
//	release check v0.3.0    refuse a tag whose record is missing or stale
//
// Freezing writes the list of files and their digests. The schema each engine
// builds is written first, by a test, because only a test has the engines;
// make release-freeze runs both and then the check.
package main

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate/released"
)

const (
	root       = "internal/database/migrate/released"
	migrations = "internal/database/migrate/migrations"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: release freeze|check vX.Y.Z")
		os.Exit(2)
	}
	switch tag := os.Args[2]; os.Args[1] {
	case "freeze":
		// A tagged release's record is what it shipped, and freezing it again
		// would rewrite that record to whatever the tree holds now.
		if version, err := released.Base(tag); err == nil && tagged(version) {
			fmt.Fprintf(os.Stderr, "freeze %s: %s is tagged, and its record is what it shipped; "+
				"a later migration belongs to the next release\n", tag, version)
			os.Exit(1)
		}
		r, err := released.Freeze(root, migrations, tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "freeze %s: %v\n", tag, err)
			os.Exit(1)
		}
		fmt.Printf("%s: %d files recorded, through migration %d\n", r.Version, len(r.Digests), r.Last)
	case "check":
		faults, err := released.Check(root, migrations, tag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "check %s: %v\n", tag, err)
			os.Exit(1)
		}
		for _, fault := range faults {
			fmt.Fprintln(os.Stderr, fault)
		}
		if len(faults) > 0 {
			os.Exit(1)
		}
		fmt.Printf("%s ships the migrations it froze\n", tag)
	default:
		fmt.Fprintln(os.Stderr, "usage: release freeze|check vX.Y.Z")
		os.Exit(2)
	}
}

// tagged reports whether a release's own tag exists in this checkout.
func tagged(version string) bool {
	//nolint:gosec // G204: a version Base has already read as vX.Y.Z
	return exec.Command("git", "rev-parse", "-q", "--verify", "refs/tags/"+version).Run() == nil
}
