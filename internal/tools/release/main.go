// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command release freezes a release's migrations and checks that a tag's
// release was frozen.
//
//	release guard v0.3.0    refuse a release whose tag exists
//	release freeze v0.3.0   write the record of the files v0.3.0 ships
//	release check v0.3.0    refuse a tag whose record is missing or stale
//
// Freezing writes the list of files and their digests. The schema each engine
// builds is written first, by a test, because only a test has the engines;
// make release-freeze runs the guard, then both, then the check. The guard
// runs before the test, because the test rewrites the schema records too, so
// it refuses everything freezing would refuse: a tagged release, and every
// release the tree cannot freeze.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/nexthop-ai/openpsirt/internal/database/migrate/released"
)

const (
	root       = "internal/database/migrate/released"
	migrations = "internal/database/migrate/migrations"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: release guard|freeze|check vX.Y.Z")
		os.Exit(2)
	}
	switch tag := os.Args[2]; os.Args[1] {
	case "guard":
		if err := guard(".", tag); err != nil {
			fmt.Fprintf(os.Stderr, "freeze %s: %v\n", tag, err)
			os.Exit(1)
		}
	case "freeze":
		if err := guard(".", tag); err != nil {
			fmt.Fprintf(os.Stderr, "freeze %s: %v\n", tag, err)
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
		fmt.Fprintln(os.Stderr, "usage: release guard|freeze|check vX.Y.Z")
		os.Exit(2)
	}
}

// guard refuses to freeze a release whose tag exists in the checkout at dir,
// and refuses where git cannot say. A tagged release's record is what it
// shipped, and freezing it again would rewrite that record to whatever the
// tree holds now. It then refuses whatever freezing itself would, before the
// schema records are written: a checkout without tags otherwise rewrites a
// shipped release's schema and is refused only afterwards.
func guard(dir, tag string) error {
	version, err := released.Base(tag)
	if err != nil {
		return err
	}
	shipped, err := tagged(dir, version)
	if err != nil {
		return err
	}
	if shipped {
		return fmt.Errorf("%s is tagged, and its record is what it shipped; "+
			"a later migration belongs to the next release", version)
	}
	return released.Ready(filepath.Join(dir, root), filepath.Join(dir, migrations), tag)
}

// tagged reports whether a release's own tag exists in the checkout at dir.
// git answers a missing tag with exit status 1 and every failure — no
// repository, no git — with another, and only the first reads as untagged.
func tagged(dir, version string) (bool, error) {
	//nolint:gosec // G204: a version Base has already read as vX.Y.Z
	cmd := exec.Command("git", "rev-parse", "-q", "--verify", "refs/tags/"+version)
	cmd.Dir = dir
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return false, nil
	default:
		return false, fmt.Errorf("git could not say whether %s is tagged, so nothing was frozen: %w", version, err)
	}
}
