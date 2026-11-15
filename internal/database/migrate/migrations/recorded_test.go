// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package migrations_test

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// firstRecorded is the first migration that writes the record of its change
// in its own transaction, the one that made the record.
const firstRecorded = 47

// migrationFile is a migration's file name, with its version.
var migrationFile = regexp.MustCompile(`^(\d{5})_[a-z0-9_]+\.go$`)

// recording is a migration's call writing the record of its change, with the
// version it names.
var recording = regexp.MustCompile(`releaseUpgrade\(ctx, sqldb, (\d+),`)

// unrecorded reports whether a migration's source, of version, runs its
// upgrade without writing the record of the change to that version in the
// same transaction.
func unrecorded(source string, version int) bool {
	m := recording.FindStringSubmatch(source)
	return m == nil || m[1] != strconv.Itoa(version) || strings.Contains(source, "inV020(")
}

// Every release's migration from the one that made the record of schema
// changes on writes that record in its own transaction, so a process killed
// between the commit and the migration library recording the version leaves
// serving instances paused on every engine.
func TestEveryReleaseMigrationRecordsItsChange(t *testing.T) {
	if !unrecorded("return inV020(ctx, sqldb, upgradeV0140)", 48) {
		t.Error("a migration calling inV020 directly was not reported")
	}
	if !unrecorded("return releaseUpgrade(ctx, sqldb, 47, upgradeV0140)", 48) {
		t.Error("a migration recording another version than its own was not reported")
	}
	if unrecorded("return releaseUpgrade(ctx, sqldb, 48, upgradeV0140)", 48) {
		t.Error("a migration recording its own version through releaseUpgrade was reported")
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	examined := 0
	for _, entry := range entries {
		m := migrationFile.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		version, err := strconv.Atoi(m[1])
		if err != nil || version < firstRecorded {
			continue
		}
		examined++
		source, err := os.ReadFile(entry.Name()) //nolint:gosec // this package's own sources
		if err != nil {
			t.Fatal(err)
		}
		if unrecorded(string(source), version) {
			t.Errorf("%s runs its upgrade without releaseUpgrade naming version %d, so nothing records the "+
				"change in its transaction", entry.Name(), version)
		}
	}
	if examined == 0 {
		t.Fatal("no migration from the first that records its change was found, so this checked nothing")
	}
}
