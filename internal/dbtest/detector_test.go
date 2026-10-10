// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build race

package dbtest_test

import (
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// racyChildEnv marks the child process that runs the deliberate race.
const racyChildEnv = "OPENPSIRT_TEST_RACY_CHILD"

// The race pass leaves the SQLite engine's translated C and its C library
// uninstrumented, and nothing else. A race between this package's code and the
// standard library's database layer is still reported: database/sql writes a
// scanned value into a variable this test reads on another goroutine, and the
// child process running that race is expected to print the detector's report
// naming both sides. A pattern widened past the SQLite engine's packages
// leaves one side or both uninstrumented, and the report never comes.
//
// Verified by widening the pattern to every package: the child then exits
// cleanly and this test fails.
func TestARaceBetweenOurCodeAndTheDatabaseLayerIsReported(t *testing.T) {
	if os.Getenv(racyChildEnv) != "" {
		raceAcrossAQuery(t)
		return
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0],
		"-test.run=^TestARaceBetweenOurCodeAndTheDatabaseLayerIsReported$", "-test.count=1")
	cmd.Env = append(os.Environ(), racyChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	report := string(out)
	if err == nil {
		t.Fatalf("the child ran a race and exited cleanly, so the detector saw nothing:\n%s", report)
	}
	for _, want := range []string{
		"WARNING: DATA RACE",
		"database/sql.convertAssign",
		"dbtest_test.raceAcrossAQuery",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("the child's output does not contain %q:\n%s", want, report)
		}
	}
}

// raceAcrossAQuery scans query results into a variable on one goroutine while
// another reads it. The reader touches nothing else, so nothing it does orders
// it against the writer.
func raceAcrossAQuery(t *testing.T) {
	dbtest.Only(t, database.SQLite, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		var shared string
		var scanned error
		read := 0
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 50 {
				if scanned = db.QueryRowContext(ctx, `SELECT 'scanned'`).Scan(&shared); scanned != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				read += len(shared)
			}
		}()
		wg.Wait()
		if scanned != nil {
			t.Fatal(scanned)
		}
		t.Logf("read %d bytes", read)
	})
}
