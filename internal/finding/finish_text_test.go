// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package finding_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	world "github.com/nexthop-ai/openpsirt/internal/dbtest/fixture"
	"github.com/nexthop-ai/openpsirt/internal/finding"
)

// A scanner writes what it likes to standard error, and its failure and its
// caution quote that text. PostgreSQL refuses invalid UTF-8 and a NUL in a
// text column, and MySQL and MariaDB refuse invalid UTF-8 in strict mode; a
// run whose end cannot be recorded stays open. What reaches each engine is
// text it stores, with each invalid byte read as U+FFFD and each NUL dropped.
func TestARunEndedInBytesThatAreNotTextIsRecordedOnEveryEngine(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		ctx := t.Context()
		w := world.New(t, db)
		findings := finding.NewStore(db.DB)
		run, err := findings.Begin(ctx, finding.Run{TargetID: w.Target.ID, Scanner: "grype", RanHere: true})
		if err != nil {
			t.Fatal(err)
		}
		said := "could not read /srv/caf\xe9 \xff\xfe\x00and went on \xe2\x82"
		if err := findings.Finish(ctx, run.ID, "0.112\xff", "db\x00", said, errors.New(said)); err != nil {
			t.Fatalf("the end of a run quoting bytes that are not text was refused: %v", err)
		}
		var got finding.Run
		if err := db.DB.NewSelect().Model(&got).Where(`"id" = ?`, run.ID).Scan(ctx); err != nil {
			t.Fatal(err)
		}
		if got.FinishedAt == nil {
			t.Fatal("the run was left open")
		}
		for name, value := range map[string]string{"failure": got.Failure, "caution": got.Caution,
			"scanner version": got.ScannerVersion, "database version": got.DatabaseVersion} {
			if !utf8.ValidString(value) || strings.Contains(value, "\x00") {
				t.Errorf("the %s was stored as %q", name, value)
			}
		}
		if !strings.Contains(got.Caution, "caf�") || !strings.Contains(got.Caution, "and went on") {
			t.Errorf("the text around the bad bytes was lost: %q", got.Caution)
		}
	})
}
