package migrations

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/database/migrate"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/engines"
)

// This package cannot use dbtest: dbtest builds the schema and the schema is
// these migrations, and Go allows no such cycle. The migration lock's own test
// is in the same position and opens a connection the same way.
const mysqlURLEnv = "OPENPSIRT_TEST_MYSQL_URL"

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestAMigrationThatFailedPartWayThroughCanBeRunAgain(t *testing.T) {
	// Every migration here is registered in the library's transactional form
	// and takes a transaction. On MySQL and MariaDB that transaction is
	// decorative: both commit implicitly before and after every
	// data-definition statement. A failure at statement N leaves 1 to N-1
	// committed, the rollback removes nothing, and no version row is written
	// — so the next start runs the same migration from statement 1 and fails
	// on "table already exists", for ever, with every replacement process
	// failing its startup probe in turn.
	//
	// PostgreSQL and SQLite have transactional data definition and never
	// reach this, which is why a four-engine run that only exercises the
	// success path says nothing about it.
	engines.SkipUnless(t, database.MySQL)
	url := os.Getenv(mysqlURLEnv)
	if url == "" {
		t.Skipf("%s is not set, so resuming is untested here", mysqlURLEnv)
	}
	target, err := database.ParseURL(url)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	db, err := database.Open(t.Context(), target)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx := migrate.WithEngine(t.Context(), db.Server.Engine, quiet())
	const (
		first  = "resume_probe_one"
		second = "resume_probe_two"
	)
	drop := func() {
		for _, name := range []string{second, first} {
			_, _ = db.ExecContext(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS "`+name+`"`)
		}
	}
	drop()
	t.Cleanup(drop)

	// A migration whose third statement cannot work — for a reason that is
	// not a name already taken, since that is the case the resume is *for*.
	// The first two are committed on this engine whatever happens to the
	// transaction around them.
	broken := []string{
		`CREATE TABLE "` + first + `" ("id" BIGINT)`,
		`CREATE TABLE "` + second + `" ("id" BIGINT)`,
		`CREATE TABLE "resume_probe_three" ("id" NOTATYPE)`,
	}
	tx, err := db.DB.DB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := apply(ctx, tx, broken); err == nil {
		t.Fatal("a statement the engine cannot run was reported as applied")
	}
	// Rolled back the way the library rolls a failed migration back, which on
	// this engine removes nothing.
	_ = tx.Rollback()

	for _, name := range []string{first, second} {
		var probe int
		if err := db.QueryRowContext(ctx, `SELECT 1 FROM "`+name+`"`).Scan(&probe); err != nil &&
			!database.IsNoRows(err) {
			t.Fatalf("this engine rolled back data definition after all, so there is nothing to resume: %v", err)
		}
	}

	// The same migration again, repaired — which is what the next start runs.
	// The first two statements are already done and must be stepped over
	// rather than collided with.
	repaired := []string{
		broken[0],
		broken[1],
		`CREATE TABLE "resume_probe_three" ("id" BIGINT)`,
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS "resume_probe_three"`)
	})
	tx, err = db.DB.DB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := apply(ctx, tx, repaired); err != nil {
		_ = tx.Rollback()
		t.Fatalf("running the migration again could not get past what it had already made: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestResumingStepsOverOnlyTheObjectAStatementNames(t *testing.T) {
	// A helper that skipped on any collision could hide a genuine one — two
	// migrations creating the same table under the same name — so what is
	// recognized is the exact object the statement names, and a statement
	// whose object cannot be identified is run rather than guessed at.
	for _, c := range []struct {
		what      string
		statement string
		named     bool
	}{
		{"a table", `CREATE TABLE "widget" ("id" BIGINT)`, true},
		{"an index", `CREATE INDEX "widget_idx" ON "widget" ("id")`, true},
		{"a unique index", `CREATE UNIQUE INDEX "widget_idx" ON "widget" ("id")`, true},
		{"a table declared over several lines", "CREATE TABLE \"widget\" (\n\t\"id\" BIGINT\n)", true},
		{"anything else", `INSERT INTO "widget" ("id") VALUES (1)`, false},
		{"a drop", `DROP TABLE "widget"`, false},
	} {
		t.Run(c.what, func(t *testing.T) {
			table := createsTable.FindStringSubmatch(c.statement)
			index := createsIndex.FindStringSubmatch(c.statement)
			if named := table != nil || index != nil; named != c.named {
				t.Errorf("%q reads as named=%v, want %v", c.statement, named, c.named)
			}
			if index != nil && index[2] != "widget" {
				t.Errorf("the index's table reads as %q", index[2])
			}
			if table != nil && table[1] != "widget" {
				t.Errorf("the table reads as %q", table[1])
			}
		})
	}
}

func TestDroppingAnIndexNamesItsTableOnlyWhereThatIsRequired(t *testing.T) {
	// Two engines spell this `DROP INDEX "n" ON "t"` and the other two take
	// the index name alone and refuse the table. It was written out twice in
	// two migrations, and a third that drops an index had nothing to stop it
	// being written a third time with one arm missing.
	//
	// Reading the statement the code builds rather than running it: there is
	// no engine here to disagree about what it says, only about which of the
	// two spellings it accepts, and a test that rebuilt the branch beside the
	// branch could not fail for the reason it is named.
	for _, c := range []struct {
		engine database.Engine
		want   string
	}{
		{database.MySQL, `DROP INDEX "widget_idx" ON "widget"`},
		{database.MariaDB, `DROP INDEX "widget_idx" ON "widget"`},
		{database.Postgres, `DROP INDEX "widget_idx"`},
		{database.SQLite, `DROP INDEX "widget_idx"`},
	} {
		t.Run(string(c.engine), func(t *testing.T) {
			ctx := migrate.WithEngine(t.Context(), c.engine, quiet())
			if got := dropIndexStatement(ctx, "widget", "widget_idx"); got != c.want {
				t.Errorf("%s drops an index with %q, want %q", c.engine, got, c.want)
			}
		})
	}
}
