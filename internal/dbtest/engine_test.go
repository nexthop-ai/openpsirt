// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package dbtest_test

import (
	"os"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
)

// The engines gate greps this test's output for each engine by name, and until
// now that only proved a subtest with that *label* had run. The label comes
// from a list in this package; the connection comes from an environment
// variable. Nothing checked that the two agreed.
//
// So pointing the MySQL and MariaDB URLs at the same PostgreSQL server — four
// URLs differing only in a port digit, which is exactly the slip somebody
// makes — produced four green lines and "every engine ran". The suite would
// then have tested one engine three times while reporting three.
//
// This asks the server what it is and compares that against the name the
// harness gave it.
func TestEachEngineIsTheEngineItSaysItIs(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		// The label, not the engine the connection thinks it is. Those are
		// two different facts and comparing the connection against itself
		// proves nothing: a MySQL URL pointed at a PostgreSQL server opens as
		// PostgreSQL and agrees with itself perfectly, while the gate greps
		// for a line saying "mysql". The label is what the gate believes, so
		// the label is what has to be checked.
		parts := strings.Split(t.Name(), "/")
		labeled := database.Engine(parts[len(parts)-1])

		// The URL's own scheme must match the label. This is what catches the
		// likeliest slip — four URLs differing by a port digit, one pasted
		// over another — because a `postgres://` URL under the `mysql` label
		// opens as PostgreSQL and then agrees with itself about being
		// PostgreSQL.
		if db.Server.Engine != labeled {
			t.Fatalf("the connection labeled %s opened as %s, so this run "+
				"tested a different engine than it reported", labeled, db.Server.Engine)
		}

		var said string
		query := "SELECT version()"
		if labeled == database.SQLite {
			query = "SELECT sqlite_version()"
		}
		if err := db.QueryRowContext(t.Context(), query).Scan(&said); err != nil {
			t.Fatalf("ask the server what it is: %v", err)
		}

		want, known := banners[labeled]
		if !known {
			t.Fatalf("no banner is recorded for %q, so this test cannot tell "+
				"which engine it connected to", labeled)
		}

		lower := strings.ToLower(said)
		for _, says := range want.says {
			if !strings.Contains(lower, says) {
				t.Errorf("the connection labeled %s reports itself as %q, "+
					"so this run tested a different engine than it said",
					labeled, said)
			}
		}
		for _, other := range want.mustNotSay {
			if strings.Contains(lower, other) {
				t.Errorf("the connection labeled %s reports itself as %q", labeled, said)
			}
		}
	})
}

// banners is what each engine's own version string says about itself, and what
// it must not say.
//
// MariaDB reports itself through MySQL's function and says "MariaDB" in the
// text, which is the only thing telling the two apart from here. MySQL is the
// awkward one: it has no banner of its own, so it is named by what it must
// *not* say. SQLite answers a function no other engine has, so getting an
// answer at all is most of the check.
var banners = map[database.Engine]struct{ says, mustNotSay []string }{
	database.Postgres: {says: []string{"postgresql"}},
	database.MariaDB:  {says: []string{"mariadb"}},
	database.MySQL:    {mustNotSay: []string{"mariadb", "postgresql", "sqlite"}},
	database.SQLite:   {mustNotSay: []string{"mariadb", "postgresql"}},
}

// Every engine has to have an entry, and this is what says so. The identity
// test itself cannot: it runs only against engines that are configured, so on
// a SQLite-only machine a missing PostgreSQL entry would go unnoticed until
// CI. Read with the two-value form there for the same reason — a map read
// one-valued hands back the empty string, and strings.Contains is satisfied by
// every possible banner, so the check would pass for an engine it knows
// nothing about.
func TestEveryEngineHasABannerRecorded(t *testing.T) {
	if len(database.Engines()) == 0 {
		t.Fatal("there are no engines, so this checked nothing")
	}
	for _, engine := range database.Engines() {
		want, known := banners[engine]
		if !known {
			t.Errorf("%s has no banner recorded, so the identity check cannot "+
				"tell whether a connection labeled %s reached it", engine, engine)
			continue
		}
		if len(want.says) == 0 && len(want.mustNotSay) == 0 {
			t.Errorf("%s has an empty banner, which every version string satisfies", engine)
		}
	}
}

// Two is skipping, not silently running fewer engines: the two it leaves out
// are reported, with a reason that is not "unconfigured".
func TestTwoReportsTheEnginesItLeavesOut(t *testing.T) {
	ran := map[database.Engine]bool{}
	dbtest.Two(t, func(t *testing.T, db *database.DB) {
		ran[db.Server.Engine] = true
	})
	for _, engine := range []database.Engine{database.MySQL, database.MariaDB} {
		if ran[engine] {
			t.Errorf("%s ran under Two", engine)
		}
	}
	// Asked of the run rather than assumed of it. The gate narrows the engines
	// twice over — the detector pass is SQLite alone, the engine pass is the
	// three servers — so what Two reaches depends on which pass this is, and a
	// flat assertion that SQLite ran fails in the pass that excluded it.
	if inThisRun(database.SQLite) && !ran[database.SQLite] {
		t.Error("sqlite did not run under Two")
	}
	if inThisRun(database.Postgres) && os.Getenv(dbtest.PostgresURLEnv) != "" && !ran[database.Postgres] {
		t.Error("postgres is configured and in this run, and did not run under Two")
	}
}

// inThisRun reports whether the environment leaves engine in the run. Unset
// means every engine that is configured.
func inThisRun(engine database.Engine) bool {
	raw := strings.TrimSpace(os.Getenv(dbtest.EnginesEnv))
	if raw == "" {
		return true
	}
	for _, name := range strings.Split(raw, ",") {
		if database.Engine(strings.TrimSpace(strings.ToLower(name))) == engine {
			return true
		}
	}
	return false
}

// The quick loop narrows the engines through the environment, and an engine
// left out that way is skipped whether or not it is configured.
//
// dbtest.Alone, because the variable it sets is read by the whole process:
// a test that narrowed the engines for everything running beside it would
// narrow what those tests reached.
func TestTheEnvironmentNarrowsWhichEnginesRun(t *testing.T) {
	t.Setenv(dbtest.EnginesEnv, "sqlite")
	ran := map[database.Engine]bool{}
	dbtest.Alone(t, func(t *testing.T, db *database.DB) {
		ran[db.Server.Engine] = true
	})
	if len(ran) != 1 || !ran[database.SQLite] {
		t.Errorf("ran %v, wanted sqlite alone", ran)
	}
}
