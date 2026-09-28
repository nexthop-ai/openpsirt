// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database_test

import (
	"os"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
	"github.com/nexthop-ai/openpsirt/internal/dbtest/engines"
)

func TestOpenIdentifiesTheServer(t *testing.T) {
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		if db.Server.Engine == "" {
			t.Fatal("no engine identified")
		}
		if db.Server.Raw == "" {
			t.Error("no version string was reported")
		}
		if db.Server.Version.Major == 0 {
			t.Errorf("version %s looks unparsed (raw %q)", db.Server.Version, db.Server.Raw)
		}
		t.Logf("%s %s (%s)", db.Server.Engine, db.Server.Version, db.Server.Raw)
	})
}

func TestOpenSaysWhetherTheConnectionIsEncrypted(t *testing.T) {
	// Both drivers negotiate opportunistically and neither says which way it
	// went, so a deployment that believed its connection was encrypted had
	// nowhere to look. The answer is asked of the server, so it describes the
	// connection rather than the intention.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		got := db.Server.Transport
		if got == "" {
			t.Fatal("the connection does not say what transport it negotiated")
		}
		if got == "unknown" {
			t.Errorf("%s would not say what transport it negotiated", db.Server.Engine)
		}
		if db.Server.Engine == database.SQLite && got != "none" {
			t.Errorf("SQLite is a file and has no transport, but reported %q", got)
		}
		t.Logf("%s negotiated %q", db.Server.Engine, got)
	})
}

func TestOpenTellsMySQLFromMariaDB(t *testing.T) {
	// They share a driver and a URL scheme. Believing the URL rather than the
	// server would apply the wrong version floor and let an unsupported server
	// through unnoticed.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		switch db.Server.Engine {
		case database.MySQL, database.MariaDB:
			raw := db.Server.Raw
			isMaria := containsFold(raw, "mariadb")
			if isMaria && db.Server.Engine != database.MariaDB {
				t.Errorf("server says MariaDB (%q) but was identified as %s", raw, db.Server.Engine)
			}
			if !isMaria && db.Server.Engine != database.MySQL {
				t.Errorf("server says MySQL (%q) but was identified as %s", raw, db.Server.Engine)
			}
		default:
			t.Skipf("%s is not a MySQL-protocol server", db.Server.Engine)
		}
	})
}

func TestSimpleQueryRunsEverywhere(t *testing.T) {
	// The smallest proof that the dialect and driver agree with each other.
	dbtest.Each(t, func(t *testing.T, db *database.DB) {
		var got int
		if err := db.QueryRowContext(t.Context(), "SELECT 1").Scan(&got); err != nil {
			t.Fatalf("SELECT 1: %v", err)
		}
		if got != 1 {
			t.Errorf("SELECT 1 returned %d", got)
		}
	})
}

func TestOpenRejectsAnUnsupportedURL(t *testing.T) {
	if _, err := database.ParseURL("oracle://user@host/db"); err == nil {
		t.Fatal("an unsupported database was accepted")
	}
}

func containsFold(haystack, needle string) bool {
	lower := func(s string) string {
		b := []byte(s)
		for i := range b {
			if b[i] >= 'A' && b[i] <= 'Z' {
				b[i] += 'a' - 'A'
			}
		}
		return string(b)
	}
	h, n := lower(haystack), lower(needle)
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

// SQLite is opened in write-ahead-log mode with NORMAL syncing, and a URL
// may add pragmas of its own after those, the last setting of a name winning.
func TestSQLiteIsOpenedForSpeedAndAURLMayOverrideIt(t *testing.T) {
	read := func(t *testing.T, url, pragma string) string {
		t.Helper()
		db := dbtest.Open(t, url)
		var value string
		if err := db.QueryRowContext(t.Context(), "PRAGMA "+pragma).Scan(&value); err != nil {
			t.Fatalf("PRAGMA %s: %v", pragma, err)
		}
		return value
	}
	base := "sqlite://" + t.TempDir() + "/pragmas.db"
	if got := read(t, base, "journal_mode"); got != "wal" {
		t.Errorf("journal_mode = %q, wanted wal", got)
	}
	// synchronous reads back as a number: 1 is NORMAL, 0 is OFF.
	if got := read(t, base, "synchronous"); got != "1" {
		t.Errorf("synchronous = %q, wanted 1 (NORMAL)", got)
	}
	if got := read(t, base+"?_pragma=synchronous(OFF)", "synchronous"); got != "0" {
		t.Errorf("synchronous with the URL's own pragma = %q, wanted 0 (OFF)", got)
	}
	if got := read(t, base, "foreign_keys"); got != "1" {
		t.Errorf("foreign_keys = %q, wanted 1", got)
	}
}

func TestAConnectionIsRefusedWhereEncryptionWasRequiredAndNotGot(t *testing.T) {
	// Both drivers negotiate opportunistically and neither says which way it
	// went, so every deployment took whatever the server offered. A
	// deployment that needs certainty states it, and what it gets is a
	// refusal rather than a line in a log somebody has to read.
	//
	// Asked of the answer the connection gave rather than of a live server:
	// what this decides is a comparison, and a test against whichever
	// transport a test server happens to negotiate would pass for the wrong
	// reason on one engine and skip on another.
	for _, c := range []struct {
		what     string
		server   database.Server
		required bool
		refused  bool
		mentions string
	}{
		{
			"encrypted, which is what was asked for",
			database.Server{Engine: database.Postgres, Transport: "TLSv1.3"},
			true, false, "",
		},
		{
			"cleartext where the deployment said it must be encrypted",
			database.Server{Engine: database.Postgres, Transport: "none"},
			true, true, "cleartext",
		},
		{
			"a server that would not say, which is not certainty either",
			database.Server{Engine: database.MySQL, Transport: "unknown"},
			true, true, "would not say",
		},
		{
			"a file opened directly, which has no connection to encrypt",
			database.Server{Engine: database.SQLite, Transport: "none"},
			true, true, "no connection to encrypt",
		},
		{
			"cleartext where the deployment said nothing, which is the other choice",
			database.Server{Engine: database.Postgres, Transport: "none"},
			false, false, "",
		},
	} {
		err := database.EncryptionAsAsked(c.server, database.Target{
			Engine: c.server.Engine, Redacted: "postgres://user@host:5432/openpsirt",
			RequireEncryption: c.required,
		})
		if (err != nil) != c.refused {
			t.Errorf("%s: refused=%v (%v), want %v", c.what, err != nil, err, c.refused)
			continue
		}
		if err == nil {
			continue
		}
		if !strings.Contains(err.Error(), c.mentions) {
			t.Errorf("%s: the refusal does not say %q: %v", c.what, c.mentions, err)
		}
		// Naming the setting is what makes the refusal actionable: whoever
		// meets it is the operator who set it.
		if !strings.Contains(err.Error(), database.RequiredEncryption) {
			t.Errorf("%s: the refusal does not name the setting: %v", c.what, err)
		}
	}
}

// A sql_mode written the way the driver documents a string variable, in one
// pair of quotes, is a connection the server accepts, on both engines that
// read one.
func TestAQuotedSQLModeIsAcceptedByTheServer(t *testing.T) {
	for engine, env := range map[database.Engine]string{
		database.MySQL:   dbtest.MySQLURLEnv,
		database.MariaDB: dbtest.MariaDBURLEnv,
	} {
		t.Run(string(engine), func(t *testing.T) {
			engines.SkipUnless(t, engine)
			address := os.Getenv(env)
			if address == "" {
				t.Skipf("%s is not set", env)
			}
			target, err := database.ParseURL(address + "?sql_mode=%27NO_ZERO_DATE%27")
			if err != nil {
				t.Fatal(err)
			}
			db, err := database.Open(t.Context(), target)
			if err != nil {
				t.Fatalf("a quoted mode was refused: %v", err)
			}
			defer func() { _ = db.Close() }()
			var held string
			if err := db.QueryRowContext(t.Context(), "SELECT @@SESSION.sql_mode").Scan(&held); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"NO_ZERO_DATE", "ANSI_QUOTES", "STRICT_TRANS_TABLES"} {
				if !strings.Contains(held, want) {
					t.Errorf("the session mode %q lacks %s", held, want)
				}
			}
		})
	}
}

// Where encryption is required, every connection the pool opens carries a
// transport that cannot fall back to cleartext, not only the one asked at
// startup. A transport that may fall back is made one that may not, one that
// is cleartext outright is refused, and one the deployment named that cannot
// fall back is left as written.
func TestARequiredTransportIsImposedOnEveryConnection(t *testing.T) {
	for _, c := range []struct {
		url      string
		required bool
		want     string // a fragment of the connection string, or "" where refused
	}{
		{"postgres://u:p@db/openpsirt", true, "sslmode=require"},
		{"postgres://u:p@db/openpsirt?sslmode=prefer", true, "sslmode=require"},
		{"postgres://u:p@db/openpsirt?sslmode=allow&x=1", true, "sslmode=require&x=1"},
		{"postgres://u:p@db/openpsirt?sslmode=verify-full", true, "sslmode=verify-full"},
		{"postgres://u:p@db/openpsirt?sslmode=disable", true, ""},
		{"postgres://u:p@db/openpsirt?sslmode=prefer", false, "sslmode=prefer"},
		{"mysql://u:p@db/openpsirt", true, "tls=skip-verify"},
		{"mysql://u:p@db/openpsirt?tls=preferred", true, "tls=skip-verify"},
		{"mariadb://u:p@db/openpsirt?tls=true", true, "tls=true"},
		{"mysql://u:p@db/openpsirt?tls=false", true, ""},
		{"mysql://u:p@db/openpsirt", false, "tls=preferred"},
	} {
		target, err := database.ParseURL(c.url)
		if err != nil {
			t.Fatal(err)
		}
		target.RequireEncryption = c.required
		dsn, err := database.MandatoryTransport(target)
		if c.want == "" {
			if err == nil {
				t.Errorf("%s: a transport in cleartext was accepted as %q", c.url, dsn)
			} else if !strings.Contains(err.Error(), database.RequiredEncryption) {
				t.Errorf("%s: the refusal does not name the setting: %v", c.url, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.url, err)
			continue
		}
		if !strings.Contains(dsn, c.want) {
			t.Errorf("%s (required %v): opened as %q, want it to carry %s", c.url, c.required, dsn, c.want)
		}
		for _, weak := range []string{"sslmode=prefer", "sslmode=allow", "tls=preferred"} {
			if c.required && strings.Contains(dsn, weak) {
				t.Errorf("%s: required, and still opened with %s", c.url, weak)
			}
		}
	}
}
