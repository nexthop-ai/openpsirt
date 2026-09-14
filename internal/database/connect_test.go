package database_test

import (
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/dbtest"
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
