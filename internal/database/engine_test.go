// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package database

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestParseURLRecognizesEachEngine(t *testing.T) {
	for _, tc := range []struct {
		url    string
		engine Engine
	}{
		{"postgres://u:p@host:5432/db", Postgres},
		{"postgresql://u:p@host:5432/db", Postgres},
		{"mysql://u:p@host:3306/db", MySQL},
		{"mariadb://u:p@host:3306/db", MariaDB},
		{"sqlite:///var/lib/openpsirt.db", SQLite},
		{"sqlite://:memory:", SQLite},
	} {
		t.Run(tc.url, func(t *testing.T) {
			got, err := ParseURL(tc.url)
			if err != nil {
				t.Fatalf("ParseURL: %v", err)
			}
			if got.Engine != tc.engine {
				t.Errorf("engine = %q, want %q", got.Engine, tc.engine)
			}
			if got.DSN == "" {
				t.Error("DSN is empty")
			}
		})
	}
}

func TestParseURLRejectsWhatWeDoNotSupport(t *testing.T) {
	for _, raw := range []string{
		"",
		"  ",
		"oracle://u:p@host/db",
		"mongodb://host/db",
		"mysql://u:p@host:3306/", // names no database
		"sqlite://",              // names no file
	} {
		if _, err := ParseURL(raw); err == nil {
			t.Errorf("ParseURL(%q) was accepted", raw)
		}
	}
}

func TestMySQLDSNIsRewrittenForItsDriver(t *testing.T) {
	// The driver wants user:pass@tcp(host:port)/db, not a URL. Handing it the
	// URL unchanged fails at connect time with an unhelpful message.
	got, err := ParseURL("mysql://user:secret@db.example:3306/openpsirt")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	want := "user:secret@tcp(db.example:3306)/openpsirt?parseTime=true&loc=UTC&" +
		"clientFoundRows=true&tls=preferred&sql_mode=" +
		url.QueryEscape("CONCAT(@@sql_mode,',ANSI_QUOTES,STRICT_TRANS_TABLES')") +
		"&cte_max_recursion_depth=1000000"
	if got.DSN != want {
		t.Errorf("DSN\n got %q\nwant %q", got.DSN, want)
	}
}

func TestEachEngineOfTheFamilyIsToldItsOwnRecursionBound(t *testing.T) {
	// The two engines name the setting differently and each refuses the
	// other's name, so a connection sent the wrong one does not open.
	for _, c := range []struct{ raw, want, not string }{
		{"mysql://u:p@h/db", "cte_max_recursion_depth=1000000", "max_recursive_iterations"},
		{"mariadb://u:p@h/db", "max_recursive_iterations=1000000", "cte_max_recursion_depth"},
		{"mysql://u:p@h/db?cte_max_recursion_depth=5000", "cte_max_recursion_depth=5000", "=1000000"},
	} {
		got, err := ParseURL(c.raw)
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", c.raw, err)
		}
		if !strings.Contains(got.DSN, c.want) || strings.Contains(got.DSN, c.not) {
			t.Errorf("%s became %q, want %s and no %s", c.raw, got.DSN, c.want, c.not)
		}
	}
}

func TestMySQLDSNNegotiatesTLSUnlessTheURLSaysOtherwise(t *testing.T) {
	// This driver leaves the connection in cleartext when nothing asks for
	// TLS, where pgx takes the same URL and negotiates opportunistically. One
	// URL grammar with opposite transport defaults, over a database holding
	// undisclosed findings.
	got, err := ParseURL("mysql://u:p@h/db")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if !contains(got.DSN, "tls=preferred") {
		t.Errorf("DSN %q does not ask for a transport", got.DSN)
	}

	// "preferred" is a floor, and a deployment that needs certainty says so.
	// Naming tls here as well would override the answer only the deployment
	// can give, because the driver takes the last value of a name.
	for _, raw := range []string{
		"mysql://u:p@h/db?tls=true",
		"mysql://u:p@h/db?tls=skip-verify",
		"mariadb://u:p@h/db?tls=our-own-config",
	} {
		got, err := ParseURL(raw)
		if err != nil {
			t.Fatalf("ParseURL(%q): %v", raw, err)
		}
		if strings.Count(got.DSN, "tls=") != 1 {
			t.Errorf("ParseURL(%q) DSN %q names tls more than once", raw, got.DSN)
		}
		if contains(got.DSN, "tls=preferred") {
			t.Errorf("ParseURL(%q) DSN %q overrode the transport the URL asked for", raw, got.DSN)
		}
	}
}

func TestMySQLDSNAssertsStrictnessRatherThanInheritingIt(t *testing.T) {
	// Appending alone keeps whatever the server already held, and a server
	// whose global sql_mode omits strictness truncates an oversized value with
	// no error — the one portability difference that loses data rather than
	// reporting it. Naming the mode makes it a property of this application
	// rather than of the server it was pointed at.
	got, err := ParseURL("mysql://u:p@h/db")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	for _, want := range []string{"CONCAT", "ANSI_QUOTES", "STRICT_TRANS_TABLES"} {
		if !contains(got.DSN, url.QueryEscape(want)) && !contains(got.DSN, want) {
			t.Errorf("DSN %q is missing %q", got.DSN, want)
		}
	}
}

func TestMySQLDSNAlwaysAsksForUTCTimesAndStandardQuoting(t *testing.T) {
	// Without the first two the driver returns timestamps as bytes in the
	// server's timezone, so every time comparison depends on how the server is
	// set up.
	//
	// The third is about identifiers. These engines quote with backticks by
	// default where the other two use the standard double quote, so without it
	// portable data definition means quoting nothing — and quoting nothing is
	// what a reserved word catches, on whichever engine happens to reserve it.
	got, err := ParseURL("mysql://u@h/db?charset=utf8mb4")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	// CONCAT, not assignment. Assigning the mode replaces it, and what it
	// replaces includes the strictness that makes an oversized value an error
	// rather than a silent truncation.
	for _, want := range []string{"charset=utf8mb4", "parseTime=true", "loc=UTC", "ANSI_QUOTES", "CONCAT", "clientFoundRows=true"} {
		if !contains(got.DSN, want) {
			t.Errorf("DSN %q is missing %q", got.DSN, want)
		}
	}
}

func TestPasswordsAreNotLogged(t *testing.T) {
	got, err := ParseURL("postgres://user:hunter2@host:5432/db")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if contains(got.Redacted, "hunter2") {
		t.Errorf("redacted form still contains the password: %q", got.Redacted)
	}
	if !contains(got.DSN, "hunter2") {
		t.Error("the DSN lost the password; it is what actually connects")
	}
}

func TestAURLTheParserRefusesIsNotRepeatedBack(t *testing.T) {
	// The parser's own message quotes what it could not read, and what it
	// could not read is the URL — password included, in the first line the
	// process logs. The message names the scheme and host and nothing else.
	_, err := ParseURL("postgres://openpsirt:hunter%2too@db.internal:5432/openpsirt")
	if err == nil {
		t.Fatal("a URL with a malformed escape was accepted")
	}
	for _, secret := range []string{"hunter", "%2t", "openpsirt:"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error repeats the credential: %v", err)
		}
	}
	for _, kept := range []string{"postgres", "db.internal:5432", "escape"} {
		if !strings.Contains(err.Error(), kept) {
			t.Errorf("the error does not say %q: %v", kept, err)
		}
	}
}

func TestAPasswordContainingASlashIsNotMistakenForTheHost(t *testing.T) {
	// The authority was cut at the first slash before the "@" was looked for,
	// so a password with a slash in it — which a base64-shaped generated one
	// has routinely — put the "@" beyond the cut, and the userinfo was named
	// as the host in the first line a misconfigured start writes to stderr.
	_, err := ParseURL("postgres://openpsirt:hunter2secret/x@db.internal:5432/openpsirt")
	if err == nil {
		t.Fatal("a URL with a slash in the password was accepted")
	}
	for _, secret := range []string{"hunter", "openpsirt:"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error repeats the credential: %v", err)
		}
	}
	if !strings.Contains(err.Error(), "db.internal:5432") {
		t.Errorf("the error does not name the host it could not reach: %v", err)
	}
}

func TestACredentialNeverLeavesThePackage(t *testing.T) {
	// The redacted URL is logged on every start, and an error from opening a
	// connection reaches stderr. Neither carries the password, however the
	// URL spells it: in the userinfo with a delimiter left unescaped, or as a
	// query parameter, well formed or not.
	for _, c := range []struct {
		what, raw, secret string
	}{
		{"a slash in the password, before digits", "postgres://app:12/34@127.0.0.1:1/x", "34@"},
		{"a question mark in the password", "postgres://app:12?34@127.0.0.1:1/x", "34@"},
		{"a number sign in the password", "postgres://app:12#34@127.0.0.1:1/x", "34@"},
		{"a password parameter", "postgres://app@127.0.0.1:1/x?password=s3cret&connect_timeout=1", "s3cret"},
		{"a password parameter with a malformed escape",
			"postgres://app@127.0.0.1:1/x?password=s3cr%zz&connect_timeout=1", "s3cr"},
		{"an encoded password parameter", "postgres://app@127.0.0.1:1/x?password=s3%2Fcret&connect_timeout=1", "s3"},
		{"a TLS key password", "postgres://app@127.0.0.1:1/x?sslpassword=k3yp4ss&connect_timeout=1", "k3yp4ss"},
		{"a password parameter the driver quotes back",
			"postgres://app@127.0.0.1:1/x?password=s3cret&connect_timeout=never", "s3cret"},
		{"an at sign in the password, before a slash", "postgres://app:p@ss/word@127.0.0.1:1/x", "ss/word"},
		{"an opaque URL", "postgres:app:s3cret@127.0.0.1:1/x", "s3cret"},
		{"a number sign in a password parameter", "postgres://127.0.0.1:1?password=s3cr#t", "s3cr"},
		{"an at sign in a password parameter", "postgres://127.0.0.1:1/x?password=ab@cd%zz", "cd"},
	} {
		t.Run(c.what, func(t *testing.T) {
			target, err := ParseURL(c.raw)
			if err != nil {
				if strings.Contains(err.Error(), c.secret) {
					t.Errorf("the refusal carries the credential: %v", err)
				}
				return
			}
			if strings.Contains(target.Redacted, c.secret) {
				t.Errorf("the logged URL carries the credential: %q", target.Redacted)
			}
			// Nothing listens on port 1, so this fails in the driver: parsing
			// what it was given, or connecting.
			db, err := Open(t.Context(), target)
			if err == nil {
				_ = db.Close()
				t.Fatal("a connection to a port nothing listens on succeeded")
			}
			if strings.Contains(err.Error(), c.secret) {
				t.Errorf("the connection error carries the credential: %v", err)
			}
		})
	}
}

func TestAnAtSignInAQueryValueIsNotAStrayCredential(t *testing.T) {
	// Drivers read a user name and a password from the query, and a user name
	// holding an "@" is written there as it is.
	target, err := ParseURL("postgres://db.internal/x?user=app@corp&password=hunter2")
	if err != nil {
		t.Fatalf("a user name in the query was refused: %v", err)
	}
	if strings.Contains(target.Redacted, "hunter2") {
		t.Errorf("the logged URL carries the password: %q", target.Redacted)
	}
}

func TestARefusalNamesAHostOnlyWhereTheTextSaysWhichPartIsTheHost(t *testing.T) {
	for _, c := range []struct {
		raw, want string
	}{
		{"postgres://app:12/34@db.internal:5432/x", `the postgres URL for "db.internal:5432"`},
		{"postgres://db.internal?password=s3cr#t", `the postgres URL for "db.internal"`},
		{"postgres://app:p@ss/word@db:5432/x", "the postgres URL could"},
		{"postgres://u:p%zz@db/x?password=ab@cd", "the postgres URL has"},
	} {
		_, err := ParseURL(c.raw)
		if err == nil {
			t.Fatalf("%s was accepted", c.raw)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: the refusal does not say %q: %v", c.raw, c.want, err)
		}
	}
}

func TestADriverErrorQuotingTheCredentialIsScrubbed(t *testing.T) {
	// A driver describes what it was given, and its own redaction covers the
	// userinfo only. Every spelling of each credential leaves the error, and
	// the error it wraps is still reachable.
	target, err := ParseURL("postgres://app:p%40ss@db:5432/x?sslpassword=k3y%2Fpass&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("driver")
	quoted := fmt.Errorf("cannot parse `password=p@ss sslpassword=k3y/pass` "+
		"(from p%%40ss and k3y%%2Fpass): %w", cause)
	got := scrub(quoted, target)
	for _, secret := range []string{"p@ss", "p%40ss", "k3y/pass", "k3y%2Fpass"} {
		if strings.Contains(got.Error(), secret) {
			t.Errorf("the scrubbed error carries %q: %v", secret, got)
		}
	}
	if !errors.Is(got, cause) {
		t.Errorf("the scrubbed error no longer wraps what the driver said: %v", got)
	}
}

func TestOnlySQLiteIsNonProduction(t *testing.T) {
	for _, e := range []Engine{Postgres, MySQL, MariaDB} {
		if !e.IsProduction() {
			t.Errorf("%s should be a production engine", e)
		}
	}
	if SQLite.IsProduction() {
		t.Error("SQLite must never count as a production engine")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

func TestAnOperatorsOwnSQLModeSurvives(t *testing.T) {
	// The settings are appended after the URL's own query and the driver takes
	// the last value of a name, so a sql_mode an operator wrote was dropped
	// without a word — the same loss appending to the server's mode exists to
	// avoid, and inconsistent with the transport, which an operator may state.
	got, err := ParseURL("mysql://u:p@h/db?sql_mode=ANSI,NO_ZERO_DATE")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	for _, want := range []string{"ANSI,NO_ZERO_DATE", "ANSI_QUOTES", "STRICT_TRANS_TABLES"} {
		if !contains(got.DSN, url.QueryEscape(want)) {
			t.Errorf("DSN %q lost %q", got.DSN, want)
		}
	}
	// And what the server already held is no longer the base, because the
	// operator named one.
	if contains(got.DSN, url.QueryEscape("@@sql_mode")) {
		t.Errorf("DSN %q added the operator's mode to the server's instead of replacing it", got.DSN)
	}

	// A quote in the value is escaped for SQL rather than for Go: under
	// ANSI_QUOTES a double-quoted value is an identifier, so the wrong quoting
	// asks for a mode named after the text rather than the text.
	got, err = ParseURL("mysql://u:p@h/db?sql_mode=IT%27S")
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if !contains(got.DSN, url.QueryEscape("'IT''S'")) {
		t.Errorf("DSN %q does not carry the operator's mode as a SQL string", got.DSN)
	}
}
