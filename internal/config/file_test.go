// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// writeFile writes a configuration file only its owner may read, and returns
// its path.
func writeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openpsirt.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// literal is how a file writes the value the environment spells as raw, for
// a setting of the kind given. A value the kind cannot hold natively is
// written as a string, which the file then refuses as the wrong type.
func literal(k kind, raw string) string {
	switch k {
	case number:
		if _, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return raw
		}
	case boolean:
		if raw == "true" || raw == "false" {
			return raw
		}
	case list:
		var items []string
		for item := range strings.SplitSeq(raw, ",") {
			items = append(items, strconv.Quote(item))
		}
		return "[" + strings.Join(items, ", ") + "]"
	}
	return strconv.Quote(raw)
}

func lookup(t *testing.T, env string) setting {
	t.Helper()
	for _, one := range settings {
		if one.env == env {
			return one
		}
	}
	t.Fatalf("%s is not in the table", env)
	return setting{}
}

// everySetting is a value for every setting, distinct from its default and
// from every other value, which together make a configuration the loader
// accepts. Distinct, so that a file key read into the wrong setting shows as
// a difference rather than as two equal values trading places.
var everySetting = map[string]string{
	"ADDR": "127.0.0.1:9090", "BASE_URL": "https://psirt.example.test",
	"PLAIN_HTTP": "true", "SHUTDOWN_GRACE": "21s", "STARTUP_TIMEOUT": "77s",
	"LOG_LEVEL": "debug", "LOG_FORMAT": "json",

	"DATABASE_URL": "postgres://db.example.test:5432/psirt", "AUTO_MIGRATE": "false",
	"DB_MAX_OPEN": "11", "DB_MAX_IDLE": "9", "DB_IDLE_TIMEOUT": "45s",
	"DB_CONN_LIFETIME": "13m", "DB_REQUIRE_ENCRYPTION": "true",

	"SCANNER_PATH": "/opt/grype", "SCANNER_TIMEOUT": "40m",
	"SCANNER_MAX_OUTPUT": "1000001", "SCANNER_MAX_COMPLAINT": "4001",
	"SCANNER_MAX_MATCHES": "301", "SCANNER_MAX_REFERENCES": "31",

	"MAIL_FROM": "psirt@example.test", "MAIL_SERVER": "smtp.example.test:587",
	"MAIL_USERNAME": "mailer", "MAIL_PASSWORD": "mail-secret",
	"SLACK_TOKEN": "xoxb-1", "ZULIP_SITE": "https://chat.example.test",
	"ZULIP_EMAIL": "bot@example.test", "ZULIP_KEY": "zulip-key",

	"PUBLISHER_NAME": "Example", "PUBLISHER_NAMESPACE": "https://example.test",
	"PUBLISHER_CATEGORY": "coordinator", "ADVISORY_PREFIX": "EXA",

	"DIRECTORY_URL": "https://advisories.example.test/csaf", "DIRECTORY_BUCKET": "dir-bucket",
	"DIRECTORY_ENDPOINT": "https://s3.example.test", "DIRECTORY_REGION": "dir-region",
	"DIRECTORY_KEY": "dir-key", "DIRECTORY_SECRET": "dir-secret",
	"DIRECTORY_SESSION_TOKEN": "dir-token", "DIRECTORY_PATH_STYLE": "false",
	"DIRECTORY_ALLOW_HTTP": "true", "DIRECTORY_DIR": "/srv/csaf",
	"DIRECTORY_LIST": "false", "DIRECTORY_MIRROR": "true",

	"UPSTREAM_INTERNAL": "corp,internal-lib", "OUTBOUND_EXCLUDED": "corp.example.test,203.0.113.0/24",
	"PATCH_BRANCHES": "true", "PATCH_DIR": "/srv/copies", "PATCH_QUOTA": "1073741824",

	"BOOTSTRAP_ADMINS": "ana,ben", "SESSION_LIFETIME": "8h",
	"OIDC_NAME": "corp", "OIDC_ISSUER": "https://id.example.test", "OIDC_CLIENT_ID": "cid",
	"OIDC_CLIENT_SECRET": "csecret", "OIDC_GROUPS_CLAIM": "groups",
	"OIDC_USERNAME_CLAIM": "preferred_username",
	"GITHUB_CLIENT_ID":    "gid", "GITHUB_CLIENT_SECRET": "gsecret", "GITHUB_ORG": "example",
	"TRUSTED_HEADER": "X-User", "TRUSTED_SOURCES": "10.0.0.0/8,192.0.2.0/24",
	"TRUSTED_GROUPS_HEADER": "X-Groups", "TRUSTED_GROUPS_DELIMITER": ";",

	"ATTACHMENT_BUCKET": "att-bucket", "ATTACHMENT_ENDPOINT": "https://store.example.test",
	"ATTACHMENT_REGION": "att-region", "ATTACHMENT_KEY": "att-key",
	"ATTACHMENT_SECRET": "att-secret", "ATTACHMENT_SESSION_TOKEN": "att-token",
	"ATTACHMENT_PATH_STYLE": "true", "ATTACHMENT_ALLOW_HTTP": "false", "ATTACHMENT_DIR": "/srv/att",

	"QUEUE_MAX_ATTEMPTS": "7", "QUEUE_CLAIM_TIMEOUT": "31m", "QUEUE_HEARTBEAT": "4m",
	"QUEUE_MAX_HOLD": "3h", "QUEUE_BACKOFF": "20s",

	"INGEST_MAX_BYTES": "1048576", "INGEST_MAX_COMPONENTS": "501", "INGEST_MAX_EDGES": "502",
	"INGEST_MAX_FILES": "503", "INGEST_MAX_STATEMENTS": "504", "INGEST_MAX_DEPTH": "12",
	"INGEST_MAX_DOCUMENTS": "5",
}

// A deployment configured by file and one configured by the environment, with
// the same value for every setting, are configured identically.
//
// Every setting at once rather than a sample: the values are distinct, so a
// key read into the wrong setting, or a value spelled differently on the way
// through, is a difference in the result.
func TestAFileAndTheEnvironmentConfigureTheSame(t *testing.T) {
	if len(everySetting) != len(settings) {
		t.Fatalf("%d values for %d settings: every setting needs one", len(everySetting), len(settings))
	}
	var file strings.Builder
	for _, one := range settings {
		raw, ok := everySetting[one.env]
		if !ok {
			t.Fatalf("no value for %s%s", envPrefix, one.env)
		}
		t.Setenv(envPrefix+one.env, raw)
		file.WriteString(one.file + " = " + literal(one.kind, raw) + "\n")
	}
	fromEnv, err := Load()
	if err != nil {
		t.Fatalf("the environment: %v", err)
	}
	fromFile, err := LoadFile(writeFile(t, file.String()), nil)
	if err != nil {
		t.Fatalf("the file: %v", err)
	}
	if !reflect.DeepEqual(fromEnv, fromFile) {
		t.Errorf("the two differ:\n environment %+v\n file        %+v", fromEnv, fromFile)
	}
	defaults, err := load(nil)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(fromFile, defaults) {
		t.Error("the file configured nothing: the result is the defaults")
	}
}

// A file written with sections, as an operator writes one, reads as the
// dotted keys do.
func TestAFileIsReadBySection(t *testing.T) {
	path := writeFile(t, `
[server]
address = "127.0.0.1:9191"

[database]
url = "sqlite:///var/lib/openpsirt/openpsirt.db"
max_open = 4

[signin]
bootstrap_admins = ["ana", "ben"]

[signin.trusted_header]
name = "X-User"
sources = ["127.0.0.1/32"]
`)
	c, err := LoadFile(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != "127.0.0.1:9191" || c.DatabaseURL != "sqlite:///var/lib/openpsirt/openpsirt.db" ||
		c.DBMaxOpen != 4 || !reflect.DeepEqual(c.BootstrapAdmins, []string{"ana", "ben"}) ||
		c.TrustedHeader != "X-User" || len(c.TrustedSources) != 1 {
		t.Errorf("read %+v", c)
	}
}

// Any variable of this deployment's own beside a file is refused, and the
// refusal names every one. The environment's other variables are left alone:
// they belong to the libraries and programs this process runs.
func TestTheEnvironmentAndAFileAreNeverBothRead(t *testing.T) {
	path := writeFile(t, "[server]\naddress = \":9000\"\n")
	theirs := []string{
		"PATH=/usr/bin", "HOME=/var/lib/openpsirt", "TMPDIR=/tmp", "TZ=UTC",
		"SSL_CERT_FILE=/etc/ssl/cert.pem", "SSL_CERT_DIR=/etc/ssl/certs",
		"HTTP_PROXY=http://proxy:3128", "HTTPS_PROXY=http://proxy:3128", "NO_PROXY=localhost",
		"http_proxy=http://proxy:3128", "https_proxy=http://proxy:3128", "no_proxy=localhost",
		"GRYPE_DB_CACHE_DIR=/var/cache/openpsirt/grype", "GRYPE_DB_AUTO_UPDATE=false",
		"PGSSLMODE=require", "AWS_REGION=eu-west-1",
	}
	if _, err := LoadFile(path, theirs); err != nil {
		t.Fatalf("a variable that is not the deployment's own was refused: %v", err)
	}

	ours := []string{"OPENPSIRT_MAIL_PASSWORD=x", "OPENPSIRT_DATABASE_URL=", "OPENPSIRT_TEST_POSTGRES_URL=y"}
	_, err := LoadFile(path, append(theirs, ours...))
	if err == nil {
		t.Fatal("a file with the deployment's own variables beside it was read")
	}
	named, _, _ := strings.Cut(err.Error(), " is set beside")
	want := "OPENPSIRT_DATABASE_URL, OPENPSIRT_MAIL_PASSWORD, OPENPSIRT_TEST_POSTGRES_URL"
	if named != want {
		t.Errorf("the refusal names %q, want every one of the deployment's and nothing else: %q",
			named, want)
	}
}

func TestAFileOthersMayReadIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o400} {
		path := writeFile(t, "")
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFile(path, nil); err != nil {
			t.Errorf("mode %04o was refused: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o644, 0o620, 0o602} {
		path := writeFile(t, "")
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := LoadFile(path, nil)
		if err == nil {
			t.Errorf("mode %04o was accepted", mode)
			continue
		}
		if !strings.Contains(err.Error(), "0600") {
			t.Errorf("mode %04o: the refusal does not say what to set: %v", mode, err)
		}
	}
}

func TestAKeyTheFileDoesNotKnowIsRefused(t *testing.T) {
	for body, key := range map[string]string{
		"[database]\nurll = \"x\"\n":             "database.urll",
		"[databse]\nurl = \"x\"\n":               "databse",
		"url = \"x\"\n":                          "url",
		"[database.url]\nhost = \"x\"\n":         "database.url",
		"[signin.oidc]\nissuer_url = \"x\"\n":    "signin.oidc.issuer_url",
		"[patch_branches]\nexcluded = [\"a\"]\n": "patch_branches.excluded",
	} {
		_, err := LoadFile(writeFile(t, body), nil)
		if err == nil {
			t.Errorf("%q was accepted", body)
			continue
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("%q: the refusal does not name %s: %v", body, key, err)
		}
	}
}

func TestAValueOfTheWrongTypeIsRefused(t *testing.T) {
	for body, key := range map[string]string{
		"[database]\nmax_open = \"25\"\n":             "database.max_open",
		"[database]\nmax_open = 2.5\n":                "database.max_open",
		"[database]\nauto_migrate = \"false\"\n":      "database.auto_migrate",
		"[database]\nurl = 5\n":                       "database.url",
		"[server]\nshutdown_grace = 15\n":             "server.shutdown_grace",
		"[signin]\nbootstrap_admins = \"ana,ben\"\n":  "signin.bootstrap_admins",
		"[signin]\nbootstrap_admins = [\"ana\", 1]\n": "signin.bootstrap_admins",
		"[outbound]\nexcluded = [\"a,b\"]\n":          "outbound.excluded",
	} {
		_, err := LoadFile(writeFile(t, body), nil)
		if err == nil {
			t.Errorf("%q was accepted", body)
			continue
		}
		if !strings.Contains(err.Error(), key) {
			t.Errorf("%q: the refusal does not name %s: %v", body, key, err)
		}
	}
}

func TestAFileThatIsNotTOMLIsRefusedNamingTheLine(t *testing.T) {
	_, err := LoadFile(writeFile(t, "[server]\naddress = \":9000\"\nbase_url = https://x\n"), nil)
	if err == nil {
		t.Fatal("a malformed file was accepted")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("the refusal does not name the line: %v", err)
	}
}

// Every refusal the loader makes of a value is made of the same value in a
// file, and names the key rather than the variable.
func TestAValueRefusedFromTheEnvironmentIsRefusedFromAFile(t *testing.T) {
	cases := []struct{ key, value string }{
		{"LOG_LEVEL", "chatty"}, {"LOG_FORMAT", "yaml"}, {"ADDR", "  "},
		{"SHUTDOWN_GRACE", "soon"}, {"SHUTDOWN_GRACE", "0s"}, {"SHUTDOWN_GRACE", "-5s"},
		{"SESSION_LIFETIME", "12"}, {"SESSION_LIFETIME", "900h"},
		{"DB_MAX_OPEN", "0"}, {"DB_MAX_OPEN", "-3"},
		{"TRUSTED_HEADER", "X-User"}, {"TRUSTED_SOURCES", "not-an-address"},
		{"MAIL_SERVER", "smtp.example.test:587"}, {"ZULIP_KEY", "k"},
		{"ADVISORY_PREFIX", "nexthop"}, {"PUBLISHER_CATEGORY", "vendo"},
		{"DIRECTORY_URL", "http://psirt.example.test/csaf"},
		{"DIRECTORY_BUCKET", "b"},
		{"BASE_URL", "psirt.example.test"},
		{"OUTBOUND_EXCLUDED", "10.0.0.0/33"},
	}
	for _, c := range cases {
		t.Run(c.key+"="+c.value, func(t *testing.T) {
			one := lookup(t, c.key)
			t.Setenv(envPrefix+c.key, c.value)
			if _, err := Load(); err == nil {
				t.Fatalf("the environment accepted %s=%q, so this case pins nothing", c.key, c.value)
			}
			_, err := LoadFile(writeFile(t, one.file+" = "+literal(one.kind, c.value)+"\n"), nil)
			if err == nil {
				t.Fatalf("%s = %q was accepted from a file", one.file, c.value)
			}
			if !strings.Contains(err.Error(), one.file) {
				t.Errorf("the refusal does not name %s: %v", one.file, err)
			}
			if strings.Contains(err.Error(), envPrefix+c.key) {
				t.Errorf("the refusal names the variable rather than the key: %v", err)
			}
		})
	}
}

func TestARefusalNamesTheKeyAndKeepsWhatItWraps(t *testing.T) {
	cause := errors.New("OPENPSIRT_DIRECTORY_URL: set it alongside OPENPSIRT_DIRECTORY_BUCKET or " +
		"OPENPSIRT_DIRECTORY_DIR; see OPENPSIRT_PATCH_EXCLUDED")
	got := InFile(cause)
	want := "directory.url: set it alongside directory.bucket or directory.dir; " +
		"see OPENPSIRT_PATCH_EXCLUDED"
	if got.Error() != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if !errors.Is(got, cause) {
		t.Error("the rewritten refusal no longer wraps what it rewrote")
	}
	if InFile(nil) != nil {
		t.Error("no refusal became one")
	}
}
