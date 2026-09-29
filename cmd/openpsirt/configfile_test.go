// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nexthop-ai/openpsirt/internal/schema"
)

// withoutOurVariables clears every variable of the deployment's own for the
// rest of the test, and puts each back after it. The shell running the tests
// may export some, such as the engines the suite runs against, and a file is
// refused beside any of them.
func withoutOurVariables(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "OPENPSIRT_") {
			continue
		}
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Setenv(name, value) })
	}
}

// configFile writes a configuration file only its owner may read.
func configFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openpsirt.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runOut runs the command and returns what it wrote to its output.
func runOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = quiet.Close() }()
	ran := run(args, out, quiet)
	written, err := os.ReadFile(out.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(written), ran
}

// The migrate command reads the database it migrates from the file named by
// --config, written before the command or after it.
func TestMigrateReadsTheConfigurationFile(t *testing.T) {
	withoutOurVariables(t)
	url := "sqlite://" + filepath.Join(t.TempDir(), "configured.db")
	path := configFile(t, "[database]\nurl = \""+url+"\"\n\n[log]\nlevel = \"warn\"\n")

	if _, err := runOut(t, "migrate", "up", "--config", path); err != nil {
		t.Fatalf("migrate up --config: %v", err)
	}
	wanted, err := schema.Expected()
	if err != nil {
		t.Fatal(err)
	}
	status, err := runOut(t, "--config", path, "migrate", "status")
	if err != nil {
		t.Fatalf("--config migrate status: %v", err)
	}
	current := "schema version " + strconv.FormatInt(wanted, 10) + " of " + strconv.FormatInt(wanted, 10)
	if !strings.Contains(status, current) {
		t.Errorf("the database the file names was not migrated: %q", status)
	}
	if _, err := runOut(t, "migrate", "--config", path, "status"); err != nil {
		t.Errorf("migrate --config status: %v", err)
	}
}

func TestTheCommandRefusesAFileBesideTheEnvironment(t *testing.T) {
	withoutOurVariables(t)
	path := configFile(t, "[database]\nurl = \"sqlite:///nowhere.db\"\n")
	t.Setenv("OPENPSIRT_DATABASE_URL", "sqlite:///elsewhere.db")
	_, err := runOut(t, "migrate", "status", "--config", path)
	if err == nil || !strings.Contains(err.Error(), "OPENPSIRT_DATABASE_URL") {
		t.Errorf("a file beside the environment was not refused naming the variable: %v", err)
	}
}

// A refusal made after the file is read names the key in the file, including
// one made outside the loader.
func TestARefusalOfAFileNamesTheKey(t *testing.T) {
	withoutOurVariables(t)
	path := configFile(t, "[database]\nmax_open = 0\n")
	_, err := runOut(t, "serve", "--config", path)
	if err == nil || !strings.Contains(err.Error(), "database.max_open") {
		t.Errorf("the refusal does not name the key: %v", err)
	}
	// The schema check in serving writes the variable's name, and runs well
	// after the file is read.
	behind := configFile(t, "[database]\nurl = \"sqlite://"+
		filepath.Join(t.TempDir(), "empty.db")+"\"\nauto_migrate = false\n")
	_, err = runOut(t, "--config", behind)
	if err == nil || !strings.Contains(err.Error(), "database.auto_migrate") ||
		strings.Contains(err.Error(), "OPENPSIRT_") {
		t.Errorf("a refusal after startup began does not name the key: %v", err)
	}
}

func TestAnArgumentAfterACommandIsRefused(t *testing.T) {
	withoutOurVariables(t)
	for _, args := range [][]string{
		{"serve", "now"},
		{"migrate", "up", "down"},
	} {
		if _, err := runOut(t, args...); err == nil || !strings.Contains(err.Error(), "unexpected argument") {
			t.Errorf("%v: %v", args, err)
		}
	}
}
