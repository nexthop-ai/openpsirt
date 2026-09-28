// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const rehearsalSecret = "s3cret-rehearsal"

func TestAContainerRunTakesTheDatabaseFromTheEnvironment(t *testing.T) {
	// An argument is readable by every local user and is written to the log,
	// and the URL carries the database password.
	r := &run{appURL: "postgres://app:" + rehearsalSecret + "@host.docker.internal:5432/x"}
	args := r.container("--rm", "image", "migrate", "up")
	named := false
	for _, arg := range args {
		if strings.Contains(arg, rehearsalSecret) {
			t.Errorf("an argument carries the password: %q", arg)
		}
		named = named || arg == "OPENPSIRT_DATABASE_URL"
	}
	if !named {
		t.Errorf("the container is not told to take the URL from the environment: %v", args)
	}
	if got := strings.Join(r.withDatabase(), " "); !strings.Contains(got, rehearsalSecret) {
		t.Errorf("the environment does not carry the URL: %q", got)
	}
}

func TestTheReleaseWrapperPassesTheDatabaseThroughTheEnvironment(t *testing.T) {
	// The release's own targets write the URL as an argument. The wrapper
	// swaps in the rehearsal database, and the value it swaps in goes through
	// the environment rather than the command line docker is started with.
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	r := &run{work: t.TempDir()}
	wrapper, err := r.wrapper()
	if err != nil {
		t.Fatal(err)
	}
	// A docker that reports what it was started with.
	fake := t.TempDir()
	script := "#!/usr/bin/env bash\necho \"ARGS $*\"\necho \"ENV $OPENPSIRT_DATABASE_URL\"\n"
	if err := os.WriteFile(filepath.Join(fake, "docker"), []byte(script), 0o700); err != nil { //nolint:gosec // G306: a script the test executes
		t.Fatal(err)
	}
	c := exec.CommandContext(t.Context(), wrapper, "run", "-e", "OPENPSIRT_DATABASE_URL=sqlite:///old", "image") //nolint:gosec // G204: a script this test wrote
	c.Env = append(os.Environ(), "PATH="+fake+string(os.PathListSeparator)+os.Getenv("PATH"),
		"REHEARSAL_DB=postgres://app:"+rehearsalSecret+"@db/x")
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("the wrapper failed: %v\n%s", err, out)
	}
	var args, env string
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, "ARGS "); ok {
			args = rest
		}
		if rest, ok := strings.CutPrefix(line, "ENV "); ok {
			env = rest
		}
	}
	if strings.Contains(args, rehearsalSecret) || strings.Contains(args, "sqlite:///old") {
		t.Errorf("docker was started with the URL as an argument: %q", args)
	}
	if !strings.Contains(env, rehearsalSecret) {
		t.Errorf("docker's environment does not carry the rehearsal database: %q", env)
	}
}

func TestTheEngineURLIsReadFromTheEnvironmentRatherThanTheCommandLine(t *testing.T) {
	// A command line is readable by every local user for the whole run.
	env := map[string]string{"OPENPSIRT_TEST_POSTGRES_URL": "postgres://app:" + rehearsalSecret + "@db/x"}
	if got := engineURL("", "postgres", func(name string) string { return env[name] }); got != env["OPENPSIRT_TEST_POSTGRES_URL"] {
		t.Errorf("the environment's URL was not read: %q", got)
	}
	if got := engineURL("postgres://named/x", "postgres", func(string) string { return "" }); got != "postgres://named/x" {
		t.Errorf("a URL named on the command line was not used: %q", got)
	}
}

func TestAnUnreadableEngineURLIsNotRepeatedBack(t *testing.T) {
	// The URL parser quotes the text it could not read, password included.
	r := &run{engine: "postgres", adminURL: "postgres://u:pa%zz@db/x"}
	err := r.database(t.Context())
	if err == nil {
		t.Fatal("a URL with a malformed escape was accepted")
	}
	if strings.Contains(err.Error(), "pa%zz") {
		t.Errorf("the error repeats the credential: %v", err)
	}
}
