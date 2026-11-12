// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// The passes a deployment runs beside the server, and the ones it does not.
//
// Held to here rather than left to reading, and without starting anything: the
// methods are taken as values, which a nil receiver allows because nothing
// calls them.

// alwaysRuns is every pass a deployment runs whatever is configured.
var alwaysRuns = []string{
	"read what arrived",
	"scan what arrived",
	"schedule rescans",
	"ask upstream what is current",
	"ask when issues were published",
	"read what suppliers publish",
	"read what upstreams publish",
	"look up the branches patches are on",
	"watch for quiet builds",
	"send what is owed outward",
	"assign unheld work to teams",
	"sweep every ruled product",
	"rewrite deadlines after a policy change",
	"apply analyzer runs",
	"fail jobs whose worker died",
}

// optional is every pass that runs only where what it works on is configured.
var optional = []string{
	"send mail",
	"send what is owed to chat",
	"sweep unattached files",
	"write the published advisory directory",
	"fetch the CVE records",
	"watch the signing key's expiry",
	"write the published documents",
}

// sharedBy is every pass struct field that runs more than one pass, and how
// many.
var sharedBy = map[string]int{"assigning": 2}

func TestWhatADeploymentWithNothingConfiguredStillRuns(t *testing.T) {
	running := named((passes{}).loops())
	for _, want := range alwaysRuns {
		if !running[want] {
			t.Errorf("%q does not run in a deployment with nothing configured", want)
		}
	}
	for _, absent := range optional {
		if running[absent] {
			t.Errorf("%q runs with nothing configured to do it with", absent)
		}
	}
	if len(running) != len(alwaysRuns) {
		t.Errorf("a deployment with nothing configured runs %d passes, want %d: %v",
			len(running), len(alwaysRuns), keysOf(running))
	}
}

// everythingConfigured is the passes of a deployment that configured every
// optional one: every field set, read from the struct, so a field added to it
// is configured here without anybody listing it.
func everythingConfigured(t *testing.T) passes {
	t.Helper()
	var all passes
	value := reflect.ValueOf(&all).Elem()
	if value.NumField() == 0 {
		t.Fatal("the passes hold no field, so this checked nothing")
	}
	for i := range value.NumField() {
		field := value.Field(i)
		if field.Kind() != reflect.Pointer {
			t.Fatalf("%s is not a pass", value.Type().Field(i).Name)
		}
		setPass(field)
	}
	return all
}

// setPass sets one pass field to a zero pass that nothing runs. The field is
// unexported, so it is set through its address.
func setPass(field reflect.Value) {
	//nolint:gosec // G103: a test setting the unexported fields of a struct in its own package
	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.New(field.Type().Elem()))
}

// onlyConfigured is the passes of a deployment configuring one field alone.
func onlyConfigured(t *testing.T, index int) passes {
	t.Helper()
	var one passes
	setPass(reflect.ValueOf(&one).Elem().Field(index))
	return one
}

func TestEveryPassFieldRunsAPass(t *testing.T) {
	// A field nothing in loops reads is a pass constructed and never run.
	fields := reflect.TypeFor[passes]().NumField()
	want := fields
	for name, n := range sharedBy {
		if _, ok := reflect.TypeFor[passes]().FieldByName(name); !ok {
			t.Errorf("%s is listed as running %d passes and is no field of the passes", name, n)
		}
		want += n - 1
	}
	if got := len(everythingConfigured(t).loops()); got != want {
		t.Errorf("a deployment with every pass configured runs %d passes, and its %d fields run %d", got, fields, want)
	}
	// The fields whose absence stops a pass are the optional ones, one each.
	nothing := len((passes{}).loops())
	guarded := 0
	for i := range fields {
		added := len(onlyConfigured(t, i).loops()) - nothing
		if added == 0 {
			continue
		}
		guarded++
		// A guarded field runs the passes it adds, one unless listed.
		name := reflect.TypeFor[passes]().Field(i).Name
		if runs := max(sharedBy[name], 1); added != runs {
			t.Errorf("%s adds %d passes where it is configured, and is listed as running %d", name, added, runs)
		}
	}
	if guarded != len(optional) {
		t.Errorf("%d fields are guarded by being configured, and %d passes are listed as optional", guarded, len(optional))
	}
}

func TestEveryOptionalPassRunsWhereItIsConfigured(t *testing.T) {
	// The ones that are absent above, present here — which is what makes the
	// test above a statement about configuration rather than about nil.
	running := named(everythingConfigured(t).loops())
	for _, want := range append(append([]string{}, alwaysRuns...), optional...) {
		if !running[want] {
			t.Errorf("%q does not run where it is configured", want)
		}
	}
	if want := len(alwaysRuns) + len(optional); len(running) != want {
		t.Errorf("a deployment with everything configured runs %d passes, want %d: %v",
			len(running), want, keysOf(running))
	}
}

func TestEveryPassSaysWhatItIsAndHowOftenItRuns(t *testing.T) {
	// A pass added to the struct and left out of the list is one that stops
	// running with nothing saying so, and an unnamed one is a line in a
	// failure message that names nothing.
	for _, one := range everythingConfigured(t).loops() {
		if one.what == "" {
			t.Error("a pass runs under no name")
		}
		if one.run == nil {
			t.Errorf("%q is listed and has nothing to run", one.what)
		}
		if one.every < 0 {
			t.Errorf("%q runs every %s", one.what, one.every)
		}
	}
}

func named(loops []loop) map[string]bool {
	out := make(map[string]bool, len(loops))
	for _, one := range loops {
		out[one.what] = true
	}
	return out
}

func keysOf(running map[string]bool) []string {
	out := make([]string, 0, len(running))
	for what := range running {
		out = append(out, what)
	}
	return out
}

// TestAnUnknownSubcommandIsRefused pins the one that silently started a server.
//
// `openpsirt migrat` — a typo in a job meant to apply migrations and nothing
// else — fell through to serving, against whatever schema was there.
func TestAnUnknownSubcommandIsRefused(t *testing.T) {
	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = quiet.Close() }()

	for _, c := range []struct {
		args    []string
		refused bool
	}{
		{[]string{"migrat"}, true},
		{[]string{"serv"}, true},
		{[]string{"serve"}, false},
		// A flag nobody defined is the parser's to refuse, and it already
		// does — with a better message than this could give.
		{[]string{"migrate"}, false},
		{[]string{"migrate", "status"}, false},
	} {
		// No database is configured, whatever the shell running the tests
		// exports: one that is set would be migrated by the case that is not
		// refused. That case stops at the database instead, which is the
		// distinction being pinned.
		t.Setenv("OPENPSIRT_DATABASE_URL", "")
		t.Setenv("OPENPSIRT_AUTO_MIGRATE", "false")
		err := run(c.args, os.Environ(), quiet, quiet)
		named := err != nil && strings.Contains(err.Error(), "unknown command")
		if named != c.refused {
			t.Errorf("%v: refused as unknown = %v, want %v (err %v)",
				c.args, named, c.refused, err)
		}
		if !c.refused && (err == nil || !strings.Contains(err.Error(), "no database configured")) {
			t.Errorf("%v: stopped with %v, want it stopped at the database", c.args, err)
		}
	}
}

// An unknown migrate action is named before anything is contacted, so a typo
// is not reported as a missing or unreachable database.
func TestAnUnknownMigrateActionIsRefusedBeforeConnecting(t *testing.T) {
	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = quiet.Close() }()
	t.Setenv("OPENPSIRT_DATABASE_URL", "")
	err = run([]string{"migrate", "statsu"}, os.Environ(), quiet, quiet)
	if err == nil || !strings.Contains(err.Error(), "unknown migrate action") {
		t.Errorf("answered %v, want the action refused by name", err)
	}
}

// Connecting to migrate is bounded by the startup timeout. A server that
// accepts the connection and never answers otherwise holds the command for
// ever, with nothing logged.
func TestMigratingGivesUpOnADatabaseThatNeverAnswers(t *testing.T) {
	quiet, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = quiet.Close() }()
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan net.Conn, 16)
	defer func() {
		_ = silent.Close()
		for {
			select {
			case conn := <-held:
				_ = conn.Close()
			default:
				return
			}
		}
	}()
	go func() {
		for {
			conn, err := silent.Accept()
			if err != nil {
				return
			}
			held <- conn
		}
	}()
	t.Setenv("OPENPSIRT_DATABASE_URL", "postgres://u:p@"+silent.Addr().String()+"/x?sslmode=disable")
	t.Setenv("OPENPSIRT_STARTUP_TIMEOUT", "500ms")
	done := make(chan error, 1)
	go func() { done <- run([]string{"migrate", "up"}, os.Environ(), quiet, quiet) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "gave up connecting to the database") {
			t.Errorf("answered %v, want it to give up connecting", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("still connecting after 30s")
	}
}
