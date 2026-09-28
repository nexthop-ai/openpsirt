// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/scanner"
)

// The scanner is an external program, so exercising the part of this package
// that runs one needs a program. The test binary re-executes itself with an
// environment variable saying what to be, which is how the standard library's
// own os/exec tests do it: no shell script, nothing to install, and the
// fixture is written in Go beside the test that uses it.
//
// Named under the scanner's own prefix, because that is what reaches it: the
// rest of this process's environment is not handed over.
const beingTheScanner = "GRYPE_OPENPSIRT_TEST_AS"

func TestMain(m *testing.M) {
	switch os.Getenv(beingTheScanner) {
	case "":
		os.Exit(m.Run())
	case "report":
		// A report larger than the bound the test sets.
		fmt.Print(`{"matches":[`)
		for range 200 {
			fmt.Print(strings.Repeat(" ", 1024))
		}
		fmt.Print(`],"descriptor":{"version":"0.112.0"}}`)
	case "complaint":
		// A scanner with far more to say than is kept, which still worked.
		fmt.Fprint(os.Stderr, strings.Repeat("x", 200*1024))
		fmt.Fprint(os.Stderr, "\nthe last thing it said")
		fmt.Print(`{"matches":[],"descriptor":{"version":"0.112.0"}}`)
	case "empty":
		fmt.Print(`{"matches":[],"descriptor":{"version":"0.112.0"}}`)
	case "environment":
		// What it was given, one name per line, where the run keeps what a
		// scanner says, bounded short: the value only for the scanner's own
		// settings, and a mark for any value carrying the test's secret.
		for _, kv := range os.Environ() {
			name, value, _ := strings.Cut(kv, "=")
			switch {
			case strings.Contains(value, "hunter2"):
				fmt.Fprintln(os.Stderr, "SECRET "+name)
			case strings.HasPrefix(name, "GRYPE_CHECK") || strings.HasPrefix(name, "GRYPE_DB"):
				fmt.Fprintln(os.Stderr, kv)
			default:
				fmt.Fprintln(os.Stderr, name)
			}
		}
		fmt.Print(`{"matches":[],"descriptor":{"version":"0.112.0"}}`)
	}
	os.Exit(0)
}

// scanning runs the scan against the test binary pretending to be a scanner.
func scanning(t *testing.T, being string, limits scanner.Limits) (scanner.Result, error) {
	t.Helper()
	t.Setenv(beingTheScanner, being)
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("the test binary: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	return scanner.Grype{Path: self, Limits: limits}.
		Scan(ctx, strings.NewReader(`{"components":[]}`))
}

func TestAReportPastTheLimitFailsTheRun(t *testing.T) {
	// Not truncated: half a report read as a whole one is a product that
	// appears to have stopped having problems, which is the failure the
	// findings this produces are supposed to prevent.
	_, err := scanning(t, "report", scanner.Limits{MaxOutput: 64 << 10})
	if err == nil {
		t.Fatal("a report past the limit was read as a run that worked")
	}
	if !strings.Contains(err.Error(), "report limit") {
		t.Errorf("the failure does not name the limit it hit: %v", err)
	}
}

func TestAReportInsideTheLimitIsRead(t *testing.T) {
	// The other half of the pair: a bound set too low is only visible against
	// a run that has to keep working.
	result, err := scanning(t, "report", scanner.Limits{MaxOutput: 1 << 20})
	if err != nil {
		t.Fatalf("a report inside the limit: %v", err)
	}
	if result.Version != "0.112.0" {
		t.Errorf("the scanner's version is %q", result.Version)
	}
}

func TestAScannerWithTooMuchToSayStillScanned(t *testing.T) {
	// The opposite direction from the report: complaints past the bound are
	// dropped rather than failing a run that worked.
	result, err := scanning(t, "complaint", scanner.Limits{MaxComplaint: 4 << 10})
	if err != nil {
		t.Fatalf("a chatty scanner: %v", err)
	}
	if len(result.Caution) > 4<<10 {
		t.Errorf("what it said was kept at %d bytes", len(result.Caution))
	}
	if result.Caution == "" {
		t.Error("what it said was dropped whole rather than bounded")
	}
}

func TestAScanOfNothingIsNotAFailure(t *testing.T) {
	result, err := scanning(t, "empty", scanner.Limits{})
	if err != nil {
		t.Fatalf("an empty scan: %v", err)
	}
	if len(result.Reported) != 0 {
		t.Errorf("an empty scan reported %d things", len(result.Reported))
	}
}

// The scanner is somebody else's program reading somebody else's inventory, and
// it is handed none of this process's secrets: nothing of the deployment's
// own configuration reaches it, while where to find programs, the proxy and
// its own settings do. Its check for a newer release of itself, a request to a
// host nobody configured, is off unless an operator turned it on.
func TestTheScannerIsGivenNoneOfThisProcesssSecrets(t *testing.T) {
	t.Setenv("OPENPSIRT_DATABASE_URL", "postgres://u:hunter2@db/openpsirt")
	t.Setenv("OPENPSIRT_MAIL_PASSWORD", "hunter2")
	t.Setenv("HTTPS_PROXY", "http://proxy.example.test:3128")
	t.Setenv("GRYPE_DB_AUTO_UPDATE", "false")
	result, err := scanning(t, "environment", scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	given := strings.Split(result.Caution, "\n")
	if len(given) < 3 {
		t.Fatalf("the scanner reported an environment of %d lines, so this checked nothing", len(given))
	}
	for _, kv := range given {
		if strings.HasPrefix(kv, "OPENPSIRT_") || strings.HasPrefix(kv, "SECRET ") {
			t.Errorf("the scanner was given %s", kv)
		}
	}
	for _, want := range []string{"PATH", "HTTPS_PROXY", "GRYPE_DB_AUTO_UPDATE=false", "GRYPE_CHECK_FOR_APP_UPDATE=false"} {
		found := false
		for _, kv := range given {
			found = found || kv == want
		}
		if !found {
			t.Errorf("the scanner was not given %s", want)
		}
	}
}

// An operator who turns the scanner's update check on is left alone.
func TestTheScannersUpdateCheckIsAnOperatorsToTurnOn(t *testing.T) {
	t.Setenv("GRYPE_CHECK_FOR_APP_UPDATE", "true")
	result, err := scanning(t, "environment", scanner.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.Caution, "GRYPE_CHECK_FOR_APP_UPDATE=true") ||
		strings.Contains(result.Caution, "GRYPE_CHECK_FOR_APP_UPDATE=false") {
		t.Errorf("the operator's setting did not reach the scanner as written:\n%s", result.Caution)
	}
}
