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
const beingTheScanner = "OPENPSIRT_TEST_SCANNER"

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
