// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"

	"github.com/nexthop-ai/openpsirt/internal/database"
)

// TestALostRaceReachesTheRetryHelper pins the one thing that makes handing a
// race back work at all.
//
// A store inside somebody else's transaction cannot go again itself, so it
// says it lost and the helper that opened the transaction takes the whole act
// again. That only happens if the sentinel survives the handler: wentWrong
// builds a fresh refusal wrapping nothing, so reporting the loss as a fault
// destroys it — and the mechanism is then dead with every document describing
// it still saying it works.
func TestALostRaceReachesTheRetryHelper(t *testing.T) {
	lost := fmt.Errorf("record the %q setting: %w", "triage.floor", database.ErrGoAgain)

	kept := recording(nil, "that setting could not be recorded", lost)
	if !errors.Is(kept, database.ErrGoAgain) {
		t.Errorf("a lost race came back as %v, which the retry helper cannot recognize", kept)
	}
	if !database.WorthRetrying(kept) {
		t.Error("the retry helper does not read what comes back as worth going again")
	}

	// And everything else is still a fault, reported as one. The cause travels
	// with it for the retry helper to read and is not what the caller is told,
	// which is the property the test below this one pins.
	broken := errors.New("dial tcp 10.0.0.4:5432: connection refused")
	said := recording(nil, "that setting could not be recorded", broken)
	if database.WorthRetrying(said) {
		t.Error("a database that cannot be reached is being retried as a lost race")
	}
	var status huma.StatusError
	if !errors.As(said, &status) || status.GetStatus() != http.StatusInternalServerError {
		t.Errorf("a database that cannot be reached does not answer as a fault: %v", said)
	}
	if strings.Contains(status.Error(), "10.0.0.4") {
		t.Errorf("the address it tried is what the caller is told: %q", status.Error())
	}
	if recording(nil, "nothing went wrong", nil) != nil {
		t.Error("a write that succeeded is being reported as a failure")
	}
}

// TestAFaultKeepsItsCauseForTheRetryHelper pins the other half of going again.
//
// Every act that became a transaction reports a store failure as a refusal, and
// a refusal built fresh wraps nothing — so the helper that opened the
// transaction asked "is this worth going again" of an error with no cause in
// it, and contention in the middle of an act was reported to an administrator
// rather than taken again. Contention at the commit still retried, because that
// comes back from the driver itself, which is what made the gap quiet.
func TestAFaultKeepsItsCauseForTheRetryHelper(t *testing.T) {
	// Something the retry helper recognizes, asked for by name rather than
	// built from a driver's own type: which code each engine calls contention
	// is the database package's business, and naming one here would be
	// engine-specific code outside where that is allowed.
	contention := fmt.Errorf("withdraw the role: %w", database.ErrGoAgain)
	said := wentWrong(nil, "cannot withdraw the role", contention)

	if !database.WorthRetrying(said) {
		t.Error("contention reported as a fault is not taken again")
	}
	if !errors.Is(said, contention) {
		t.Errorf("the cause did not survive being reported: %v", said)
	}

	// And none of it is what the caller is told. The framework resolves a
	// returned error to the first status error it finds, which is the refusal.
	var status huma.StatusError
	if !errors.As(said, &status) {
		t.Fatal("a fault no longer carries a status for the framework to write")
	}
	if status.GetStatus() != http.StatusInternalServerError {
		t.Errorf("a fault answers %d", status.GetStatus())
	}
	if strings.Contains(status.Error(), "withdraw the role:") {
		t.Errorf("what the store wrote is what the caller is told: %q", status.Error())
	}
}
