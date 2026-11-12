// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

// The re-scan pass and the owed-check pass share nothing, so either failing
// leaves the other to run, and both failures are reported.
func TestAFailedRescanPassStillAsksForOwedChecks(t *testing.T) {
	s := &Schedule{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rescanFailed := errors.New("the re-scan setting could not be read")
	checkFailed := errors.New("the owed checks could not be read")

	checked := false
	asked, err := s.both(t.Context(),
		func(context.Context) (int, error) { return 0, rescanFailed },
		func(context.Context) (int, error) { checked = true; return 1, nil })
	if !checked {
		t.Error("a failed re-scan pass skipped asking for owed checks")
	}
	if !errors.Is(err, rescanFailed) || asked != 0 {
		t.Errorf("answered %d, %v; want the re-scan failure", asked, err)
	}

	_, err = s.both(t.Context(),
		func(context.Context) (int, error) { return 2, rescanFailed },
		func(context.Context) (int, error) { return 0, checkFailed })
	if !errors.Is(err, rescanFailed) || !errors.Is(err, checkFailed) {
		t.Errorf("answered %v; want both failures", err)
	}
}
