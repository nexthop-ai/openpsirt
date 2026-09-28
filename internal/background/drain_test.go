// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package background_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
)

func TestABacklogDrainsInOnePass(t *testing.T) {
	// Five jobs waiting and an interval of an hour: all five are taken on the
	// first tick, rather than one an hour.
	var taken atomic.Int64
	ctx, done := context.WithCancel(t.Context())
	defer done()
	go background.Drain(ctx, time.Hour, time.Hour, func(context.Context) (bool, error) {
		if taken.Load() >= 5 {
			return false, nil
		}
		taken.Add(1)
		return true, nil
	}, func(err error) { t.Errorf("a pass with nothing wrong reported %v", err) })
	waitFor(t, func() bool { return taken.Load() == 5 },
		"the pass took %d of five waiting jobs", &taken)
}

func TestWorkCutShortByShutdownIsNotReportedAsAFailure(t *testing.T) {
	// A failure while the process runs is reported. One that is only the
	// context ending under the work is not a fault in anything: the work is
	// handed back and taken again after the restart.
	var reported, tried atomic.Int64
	failing := errors.New("the database went away")
	ctx, done := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		background.Drain(ctx, time.Millisecond, time.Hour, func(ctx context.Context) (bool, error) {
			if tried.Add(1) == 1 {
				return false, failing
			}
			done()
			return false, ctx.Err()
		}, func(err error) {
			if !errors.Is(err, failing) {
				t.Errorf("reported %v, which is only the pass being stopped", err)
			}
			reported.Add(1)
		})
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the pass did not stop with its context")
	}
	if n := reported.Load(); n != 1 {
		t.Errorf("%d failures reported, want the one that happened while running", n)
	}
}
