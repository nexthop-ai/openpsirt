// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package queue_test

import (
	"context"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/queue"
)

// A lease is held for several cycles, and never for less than a minute.
func TestALeaseCoversSeveralCyclesAndAMinute(t *testing.T) {
	if got := queue.LeaseFor(time.Hour); got != 5*time.Hour {
		t.Errorf("an hourly pass holds its lease for %v, want five hours", got)
	}
	if got := queue.LeaseFor(time.Second); got != time.Minute {
		t.Errorf("a pass every second holds its lease for %v, want a minute", got)
	}
}

// A renewal takes the lease again on the count of steps, and on the clock once
// half the lease has gone by, whichever comes first; it takes none for the
// first step, which runs on the lease the pass took to start.
func TestARenewalTakesTheLeaseOnTheCountOrTheClock(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	taken := 0
	renewal := queue.NewRenewal(func(context.Context) (bool, error) { taken++; return true, nil },
		time.Hour, func() time.Time { return now })
	for range queue.RenewEvery {
		if mine, err := renewal.Keep(ctx); err != nil || !mine {
			t.Fatalf("kept %v: %v", mine, err)
		}
	}
	if taken != 0 {
		t.Fatalf("the lease was taken %d times within one count", taken)
	}
	if _, err := renewal.Keep(ctx); err != nil || taken != 1 {
		t.Fatalf("at the count the lease was taken %d times: %v", taken, err)
	}
	now = now.Add(31 * time.Minute)
	if _, err := renewal.Keep(ctx); err != nil || taken != 2 {
		t.Errorf("past half the lease it was taken %d times, want once more: %v", taken, err)
	}
	if _, err := renewal.Keep(ctx); err != nil || taken != 2 {
		t.Errorf("just after a renewal it was taken %d times, want none more: %v", taken, err)
	}
}

// A renewal that finds the lease taken by another replica says so, so the
// pass stops.
func TestARenewalThatLostTheLeaseSaysSo(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	renewal := queue.NewRenewal(func(context.Context) (bool, error) { return false, nil },
		time.Minute, func() time.Time { return now })
	if mine, _ := renewal.Keep(t.Context()); !mine {
		t.Fatal("the first step was refused before anything was asked")
	}
	now = now.Add(time.Minute)
	if mine, _ := renewal.Keep(t.Context()); mine {
		t.Error("a renewal that lost the lease reports holding it")
	}
}
