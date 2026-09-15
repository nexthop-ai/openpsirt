package background_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/background"
)

func TestThePassRunsAtOnceAndThenOnTheInterval(t *testing.T) {
	// The first tick is immediate on purpose: a process that has just started
	// is the moment a sweep is most worth running, because whatever
	// accumulated while it was down is waiting.
	var ran atomic.Int64
	ctx, done := context.WithCancel(t.Context())
	go background.Every(ctx, time.Millisecond, time.Hour, func(context.Context) {
		ran.Add(1)
	})
	waitFor(t, func() bool { return ran.Load() >= 3 },
		"the pass ran %d times, want it running on the interval", &ran)
	done()
}

func TestAnIntervalOfNothingTakesTheFallback(t *testing.T) {
	// A caller passes a configured value straight through, so what nothing
	// means is decided here rather than nine times.
	var ran atomic.Int64
	ctx, done := context.WithCancel(t.Context())
	go background.Every(ctx, 0, time.Millisecond, func(context.Context) {
		ran.Add(1)
	})
	waitFor(t, func() bool { return ran.Load() >= 3 },
		"the pass ran %d times, want the fallback interval in force", &ran)
	done()
}

func TestThePassStopsWithItsContext(t *testing.T) {
	// The half that matters at shutdown: a pass that kept running would hold
	// the process open past the grace period.
	var ran atomic.Int64
	ctx, done := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		background.Every(ctx, time.Millisecond, time.Hour, func(context.Context) {
			ran.Add(1)
		})
	}()
	waitFor(t, func() bool { return ran.Load() >= 1 },
		"the pass never ran at all (%d)", &ran)
	done()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the pass did not stop with its context")
	}
	settled := ran.Load()
	time.Sleep(20 * time.Millisecond)
	if after := ran.Load(); after != settled {
		t.Errorf("the pass ran %d more times after its context ended", after-settled)
	}
}

// waitFor polls until the condition holds, rather than sleeping for a fixed
// time that is either flaky or slow.
func waitFor(t *testing.T, until func() bool, why string, ran *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if until() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf(why, ran.Load())
}
