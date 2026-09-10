package main

import (
	"sync"
	"testing"
	"time"
)

func TestShutdownDoesNotWaitForever(t *testing.T) {
	// A worker that will not stop must not hold the process open. On SQLite
	// the pool is one connection by design, so an HTTP handler running a slow
	// statement blocks every worker behind it — and a worker that cannot get a
	// connection cannot notice it has been asked to stop. Waiting for it then
	// waits for the request, which is how a SIGTERM came to do nothing and the
	// process had to be killed.
	var stuck sync.WaitGroup
	stuck.Add(1)
	// Never released, which is the case being tested.
	defer stuck.Done()

	started := time.Now()
	if waitFor(&stuck, 50*time.Millisecond) {
		t.Fatal("a worker that never finished was reported as having finished")
	}
	if waited := time.Since(started); waited > time.Second {
		t.Errorf("waited %s for a bound of 50ms", waited)
	}
}

func TestShutdownWaitsForWorkThatFinishes(t *testing.T) {
	// The bound is a last resort, not the normal path: work that stops when
	// asked is still waited for, because returning early closes the database
	// underneath it and turns an orderly shutdown into a failed scan.
	var working sync.WaitGroup
	working.Add(1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		working.Done()
	}()

	if !waitFor(&working, 5*time.Second) {
		t.Error("work that finished in time was abandoned")
	}
}
