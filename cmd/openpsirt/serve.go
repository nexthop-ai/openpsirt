// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/directory"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/adminapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
	"github.com/nexthop-ai/openpsirt/internal/upstream"
	"github.com/nexthop-ai/openpsirt/internal/version"
)

// readInterval is how long an idle reader waits before asking for work again.
//
// It bounds how long a producer waits to see its scan reflected, which nobody
// is watching a clock for, and a queue that is not empty drains without
// waiting for it.
const readInterval = 5 * time.Second

// scheduleInterval is how often the pass that asks for re-scans looks.
//
// Far more often than anything is due, and deliberately: what it looks *for*
// is a setting an administrator may shorten, and a pass that woke only once a
// day would take up to a day to notice they had. Looking is one query that
// finds nothing, which is the ordinary answer on every cycle but a few.
const scheduleInterval = 5 * time.Minute

// askInterval is how long the upstream pass waits between slices.
//
// Slower than the readers by a long way, and deliberately so. It bounds how
// fast we walk somebody else's free public index, and the answer it collects
// is one that changes on the order of days — a minute between slices drains a
// first run over a few hours and is invisible thereafter.
const askInterval = time.Minute

// passes is what runs beside the server.
//
// Some of them may be absent because what they work on is not configured:
// the mail sender, the chat sender, the attachment sweeper, the published
// directory writer and the CVE record fetcher. The rest always run, and only
// the ones that may be absent are guarded, so a guard is a condition that can
// be false.
//
// Grouped rather than passed one at a time. A call site with a parameter per
// pass cannot be read, and they divide cleanly into what to serve and what to
// run beside it — this is the second half.
type passes struct {
	reader   *ingest.Reader
	runner   *scanner.Runner
	schedule *scanner.Schedule
	upstream *currency.Refresher
	// suppliers reads what configured publishers say about their own flaws.
	suppliers *supplier.Pass
	// forks reads what the upstream each product trusts publishes.
	forks *upstream.Pass
	// branches looks up which branches the commits patch links name are on.
	branches *patchbranch.Pass
	// records keeps the CVE record snapshot current. Nil where fetching is
	// off.
	records *cverecord.Fetcher
	watch   *notify.Watch
	post    *notify.Post
	outward *notify.Signal
	// talk carries notifications to chat. Nil where no platform is configured.
	talk    *notify.Talk
	keeper  *attach.Keeper
	routing *finding.Sweeper
	// undertaker sets aside work whose worker never came back, which is the
	// only pass that observes a worker having died at all.
	undertaker *queue.Undertaker
	// publish writes the advisories that have gone out as a directory
	// somebody else serves. Nil where this deployment writes none.
	publish *directory.Writer
	// documents writes the security documents this deployment serves to
	// anybody. Nil where it publishes none.
	documents *publish.Pass
}

// background starts every pass that has something to work on, and answers
// with what to wait for.
//
// Waited for, not merely signalled. A worker can be mid-query when the signal
// lands, and returning from serve closes the database underneath it — which
// turns an orderly shutdown into a failed scan and a job that has to be
// retried for no reason.
func (p passes) background(ctx context.Context) *sync.WaitGroup {
	var workers sync.WaitGroup
	for _, one := range p.loops() {
		workers.Add(1)
		go func() {
			defer workers.Done()
			one.run(ctx, one.every)
		}()
	}
	return &workers
}

// loop is one background pass, and how often it runs.
type loop struct {
	what  string
	run   func(context.Context, time.Duration)
	every time.Duration
}

// loops is what this deployment runs beside the server.
//
// A list rather than a run of if statements, so that what a given deployment
// starts can be read — and held to — without starting any of it.
func (p passes) loops() []loop {
	// The ones that always run. Their constructors return a value
	// unconditionally; NewUndertaker returns nil only for a nil queue, which
	// queue.New never produces, and Undertaker.Run answers a nil receiver. So
	// a guard on any of them is a condition a reader has to go and disprove.
	all := []loop{
		{"read what arrived", p.reader.Run, readInterval},
		{"scan what arrived", p.runner.Run, readInterval},
		{"schedule rescans", p.schedule.Run, scheduleInterval},
		{"ask upstream what is current", p.upstream.Run, askInterval},
		{"read what suppliers publish", p.suppliers.Run, scheduleInterval},
		{"read what upstreams publish", p.forks.Run, scheduleInterval},
		{"look up the branches patches are on", p.branches.Run, 0},
		{"watch for quiet builds", p.watch.Run, 0},
		{"send what is owed outward", p.outward.Run, 0},
		{"route unheld work to teams", p.routing.Run, readInterval},
		{"set aside work whose worker died", p.undertaker.Run, 0},
	}
	// And the ones a deployment may not have, each nil where what it works
	// on is not configured: NewPost where no mail channel is, the chat sender
	// where no platform is, NewKeeper where no attachment store is,
	// directory.New where no address or no store for it is, and the CVE
	// record fetcher where the deployment keeps the snapshot itself. These
	// guards are the ones that say something.
	if p.post != nil {
		all = append(all, loop{"send mail", p.post.Run, 0})
	}
	if p.talk != nil {
		all = append(all, loop{"send what is owed to chat", p.talk.Run, 0})
	}
	if p.keeper != nil {
		all = append(all, loop{"sweep unattached files", p.keeper.Run, 0})
	}
	if p.publish != nil {
		all = append(all, loop{"write the published advisory directory", p.publish.Run, 0})
	}
	if p.records != nil {
		all = append(all, loop{"fetch the CVE records", p.records.Run, 0})
	}
	if p.documents != nil {
		all = append(all, loop{"write the published documents", p.documents.Run, 0})
	}
	return all
}

func serve(cfg config.Config, logger *slog.Logger, handler http.Handler, beside passes) error {
	return serveBeside(context.Background(), cfg, logger, handler, beside.background)
}

// serveBeside serves, with whatever start begins running beside the server
// stopped and waited for on every way out.
//
// It shuts down on an interrupt, a SIGTERM, or parent ending, and all three
// take the same path.
func serveBeside(parent context.Context, cfg config.Config, logger *slog.Logger, handler http.Handler,
	start func(context.Context) *sync.WaitGroup) error {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Reading stops when the signal arrives, before the server drains, so a
	// scan is not picked up during the seconds we are on our way out.
	workers := start(ctx)
	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: handler,
		// Without these a client can hold a connection, a goroutine and a file
		// descriptor open indefinitely by sending headers slowly. Enough such
		// connections exhaust every replica while the liveness probe keeps
		// passing, because the process itself is fine.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       120 * time.Second,
	}
	errs := make(chan error, 1)

	go func() {
		v := version.Get()
		logger.Info("listening", "addr", cfg.Addr, "version", v.Version, "commit", v.Commit)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()

	select {
	case err := <-errs:
		// The workers are already running, each of them beginning with a
		// timer that fires at once. Returning without waiting would leave
		// them mid-query while the caller's deferred close takes the database
		// away, turning an orderly failure to listen into failed scans and
		// jobs retried for no reason. Stopping them is what ctx's cancel
		// does; waiting is what this adds.
		stop()
		return errors.Join(err, workersStopped(workers, cfg, logger))
	case <-ctx.Done():
	}

	// Let in-flight requests finish rather than cutting them off.
	logger.Info("shutting down", "grace", cfg.ShutdownGrace)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	shutdownErr := srv.Shutdown(shutdownCtx)
	// A deadline rewrite a request started runs off the request, so the
	// server's drain does not wait for it. Ended here, once no request can
	// start another, it hands its lease back for the next process.
	adminapi.StopRewrites(shutdownCtx)

	// And give the workers the same bound, rather than none.
	//
	// A worker mid-query should not have the database pulled from under it,
	// which argues for waiting; an unbounded wait is that argument with no
	// end. On SQLite an HTTP handler running a slow write holds the write lock,
	// so it blocks every worker writing behind it, and a worker waiting on
	// that lock cannot notice it has been asked to stop.
	// Waiting for it then waits for the request, and shutting down takes as
	// long as the slowest thing in the process.
	//
	// Measured: a query that should have taken milliseconds ran for over an
	// hour, SIGTERM did nothing, and the process had to be killed. A shutdown
	// that cannot be completed by the signal meant for it is not a shutdown.
	//
	// Both halves of the grace answer the same way, which is why
	// workersStopped returns an error rather than logging a warning: an
	// overrun request makes Shutdown return an error and the process exit 1,
	// and an overrun worker does the same. `docs/configuration.md` describes
	// the two as one setting applied twice, and a supervisor reads the exit
	// code.
	workerErr := workersStopped(workers, cfg, logger)
	if shutdownErr != nil {
		shutdownErr = fmt.Errorf("shutdown: %w", shutdownErr)
	}
	if err := errors.Join(shutdownErr, workerErr); err != nil {
		return err
	}
	logger.Info("stopped")
	return nil
}

// workersStopped waits out the grace and says whether the workers finished.
//
// An error rather than a warning, because it is the same overrun the server's
// own shutdown reports as one.
func workersStopped(workers *sync.WaitGroup, cfg config.Config, logger *slog.Logger) error {
	if waitFor(workers, cfg.ShutdownGrace) {
		return nil
	}
	logger.Warn("stopped without waiting for background work to finish",
		"grace", cfg.ShutdownGrace,
		"why", "a worker did not stop in time, most likely blocked on a slow query")
	return fmt.Errorf("background work did not stop within %s", cfg.ShutdownGrace)
}

// waitFor waits for a group, and reports whether it finished in time.
//
// The goroutine it leaks where the wait times out is deliberate and bounded by
// the process: it ends when the process does, which is a moment later, and the
// alternative is a shutdown with no end at all.
func waitFor(group *sync.WaitGroup, grace time.Duration) bool {
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(grace):
		return false
	}
}
