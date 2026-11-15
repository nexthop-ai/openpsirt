// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/analysis"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/directory"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/issuedate"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/publish"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/nexthop-ai/openpsirt/internal/signing"
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
// directory writer, the CVE record fetcher, the published documents writer
// and the signing key's watch. The rest always run, and only the ones that may be absent are
// guarded, so a guard is a condition that can be false.
//
// Grouped rather than passed one at a time. A call site with a parameter per
// pass cannot be read, and they divide cleanly into what to serve and what to
// run beside it — this is the second half.
type passes struct {
	reader   *ingest.Reader
	runner   *scanner.Runner
	schedule *scanner.Schedule
	upstream *currency.Refresher
	// dates asks OSV when each issue was published.
	dates *issuedate.Pass
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
	talk      *notify.Talk
	keeper    *attach.Keeper
	assigning *finding.Sweeper
	// rewriting rewrites stored deadlines after a policy change.
	rewriting *finding.Rewriter
	analyze   *analysis.Worker
	// undertaker fails the jobs whose worker never came back, which is the
	// only pass that observes a worker having died at all.
	undertaker *queue.Undertaker
	// publish writes the advisories that have gone out as a directory
	// somebody else serves. Nil where this deployment writes none.
	publish *directory.Writer
	// documents writes the security documents this deployment serves to
	// anybody. Nil where it publishes none.
	documents *publish.Pass
	// key says when the key published documents are signed with expires
	// soon. Nil where they go unsigned or the key never expires.
	key *signing.Watch
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
		{"ask when issues were published", p.dates.Run, askInterval},
		{"read what suppliers publish", p.suppliers.Run, scheduleInterval},
		{"read what upstreams publish", p.forks.Run, scheduleInterval},
		{"look up the branches patches are on", p.branches.Run, 0},
		{"watch for quiet builds", p.watch.Run, 0},
		{"send what is owed outward", p.outward.Run, 0},
		{"assign unheld work to teams", p.assigning.Run, readInterval},
		{"sweep every ruled product", p.assigning.CatchUp, 0},
		{"rewrite deadlines after a policy change", p.rewriting.Run, readInterval},
		{"apply analyzer runs", p.analyze.Run, readInterval},
		{"fail jobs whose worker died", p.undertaker.Run, 0},
	}
	// And the ones a deployment may not have, each nil where what it works
	// on is not configured: NewPost where no mail channel is, the chat sender
	// where no platform is, NewKeeper where no attachment store is,
	// directory.New where no address or no store for it is, the CVE record
	// fetcher where the deployment keeps the snapshot itself, the published
	// documents writer where nothing is published, and the key's watch where
	// documents go unsigned or the key never expires. These guards are the
	// ones that say something.
	if p.post != nil {
		all = append(all,
			loop{"send mail", p.post.Run, 0},
			loop{"send digests", p.post.RunDigests, 0})
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
	if p.key != nil {
		all = append(all, loop{"watch the signing key's expiry", p.key.Run, 0})
	}
	return all
}

// listening is the HTTP server once its port is open, answering through
// whichever handler the phase it is in holds.
//
// Where the process applies the schema itself, the port opens before it does,
// answering through the handler for that phase, and the router replaces it
// once the start is complete. A platform that asks whether the process is
// alive then hears that it is while a long migration runs, rather than ending
// it part way.
//
// Once the router answers, another instance changing the schema pauses it:
// every request is answered as the start answers while it migrates, and every
// request the router was answering has its context ended, so its transaction
// rolls back.
type listening struct {
	srv   *http.Server
	phase atomic.Pointer[phase]
	// router answers once the start is complete, and again after a pause.
	router http.Handler
	// upgrading answers while a schema is applied, here or elsewhere.
	upgrading http.Handler
	// end ends the requests of the phase the router answers in.
	end context.CancelCauseFunc
	// failed carries a failure to serve after the port opened.
	failed chan error
}

// phase is a handler and how long the requests it answers last.
type phase struct {
	handler http.Handler
	// ended ends every request this phase answers, once the phase is over.
	// Nil where requests outlast it: one already answered while the port
	// opens is finished with the handler it began with.
	ended context.Context
}

// errStranded is a schema an upgrade left with its record standing and
// nothing changing it.
var errStranded = errors.New("an upgrade left the schema changed without recording its version, as one " +
	"failing part way on MySQL or MariaDB does: complete the upgrade or restore the backup taken before it")

// errSchemaChanging is why a request the router was answering ended.
var errSchemaChanging = errors.New("another instance is changing the schema")

// listen opens the port and serves through first until answer replaces it.
//
// The port is opened here rather than in the goroutine that serves it, so an
// address somebody else holds is refused before anything else starts.
func listen(cfg config.Config, logger *slog.Logger, first http.Handler) (*listening, error) {
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, err
	}
	l := &listening{failed: make(chan error, 1), upgrading: httpapi.Upgrading()}
	l.phase.Store(&phase{handler: first})
	l.srv = &http.Server{
		Handler: http.HandlerFunc(l.serve),
		// Without these a client can hold a connection, a goroutine and a file
		// descriptor open indefinitely by sending headers slowly. Enough such
		// connections exhaust every replica while the liveness probe keeps
		// passing, because the process itself is fine.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       120 * time.Second,
	}
	v := version.Get()
	logger.Info("listening", "addr", ln.Addr().String(), "version", v.Version, "commit", v.Commit)
	go func() {
		if err := l.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			l.failed <- err
		}
	}()
	return l, nil
}

// serve answers a request through the current phase. A request the router
// answers ends when its phase does, and a failure it answers after that, or
// no answer, is replaced by the upgrading one.
func (l *listening) serve(w http.ResponseWriter, r *http.Request) {
	p := l.phase.Load()
	if p.ended == nil {
		p.handler.ServeHTTP(w, r)
		return
	}
	ctx, cancel := context.WithCancelCause(r.Context())
	defer cancel(nil)
	stop := context.AfterFunc(p.ended, func() { cancel(context.Cause(p.ended)) })
	defer stop()
	answer := &diverting{ResponseWriter: w, r: r, ended: p.ended, upgrading: l.upgrading}
	p.handler.ServeHTTP(answer, r.WithContext(ctx))
	answer.finish()
}

// answer makes handler the router, which every request after this one
// reaches. A request already being answered finishes with the handler it
// began with.
func (l *listening) answer(handler http.Handler) {
	l.router = handler
	l.open()
}

// open starts a phase the router answers in.
func (l *listening) open() {
	ended, end := context.WithCancelCause(context.Background())
	l.end = end
	l.phase.Store(&phase{handler: l.router, ended: ended})
}

// pause answers every request as upgrading and ends the ones the router was
// answering.
func (l *listening) pause() {
	l.phase.Store(&phase{handler: l.upgrading})
	if l.end != nil {
		l.end(errSchemaChanging)
	}
}

// resume answers through the router again.
func (l *listening) resume() {
	l.open()
}

// diverting is the response to a request the router answers. Where the
// phase ended and the handler's answer is a refusal or a failure, or the
// handler wrote nothing, the upgrading answer is written instead: a handler
// whose context ended may answer its failed lookup as a refusal. A success is
// written as the handler wrote it, since what it did took effect, and so is a
// redirect, which a browser follows and which may carry a session it set; a
// sign-in the pause ended redirects to its failure screen.
type diverting struct {
	http.ResponseWriter
	r         *http.Request
	ended     context.Context
	upgrading http.Handler
	begun     bool
	diverted  bool
}

// through reports whether the handler's answer, beginning with status code,
// is the one written, deciding as the answer begins.
func (d *diverting) through(code int) bool {
	if !d.begun {
		d.begun = true
		if code >= http.StatusBadRequest && d.ended.Err() != nil {
			d.divert()
		}
	}
	return !d.diverted
}

// divert writes the upgrading answer in place of the handler's.
func (d *diverting) divert() {
	d.begun, d.diverted = true, true
	// The handler's headers belong to the answer dropped.
	header := d.Header()
	for name := range header {
		delete(header, name)
	}
	d.upgrading.ServeHTTP(d.ResponseWriter, d.r)
}

// finish answers a request whose handler wrote nothing and whose phase ended.
func (d *diverting) finish() {
	if !d.begun && d.ended.Err() != nil {
		d.divert()
	}
}

func (d *diverting) WriteHeader(code int) {
	if code < http.StatusOK {
		// An informational answer precedes the answer, and decides nothing.
		if !d.begun {
			d.ResponseWriter.WriteHeader(code)
		}
		return
	}
	if d.through(code) {
		d.ResponseWriter.WriteHeader(code)
	}
}

func (d *diverting) Write(b []byte) (int, error) {
	if d.through(http.StatusOK) {
		return d.ResponseWriter.Write(b)
	}
	return len(b), nil
}

// Unwrap lets a response controller reach the connection's writer.
func (d *diverting) Unwrap() http.ResponseWriter {
	return d.ResponseWriter
}

// abandon closes the port of a start that did not complete, and answers the
// error that ended it. Whether that error fails the start is the caller's to
// decide: a start a stop signal ended is a clean stop.
func (l *listening) abandon(cfg config.Config, logger *slog.Logger, err error) error {
	closing, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	if closeErr := l.srv.Shutdown(closing); closeErr != nil {
		logger.Warn("closing the port of a start that did not complete", "error", closeErr)
	}
	return err
}

// sighting is the standing of the schema, as it moved.
type sighting struct {
	standing schema.Standing
	// applied is the version applied, and carried the one this build carries.
	applied, carried int64
	// failed is whether the standing is a look that failed, read as Changes.
	failed bool
}

// lookBeforeServing looks at the schema once more just before the router
// opens, and refuses the start unless it is this build's with nothing
// changing it. What the start checked was read before preparing, which can
// take the whole startup deadline, and an upgrade's notice may have run out
// since. The first look of the watch follows within an interval, inside the
// notice.
func lookBeforeServing(ctx context.Context, look func(context.Context) (schema.Standing, int64, int64, error)) error {
	standing, applied, carried, err := look(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("could not ask whether the schema is changing before serving: %w", err)
	case standing == schema.Changes:
		return fmt.Errorf("another instance began changing the schema, at version %d, while this one started", applied)
	case standing == schema.Stranded:
		return fmt.Errorf("%w, at version %d", errStranded, applied)
	case standing != schema.Serves:
		return fmt.Errorf("the database is at schema version %d, and this build carries %d", applied, carried)
	}
	return nil
}

// watchSchema answers what looks at the schema every interval until its
// context ends, sending each standing that differs from the one before. The
// first compared against is Serves, which the start established.
//
// A look that fails is read as Changes: an instance that cannot tell whether
// the schema is changing does not serve it. The failure is logged once until
// a look succeeds.
func watchSchema(logger *slog.Logger, look func(context.Context) (schema.Standing, int64, int64, error),
	every time.Duration) func(context.Context) <-chan sighting {
	return func(ctx context.Context) <-chan sighting {
		seen := make(chan sighting)
		go func() {
			last := sighting{standing: schema.Serves}
			failing := false
			tick := time.NewTicker(every)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
				standing, applied, carried, err := look(ctx)
				if ctx.Err() != nil {
					return
				}
				switch {
				case err != nil:
					if !failing {
						logger.Warn("could not ask whether the schema is changing: not serving until it can",
							"error", err)
					}
					failing, standing = true, schema.Changes
				default:
					failing = false
				}
				now := sighting{standing: standing, applied: applied, carried: carried, failed: failing}
				if now.standing == last.standing && now.failed == last.failed {
					continue
				}
				last = now
				select {
				case seen <- now:
				case <-ctx.Done():
					return
				}
			}
		}()
		return seen
	}
}

// serveBeside serves, with whatever start begins running beside the server
// stopped and waited for on every way out.
//
// It shuts down when parent ends, which is a stop signal in a running process.
//
// While it serves, watch reports the schema's standing. Where another
// instance changes the schema, it pauses: requests are answered as upgrading,
// the ones being answered end, and the passes stop. It serves again when the
// schema is this build's, starting the passes again once the ones stopped
// have ended, and stops where they have not ended within the shutdown grace.
// Where a later release has upgraded the schema, or it has fallen behind this
// build with nothing changing it, it stops, and says so in its error. A nil
// watch reports nothing.
func serveBeside(parent context.Context, cfg config.Config, logger *slog.Logger, server *listening,
	start func(context.Context) *sync.WaitGroup, watch func(context.Context) <-chan sighting) error {
	ctx, stop := context.WithCancel(parent)
	defer stop()

	var standings <-chan sighting
	if watch != nil {
		standings = watch(ctx)
	}
	// Reading stops when the signal arrives, before the server drains, so a
	// scan is not picked up during the seconds we are on our way out.
	// A pause ends the passes with queue.ErrPaused as the cause, so a job a
	// pause stopped is handed back untried rather than failed.
	running, endRunning := context.WithCancelCause(ctx)
	stopRunning := func() { endRunning(nil) }
	defer func() { stopRunning() }()
	workers := start(running)
	srv := server.srv
	errs := server.failed
	// paused is whether the router is set aside, and halted whether the
	// passes are stopped. drained closes once the passes a pause stopped have
	// ended, and is nil while none are ending; the passes start again only
	// after, so two copies of one pass never run at once. stalled fires where
	// they have not ended a grace after the router resumed.
	paused, halted := false, false
	var drained <-chan struct{}
	var stalled <-chan time.Time
	var stopping error
	restart := func() {
		running, endRunning = context.WithCancelCause(ctx)
		stopRunning = func() { endRunning(nil) }
		workers = start(running)
		halted, stalled = false, nil
	}

serving:
	for {
		select {
		case err := <-errs:
			// The workers are already running, each of them beginning with a
			// timer that fires at once. Returning without waiting would leave
			// them mid-query while the caller's deferred close takes the database
			// away, turning an orderly failure to serve into failed scans and
			// jobs retried for no reason. Stopping them is what ctx's cancel
			// does; waiting is what this adds.
			stopRunning()
			stop()
			return errors.Join(err, workersStopped(workers, cfg, logger))
		case <-ctx.Done():
			break serving
		case <-drained:
			drained, stalled = nil, nil
			if halted && !paused {
				restart()
			}
		case <-stalled:
			stopping = fmt.Errorf("background work stopped for a schema change did not end within %s "+
				"of serving again", cfg.ShutdownGrace)
			logger.Error("background work did not stop for a schema change: stopping", "grace", cfg.ShutdownGrace)
			break serving
		case seen := <-standings:
			switch seen.standing {
			case schema.Changes, schema.Stranded:
				if !halted {
					endRunning(queue.ErrPaused)
					drained = ended(workers)
					halted = true
				}
				// Logged on every move between these, which the watch sends
				// only when the standing differs.
				if !paused {
					server.pause()
					paused = true
				}
				switch {
				case seen.failed:
					logger.Warn("could not look at the schema: not serving until a look succeeds")
				case seen.standing == schema.Stranded:
					logger.Error(errStranded.Error()+": not serving", "applied", seen.applied,
						"carried", seen.carried)
				default:
					logger.Warn("another instance is changing the schema: not serving until it is this build's",
						"applied", seen.applied, "carried", seen.carried)
				}
			case schema.Serves:
				if !paused {
					continue
				}
				server.resume()
				paused = false
				logger.Info("the schema is this build's again: serving", "version", seen.applied)
				if drained == nil {
					restart()
				} else if stalled == nil {
					// Counted from the first time it serves again, so a
					// standing moving back and forth never restarts it.
					stalled = time.After(cfg.ShutdownGrace)
				}
			case schema.Superseded, schema.Behind:
				server.pause()
				stopRunning()
				stopping = fmt.Errorf("the database is at schema version %d, which a later release "+
					"applied while this build served it, and this build carries %d: a database is only "+
					"ever upgraded, so this build stops and the release that upgraded it serves it",
					seen.applied, seen.carried)
				if seen.standing == schema.Behind {
					stopping = fmt.Errorf("the database is at schema version %d, behind the %d this "+
						"build carries, and nothing is changing it: this build stops, and its next "+
						"start migrates it or refuses it", seen.applied, seen.carried)
				}
				logger.Error("the schema is no longer this build's: stopping", "applied", seen.applied,
					"carried", seen.carried)
				break serving
			}
		}
	}
	stopRunning()

	// Let in-flight requests finish rather than cutting them off.
	logger.Info("shutting down", "grace", cfg.ShutdownGrace)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	shutdownErr := srv.Shutdown(shutdownCtx)

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
	if err := errors.Join(stopping, shutdownErr, workerErr); err != nil {
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

// ended closes once a group has finished.
func ended(group *sync.WaitGroup) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	return done
}

// waitFor waits for a group, and reports whether it finished in time.
//
// The goroutine it leaks where the wait times out is deliberate and bounded by
// the process: it ends when the process does, which is a moment later, and the
// alternative is a shutdown with no end at all.
func waitFor(group *sync.WaitGroup, grace time.Duration) bool {
	select {
	case <-ended(group):
		return true
	case <-time.After(grace):
		return false
	}
}
