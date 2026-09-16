// Command openpsirt serves the OpenPSIRT API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/publisher"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/signin"
	"github.com/nexthop-ai/openpsirt/internal/version"
	"github.com/nexthop-ai/openpsirt/internal/webui"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "openpsirt: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr *os.File) error {
	fs := flag.NewFlagSet("openpsirt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the build and exit")
	dumpSpec := fs.Bool("openapi", false, "write the OpenAPI document to stdout and exit")
	if err := fs.Parse(args); err != nil {
		// Asking for help is not a failure.
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if *showVersion {
		v := version.Get()
		_, err := fmt.Fprintf(stdout, "OpenPSIRT %s (%s, built %s, %s)\n", v.Version, v.Commit, v.Date, v.Go)
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := newLogger(cfg, stderr)

	// Generating the document from the running registrations is what keeps it
	// from drifting away from the server. It needs no database.
	if *dumpSpec {
		_, api := httpapi.New(logger, nil, httpapi.Ingest{})
		doc, err := api.OpenAPI().YAML()
		if err != nil {
			return fmt.Errorf("render OpenAPI document: %w", err)
		}
		_, err = stdout.Write(doc)
		return err
	}

	ctx := context.Background()
	// A subcommand this does not know is refused rather than ignored.
	// Ignored, `openpsirt migrat` started the server — a typo in a job that
	// was meant to apply migrations and nothing else, answering requests
	// against whatever schema was there. runMigrate already refuses an
	// action it does not know, which is the contrast.
	if fs.NArg() > 0 {
		if fs.Arg(0) != "migrate" {
			return fmt.Errorf("unknown command %q: the only one is \"migrate\"", fs.Arg(0))
		}
		return runMigrate(ctx, cfg, logger, stdout, fs.Args()[1:])
	}

	// Everything below this line is contacted before the server listens, and
	// all of it under one deadline.
	//
	// **Unbounded, a hang here was silent and total.** An endpoint that
	// accepts the connection and never answers held PingContext for ever: the
	// process was up, no port was listening, and not one log line had been
	// written — from outside, the same thing as a slow image pull. A crash
	// loop that names what it could not reach is the failure a supervisor can
	// act on. Migrating is outside it — both the subcommand above and the
	// auto-migration below — because a schema change on a large table
	// legitimately takes longer than a deployment starts in.
	//
	// Each step says what it is about to do, for the same reason: a hang has
	// to name what it is hanging on.
	migrating := ctx
	startup, settled := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer settled()
	ctx = startup
	logger.Info("starting", "timeout", cfg.StartupTimeout)

	logger.Info("connecting to the database")
	db, err := openDatabase(ctx, cfg, logger)
	if err != nil {
		return startupFailed(err, "connecting to the database", cfg)
	}
	defer closeQuietly(db, logger)

	// Migrating before serving means a request never arrives against a schema
	// the code does not expect.
	//
	// **Outside the startup deadline**, and the deadline is why: a migration
	// adding an index to a large finding table takes longer than a deployment
	// starts in, so bounded at 60s it gives up, restarts, and begins the
	// migration again — for ever. A second replica waits on the advisory lock
	// and dies under the same bound. What bounds this instead is the chart's
	// startup probe, which allows ten minutes and says so.
	//
	// The `migrate` subcommand above returns before any of this; what runs
	// here is the same work under `auto-migrate`, which the chart defaults on.
	if cfg.AutoMigrate {
		logger.Info("applying the schema")
		if err := schema.Up(migrating, db, logger); err != nil {
			return fmt.Errorf("applying the schema: %w", err)
		}
	} else if err := schemaIsCurrent(ctx, db, logger); err != nil {
		return startupFailed(err, "checking the schema version", cfg)
	}

	// Named administrators are granted at every start, which is what makes
	// this the way back in rather than a one-time setup step.
	if err := access.Bootstrap(ctx, access.NewStore(db.DB), cfg.BootstrapAdmins); err != nil {
		return startupFailed(err, "granting the administrators named in configuration", cfg)
	}
	if len(cfg.BootstrapAdmins) > 0 {
		logger.Info("administrators granted from configuration", "count", len(cfg.BootstrapAdmins))
	}

	// A deployment that cannot reach its own administration has one route
	// back — editing the database by hand — and nobody discovers that at a
	// good moment. Checked here rather than trusted to have been arranged.
	settings := setting.NewStore(db.DB)
	stored, _, err := settings.Get(ctx, setting.RoleMode)
	if err != nil {
		return err
	}
	mode := access.AsMode(stored)
	rights := access.NewStore(db.DB)
	canAdminister, err := rights.CanAdminister(ctx, mode)
	if err != nil {
		return err
	}
	if !canAdminister {
		return fmt.Errorf(
			"nobody can administer this deployment: %s mode is on with no group bound to "+
				"administration, and OPENPSIRT_BOOTSTRAP_ADMINS names nobody. Name somebody "+
				"there and start again",
			mode)
	}
	logger.Info("roles are assigned", "mode", mode)

	// Providers are built at startup so a misconfigured one stops the process
	// rather than producing a deployment whose sign-in fails later, in a way
	// only the person trying to sign in ever sees.
	providers, err := signInProviders(ctx, cfg, logger)
	if err != nil {
		return err
	}
	// One provider at a time is a rule across time, not only at one instant
	// (REQ-41). A deployment pointed at a second provider reads identifiers
	// the first issued as though this one had issued them, and two providers
	// do not agree on what any given identifier names — so the first person
	// to sign in redeems whatever the identifier they happen to hold was
	// bound to. Nothing at sign-in time can tell that from an ordinary
	// arrival, which is why it is refused here.
	if err := onlyTheBoundProvider(ctx, rights, providers); err != nil {
		return err
	}
	if len(providers) > 0 && cfg.BaseURL == "" {
		// A provider sends people back to an address, and it compares that
		// address against what it was registered with. Deriving it from
		// whatever a request claims its host is would make the address depend
		// on the request — so it is stated, and a deployment that configured a
		// provider without stating it stops here rather than at somebody's
		// first sign-in.
		return errors.New("OPENPSIRT_BASE_URL has to name the address people reach this on, " +
			"because a provider is configured")
	}

	// Where files hanging off an issue are kept. Nothing configured is the
	// ordinary case: attachments are off and everything else works.
	logger.Info("checking the attachment store")
	files, err := attachmentStore(ctx, cfg, logger)
	if err != nil {
		return err
	}

	// An API-only build serves no page and says so once; a binary whose
	// embedded interface cannot be read at all is broken and refuses to
	// start. Two different states, told apart here, because serving nothing
	// on purpose and serving nothing by accident look identical from a
	// browser.
	pages, err := webui.Files()
	switch {
	case errors.Is(err, webui.ErrNoInterface):
		logger.Info("serving the API only", "why", err)
		pages = nil
	case err != nil:
		return fmt.Errorf("the interface built into this binary could not be read: %w", err)
	}

	queueing := queue.DefaultOptions()
	// What the deployment sizes. How deep the queue may get is not among
	// these: it is a stored setting, so an operator meeting a refused upload
	// has a remedy that does not need a restart.
	queueing.MaxAttempts = cfg.QueueMaxAttempts
	queueing.ClaimTimeout = cfg.QueueClaimTimeout
	queueing.Heartbeat = cfg.QueueHeartbeat
	queueing.MaxHold = cfg.QueueMaxHold
	queueing.Backoff = cfg.QueueBackoff
	if err := queueing.Check(); err != nil {
		return err
	}
	// The ceiling on one hold is what cuts a long scan off, and it is the only
	// bound here that can: the claim is renewed for as long as the scan runs,
	// so the claim timeout never reaches it. A scanner allowed to run past the
	// ceiling would be killed mid-run on every attempt and the job set aside
	// with nothing saying why, so the two are compared where both are in hand
	// rather than left to a documentation row.
	if queueing.MaxHold > 0 && cfg.ScannerTimeout >= queueing.MaxHold {
		return fmt.Errorf(
			"OPENPSIRT_SCANNER_TIMEOUT is %s, which is not below the %s a worker may hold "+
				"one job for — a scan allowed to run that long is killed before it finishes",
			cfg.ScannerTimeout, queueing.MaxHold)
	}
	work := queue.New(db, queueing)
	// Named before the handler is built as well as before the workers are:
	// work that must happen once — rewriting deadlines after a policy
	// change — is held by one replica, and the name is what holds it.
	name := workerName()
	handler, _ := httpapi.New(logger, db.Validate, httpapi.Ingest{
		DB: db, Queue: work, Replica: name,
		Interface: httpapi.Interface{Files: pages},
		Access: access.NewResolver(rights, access.Trust{
			Header: cfg.TrustedHeader, From: cfg.TrustedSources,
			GroupsHeader: cfg.TrustedGroupsHeader, GroupsDelimiter: cfg.TrustedGroupsDelimiter,
		}).WithLogger(logger).WithMode(roleMode(settings)).OverPlainHTTP(cfg.PlainHTTP),
		Providers:       providers,
		BaseURL:         cfg.BaseURL,
		PlainHTTP:       cfg.PlainHTTP,
		SessionLifetime: cfg.SessionLifetime,
		Publisher: publisher.Named{
			Name: cfg.PublisherName, Namespace: cfg.PublisherNamespace,
			Category: cfg.PublisherCategory,
		},
		Mode:  roleMode(settings),
		Files: files,
	})

	// Every replica serves, reads and scans. Separate worker deployments would
	// be more things to run and more things to get wrong for an installation
	// this size, and the queue already stops two of them taking the same work.
	reader := ingest.NewReader(db, work, cfg.Limits(), logger, name)
	// A scan that moves the code out from under somebody's judgment hands
	// them work back that they did nothing to cause, so they are told.
	// Wired here rather than inside the scanner: what a scan does and how
	// anybody hears about it are separate concerns, and the notification
	// pass reads what has been ingested, so a scanner reaching it directly
	// would close a cycle between the two.
	runner := scanner.NewRunner(db, work, scanner.Grype{
		Path: cfg.ScannerPath, Timeout: cfg.ScannerTimeout, Limits: cfg.ScannerLimits(),
	}, logger, name).
		Telling(notify.Lapses(db.DB, logger))
	// Asks public indexes what upstream has released. Started whatever the
	// setting says and does nothing until it is turned on: the setting is
	// read each cycle, so turning this off takes effect without a
	// redeploy, which matters more than turning it on does.
	//
	// Started on every replica and asking on one: the politeness this pass
	// is built around is a rate per deployment, so which replica asks is
	// settled by a lease rather than by all of them asking at once.
	upstream := currency.NewRefresher(db.DB, logger, name)
	// Places work nobody holds onto the team a standing rule names. Queued
	// work rather than part of the request that saved the rule: one rule
	// sweeps thousands of findings, and saving a form must not hold a
	// transaction open across the estate.
	routing := finding.NewSweeper(db, work, logger, name)
	// What the tool has to say about its own health. It needs nothing
	// configured, which is the point: an operator who never set up mail is
	// exactly the one who would otherwise never hear that a build stopped
	// being scanned.
	watch := notify.NewWatch(db.DB, logger)
	// Asks for everything tracked to be scanned again against the day's
	// vulnerability data. Started on every replica and asking on one, by
	// the same lease the upstream pass uses: two replicas asking would put
	// two scans of one build on the queue and the second would find
	// nothing to do.
	schedule := scanner.NewSchedule(db, work, logger, name)
	// What leaves the application, where an operator configured somewhere for
	// it to go. Nil when they did not, which is ordinary rather than broken:
	// the notification area is the channel that always exists.
	post := notify.NewPost(db.DB, mailChannel(cfg, logger), cfg.BaseURL, logger, name)
	// One signed request per notification, to whatever destinations an
	// administrator configured. Started whatever is configured and does
	// nothing where nothing is: the destinations are read each cycle, so
	// adding one takes effect without a redeploy.
	outward := notify.NewSignal(db.DB, cfg.BaseURL, logger, name)
	// Removes uploads nothing ever referred to. Nil where this deployment
	// holds no files, which is ordinary.
	keeper := attach.NewKeeper(db.DB, files, logger, 0)
	// Sets aside work whose worker never came back. Nothing else is the
	// moment to notice: a worker that was killed reports nothing, so the row
	// would sit claimed for ever and read everywhere else as work in progress.
	undertaker := queue.NewUndertaker(work, queue.NewLeases(db.DB), name, logger)
	return serve(cfg, logger, handler, passes{
		reader: reader, runner: runner, schedule: schedule, upstream: upstream,
		watch: watch, post: post, outward: outward, keeper: keeper, routing: routing,
		undertaker: undertaker,
	})
}

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

// workerName identifies this process in a claim, so a job held by something
// that has since died can be told apart from one being worked on.
func workerName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("%s/%d", host, os.Getpid())
}

// closeQuietly closes the database at shutdown. A failure here changes nothing
// about the exit, but silence would hide a genuinely stuck connection.
func closeQuietly(db *database.DB, logger *slog.Logger) {
	if err := db.Close(); err != nil {
		logger.Warn("closing the database", "error", err)
	}
}

// startupFailed names what the process was doing when it gave up.
//
// A deadline reached says only "context deadline exceeded", which names
// nothing an operator can go and look at. What they need is which of the
// things contacted before the server listens did not answer.
func startupFailed(err error, doing string, cfg config.Config) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("gave up %s after %s: %w", doing, cfg.StartupTimeout, err)
	}
	return err
}

func openDatabase(ctx context.Context, cfg config.Config, logger *slog.Logger) (*database.DB, error) {
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("no database configured: set OPENPSIRT_DATABASE_URL")
	}
	target, err := database.ParseURL(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	target.RequireEncryption = cfg.DBRequireEncryption
	db, err := database.OpenWithPool(ctx, target, database.Pool{
		MaxOpen:     cfg.DBMaxOpen,
		MaxIdle:     cfg.DBMaxIdle,
		IdleTimeout: cfg.DBIdleTimeout,
		Lifetime:    cfg.DBLifetime,
	})
	if err != nil {
		return nil, err
	}
	// The transport is logged because both drivers negotiate it
	// opportunistically and neither says which way it went, so a deployment
	// that believed the connection to its findings was encrypted had nowhere
	// to check.
	logger.Info("database connected",
		"engine", db.Server.Engine, "version", db.Server.Version,
		"transport", db.Server.Transport, "url", target.Redacted)
	// Only where the deployment has not stated that encryption is required: a
	// connection that did not get it is refused above where it has, so
	// reaching here means this is the state that was chosen.
	if db.Server.Engine.IsProduction() && db.Server.Transport == "none" {
		logger.Warn("the database connection is not encrypted",
			"engine", db.Server.Engine,
			"remedy", "ask for encryption in OPENPSIRT_DATABASE_URL: sslmode=verify-full, "+
				"or tls=true — and set "+database.RequiredEncryption+" to refuse a "+
				"connection that does not get it")
	}
	if !db.Server.Engine.IsProduction() {
		logger.Warn("this database is for development and testing only",
			"engine", db.Server.Engine)
	}
	return db, nil
}

// schemaIsCurrent refuses to serve against a schema this build is ahead of.
//
// Applying migrations separately is supported and is why the setting exists.
// What it leaves is a binary and a schema that move independently, and nothing
// compared them: a build carrying a new migration started, granted
// administrators, answered the readiness probe, and failed every request that
// touched the new table. In a rolling deployment the probe passing is what
// retires the last replica that worked.
//
// Refused at startup rather than through readiness, which is where every other
// startup condition is refused and what keeps the previous replica alive.
//
// **Only when the database is behind.** A schema ahead of this build is a
// rollback, which has to keep working: the migrations a newer binary applied
// are additive, and refusing here would leave a bad deployment with no way
// back.
//
// **It compares version numbers, which is less than it sounds.** Before the
// first release a schema change edits the migration that created the thing
// rather than adding one beside it, so two builds can carry the same highest
// version and different schemas — and an existing database then matches on the
// number while its columns are whatever the earlier build made. Nothing here
// can see that, which is why the line it logs names the version rather than
// calling the schema current.
func schemaIsCurrent(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	applied, err := schema.Version(ctx, db)
	if err != nil {
		return err
	}
	wanted, err := schema.Expected()
	if err != nil {
		return err
	}
	if applied < wanted {
		return fmt.Errorf(
			"the database is at schema version %d and this build expects %d: "+
				"run \"openpsirt migrate up\", or set OPENPSIRT_AUTO_MIGRATE=true",
			applied, wanted)
	}
	if applied > wanted {
		logger.Info("automatic migration is off, and the schema is ahead of this build",
			"applied", applied, "expected", wanted)
		return nil
	}
	logger.Info("automatic migration is off, and the schema version is the one this build expects",
		"version", applied)
	return nil
}

// runMigrate applies or rolls back schema changes on their own, so an operator
// can run them under different credentials and at a time they choose.
func runMigrate(ctx context.Context, cfg config.Config, logger *slog.Logger, stdout *os.File, args []string) error {
	action := "up"
	if len(args) > 0 {
		action = args[0]
	}

	db, err := openDatabase(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer closeQuietly(db, logger)

	switch action {
	case "up":
		return schema.Up(ctx, db, logger)
	case "down":
		return schema.Down(ctx, db, logger)
	case "status":
		applied, err := schema.Version(ctx, db)
		if err != nil {
			return err
		}
		// Both numbers, because one of them answers nothing. "Schema version
		// 34" is only useful beside what this build was written against.
		wanted, err := schema.Expected()
		if err != nil {
			return err
		}
		state := "the version this build expects"
		switch {
		case applied < wanted:
			state = fmt.Sprintf("behind by %d", wanted-applied)
		case applied > wanted:
			state = "ahead of this build"
		}
		_, err = fmt.Fprintf(stdout, "%s %s, schema version %d of %d (%s)\n",
			db.Server.Engine, db.Server.Version, applied, wanted, state)
		return err
	}
	return fmt.Errorf("unknown migrate action %q: want up, down or status", action)
}

func newLogger(cfg config.Config, w *os.File) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// passes is what runs beside the server.
//
// Two of them may be absent because the thing they work on is not configured:
// the mail sender where no channel is, and the attachment sweeper where no
// store is. The rest always run. Guarding all of them read as though any could
// be missing, and made the reader open a package per pass to find out that
// most of the guards could never be false.
//
// Grouped rather than passed one at a time. Twelve parameters is past what a
// call site can be read at, and they divide cleanly into what to serve and
// what to run beside it — this is the second half.
type passes struct {
	reader   *ingest.Reader
	runner   *scanner.Runner
	schedule *scanner.Schedule
	upstream *currency.Refresher
	watch    *notify.Watch
	post     *notify.Post
	outward  *notify.Signal
	keeper   *attach.Keeper
	routing  *finding.Sweeper
	// undertaker sets aside work whose worker never came back, which is the
	// only pass that observes a worker having died at all.
	undertaker *queue.Undertaker
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
	// The ones that always run. Seven of these constructors return a value
	// unconditionally; NewUndertaker returns nil only for a nil queue, which
	// queue.New never produces, and Undertaker.Run answers a nil receiver. So
	// a guard on any of them is a condition a reader has to go and disprove —
	// which is what four of them were.
	all := []loop{
		{"read what arrived", p.reader.Run, readInterval},
		{"scan what arrived", p.runner.Run, readInterval},
		{"schedule rescans", p.schedule.Run, scheduleInterval},
		{"ask upstream what is current", p.upstream.Run, askInterval},
		{"watch for quiet builds", p.watch.Run, 0},
		{"send what is owed outward", p.outward.Run, 0},
		{"route unheld work to teams", p.routing.Run, readInterval},
		{"set aside work whose worker died", p.undertaker.Run, 0},
	}
	// And the two a deployment may not have. NewPost answers nil where no
	// mail channel is configured and NewKeeper where no attachment store is,
	// so these two guards are the ones that say something.
	if p.post != nil {
		all = append(all, loop{"send mail", p.post.Run, 0})
	}
	if p.keeper != nil {
		all = append(all, loop{"sweep unattached files", p.keeper.Run, 0})
	}
	return all
}

func serve(cfg config.Config, logger *slog.Logger, handler http.Handler, beside passes) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Reading stops when the signal arrives, before the server drains, so a
	// scan is not picked up during the seconds we are on our way out.
	workers := beside.background(ctx)
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
		// timer that fires at once. Returning here left them mid-query while
		// the caller's deferred close took the database away — an orderly
		// failure to listen turned into failed scans and jobs retried for no
		// reason. Stopping them is what ctx's cancel does; waiting is what
		// this adds.
		stop()
		return errors.Join(err, workersStopped(workers, cfg, logger))
	case <-ctx.Done():
	}

	// Let in-flight requests finish rather than cutting them off.
	logger.Info("shutting down", "grace", cfg.ShutdownGrace)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()
	shutdownErr := srv.Shutdown(shutdownCtx)

	// And give the workers the same bound, rather than none.
	//
	// This wait used to be unbounded, on the reasoning above — a worker
	// mid-query should not have the database pulled from under it. That
	// reasoning holds and the wait stays; what it lacked was an end. On SQLite
	// the pool is one connection by design, so an HTTP handler running a slow
	// statement blocks every worker behind it, and a worker that cannot get a
	// connection cannot notice it has been asked to stop. Waiting for it then
	// waits for the request, and shutting down takes as long as the slowest
	// thing in the process.
	//
	// Observed: a query that should have taken milliseconds ran for over an
	// hour, SIGTERM did nothing, and the process had to be killed. A shutdown
	// that cannot be completed by the signal meant for it is not a shutdown.
	// Both halves of the grace answer the same way. An overrun request made
	// Shutdown return an error and the process exit 1; an overrun worker
	// logged a warning and returned nil, so the process exited 0 — and
	// `docs/configuration.md` describes the two as one setting applied twice.
	// A supervisor reading the exit code was told that half of a shutdown
	// that did not finish had finished.
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

// onlyTheBoundProvider refuses a provider change that nobody re-granted.
//
// Identities bound by a provider that is no longer configured are not
// interpretable: the identifiers belong to somebody else's namespace. The way
// out is to withdraw the bindings deliberately, which is an administrative act
// with a record, rather than to have them silently mean something new.
func onlyTheBoundProvider(ctx context.Context, rights *access.Store, providers map[string]signin.Provider) error {
	if len(providers) == 0 {
		// Nothing is configured, so nothing reinterprets anything. A
		// deployment authenticating at a proxy is the ordinary case here.
		return nil
	}
	bound, err := rights.BoundProviders(ctx)
	if err != nil {
		return err
	}
	// Compared on the issuer rather than the name. The name is a label an
	// operator picks and may change without anything about the identities
	// moving, and repointing the issuer at a different provider while leaving
	// the label alone is the ordinary shape of a provider change — so
	// comparing names would miss the case this exists for and refuse the one
	// it does not care about.
	issuers := make(map[string]bool, len(providers))
	configured := make([]string, 0, len(providers))
	for _, provider := range providers {
		issuers[provider.Issuer()] = true
		configured = append(configured, provider.Issuer())
	}
	sort.Strings(configured)

	for _, was := range bound {
		if issuers[was] {
			continue
		}
		// The way out has to be in the message. By the time anybody reads
		// this the provider has already changed and the process will not
		// start, so the route that withdraws a binding is not serving — and
		// naming the act without saying where it is reachable from leaves an
		// operator with a stopped process and no next step.
		return fmt.Errorf(
			"identities here are bound to %q and this deployment is configured for %s: "+
				"an identifier one provider issued names somebody else at another. Point "+
				"OPENPSIRT_OIDC_ISSUER back at %[1]q, unbind each person under Administration "+
				"(DELETE /v1/people/{identity}/identifier), and change the issuer after that "+
				"— a binding is withdrawn while the provider that made it is still "+
				"configured. Where %[1]q cannot be reached either, configure the trusted "+
				"header with no provider at all and do the same from there",
			was, strings.Join(configured, ", "))
	}
	return nil
}

// signInProviders builds the way somebody may sign in.
//
// A deployment may configure none, which is the arrangement where a reverse
// proxy authenticates instead — so an empty set is not a fault. It may not
// configure two: an identity here is a username, and two providers issuing
// usernames independently would make the same name two different people or one
// person two accounts, depending on which way the ambiguity fell (REQ-41).
func signInProviders(ctx context.Context, cfg config.Config, logger *slog.Logger) (map[string]signin.Provider, error) {
	providers := map[string]signin.Provider{}

	// Refused here rather than at somebody's first sign-in, which is the point
	// of building providers at startup at all. Naming both settings is what
	// makes the message actionable: whichever one is wrong, the operator can
	// see which two are fighting.
	if cfg.OIDCIssuer != "" && cfg.GitHubClientID != "" {
		return nil, fmt.Errorf(
			"two sign-in providers are configured: OPENPSIRT_OIDC_ISSUER and " +
				"OPENPSIRT_GITHUB_CLIENT_ID. One provider is configured at a time, because an " +
				"identity here is a username and two providers issuing them independently " +
				"cannot be told apart. Remove one and start again")
	}

	if cfg.OIDCIssuer != "" {
		provider, err := signin.NewOIDC(ctx, signin.OIDCConfig{
			Name: cfg.OIDCName, Issuer: cfg.OIDCIssuer,
			ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret,
			GroupsClaim: cfg.OIDCGroupsClaim, UsernameClaim: cfg.OIDCUsernameClaim,
		})
		if err != nil {
			return nil, err
		}
		providers[provider.Name()] = provider
		logger.Info("sign-in configured", "provider", provider.Name(), "issuer", cfg.OIDCIssuer)
	}

	if cfg.GitHubClientID != "" {
		provider, err := signin.NewGitHub(signin.GitHubConfig{
			ClientID: cfg.GitHubClientID, ClientSecret: cfg.GitHubClientSecret,
			Organization: cfg.GitHubOrg,
		})
		if err != nil {
			return nil, err
		}
		providers[provider.Name()] = provider
		logger.Info("sign-in configured", "provider", provider.Name(), "organization", cfg.GitHubOrg)
	}

	return providers, nil
}

// roleMode reads where roles come from, per request.
//
// Read rather than held because an administrator can change it without a
// restart, and a held copy would keep deriving roles from groups after they
// turned that off. A read that fails answers with the mode that derives
// nothing, which is the safe direction.
func roleMode(settings *setting.Store) func(context.Context) access.Mode {
	return func(ctx context.Context) access.Mode {
		stored, _, err := settings.Get(ctx, setting.RoleMode)
		if err != nil {
			return access.Direct
		}
		return access.AsMode(stored)
	}
}

// mailChannel is the channel an operator configured, or nothing.
//
// Returned as the interface rather than the concrete type, and deliberately
// through a function that can answer nil: a typed nil pointer handed to an
// interface is not nil, and the sweep asks whether it has a channel.
// Which of the two it got is logged, the way the attachment store logs what it
// chose. Half a configuration is refused where it is read, so what reaches
// here is either a whole one or none — and "none" is ordinary rather than a
// fault, which is exactly why it has to be said out loud.
func mailChannel(cfg config.Config, logger *slog.Logger) notify.Channel {
	mail := notify.NewMail(cfg.MailServer, cfg.MailFrom, cfg.MailUsername, cfg.MailPassword)
	if mail == nil {
		logger.Info("mail is not configured, so nothing is sent outside the application")
		return nil
	}
	logger.Info("mail is configured", "server", cfg.MailServer, "from", cfg.MailFrom)
	return mail
}

// noteStoreInTheClear says what a plaintext object store costs, at every start
// rather than once at the moment somebody configured it. The address a browser
// is redirected to carries its own authorization, so anybody on the path
// between them and the store may fetch the file it names.
//
// Its own function so that a test can watch it happen. Reached through the
// store's own report rather than through the setting, because what matters is
// the endpoint that was accepted rather than the intent that admitted it, and
// the endpoint it names has had any password taken out of it.
func noteStoreInTheClear(bucket *attach.Bucket, logger *slog.Logger) {
	if !bucket.InTheClear() {
		return
	}
	logger.Warn("attachment links cross the network in the clear",
		"endpoint", bucket.Endpoint())
}

// attachmentStore is where attachments go, or nothing where an operator
// configured nowhere.
//
// The bucket wins where both are set. The local directory is the development
// backend — one process and one disk — and a deployment that named a bucket
// meant the bucket.
func attachmentStore(ctx context.Context, cfg config.Config, logger *slog.Logger) (attach.Storage, error) {
	bucket, err := attach.NewBucket(ctx, attach.BucketConfig{
		Endpoint:  cfg.AttachmentEndpoint,
		Bucket:    cfg.AttachmentBucket,
		Region:    cfg.AttachmentRegion,
		Key:       cfg.AttachmentKey,
		Secret:    cfg.AttachmentSecret,
		Token:     cfg.AttachmentToken,
		PathStyle: cfg.AttachmentPathStyle,
		AllowHTTP: cfg.AttachmentAllowHTTP,
	})
	if err != nil {
		return nil, err
	}
	if bucket != nil {
		// Asked now rather than at somebody's first upload. A bucket that does
		// not answer is a configuration mistake, and the moment to report one
		// is while whoever made it is still watching the logs.
		if err := bucket.Reachable(ctx); err != nil {
			return nil, err
		}
		noteStoreInTheClear(bucket, logger)
		logger.Info("attachments are held in an object store", "bucket", cfg.AttachmentBucket)
		return bucket, nil
	}
	local, err := attach.NewFiles(cfg.AttachmentDir)
	if err != nil {
		return nil, err
	}
	if local == nil {
		return nil, nil
	}
	if err := local.Reachable(ctx); err != nil {
		return nil, err
	}
	// Said plainly, because it is the backend that is not a production
	// option: one process and one disk, and two replicas would disagree about
	// what exists.
	logger.Warn("attachments are held on this machine's disk, which is for development",
		"directory", cfg.AttachmentDir)
	return local, nil
}
