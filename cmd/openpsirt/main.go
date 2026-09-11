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
	if fs.NArg() > 0 && fs.Arg(0) == "migrate" {
		return runMigrate(ctx, cfg, logger, stdout, fs.Args()[1:])
	}

	db, err := openDatabase(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer closeQuietly(db, logger)

	// Migrating before serving means a request never arrives against a schema
	// the code does not expect.
	if cfg.AutoMigrate {
		if err := schema.Up(ctx, db, logger); err != nil {
			return err
		}
	} else {
		logger.Info("automatic migration is off; run \"openpsirt migrate up\" separately")
	}

	// Named administrators are granted at every start, which is what makes
	// this the way back in rather than a one-time setup step.
	if err := access.Bootstrap(ctx, access.NewStore(db.DB), cfg.BootstrapAdmins); err != nil {
		return err
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
			"nobody can administer this deployment: %s mode is on with no group bound to administration, "+
				"and %sBOOTSTRAP_ADMINS names nobody. Name somebody there and start again",
			mode, "OPENPSIRT_")
	}
	logger.Info("roles are assigned", "mode", mode)

	// Providers are built at startup so a misconfigured one stops the process
	// rather than producing a deployment whose sign-in fails later, in a way
	// only the person trying to sign in ever sees.
	providers, err := signInProviders(ctx, cfg, logger)
	if err != nil {
		return err
	}
	if len(providers) > 0 && cfg.BaseURL == "" {
		// A provider sends people back to an address, and it compares that
		// address against what it was registered with. Deriving it from
		// whatever a request claims its host is would make the address depend
		// on the request — so it is stated, and a deployment that configured a
		// provider without stating it stops here rather than at somebody's
		// first sign-in.
		return fmt.Errorf(
			"%sBASE_URL has to name the address people reach this on, because a provider is configured",
			"OPENPSIRT_")
	}

	// Where files hanging off an issue are kept. Nothing configured is the
	// ordinary case: attachments are off and everything else works.
	files, err := attachmentStore(ctx, cfg, logger)
	if err != nil {
		return err
	}

	work := queue.New(db, queue.DefaultOptions())
	// Named before the handler is built as well as before the workers are:
	// work that must happen once — rewriting deadlines after a policy
	// change — is held by one replica, and the name is what holds it.
	name := workerName()
	handler, _ := httpapi.New(logger, db.Validate, httpapi.Ingest{
		DB: db, Queue: work, Replica: name,
		Interface: httpapi.Interface{Files: webui.Files()},
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
	runner := scanner.NewRunner(db, work, scanner.Grype{Path: cfg.ScannerPath}, logger, name).
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
	post := notify.NewPost(db.DB, mailChannel(cfg), cfg.BaseURL, logger, name)
	// One signed request per notification, to whatever destinations an
	// administrator configured. Started whatever is configured and does
	// nothing where nothing is: the destinations are read each cycle, so
	// adding one takes effect without a redeploy.
	outward := notify.NewSignal(db.DB, cfg.BaseURL, logger, name)
	// Removes uploads nothing ever referred to. Nil where this deployment
	// holds no files, which is ordinary.
	keeper := attach.NewKeeper(db.DB, files, logger, 0)
	return serve(cfg, logger, handler, passes{
		reader: reader, runner: runner, schedule: schedule, upstream: upstream,
		watch: watch, post: post, outward: outward, keeper: keeper, routing: routing,
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

func openDatabase(ctx context.Context, cfg config.Config, logger *slog.Logger) (*database.DB, error) {
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("no database configured: set OPENPSIRT_DATABASE_URL")
	}
	target, err := database.ParseURL(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	db, err := database.OpenWithPool(ctx, target, database.Pool{
		MaxOpen:     cfg.DBMaxOpen,
		MaxIdle:     cfg.DBMaxIdle,
		IdleTimeout: cfg.DBIdleTimeout,
		Lifetime:    cfg.DBLifetime,
	})
	if err != nil {
		return nil, err
	}
	logger.Info("database connected",
		"engine", db.Server.Engine, "version", db.Server.Version, "url", target.Redacted)
	if !db.Server.Engine.IsProduction() {
		logger.Warn("this database is for development and testing only",
			"engine", db.Server.Engine)
	}
	return db, nil
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
		v, err := schema.Version(ctx, db)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s %s, schema version %d\n",
			db.Server.Engine, db.Server.Version, v)
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

// passes is what runs beside the server: the nine background loops, each of
// which may be absent because the thing it works on is not configured.
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
	start := func(run func(context.Context, time.Duration), every time.Duration) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			run(ctx, every)
		}()
	}
	if p.reader != nil {
		start(p.reader.Run, readInterval)
	}
	if p.post != nil {
		start(p.post.Run, 0)
	}
	if p.outward != nil {
		start(p.outward.Run, 0)
	}
	if p.keeper != nil {
		start(p.keeper.Run, 0)
	}
	if p.runner != nil {
		start(p.runner.Run, readInterval)
	}
	if p.routing != nil {
		start(p.routing.Run, readInterval)
	}
	start(p.schedule.Run, scheduleInterval)
	start(p.upstream.Run, askInterval)
	start(p.watch.Run, 0)
	return &workers
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
		return err
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
	if !waitFor(workers, cfg.ShutdownGrace) {
		logger.Warn("stopped without waiting for background work to finish",
			"grace", cfg.ShutdownGrace,
			"why", "a worker did not stop in time, most likely blocked on a slow query")
	}
	if shutdownErr != nil {
		return fmt.Errorf("shutdown: %w", shutdownErr)
	}
	logger.Info("stopped")
	return nil
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

// signInProviders builds the ways somebody may sign in.
//
// A deployment may configure none, which is the arrangement where a reverse
// proxy authenticates instead — so an empty set is not a fault.
func signInProviders(ctx context.Context, cfg config.Config, logger *slog.Logger) (map[string]signin.Provider, error) {
	providers := map[string]signin.Provider{}

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
func mailChannel(cfg config.Config) notify.Channel {
	mail := notify.NewMail(cfg.MailServer, cfg.MailFrom, cfg.MailUsername, cfg.MailPassword)
	if mail == nil {
		return nil
	}
	return mail
}

// attachmentStore is where attachments go, or nothing where an operator
// configured nowhere.
//
// The bucket wins where both are set. The local directory is the development
// backend — one process and one disk — and a deployment that named a bucket
// meant the bucket.
func attachmentStore(ctx context.Context, cfg config.Config, logger *slog.Logger) (attach.Storage, error) {
	bucket, err := attach.NewBucket(ctx, cfg.AttachmentEndpoint, cfg.AttachmentBucket,
		cfg.AttachmentRegion, cfg.AttachmentKey, cfg.AttachmentSecret, cfg.AttachmentToken,
		cfg.AttachmentPathStyle)
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
