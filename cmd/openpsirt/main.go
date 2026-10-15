// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

// Command openpsirt serves the OpenPSIRT API.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/attach"
	"github.com/nexthop-ai/openpsirt/internal/config"
	"github.com/nexthop-ai/openpsirt/internal/currency"
	"github.com/nexthop-ai/openpsirt/internal/cverecord"
	"github.com/nexthop-ai/openpsirt/internal/database"
	"github.com/nexthop-ai/openpsirt/internal/directory"
	"github.com/nexthop-ai/openpsirt/internal/finding"
	"github.com/nexthop-ai/openpsirt/internal/httpapi"
	"github.com/nexthop-ai/openpsirt/internal/httpapi/core"
	"github.com/nexthop-ai/openpsirt/internal/ingest"
	"github.com/nexthop-ai/openpsirt/internal/notify"
	"github.com/nexthop-ai/openpsirt/internal/patchbranch"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
	"github.com/nexthop-ai/openpsirt/internal/schema"
	"github.com/nexthop-ai/openpsirt/internal/setting"
	"github.com/nexthop-ai/openpsirt/internal/supplier"
	"github.com/nexthop-ai/openpsirt/internal/trail"
	"github.com/nexthop-ai/openpsirt/internal/version"
	"github.com/nexthop-ai/openpsirt/internal/webui"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "openpsirt: %v\n", err)
		os.Exit(1)
	}
}

// configUsage is what --config says about itself wherever it is accepted.
const configUsage = "read settings from this TOML file rather than the environment"

// configFlag sets where settings are read from, refusing an empty path. An
// empty one is what `--config "$CONF"` passes with CONF unset, and read as no
// file it would fall back to the environment and stop somewhere unrelated.
func configFlag(file *string) func(string) error {
	return func(path string) error {
		if path == "" {
			return errors.New("names no file")
		}
		*file = path
		return nil
	}
}

func run(args []string, stdout, stderr *os.File) (err error) {
	fs := flag.NewFlagSet("openpsirt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print the build and exit")
	dumpSpec := fs.Bool("openapi", false, "write the OpenAPI document to stdout and exit")
	var file string
	fs.Func("config", configUsage, configFlag(&file))
	if err := fs.Parse(args); err != nil {
		// A request for help is not a failure.
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

	// A subcommand this does not know is refused rather than ignored.
	// Ignored, `openpsirt migrat` would start the server — a typo in a job
	// meant to apply migrations and nothing else, answering requests against
	// whatever schema is there. runMigrate refuses an action it does not
	// know in the same way.
	//
	// Each subcommand takes --config after its name as well as before it, so
	// `openpsirt migrate up --config f` names the file where it is written.
	command, action, operand := "serve", "", ""
	if fs.NArg() > 0 {
		command = fs.Arg(0)
		if command != "serve" && command != "migrate" && command != "records" && command != "health" {
			return fmt.Errorf("unknown command %q: the commands are \"serve\", \"migrate\", "+
				"\"records\" and \"health\"", command)
		}
		rest := fs.Args()[1:]
		for {
			sub := flag.NewFlagSet("openpsirt "+command, flag.ContinueOnError)
			sub.SetOutput(stderr)
			sub.Func("config", configUsage, configFlag(&file))
			if err := sub.Parse(rest); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil
				}
				return err
			}
			if sub.NArg() == 0 {
				break
			}
			switch {
			case command == "serve" || command == "health":
				return fmt.Errorf("openpsirt %s: unexpected argument %q", command, sub.Arg(0))
			case action == "":
				action = sub.Arg(0)
			// Importing names the archive it reads, and nothing else takes a
			// second argument.
			case command == "records" && action == "import" && operand == "":
				operand = sub.Arg(0)
			default:
				return fmt.Errorf("openpsirt %s: unexpected argument %q", command, sub.Arg(0))
			}
			rest = sub.Args()[1:]
		}
	}

	var cfg config.Config
	if file == "" {
		cfg, err = config.Load()
	} else {
		cfg, err = config.LoadFile(file, os.Environ())
	}
	if err != nil {
		return err
	}
	if file != "" {
		// Every refusal from here on names a setting by its key in the file,
		// which is where somebody configuring by file changes it. Not the
		// refusal of the file itself, which names variables that are set.
		defer func() { err = config.InFile(err) }()
	}
	logger := newLogger(cfg, stderr)

	// Generating the document from the running registrations is what keeps it
	// from drifting away from the server. It needs no database.
	if *dumpSpec {
		_, api := httpapi.New(logger, nil, core.Deps{})
		doc, err := api.OpenAPI().YAML()
		if err != nil {
			return fmt.Errorf("render OpenAPI document: %w", err)
		}
		_, err = stdout.Write(doc)
		return err
	}

	ctx := context.Background()
	if command == "health" {
		return runHealth(ctx, cfg.Addr)
	}
	if command == "migrate" {
		return runMigrate(ctx, cfg, logger, stdout, action)
	}
	if command == "records" {
		return runRecords(ctx, cfg, logger, stdout, action, operand)
	}

	// Everything below this line is contacted before the server listens, and
	// all of it under one deadline.
	//
	// Unbounded, a hang here is silent and total. An endpoint that accepts the
	// connection and never answers holds PingContext for ever: the process is
	// up, no port is listening, and not one log line has been written — from
	// outside, the same thing as a slow image pull. A crash
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
	// Outside the startup deadline, and the deadline is why: a migration
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
	// A database last opened by a release that kept no statistics, or copied
	// in from elsewhere, has none until a scan applies.
	if err := database.RefreshStatistics(ctx, db); err != nil {
		logger.Error("could not refresh the planner's statistics", "error", err)
	}

	handler, beside, err := prepare(ctx, cfg, logger, db)
	if err != nil {
		return err
	}
	return serve(cfg, logger, handler, beside)
}

// prepare is everything a start does after the schema is in place and before
// the server listens: the administrators and group mappings named in
// configuration, the sign-in providers, the stores, the queue and the passes.
//
// Apart from run so that each refusal it makes is reachable by a test with a
// database and a configuration in hand, rather than only by starting the
// program.
func prepare(ctx context.Context, cfg config.Config, logger *slog.Logger,
	db *database.DB) (http.Handler, passes, error) {

	// Named administrators are granted at every start, which is what makes
	// this the way back in rather than a one-time setup step.
	// Each one named or no longer named is recorded in the administrative
	// trail, against configuration.
	unnamed, err := trail.NameAdministrators(ctx, db.DB, cfg.BootstrapAdmins)
	if err != nil {
		return nil, passes{}, startupFailed(err, "granting the administrators named in configuration", cfg)
	}
	if len(cfg.BootstrapAdmins) > 0 {
		logger.Info("administrators granted from configuration", "count", len(cfg.BootstrapAdmins))
	}
	// Taking administration away is also said in the log, where an operator
	// who just edited the configuration is looking.
	for _, identity := range unnamed {
		logger.Warn("administration named in configuration withdrawn: no longer named",
			"identity", identity)
	}

	// Group mappings are applied at every start, and decide where roles come
	// from: any mapping means groups, none means an administrator assigns
	// them. Each change is recorded in the administrative trail against
	// configuration, and the whole map is logged, because a group whose
	// spelling is wrong grants nothing and says nothing.
	//
	// A deployment that cannot reach its own administration has one route
	// back — editing the database by hand — and nobody discovers that at a
	// good moment. Applying the mappings refuses one, and changes nothing
	// when it does.
	mapped, mode, err := trail.MapGroups(ctx, db.DB, cfg.GroupRoles)
	switch {
	case errors.Is(err, access.ErrNobodyAdministers) && len(cfg.GroupRoles) > 0:
		return nil, passes{}, fmt.Errorf("nobody can administer this deployment: OPENPSIRT_GROUP_ROLES maps no " +
			"group to admin, and OPENPSIRT_BOOTSTRAP_ADMINS names nobody who can. Map a group to " +
			"admin or name somebody there, and start again")
	case errors.Is(err, access.ErrNobodyAdministers):
		return nil, passes{}, fmt.Errorf("nobody can administer this deployment: nobody holds administration, " +
			"and OPENPSIRT_BOOTSTRAP_ADMINS names nobody who can. Name somebody there and start again")
	case err != nil:
		return nil, passes{}, startupFailed(err, "applying the group mappings named in configuration", cfg)
	}
	for _, mapping := range cfg.GroupRoles {
		logger.Info("group mapped", "mapping", mapping.String(), "grants", mapping.Grants)
	}
	for _, mapping := range mapped.Removed {
		logger.Warn("group mapping withdrawn: configuration no longer states it",
			"mapping", mapping.String(), "grants", mapping.Grants)
	}
	settings := setting.NewStore(db.DB)
	rights := access.NewStore(db.DB)
	logger.Info("roles are assigned", "mode", mode)

	// Providers are built at startup so a misconfigured one stops the process
	// rather than producing a deployment whose sign-in fails later, in a way
	// only the person trying to sign in ever sees.
	providers, err := signInProviders(ctx, cfg, logger)
	if err != nil {
		return nil, passes{}, err
	}
	// One provider at a time is a rule across time, not only at one instant
	// (REQ-41). A deployment pointed at a second provider reads identifiers
	// the first issued as though this one had issued them, and two providers
	// do not agree on what any given identifier names — so the first person
	// to sign in redeems whatever the identifier they happen to hold was
	// bound to. Nothing at sign-in time can tell that from an ordinary
	// arrival, which is why it is refused here.
	if err := onlyTheBoundProvider(ctx, rights, providers); err != nil {
		return nil, passes{}, err
	}
	if err := returnsTo(providers, cfg.BaseURL); err != nil {
		return nil, passes{}, err
	}

	// The store for files hanging off an issue. Nothing configured is the
	// ordinary case: attachments are off and everything else works.
	logger.Info("checking the attachment store")
	files, err := attachmentStore(ctx, cfg, logger)
	if err != nil {
		return nil, passes{}, err
	}

	// Where the advisories that have gone out are written for somebody else
	// to serve. Nothing configured is the ordinary case: documents are
	// generated and handed over, and no directory is written.
	logger.Info("checking the published advisory directory store")
	published, err := directoryStore(ctx, cfg, logger)
	if err != nil {
		return nil, passes{}, err
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
		return nil, passes{}, fmt.Errorf("the interface built into this binary could not be read: %w", err)
	}

	queueing := queue.DefaultOptions()
	// The sizes the deployment sets. The queue's depth is not among
	// these: it is a stored setting, so an operator meeting a refused upload
	// has a remedy that does not need a restart.
	queueing.MaxAttempts = cfg.QueueMaxAttempts
	queueing.ClaimTimeout = cfg.QueueClaimTimeout
	queueing.Heartbeat = cfg.QueueHeartbeat
	queueing.MaxHold = cfg.QueueMaxHold
	queueing.Backoff = cfg.QueueBackoff
	if err := queueing.Check(); err != nil {
		return nil, passes{}, err
	}
	// The ceiling on one hold is what cuts a long scan off, and it is the only
	// bound here that can: the claim is renewed for as long as the scan runs,
	// so the claim timeout never reaches it. A scanner allowed to run past the
	// ceiling would be killed mid-run on every attempt and the job set aside
	// with nothing saying why, so the two are compared where both are in hand
	// rather than left to a documentation row.
	if queueing.MaxHold > 0 && cfg.ScannerTimeout >= queueing.MaxHold {
		return nil, passes{}, fmt.Errorf(
			"OPENPSIRT_SCANNER_TIMEOUT is %s, which is not below the %s a worker may hold "+
				"one job for — a scan allowed to run that long is killed before it finishes",
			cfg.ScannerTimeout, queueing.MaxHold)
	}
	work := queue.New(db, queueing)
	// Named before the handler is built as well as before the workers are:
	// work that must happen once — rewriting deadlines after a policy
	// change — is held by one replica, and the name is what holds it.
	name := workerName()
	// The names this deployment calls its own, and so never sends to a public
	// package index. Derived from the namespace it publishes under, which is
	// the one place it has already said who it is, and unioned with whatever
	// else the deployment stated. What a scan was about is folded in as the
	// pass runs, because that comes from the database rather than from here.
	ours := currency.Ourselves(cfg.PublisherNamespace, cfg.UpstreamInternal)
	// The chat platforms this deployment holds a credential for, which a
	// destination and a person's own settings are checked against.
	chats := chatPlatforms(cfg, logger)
	handler, _ := httpapi.New(logger, db.Validate, core.Deps{
		DB: db, Queue: work, Replica: name,
		Interface: core.Interface{Files: pages},
		// The resolver reads through a store that bounds a derived grant to
		// the session lifetime. A browser re-derives its roles at every
		// sign-in; a personal token never signs in, so without a bound a
		// group somebody left keeps granting them roles through that token
		// for as long as it lasts. The same window, resolved the same way, for
		// both ways in — including the administrator's setting, which is the
		// one that decides and is read per request rather than at startup.
		Access: access.NewResolver(
			rights.DerivingWithin(httpapi.DerivedWindow(settings, cfg.SessionLifetime)),
			access.Trust{
				Header: cfg.TrustedHeader, From: cfg.TrustedSources,
				GroupsHeader: cfg.TrustedGroupsHeader, GroupsDelimiter: cfg.TrustedGroupsDelimiter,
			}).WithLogger(logger).WithMode(roleMode(settings)).OverPlainHTTP(cfg.PlainHTTP),
		Providers:       providers,
		BaseURL:         cfg.BaseURL,
		PlainHTTP:       cfg.PlainHTTP,
		SessionLifetime: cfg.SessionLifetime,
		Publisher:       publishesAs(cfg),
		Mode:            roleMode(settings),
		Files:           files,
		// The names that never leave, derived once here and read by the pass
		// that asks and by the report saying what it held back. Two
		// derivations of one boundary would be two boundaries the first time
		// either moved.
		Ours:          ours,
		Excluded:      cfg.OutboundExcluded,
		PatchBranches: cfg.PatchBranches,
		Chats:         notify.Offering(chats),
	})

	// Every replica serves, reads and scans. Separate worker deployments would
	// be more things to run and more things to get wrong for an installation
	// this size, and the queue already stops two of them taking the same work.
	// An upload that changed much of what a build is made of is the one thing
	// an inventory arriving is worth interrupting anybody for. Wired here for
	// the reason the lapse notice below is: reading a document and telling
	// somebody about it are separate concerns.
	reader := ingest.NewReader(db, work, cfg.Limits(), logger, name).
		Telling(notify.Movements(db.DB, logger))
	// A scan that moves the code out from under somebody's judgment hands
	// them work back that they did nothing to cause, so they are told.
	// Wired here rather than inside the scanner: what a scan does and how
	// anybody hears about it are separate concerns, and the notification
	// pass reads what has been ingested, so a scanner reaching it directly
	// would close a cycle between the two.
	runner := scanner.NewRunner(db, work, scanner.Grype{
		Path: cfg.ScannerPath, Timeout: cfg.ScannerTimeout, Limits: cfg.ScannerLimits(),
	}, logger, name).
		Telling(notify.Lapses(db.DB, logger)).
		TellingSuperseded(notify.Superseded(db.DB, logger)).
		Narrowing(cverecord.NewHeld(cfg.RecordsDir))
	// Keeps the CVE record snapshot current with the CVE List, the way the
	// scanner keeps its own data, in a directory on the scanner's volume: each
	// replica's own on scratch space, shared where the replicas mount one
	// claim, which the rename that replaces it keeps safe. Nil where fetching
	// is off, which leaves the snapshot an operator placed there.
	var records *cverecord.Fetcher
	if cfg.RecordsUpdate {
		records = cverecord.NewFetcher(cfg.RecordsDir, logger)
	}
	// Asks public indexes what upstream has released. Started whatever the
	// setting says and does nothing until it is turned on: the setting is
	// read each cycle, so turning this off takes effect without a
	// redeploy, which matters more than turning it on does.
	//
	// Started on every replica and asking on one: the politeness this pass
	// is built around is a rate per deployment, so which replica asks is
	// settled by a lease rather than by all of them asking at once.
	upstream := currency.NewRefresher(db.DB, logger, name, ours)
	// Places work nobody holds onto the team a standing rule names. Queued
	// work rather than part of the request that saved the rule: one rule
	// sweeps thousands of findings, and saving a form must not hold a
	// transaction open across the estate.
	routing := finding.NewSweeper(db, work, logger, name)
	// The tool's own health. It needs nothing configured, which is the point:
	// an operator who never set up mail is exactly the one who would otherwise
	// never hear that a build stopped being scanned.
	watch := notify.NewWatch(db.DB, logger)
	// Asks for everything tracked to be scanned again against the day's
	// vulnerability data. Started on every replica and asking on one, by
	// the same lease the upstream pass uses: two replicas asking would put
	// two scans of one build on the queue and the second would find
	// nothing to do.
	schedule := scanner.NewSchedule(db, work, logger, name)
	// Reads what configured suppliers publish about their own flaws. Started
	// whatever is configured and doing nothing where nothing is: the
	// suppliers are read each cycle, so naming one takes effect without a
	// redeploy and so does withdrawing one. Started on every replica and
	// reaching out on one, holding a lease of its own the way the two passes
	// above hold theirs: the politeness it keeps to is a rate per deployment
	// rather than per replica.
	suppliers := supplier.NewPass(db.DB, logger, name, cfg.Limits(), cfg.OutboundExcluded)
	// Fetches the repositories patch links point into and records which
	// branches each linked commit is on. Started either way and doing nothing
	// unless the deployment turned it on. One replica fetches, settled by a
	// lease, because the copies are that replica's disk and a fetch of a large
	// tree is not work to do twice.
	branches := patchbranch.NewPass(db.DB, logger, name, patchbranch.Options{
		Dir: cfg.PatchDir, Quota: int64(cfg.PatchQuota), Excluded: cfg.OutboundExcluded,
		On: cfg.PatchBranches,
	})
	// The messages that leave the application, where an operator configured
	// somewhere for it to go. Nil when they did not, which is ordinary rather
	// than broken: the notification area is the channel that always exists.
	post := notify.NewPost(db.DB, mailChannel(cfg, logger), cfg.BaseURL, logger, name)
	// One signed request per notification, to whatever destinations an
	// administrator configured. Started whatever is configured and does
	// nothing where nothing is: the destinations are read each cycle, so
	// adding one takes effect without a redeploy.
	outward := notify.NewSignal(db.DB, cfg.BaseURL, logger, name)
	// Channel posts and direct messages on the chat platforms this deployment
	// holds a credential for. Nil where it holds none, which is ordinary.
	talk := notify.NewTalk(db.DB, chats, cfg.BaseURL, logger, name)
	// Removes uploads nothing ever referred to. Nil where this deployment
	// holds no files, which is ordinary.
	keeper := attach.NewKeeper(db.DB, files, logger, 0)
	// Sets aside work whose worker never came back. Nothing else is the
	// moment to notice: a worker that was killed reports nothing, so the row
	// would sit claimed for ever and read everywhere else as work in progress.
	undertaker := queue.NewUndertaker(work, queue.NewLeases(db.DB), name, logger)
	// Writes the advisories that have gone out where somebody else's web
	// server can serve them. Nil where this deployment publishes no
	// directory, which is ordinary.
	writer := directory.New(db.DB, published, publishesAs(cfg), directory.Config{
		List: cfg.DirectoryList, Mirror: cfg.DirectoryMirror,
	}, logger)
	// A store configured and nothing written to it. The address is refused
	// where it is read if a store is configured without one, so what is left
	// is the publisher, which is configured elsewhere and is what every
	// document in the directory names. Said here rather than left as a
	// directory that stays empty for ever.
	if published != nil && writer == nil {
		logger.Warn("a store for published advisories is configured and nothing is " +
			"written to it: set OPENPSIRT_PUBLISHER_NAME and OPENPSIRT_PUBLISHER_NAMESPACE")
	}
	return handler, passes{
		reader: reader, runner: runner, schedule: schedule, upstream: upstream,
		watch: watch, post: post, outward: outward, talk: talk, keeper: keeper, routing: routing,
		undertaker: undertaker, publish: writer, suppliers: suppliers,
		branches: branches,
		records:  records,
	}, nil
}

// workerName identifies this process in a claim and as a lease's holder, so a
// job held by something that has since died can be told apart from one being
// worked on.
//
// The host and the process are what an operator reads, and neither tells two
// processes apart: in a container the process is the first one, and replicas
// sharing the host's network share its name. Random characters do, so two
// replicas never both hold one job or one lease.
func workerName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("%s/%d/%s", host, os.Getpid(), rand.Text()[:16])
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
	// opportunistically and neither says which way it went, and this line is
	// where a deployment checks whether the connection to its findings is
	// encrypted.
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
// It leaves a binary and a schema that move independently, and nothing
// compared them: a build carrying a new migration started, granted
// administrators, answered the readiness probe, and failed every request that
// touched the new table. In a rolling deployment the probe passing is what
// retires the last replica that worked.
//
// Refused at startup rather than through readiness, which is where every other
// startup condition is refused and what keeps the previous replica alive.
//
// A schema ahead of this build is refused too. A database is only ever
// upgraded, so a later release's schema is one this build may not read, and
// the way back to an earlier release is the backup taken before the upgrade.
//
// It compares version numbers, which is less than it sounds. Below 1.0 a
// schema change edits what declares the thing rather than adding a migration
// beside it, so two builds can carry the same highest version and different
// schemas — and an existing database then matches on the
// number while its columns are whatever the earlier build made. Nothing here
// can see that, which is why the line it logs names the version rather than
// calling the schema current.
func schemaIsCurrent(ctx context.Context, db *database.DB, logger *slog.Logger) error {
	if err := schema.NotBeforeTheBaseline(ctx, db); err != nil {
		return err
	}
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
				"run \"openpsirt migrate up\" with the same configuration, or set OPENPSIRT_AUTO_MIGRATE=true",
			applied, wanted)
	}
	if err := schema.NotAhead(ctx, db); err != nil {
		return err
	}
	logger.Info("automatic migration is off, and the schema version is the one this build expects",
		"version", applied)
	return nil
}

func newLogger(cfg config.Config, w *os.File) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
