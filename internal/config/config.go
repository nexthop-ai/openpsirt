// Package config loads runtime settings.
//
// Settings come from the environment. Every one has a working default, so an
// operator can start the binary with nothing set and get something sensible.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
	"github.com/nexthop-ai/openpsirt/internal/queue"
	"github.com/nexthop-ai/openpsirt/internal/scanner"
)

// Config is everything the process needs to start.
type Config struct {
	// Addr is the host:port the HTTP server listens on.
	Addr string
	// LogLevel controls verbosity.
	LogLevel slog.Level
	// LogFormat is "text" or "json".
	LogFormat string
	// ShutdownGrace is how long in-flight requests get to finish.
	ShutdownGrace time.Duration

	// StartupTimeout bounds everything contacted before the server listens:
	// the database, the schema, the administrators named in configuration and
	// the attachment store.
	//
	// Bounded because an endpoint that accepts a connection and never answers
	// — a stale load-balancer target, a paused instance — held the process for
	// ever with no log line written and no port listening. From outside that
	// is indistinguishable from a slow image pull, and a supervisor cannot act
	// on it. A crash loop naming what it could not reach is the failure mode
	// that can be.
	StartupTimeout time.Duration
	// DatabaseURL says which database to use and how to reach it.
	DatabaseURL string
	// ReadTimeout and WriteTimeout bound a single request.
	//
	// Generous by web-server standards on purpose: scan files are large and
	// arrive over links we do not control. Too tight and a legitimate upload
	// is cut off mid-transfer.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// Database pool settings. The one that matters is IdleTimeout: a
	// connection has to be closed by us before anything in the path closes it
	// behind our back.
	DBMaxOpen     int
	DBMaxIdle     int
	DBIdleTimeout time.Duration
	DBLifetime    time.Duration
	// DBRequireEncryption states that the connection to the database must be
	// encrypted, and one that is not is refused as the process starts. Off is
	// what every deployment had: encrypted where the server offers it, and
	// cleartext where it does not. Both are choices now, and which one is in
	// force is stated rather than inherited from what a server happened to
	// offer.
	DBRequireEncryption bool
	// ScannerPath is where the vulnerability scanner lives. Empty means
	// whatever the environment resolves.
	//
	// The scanner is a requirement of a deployment rather than an option:
	// without it there is nothing to triage, because the vulnerability data is
	// produced here rather than sent to us.
	ScannerPath string
	// ScannerTimeout bounds one execution of the scanner. A scan that has
	// stopped making progress must fail as a run that failed rather than hold
	// a worker, and a deployment whose inventories legitimately take longer
	// than the default has to be able to raise it.
	ScannerTimeout time.Duration

	// The queue's own bounds, each of which the documents describe as
	// something a deployment sizes. Here rather than among the stored
	// settings because of the layering: the setting package reads the
	// database, so the database and queue packages cannot read a setting
	// without inverting that import. The consequence to accept is that
	// changing one needs a restart.
	//
	// The queue's depth is the exception and is a stored setting: an
	// operator meeting a refused upload wants that remedy without one.
	QueueMaxAttempts  int
	QueueClaimTimeout time.Duration
	QueueHeartbeat    time.Duration
	QueueMaxHold      time.Duration
	QueueBackoff      time.Duration

	// The bounds one execution of the scanner is read within. Each is what a
	// deployment may lower or raise; left unset, the package's own defaults
	// apply. Here rather than among the runtime settings for the reason the
	// ingest bounds are: what they stop is a document being read, which
	// happens in the worker rather than in a request.
	ScannerMaxOutput     int
	ScannerMaxComplaint  int
	ScannerMaxMatches    int
	ScannerMaxReferences int
	// Mail is where messages that leave the application go. Absent is
	// ordinary: the notification area needs nothing configured, and a
	// deployment that sets none of this simply tells nobody anything outside
	// the application.
	//
	// MailFrom and MailServer are both required for mail to happen at all
	// — a server with nobody to send as is not a configuration, it is half
	// of one. Credentials are optional and are refused over a connection
	// the server would not secure.
	MailFrom     string
	MailServer   string
	MailUsername string
	MailPassword string
	// AttachmentBucket is where files hanging off an issue are kept, and
	// absent is ordinary: with none of this set, attachments are off and
	// everything else works . An operator who wants none should not have
	// to run a bucket.
	//
	// AttachmentBucket is what turns the object store on. Endpoint is what
	// a self-hosted store needs and a cloud one does not; credentials are
	// optional, because a deployment on a cloud provider gets a rotating
	// role from its environment rather than a key somebody stored.
	//
	// AttachmentDir is the development backend, for running the tool
	// without standing an object store up first — one process and one
	// disk, so never a production option. The bucket wins where both are
	// set.
	AttachmentBucket    string
	AttachmentEndpoint  string
	AttachmentRegion    string
	AttachmentKey       string
	AttachmentSecret    string
	AttachmentToken     string
	AttachmentPathStyle bool
	// AttachmentAllowHTTP permits a plaintext endpoint that is not this
	// machine, for a store on a network an operator accepts that on. Off
	// unless it is set, and distinct from PlainHTTP, which is about how this
	// application is served and loosens cookies rather than anything about
	// where attachments are kept (REQ-70).
	AttachmentAllowHTTP bool
	AttachmentDir       string

	// The bounds a scan file is read within. Each is what a deployment may
	// lower or raise; left unset, the reader's own defaults apply, which
	// are several times the largest producer we have. They are here rather
	// than among the runtime settings because refusing a document too
	// large to read is the first thing that happens to it, before anything
	// has a database to consult.
	IngestMaxBytes      int
	IngestMaxComponents int
	IngestMaxEdges      int
	IngestMaxFiles      int
	IngestMaxStatements int
	IngestMaxDepth      int
	IngestMaxDocuments  int
	// BootstrapAdmins are granted administrator at every startup, not only the
	// first. Applying it every time makes it the way back in for an operator
	// who has locked themselves out: add yourself, restart. For software
	// somebody else runs, a way back in matters more than a tidy one-shot.
	//
	// It is a pre-authorization and not a bypass: being named grants the role,
	// it does not admit anybody who has not authenticated.
	BootstrapAdmins []string
	// TrustedHeader is the header a reverse proxy sets to say who somebody is,
	// and TrustedSources are the addresses it is honored from. Both are needed
	// for either to do anything.
	TrustedHeader  string
	TrustedSources []net.IPNet
	// TrustedGroupsHeader is where that proxy reports membership, and
	// TrustedGroupsDelimiter what separates the names. Neither header nor
	// separator is standardized, so both are named rather than guessed.
	TrustedGroupsHeader    string
	TrustedGroupsDelimiter string
	// BaseURL is the address people arrive on. Behind a proxy that is not what
	// this process thinks it is called, and a provider compares the callback
	// against what it was registered with, so it has to be stated.
	BaseURL string
	// PlainHTTP serves without TLS, which is what running this locally looks
	// like. It only loosens cookies, and it is named for what it is.
	PlainHTTP bool

	// Publisher is who an advisory says issued it: the organization
	// running this deployment. Per deployment rather than tuned by an
	// administrator, like any other hand-off, because it is the identity
	// of the installation in the way the address people arrive on is.
	//
	// Both a name and a namespace are needed for either to do anything: a
	// CSAF document requires both, and one without the other produces a
	// document that fails validation wherever somebody takes it next. With
	// neither, no advisory is generated and the refusal says why.
	PublisherName      string
	PublisherNamespace string
	// PublisherCategory is what the standard calls the kind of publisher.
	// A deployment publishing about its own product is a vendor.
	PublisherCategory string
	// AdvisoryPrefix is what a minted advisory identifier opens with.
	//
	// No default. An identifier is what a reader cites a document by and what
	// they search for later, so a generic one traceable to no publisher is
	// worse than refusing to mint: the refusal is fixed once by an operator,
	// and the identifier is in every document that went out.
	AdvisoryPrefix string
	// UpstreamInternal are names this deployment never sends to a public
	// package index, on top of the ones derived from the publisher's
	// namespace and from what the scans were about.
	//
	// Here rather than among the settings an administrator tunes, beside the
	// namespace the default is derived from. Asking upstream is a switch an
	// administrator throws; what leaves the deployment when it is on is a
	// boundary the person who deployed it drew, and a boundary that can be
	// widened from inside the application is not one.
	UpstreamInternal []string
	// SessionLifetime bounds a sign-in. Zero takes the built-in default.
	SessionLifetime time.Duration

	// OIDC is an OpenID Connect provider. Issuer being empty means none is
	// configured.
	OIDCName          string
	OIDCIssuer        string
	OIDCClientID      string
	OIDCClientSecret  string
	OIDCGroupsClaim   string
	OIDCUsernameClaim string

	// GitHub is OAuth 2.0 rather than OpenID Connect, so it is configured
	// separately. GitHubOrg being empty means teams are not read at all.
	GitHubClientID     string
	GitHubClientSecret string
	GitHubOrg          string

	// AutoMigrate applies outstanding schema changes at startup.
	//
	// On by default: a self-hosted operator should not need a separate step,
	// and deploying the binary is then the whole upgrade. Turning it off suits
	// someone who would rather run migrations themselves, under different
	// credentials, at a time they choose.
	AutoMigrate bool
}

const envPrefix = "OPENPSIRT_"

// Load reads configuration from the environment.
//
// A value that is set and cannot be read is a startup error naming the
// variable, never a silent fallback. "PLAIN_HTTP=false" turning Secure
// cookies off, or "AUTO_MIGRATE=0" still migrating, is a setting that does
// the opposite of what it says — worse than refusing to start, because the
// operator has no reason to look.
func Load() (Config, error) {
	var r reader
	// The queue's defaults where nothing says otherwise, read from
	// the queue rather than restated: two spellings of one default disagree
	// the first time either moves.
	queueing := queue.DefaultOptions()
	c := Config{
		Addr:                env("ADDR", ":8080"),
		BaseURL:             env("BASE_URL", ""),
		MailFrom:            env("MAIL_FROM", ""),
		MailServer:          env("MAIL_SERVER", ""),
		MailUsername:        env("MAIL_USERNAME", ""),
		MailPassword:        env("MAIL_PASSWORD", ""),
		IngestMaxBytes:      r.number("INGEST_MAX_BYTES", 0),
		IngestMaxComponents: r.number("INGEST_MAX_COMPONENTS", 0),
		IngestMaxEdges:      r.number("INGEST_MAX_EDGES", 0),
		IngestMaxFiles:      r.number("INGEST_MAX_FILES", 0),
		IngestMaxStatements: r.number("INGEST_MAX_STATEMENTS", 0),
		IngestMaxDepth:      r.number("INGEST_MAX_DEPTH", 0),
		IngestMaxDocuments:  r.number("INGEST_MAX_DOCUMENTS", 0),

		QueueMaxAttempts:  r.number("QUEUE_MAX_ATTEMPTS", queueing.MaxAttempts),
		QueueClaimTimeout: r.duration("QUEUE_CLAIM_TIMEOUT", queueing.ClaimTimeout),
		QueueHeartbeat:    r.duration("QUEUE_HEARTBEAT", queueing.Heartbeat),
		QueueMaxHold:      r.duration("QUEUE_MAX_HOLD", queueing.MaxHold),
		QueueBackoff:      r.duration("QUEUE_BACKOFF", queueing.Backoff),

		ScannerMaxOutput:     r.number("SCANNER_MAX_OUTPUT", 0),
		ScannerMaxComplaint:  r.number("SCANNER_MAX_COMPLAINT", 0),
		ScannerMaxMatches:    r.number("SCANNER_MAX_MATCHES", 0),
		ScannerMaxReferences: r.number("SCANNER_MAX_REFERENCES", 0),

		AttachmentBucket:   env("ATTACHMENT_BUCKET", ""),
		AttachmentEndpoint: env("ATTACHMENT_ENDPOINT", ""),
		AttachmentRegion:   env("ATTACHMENT_REGION", ""),
		AttachmentKey:      env("ATTACHMENT_KEY", ""),
		AttachmentSecret:   env("ATTACHMENT_SECRET", ""),
		AttachmentToken:    env("ATTACHMENT_SESSION_TOKEN", ""),
		AttachmentDir:      env("ATTACHMENT_DIR", ""),
		// Path style is what a self-hosted store is usually addressed by and
		// a provider usually is not, so it follows the endpoint rather than
		// having a default of its own.
		AttachmentPathStyle: r.boolean("ATTACHMENT_PATH_STYLE",
			env("ATTACHMENT_ENDPOINT", "") != ""),
		// No default of its own, and it follows nothing: what it allows has to
		// be somebody's decision rather than a consequence of another setting.
		AttachmentAllowHTTP:    r.boolean("ATTACHMENT_ALLOW_HTTP", false),
		PublisherName:          env("PUBLISHER_NAME", ""),
		PublisherNamespace:     env("PUBLISHER_NAMESPACE", ""),
		PublisherCategory:      env("PUBLISHER_CATEGORY", "vendor"),
		AdvisoryPrefix:         env("ADVISORY_PREFIX", ""),
		UpstreamInternal:       listed(env("UPSTREAM_INTERNAL", "")),
		TrustedGroupsHeader:    env("TRUSTED_GROUPS_HEADER", ""),
		TrustedGroupsDelimiter: env("TRUSTED_GROUPS_DELIMITER", ","),
		PlainHTTP:              r.boolean("PLAIN_HTTP", false),
		SessionLifetime:        r.duration("SESSION_LIFETIME", 0),

		OIDCName:          env("OIDC_NAME", "oidc"),
		OIDCIssuer:        env("OIDC_ISSUER", ""),
		OIDCClientID:      env("OIDC_CLIENT_ID", ""),
		OIDCClientSecret:  env("OIDC_CLIENT_SECRET", ""),
		OIDCGroupsClaim:   env("OIDC_GROUPS_CLAIM", ""),
		OIDCUsernameClaim: env("OIDC_USERNAME_CLAIM", ""),

		GitHubClientID:     env("GITHUB_CLIENT_ID", ""),
		GitHubClientSecret: env("GITHUB_CLIENT_SECRET", ""),
		GitHubOrg:          env("GITHUB_ORG", ""),
		LogFormat:          env("LOG_FORMAT", "text"),
		ShutdownGrace:      r.duration("SHUTDOWN_GRACE", 15*time.Second),
		StartupTimeout:     r.duration("STARTUP_TIMEOUT", 60*time.Second),
		DatabaseURL:        env("DATABASE_URL", ""),
		ScannerPath:        env("SCANNER_PATH", ""),
		ScannerTimeout:     r.duration("SCANNER_TIMEOUT", scanner.DefaultTimeout),
		TrustedHeader:      env("TRUSTED_HEADER", ""),
		AutoMigrate:        r.boolean("AUTO_MIGRATE", true),
		ReadTimeout:        5 * time.Minute,
		WriteTimeout:       5 * time.Minute,
		DBMaxOpen:          r.number("DB_MAX_OPEN", 25),
		DBMaxIdle:          r.number("DB_MAX_IDLE", 25),
		DBIdleTimeout:      r.duration("DB_IDLE_TIMEOUT", time.Minute),
		DBLifetime:         r.duration("DB_CONN_LIFETIME", 30*time.Minute),
		// No default of its own and it follows nothing: a deployment either
		// states this or it does not.
		DBRequireEncryption: r.boolean("DB_REQUIRE_ENCRYPTION", false),
	}
	if r.err != nil {
		return Config{}, r.err
	}

	c.BootstrapAdmins = access.Identities(env("BOOTSTRAP_ADMINS", ""))

	sources, err := access.ParseSources(env("TRUSTED_SOURCES", ""))
	if err != nil {
		return Config{}, fmt.Errorf("OPENPSIRT_TRUSTED_SOURCES: %w", err)
	}
	c.TrustedSources = sources
	// A half-configuration is the dangerous state, so it stops the process
	// rather than being quietly ignored: a header named with nothing to trust
	// it from is either a mistake or the first half of one.
	if err := (access.Trust{Header: c.TrustedHeader, From: c.TrustedSources}).Configured(); err != nil {
		return Config{}, fmt.Errorf("OPENPSIRT_TRUSTED_HEADER: %w", err)
	}
	// The same rule, for the same reason. A server with nobody to send as is
	// not a configuration, it is half of one — and half of one answered as
	// "no mail configured", which is a choice an operator is entitled to make
	// and is indistinguishable from the mistake. Embargo mail is what a
	// coordinated disclosure runs on, and it was silently off.
	if (strings.TrimSpace(c.MailServer) == "") != (strings.TrimSpace(c.MailFrom) == "") {
		return Config{}, fmt.Errorf(
			"OPENPSIRT_MAIL_SERVER and OPENPSIRT_MAIL_FROM: set both or neither — " +
				"a server with nobody to send as sends nothing, and says nothing about it")
	}

	if err := c.LogLevel.UnmarshalText([]byte(env("LOG_LEVEL", "info"))); err != nil {
		return Config{}, fmt.Errorf("OPENPSIRT_LOG_LEVEL: %w", err)
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return Config{}, fmt.Errorf("OPENPSIRT_LOG_FORMAT: want \"text\" or \"json\", got %q", c.LogFormat)
	}
	// The standard permits exactly six words here and the value reaches the
	// document verbatim, so a typo produced advisories that fail validation
	// wherever anybody takes them — which is the one use a generated advisory
	// has. Refused at startup, beside the setting above that is checked the
	// same way for the same reason.
	switch c.PublisherCategory {
	case "coordinator", "discoverer", "other", "translator", "user", "vendor":
	default:
		return Config{}, fmt.Errorf("OPENPSIRT_PUBLISHER_CATEGORY: want one of "+
			"\"coordinator\", \"discoverer\", \"other\", \"translator\", \"user\" or "+
			"\"vendor\", got %q", c.PublisherCategory)
	}
	// The value reaches every advisory identifier verbatim, and an identifier
	// is matched, cited and searched for. Refused at startup beside the two
	// above, for the reason those are: the alternative is documents that are
	// wrong in a way only a reader outside this deployment notices.
	if c.AdvisoryPrefix != "" && !advisoryPrefix.MatchString(c.AdvisoryPrefix) {
		return Config{}, fmt.Errorf("OPENPSIRT_ADVISORY_PREFIX: want a letter followed by up "+
			"to nineteen letters, digits or hyphens, got %q", c.AdvisoryPrefix)
	}
	if strings.TrimSpace(c.Addr) == "" {
		return Config{}, fmt.Errorf("OPENPSIRT_ADDR: must not be empty")
	}
	// Refused at startup rather than at the first sign-in. The API write path
	// bounds this setting and the environment path did not, so a deployment
	// following the documented configuration started cleanly and then failed
	// every browser sign-in — and the way back needed an administrator's key,
	// because nobody could sign in.
	if c.SessionLifetime > access.MaxSessionLifetime {
		return Config{}, fmt.Errorf("OPENPSIRT_SESSION_LIFETIME: want at most %s, got %q",
			access.MaxSessionLifetime, c.SessionLifetime)
	}
	if err := absoluteBase(c.BaseURL); err != nil {
		return Config{}, err
	}
	return c, nil
}

// absoluteBase refuses a deployment address that is not one.
//
// Checked here so that every consumer may assume it is absolute, which
// four of them already did. It was the one string setting with a required
// shape that nothing parsed, and the failure was silent where it mattered
// most: `OPENPSIRT_BASE_URL=psirt.example.com` — the form the value takes in a
// DNS record or an Ingress host field — parses, puts the whole string in Path
// and leaves Host empty, so the same-origin check fell through to origins
// derived from the request's own Host header. The guard became an echo of what
// the request said, with nothing logged, while the operator believed they had
// pinned the origin.
//
// The other consequences were loud and self-correcting, which is what hid it:
// the OIDC redirect address is not absolute either, so every sign-in fails at
// the provider — naming the provider rather than this deployment.
func absoluteBase(base string) error {
	if base == "" {
		return nil
	}
	parsed, err := url.Parse(base)
	switch {
	case err != nil:
		return fmt.Errorf("OPENPSIRT_BASE_URL: not an address at all: %q", base)
	case parsed.Scheme != "http" && parsed.Scheme != "https":
		return fmt.Errorf(
			"OPENPSIRT_BASE_URL: want an absolute address such as "+
				"https://psirt.example.com, got %q", base)
	case parsed.Host == "":
		return fmt.Errorf("OPENPSIRT_BASE_URL: names no host: %q", base)
	case strings.Trim(parsed.Path, "/") != "":
		// A path below the address would make every link this deployment
		// writes point somewhere it does not answer.
		return fmt.Errorf("OPENPSIRT_BASE_URL: names the address, not a path below it: %q",
			base)
	}
	return nil
}

// reader reads typed settings and keeps the first value it could not read.
// A setting that is absent takes its fallback; one that is present has to
// parse, and zero or negative reads as unset everywhere so it is refused
// rather than taken.
type reader struct {
	err error
}

// The one refusal here that composes the prefix rather than writing a name
// whole: the name is what it is given, one message for every setting, so there
// is no literal to write. What keeps a variable findable in this file is the
// call site — `r.duration("SHUTDOWN_GRACE", …)` — which is also what
// `documented_test.go` reads to hold the set against the page.
func (r *reader) refuse(key, want, got string) {
	if r.err == nil {
		r.err = fmt.Errorf("%s%s: want %s, got %q", envPrefix, key, want, got)
	}
}

// boolean reads a switch: true or false, in the spellings strconv accepts.
func (r *reader) boolean(key string, fallback bool) bool {
	raw, ok := os.LookupEnv(envPrefix + key)
	if !ok {
		return fallback
	}
	v, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		r.refuse(key, "true or false", raw)
		return fallback
	}
	return v
}

// duration reads a positive duration, such as 30s or 5m.
func (r *reader) duration(key string, fallback time.Duration) time.Duration {
	raw, ok := os.LookupEnv(envPrefix + key)
	if !ok {
		return fallback
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || d <= 0 {
		r.refuse(key, "a positive duration such as 30s or 5m", raw)
		return fallback
	}
	return d
}

// number reads a positive integer.
func (r *reader) number(key string, fallback int) int {
	raw, ok := os.LookupEnv(envPrefix + key)
	if !ok {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		r.refuse(key, "a positive whole number", raw)
		return fallback
	}
	return n
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(envPrefix + key); ok {
		return v
	}
	return fallback
}

// listed reads a comma-separated value into the names it carries.
//
// Empty entries are dropped rather than kept as a name of nothing: a trailing
// comma is what a list assembled by a template looks like, and a name that is
// the empty string would match everything it was compared against.
func listed(raw string) []string {
	var names []string
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// advisoryPrefix is the shape a minted advisory identifier may open with.
//
// Upper case, because the identifier is folded for matching and a prefix that
// varies in case would read as two publishers to anybody scanning a list.
var advisoryPrefix = regexp.MustCompile(`^[A-Z][A-Z0-9-]{0,19}$`)
