// Package config loads runtime settings.
//
// Settings come from the environment. Every one has a working default, so an
// operator can start the binary with nothing set and get something sensible.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nexthop-ai/openpsirt/internal/access"
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
	// ScannerPath is where the vulnerability scanner lives. Empty means
	// whatever the environment resolves.
	//
	// The scanner is a requirement of a deployment rather than an option:
	// without it there is nothing to triage, because the vulnerability data is
	// produced here rather than sent to us.
	ScannerPath string
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
	// Where files hanging off an issue are kept, and absent is ordinary:
	// with none of this set, attachments are off and everything else works
	// . An operator who wants none should not have to run a bucket.
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
		DatabaseURL:        env("DATABASE_URL", ""),
		ScannerPath:        env("SCANNER_PATH", ""),
		TrustedHeader:      env("TRUSTED_HEADER", ""),
		AutoMigrate:        r.boolean("AUTO_MIGRATE", true),
		ReadTimeout:        5 * time.Minute,
		WriteTimeout:       5 * time.Minute,
		DBMaxOpen:          r.number("DB_MAX_OPEN", 25),
		DBMaxIdle:          r.number("DB_MAX_IDLE", 25),
		DBIdleTimeout:      r.duration("DB_IDLE_TIMEOUT", time.Minute),
		DBLifetime:         r.duration("DB_CONN_LIFETIME", 30*time.Minute),
	}
	if r.err != nil {
		return Config{}, r.err
	}

	c.BootstrapAdmins = access.Identities(env("BOOTSTRAP_ADMINS", ""))

	sources, err := access.ParseSources(env("TRUSTED_SOURCES", ""))
	if err != nil {
		return Config{}, fmt.Errorf("%sTRUSTED_SOURCES: %w", envPrefix, err)
	}
	c.TrustedSources = sources
	// A half-configuration is the dangerous state, so it stops the process
	// rather than being quietly ignored: a header named with nothing to trust
	// it from is either a mistake or the first half of one.
	if err := (access.Trust{Header: c.TrustedHeader, From: c.TrustedSources}).Configured(); err != nil {
		return Config{}, fmt.Errorf("%sTRUSTED_HEADER: %w", envPrefix, err)
	}

	if err := c.LogLevel.UnmarshalText([]byte(env("LOG_LEVEL", "info"))); err != nil {
		return Config{}, fmt.Errorf("%sLOG_LEVEL: %w", envPrefix, err)
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return Config{}, fmt.Errorf("%sLOG_FORMAT: want \"text\" or \"json\", got %q", envPrefix, c.LogFormat)
	}
	if strings.TrimSpace(c.Addr) == "" {
		return Config{}, fmt.Errorf("%sADDR: must not be empty", envPrefix)
	}
	return c, nil
}

// reader reads typed settings and keeps the first value it could not read.
// A setting that is absent takes its fallback; one that is present has to
// parse, and zero or negative reads as unset everywhere so it is refused
// rather than taken.
type reader struct {
	err error
}

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
