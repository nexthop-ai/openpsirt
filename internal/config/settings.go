// Copyright Nexthop Systems Inc.
// SPDX-License-Identifier: Apache-2.0

package config

// kind is the shape a setting's value takes, which is what a configuration
// file has to write natively and what the environment spells as text.
type kind int

const (
	// text is a string, taken as written.
	text kind = iota
	// number is a positive whole number: an integer in a file.
	number
	// duration is a positive duration such as 30s: a string in a file, since
	// the format has no duration of its own.
	duration
	// boolean is a switch: true or false in a file.
	boolean
	// list is several names: an array of strings in a file, and the same
	// names joined with commas in the environment.
	list
	// groupRoles is what groups grant: an array of tables in a file, each
	// with a group, its roles and optionally its products, and the entries
	// written the way the variable carries them in the environment.
	groupRoles
)

// setting is one thing a deployment configures, under the one name it has in
// each source.
//
// env is the environment name after the prefix, which is what the loader
// reads by. file is the key in a configuration file, a dotted path of tables
// ending in the key: "database.url" is `url` under `[database]`.
type setting struct {
	env  string
	file string
	kind kind
}

// settings is every setting a deployment configures, and the only place
// either name is defined.
//
// Both sources read through it. The environment is asked for each env name
// here, and a file is read into the same names, so the loader behind them sees
// one set of values whichever source supplied it. A name the loader asks for
// that is missing here reads as unset in both, which the test holding this
// table to the loader reports.
var settings = []setting{
	{"ADDR", "server.address", text},
	{"BASE_URL", "server.base_url", text},
	{"PLAIN_HTTP", "server.plain_http", boolean},
	{"SHUTDOWN_GRACE", "server.shutdown_grace", duration},
	{"STARTUP_TIMEOUT", "server.startup_timeout", duration},

	{"LOG_LEVEL", "log.level", text},
	{"LOG_FORMAT", "log.format", text},

	{"DATABASE_URL", "database.url", text},
	{"AUTO_MIGRATE", "database.auto_migrate", boolean},
	{"DB_MAX_OPEN", "database.max_open", number},
	{"DB_MAX_IDLE", "database.max_idle", number},
	{"DB_IDLE_TIMEOUT", "database.idle_timeout", duration},
	{"DB_CONN_LIFETIME", "database.connection_lifetime", duration},
	{"DB_REQUIRE_ENCRYPTION", "database.require_encryption", boolean},

	{"SCANNER_PATH", "scanner.path", text},
	{"SCANNER_TIMEOUT", "scanner.timeout", duration},
	{"SCANNER_MAX_OUTPUT", "scanner.max_output", number},
	{"SCANNER_MAX_COMPLAINT", "scanner.max_complaint", number},
	{"SCANNER_MAX_MATCHES", "scanner.max_matches", number},
	{"SCANNER_MAX_REFERENCES", "scanner.max_references", number},

	{"MAIL_FROM", "mail.from", text},
	{"MAIL_SERVER", "mail.server", text},
	{"MAIL_USERNAME", "mail.username", text},
	{"MAIL_PASSWORD", "mail.password", text},

	{"SLACK_TOKEN", "chat.slack.token", text},
	{"ZULIP_SITE", "chat.zulip.site", text},
	{"ZULIP_EMAIL", "chat.zulip.email", text},
	{"ZULIP_KEY", "chat.zulip.key", text},

	{"PUBLISHER_NAME", "publisher.name", text},
	{"PUBLISHER_NAMESPACE", "publisher.namespace", text},
	{"PUBLISHER_CATEGORY", "publisher.category", text},
	{"ADVISORY_PREFIX", "publisher.advisory_prefix", text},

	{"DIRECTORY_URL", "directory.url", text},
	{"DIRECTORY_BUCKET", "directory.bucket", text},
	{"DIRECTORY_ENDPOINT", "directory.endpoint", text},
	{"DIRECTORY_REGION", "directory.region", text},
	{"DIRECTORY_KEY", "directory.key", text},
	{"DIRECTORY_SECRET", "directory.secret", text},
	{"DIRECTORY_SESSION_TOKEN", "directory.session_token", text},
	{"DIRECTORY_PATH_STYLE", "directory.path_style", boolean},
	{"DIRECTORY_ALLOW_HTTP", "directory.allow_http", boolean},
	{"DIRECTORY_DIR", "directory.dir", text},
	{"DIRECTORY_LIST", "directory.list", boolean},
	{"DIRECTORY_MIRROR", "directory.mirror", boolean},

	{"UPSTREAM_INTERNAL", "upstream.internal", list},
	{"OUTBOUND_EXCLUDED", "outbound.excluded", list},

	{"PATCH_BRANCHES", "patch_branches.enabled", boolean},
	{"PATCH_DIR", "patch_branches.dir", text},
	{"PATCH_QUOTA", "patch_branches.quota", number},

	{"BOOTSTRAP_ADMINS", "signin.bootstrap_admins", list},
	{"GROUP_ROLES", "signin.roles", groupRoles},
	{"SESSION_LIFETIME", "signin.session_lifetime", duration},
	{"OIDC_NAME", "signin.oidc.name", text},
	{"OIDC_ISSUER", "signin.oidc.issuer", text},
	{"OIDC_CLIENT_ID", "signin.oidc.client_id", text},
	{"OIDC_CLIENT_SECRET", "signin.oidc.client_secret", text},
	{"OIDC_GROUPS_CLAIM", "signin.oidc.groups_claim", text},
	{"OIDC_USERNAME_CLAIM", "signin.oidc.username_claim", text},
	{"GITHUB_CLIENT_ID", "signin.github.client_id", text},
	{"GITHUB_CLIENT_SECRET", "signin.github.client_secret", text},
	{"GITHUB_ORG", "signin.github.org", text},
	{"TRUSTED_HEADER", "signin.trusted_header.name", text},
	{"TRUSTED_SOURCES", "signin.trusted_header.sources", list},
	{"TRUSTED_GROUPS_HEADER", "signin.trusted_header.groups_header", text},
	{"TRUSTED_GROUPS_DELIMITER", "signin.trusted_header.groups_delimiter", text},

	{"ATTACHMENT_BUCKET", "attachments.bucket", text},
	{"ATTACHMENT_ENDPOINT", "attachments.endpoint", text},
	{"ATTACHMENT_REGION", "attachments.region", text},
	{"ATTACHMENT_KEY", "attachments.key", text},
	{"ATTACHMENT_SECRET", "attachments.secret", text},
	{"ATTACHMENT_SESSION_TOKEN", "attachments.session_token", text},
	{"ATTACHMENT_PATH_STYLE", "attachments.path_style", boolean},
	{"ATTACHMENT_ALLOW_HTTP", "attachments.allow_http", boolean},
	{"ATTACHMENT_DIR", "attachments.dir", text},

	{"QUEUE_MAX_ATTEMPTS", "queue.max_attempts", number},
	{"QUEUE_CLAIM_TIMEOUT", "queue.claim_timeout", duration},
	{"QUEUE_HEARTBEAT", "queue.heartbeat", duration},
	{"QUEUE_MAX_HOLD", "queue.max_hold", duration},
	{"QUEUE_BACKOFF", "queue.backoff", duration},

	{"INGEST_MAX_BYTES", "ingest.max_bytes", number},
	{"INGEST_MAX_COMPONENTS", "ingest.max_components", number},
	{"INGEST_MAX_EDGES", "ingest.max_edges", number},
	{"INGEST_MAX_FILES", "ingest.max_files", number},
	{"INGEST_MAX_STATEMENTS", "ingest.max_statements", number},
	{"INGEST_MAX_DEPTH", "ingest.max_depth", number},
	{"INGEST_MAX_DOCUMENTS", "ingest.max_documents", number},
}
