package database

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/mysqldialect"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/schema"

	_ "github.com/go-sql-driver/mysql" // MySQL and MariaDB
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL
	_ "modernc.org/sqlite"             // SQLite, pure Go so the binary stays static
)

// minimum is the oldest release of each engine we will run against.
//
// A floor is a release series: the oldest series whose behavior the queries
// and schema here are written against.
//
// **It does not say upstream still publishes fixes for that series.** MySQL
// 8.0 and MariaDB 10.6 are both past upstream end of life and are admitted
// anyway, because raising a floor refuses deployments that start today, which
// is a decision rather than upkeep.
//
// **Nor that the server in front of it carries the fixes for its own series.**
// Upstream publishes per patch release, and which patch release an operator
// runs is a property of the deployment that no comparison made at startup can
// act on — a floor that admits a series admits every unpatched release in it.
// So this is a compatibility floor, not the thing that keeps a deployment
// current.
var minimum = map[Engine]Version{
	Postgres: {14, 0, 0},
	MySQL:    {8, 0, 0},
	MariaDB:  {10, 6, 0},
	SQLite:   {3, 35, 0},
}

// Version is a release number, compared from the most significant part down.
//
// The patch level is carried because servers report one and comparing without
// it is a comparison that cannot express what it is given: two releases of the
// same series read as equal. PostgreSQL is the exception that proves the shape
// is right — since 10 it numbers releases as series.patch, so its patch level
// lands in Minor and stays there, and the same comparison orders it correctly.
type Version struct{ Major, Minor, Patch int }

// String writes the version the way the server that reported it does, which is
// two parts for PostgreSQL and SQLite in-memory builds and three for the rest.
// A patch level appended to a version that never had one reads as a precision
// nobody reported.
func (v Version) String() string {
	if v.Patch == 0 {
		return fmt.Sprintf("%d.%d", v.Major, v.Minor)
	}
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// AtLeast reports whether v is no older than floor.
func (v Version) AtLeast(floor Version) bool {
	if v.Major != floor.Major {
		return v.Major > floor.Major
	}
	if v.Minor != floor.Minor {
		return v.Minor > floor.Minor
	}
	return v.Patch >= floor.Patch
}

// Server is what actually answered.
type Server struct {
	// Engine is the engine that responded. For a MySQL-protocol connection
	// this is settled here rather than taken from the URL, because MySQL and
	// MariaDB are indistinguishable until the server says which it is.
	Engine Engine
	// Version is the release it reported.
	Version Version
	// Raw is the untouched version string, kept for logs and diagnostics.
	Raw string
	// Transport is the encryption the connection actually negotiated: the
	// protocol version where there is one, "none" where the connection is in
	// cleartext, and "unknown" where the server would not say.
	//
	// Both drivers encrypt only where the server offers it and neither says
	// which happened, so a deployment that believed its database connection
	// was encrypted had no way to find out that it was not.
	Transport string
}

// DB is an open database and what we know about the server behind it.
type DB struct {
	*bun.DB
	Server Server
}

// OpenWithPool connects using specific pool settings.
func OpenWithPool(ctx context.Context, target Target, pool Pool) (*DB, error) {
	db, err := Open(ctx, target)
	if err != nil {
		return nil, err
	}
	pool.apply(db)
	return db, nil
}

// Open connects, identifies the server, and refuses anything too old.
//
// Refusing at startup is deliberate: the alternative is a confusing failure
// later, in whichever query first depends on something the server cannot do.
func Open(ctx context.Context, target Target) (*DB, error) {
	driver, dialect, err := driverFor(target.Engine)
	if err != nil {
		return nil, err
	}

	sqldb, err := sql.Open(driver, target.DSN)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", target.Engine, err)
	}
	if err := sqldb.PingContext(ctx); err != nil {
		_ = sqldb.Close()
		return nil, fmt.Errorf("connect to %s at %s: %w", target.Engine, target.Redacted, err)
	}

	server, err := identify(ctx, sqldb, target.Engine)
	if err != nil {
		_ = sqldb.Close()
		return nil, err
	}
	if floor, ok := minimum[server.Engine]; ok && !server.Version.AtLeast(floor) {
		_ = sqldb.Close()
		return nil, fmt.Errorf("%s %s is too old: %s or later is required",
			server.Engine, server.Version, floor)
	}

	// bun's dialect is chosen from the URL's scheme, which is right even when
	// the server turns out to be MariaDB: the two share a dialect.
	db := &DB{DB: bun.NewDB(sqldb, dialect()), Server: server}
	DefaultPool().apply(db)
	return db, nil
}

func driverFor(e Engine) (driver string, dialect func() schema.Dialect, err error) {
	switch e {
	case Postgres:
		return "pgx", func() schema.Dialect { return pgdialect.New() }, nil
	case MySQL, MariaDB:
		return "mysql", func() schema.Dialect { return mysqldialect.New() }, nil
	case SQLite:
		return "sqlite", func() schema.Dialect { return sqlitedialect.New() }, nil
	}
	return "", nil, fmt.Errorf("unsupported database %q", e)
}

// identify asks the server what it is, rather than believing the URL.
func identify(ctx context.Context, db *sql.DB, declared Engine) (Server, error) {
	query := "SELECT version()"
	if declared == SQLite {
		query = "SELECT sqlite_version()"
	}

	var raw string
	if err := db.QueryRowContext(ctx, query).Scan(&raw); err != nil {
		return Server{}, fmt.Errorf("ask %s for its version: %w", declared, err)
	}

	engine := declared
	if declared == MySQL || declared == MariaDB {
		// The only reliable way to tell them apart. Believing the URL would
		// apply the wrong version floor and hide a genuinely unsupported server.
		if strings.Contains(strings.ToLower(raw), "mariadb") {
			engine = MariaDB
		} else {
			engine = MySQL
		}
	}

	version, err := parseVersion(raw)
	if err != nil {
		return Server{}, fmt.Errorf("%s reported an unreadable version %q: %w", engine, raw, err)
	}
	return Server{Engine: engine, Version: version, Raw: raw, Transport: transportOf(ctx, db, engine)}, nil
}

// transportOf asks the server what encryption this connection negotiated.
//
// Asked rather than assumed, because both drivers negotiate opportunistically:
// a server that does not offer encryption is answered in cleartext, and
// nothing in the URL, the configuration or the logs distinguished that from a
// connection that was encrypted. Over a database of undisclosed findings, the
// difference is worth one round trip at startup.
//
// It never fails a start. A server that will not answer this question is still
// a server that answered the version question, and refusing to run because a
// diagnostic came back empty would trade a working deployment for a label.
func transportOf(ctx context.Context, db *sql.DB, engine Engine) string {
	const unknown = "unknown"
	switch engine {
	case Postgres:
		// pg_stat_ssl holds a row per backend; a connection may always read
		// its own. The version column is empty when the connection is not
		// encrypted.
		var version sql.NullString
		err := db.QueryRowContext(ctx,
			"SELECT version FROM pg_stat_ssl WHERE pid = pg_backend_pid()").Scan(&version)
		switch {
		case err != nil:
			return unknown
		case !version.Valid || version.String == "":
			return "none"
		default:
			return version.String
		}

	case MySQL, MariaDB:
		// Both spell it as a session status variable, and the two engines put
		// the table it lives in in different schemas — so it is asked for by
		// name rather than selected from either.
		var name, version string
		if err := db.QueryRowContext(ctx,
			"SHOW SESSION STATUS LIKE 'Ssl_version'").Scan(&name, &version); err != nil {
			return unknown
		}
		if version == "" {
			return "none"
		}
		return version

	case SQLite:
		// A file, opened directly. There is no connection to encrypt.
		return "none"
	}
	return unknown
}

var versionPattern = regexp.MustCompile(`(\d+)\.(\d+)(?:\.(\d+))?`)

// parseVersion pulls the release number out of the various shapes servers
// report: "16.2 (Debian ...)", "8.0.36",
// "10.11.6-MariaDB-1:10.11.6+maria~ubu2204".
//
// The patch level is optional because PostgreSQL does not have one — it
// numbers releases as series.patch — and a server that reports two parts is
// read as patch zero rather than refused.
func parseVersion(raw string) (Version, error) {
	m := versionPattern.FindStringSubmatch(raw)
	if m == nil {
		return Version{}, fmt.Errorf("no version number found")
	}
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return Version{}, err
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return Version{}, err
	}
	var patch int
	if m[3] != "" {
		if patch, err = strconv.Atoi(m[3]); err != nil {
			return Version{}, err
		}
	}
	return Version{Major: major, Minor: minor, Patch: patch}, nil
}
