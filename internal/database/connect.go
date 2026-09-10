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
// The floors are set by what we depend on and by what is still receiving
// security updates — which, for a tool whose subject is vulnerabilities, is not
// a detail to be relaxed quietly.
var minimum = map[Engine]Version{
	Postgres: {14, 0},
	MySQL:    {8, 0},
	MariaDB:  {10, 6},
	SQLite:   {3, 35},
}

// Version is a major.minor release number.
type Version struct{ Major, Minor int }

func (v Version) String() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// AtLeast reports whether v is no older than floor.
func (v Version) AtLeast(floor Version) bool {
	if v.Major != floor.Major {
		return v.Major > floor.Major
	}
	return v.Minor >= floor.Minor
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
	return Server{Engine: engine, Version: version, Raw: raw}, nil
}

var versionPattern = regexp.MustCompile(`(\d+)\.(\d+)`)

// parseVersion pulls major.minor out of the various shapes servers report:
// "16.2 (Debian ...)", "8.0.36", "10.11.6-MariaDB-1:10.11.6+maria~ubu2204".
func parseVersion(raw string) (Version, error) {
	m := versionPattern.FindStringSubmatch(raw)
	if m == nil {
		return Version{}, fmt.Errorf("no major.minor found")
	}
	major, err := strconv.Atoi(m[1])
	if err != nil {
		return Version{}, err
	}
	minor, err := strconv.Atoi(m[2])
	if err != nil {
		return Version{}, err
	}
	return Version{Major: major, Minor: minor}, nil
}
