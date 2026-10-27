# Database

The four supported engines, where engine-specific code may live, how a
connection is opened and kept, and the test harness that runs on all four.

Satisfies REQ-03, REQ-71, REQ-73.

## Contents

- [Supported engines](#supported-engines)
- [Engine-specific code](#engine-specific-code)
- [Engine detection](#engine-detection)
- [Connection encryption](#connection-encryption)
- [Connection pool](#connection-pool)
- [Statement preparation](#statement-preparation)
- [SQLite settings](#sqlite-settings)
- [Test harness](#test-harness)
- [Not built](#not-built)
- [Limits](#limits)

The rest of the area:

| Document | Covers |
|---|---|
| `design-docs/database-migrations.md` | Applying migrations, the baseline, release records, rehearsal, the migration lock |
| `design-docs/database-upgrades.md` | What each release's upgrade migration does |
| `design-docs/database-queries.md` | Query rules the engines impose: quoting, patterns, counts, recursion, collation, text, bulk inserts |
| `design-docs/database-transactions.md` | Replicas, retryable transactions, reads a write depends on, absence and failure |
| `design-docs/database-schema.md` | Indexes, planner statistics, column widths, columns no query reads |
| `design-docs/database-measurements.md` | Benchmark runs behind these rules |
| `design-docs/queue.md` | Background work as rows |

## Supported engines

Four engines are supported and tested (REQ-71).

| Engine | Role | Version floor |
|---|---|---|
| PostgreSQL | Production | 14 |
| MySQL | Production | 8.0 |
| MariaDB | Production | 10.6 |
| SQLite | Development and testing only | 3.35 |

| Rule | Reason |
|---|---|
| A floor is the oldest release series the queries and schema are written against | Raising one refuses deployments, so it is a decision: MySQL 8.0 and MariaDB 10.6 are past upstream end of life and admitted |
| A floor admits every patch release in its series | Patching the server is the operator's responsibility |
| The version compared carries a patch level | PostgreSQL since 10 numbers series and patch, so one comparison orders every engine |
| SQLite serves one replica | It is one file, so a scaled deployment (REQ-03) runs on a server engine |
| MySQL and MariaDB are separate targets | They share a protocol and driver and differ in JSON, sequences, partitioning and collation defaults |

Supporting all four rules out PostgreSQL JSON operators and GIN indexes on
JSON, `RETURNING` (absent from MySQL 8), PostgreSQL full-text search, arrays,
partial indexes and `DISTINCT ON`. `WITH RECURSIVE` works on all four, so a
graph walk has no engine-specific path.

## Engine-specific code

Queries above the database package are written once and run unchanged on
every engine. Engine-specific code lives in these places and no others.

| Location | Reason |
|---|---|
| Schema migrations | Data-definition language differs |
| The migration lock | Each engine spells advisory locking differently |
| Connection setup | Driver-specific settings, including how PostgreSQL's statements are sent (§ Statement preparation) |
| Recognizing what an engine reports | Each driver has its own error type. Three questions, each silent when wrong: a lost race worth retrying (REQ-71), a unique constraint refusing a duplicate, a failure from the engine rather than an impossible request |
| Subtracting two moments | No portable expression yields seconds: one engine returns an interval, one a number of days |
| Inserting a row another writer may already have written | `ON CONFLICT DO NOTHING` on two engines, `ON DUPLICATE KEY UPDATE` setting the key to itself on two. Never `INSERT IGNORE`, which also stores a value cut to fit, a dangling reference or a missing value as a warning. Only for a table of facts, where two writers agree |
| The job queue's locking | The one place outside the database package, because the queue owns the statement |
| Typing a composed expression as a moment | A `CASE` over bound values is untyped and PostgreSQL refuses it in a timestamp column. PostgreSQL casts to a zoned timestamp, MySQL and MariaDB to a six-digit datetime, SQLite to nothing |
| The test harness | It names each engine to choose a connection and report which ran, never to write a query |
| Leasing the harness's slots | A named lock on MySQL and MariaDB, a numbered advisory lock on PostgreSQL, each held for the connection |
| Numbering the rows of one insert on MySQL | MySQL reports only the first identifier; the rest are counted in the server's step, read from the inserting session. The branch asks which statements the dialect can write |
| Writing a batch whose identifiers nobody reads | PostgreSQL takes one array a column; the others take a list of rows (`design-docs/database-queries.md` § Bulk inserts) |
| Counting the statements a server holds prepared | A test of connection setup. PostgreSQL lists them in its catalog; MySQL and MariaDB count them in session status, in two different schemas |
| Listing the harness's own databases | PostgreSQL's information schema describes only the connected database |
| Listing the tables of the harness's SQLite schema | SQLite keeps its schema in its own catalog |
| Commit durability on the harness servers | A global setting on MySQL and MariaDB. PostgreSQL takes it per session in the connection string |
| Refreshing planner statistics before a measurement | A measurement queries seconds after a bulk load, before a server's own refresh. It asks as a start does |
| Emptying a database for a measurement | PostgreSQL truncates every table in one statement; MySQL and MariaDB one table a statement, with foreign key checks suspended. SQLite copies a migrated file. `design-docs/build-tests.md` § Measurement databases has the measurement |
| Reading a table's layout beside a measurement | PostgreSQL keeps pages and column correlation in its catalogs; MySQL and MariaDB report size through the information schema, in bytes of a page size each server sets |
| Refreshing planner statistics in a deployment | `ANALYZE` with `SKIP_LOCKED` on PostgreSQL, `ANALYZE TABLE` under a bound on lock waits on MySQL and MariaDB, each table named from the catalog. SQLite is asked at start and after every scan (`design-docs/database-schema.md` § Planner statistics) |
| Reading the planner's estimate of a table in a test | PostgreSQL's catalog, InnoDB's statistics tables, SQLite's own table |
| A test choosing which engine it runs on | Allowed anywhere: it selects an engine and branches no query |
| A release's upgrade | Changing an existing table is spelled per engine (`design-docs/database-upgrades.md` § Release upgrades). The catalog is asked which indexes, columns and foreign keys a table holds |
| When PostgreSQL vacuums the finding table | A storage setting of PostgreSQL's alone (`design-docs/database-schema.md` § Indexes) |
| Asking each engine what words it reserves | Each publishes them somewhere of its own. It regenerates the quoting gate's word list and is not a query the application runs |

| Rule | Reason |
|---|---|
| `make confined` refuses a dialect named outside the allowed paths | A hand-kept list grows silently |
| The allowed paths are the database package, the queue's locking file, the test harness, and the tools that enforce this rule and regenerate the reserved words | The four directories pass any branch inside them, so the row naming that branch here is kept by review |
| It reads tests | A branch in a test is a branch. An engine named to choose which engine runs is the one thing let past |
| It looks for the branch: engine constants, driver error types, the query builder's upsert spellings, a handle asked which engine it is, and SQL only some engines accept | |
| A path is added to the gate and to this table in one change | The gate holds the paths and this table the reasons |

## Engine detection

| Rule | Reason |
|---|---|
| The server is asked what it is, whatever the URL says | A MySQL-protocol connection may be MySQL or MariaDB. Believing the URL applies the wrong floor. MariaDB names itself in its version string |
| A server below the floor stops the process at start, naming the version found and the version required | Otherwise it fails later, in whichever query first needs what the server lacks |
| The connection is asked what encryption it negotiated | It stops a start only where the deployment requires encryption (§ Connection encryption) |

## Connection encryption

Neither driver reports what it negotiated. One negotiates where the server
offers; the other connects in cleartext unless asked.

| Rule | Reason |
|---|---|
| By default a connection is encrypted where the server offers it, cleartext where it does not, with no certificate checked | The same on every engine |
| What a URL says about the transport is left as written | The default is a floor, never an override |
| The negotiated outcome is logged beside the engine and version | A production engine in cleartext is warned about by name, with the setting that fixes it |
| A deployment may require encryption, and a start whose connection lacks it is refused | Taking what the server offers remains the other choice |
| Required is asked of the connection, never read from the URL | A server may ignore what was asked |
| Required is imposed on every connection the pool opens | A transport that can fall back (`sslmode` `prefer` or `allow`, `tls=preferred`, or none named) is replaced by one that cannot. One asking for cleartext, or `allowFallbackToPlaintext` true, is refused. A MySQL value is read as the driver reads it: any case, 0 and 1 as false and true |
| A PostgreSQL URL naming no mode is judged by `PGSSLMODE` | The driver takes the environment's mode there. A mode is appended only where that one is weak, so `verify-full` is never replaced |
| A PostgreSQL key is read as the driver reads it | Decoded, last value of a repeat wins, every repeat judged. A pair the URL parser cannot read is refused, naming the setting |
| The driver's parsed configuration is the last word on PostgreSQL | It merges a service file above the environment and under the URL, which can supply a mode the URL does not show. Every attempt it makes, first and each fallback, must be encrypted |
| A server that will not say is refused under required | |
| Required against SQLite is refused | A file opened directly has no connection to encrypt |

## Connection pool

A far end gone without a FIN or an RST (a firewall dropping an idle flow, a
load balancer timeout, a failover) leaves a socket the pool hands out and a read
blocked about fifteen minutes, silently. Go's pool never validates a connection
before handing it out, so no connection stays idle long enough to be killed.

| Setting | Default | Reason |
|---|---|---|
| Idle timeout | 1 minute | Shorter than the shortest idle timeout in the path: firewall, load balancer or server |
| Lifetime | 30 minutes | Connections redistribute after a failover |
| Max open | 25 | Unbounded, a burst opens more than the server permits, and PostgreSQL is expensive per connection |
| Max idle | 25 | Go's default of 2 churns connections under moderate load |

Go's cleaner runs at most once a second, so an idle timeout below a second
reaps no faster.

## Statement preparation

| Rule | Reason |
|---|---|
| A PostgreSQL statement is parsed as the unnamed statement, described, and run | Nothing is kept on either side. Prepared and kept, 512 statements held 2,957 MB a connection in the server and 16 held 88 MB; this holds 3 MB |
| Results come back in the binary encoding | A moment read as text carries the session's zone and date style: a session fourteen hours east dates a late-evening moment a day late, and a month-first date style is not read at all |
| MySQL and MariaDB are sent the text alone | Their driver prepares only a statement with parameters, and the builder sends none |

The query builder writes every value into the statement text, so no two
statements share a text and a statement cache never hits. Describing costs one
round trip a statement, 20 ms on the findings list
(`design-docs/database-measurements.md` § Statement preparation modes).

A test asks each server how many statements it holds prepared for one
connection before and after a query and an insert. Another stores a moment and
reads it back on sessions set fourteen hours east and to a month-first date
style.

## SQLite settings

| Setting | Reason |
|---|---|
| The configured pool, as on the servers | In WAL mode readers block neither each other nor the writer. On one connection eight requests from one home page took 12.5 s together, and 4.4 s for the slowest alone |
| One connection to an in-memory database | Each connection to one opens a database of its own |
| Every transaction takes the write lock as it begins | A deferred one that reads then writes fails at once behind a later commit, ignoring the busy timeout |
| A busy timeout of a minute | Writers take turns on one write lock. The longest writer, a scan's apply, took 26.1 s for 321,067 findings |
| One connection while migrating | A migration's connection settings must reach its transaction (`design-docs/database-migrations.md` § Migration locks) |
| One connection in the test harness | A read through the root handle inside a transaction then waits on the held connection and the test's deadline reports it. On a wider pool it answers from outside the transaction, silently |
| Write-ahead log, synchronous NORMAL | A scan applies hundreds of thousands of rows. A process crash loses nothing; a power loss can lose the last commits, never consistency |
| Planner statistics refreshed at start and after every scan | SQLite gathers none unless asked. On 361,429 findings the review queue took 4.1 s without them and 0.08 s with them, and a whole analysis 0.66 s. After every scan, because a scan changes how rows divide: analyzed only on growth, the findings list took 2.1 s instead of 0.57 s. Sampling the first rows of each index misjudged which findings were assigned |
| A connection lives a minute, and a refresh closes the idle ones | A connection reads statistics when it opens and never again. Across a refresh the review queue took 4.1 s on every connection but the one that analyzed |

The pragmas are set on the connection string, and a URL may add its own after
them. The test harness adds `synchronous(OFF)`.

## Test harness

The harness runs a test against every database available to it. SQLite always
runs; a server runs when the environment points at it and is skipped with the
reason otherwise. CI provides all four and checks that all four ran.

The schema is built once per test binary. On SQLite a file is migrated on first
use and copied per test; on a server the binary leases a slot of the schema and
its database for as long as it runs, and the database is kept for the next
binary (`design-docs/build-tests.md` § Test databases).

| Rule | Reason |
|---|---|
| The SQLite template is kept in the user's cache directory, readable by nobody else | Its name derives from readable files, so in a shared temporary directory another user could plant it first |
| A harness call that cannot run beside the others says why | The testing package otherwise panics on a second call in one test function, or one after setting the environment |
| An engine left out is skipped with the reason, and a test holds the harness to it | |

| A test pins | Runs on |
|---|---|
| What a query returns, hides, conflicts on or spells | Every engine |
| Routing, authorization mapping, or a response's shape | SQLite and PostgreSQL |

The line is drawn at SQL, not at the package: a handler test that pins a query
runs on all four. A handler test on two engines leaves its store's query shapes
(an escaped `LIKE`, a case-folded `IN`, a conditional update) to store tests on
every engine.

The harness offers a handle whose `COMMIT` can be made to fail.

| Rule | Reason |
|---|---|
| It refuses a stated number of commits in the words the lost-race check matches, rolling the work back | Nothing else produces a cluster's refusal at commit |
| A hook runs between the refusal and the retry | Where a test puts what another worker did meanwhile |
| A test asserts both directions | A value from the rolled-back attempt does not survive, the work still happens, and the path committed something the handle could refuse. A write outside a transaction passes every other assertion |
| It is SQLite underneath, with the usual pragmas | The retry is driven by a synthesized error, which does not vary by engine. Foreign keys are enforced |

The harness owns the seams that put a writer or a failure at one point.

| Seam | What it does |
|---|---|
| A rival after a read | Arms once a statement reads one table and starts another writer before the next statement writing a second, waiting a bounded time. A rival blocked on a held lock lands at commit. A rival that never ran fails the test. Skipped on SQLite |
| A rival after a select | Arms once a select reads one table and starts another writer before the next statement, reaching the gap between two reads a write depends on. A rival that never ran fails the test. Skipped on SQLite |
| A failing statement | The armed statement runs on an ended context, so its failure carries a cancellation a test can tell apart |
| A hidden table | Renamed away and put back when the test ends, however it ends |
| A closed database | Opened and closed, so every call fails. A missing database is refused by a different arm |

The suite pins:

- Every engine is identified and its version parsed
- MariaDB is told from MySQL by asking the server
- A server below the floor is refused, against a real old server
- Migrations apply and are idempotent on every engine, and a database ahead of the binary is refused
- The advisory lock excludes a second connection while held and admits it once released, driven from two pools, and a refusal names the holding session
- A migration whose lock is lost part way fails, by ending the holder's session
- Reading the schema version changes no schema

## Not built

Nothing is purged and nothing is partitioned. REQ-73 has high-volume history
aged out by dropping partitions, exported to a compressed file first. No table
is partitioned, no retention pass runs, and nothing exports rows. The only
deletion of old data is expired sessions, a plain conditional delete. The column
to partition on and the granularity are open; nothing else in the design rests
on partitions.

## Limits

| Limit | Detail |
|---|---|
| Queries are not bounded | No statement timeout and no driver read timeout. A bound kills legitimate slow work, a large report or an ingest over tens of thousands of components, and would cut a migration part way |
| Connections are not validated on checkout | There is no hook. A validation helper with a short deadline serves callers that would block on a dead connection, readiness among them; it costs a round trip and says only that a connection was alive a moment ago |
| A SQLite write waiting on the write lock ignores its request's context | A write given 300 ms waited out 55 s, holding its goroutine and connection. The driver offers no busy handler, and queuing writes in the process would miss every write outside a transaction |
| PostgreSQL compiles a plan priced past its default `jit_above_cost` of 100,000 | Server settings are left at their defaults, so a 30 ms statement can spend 150 ms compiling. A group condition in `HAVING` is the known case, asked over the grouped statement instead (`design-docs/triage-decisions.md` § Act placement) |
| Timestamp semantics differ between engines | Moments are stored in UTC with explicit types |
