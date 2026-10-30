# Database migrations

How the schema is created and moved forward: application at start, the chain
from the baseline, the record each release keeps, the rehearsal before a tag,
and the lock that lets one instance migrate at a time.

Satisfies REQ-72, REQ-76.

## Contents

- [Migrations](#migrations)
- [The baseline](#the-baseline)
- [Forward only](#forward-only)
- [Migrations that stop half way](#migrations-that-stop-half-way)
- [Release records](#release-records)
- [Upgrade rehearsal](#upgrade-rehearsal)
- [Migration locks](#migration-locks)
- [Limits](#limits)

## Migrations

The application creates and migrates its own schema at start (REQ-72).
Migrations are embedded in the binary, so a deployment is one artifact and an
upgrade is deploying it.

| Rule | Reason |
|---|---|
| Automatic application can be turned off, and `openpsirt migrate up\|status` runs migrations separately | An operator may use other credentials at a time they choose |
| The command refuses an unknown action before contacting anything | |
| It connects within the startup timeout; the migration itself is unbounded | A schema change on a large table takes longer than a start |
| With automatic application off, the schema version is compared before anything is served | Uncompared, a build with a new migration passes the readiness probe, a ping, fails every request touching the new table, and in a rolling deployment retires the last working replica |
| The version a binary carries is the highest among its embedded migrations, read from their file names | The migration library applies the same rule |
| Migrations are written in Go | They branch on the engine. A timestamp has no portable spelling: PostgreSQL has no `DATETIME`, and MySQL's `TIMESTAMP` is 32-bit and can acquire an implicit default and on-update clause from server configuration |
| Only the migrations registered in the binary are applied, and no directory is read | The library otherwise globs the working directory: a stray `.sql` refuses every start, a numbered one runs under the migration credential, and a numbered `.go` file narrows what is applied |
| What every migration does around its statements is one place: asking the engine, refusing one with no spellings, running each statement, naming the one that failed by its first line | |
| Dropping an index is one place | Two engines name an index's table and two refuse to |

| Applied version | At start |
|---|---|
| Behind the binary | Refused, naming both versions and what to run. The previous replica stays up, which a startup refusal buys over a readiness failure |
| Equal | Served, both versions logged |
| Ahead | Refused, and by `openpsirt migrate up`, naming both versions (§ Forward only) |

Version zero means nothing is applied. The bookkeeping table is looked for in
the catalog before the version is read, so an inspection creates nothing, and a
credential that cannot read the table is never answered version zero.

| Engine | Asked | Tells an absent table from an unreadable one |
|---|---|---|
| PostgreSQL | `pg_class`, readable by any role; its information schema is filtered by privilege | Yes |
| MySQL, MariaDB | The information schema, the only catalog offered | No: what runs next fails with the engine's permission message |
| SQLite | `sqlite_master` | No privileges exist |

On PostgreSQL the table's name is resolved through the session's search path,
as the library's unqualified reference resolves it. A runtime role with its own
schema has that schema first and the bookkeeping table in `public`; matching the
current schema alone would answer zero for a migrated database. Resolving needs
the right to use the schema and nothing on the table.

| An upgrade that fails | The error says |
|---|---|
| On an empty database | The failure alone |
| On MySQL or MariaDB | The schema is left part changed and the backup taken before the upgrade recovers it; a database an unreleased build made is recreated |
| On PostgreSQL or SQLite | A database an unreleased build made is recreated. Data definition is transactional, so nothing is part changed |
| Stopped by its caller, on any engine | It stopped part way, and the next start applies the schema again (§ Migrations that stop half way) |

Both recoveries are named because the version cannot say whether a release or
an unreleased build made the database.

The chain is the baseline, then one migration per release.

| Migration | What it is |
|---|---|
| 43 | The baseline: v0.9.0's schema, made at once on an empty database (§ The baseline) |
| 44 | v0.9.0's schema into v0.10.0's |
| 45 | v0.10.0's schema into v0.11.0's, the untagged release's own |

`design-docs/database-upgrades.md` says what each does. A tagged release's
migration, and every declaration it reads, never changes again, because a
database that release built applied it as tagged. Each release's table
declarations sit beside its upgrade migration.

Below 1.0 nothing about the schema is promised (REQ-76). A schema change edits
the untagged release's migration and declarations, never a migration beside it.
Once a release is tagged, a change is a migration after it. At 1.0 the baseline
becomes 1.0's schema, beside one migration upgrading what the last 0.x release
built; a database an earlier 0.x release built is upgraded to that release
first.

## The baseline

Migration 43 makes v0.9.0's schema directly. It is numbered as v0.9.0's last
migration, so a database v0.9.0 or v0.10.x built has it recorded and applies
only what follows. A fresh install applies it and every migration after it.

| Rule | Reason |
|---|---|
| Each table is made by one declaration, beside the migration, grouped by area with the reasoning for its shape | The migration names every table after every table it points at |
| v0.9.0's record of its schema holds the baseline | On each engine it builds exactly v0.9.0's columns, constraints and indexes, and the schema test fails on any line either side lacks |
| Every statement a declaration holds is one the baseline makes | A test fails on a table or index made from anywhere else |
| On PostgreSQL the baseline also sets the finding table's vacuum settings | They are storage settings, which no declaration holds (`design-docs/database-schema.md` § Indexes) |
| A release's declaration may derive from a baseline declaration | v0.10.0's finding and supplier statement tables, and several of v0.11.0's, are the baseline's with columns or indexes added |
| A baseline declaration a later migration reads keeps its name, and each table a later migration picks from it keeps its statements | Migrations 44 and 45 read declarations by the names v0.9.0 gave them, and get v0.9.0's statements byte for byte for every table they pick |
| A database at versions 1 to 42 is refused | A release before v0.9.0 built it. Start and `openpsirt migrate up` refuse before anything runs, naming its version and the releases that upgrade it; `openpsirt migrate status` reports it as before the baseline with the same releases. v0.10.2 upgrades from version 41; v0.8.0 upgrades 39 and 40 into one v0.10.2 upgrades, and below 39 takes v0.6.0 first. Unrefused, PostgreSQL and SQLite fail on the first taken name, and MySQL and MariaDB step over every existing table and record the baseline over the old schema |

## Forward only

A database is only ever upgraded (REQ-72). Going back is restoring the backup
taken before the upgrade, which is exact on every engine.

| Rule | Reason |
|---|---|
| No migration is applied downward | There is no `openpsirt migrate down`, and no migration registers a way back |
| A database ahead of the binary is refused, at start and by `openpsirt migrate up`, naming both versions and the backup | Its schema may hold what this binary cannot read |
| The upgrade note says to take a backup first | `docs/configuration.md` § Every upgrade |
| An upgrade test reaches an earlier schema by emptying the database and migrating up to that release's last | |

## Migrations that stop half way

MySQL and MariaDB commit implicitly before and after every data-definition
statement, so a migration's transaction holds nothing together there. A failure
at statement N leaves 1 to N-1 committed and no version recorded, and every
later start fails on a name already taken.

| Rule | Reason |
|---|---|
| On MySQL and MariaDB a statement is preceded by a probe: does what it creates exist? If so it is stepped over and the step logged | The migration reaches its end and records its version. PostgreSQL and SQLite have transactional data definition |
| A probe, not `IF NOT EXISTS` | MariaDB accepts it on a table and an index; MySQL on a table only |
| Only the exact object the statement names is stepped over | One that cannot be identified runs and fails; a skip on any collision could hide a real one |
| A collision with an object made earlier in the same run is stepped over too | The probe cannot tell the two apart; the log surfaces it |
| An index a foreign key adopted is made once and never replaced | MySQL and MariaDB adopt an index led by the key's column and refuse to drop it while the key stands |
| A migration stopped half way, with a table and an index made, is run again on both engines in CI, and `make check-engines` fails when either did not run it | The engines agree on what a migration does and differ only in what a stop leaves |

## Release records

Each tagged release keeps a record of its migrations: the files it shipped,
the digest of each below its license header, its last migration, and the
schema they build on each of the four engines, captured from the tag.

| The record holds | Reason |
|---|---|
| Each file a release shipped is the file it tagged, and each file numbered or named as the release's is one it shipped | An edit changes a schema deployments hold without changing their version |
| The migrations up to a release's last build, on every engine, the schema the tag built | The files read column spellings and widths from helpers a later change may edit. On SQLite the description includes whether each key is `AUTOINCREMENT` and each index partial, which its listings omit |
| The migration library's bookkeeping table is left out of the compared schema, and a record listing it is compared without it | The library chooses its column types, and its releases change them |
| A release the baseline replaced lists no file | Its files are gone. v0.9.0's schema on each engine holds the baseline |

A file a release owns is a migration numbered after the previous release's last
up to its own, or a declaration named for it. A release changing no schema owns
no file and carries the previous release's last migration as its own.

`make release-freeze` freezes a release on a branch from the head of `main`
that lands before the tag. The release workflow runs `make release-check` and
refuses a tag whose release is not frozen, before building anything.
`design-docs/packaging-release.md` § The release procedure says where the two sit.

1. The untagged release carries one migration, numbered after the previous release's last. Its declarations are named for it by its code, the version's parts run together: `v030` for v0.3.0, `v0100` for v0.10.0. Every schema change before the tag edits these.
2. Rehearse from every earlier release the baseline upgrades, on each engine (§ Upgrade rehearsal).
3. Freeze with the four engines running: the chain's schema is described on each, then every owned file is listed with its digest and the last migration.
4. Land the record through a pull request. The digest test and the schema test hold the tree to it from then on.
5. Run `make release-check` on the commit to be tagged, then tag. The workflow checks again before building.
6. The next schema change is a new migration numbered after the tagged release's last.

| The check refuses | Reason |
|---|---|
| A release with no record | |
| An owned file the record omits or lists with another digest | The tree moved after the freeze |
| A migration numbered past the release's last | It would ship unheld |
| Declarations named for a release nothing froze | The same, for tables a migration reads |
| A record missing an engine's schema, or holding an empty one | The schema test cannot hold that engine |
| A tag that is not `vX.Y.Z` or `vX.Y.Z-rc.N` | A candidate is held to the record of the release it precedes. Any other suffix is refused, so `git describe` output is never a release |

| Freeze refuses, before writing anything | Reason |
|---|---|
| A version whose tag exists in the checkout, or where git cannot say | A tagged record is what shipped |
| A version older than one recorded | The tree's last migration is the newer release's and would be claimed |
| A version whose code a recorded release carries | v0.11.0 after v0.1.10: both read `v0110` |
| A tree whose last migration is behind the previous release's | |
| A checkout without tags | |

| Situation | What is done |
|---|---|
| The release's migration needs a fix after the freeze, before the tag or between candidates | Edit the migration and declarations, freeze again in the same pull request, and recreate any database a candidate built |
| A tagged release's migration cannot finish on a deployment, and the owner approves a fix building the same schema | The file is edited, its digest rewritten, and a comment line in the record names it amended. The schema records stay; the schema test holds the edit to the tag's schema on every engine. A fix changing the schema goes in a later migration |
| A patch to an older line after a newer release is recorded | Not cut. A tag must be on `main`, which holds the newer record |

## Upgrade rehearsal

`make upgrade-rehearsal FROM=<release> ENGINE=<engine>` upgrades a database an
earlier release built and filled itself. It is step 2 of § Release records, run
from every release from v0.9.0 on, on each engine. It builds images and scans
the demo's inventories, so it runs locally, outside the gate.

| Stage | What it does |
|---|---|
| The release's database | The release's image, built from its tag, runs its own demo targets unedited against the rehearsal's empty database: products, inventories, scans, a VEX document, decisions and an approval, an assignment, and a recorded flaw. Below v0.11.0 the rehearsal then acknowledges every report through the release's API as the administrator, since no release's seed acknowledges one |
| What it held | Open findings per build from its status report, and every table's row count with it stopped. A build with no count is not settled, and the wait refuses naming it |
| The upgrade | This tree's image applies the migrations alone, reaching this tree's last migration |
| The rows | A table holds what it held plus what the upgrade fills it with from the release's other rows; a table only the upgrade holds holds only what it is filled with; a renamed table is counted under its new name on both sides. The one fill is the v0.11.0 upgrade's: each report a release before it recorded as acknowledged, with who acknowledged it, becomes one message sent |
| Served | This tree's server, started with the release's demo configuration, reports the same open findings per build, and no GET in the API document answers 5xx. The sweep names the build that sorts first. A GET whose path parameter the seed has no name for is skipped |

| Rule | Reason |
|---|---|
| The release seeds itself | A fixture written today records what this tree thinks the release wrote |
| Only the docker command is wrapped | Containers, network and ports are renamed so a running demo is untouched, and the application points at the rehearsal's database |
| A seed that left a counted table empty is refused | An upgrade of an empty table checks nothing. The counted tables hold findings, decisions, their occurrences, received VEX statements and reports; below v0.11.0 an acknowledged report is counted too, since the v0.11.0 fill of none checks nothing |
| Counts are taken with nothing running | A server's passes write rows |
| This tree is served with the release's configuration | The environment the release's server started with, less its image's own and the database URL, reaches every container of this tree |
| An engine `make engines-up` made joins the rehearsal's network | It publishes on loopback, which no container reaches. The container publishing the URL's port joins and is addressed by name, on Docker Desktop, rootless Docker and Podman. A failing docker command, or two containers publishing the port, refuses with docker's words. Another host, or a port no container publishes, is reached through `host.docker.internal` |
| Everything it made is removed on pass, fail or interrupt | Its containers, network and database. The worktree, both images, the run's logs and the scanner's database are kept. `-keep` keeps everything. A second interrupt stops the removal |

## Migration locks

One instance migrates at a time (REQ-72).

| Lock | Excludes | Mechanism |
|---|---|---|
| Migration mutex | Other goroutines in the process | A mutex. The migration library keeps its dialect in package state, so two goroutines race whatever the database lock |
| Advisory lock | Other instances on the database | `pg_advisory_lock`, held by the database; `GET_LOCK` on a name carrying the database, since a MySQL named lock belongs to the server; an operating-system lock on a file beside a SQLite database |

| Rule | Reason |
|---|---|
| SQLite's lock is taken outside the database | It cannot take one inside, and it migrates on its one connection |
| The file lock is the operating system's advisory lock, never a lock file written by hand | The kernel drops it however a process ends. A platform without it refuses |
| SQLite's pool is narrowed to one connection while migrating, and restored after | Foreign keys are turned off on a connection before the transaction opens, which on a wider pool lands elsewhere. A release's upgrade holds one connection throughout, because a pool of one still recycles one past its lifetime. A dangling reference at commit refuses the upgrade |
| The advisory lock is taken on a pinned connection | A session lock released through the pool can land on another connection, and fails to release silently |
| The release result is read | PostgreSQL and the MySQL-protocol servers report "you did not hold this" as a value |
| A lock not held at its release fails the migration | The session was lost part way and another instance may have migrated alongside |
| A waiter waits as long as the lock is held, on every engine, in attempts of five seconds, checking between them whether to stop | The v0.9.0 upgrade took 873 s on a production-shaped PostgreSQL database, and a five-minute bound gave up at 300 s |
| A waiting process answers its health check | A replica started beside a long migration waits it out |
| A waiter names the holder at its first timed-out attempt and about once a minute after | A holder wedged part way holds every replacement behind it |
| A holder that dies releases the lock | Session locks go with the session and a file lock with the process. The waiter takes it and applies the schema from where the rolled-back migration left it |
| A stop ends a wait at once | The attempt in progress is canceled |
| `openpsirt migrate up` waits the same way | A job started beside a migrating replica waits, then finds the work done |
| The holder is named: the connection number on MySQL and MariaDB, the server process with user and application on PostgreSQL where the role may see them, and on SQLite the process and host the holder writes into the lock file | Any account that can connect may take the lock, and "another instance holds it" sends an operator looking for a replica that may not exist |
| The pinned connection is used every half minute while held | Checked out past the idle timeout, a server's or intermediary's idle timeout would end the session and release the lock to a waiter |
| A keep-alive use carries no deadline | Both drivers close a connection whose query outlives its context, which loses the lock the same way |
| A pool of one is refused before the lock is taken, on the three servers, naming `OPENPSIRT_DB_MAX_OPEN` | The lock holds one connection and the migration needs another, so it would wait for ever |
| PostgreSQL's attempt bound is a session setting unwound before the connection goes back, on every path | Left set, one pooled connection carries a five-second bound and the same query waits or is canceled by which connection it gets. `GET_LOCK` takes its bound as an argument |

A SQLite URL is accepted with a warning beside a chart that runs one process.
Four processes on one file with no lock leave the schema correct, with three
failing on the library's bookkeeping; the lock makes them wait and find the work
done.

## Limits

| Limit | Detail |
|---|---|
| The concurrency test does not cover the advisory lock | Every caller takes the in-process mutex first, so goroutines driven through the normal path pass with the advisory lock deleted. The suite drives the advisory lock from two pools directly (`design-docs/database.md` § Test harness) |
