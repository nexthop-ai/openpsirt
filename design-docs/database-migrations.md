# Database migrations

How the schema is created and moved forward: application at start, the chain
from the baseline, the record each release keeps, the rehearsal before a tag,
the lock that lets one instance migrate at a time, and the lock that stops
every other instance serving while it does.

Satisfies REQ-72, REQ-76.

## Contents

- [Migrations](#migrations)
- [The baseline](#the-baseline)
- [Forward only](#forward-only)
- [Migrations that stop half way](#migrations-that-stop-half-way)
- [Release records](#release-records)
- [Upgrade rehearsal](#upgrade-rehearsal)
- [Statement lock waits](#statement-lock-waits)
- [Migration locks](#migration-locks)
- [Instances during an upgrade](#instances-during-an-upgrade)
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
| A run that applied a migration to a database holding a schema ends by analyzing every table, inside the lock | The statistics describe the schema before it (`design-docs/database-schema.md` § Planner statistics) |
| With automatic application off, the schema version is compared before anything is served | Uncompared, a build with a new migration passes the readiness probe, a ping, fails every request touching the new table, and in a rolling deployment retires the last working replica |
| The version a binary carries is the highest among its embedded migrations, read from their file names | The migration library applies the same rule |
| Migrations are written in Go | They branch on the engine. A timestamp has no portable spelling: PostgreSQL has no `DATETIME`, and MySQL's `TIMESTAMP` is 32-bit and can acquire an implicit default and on-update clause from server configuration |
| Only the migrations registered in the binary are applied, and no directory is read | The library otherwise globs the working directory: a stray `.sql` refuses every start, a numbered one runs under the migration credential, and a numbered `.go` file narrows what is applied |
| What every migration does around its statements is one place: asking the engine, refusing one with no spellings, running each statement with its wait for a lock bounded (§ Statement lock waits), naming the one that failed by its first line | |
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
| 45 | v0.10.0's schema into v0.11.0's |
| 46 | v0.11.0's schema into v0.12.0's |
| 47 | v0.12.0's schema into v0.13.0's |

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
| One database per engine climbs the releases, checked at each; it also holds the unstopped v0.9.0 to v0.10.0 and v0.11.0 to v0.12.0 upgrades to their declarations | It reaches both schemas on its way. The v0.10.0 check is followed by a rung, which fails on a scratch table it leaves behind |

A file a release owns is a migration numbered after the previous release's last
up to its own, or a declaration named for it. Only a Go file that is not a test
is either, for the files owned and for the last migration alike. A release
changing no schema owns no file and carries the previous release's last
migration as its own.

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
| A tag that is not `vX.Y.Z` or `vX.Y.Z-rc.N`, each number without leading zeros | A candidate is held to the record of the release it precedes. Any other suffix is refused, so `git describe` output is never a release. One release has one spelling, so it is never frozen twice |

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
| A tagged release's migration cannot finish on a deployment, or logs what it must not or leaves a connection changed, and the owner approves a fix building the same schema | The file is edited, its digest rewritten, and a comment line in the record names it amended. The schema records stay; the schema test holds the edit to the tag's schema on every engine. A fix changing the schema goes in a later migration |
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
| A table that must exist and cannot be counted stops the run, naming it | An uncounted table reads as absent, and a table absent before and empty after passes. Before the upgrade every table the release's schema record names must exist; after it, every table this tree declares. A name only the release used is gone after the renames and is left out |
| A sweep in which no GET answered 2xx is refused | A refusal says nothing about whether the query behind it works. A GET that fails or answers 5xx is a fault; any other answer is logged |
| This tree is served with the release's configuration | The environment the release's server started with, less its image's own and the database URL, reaches every container of this tree |
| An engine `make engines-up` made joins the rehearsal's network | It publishes on loopback, which no container reaches. The container publishing the URL's port joins and is addressed by name, on Docker Desktop, rootless Docker and Podman. A failing docker command, or two containers publishing the port, refuses with docker's words. Another host, or a port no container publishes, is reached through `host.docker.internal`. A port no container publishes is refused while a container runs on the host network, where `ENGINE_NETWORK=host` starts the engines on loopback, out of a container's reach |
| Everything it made is removed on pass, fail or interrupt | Its containers, network and database. The worktree, both images, the run's logs and the scanner's database are kept. `-keep` keeps everything. A second interrupt stops the removal |

## Statement lock waits

A data-definition statement waits for every session holding its table, and on
PostgreSQL, MySQL and MariaDB every later statement from another session on that table
queues behind the waiting one. A paged export's snapshot holds every table it has read
for up to ten minutes (`design-docs/analytics-exports.md` § Exports).

| Setting | Value | Reason |
|---|---|---|
| One attempt's wait | 3 s, for each lock the statement waits for | A statement queued behind a waiting lock is released within this long; a statement taking two tables can hold the first while it waits for the second. A short transaction holds a lock for milliseconds and ends inside one attempt. MySQL and MariaDB count whole seconds |
| Pause after the first attempt that waits out its bound | 1 s, doubling after each | Queued statements go through during the pause, so a holder that stays leaves the table queued three seconds in four after the first attempt, and three in thirty-three from the sixth |
| Longest pause | 30 s | The longest a migration starts late once its holder lets go |
| Total wait | None | A cap is a guess at the longest holder. A stop ends the wait, and every attempt names the sessions to look at |

| Engine | Bound | An attempt that waits out its bound |
|---|---|---|
| PostgreSQL | `lock_timeout`, set for the transaction before each statement | The upgrade's transaction rolls back, letting go of every table it took, and runs again after the pause |
| MySQL, MariaDB | `lock_wait_timeout`, set for the session before each statement and put back to the session's own once it ends | The statement runs again where it stands. Each data-definition statement commits, so nothing earlier is held |
| SQLite | The busy timeout every connection opens with, a minute unless the URL names its own (`design-docs/database.md` § SQLite settings) | The upgrade's transaction rolls back and runs again after the pause. In write-ahead-log mode a reader goes through beside a writer. A table locked on the migration's own connection fails it, since no wait frees one |

| Rule | Reason |
|---|---|
| Every statement of a migration's schema change and every index dropped is bounded, the baseline's included | They run through the one place that runs a migration's statements (§ Migrations) |
| The bound is set for each statement | The v0.11.0 renames put PostgreSQL's back to the server's default part way through their migration |
| On PostgreSQL the bound lasts until the transaction ends or something resets it, so a data step after a bounded statement is bounded too, and a wait it ends runs the upgrade again | `SET LOCAL` belongs to the transaction |
| On MySQL and MariaDB the bound is lifted when the statement ends, so a data step beside it waits as the server says | The bound belongs to the session |
| A deadlock that ends the migration's statement is an attempt that waited out its bound | A holder reading a table the migration already took closes a cycle, and an ended attempt changed nothing |
| On PostgreSQL a deadlock ends whichever side checks first, once its wait passes the server's deadlock timeout | Each side checks on its own clock |
| On MySQL and MariaDB a deadlock ends the holder | A schema change outweighs a read |
| On MySQL and MariaDB a bound the session already carried, such as one the URL set, is put back after each statement, and after the v0.11.0 renames | The bound belongs to the session, and the connection goes back to the pool |
| An upgrade gives up only when stopped or on a failure other than a lock wait | A holder that ends, an export's ten-minute snapshot among them, is waited out, and the migration takes the table at the first attempt that finds it free |
| Each attempt that waits out its bound is logged with its number, the time waited, the statement, and every other session on the database with a transaction open, oldest first, twenty at most | A holder that never lets go holds the start, and the log names the session to end |
| On PostgreSQL a session whose state is hidden is named after the open transactions, whether it holds one or sits idle | Another role's state and times show only to a role that reads every session's statistics |
| On MySQL and MariaDB an account that cannot see every process is shown its own other sessions on the database | Open transactions list only for an account that sees every process, and no other account's sessions show |
| Where MySQL and MariaDB list no open transaction, every session on the database the account can see is named, idle ones included, the migrating instance's own among them | The session holding the migration lock is one of them, and ending it gives the lock up mid-migration (§ Migration locks) |
| On PostgreSQL a retried upgrade runs its earlier statements again, holding each table it takes until the attempt ends | A statement queued on such a table waits at most one attempt and the statements before it |
| The v0.11.0 renames wait in their own attempts of three seconds with a pause of a second, inside the upgrade's transaction on PostgreSQL | Their migration is the release's record, and is amended only for a fix the owner approves |
| The baseline never waits | It makes its tables in an empty database, where no session holds one |

## Migration locks

One instance migrates at a time (REQ-72).

| Lock | Excludes | Mechanism |
|---|---|---|
| Migration mutex | Other goroutines in the process | A mutex. The migration library keeps its dialect in package state, so two goroutines race whatever the database lock |
| Advisory lock | Other instances on the database | `pg_advisory_lock`, held by the database; `GET_LOCK` on a name carrying the database, since a MySQL named lock belongs to the server; an operating-system lock on a file beside a SQLite database |
| Schema change lock | Serving, on every other instance, while migrations are applied (§ Instances during an upgrade) | The same mechanisms under another key, name or file, taken on the advisory lock's session |

| Rule | Reason |
|---|---|
| SQLite's lock is taken outside the database | It cannot take one inside, and it migrates on its one connection |
| The file lock is the operating system's advisory lock, never a lock file written by hand | The kernel drops it however a process ends. A platform without it refuses |
| The lock file is opened only as a regular file with one name, never through a symbolic or hard link | The holder truncates it and writes its name into it, so a planted link would clobber the file it points at |
| A waiter reads the holder's name through the file it opened and checked, never through the path again | The path can name something else by then, and the name reaches the log |
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
| The release is bounded, as unwinding the session is, and waits for a keep-alive use no longer than that | A stalled connection otherwise holds the start for as long as the operating system retransmits, after the work is done. The failure is reported, and the connection is closed once its use ends, never returned to the pool, so its session ends and the server frees the lock |
| An unlock that fails closes its connection, never returning it to the pool | A statement whose context has already ended is refused before it is sent, and neither driver closes the connection for it, so its session still holds the lock |
| A pool of one is refused before the lock is taken, on the three servers, naming `OPENPSIRT_DB_MAX_OPEN` | The lock holds one connection and the migration needs another, so it would wait for ever |
| PostgreSQL's attempt bound is a session setting unwound before the connection goes back, on every path | Left set, one pooled connection carries a five-second bound and the same query waits or is canceled by which connection it gets. `GET_LOCK` takes its bound as an argument |

A SQLite URL is accepted with a warning beside a chart that runs one process.
Four processes on one file with no lock leave the schema correct, with three
failing on the library's bookkeeping; the lock makes them wait and find the work
done.

## Instances during an upgrade

No instance serves while another applies migrations (REQ-72): an answer read
from a schema part way through a change cannot be trusted, so an upgrade is an
outage for as long as its migrations take.

| Rule | Reason |
|---|---|
| An upgrade takes the schema change lock after reading the version, where a migration is outstanding, and lets it go after the last migration and the statistics refresh, on every path | A start with nothing to apply takes the migration lock alone, so a replica starting beside others pauses none of them |
| On MySQL and MariaDB, beside the lock, the upgrade writes a row to the schema change record, where the database has that table, naming the last version it applies | The lock goes with its session; the row outlives an upgrade that fails part way |
| On every engine, a release's migration writes a row naming its version in its own transaction, which a test holds for every release migration from v0.13.0's on | It commits with the schema and rolls back with it, so a process killed after the commit and before the migration library records the version leaves a row |
| An upgrade ending any way removes every row naming a version no later than the one then applied | A success leaves no row; a failure leaves the rows of what is still outstanding |
| A row counts while the version applied is behind the one it names | A row left by a process ended after its last migration, or by a removal that failed, pauses nobody |
| A start with nothing to apply removes every row the version applied has reached | The record holds only upgrades still outstanding |
| On MySQL and MariaDB a failed upgrade's row stays | Each data-definition statement commits alone, so the schema is part changed, and nothing serves it until an upgrade reaches the version the row names or the backup is restored |
| On PostgreSQL and SQLite no row is written before the first statement | The change lock and a migration's transaction end together, a killed process included, so a row written ahead would outlive a schema left whole |
| An upgrade stopped during the notice removes the row it wrote | Nothing has changed |
| On a database holding a schema, the upgrade waits 46 seconds holding the change lock before its first statement | For every serving instance to see the lock, 15 seconds: the rest of a look that asked just before the lock was taken, an interval, and one whole look; then 30 seconds for the longest write a stopped request or pass goes on with (recording a patch branch visit, cleaning up an attachment), and a second more. A test helper migrating a database it alone holds waits none |
| A statement already running when an instance pauses holds its tables, and the upgrade waits for it | § Statement lock waits |
| `openpsirt migrate up` takes the change lock and waits the same way | It is the same upgrade under other credentials |
| A serving instance looks every second: is the change lock held or a record standing, and which version is applied, read before and after | One look costs under two milliseconds on every engine: 1.12 ms on PostgreSQL, the slowest, with a count of a table holding no row beside it where the lock is free (`design-docs/database-measurements.md` § Schema watch looks) |
| A look takes nothing an upgrade waits for | PostgreSQL reads the lock table; MySQL and MariaDB ask who holds the named lock; SQLite takes a shared lock on the file for the moment of looking, never through a link and never waiting on a file that is not a regular one, and the upgrade tries again past it |
| A look takes a connection of its own from the pool, waiting up to ten seconds, then asks within two | A pool busy with requests delays a look without failing it |
| A look that cannot take a connection, fails, or overruns either bound reads as Changes, logged once until a look succeeds | An instance that cannot tell whether the schema is changing does not serve it |
| A look reads the version first, and a version ahead is Superseded even where asking about a change then fails | A later release may have reshaped what that asks |
| A start looks once more just before its router opens, and refuses to start unless the look finds Serves | Preparing to serve takes up to the startup deadline, longer than the notice |
| SQLite's change lock file gains read for every user after opening, whatever the umask; where the file system refuses, the upgrade logs it and goes on | Migrations may run as another user than the server, whose looks would otherwise fail and pause it |
| On SQLite a change lock held past one attempt at the migration lock is logged about once a minute | A serving instance's look holds it for a moment; anything longer is a holder outside the application |
| On the server engines the change lock held by a session outside the application refuses the upgrade, naming the holder | Only the migration lock's holder takes it |
| The change lock's statements and the keep-alive never overlap on the lock's connection | A driver may close a connection asked a second question before it has read the first answer, and both locks go with the session |
| A change lock whose release failed has its connection closed when the migration lock is let go, never pooled | A pooled connection holding it would pause every instance until the pool retired it |

| Standing | When | The instance |
|---|---|---|
| Serves | The applied version is this build's and nothing is changing it | Serves through the router, and runs its passes |
| Changes | The change lock is held or a record stands, at a version not ahead of this build's | Pauses, and resumes at Serves |
| Behind | The applied version is behind this build's and nothing is changing it, such as a restored backup | Stops |
| Superseded | The applied version is ahead of this build's, whether or not anything is changing it | Stops |

| A paused instance | Reason |
|---|---|
| Answers every request as it answers while it migrates at start (`design-docs/packaging.md` § Starting and stopping) | Readiness fails, and every other path is 503 with `Retry-After` |
| Ends every request the router was answering | Its transaction rolls back |
| Answers a request it ended as upgrading where the handler's answer is a refusal, a failure or nothing | A handler whose context ended may answer its failed lookup as a refusal |
| Keeps the answer of a request whose handler wrote a success or a redirect | What it did took effect, and a retry would repeat it |
| Stops every pass and the queue's workers | No pass writes while another instance migrates |
| Answers through the router again at Serves, whether or not the stopped passes have ended | The router does not depend on the passes |
| Starts the passes again once the stopped ones have ended | Two copies of one pass never run at once |
| Stops, exiting 1, where a stopped pass has not ended within the shutdown grace of serving again | A pass that ignores its context would otherwise keep the passes off with nothing logged |

| A stopping instance | Reason |
|---|---|
| Pauses, then stops through the ordinary shutdown and exits 1, naming both versions | A supervisor reads the exit code |
| Stops when Superseded | A database is only ever upgraded, so it never serves this one again; the platform replaces it |
| Stops when Behind | Its next start migrates the database or refuses it |

| Rule | Reason |
|---|---|
| The watch runs whether automatic migration is on or off | A separate `openpsirt migrate up` changes the schema the same way |
| The watch ends with serving | It reads a database the process closes once serving ends |
| No interval setting | A look every second costs under two milliseconds, so a slower one earns nothing |

## Limits

| Limit | Detail |
|---|---|
| The concurrency test does not cover the advisory lock | Every caller takes the in-process mutex first, so goroutines driven through the normal path pass with the advisory lock deleted. The suite drives the advisory lock from two pools directly (`design-docs/database.md` § Test harness) |
| Any account can hold the migration lock and the change lock | Any account on a MySQL or MariaDB server, or any role with CONNECT on the PostgreSQL database, can take the migration lock and hold every start behind it; the waiter's log line names the connection to end. The same account taking the change lock pauses every serving instance until its session ends |
| An instance of a release without the change lock does not look | It serves through an upgrade; the upgrade note says to stop every instance of the earlier release first |
| On MySQL and MariaDB a data step waits for a row as the server's own bound says, and a writer holding the row past it fails the migration. | Retrying the step where it stands loses the work before it under `innodb_rollback_on_timeout`, and retrying from the start runs again each data-definition statement already committed |
