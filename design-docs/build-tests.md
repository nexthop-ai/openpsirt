# Test databases and engines

The database servers the suite runs against, the database each test binary
holds, the race pass, and the durability a test commit waits for.

Satisfies REQ-75.

## Contents

- [Database engines](#database-engines)
- [Test databases](#test-databases)
- [Seeded templates](#seeded-templates)
- [Shared scenarios](#shared-scenarios)
- [Server database slots](#server-database-slots)
- [Measurement databases](#measurement-databases)
- [The race pass](#the-race-pass)
- [Checks beside the tests](#checks-beside-the-tests)
- [Engine selection](#engine-selection)
- [Commit durability](#commit-durability)
- [In-package test files](#in-package-test-files)
- [Test bodies](#test-bodies)
- [Limits](#limits)

## Database engines

The suite runs on SQLite alone unless pointed at servers, and a skipped engine
passes. `make engines-up` starts the servers, waits until each answers, and
writes their URLs to the git-ignored `local.mk`, which the makefile includes.

| Rule | Reason |
|---|---|
| Each server is asked with its own client, in its own container | "Up" is not answering, and no host client is assumed |
| Each listens on loopback alone: published on it by default, or bound to it on the host network where `ENGINE_NETWORK` is `host` | They carry the password `test` |
| CI runs them on the host network | A published port's traffic passes through a proxy process: 77 of 871 processor-seconds of `test-all` on four cores |
| Published ports stay the default | The host network of rootless Docker or a desktop virtual machine is not the machine's |
| A published server listens on its image's port inside its container; on the host network each listens on its own | A container created before the choice existed still answers |
| The PostgreSQL servers run without the query compiler (JIT), the floor server included | Compiling changes no result, and whether a query compiles turns on the planner's estimates, so its cost moves at random from run to run |
| `make measure` turns the query compiler back on for its own sessions, through a setting on its PostgreSQL URL | A deployment keeps the compiler on, and a measurement has caught it costing 1,685 ms against 170 ms |
| The MySQL server runs without its performance schema | Nothing a test asserts reads it, and it costs the server 3% of its processor time |
| MySQL's X protocol listener is off | Nothing speaks it, and on the host network it would listen on every address |
| A server is ready when it answers over TCP on loopback | Each image first initializes on a temporary server listening on a socket alone |
| `local.mk` is never overwritten | It may point at an operator's own servers |
| Starting is idempotent: a running engine is left, a stopped container started | |
| CI starts its servers with `make engines-up`, from the same one list | A local pass means CI's only on the same servers |
| Images are pinned by tag and digest; `pins-check` refuses one named by tag alone, a list naming none, and a workflow declaring a container of its own | A tag moves under a rebuild, and a workflow's container is a second list. Dependabot reads no makefile, so the list moves by hand |
| The four are pulled and started at once, and a failure in any fails the target | |
| Each data directory is in memory under a cap: 1 GB PostgreSQL, 3 GB MySQL and MariaDB, 256 MB the floor server | Past it a write fails as a full disk on that server; unbounded, the four grow into the memory the tests run in. Two weeks of a workstation's runs left 349 MB, 1.6 GB, 1.6 GB and 47 MB, and the caps leave a 16 GB runner over 8 GB |
| One server is below the supported version floor | The old-server refusal is exercised |
| The URLs are read when make starts | The run writing `local.mk` is not the run using it |
| A harness session on MySQL or MariaDB waits 60 seconds for a metadata lock, unless its URL sets `lock_wait_timeout` | The servers default to a year on MySQL and a day on MariaDB, so a server wedged on a lock it never grants hangs every statement needing it to the test binary's timeout; bounded, the waiting statement fails and is named |

`design-docs/build-measurements.md` § Server processor time has the timings.

## Test databases

Each test binary is one package and holds its own database on each engine, so
packages run in parallel.

| Engine | A test gets | Emptied between tests |
|---|---|---|
| SQLite | A copy of a template migrated once per run, and its own connection | Never; each test has its own file |
| The three servers | The binary's leased database (§ Server database slots) through one pool the binary's tests share | Before every test, by deleting from tables holding rows |

| Rule | Reason |
|---|---|
| A binary's tests share one server pool | A new PostgreSQL connection's first statement costs 43 ms against 3.4 ms warm: 90 s against 48 s for the API package. Tests in a package run in sequence on a server |
| The SQLite template is migrated by the first binary asking and kept in the temporary directory | Migrating per package was 24 s of the race pass's 383 s |
| The template's file name carries the migrations' fingerprint, the name widths they read, and the SQLite and migration library versions; a file not opening as a database is migrated again | Any change names a new file |
| A handle whose commit is made to lose copies the template, through the refusing connector | 0.06 s against 1.3 s migrating, under the detector |
| A test hooking statements hooks its own copy of its query builder and builds the stores on it | A hook on the shared builder fires in later tests, which the race detector reports |
| A test never empties the database on starting | The harness has |
| A test empties it part way only to start over within itself | A second world, per-case empty tables, a migration test applying an earlier release |
| Tests within a package run in parallel only when SQLite is the whole run | On a server they would clear each other's rows |
| A test changing process-wide state, an environment variable or the working directory, runs alone | |

## Seeded templates

A package whose tests share starting rows declares them once as a seeded
template: a function filling a migrated, empty database and returning what tests
need, such as an identifier or a secret shown once.

| Engine | The seed runs | A later test gets |
|---|---|---|
| SQLite | Once per binary, into the template | A copy of the template |
| The three servers | Once per binary, in its first test, after emptying | The rows the seed wrote, read back after it ran. What the test before changed is undone, in one transaction (§ Reset between tests) |

| Rule | Reason |
|---|---|
| A test reads what the seed returns and never writes to it | It is one value shared by every test, and on SQLite by parallel tests |
| Rows are written back with the identifiers they were read with | What the seed returned names them. Emptying leaves every engine's identifier counter past them, so a row a test adds takes a new one |
| A table's rows are written back in identifier order, parents' tables first | A row referencing its own table follows the row it references |
| A measurement runs the seed per test | Truncating starts a table's identifiers again on MySQL and MariaDB, under the identifiers kept |
| A test holds every column of a written-back row to what the seed wrote: a moment to the microsecond, a date, both booleans, an absent value, text outside ASCII | A value the driver reads in one form and writes in another changes a seeded row on one engine only |
| The API package's seed is written back, never run, after its first test | About a hundred transactions: 157 ms a test on PostgreSQL and 71 ms on MySQL |
| The API package's fixture is a seeded template | Two products, eighteen people, their decisions and grants: per test it was 27% of the package's processor time under the detector |
| The API's operations are registered once per test binary, and each test's server answers with that test's dependencies | Registering takes 13 ms, and 44 ms under the detector; answering with a test's dependencies takes 6 µs |
| A test adjusting its dependencies registers afresh | An adjustment may change what registering reads, such as the limits an upload is bounded by |

A test needing a product, its branches and tags, its variants and a build takes
them from one shared default world, a seeded template of its own or part of a
package's. A test needing a second product declares it on that world. Each test
gets its own copy of the world's rows as values, so changing one reaches no
other test.

| The default world holds | So that |
|---|---|
| A product whose display name is not its name in other capitals | A read answering the display name for the name fails |
| A branch and a tag cut from it | A read keyed on either answers more than one bucket |
| One variant reaching customers and one not | A rule on that flag shows both sides |
| A person whose display name is neither empty nor their identity | The two never coincide |

| Uses its own rows, never the default world | Because |
|---|---|
| The catalog and access packages, the API package's catalog tests, the schema width tests | The declarations are what they test |
| The API authorization tests | Their products and people are the matrix |
| A migration test | It seeds the older schema it migrates from |

### Reset between tests

A later test on a server starts by undoing what the test before it did to the
kept rows, in one transaction. Emptying the seeded tables costs most of a start
on PostgreSQL, which checks every foreign key referencing a deleted row once
per row, and most tables reference a person.

| Table | At a test's start |
|---|---|
| Holding no kept row | Emptied |
| Holding kept rows, with an identifier | Rows the test added deleted; kept rows it changed written back in the columns that differ; kept rows it deleted written again with their identifiers |
| Holding kept rows, with no identifier | Emptied and written back whole where it differs |

| Rule | Reason |
|---|---|
| Kept rows are written again, parents first, and written back before anything is deleted; the deletes run children first | Every kept row then points only at kept rows, so no delete, nor a foreign key's action on one, reaches a kept row |
| A column referencing its own table with no action on a delete is emptied on the rows going first | MySQL and MariaDB enforce it during a bulk delete even where every row is going |
| No foreign key references a table without an identifier | Writing it back whole would delete what references it. A test holds this and the list of self-references against the schema |
| A table holding more than 200 rows past its kept ones, a changed column list, or a write back refused, ends the undoing: the transaction rolls back, and the database is emptied and the rows written again | Reading a large table to compare costs more than emptying it; a refusal is usually a unique value an added row holds |
| A test changes kept rows in each way above and holds what reads back to what the seed wrote, on every engine | |
| The question of which tables hold rows is prepared once per harness pool | Planning it costs 37 ms on a PostgreSQL connection that has not seen it and about 3 ms after |
| A measurement never undoes | It truncates, for the layout a fresh load leaves (§ Measurement databases) |

`design-docs/build-measurements.md` § Seeded test starts has the timings.

## Shared scenarios

Checks that read one scenario are subtests of one test, which builds the
scenario once per engine: a server, its seeded cast and the rows the checks read.

| Rule | Reason |
|---|---|
| A subtest is named for the check it holds and keeps that check's failure messages | A failure names the check, as a test of its own did |
| A subtest that writes runs after every subtest that reads | Each subtest reads what it read as a test of its own |
| Two checks that each write are two tests | The second would read the first's rows |
| Checks making one identical write share it, each reading before it and after | Neither reads a row the other made |
| A merged test covers the statements its checks covered as tests of their own | Merging moves where a check runs and never what it reaches |

## Server database slots

A server database is kept between binaries and runs, because migrating is nearly
the whole cost of a server engine on disk: 9.8 s on MySQL, 7.2 s on MariaDB. A
CI server is new each run, so the first binary in a slot builds its database and
later ones reuse it (`design-docs/build-measurements.md` § Server database
slots).

A database belongs to a slot of a schema, leased by one binary while it runs.
The database and the slot's lock share one name.

| Part of the name | Reason |
|---|---|
| A hash of the migration sources' fingerprint | Below 1.0 a schema change edits a migration and the version does not move |
| The slot's number | Binaries running at once hold different databases |
| Neither the package nor the checkout | Any binary of the same migrations takes a freed slot with its database |

| Slot rule | Reason |
|---|---|
| A binary leases the lowest slot no binary of its schema holds, one per server | The lowest most likely has a database |
| The lease is a lock held for one connection: a named lock on MySQL and MariaDB, a session advisory lock on PostgreSQL | A crashed binary's lock is released with its connection |
| Slots are asked for without waiting | |
| The lock is keyed on schema and slot | |
| On PostgreSQL every lock is taken in the `postgres` database | Advisory locks are per database; two URLs would otherwise share slots and empty each other's rows |
| Sixty-four slots per schema; a binary finding all held refuses in words | |

| Left by an earlier binary | Harmless because |
|---|---|
| Rows | Every test empties first |
| Identifiers past the last binary's | No test assumes a sequence start |
| A changed schema: a renamed table, an earlier release | The test restores it |

| A kept database | The harness |
|---|---|
| This schema, at its final version | Uses it |
| This schema, at another version or none | Rebuilds it. A killed migration leaves one, and on MySQL and MariaDB a schema statement commits alone, so no version records the part applied |
| Another schema, slot held | Leaves it |
| Another schema, slot free | Drops it when creating its own, under the clean's locks. A refused drop, an open session or a missing privilege, is reported and the lease stands |

`make engines-clean` drops every unheld harness database on every configured
server, safely beside running tests.

| Step | Reason |
|---|---|
| Each database's locks are taken without waiting on the clean's connection; a held one leaves the database | It is in use |
| The locks are the database's name and that name without its last part | The second is an older harness's per-package slot lock |
| The drop happens under the locks, released after | A binary starting meanwhile takes another slot |
| A database named for no slot is dropped | |
| On PostgreSQL a database is marked not a template before its drop | A test marks a stale database a template to have its drop refused, and a binary killed before its cleanup leaves the mark. A lease's own housekeeping leaves the mark, so the refusal reaches it |

## Measurement databases

A binary built with the `measure` tag empties a server database by truncating
every table, so plans are timed over the layout a fresh load leaves, the closest
to a deployment's.

| Engine | Reloaded after a delete | Emptied for a measurement |
|---|---|---|
| PostgreSQL | Fills freed space anywhere: more pages, identifier order lost | One `TRUNCATE` naming every table |
| MySQL, MariaDB | Page count varies with the purge's progress | `TRUNCATE TABLE` each, foreign key checks suspended on that connection and restored before it returns to the pool |
| SQLite | Not reached | The ordinary way |

| Rule | Reason |
|---|---|
| Truncation is for measurements alone | 96 ms on PostgreSQL, 232 ms on MySQL, 47 ms on MariaDB, against 1 to 4 ms per test |
| Every table is truncated | Another package's binary may have filled any |
| The `finding` table's layout is printed beside the timings | The plan follows the layout: a 32 to 104 s plan was chosen over a fresh database four times in four and over a reused one never in six |
| A table with no statistics is refused | It reads as empty |

| Engine | Printed |
|---|---|
| PostgreSQL | Pages, and the correlation of each column leading an index |
| MySQL, MariaDB | Clustered index pages; InnoDB orders rows by primary key |
| SQLite | Nothing |

## The race pass

The race detector runs on SQLite alone: a data race does not vary by engine, and
the detector's cost is in-process work. The detector is per binary, so
`test-all` is two runs, SQLite with it and the servers without.

| Rule | Reason |
|---|---|
| The server run takes only the packages whose test binaries reach `database/sql`; the race run takes every package | A binary holding no SQL connects to no engine, so the server run repeats it without the detector: 3.2 s and 10.8 s of processor time on a cold build cache |
| A program reads the division from `go list -test`, never a list. It and its test run the go command `GO` names, which make exports | A listing by another toolchain is one the recipe never sees. Its tests report a package importing a database package that the server run lacks, a listed package outside the module, a recipe handing either run the other's list, and a listing that examined nothing or picked nothing |
| The two runs go at once on half the cores each | One is in-process, the other waits on sockets: 100 s and 1.5 GB against 119 s and 3.4 GB in sequence |
| Each run labels its lines as it prints | Held, a slow run looks stopped; unlabeled, nobody knows which failed |
| Each run ends on a line giving when it finished and how long after the start | CI reads it to measure the cores one run leaves idle |
| A failure in either fails the target | Checked by breaking each |
| The race binary sleeps 100 ms before exiting | The default second is paid per binary, the better part of a minute across the tree where the pass runs one package at a time |
| The SQLite engine's translated C, its C library and the allocator under the library are built without the detector and its pointer checks, and nothing else is | They are most of the cost: an empty test takes 57 ms against 4.4 ms |
| The engine's Go driver stays instrumented | Uninstrumented, an error it fills reports a false race |
| A race inside the translated C, its C library or the allocator is not reported | |
| A test races this tree against the standard database layer and expects the report | Excluding more silences it |
| The per-package compiler flags are undocumented | A Go release rejecting one fails the build loudly |
| Neither run vets; `make test` keeps the vet `go test` runs | The linter's `govet` runs every analyzer `go vet` does over the test files (`design-docs/build.md` § Static analysis), and the subset `go test` picks cost each run 1.8 s and 11 s of processor time after a change low in the tree |
| Every test target links its binaries without DWARF | Nothing in a test reads it: a caller's file and line and a race report's frames come from the runtime's own tables. A relink of every test binary is 42 to 47 s against 55 s in sequence |

`design-docs/build-measurements.md` § The race pass has every configuration.

## Checks beside the tests

`make check` runs its checks reading no database inside `test-all`, in the
cores the first run to end leaves idle: the interface install, the API
document, the full-size inventory read, the Go vulnerability scan, the
licenses, the secret scan, the API document's currency, this project's
inventory and the interface checks.

| Rule | Reason |
|---|---|
| They start when the first run ends | Both runs together leave 3% of a four-core runner idle; the server run alone leaves 39% |
| They run one after another, at the lowest scheduling priority | A run still going takes every core it can use, and the checks take what it leaves |
| Each check, and every program it starts, uses at most as many cores as one run had: Go's thread count and the interface tests' workers | The cores a finished run frees are the room, and more workers than that contend for nothing idle |
| Each check's output is held in a file and printed whole, labeled, when it ends, followed by a line naming it, its result and its time | Threaded through the running pass's lines, it reads as neither |
| The checks end on a line giving when they finished and how long after the start | CI reports the cores idle beside them and after them from it |
| Every check runs, and any one failing fails `test-all` and `check` | Checked by breaking one |
| A check that passed is not made again by a later one | The interface is installed and the API document generated once |
| They also start if both runs end without printing their last line | A run killed by a signal leaves nothing to wait for |
| `test-all` on its own runs the tests alone | `make gate` runs the checks a change reaches as targets of their own |
| `test-all` names the make command it runs the checks with through the environment | A recipe naming it is run even by `make -n`, which would run the suite |
| The variable listing the checks is set before the `check` rule line | Set after it, the recipe lines printed where an engine is unconfigured follow a variable line, and make refuses the file |

`design-docs/build-measurements.md` § Checks beside the tests has the times.

## Engine selection

`OPENPSIRT_TEST_ENGINES` narrows the engines a run touches; `test` and
`test-race` set it to `sqlite`.

| Rule | Reason |
|---|---|
| The pool's idle reaper, the migration lock and the version floor read it too | Otherwise the quick loop opens the servers and a stopped container reads as a regression |
| The rule lives in one package below the harness and the migration runner | The migration lock's internal test cannot import the harness |

## Commit durability

Test databases are disposable and a crash is answered by rerunning, so commit
durability protects nothing and is most of a run's cost.

| Engine | Setting | Asked for |
|---|---|---|
| SQLite | `synchronous` off | A pragma on every harness connection, the racing handle included |
| PostgreSQL | `synchronous_commit` off | The connection string, for the session alone |
| MySQL, MariaDB | `innodb_flush_log_at_trx_commit` and `sync_binlog` zero | By the harness from the connection, once per engine per binary, where `OPENPSIRT_TEST_RELAX_DURABILITY` is 1. Both are global and outlive the run for every database on the server |

| Rule | Reason |
|---|---|
| A server's globals change only where it is declared a throwaway | `make engines-up` writes `OPENPSIRT_TEST_RELAX_DURABILITY ?= 1` into a new `local.mk`, and CI sets it. Elsewhere the server keeps its durability and the test pinning the settings skips |
| Nothing a test observes changes | The settings govern crash survival alone |
| The harness asks from the connection | It reaches a server somebody else started, which takes no command line from here. Relaxed, the server packages take 77 s against 240 s on a workstation; a GitHub runner's pass on disk did not move |
| `make engines-up` also passes the same intent on the server's command line at startup | It reaches settings an engine accepts only there |
| A server `make engines-up` starts keeps its data directory in memory, CI's included | A schema change syncs its files whatever the settings: 0.83 s against 9.8 s on MySQL. The cap bounds what it takes (§ Database engines) |
| A restarted container has lost its databases, and the harness migrates new ones | |
| A test reads the setting back and fails where it is durable on a connection that could change it | It separates a harness that stopped asking from a server nobody may configure, which runs slower |

`design-docs/build-measurements.md` § Commit durability has the timings.

## In-package test files

A test file in a package's own namespace builds a variant of the package for
its test binary, and every package that binary holds which imports it is
compiled again against that variant: the harness, the seeded world, and the
findings package between them.

| Rule | Reason |
|---|---|
| A package the harness or the seeded world imports tests through its exported surface where it can | The trail's tests build in 0.67 s against 2.4 to 3.1 s after a change to the findings package |
| A test needing a moment the store stamps writes the row, then moves its timestamp in the database | The store's clock is unexported, and exporting it for a test is exported code with no caller |

## Test bodies

Work a test repeats in its own body, past what the harness sets up.

| Rule | Reason |
|---|---|
| A test reaching a bound sets a small one on its own store | The default's worth of rows took 3.6 to 3.8 s on PostgreSQL and MySQL, and the next test on PostgreSQL 3 s more emptying them. A package variable races with the package's parallel SQLite tests |
| Cases ordering rows by each row's own values are pairs of rows in one world, each case a named subtest | A world per case is an API, a seeded code finding and two runs |
| A test needing PostgreSQL to refuse a drop marks the database a template | A drop beside another open session is refused only after the server waits five seconds for it to leave |
| A randomized comparison reaches each check it guards in a steady round | Its random rounds differ run to run: one PostgreSQL run of twelve in nineteen missed a block every run of twenty reached |
| Its random rounds are the fewest reaching, over repeated runs on every engine and from several sets of seeds, the blocks a larger count reaches | A round past that reaches nothing new |

`design-docs/build-measurements.md` § Test bodies has the timings.

## Limits

| Limit | Detail |
|---|---|
| A test database is named for schema and slot alone | A checkout in the name outlives it: one workstation reached about 750 databases and 55,000 tables per MySQL and MariaDB server |
| Foreign key checks stay on while a test starts | Suspending them is engine-specific, and on PostgreSQL needs a privilege a test server may not grant |
| A test killed while changing the schema leaves it changed | The version still matches, so the next binary fails on the missing table until `make engines-clean` |
| Checkouts of two schemas running at once drop each other's free databases | Each drop costs the other one build |
| The clean trusts the slot lock alone | A database used without its lock is dropped in use |
| A check needing a running server refuses, never skips | A skip passes |
| The checks beside the tests outlast the server run where it leaves too little idle | They keep the lowest priority and the cores one run had |
| The lowest priority ranks the checks below the test binaries alone | The servers run in containers the scheduler shares time between first, so the checks still take some from them: on four cores of a workstation the server run ended 9 to 20 s later |
| The graph, inventory reader, currency and access packages keep in-package test files | Each exposes an unexported value, bound or clock to its tests, and exporting one would be for a test alone; their test binaries still compile the packages between them and the harness twice |
| A MySQL lock wait in an upgrade test reports the holders from the process list | The metadata locks it names elsewhere are in the performance schema, which the test server lacks |
| MySQL and MariaDB drop a database another session is open on | The test of a refused stale drop refuses nothing there |
