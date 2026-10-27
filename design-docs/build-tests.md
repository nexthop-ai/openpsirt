# Test databases and engines

The database servers the suite runs against, the database each test binary
holds, the race pass, and the durability a test commit waits for.

Satisfies REQ-75.

## Contents

- [Database engines](#database-engines)
- [Test databases](#test-databases)
- [Seeded templates](#seeded-templates)
- [Server database slots](#server-database-slots)
- [Measurement databases](#measurement-databases)
- [The race pass](#the-race-pass)
- [Engine selection](#engine-selection)
- [Commit durability](#commit-durability)
- [Limits](#limits)

## Database engines

The suite runs against SQLite alone unless pointed at real servers, and a
skipped engine passes, so a green run means nothing failed. `make engines-up`
starts the servers, waits until each answers, and writes their URLs to the
git-ignored `local.mk`, which the makefile includes when present.

| Rule | Reason |
|---|---|
| Each server is asked with its own client, inside its own container | A container reported "Up" is not one that answers, and nothing depends on a client installed on the machine |
| Each is published on the loopback address alone | They carry the password `test` and accept any statement |
| `local.mk` is never overwritten | It may point at an operator's own servers |
| Starting is idempotent | A running engine is left alone; a stopped container is started, never replaced |
| Images are pinned and compared against CI's in both directions, with CI running the check | A local four-engine pass means CI's only on the same servers |
| Each image is named by tag and digest, here and in CI, and `pins-check` refuses a workflow service named by tag alone | An upstream rebuild moves a tag. Dependabot reads no workflow service, so the two lists move by hand, together |
| One of the four is below the supported version floor | The refusal to run against an old server is exercised |
| The URLs are read when make starts | The run writing `local.mk` is not the run using it |

## Test databases

Every test binary is one package and holds a database of its own on each engine
while it runs, so packages run in parallel and share nothing.

| Engine | A test gets | Emptied between tests |
|---|---|---|
| SQLite | A copy of a template migrated once per run, kept in the temporary directory, and a connection of its own | Never; each test holds its own file |
| The three servers | The binary's leased database (§ Server database slots), through one pool every test in the binary shares | Before every test, by deleting from the tables holding rows |

| Rule | Reason |
|---|---|
| The server pool is shared by the binary's tests | A new PostgreSQL connection's first statement over the schema costs 43 ms against 3.4 ms warm; the API package spent 90 s with a pool per test and 48 s with one. Tests in a package run in sequence on a server, and the emptying removes what the pool could carry |
| The SQLite template is migrated by the first binary that asks and kept for the rest | Migrating once per package was 24 s of 383 s of the race pass's processor time |
| The template's file name carries everything its content follows from: the migrations' fingerprint, the name widths they read, the SQLite library and the migration library | Any of those changing names a different file. One that does not open as a database is migrated again |
| A handle whose commit is made to lose a race copies the same template, opened through the connector refusing the commit | 0.06 s of processor time against 1.3 s migrating a fresh file, under the detector |
| Each test gets a query builder of its own over the shared pool; a test counting or interrupting statements hooks a copy and builds the stores under test on it | A hook on a shared builder fires in every later test, beside that test's writers, which the race detector reports |
| The harness empties the database before every test, so a test never empties it on starting | |
| Emptying part way through is for a test starting over within itself | One seeding a second world, one whose cases each need an empty table, a migration test applying an earlier release |
| Tests within a package run in parallel only when SQLite is the whole run | Only then does each test hold a database nothing else reaches; on a server two tests would clear each other's rows |
| A test changing what the whole process shares, an environment variable or the working directory, says so and runs alone | |

## Seeded templates

A package whose tests start from the same rows declares them once, as a seeded
template: a function filling a migrated, empty database and returning what a
test needs to reach the rows, such as an identifier or a secret shown once.

| Engine | The seed runs |
|---|---|
| SQLite | Once per binary, against the template, before the first copy |
| The three servers | Per test, after the binary's database is emptied |

| Rule | Reason |
|---|---|
| What the seed returns on SQLite is one value shared by tests running in parallel, so a test reads it and never writes to it | |
| The API package's fixture is a seeded template | Two products and eighteen people with their decisions and grants, about sixty transactions: per test it was 27% of the package's processor time under the detector, as a template it is a file write |

A test needing a product, its branches and tags, its variants and a build takes
them from one shared default world, seeded per test or as a package template's
rows.

| The default world holds | So that |
|---|---|
| A product whose display name is not its name in other capitals | A read answering the display name where the name is resolved fails |
| A branch and a tag cut from it | A read keyed on the branch or tag answers more than one bucket |
| One variant reaching customers and one not | A rule keyed on that flag is shown on both sides |
| A person whose display name is neither empty nor their identity | A read of one never coincides with the other |

| Declares its own rows | Because |
|---|---|
| A test needing a second product | It declares it on the same world |
| The catalog and access packages, the API package's catalog tests, the schema width tests | The declarations are what they test |
| The API authorization tests | Their two products and people are what the matrix tests |
| A migration test | It seeds the older schema it migrates from |

## Server database slots

A server database is kept between binaries and runs and reused, because
applying the migrations is nearly the whole cost of a server engine on disk:
9.8 s on MySQL and 7.2 s on MariaDB for one database. A server CI starts is new
every run, so the first binary to lease each slot builds its database and later
binaries in that slot reuse it. `design-docs/build-measurements.md` § Server
database slots has the pass timings.

A database belongs to a slot of a schema, and a binary leases the slot while it
runs. The database and the slot's lock share one name.

| Part of the name | Reason |
|---|---|
| A hash of the migration sources' fingerprint | An edited migration names different databases. Below 1.0 a schema change edits a declaration and the applied version does not move, so only content tells schemas apart |
| The slot's number | Two binaries running at once hold different databases |
| Neither the package nor the checkout | A binary of any package, from any checkout of the same migrations, takes a freed slot with its database. A server holds as many databases per schema as the most binaries of it alive there at once |

| Slot rule | Reason |
|---|---|
| A binary leases one slot per server, the lowest no other binary of its schema holds | Slots stay few, and the lowest most likely holds a database already |
| The lease is a lock the server keeps for one connection: a named lock on MySQL and MariaDB, a session advisory lock on PostgreSQL | A binary that exits or crashes closes the connection, which releases the lock |
| Each slot is asked for without waiting | Two binaries starting at once get different slots |
| The lock is keyed on the schema and the slot | Checkouts of different migrations never build over each other's database |
| On PostgreSQL every lock is taken in the maintenance database, `postgres` | An advisory lock is scoped to one database; two URLs naming different databases would take two lock spaces over one set of slot databases and empty each other's rows |
| Sixty-four slots per schema | A binary finding every one held refuses in words |

| Left by an earlier binary | A later one is unaffected because |
|---|---|
| Rows | Every test empties the database first |
| Identifiers past the last binary's | A test reads the identifiers it made and assumes no sequence start |
| A schema a test changed: a table renamed, an earlier release applied | The test restores the schema when it ends |

| A kept database | The harness |
|---|---|
| This build's schema, at the version its migrations end at | Uses it |
| This build's schema, at any other version or none | Drops and rebuilds it. A run killed mid-migration leaves one, and on MySQL and MariaDB a schema statement commits alone, so a part-applied migration has no version |
| Another schema, its slot held | Leaves it; that checkout is running |
| Another schema, its slot free | Drops it when creating a database for its own schema, under the clean's locks below. A drop the server refuses, a session still open or a role that may not drop, is reported and the lease stands, since the binary's own database is whole |

`make engines-clean` drops the harness's databases on every configured server
whose slot nobody holds, safely while other checkouts run.

| Step | Reason |
|---|---|
| Each database's locks are taken without waiting, on the clean's own connection | A held lock is a running binary, and its database is left |
| The locks are the database's name and that name without its last part | The second is the slot lock of an older harness that named a database for its package, slot and schema |
| The database is dropped while the locks are held, and they are released after | A binary starting meanwhile takes another slot |
| A database whose name is no slot's is dropped | No binary takes its locks |

## Measurement databases

A measurement binary, selected by the `measure` build tag, empties a server
database by truncating every table, so a measurement times plans chosen over
tables laid out as a load into a newly migrated database leaves them, the layout
closest to a deployment's.

| Engine | A table loaded again after a delete | Emptied for a measurement |
|---|---|---|
| PostgreSQL | Fills the deleted rows' space wherever it sits: more pages, and an order identifiers no longer follow | One `TRUNCATE` naming every table |
| MySQL, MariaDB | The clustered index takes a page count varying with how far the server purged the deleted rows | `TRUNCATE TABLE` per table, foreign key checks suspended on that connection and restored before it returns to the pool |
| SQLite | Not reached: each test copies a migrated file | The ordinary way |

| Rule | Reason |
|---|---|
| Truncation is for measurements alone | 96 ms on PostgreSQL, 232 ms on MySQL and 47 ms on MariaDB for an empty database, against 1 to 4 ms for the ordinary emptying run before every test |
| Every table is truncated, whether or not it holds rows | Slot databases are shared, so another package's binary may have filled and deleted one |
| The `finding` table's layout is printed beside the timings | Runs reading different layouts are different measurements. A plan taking 32 to 104 s was chosen over a newly built database in four runs of four and over a reused one in none of six |
| A table with no statistics is refused | No pages and no correlation read as an empty table |

| Engine | Printed with refreshed statistics |
|---|---|
| PostgreSQL | The table's pages, and the correlation of every column leading an index |
| MySQL, MariaDB | The clustered index's pages; InnoDB keeps rows in primary key order, so there is no correlation |
| SQLite | Nothing: no earlier test's layout reaches a copied file |

`design-docs/build-measurements.md` § Measurement databases has the layouts.

## The race pass

The race detector runs on SQLite alone, because a data race does not vary by
engine and the detector's cost is in-process work, most of what SQLite spends.
The detector is a property of the binary, so `test-all` is two runs: SQLite with
it, the three servers without.

| Rule | Reason |
|---|---|
| The two runs go at once, each on half the cores | They share no engine, and one is bound in-process while the other waits on sockets. 119 s and 3.4 GB in sequence, 100 s and 1.5 GB together |
| Each run labels its own lines as it prints | Held to the end, a slow run looks stopped; interleaved unlabeled, nobody can tell which said what |
| A failure in either fails the target | Checked by breaking one run at a time |
| The race binary sleeps 100 ms before exiting | The default second, kept for a goroutine to report, is paid by every binary: 1.02 s against 0.015 s for a quick package. Nothing leaves a goroutine running on purpose |
| The SQLite engine's translated C and its C library are compiled without the detector and its pointer checks, and nothing else is | Instrumenting them is most of the cost: an empty test is 57 ms against 4.4 ms. This tree, the engine's Go driver, the query builder and the standard database layer stay instrumented |
| The engine's Go driver stays instrumented | An error it fills uninstrumented leaves no record of the write, and this tree reading it reports a race that is not there |
| A race inside the engine's translated C or its C library is not reported | It is the one code the pass does not inspect |
| A test races this tree's code against the standard database layer and expects the report | Leaving out more silences it, and the test fails |
| The compiler flags turning the detector off per package are undocumented | A Go release rejecting one fails the build loudly, and the patterns are respelled or removed |

`design-docs/build-measurements.md` § The race pass has every configuration.

## Engine selection

`OPENPSIRT_TEST_ENGINES` narrows which engines a run touches, and `test` and
`test-race` set it to `sqlite`.

| Rule | Reason |
|---|---|
| The pool's idle reaper, the migration lock and the version floor read it, though they open connections themselves | A copy of the rule that ignores the variable opens three servers in the quick loop, failing on a stopped container in a way that reads as a regression |
| The rule lives in one package below both the harness and the migration runner | The migration lock's test is internal to the runner, which the harness depends on, so it cannot reach a rule held in the harness |

## Commit durability

A test database is created by the harness and dropped by a later run, and a
crash is answered by running the suite again, so commit durability protects
nothing here and is most of a run's cost.

| Engine | Setting | Asked for |
|---|---|---|
| SQLite | `synchronous` off | A pragma on every test connection the harness opens, the racing handle included |
| PostgreSQL | `synchronous_commit` off | The connection string, so the session gets it and the server is untouched |
| MySQL, MariaDB | `innodb_flush_log_at_trx_commit` and `sync_binlog` zero | The server's command line for the containers `make engines-up` starts; and the server, once per engine per binary, where `OPENPSIRT_TEST_RELAX_DURABILITY` is 1. Both are global, so the change outlives the run for every database on the server |

| Rule | Reason |
|---|---|
| A server's globals change only where it is declared a throwaway | `make engines-up` writes `OPENPSIRT_TEST_RELAX_DURABILITY ?= 1` into the `local.mk` it creates, and CI sets it beside its URLs. A server of somebody's own keeps its durability, and the test pinning the settings skips there |
| Nothing a test observes changes | The settings govern what survives a crash, never what a statement returns, what a transaction sees, or which constraint holds |
| The harness asks from the connection, as well as the command line | The command line reaches settings an engine accepts only at startup, but a workflow's service container has no command line to pass. Relaxed, the three servers' packages take 77 s against 240 s on a workstation; a GitHub runner's server pass does not move, 412 s against 413 s |
| A server `make engines-up` starts keeps its data directory in memory | A schema change syncs its files whatever the settings: 0.83 s against 9.8 s to build the schema on MySQL. CI services keep theirs on disk, which pays little, since the suite runs in the runner's memory |
| A container stopped and started again has lost its databases, and the harness migrates new ones | |
| A test reads the setting back from its session and fails where it is durable on a connection that could have changed it | It tells a harness that stopped asking from a server nobody may configure. A connection that may not set a global leaves the server as it is, and the suite runs slower |

`design-docs/build-measurements.md` § Commit durability has the timings.

## Limits

| Limit | Detail |
|---|---|
| A test database is named for its schema and slot, never its package or checkout | A name carrying the checkout outlives it: one workstation of short-lived worktrees reached about 750 databases and 55,000 tables per MySQL and MariaDB server, slowing every information-schema question |
| A test killed part way through changing the schema leaves it changed | The version still matches, so the next binary uses the database and its first test fails on the missing table. `make engines-clean` drops it |
| Checkouts of two schemas running at once drop each other's free databases | Only a binary creating a database drops another schema's, so each drop costs the other checkout one build |
| The clean trusts the slot lock alone | A database used without its slot's lock, one made by hand or by a harness naming databases another way, is dropped in use |
| A check needing a running server refuses rather than skips | A skipped test passes, and "the suite is green" differs from "the suite ran" |
