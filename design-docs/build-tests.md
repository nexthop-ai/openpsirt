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

The suite runs on SQLite alone unless pointed at servers, and a skipped engine
passes. `make engines-up` starts the servers, waits until each answers, and
writes their URLs to the git-ignored `local.mk`, which the makefile includes.

| Rule | Reason |
|---|---|
| Each server is asked with its own client, in its own container | "Up" is not answering, and no host client is assumed |
| Each listens on loopback alone | They carry the password `test` |
| `local.mk` is never overwritten | It may point at an operator's own servers |
| Starting is idempotent: a running engine is left, a stopped container started | |
| Images are pinned by tag and digest, compared against CI's in both directions by CI, and `pins-check` refuses a workflow service named by tag alone | A local pass means CI's only on the same servers. Dependabot reads no workflow service, so both lists move by hand |
| One server is below the supported version floor | The old-server refusal is exercised |
| The URLs are read when make starts | The run writing `local.mk` is not the run using it |

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
| The three servers | Once per binary, in its first test, after emptying | The rows the seed wrote, read back after it ran and written again after emptying, in one transaction |

| Rule | Reason |
|---|---|
| A test reads what the seed returns and never writes to it | It is one value shared by every test, and on SQLite by parallel tests |
| Rows are written back with the identifiers they were read with | What the seed returned names them. Emptying leaves every engine's identifier counter past them, so a row a test adds takes a new one |
| A table's rows are written back in identifier order, parents' tables first | A row referencing its own table follows the row it references |
| A measurement runs the seed per test | Truncating starts a table's identifiers again on MySQL and MariaDB, under the identifiers kept |
| A test holds every column of a written-back row to what the seed wrote: a moment to the microsecond, a date, both booleans, an absent value, text outside ASCII | A value the driver reads in one form and writes in another changes a seeded row on one engine only |
| The API package's seed is written back, never run, after its first test | About a hundred transactions: 157 ms a test on PostgreSQL and 71 ms on MySQL |
| The API package's fixture is a seeded template | Two products, eighteen people, their decisions and grants: per test it was 27% of the package's processor time under the detector |

A test needing a product, its branches and tags, its variants and a build takes
them from one shared default world, seeded per test or into a template. A test
needing a second product declares it on that world.

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
| The two runs go at once on half the cores each | One is in-process, the other waits on sockets: 100 s and 1.5 GB against 119 s and 3.4 GB in sequence |
| Each run labels its lines as it prints | Held, a slow run looks stopped; unlabeled, nobody knows which failed |
| A failure in either fails the target | Checked by breaking each |
| The race binary sleeps 100 ms before exiting | The default second is paid per binary, the better part of a minute across the tree where the pass runs one package at a time |
| The SQLite engine's translated C and its C library are built without the detector and its pointer checks, and nothing else is | They are most of the cost: an empty test takes 57 ms against 4.4 ms |
| The engine's Go driver stays instrumented | Uninstrumented, an error it fills reports a false race |
| A race inside the translated C or its C library is not reported | |
| A test races this tree against the standard database layer and expects the report | Excluding more silences it |
| The per-package compiler flags are undocumented | A Go release rejecting one fails the build loudly |

`design-docs/build-measurements.md` § The race pass has every configuration.

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
| The harness asks from the connection | It reaches a workflow's service container, which takes no command line. Relaxed, the server packages take 77 s against 240 s on a workstation; a GitHub runner's pass does not move |
| `make engines-up` also passes the same intent on the server's command line at startup | It reaches settings an engine accepts only there |
| A server `make engines-up` starts keeps its data directory in memory | A schema change syncs its files whatever the settings: 0.83 s against 9.8 s on MySQL |
| CI services keep their data on disk | A runner's memory is what the suite runs in, and its disk pays little for a schema change |
| A restarted container has lost its databases, and the harness migrates new ones | |
| A test reads the setting back and fails where it is durable on a connection that could change it | It separates a harness that stopped asking from a server nobody may configure, which runs slower |

`design-docs/build-measurements.md` § Commit durability has the timings.

## Limits

| Limit | Detail |
|---|---|
| A test database is named for schema and slot alone | A checkout in the name outlives it: one workstation reached about 750 databases and 55,000 tables per MySQL and MariaDB server |
| A test killed while changing the schema leaves it changed | The version still matches, so the next binary fails on the missing table until `make engines-clean` |
| Checkouts of two schemas running at once drop each other's free databases | Each drop costs the other one build |
| The clean trusts the slot lock alone | A database used without its lock is dropped in use |
| A check needing a running server refuses, never skips | A skip passes |
