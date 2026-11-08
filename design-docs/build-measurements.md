# Build measurements

Benchmark runs behind the CI cache, test database, race pass, commit
durability, seeded start, migration test, gate build and other gate work
rules.

## Contents

- [CI caches](#ci-caches)
- [Server database slots](#server-database-slots)
- [The race pass](#the-race-pass)
- [Measurement databases](#measurement-databases)
- [Commit durability](#commit-durability)
- [Seeded test starts](#seeded-test-starts)
- [Migration tests](#migration-tests)
- [Test bodies](#test-bodies)
- [Suite totals](#suite-totals)
- [Gate build work](#gate-build-work)
- [Gate work outside the tests](#gate-work-outside-the-tests)

## CI caches

Rules in `design-docs/build.md` § CI caches.

A fresh Go build cache for this tree is 2.1 GB, 470 MB as stored; the race
flavor is 640 MB of it and the tools 840 MB. Go trims an entry only after five
days unused. Marking and deleting the unread entries take under five seconds;
emptying the cache and building again costs 150 s on four cores for the test
binaries alone.

| | Saved as the run left it | Saved holding what the run read |
|---|---|---|
| Go build cache, as stored | 2.87 GB | 683 MB |
| Its restore | 55 to 71 s | 11 s |
| Its save | 38 to 47 s | 7 to 10 s |
| The linter, no results / results for the same tree | 74 to 75 s | 1.4 s |

The linter's results are 0.7 MB as stored; on four local cores one changed file
costs 9 to 12 s against 42 s with no results. With the Go build cache inside the
image layers, the compile step's layer was 441 MB and the bill-of-materials
step's 499 MB per commit, and each run exported about 420 MB of blobs no later
run read; mounted, the same steps are 39 MB and 131 kB, the binary and the
document.

## Server database slots

Rules in `design-docs/build-tests.md` § Server database slots. Each engine alone,
four cores, a container started for the run on its own disk, as CI starts one.
A pass running two binaries at once builds two databases per engine; a database
per package built 33 or 34.

| Server pass, fresh containers, two binaries at once | A database per package | A database per slot |
|---|---|---|
| PostgreSQL, processor time, test binaries and server | 211 s | 188 s |
| MySQL, the same | 154 s | 103 s |
| MariaDB, the same | 97 s | 79 s |
| PostgreSQL, wall time | 230 s | 123 s |
| MySQL, wall time | 403 s | 151 s |
| MariaDB, wall time | 308 s | 132 s |

## The race pass

Rules in `design-docs/build-tests.md` § The race pass.

| `internal/httpapi`, one engine | With the detector | Without |
|---|---|---|
| SQLite | 73.6 s | 10.1 s |
| PostgreSQL | 59.6 s | 33.5 s |
| MySQL | 18.5 s | 12.0 s |
| MariaDB | 16.9 s | 12.0 s |

The default one-second exit sleep costs 1.02 s against 0.015 s for a package
whose tests take milliseconds, the better part of a minute across the tree on a
runner running the pass one package at a time.

An empty test spends 57 ms under the detector against 4.4 ms without, 48% of it
in the engine parsing the schema and 16 to 22% in the pointer checks.

| The race pass, every package, four cores | Processor time | Wall time | Races reported |
|---|---|---|---|
| Every package instrumented | 481 s | 123 s | None |
| Pointer checks off in the engine's packages | 316 s | 81 s | None |
| The translated engine left out | 235 s | 62 s | None |
| The translated engine and its C library left out | 186 s | 49 s | None |
| Every package of the engine left out, its Go driver included | 180 s | 57 s | False, in 3 of 10 runs of one package |

The allocator under the C library is the same kind of translated support, and
leaving it out too was measured on a later tree:

| The race pass, every package, four cores, two packages at once | Processor time | Wall time | Races reported |
|---|---|---|---|
| The translated engine and its C library left out | 367 s | 146 s | None |
| The same and the library's allocator | 349 s | 137 s | None |

Run with the server pass on twelve cores, everything warm: 119 s and 3.4 GB peak
one after another, 100 s and 1.5 GB together.

## Measurement databases

Rules in `design-docs/build-tests.md` § Measurement databases. The `finding`
table after two measurements, each run twice over a reused slot database and
twice with truncation, one engine at a time:

| Measurement, engine | Deleted, then reloaded | Truncated, then reloaded | A newly built database |
|---|---|---|---|
| The list across products, PostgreSQL | 20,900 pages, correlation of `id` −0.38 and of `vulnerability_id` −0.32; then 12,697 pages, 1.00 and 0.68 | 12,697 pages, 1.00 and 0.68, then 0.67 | Correlation 1.00 and 0.67 |
| A planned upgrades page, PostgreSQL | 20,900 and 18,867 pages | 6,169 and 6,170 pages | — |
| A planned upgrades page, MySQL | 3,078 and 3,014 pages, 30.6 s and 31.4 s | 2,854 pages, 14.5 s, both runs | 2,854 pages, 15.1 s |
| A planned upgrades page, MariaDB | 2,886 and 2,823 pages, 25.0 s and 24.7 s | 2,854 pages, 11.3 s and 10.6 s | 2,854 pages, 11.3 s |
| The list across products, MySQL and MariaDB | 5,802 pages, and once 5,834 on MariaDB | 5,802 pages | — |

| Reading | Detail |
|---|---|
| The deleted runs on PostgreSQL disagree with each other | Autovacuum decides when deleted space becomes free, a race with the next load |
| The plan moves with the layout | In the list across products, a plan taking 32 to 104 s was chosen over a newly built database in four runs of four and over a reused one in none of six |

## Commit durability

Rules in `design-docs/build-tests.md` § Commit durability.

| Every package, one engine, a workstation | Durable | Relaxed |
|---|---|---|
| PostgreSQL | 90 s | 60 s |
| MySQL | 59 s | 12 s |
| MariaDB | 19 s | 12 s |
| The three together | 240 s | 77 s |

The saving belongs to the storage underneath. The servers a GitHub runner starts
pay little enough that the whole server pass does not move: 412 s against 413 s,
where two runs of one tree vary by 5 to 10 s on each large package.

| Building the schema, one database, a workstation | On disk | In memory | Server processor time, in memory |
|---|---|---|---|
| PostgreSQL | 0.43 s | 0.42 s | 0.37 s |
| MySQL | 9.8 s | 0.83 s | 1.38 s |
| MariaDB | 7.2 s | 0.18 s | 0.14 s |

The server pass over every package, six at once, went from 516 s to 246 s of
package time with the shared pool and the data in memory, where the 516 s reused
databases an earlier run migrated and the 246 s migrated every one.

## Seeded test starts

Rules in `design-docs/build-tests.md` § Undoing a test. The triage API, finding,
API and findings API packages, one engine at a time, a workstation shared with
other work, each binary's first test included:

| A test's start | Emptied and written back | Undone |
|---|---|---|
| PostgreSQL, mean | 28 to 34 ms | 6.9 to 7.6 ms |
| PostgreSQL, 90th percentile | 60 to 66 ms | 9.5 to 11 ms |
| PostgreSQL, the four packages' starts together | 33 to 41 s | 8.1 to 9.0 s |
| PostgreSQL, the four packages' wall time | 115 to 136 s | 88 to 90 s |
| MySQL, mean | 5.0 ms | 3.4 ms |
| MariaDB, mean | 4.9 ms | 4.1 ms |

Deleting from `person` alone was about 31 ms of a PostgreSQL start. In an
earlier run of the same packages, emptying with the foreign key triggers off
averaged 9.3 ms against 23 to 28 ms with them on; that setting needs a
superuser.

## Migration tests

Rules in `design-docs/database-upgrades.md`. The migrations package, one engine
at a time, the same workstation; two runs of the earlier tree:

| The migrations package | A build per test | One build per starting release | And fewer stops where a stop rolls back |
|---|---|---|---|
| SQLite | 10.5 to 15.9 s | 8.9 s | 5.5 s |
| SQLite under the race detector | 56 to 68 s | 37 s | 16 s, the allocator also uninstrumented |
| PostgreSQL | 37 to 51 s | 24 s | 22 s |
| MySQL | 68 to 92 s | 38 s | 39 s |
| MariaDB | 17 to 27 s | 12 s | 12 s |

Covered statements were the same on every engine with one build per starting
release. Fewer stops leaves three statements uncovered on PostgreSQL and SQLite,
each returning from a stop, all covered on MySQL and MariaDB.
## Test bodies

Rules in `design-docs/build-tests.md` § Test bodies. One test alone on a
workstation, before and after, except where a package is named.

| Test, engine | Before | After |
|---|---|---|
| The upward tree's bound, SQLite | 0.54 to 0.59 s | 0.04 s |
| The same, under the race detector | 2.12 to 2.27 s | 0.12 to 0.13 s |
| The graph package, PostgreSQL | 10.1 s | 4.2 s |
| The graph package, MySQL | 5.8 s | 1.8 s |
| The graph package, MariaDB | 3.3 s | 1.6 s |
| The queue ordered by the tool's rating, SQLite | 0.21 s | 0.09 s |
| The same, under the race detector | 0.90 s | 0.38 s |
| The same, PostgreSQL | 1.60 to 2.75 s | 0.44 to 0.46 s |
| The same, MySQL | 0.57 s | 0.15 s |
| The same, MariaDB | 0.56 s | 0.17 s |
| A stale database's refused drop, PostgreSQL | 5.99 s | 0.94 s |
| Interning a run against each report alone, twenty rounds and twelve, SQLite | 0.24 s | 0.18 to 0.19 s |
| The same, under the race detector | 1.01 to 1.02 s | 0.78 to 0.84 s |
| The same, PostgreSQL | 1.75 to 2.01 s | 1.33 to 1.54 s |
| The same, MySQL | 0.89 to 1.23 s | 0.62 to 0.89 s |
| The same, MariaDB | 0.96 to 1.19 s | 0.64 to 0.94 s |

The interning comparison's coverage counts the blocks of every package in the
module except the harness and the migrations, which only a run building its
database reaches.

| The test's seeds, three runs of each count | Blocks at twenty rounds | At twelve |
|---|---|---|
| SQLite | 838 | The same blocks |
| PostgreSQL | 844 | The same blocks |
| MySQL | 872 | The same blocks |
| MariaDB | 864 | The same blocks |

From four other sets of seeds, one run of each count, twelve rounds reach the
blocks twenty do on every engine, and no set reaches a block the test's seeds
do not.

Each check below, turned off, fails the comparison on every engine in a steady
round, so at any count of random rounds:

| Check | Steady round |
|---|---|
| A severity filling an issue's gap | An issue held with no severity, reported with one |
| An earlier day an issue was exploited | Exploited on a day, then reported exploited the day before |
| A held weakness newly named the root cause | A root cause named after the last one was unmarked |
| A marked root cause another report moves away | A root cause the issue holds no weakness for |

Turning off the check for a rating the issue holds lower fails the comparison
at twelve rounds and at eight, in the fifth random round; with no random rounds
it passes.

## Suite totals

The rules in `design-docs/build-tests.md` together bring the suite to one minute
fifteen against warm servers and two minutes forty-five against cold ones, from
four minutes four seconds.

## Gate build work

Rules in `design-docs/build.md` § Make targets, `design-docs/build.md` § Static
analysis, `design-docs/build-tests.md` § The race pass and
`design-docs/build-tests.md` § In-package test files. Twelve local cores, Go
1.27.3.

| Work | Before | After |
|---|---|---|
| `make build` over a build cache holding the plain build | 23.5 s wall, 97 s processor, 461 MB more cache | Not run; 13 s on a CI runner |
| `npm ci` in one `make check` | Twice, 4 s each; 7 to 8 s each on a CI runner | Once |
| The vet `go test` runs, per pass, after an exported change in a package most others import | 1.8 s wall, 11 s processor | None |
| Linking every test binary, one at a time | 55 s; 1.8 GB of binaries | 42 to 47 s; 1.4 GB |
| Linking the largest API test binary | 1.25 s wall, 1.65 s processor; 52 MB | 0.93 s, 1.10 s; 41 MB |
| The server pass over the packages reaching no database, cold build cache | 3.2 s wall, 10.8 s processor | Not run |
| The same, warm | 2.3 to 3.1 s wall, 7.4 s processor | Not run |
| Building the trail's test binary after an exported change in the findings package | 2.4 to 3.1 s wall, 5.8 s processor | 0.67 s, 0.85 s |
| `go list` of the module's packages in one `make check` | At every expansion, 0.35 to 0.45 s each | Once per make run |

## Gate work outside the tests

Rules in `design-docs/build.md` § CI jobs, `design-docs/build.md` § CI caches,
`design-docs/build.md` § Static analysis, `design-docs/build-tests.md`
§ Database engines and `design-docs/build-interface.md` § Interface tools.
Four cores of a workstation, Go 1.27.3, unless a row says CI.

| `make vet-other-os` | Every package on macOS, the upload client on Windows | The packages whose files differ, per system |
|---|---|---|
| Empty build cache | 63.9 s | 36.4 s |
| Nothing changed | 0.5 s | 1.2 s |
| After an exported change to a package most others import | 24.8 s | 5.5 s |
| Build cache it leaves | 1,428 MB | 529 MB |

The packages picked are the background-pass package on macOS, and that, the
settings package and the migration runner on Windows.

Vetting also every package importing `syscall` or `golang.org/x/sys`, to catch
a Linux-only call in a file with no constraint, took 57 s on macOS and 66 s on
Windows from an empty build cache: the program is among them, and vetting it
compiles nearly the whole tree for that system.

| Interface check, every source file's time moved | No cache | Cached by content |
|---|---|---|
| `tsc` | 10.7 to 11.3 s, `tsc -b` with its build information present included | 1.2 s |
| ESLint | 13.7 to 14.6 s | 0.7 s |
| Prettier | 3.9 to 4.6 s | 0.6 s |

The three caches are 115 kB, 194 kB and 113 kB.

| Database servers | Measured |
|---|---|
| CI's four service containers, started before the checkout, six runs on `main` | 29 to 51 s |
| `make engines-up`, images present, four at once, to all answering | 6 s |
| A fresh data directory: PostgreSQL, MySQL, MariaDB, the floor server | 46 MB, 190 MB, 162 MB, 47 MB |
| The same servers' memory | 100 MB, 641 MB, 290 MB, 86 MB |
| A workstation's after two weeks of runs | 349 MB, 1.6 GB, 1.6 GB, 47 MB of data; 472 MB, 2.8 GB, 2.5 GB, 16 MB of memory |
| A write past a 128 MB cap on PostgreSQL | Refused: no space left on device |

A module cache filled by every target of `make check` but the tests, and a
build of every test binary, held 1,839 MB, 453 MB of it downloaded archives.
With the archives deleted and the module proxy off, every target passed again
and no archive was fetched.
