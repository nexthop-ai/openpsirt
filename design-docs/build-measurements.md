# Build measurements

Benchmark runs behind the CI cache, test database, race pass and commit
durability rules.

## Contents

- [CI caches](#ci-caches)
- [Server database slots](#server-database-slots)
- [The race pass](#the-race-pass)
- [Measurement databases](#measurement-databases)
- [Commit durability](#commit-durability)
- [Suite totals](#suite-totals)

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

The linter's results are 0.7 MB as stored. With the Go build cache inside the
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

An empty test spends 57 ms under the detector against 4.4 ms without, 48% of it
in the engine parsing the schema and 16 to 22% in the pointer checks.

| The race pass, every package, four cores | Processor time | Wall time | Races reported |
|---|---|---|---|
| Every package instrumented | 481 s | 123 s | None |
| Pointer checks off in the engine's packages | 316 s | 81 s | None |
| The translated engine left out | 235 s | 62 s | None |
| The translated engine and its C library left out | 186 s | 49 s | None |
| Every package of the engine left out, its Go driver included | 180 s | 57 s | False, in 3 of 10 runs of one package |

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

## Suite totals

The rules in `design-docs/build-tests.md` together bring the suite to one minute
fifteen against warm servers and two minutes forty-five against cold ones, from
four minutes four seconds.
