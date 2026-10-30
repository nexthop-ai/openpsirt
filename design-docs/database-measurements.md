# Database measurements

Benchmark runs behind the database rules. Each rule states its number beside
it and points here for the run.

## Contents

- [Statement preparation modes](#statement-preparation-modes)
- [Bulk insert statements](#bulk-insert-statements)
- [The v0.11.0 upgrade](#the-v0110-upgrade)
- [Index reads](#index-reads)

## Statement preparation modes

Each mode the PostgreSQL driver offers, on PostgreSQL 16 with one processor
over a 1 ms, 100 Mbit link, on the bench planning an upgrade over a kernel at
291,500 occurrences. `design-docs/database.md` § Statement preparation holds
the rule.

| Mode | Results | Kept per connection after the plan | The plan | Trend | Findings list | Home, all at once |
|---|---|---|---|---|---|---|
| Prepare and keep the last 512 | Binary | 2,957 MB in the server | — | — | — | — |
| Prepare and keep the last 16 | Binary | 88 MB in the server | 17.1 to 21.9 s | 0.14 s | 0.16 s | 0.99 s |
| Keep the last 512 descriptions | Binary | 87 MB in the driver | 20.3 to 23.4 s | 0.14 s | 0.11 s | 1.05 s |
| Describe, then run | Binary | 3 MB in the server | 20.4 to 22.1 s | 0.15 s | 0.13 s | 1.05 s |
| Run without a description | Text | 3 MB in the server | 20.2 to 21.6 s | 0.16 s | 0.11 s | 1.02 s |

Planning over the measurement fixture's kernel takes 9.8 s run without a
description and 10.0 s described first.

## Bulk insert statements

Writing the 291,500 decision occurrences of one upgrade plan, on PostgreSQL 16
with one processor over a 1 ms, 100 Mbit link.
`design-docs/database-queries.md` § Bulk inserts holds the rule.

| Statements | A row |
|---|---|
| A list of rows, prepared and kept, identifiers read back | 93 µs |
| A list of rows, described, identifiers read back | 66 to 82 µs |
| A list of rows, described, nothing read back | 55 µs |
| Arrays, nothing read back | 42 to 43 µs |
| Arrays, on the table without its four foreign keys | 17 to 20 µs |

## The v0.11.0 upgrade

Each phase at 1,000 and at 1,000,000 rows a table, each database holding the
same 1,000 rows to rewrite. `design-docs/database-upgrades.md` § The v0.11.0
upgrade holds the rules.

| Engine | Renames | Stored values | Changes | Whole upgrade |
|---|---|---|---|---|
| PostgreSQL | 138 ms, 153 ms | 21 ms, 131 ms | 0.23 s, 2.3 s | 0.40 s, 2.6 s |
| MySQL | 765 ms, 823 ms | 18 ms, 687 ms | 0.39 s, 4.9 s | 1.2 s, 6.4 s |
| MariaDB | 141 ms, 263 ms | 14 ms, 566 ms | 0.08 s, 5.4 s | 0.24 s, 6.2 s |
| SQLite | 214 ms, 3.5 s | 5 ms, 179 ms | 0.03 s, 3.8 s | 0.25 s, 8.4 s |

A notification link matched by its prefix, `/decisions/`, over a million
notifications, timed alone: 734 ms on MySQL, 575 ms on MariaDB, 114 ms on
PostgreSQL.

## Index reads

PostgreSQL 16 with one processor, one database at a time, unless an engine is
named. `design-docs/database-schema.md` § Indexes holds the rules.

| Index | Read | Without | With |
|---|---|---|---|
| Grouping, the last two columns | The trend grouped in the database over 375,843 findings | 16,500 pages, 172 ms, 4.2 MB index | 578 pages, 88 ms, 4.6 MB index |
| Who is being told | 152,859 open conditions over 204 people, the kind holding every row | MySQL 106 ms, MariaDB 22 ms, SQLite 36 ms | MySQL 15 ms, MariaDB 17 ms, SQLite 12 ms |
| Who is being told | A read averaged over every kind, PostgreSQL | 46 ms | 0.33 ms |
| Who is being told | All 28 kinds once, MySQL | 2.9 s | 18 ms |
