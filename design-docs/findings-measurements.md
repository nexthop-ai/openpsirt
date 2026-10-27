# Findings measurements

Benchmark runs behind the findings rules. Each section names the rule it
justifies. `make measure` re-runs the harness-driven ones.

## Contents

- [Fan-out cost](#fan-out-cost)
- [Interval storage](#interval-storage)
- [Decision state reads](#decision-state-reads)
- [Two-level grouping](#two-level-grouping)
- [Across products](#across-products)
- [A year of nightly scans](#a-year-of-nightly-scans)

## Fan-out cost

Justifies grouping in the database (`design-docs/findings-queries.md` § The page).
One real switch image, scanned live:

| | |
|---|---:|
| Components scanned | 8,523 |
| Distinct vulnerabilities | 5,652 |
| Components carrying one | 437 |
| Findings | 335,021 |
| …of which one kernel | 305,487 |

The kernel is 91%: 4,849 issues and 62 modules built against it. Grouped, the
image reads as 7,906 rows.

## Interval storage

Justifies batched updates (`design-docs/findings-closure.md` § Interval storage).
One image of 324,508 open findings, rescanned the day a likelihood feed moved
every issue: 651 statements of 500 rows, against 7,556 grouped by every value
including the order, and 324,508 a finding at a time.

As `make measure` takes it: 7,600 issues moved, each at three occurrences in the
scanned build and three in a tag; 367 statements against 23,074.

| Engine | A statement per issue | A statement per batch |
|---|---:|---:|
| SQLite | 2.7 s | 1.3 s |
| PostgreSQL | 6.7 to 7.8 s | 1.8 s |
| MySQL | 6 min 47 s | 2.3 s |
| MariaDB | 5 min 20 s | 1.9 s |

## Decision state reads

Justifies `design-docs/findings-queries.md` § Decision state filters. PostgreSQL
16, one CPU, 368,847 open occurrences, 133,549 decision occurrences, 59,762
lapsed.

| Statement | Equalities, joined to every occurrence | Ranges, decided groups stacked |
|---|---|---|
| Undecided, groups estimated (6,196 pass) | 1 | 837 |
| Undecided, the page's grouping | 1,149 ms | 635 ms |
| The lapsed tile's grouping, issues read first in 19 ms | 1,200 ms | 419 ms |
| The same, issues also on the decided side's occurrences | — | 2,726 ms |

| Further decision readings | |
|---|---|
| The decided side narrowed to decisions' issues | 133,549 decision occurrences naming 3,013 of 7,550 issues; a build's blocking list 403 ms against 523 ms; the issues read in 37 ms |
| Lapsed tile issues | 1,330 of 7,549 |
| A joined component beside the match | 1,570,516 rows read and discarded for 4,081 decided occurrences, with 3,673 decision occurrences and 737 components |
| Product totals as a lookup per occurrence | 2.1 s against 0.2 s joined, with 13 decision occurrences |
| Totals in a second statement | 0.9 s each with 133,549 decision occurrences; the page 2.0 s against 1.2 s in one |

On the full-size build (241,479 open rows, 7,329 groups) the page went from
2.0 s to 0.12 s, and undecided from 2.3 s to 0.18 s.

## Two-level grouping

Justifies `design-docs/findings-queries.md` § Two-level grouping. PostgreSQL 16,
one CPU, 375,843 finding rows in 10,255 open groups, server time:

| Statement | One level | Two levels |
|---|---|---|
| Findings list page | 258 ms | 66 ms |
| The same, by score | 186 ms | 97 ms |
| Across products | 395 ms | 101 ms |
| By component | 130 ms | 81 ms |
| Severity strip by component | 252 ms | 78 ms |
| Planned upgrades | 1,144 ms | 190 ms |

| Further grouping readings | |
|---|---|
| Holder counted in its own arm | 2.5 s against 1.3 s across products on MySQL with 127,704 of 425,680 held; 1.01 s against 0.26 s in one product on SQLite |
| Decided groups joined, across products, MariaDB | 0.37 s joined to every occurrence, 0.23 s stacked |
| One-level kept groups | Estimated 186 where 7,742 are kept; one level hashes the join in 2 s |
| Decision-condition view in one level, MariaDB | 2.6 s in two levels; none in three minutes for what is waiting; the components waiting gave none in three minutes joined |
| View restricted by membership | Estimated 279 where 1,753 pass; 215 s joined for components lapsed and fixable; MariaDB materializes the membership test once |
| Planned upgrade names joined | 690 occurrences a worker expected for 90,467, sorted on disk; over the kernel's 271,400 occurrences in two builds |

SQLite, 367,870 open rows: findings page 0.19 s to 0.10 s, planned upgrades 0.74 s
to 0.33 s, by component 0.10 s to 0.12 s.

## Across products

Justifies `design-docs/findings-queries.md` § Across products. 425,680 open rows
in two products, a kernel with 6,000 issues under 34 consumers, 3,060 decision
occurrences, one row per page, after planner statistics are refreshed (SQLite
findings-outermost without them).

| Undecided, first page and total | SQLite | PostgreSQL | MySQL | MariaDB |
|---|---|---|---|---|
| Decision occurrences outermost | 0.78 s | 0.57 s | 1.7 s | 0.78 s |
| Findings outermost | 331 s | 0.56 s | 1.7 s | 0.77 s |
| Inside one product | 1.3 s | 0.57 s | 1.2 s | 0.98 s |

Before a statistics refresh, servers plan fresh tables from one-row estimates,
and MySQL takes minutes however the statement is written.

## A year of nightly scans

Justifies the interval model's growth (`design-docs/findings-closure.md` §
Interval storage). A test asserts a rebuild changing nothing writes nothing.
Model: 700 components each in 34 containers (23,800
occurrences), 260 issues open at the start, 365 nightly rebuilds, 1% of
components changing version a night, three new matching issues a night.

| Over the year | Start | End |
|---|---:|---:|
| Findings | 8,840 | 148,614 |
| Edges | 23,834 | 110,466 |
| Nodes | 736 | 3,284 |

Growth is multiplicative in consumers: a moved component opens a node and 34
edges while the old ones stay as closed intervals.

| After a year | findings list | running out | trend |
|---|---:|---:|---:|
| SQLite | 27 ms | 72 ms | 419 ms |
| PostgreSQL | 24 ms | 75 ms | 136 ms |
| MySQL | 65 ms | 100 ms | 259 ms |
| MariaDB | 24 ms | 115 ms | 215 ms |

| A quiet night | average | worst | statements |
|---|---:|---:|---:|
| SQLite | 0.36 s | 0.61 s | 60 |
| PostgreSQL | 0.32 s | 0.54 s | 60 |
| MySQL | 0.34 s | 8.75 s | 60 |
| MariaDB | 0.32 s | 6.92 s | 60 |

The first night is 1,605 statements.

| Reading | Detail |
|---|---|
| Single samples are an order of magnitude | Two samples apart: MySQL's trend 1.19 s then 259 ms, MariaDB's list 212 ms then 24 ms. The growth is stable across both |
| The list holds up | It grew 1.5 to 3.5 times against the table's 16.8, indexed on build and closed |
| The trend grows about linearly | 18 ms to 394 ms on SQLite, 7 ms to 114 ms on PostgreSQL, 15 ms to 1.19 s on MySQL. It reads every interval overlapping the window; the first query to reshape if a front page is slow |
| A night costs the same on every engine | 60 statements, so per-statement cost differences do not decide it |

| After | receipts, first page | receipts, last page | release counts |
|---|---:|---:|---:|
| night 1 | 0–3 ms | 0–1 ms | 11–17 ms |
| night 365 | 3–4 ms | 2–3 ms | 71–88 ms |

Not measured: reads narrowed by product (run as an administrator), several
builds, and observed churn. The harness constants are the model.
