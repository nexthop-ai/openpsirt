# Findings measurements

Benchmark runs behind the findings rules. Each section names the rule it
justifies. `make measure` re-runs the harness-driven ones.

## Contents

- [Fan-out cost](#fan-out-cost)
- [Interval storage](#interval-storage)
- [Decision state reads](#decision-state-reads)
- [Two-level grouping](#two-level-grouping)
- [Across products](#across-products)
- [A planned kernel](#a-planned-kernel)
- [Component and upgrade views](#component-and-upgrade-views)
- [A year of nightly scans](#a-year-of-nightly-scans)
- [Replaced inventory check](#replaced-inventory-check)
- [Remediation beside a check](#remediation-beside-a-check)
- [Time to fix from publication](#time-to-fix-from-publication)

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

## A planned kernel

Justifies `design-docs/findings-queries.md` § Decision state filters and
`design-docs/database.md` § PostgreSQL session settings. The across-products
fixture with an upgrade planned over the kernel's 6,000 issues: 204,000 decision
occurrences, the kernel build's list over 6,260 groups, after planner
statistics are refreshed. Each range is two runs, alternated.

| The kernel build's list | SQLite | PostgreSQL | MySQL | MariaDB |
|---|---|---|---|---|
| No filter | 0.13 s to 0.15 s | 0.23 s to 0.25 s | 0.31 s to 0.34 s | 0.13 s |
| Undecided | 1.3 s to 1.5 s | 0.51 s to 0.75 s | 2.7 s to 2.9 s | 1.0 s to 1.2 s |
| Agreed | 1.9 s to 2.1 s | 0.73 s to 0.90 s | 3.2 s to 3.5 s | 1.5 s to 2.1 s |
| Planned | 1.7 s to 1.9 s | 0.61 s to 0.77 s | 2.9 s to 3.1 s | 1.1 s to 1.6 s |
| Any decision filter, PostgreSQL's lookup cache on | — | none in 2 minutes | — | — |

The issue lists stated unindexed and stated on the column read the same within
these ranges on every engine, each list alone and both together.

| The demo's broadcom list, SQLite | Issue lists through the index | Unindexed |
|---|---|---|
| Undecided | 2.4 s to 2.5 s | 0.26 s to 0.29 s |
| Unplanned | 2.4 s to 2.5 s | 0.26 s to 0.29 s |
| Agreed | 2.6 s | 0.46 s to 0.47 s |

The demo holds 11,766 groups and 3,105 decision occurrences over 2,990 issues.
The population's list unindexed alone leaves agreed at 2.5 s; the decision
occurrences' alone leaves undecided at 2.4 s.

| Further readings | |
|---|---|
| PostgreSQL's cache | Keyed on the occurrence identity and sized for six rows a key, where the kernel's identity holds 6,000 issues |
| The decided side's population behind DISTINCT | PostgreSQL answered; MariaDB took 4 s to 6.8 s |
| No issue lists on the decided side | SQLite across products 0.47 s to 2.5 s; MySQL and MariaDB about 2 s |
| PostgreSQL's cache off over every measured read | A product's burndown 0.42 s against 0.36 s, and the kernel's by its name 0.59 s against 0.48 s; every other read the same within the host's variation, or faster: the across-products list, the component view and the review queue by about a third |

## Component and upgrade views

Justifies `design-docs/findings-queries.md` § Two-level grouping, the rows on
reading about a page's rows. The across-products fixture, a page of fifty from
each view in one product, after planner statistics are refreshed. Each range
is two runs, alternated; "before" joins every view statement to the kept
groups and reads a components page's upgrades and ratings apart.

| Components page | SQLite | PostgreSQL | MySQL | MariaDB |
|---|---|---|---|---|
| Undecided, before | 1.8 s | 33.5 s to 34.1 s | 4.0 s | 3.2 s to 3.3 s |
| Undecided | 1.2 s to 1.4 s | 0.95 s to 1.04 s | 2.9 s | 2.8 s |
| The list's defaults, before | 1.8 s to 1.9 s | 31.5 s to 33.6 s | 3.7 s to 4.0 s | 3.0 s to 3.1 s |
| The list's defaults | 1.2 s | 0.94 s to 1.04 s | 2.8 s | 2.7 s to 2.8 s |
| A fix known, before | 3.7 s | 1.1 s to 2.0 s | 4.0 s to 4.4 s | 1.9 s to 2.2 s |
| A fix known | 2.4 s to 2.5 s | 0.87 s to 0.99 s | 3.0 s | 2.1 s |

| Planned upgrades | SQLite | PostgreSQL | MySQL | MariaDB |
|---|---|---|---|---|
| Undecided, before | 1.6 s | 16.5 s to 17.8 s | 2.3 s to 2.6 s | 2.1 s to 2.3 s |
| Undecided | 1.2 s to 1.3 s | 1.06 s to 1.15 s | 2.2 s | 2.0 s |
| A fix known, before | 2.9 s to 3.0 s | 0.85 s to 1.0 s | 2.9 s to 3.5 s | 1.7 s to 2.2 s |
| A fix known | 2.9 s to 3.0 s | 0.93 s to 1.1 s | 3.0 s | 2.0 s to 2.3 s |

Every filter needing a decision answers in under 50 ms on every engine either way.

| Further readings | |
|---|---|
| PostgreSQL, before | The page itself 0.6 s; each read about its rows 15.3 s to 17.0 s, a kernel component's 103,069 rows walked for each of 11,891 kept groups |
| One-level kept groups keyed fold first | SQLite's components page under a fix known 2.2 s against 3.6 s; PostgreSQL's planned upgrades 1.27 s to 1.42 s against 0.93 s to 1.10 s |
| The demo's planned-upgrade page under undecided, SQLite through the server's driver | 1.37 s joined with the kept groups read first, 1.04 s with the page's rows outermost; 11,766 groups and 3,105 decision occurrences |
| The demo's broadcom components page, SQLite through the server's driver | Under the list's defaults 2.17 s against 1.84 s with the upgrades and ratings read once; the same rows and totals in both, under every filter |

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

## Replaced inventory check

Justifies running the check as one transaction per replaced inventory
(`design-docs/findings-closure.md` § Replaced inventories). Model: the
full-size switch image, 6,866 components; the replacement moves every
hundredth package and the kernel, 69 components; every package of the
replaced inventory reported against one issue published while it was current.
The scanner's own run is left out.

| Engine | Both inventories read | The check | Reports dated | Findings recorded |
|---|---:|---:|---:|---:|
| SQLite | 63 ms | 760 ms | 6,843 | 132 |
| PostgreSQL | 85 ms | 1.04 s | 6,843 | 132 |
| MySQL | 52 ms | 812 ms | 6,843 | 132 |
| MariaDB | 42 ms | 1.43 s | 6,843 | 132 |

| Reading | Detail |
|---|---|
| Single samples | An order of magnitude, as elsewhere here |
| The check is a scan's apply twice over | Both inventories are fanned out over every occurrence, then compared |
| The scanner's run dominates | A scan of the image takes minutes; the check's writes are a second |

## Remediation beside a check

Justifies reading the check's matches as one set in the remediation figures
(`design-docs/analytics-program.md` § Remediation metrics). Model: the
replaced inventory check above, then a run opening fifteen issues at every
component, a third of them closed by a later run as upgraded: 103,095
findings. Median of five reads of one product's figures over all time.

| Engine | No check match counted | Asked of each row | One set |
|---|---:|---:|---:|
| SQLite | 360 ms | 385 ms | 374 ms |
| PostgreSQL | 102 ms | 1,685 ms | 170 ms |
| MySQL | | | 161 ms |
| MariaDB | | | 216 ms |

| Reading | Detail |
|---|---|
| Asked of each row | Two correlated EXISTS per row raise PostgreSQL's estimate past its default `jit_above_cost`, and each statement spends over a second compiling |
| One set | An uncorrelated lookup prices each statement under the threshold |
| MySQL and MariaDB | Measured on the set alone |

## Time to fix from publication

Justifies working out the publication figure and the undated count in the
statement averaging the first-sighting figure (`design-docs/analytics-program.md`
§ Remediation metrics). Model: the full-size image, fifteen issues at every
component, ten of them fixed everywhere and five open, every other issue
dated: 102,645 findings. Median of five reads of one product's figures over
all time, two runs each.

| Engine | First sighting alone | With the publication figure |
|---|---:|---:|
| SQLite | 229 ms, 239 ms | 243 ms, 224 ms |
| PostgreSQL | 100 ms, 98 ms | 113 ms, 98 ms |

| Reading | Detail |
|---|---|
| The difference | Inside run-to-run noise: the date is one column of the issue row the statement already joins |
| MySQL and MariaDB | Not measured; SQLite and PostgreSQL show no cost |
