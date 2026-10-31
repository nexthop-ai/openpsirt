# Analytics measurements

Benchmark runs behind the analytics rules.

## Contents

- [Grouping before the join](#grouping-before-the-join)
- [Planned upgrades page cost](#planned-upgrades-page-cost)
- [Trend beneath a replaced version](#trend-beneath-a-replaced-version)

## Grouping before the join

The rule is in `design-docs/analytics.md` § Computed on demand. Measured on
367,577 open occurrences, PostgreSQL on one CPU, across 1 ms and 100 Mbit:

| Report | Grouped to | Grouped first, against joined first |
|---|---|---|
| Backlog trend | Issue, product, and the moments it opened and closed | 15,053 rows sent against 367,577; 0.25 s against 1.58 s |
| What each release holds | Build, issue and component | 0.17 s against 1.38 s |
| Release readiness, what a build holds | Issue and component | 0.09 s against 0.33 s |
| Release over release | Release and issue | Not measured: the data holds no tags |
| Aging buckets | Issue and product, then issue, with a flag per bucket | One statement, 0.9 s, against three per bucket taking 2.1 s together, with 133,000 decision occurrences |

## Planned upgrades page cost

One build, 204,000 open findings, 136,000 naming a fixing version, folding to 700
bumps: a real switch image's two-thirds-fixable ratio at its order of open rows.
Grouped in one level, every open row on the fold directly:

| One level | Planned upgrades | The findings list, same rows |
|---|--:|--:|
| SQLite | 1.28 s | 0.19 s |
| PostgreSQL | 1.29 s | 0.43 s |
| MariaDB | 1.49 s | 0.52 s |
| MySQL | 1.56 s | 0.48 s |

The cost is the sort on the fold, a 64-character key, over every open row. The
planned upgrades group in two levels, by integers first and by the fold over the
partial groups; `design-docs/findings-queries.md` § Two-level grouping holds the
form and `design-docs/findings-measurements.md` § Two-level grouping its
measurement. `make measure` takes it over the form in force on every
engine.

## Trend beneath a replaced version

Justifies `design-docs/data-model-graph.md` § Path traversal. The full-size
switch image, every package carrying one issue and the kernel 4,943, rescanned
ten days later with the kernel and every hundredth package at a new version:
30 components replaced, half of what sat on them fixed. Twelve weekly steps,
one read after a warm one, each engine run alone.

| Read | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| Trend beneath the kernel, live version only | 111 ms | 116 ms | 233 ms | 114 ms |
| Trend beneath the kernel, replaced versions named | 490 ms | 146 ms | 238 ms | 202 ms |
| The same rows asked for by the kernel's name, no walk | 404 ms | 236 ms | 641 ms | 408 ms |
| Trend beneath a parent of 4,867 children, live only | 178 ms | 157 ms | 390 ms | 209 ms |
| The same, replaced versions named | 558 ms | 204 ms | 261 ms | 236 ms |
| The list beneath that parent, first page, before and after | 163 ms, 184 ms | 108 ms, 119 ms | 330 ms, 319 ms | 250 ms, 128 ms |
| The tree's step around the kernel, before and after | 166 ms, 172 ms | 93 ms, 98 ms | 295 ms, 242 ms | 98 ms, 101 ms |
| Reading the replaced components and their live namesakes | 0.2 ms | 1.4 ms | 0.5 ms | 0.6 ms |

| Reading | Detail |
|---|---|
| The live-only trend is the wrong answer | 0 open the week before the bump against 4,943, and none of the 2,472 it fixed resolved |
| The added cost is the rows | Named, the trend reads the replaced kernel's 4,943 issues beside the live one's 2,471; asking for the same rows by name costs as much or more |
| Matched by name inside the walk's statement | 1.72 s beneath the kernel and 1.36 s beneath the parent on MySQL 8.4, against 238 ms and 261 ms as values beside the walk |

| Caveat | Detail |
|---|---|
| Beneath the build's root is not in the table | Its walk is the one the tree's root read measures, which on MySQL outlasts the run at this size |
| One sample per figure | Five were taken; they agree within about ten percent |
