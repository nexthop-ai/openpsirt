# Analytics measurements

Benchmark runs behind the analytics rules.

## Contents

- [Grouping before the join](#grouping-before-the-join)
- [Planned upgrades page cost](#planned-upgrades-page-cost)

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
form and its measurement. `make measure` takes it over the form in force on every
engine.
