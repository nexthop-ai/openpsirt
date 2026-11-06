# Analytics measurements

Benchmark runs behind the analytics rules.

## Contents

- [Grouping before the join](#grouping-before-the-join)
- [Planned upgrades page cost](#planned-upgrades-page-cost)
- [Trend beneath a replaced version](#trend-beneath-a-replaced-version)
- [Daily trend](#daily-trend)
- [Burndown and component groups](#burndown-and-component-groups)

## Grouping before the join

The rule is in `design-docs/analytics.md` § Computed on demand. Measured on
367,577 open occurrences, PostgreSQL on one CPU, across 1 ms and 100 Mbit:

| Report | Grouped to | Grouped first, against joined first |
|---|---|---|
| Backlog trend | Issue, component, product, opening run, and the moments it opened and closed | Grouped on issue, product and the moments: 15,053 rows sent against 367,577; 0.25 s against 1.58 s |
| What each release holds | Build, issue and component | 0.17 s against 1.38 s |
| Release readiness, what a build holds | Issue and component | 0.09 s against 0.33 s |
| Release over release | Release, issue and component name | 24 tags, 453,336 open findings: 0.46 to 0.57 s on PostgreSQL and 0.85 to 0.92 s on MySQL 8.4, against 0.24 to 0.28 s and 0.20 to 0.31 s grouped on release and issue; grouping on the component's identifier first measured no faster |
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
switch image, every package carrying one issue and the kernel 4,943, in two
histories. One rescan: ten days after the first scan, the kernel and every
hundredth package at a new version, 32 components replaced. A year: 52 weekly
rescans, each moving two hundredths of the packages and every fourth the
kernel, 3,037 components replaced. A move fixes the issue on every second
package it moves and half of what is left on the kernel. Twelve weekly steps,
each figure the median of five reads after a warm one, each engine run alone.
"Small package" is a package a rescan moved that pulls in nothing, its issue
carried.

### One rescan

| Read, before and after | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| Trend beneath the kernel | 109 ms, 513 ms | 115 ms, 165 ms | 215 ms, 939 ms | 116 ms, 501 ms |
| The same rows asked for by the kernel's name, no walk | 400 ms | 229 ms | 625 ms | 403 ms |
| Trend beneath a parent of 4,867 children | 173 ms, 637 ms | 156 ms, 263 ms | 408 ms, 1,219 ms | 213 ms, 605 ms |
| Trend beneath the root | 190 ms, 660 ms | 152 ms, 263 ms | 407 ms, 1,122 ms | 236 ms, 567 ms |
| Trend beneath a small package | 0.5 ms, 7.8 ms | 108 ms, 118 ms | 0.6 ms, 11 ms | 0.8 ms, 11 ms |
| List beneath the kernel, first page | 105 ms, 111 ms | 109 ms, 124 ms | 383 ms, 455 ms | 254 ms, 288 ms |
| List beneath the parent | 161 ms, 173 ms | 106 ms, 118 ms | 323 ms, 275 ms | 225 ms, 214 ms |
| List beneath the root | 190 ms, 206 ms | 116 ms, 137 ms | 246 ms, 295 ms | 259 ms, 236 ms |
| List beneath a small package | 3.3 ms, 10 ms | 49 ms, 58 ms | 2.7 ms, 12 ms | 3.6 ms, 12 ms |
| The tree's step around the kernel | 162 ms, 168 ms | 93 ms, 103 ms | 191 ms, 221 ms | 83 ms, 89 ms |
| Reading the replaced components and their live namesakes | 7.7 ms | 7.9 ms | 11 ms | 8.9 ms |

### A year of weekly rescans

| Read, before and after | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| Trend beneath the kernel | 0.7 ms, 20 ms | 11 ms, 42 ms | 0.7 ms, 19 ms | 0.6 ms, 15 ms |
| The same rows asked for by the kernel's name, no walk | 77 ms | 42 ms | 37 ms | 32 ms |
| Trend beneath a parent of 4,867 children | 39 ms, 81 ms | 27 ms, 76 ms | 47 ms, 83 ms | 31 ms, 75 ms |
| Trend beneath the root | 53 ms, 107 ms | 34 ms, 131 ms | 55 ms, 77 ms | 41 ms, 84 ms |
| Trend beneath a small package | 0.6 ms, 19 ms | 12 ms, 34 ms | 0.6 ms, 18 ms | 0.6 ms, 15 ms |
| List beneath the kernel, first page | 5.4 ms, 27 ms | 21 ms, 44 ms | 3.4 ms, 21 ms | 4.2 ms, 17 ms |
| List beneath the parent | 52 ms, 81 ms | 53 ms, 88 ms | 70 ms, 95 ms | 48 ms, 75 ms |
| List beneath the root | 73 ms, 109 ms | 62 ms, 96 ms | 82 ms, 119 ms | 63 ms, 103 ms |
| List beneath a small package | 3.8 ms, 24 ms | 21 ms, 42 ms | 2.6 ms, 19 ms | 2.8 ms, 17 ms |
| The tree's step around the kernel | 41 ms, 60 ms | 41 ms, 57 ms | 35 ms, 55 ms | 22 ms, 39 ms |
| Reading the replaced components and their live namesakes, two reads | 14 ms | 11 ms | 14 ms | 12 ms |
| The same joined by name in one statement | 14 ms | 12 ms | 18 ms | 14 ms |

### Forms of the membership test

Findings beneath, counted, with the replaced components beneath named in each
form. The form in force unites them with the walk's answer in a derived table.

| Form, a year of rescans | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| United with the walk, beneath a small package | 0.5 ms | 18 ms | 0.3 ms | 0.2 ms |
| Two membership tests joined by OR, the same | 0.5 ms | 26 ms | 43 ms | 66 ms |
| Named in the walk's last step, the same | 0.1 ms | 17 ms | 1.7 ms | 1.8 ms |
| United with the walk, beneath the root | 57 ms | 50 ms | 68 ms | 75 ms |
| Named as a second start of the walk, the same | 62 ms | 174 ms | 63 ms | 75 ms |
| Two membership tests joined by OR, the same | 89 ms | 46 ms | 64 ms | 87 ms |

| Reading | Detail |
|---|---|
| The before figures are the wrong answer | One rescan: 0 open the week before the bump against 4,943, and none of the 2,472 it fixed resolved. A year: beneath the kernel 0 open eleven weeks back against 5 |
| The added cost beneath a large subtree is the rows | One rescan, the trend reads the replaced kernel's 4,943 issues beside the live one's 2,471; asking for the same rows by name costs 625 ms on MySQL 8.4 |
| The added cost beneath a small package is once per read | Reading the replaced components, walking for which sit beneath, and asking which hold a row the read keeps: 11 ms to 19 ms on every engine, against a statement under 1 ms |
| Two membership tests joined by OR | MySQL and MariaDB never make it a semi-join, and read every finding of the build: 43 ms and 66 ms beneath a small package |
| Replaced components named in the walk's last step | The count beneath a small package took 1.7 ms, the trend beneath it 127 ms on MySQL 8.4 and 118 ms on MariaDB |
| Replaced components named as a second start of the walk | The trend beneath the kernel took 1,161 ms on MySQL 8.4 after one rescan, and the list beneath the root 2,209 ms on PostgreSQL after a year |
| Replaced components named whatever rows they hold | MariaDB read each replaced kernel's findings on the index of the component alone, every closed row with it: the list beneath the kernel took 374 ms after a year, against 17 ms naming only those holding an open row |
| Replaced components joined to the live ones by name in one statement | 18 ms against 14 ms on MySQL 8.4 with one build; the join probes every component of a name in the deployment, so it grows with every build sharing it |

| Caveat | Detail |
|---|---|
| One build | Nothing else in the deployment shares a name |
| Each run settles its own statistics | A plan can differ between runs: MySQL 8.4 read the kernel's name in 469 ms on one run and 37 ms on another |

## Daily trend

Justifies `design-docs/analytics.md` § The period a report covers.
`design-docs/analytics-program.md` § Steps and windows holds the steps. A trend's cost is the
rows it reads, open at the window's start or moving in it, and the identity
reads beside them: which builds' first scans opened them and which issues were
present before the window. The number of steps is arithmetic over rows already
read. Each figure is the median of five reads after a warm one, each engine run
alone.

### The full-size image

The two histories of § Trend beneath a replaced version, the whole product's
trend.

| Window, one rescan | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| 12 weeks | 629 ms | 288 ms | 660 ms | 377 ms |
| 104 weeks | 650 ms | 286 ms | 620 ms | 380 ms |
| 30 days | 640 ms | 285 ms | 625 ms | 413 ms |
| 365 days | 638 ms | 275 ms | 600 ms | 497 ms |
| 730 days | 640 ms | 291 ms | 715 ms | 469 ms |

| Window, a year of weekly rescans | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| 12 weeks | 61 ms | 35 ms | 74 ms | 64 ms |
| 104 weeks | 1,352 ms | 397 ms | 1,041 ms | 696 ms |
| 30 days | 50 ms | 33 ms | 45 ms | 36 ms |
| 365 days | 1,258 ms | 366 ms | 916 ms | 694 ms |
| 730 days | 1,211 ms | 448 ms | 1,031 ms | 823 ms |

### Identity against the counts it replaced

Twelve weekly steps, the same history read by the trend that counted rows
opening and closing and by the one counting issues at components by identity.

| Read, rows counted, then by identity | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| One rescan, beneath the root | 902 ms, 1,449 ms | 333 ms, 405 ms | 1,733 ms, 1,797 ms | 766 ms, 729 ms |
| One rescan, beneath the kernel | 684 ms, 689 ms | 195 ms, 244 ms | 1,132 ms, 1,214 ms | 879 ms, 642 ms |
| A year, beneath the root | 139 ms, 143 ms | 127 ms, 142 ms | 111 ms, 151 ms | 118 ms, 162 ms |
| A year, the kernel by its name | 93 ms, 151 ms | 28 ms, 45 ms | 60 ms, 722 ms | 67 ms, 471 ms |

### A year of nightly scans

700 components under 34 consumers, 260 issues, 148,614 findings after 365
nights, read by somebody holding public and private reading. Each figure is
one read after a warm one.

| Window | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| 12 weeks | 309 ms | 97 ms | 163 ms | 116 ms |
| 52 weeks | 251 ms | 97 ms | 252 ms | 113 ms |
| 104 weeks | 326 ms | 98 ms | 236 ms | 185 ms |
| 30 days | 290 ms | 95 ms | 163 ms | 117 ms |
| 365 days | 256 ms | 96 ms | 183 ms | 122 ms |
| 730 days | 246 ms | 109 ms | 207 ms | 169 ms |

### Nightly removals

The full-size image, 60, 180 or 365 nightly uploads after the first scan, each
dropping one leaf package in 30 and restoring the previous night's, so every
night both removes and returns. A return is judged against the upload that
removed it.

| Window, 60 nights | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| 7 days | 136 ms | 101 ms | 241 ms | 123 ms |
| 30 days | 299 ms | 249 ms | 379 ms | 249 ms |
| 365 days | 408 ms | 412 ms | 623 ms | 332 ms |

| Nights, then window | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| 60, 30 days | 299 ms | 249 ms | 379 ms | 249 ms |
| 180, 30 days | 432 ms | 236 ms | | |
| 365, 30 days | 627 ms | 325 ms | 582 ms | 730 ms |
| 60, 365 days, 13,129 returns | 408 ms | 412 ms | 623 ms | 332 ms |
| 180, 365 days, 39,833 returns | 1,112 ms | 705 ms | | |
| 365, 365 days, 81,004 returns | 2,152 ms | 1,404 ms | 1,879 ms | 2,001 ms |

| Read on SQLite | 7 days | 30 days | 365 days |
|---|--:|--:|--:|
| Every removing upload the build ever received worked out | 731 ms | 2,473 ms | 2,636 ms |
| Only the uploads deciding a return, each build's in one comparison | 136 ms | 299 ms | 408 ms |
| No upload worked out | 86 ms | 143 ms | 188 ms |

| Reading | Detail |
|---|---|
| A window costs what it reaches, never its steps | 30 days against 12 weeks, and 730 days against 104 weeks, are within the noise on every engine |
| A long window over a moving history is the closed rows | A year of weekly rescans, 30 days read 62 movements in 33 ms on PostgreSQL and 365 days read 6,402 in 366 ms |
| The first scan is a baseline | One rescan, 11,751 issues the first scan brought in, which the row counts drew as 11,673 opened |
| The build grouped on doubles a product's trend on SQLite | 1,230 ms against 629 ms after one rescan, so it is read off the group, which the opening run decides |
| Present before costs most on SQLite | Beneath the root after one rescan, 11,751 issues entering in the window are asked about in batches: 547 ms more on SQLite, 72 ms more on PostgreSQL |
| Present before by a name costs most on MySQL and MariaDB | A year of rescans, the kernel by its name: 722 ms against 60 ms on MySQL 8.4, 471 ms against 67 ms on MariaDB, and 45 ms on PostgreSQL |
| Working out a sharp upload costs the uploads a return reverses | Nightly removals, 30 days: 299 ms on SQLite, against 2,473 ms working out every removing upload and 143 ms working out none |
| A build that removes nightly costs more as it ages | Every past closure of a returning component is read: 30 days on SQLite take 299, 432 and 627 ms after 60, 180 and 365 nights; a 365-day window also holds six times the returns |

| Caveat | Detail |
|---|---|
| One build | Nothing else in the deployment shares a name or a first scan |
| One issue per package | The issue and the issue at a component count alike here, so the counts above hold for either unit |
| Every engine was read keyed by issue and component | The key added a group column and a join to the component; the SQLite and PostgreSQL columns of the first three tables were read before sharp uploads were worked out only for returns, which changes nothing in histories that remove no component |
| Each engine ran alone | Other test runs on the machine were waited out first |
| Nightly removals at 180 nights were read on SQLite and PostgreSQL only | The blank cells were not measured |

## Burndown and component groups

Justifies `design-docs/analytics-program.md` § Burndown and
`design-docs/findings-queries.md` § Component groups. The full-size image with
thirteen weeks of history: a first scan of one issue per package and the
kernel's 4,942, twelve weekly rescans each dropping a hundredth of the packages'
issues and a third of the kernel's at the sixth, a few brought back at the last,
and 50 dismissals agreed four weeks back. Thirty source repositories are hung in
pulled in by nothing, each over one of the root's 30 children, beside the 15 the
image names. Each figure is the median of five reads after a warm one, each
engine run alone.

| Burndown, from the first scan | SQLite | PostgreSQL |
|---|--:|--:|
| The product | 860 ms | 266 ms |
| The product, high and worse | 823 ms | 224 ms |
| The kernel by its name | 621 ms | 358 ms |
| `pkg:deb/` as a prefix | 1,189 ms | 261 ms |
| Beneath the root | 1,512 ms | 374 ms |
| Beneath the kernel | 600 ms | 258 ms |

| Component groups | SQLite | PostgreSQL |
|---|--:|--:|
| By repository, 45 rows | 515 ms | 310 ms |
| By ecosystem, 9 rows | 446 ms | 279 ms |
| The 758 deb packages | 387 ms | 160 ms |

| Reading | Detail |
|---|---|
| A burndown costs what the trend's identity reads cost, plus the dismissals | 9,227 issues at components left over 92 days in 266 ms on PostgreSQL |
| A prefix costs a read of the whole selection on SQLite | It is tested on the rows read, so `pkg:deb/` reads every row: 1,189 ms against 860 for the product |
| Beneath the root is the dearest read on both engines | 1,512 ms on SQLite and 374 ms on PostgreSQL, the walk added to the product's read |
| A repository row costs its walk | 45 repositories reaching the whole image in 310 ms on PostgreSQL |
| MySQL 8.4 and MariaDB were not measured | Neither PostgreSQL nor SQLite showed a read past two seconds |

| Caveat | Detail |
|---|---|
| Closures here are unexplained | No rescan moves a version, so nothing counts as fixed; the rows read are the same either way |
| One build | The image's repositories reach every top-level component, the widest walk a repository row takes |
| Seeding took 28 minutes per engine | The history is built by applying each scan in turn |

