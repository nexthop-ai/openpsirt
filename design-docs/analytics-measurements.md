# Analytics measurements

Benchmark runs behind the analytics rules.

## Contents

- [Early grouping](#early-grouping)
- [Planned upgrades page cost](#planned-upgrades-page-cost)
- [Trend beneath a replaced version](#trend-beneath-a-replaced-version)
- [Daily trend](#daily-trend)
- [Burndown and component groups](#burndown-and-component-groups)
- [Export snapshots](#export-snapshots)
- [Counts by identifying name](#counts-by-identifying-name)
- [Many builds](#many-builds)
- [Many small builds](#many-small-builds)
- [Uploads of one build](#uploads-of-one-build)

## Early grouping

The rule is in `design-docs/analytics.md` § Computed on demand. Measured on
367,577 open occurrences, PostgreSQL on one CPU, across 1 ms and 100 Mbit:

| Report | Grouped to | Grouped first, against joined first |
|---|---|---|
| Backlog trend | Issue, component, product, opening run, and the moments it opened and closed | Grouped on issue, product and the moments: 15,053 rows sent against 367,577; 0.25 s against 1.58 s |
| What each release holds | Build, issue and component | 0.17 s against 1.38 s |
| Release readiness, what a build holds | Issue and component | 0.09 s against 0.33 s |
| Release over release | Release, issue and component's identifying name | 24 tags, 453,336 open findings: 0.46 to 0.57 s on PostgreSQL and 0.85 to 0.92 s on MySQL 8.4, against 0.24 to 0.28 s and 0.20 to 0.31 s grouped on release and issue; grouping on the component's identifier first measured no faster |
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
kernel's 4,942, and twelve weekly rescans. Each rescan takes a hundredth of the
packages' issues away, half of them by moving the package to a new version,
which fixes them and replaces the component; the sixth takes a third of the
kernel's, and the last brings a few back. 50 dismissals are agreed four weeks
back. Thirty source repositories are hung in pulled in by nothing, each over
one of the root's 30 children, beside the 15 the image names. Each figure is
the median of five reads after a warm one, each engine run alone.

| Burndown, from the first scan | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| The product | 1,086 ms | 397 ms | 1,031 ms | 511 ms |
| The product, high and worse | 1,064 ms | 282 ms | 764 ms | 397 ms |
| The kernel by its name | 861 ms | 473 ms | 1,799 ms | 1,265 ms |
| `pkg:deb/` as a prefix | 1,240 ms | 414 ms | 930 ms | 516 ms |
| Beneath the root | 1,970 ms | 832 ms | 1,358 ms | 730 ms |
| Beneath the kernel | 863 ms | 530 ms | 1,098 ms | 584 ms |

| Component groups | SQLite | PostgreSQL | MySQL 8.4 | MariaDB |
|---|--:|--:|--:|--:|
| By repository, 45 rows | 647 ms | 361 ms | 651 ms | 473 ms |
| By ecosystem, 9 rows | 542 ms | 275 ms | 490 ms | 401 ms |
| The 758 deb packages | 462 ms | 178 ms | 399 ms | 401 ms |

| Reading | Detail |
|---|---|
| A burndown costs what the trend's identity reads cost, plus the dismissals and the replaced components | 9,227 issues at components left over 92 days, 402 of them fixed, in 397 ms on PostgreSQL |
| A prefix costs a read of the whole selection | It is tested on the rows read, so `pkg:deb/` reads every row: 1,240 ms against 1,086 for the product on SQLite |
| Beneath the root is the dearest read on SQLite and PostgreSQL | The walk added to the product's read: 1,970 ms and 832 ms |
| The kernel by its name is the dearest read on MySQL and MariaDB | 1,799 ms and 1,265 ms: its 3,295 issues at one component are read through the name |
| A repository row costs its walk | 45 repositories reaching the whole image in 361 ms on PostgreSQL |

A repository shipped at several commits is read from every one of them. The
widest in the image is `pkg:github/sonic-net/saibcm-modules`, two commits above
the kernel; every fifth hung repository also ships at a second commit. Read in a
second run, both forms side by side:

| Beneath `saibcm-modules` | SQLite | PostgreSQL |
|---|--:|--:|
| Burndown, from both commits | 1,066 ms | 654 ms |
| Burndown, from the first commit | 1,601 ms | 637 ms |
| The list's total, from both commits | 280 ms | 176 ms |
| The list's total, from the first commit | 367 ms | 195 ms |

| Reading | Detail |
|---|---|
| A second start costs nothing measurable | The starts are one walk's seeds, and both commits reach the same 3,295 issues |
| The second run is slower across the board on SQLite | Its product burndown read 1,515 ms against 1,086 in the first; the machine was shared, so the forms are compared within the run |

The findings list's package filter, one page and its total, in a third run:

| The list of | Rows | SQLite | PostgreSQL |
|---|--:|--:|--:|
| The kernel's package | 3,295 | 215 ms | 75 ms |
| `pkg:deb/` | 3,959 | 229 ms | 75 ms |
| `pkg:generic/`, 3,872 components chosen | 3,423 | 70 ms | 82 ms |

| Reading | Detail |
|---|---|
| On SQLite and PostgreSQL a whole type costs about what one package costs | The chosen set is read once and held to by the occurrences' component |
| On MySQL and MariaDB a whole type costs about twice one package | The type is matched on the lowercased identifier, which no index answers: at 52 weekly rescans `pkg:deb/` reads a page in 888 ms against 479 for the kernel's package on MySQL 8.4, and 297 against 165 on MariaDB |

| Caveat | Detail |
|---|---|
| One build | The image's repositories reach every top-level component, the widest walk a repository row takes |
| Thirteen weeks | § Fifty-two weekly rescans has a year's figures on MySQL 8.4 and MariaDB; SQLite and PostgreSQL were not read at a year |
| Seeding took 6 minutes on SQLite and 16 to 39 on the servers | The history is built by applying each scan in turn |

### Fifty-two weekly rescans

The same image at 52 weekly rescans, read on MySQL 8.4 and MariaDB in the
review of this work, each engine run alone.

| Read | MySQL 8.4 | MariaDB |
|---|--:|--:|
| Burndown, the product | 2,691 ms | |
| Burndown, the kernel by its name | 4,439 ms | |
| Burndown, beneath the root | 3,869 ms | |
| The three reads above | 2.7 to 4.4 s | 3.8 to 4.8 s |

| Beneath, on MySQL 8.4 | Seeds of what nothing pulls in | Without them |
|---|--:|--:|
| Burndown beneath a leaf package | 1,034 ms | 22 ms |
| Trend beneath a leaf package | 290 ms | 19 ms |
| List beneath a leaf package | 217 ms | 20 ms |
| Burndown from a repository's two commits | 1,064 ms | 183 ms |

| Reading | Detail |
|---|---|
| A year of history costs the burndown its reads over the closed rows | The product alone takes 2.7 s on MySQL 8.4, so the time is outside the dismissals and the replaced components |
| A day 0 left empty pays the whole history | It is the first scan, so a year-old product reads a year each time the page opens |
| A walk from below the root is written without the seeds of what nothing pulls in | The planner prices them at every node of the build (`design-docs/data-model-graph.md` § Path traversal) |

## Export snapshots

One read-only REPEATABLE READ transaction held ten minutes on MySQL 8 and
MariaDB at CI's versions, beside a writer committing 100 transactions a
second, each updating 10 random rows of 10,000 and inserting 10. Other test
runs shared the servers.

| Elapsed | Writes | MySQL history list | MySQL scan in the snapshot | MariaDB history list | MariaDB scan in the snapshot |
|---|---|---|---|---|---|
| 0 s | 0 | 152 | | 59 | |
| 60 s | 5,963 | 30,226 | 53 ms | 34,113 | 47 ms |
| 180 s | 17,897 | 43,784 | 99 ms | 49,079 | 76 ms |
| 300 s | 29,925 | 55,824 | 193 ms | 61,118 | 141 ms |
| 452 s | 44,947 | 106,056 | 940 ms | 114,566 | 426 ms |
| 607 s | 60,406 | 139,646 | 688 ms | 154,061 | 527 ms |
| 10 s after it ended | | 323 | | 0 | |

| Finding | Detail |
|---|---|
| The history list grows by about one entry per write transaction committed anywhere on the server | The step after 360 s coincides with other test runs on the servers |
| It clears within ten seconds of the snapshot ending | |
| Without a snapshot it stays under 300 | The same writer for three minutes: at most 265 on MySQL and 271 on MariaDB |
| A read inside the snapshot slows as rows it reads gain versions | A scan of the 10,000 updated rows went from 25 ms to about 0.7 to 0.9 s on MySQL, 14 ms to about 0.5 s on MariaDB |
| On PostgreSQL vacuum keeps every row version that died while the snapshot was open, until it ends | Vacuum removes nothing the oldest open snapshot can still see; not measured here |

A product's findings file read as the export reads it, 200 groups a page,
by `TestMeasureAFindingsFileReadInOneSnapshot`: 12,000 issue-at-component
groups over two builds of 34 consumers, above the 7,374 a real switch image
carried. One engine at a time, no writer beside it, each read after an
unmeasured read of every page, so neither measured read meets a cold cache.
PostgreSQL ran on CI's image and settings with a 4 GB data directory, since the
file's seed does not fit beside other tests in the shared server's 1 GB.

| Engine | In one snapshot | One statement a page | Slowest page in the snapshot |
|---|---|---|---|
| SQLite | 14.4 s | 14.6 s | 372 ms |
| PostgreSQL 16 | 13.3 s | 12.7 s | 328 ms |
| MySQL 8.4 | 41.9 s | 42.2 s | 1.00 s |
| MariaDB 11.4 | 37.0 s | 37.0 s | 913 ms |

The slowest engine reads the file in under a tenth of the ten-minute ceiling.

## Counts by identifying name

Justifies the stored identifying name in `design-docs/data-model-components.md`
§ The identifying name. Five reads after a warm one, PostgreSQL 16 and MySQL 8.4
on throwaway servers on the shared development machine, one engine at a time.
`TestMeasureTheReleaseChartOverAReleaseLine` and
`TestMeasureAPageOfTheDecisionRecord` run them.

| Read | Data | Counted by the folded name | Pairs folded in Go | Counted by the stored identifying name |
|---|---|---|---|---|
| Release chart | 24 tags of the full-size image, every package under the root once with one issue and the kernel 4,942, a twenty-fourth of the packages moved each tag and the kernel renamed every fourth: 282,000 open findings, each one pair | 0.32 to 0.38 s on PostgreSQL, 1.23 to 1.26 s on MySQL | 1.25 to 1.30 s and 3.75 to 4.00 s | 0.25 to 0.27 s and 1.28 to 1.45 s |
| Decision record, a page of 200 | 200 promises, each on one package at a new version on each of 24 release lines, three issues under four containers: 57,600 findings, 43,800 decision occurrences | 0.53 to 1.53 s on PostgreSQL, 2.75 to 3.03 s on MySQL, over three runs | 1.25 to 1.30 s and 2.73 to 2.88 s, one run | 0.76 to 0.93 s and 1.60 to 3.24 s, over three runs |

The release chart sends every issue at a component to be folded, so folding in
Go scales with the open findings of every tag. The decision record's spread
between runs of the same code exceeds any difference between the three.

## Many builds

Justifies `design-docs/analytics.md` § Computed on demand, the rule grouping
occurrences in chunks of builds. A deployment of 15 builds of one product, each the
full-size switch image from one of its two vendors, scanned once and then
three nights each moving 40 packages: 3,678,051 findings, 3,594,873 open.
PostgreSQL 16, warm, every read of the trend's moments over a 30-day window.

| Read | Rows grouped | Time |
|---|--:|--:|
| Every build at once, as one grouping | 3,594,873 | 2.8 to 3.1 s |
| Every build at once, with the index | 3,594,873 | 1.36 to 1.40 s |
| Each build on its own, joined once | 3,594,873 | 1.5 s |
| Each build on its own, joined once, with the index | 3,594,873 | 0.40 to 0.46 s; 0.92 s with no parallel workers |

The index is the group index holding the run that opened a finding, last; it
is 66 MB beside a 1,327 MB table.

| Reading | Detail |
|---|---|
| Grouping every build at once sorts on disk | 198,198 moments from 3.6 million rows: a 232 MB external sort, 2.3 s of the 5.0 s a cold read took, after 2.1 s reading the table |
| One build fits in memory | 13,204 moments from 364,493 rows of one build: an in-memory hash of 2.3 MB, 155 ms |
| The index is read alone | Every column grouped on and filtered by is in it, so no table row is fetched |
| A deployment's builds cost in proportion | The moments are one build's each; a read with no selection costs every build's |
| The work nobody holds sorted 573 MB on disk | Every open occurrence grouped by piece of work at once: 5.19 s for the request. In chunks, dependency findings from the index alone: 1.27 s |
| The overview spilled 147 MB | Every open occurrence joined to the decided ones and grouped at once: 2.56 s for the request. In chunks, decided occurrences apart: 1.07 s |
| Each build of a real image is a chunk of its own | One holds about 240,000 open findings, past the 100,000 a chunk takes before the next starts |
| Counting a chunk's builds apart sorts each group | A count of distinct builds per piece of work took the work nobody holds from 1.27 s to 1.96 s; a chunk groups each of its builds apart instead, and the builds are counted across chunks |
| Which builds hold a row costs one count | 3.6 million open findings counted per build from an index in 85 ms |
| What each upload changed read every finding it opened from the table | Telling a check's match apart from a record taken back reads why a finding closed. The page holding a build's first upload, which opened 379,136 findings: 0.43 s, and 0.11 s served with that column in the run indexes |
| A second index leading with the build changes other plans | SQLite reached decided occurrences through an index ordered for the trend's grouping rather than by their identity, so the run is added to the group index |

Each request, served, median of three, warm:

| Request | One grouping over every build | In chunks |
|---|--:|--:|
| Trend, every build | 2.04 s | 1.49 s |
| Trend, one build | 0.46 s | 0.10 s |
| Burndown, every build | 2.60 s | 1.84 s |
| Burndown, one build | 0.46 s | 0.12 s |
| Work nobody holds | 5.19 s | 1.27 s |
| Product overview | 2.56 s | 1.07 s |
| Remediation | 1.41 s | 1.12 s |
| Uploads of one build, page holding its first | 0.43 s | 0.11 s |
| Components of the product, first page | 1.03 s | 0.79 s |
| Planned upgrades | 2.30 s | 1.92 s |

Two reads repeated within a minute differ by up to a tenth.

The deployment it models measured 8 to 10 s for the trend and the burndown over
all 15 builds, 2.3 to 3.5 s over one, and 0.2 s over one component.

## Many small builds

Justifies `design-docs/analytics.md` § Computed on demand, the bound on what a
chunk holds and the builds left out. One product of 200 and of 1,000 builds,
each 24 packages carrying one issue apiece, scanned once: 4,800 and 24,000 open
findings, the findings of one build in ten held by the reader. PostgreSQL 16,
MySQL 8.4 and MariaDB 11.4, median of five reads, main and the chunked reads
measured in one session (`make measure`, `TestMeasureReadsAcrossManySmallBuilds`).

| Read | Engine | 200 builds, one grouping | 200 builds, in chunks | 1,000 builds, one grouping | 1,000 builds, in chunks |
|---|---|--:|--:|--:|--:|
| Trend over 30 days | PostgreSQL | 23 ms | 36 ms | 95 ms | 101 ms |
| Trend over 30 days | MySQL | 18 ms | 29 ms | 91 ms | 114 ms |
| Trend over 30 days | MariaDB | 20 ms | 21 ms | 95 ms | 95 ms |
| Burndown | PostgreSQL | 36 ms | 37 ms | 111 ms | 132 ms |
| Burndown | MySQL | 21 ms | 28 ms | 100 ms | 120 ms |
| Burndown | MariaDB | 22 ms | 27 ms | 94 ms | 96 ms |
| Work nobody holds | PostgreSQL | 16 ms | 17 ms | 62 ms | 50 ms |
| Work nobody holds | MySQL | 18 ms | 20 ms | 63 ms | 74 ms |
| Work nobody holds | MariaDB | 12 ms | 18 ms | 61 ms | 57 ms |
| Work somebody holds | PostgreSQL | 7 ms | 10 ms | 12 ms | 19 ms |
| Work somebody holds | MySQL | 4 ms | 6 ms | 9 ms | 26 ms |
| Work somebody holds | MariaDB | 3 ms | 6 ms | 7 ms | 25 ms |
| Product overview | PostgreSQL | 15 ms | 20 ms | 45 ms | 62 ms |
| Product overview | MySQL | 10 ms | 20 ms | 62 ms | 77 ms |
| Product overview | MariaDB | 12 ms | 12 ms | 54 ms | 58 ms |
| Remediation | PostgreSQL | 14 ms | 23 ms | 29 ms | 44 ms |
| Remediation | MySQL | 8 ms | 15 ms | 41 ms | 65 ms |
| Remediation | MariaDB | 9 ms | 12 ms | 36 ms | 44 ms |

| Reading | Detail |
|---|---|
| Chunked reads cost a small deployment a statement | The count of what each build holds runs before the grouping: at 1,000 builds of 24 findings a read is up to 25 ms slower than one grouping, most on MySQL, and the work nobody holds is as fast or faster |
| A branch per build costs in builds | One branch per build, 24 findings each: the work nobody holds 550 ms against 12 ms at 200 builds, and at 1,000 PostgreSQL refused it for want of shared memory; the trend 1.06 s against 87 ms, 451 ms of it planning |
| Every build is one chunk | 24,000 findings are under the 100,000 a chunk holds, so the read is one grouping, as before chunking |
| The count names at most 200 builds a statement | Past 200 values in a list MySQL 8.4 reads the list value by value rather than as ranges. Counting 1,000 builds' open findings: MySQL 40 ms at 500 a statement, 10 ms at 200, 16 ms at 150; PostgreSQL 5 ms, 6 ms and 7 ms; MariaDB 7 ms, 8 ms and 16 ms |
| The count reads table rows where the condition is not in the index picked | For the work nobody holds, PostgreSQL scanned the table at 500 builds a statement, and at 200 read the index of open findings by build and took each holder from the table |

## Uploads of one build

Justifies `design-docs/analytics-program.md` § Uploads of one build, the read
from the earliest point's moment. One build of the full-size image, 6,843
packages each carrying one issue and the kernel 3,000, uploaded and scanned
nightly for 50 nights, each upload dropping one leaf package in thirty and
restoring the night before's: 453,726 findings. Median of five reads, one
engine at a time (`make measure`, `TestMeasureABuildTrendOverNightlyUploads`).

| Engine | 2 uploads | 12 uploads | 50 uploads |
|---|--:|--:|--:|
| SQLite | 254 ms | 446 ms | 1.48 s |
| PostgreSQL 16 | 197 ms | 303 ms | 385 ms |
| MySQL 8.4 | 371 ms | 615 ms | 966 ms |
| MariaDB 11.4 | 136 ms | 293 ms | 379 ms |

| Reading | Detail |
|---|---|
| 453,726 rows are one night's 153,889, each night's drop, and the kernel twice | Each night opens and closes about 600 findings. The kernel is a leaf, so the drop takes it out on nights 10 and 40: its 135,575 findings close as removed and open again as new rows the night after, the shape of a broken upload |
| Cost follows the oldest upload plotted | Each point adds the findings opened since the one before; twelve uploads, the default, read in under two thirds of a second on every engine |
| SQLite rises most with the points | 254 ms at 2 uploads to 1.48 s at 50, against 197 ms to 385 ms on PostgreSQL |
| Two full images cost what the calendar trend costs | The demo's SQLite, September and November SONiC images per build, served: broadcom 2.30 s against 2.28 s for the same build's 30-day trend, mellanox 1.00 s; September broadcom's scan opened 373,331 findings |
