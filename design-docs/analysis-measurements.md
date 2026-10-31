# Analysis measurements

Measurements behind the analyzer rules. Each section names the rule it
justifies.

## Contents

- [Producer output](#producer-output)
- [Trend of code findings](#trend-of-code-findings)
- [Security testing figures](#security-testing-figures)
- [Figures across products](#figures-across-products)
- [Code finding queue](#code-finding-queue)
- [Queue reads over rescan history](#queue-reads-over-rescan-history)

## Producer output

Justifies the bound defaults (`design-docs/analysis.md` § Bounds).

| Output | Bytes | Gzipped | Results | Rules | Most places per result | Most flow steps per result | Largest property bag | Deepest nesting |
|---|---|---|---|---|---|---|---|---|
| CodeQL 2.15.0, C++ queries over a small interpreter | 226,586 | 22,398 | 22 | 165 | 2 | 0 | 9 | 11 |
| CodeQL 2.2.5, Java queries | 111,783 | 6,439 | 15 | 25 | 4 | 12 | 7 | 14 |
| clang 18.1.3 static analyzer, one unit | 12,899 | 1,284 | 3 | 2 | 1 | 5 | none | 14 |
| cppcheck 2.22.0, two units | 6,182 | 853 | 4 | 3 | 2 | 0 | 4 | 9 |
| clang-tidy through `clang-tidy-sarif` | 751 | 328 | 1 | 0 | 1 | 0 | none | 9 |

The Java output is `samples/sarif/java/detailed/java.sarif` in
github.com/peter-murray/github-security-report-action at commit `84b2945`; the
others are the reader's fixtures, whose origins are recorded beside them.

| Reading | |
|---|---|
| Compression | Every output of 5 KB or more compressed 7 to 17 times, so a gzipped upload meets the decompressed bound well before the bound as sent |
| Size per result | CodeQL's was largest, about 10 KB a result, mostly the description of every query it ran |
| Snippets | None of them carries one |

## Trend of code findings

Justifies reading every week in one statement
(`design-docs/analysis-statistics.md` § Code findings over time).
`TestMeasureTheComponentHub` under `make measure`: one build of the given
size, 4,000 code findings, each read once as loaded and once refreshed; the
slower is shown.

| Components | Engine | Beneath the root, 12 weeks | The product, 104 weeks |
|---|---|---|---|
| 1,000 | SQLite | 27 ms | 31 ms |
| 1,000 | PostgreSQL | 28 ms | 38 ms |
| 1,000 | MySQL 8.4 | 60 ms | 63 ms |
| 1,000 | MariaDB | 29 ms | 52 ms |
| 4,000 | SQLite | 59 ms | 70 ms |
| 4,000 | PostgreSQL | 25 ms | 35 ms |
| 4,000 | MySQL 8.4 | 90 ms | 95 ms |
| 4,000 | MariaDB | 29 ms | 83 ms |
| 16,000 | SQLite | 163 ms | 161 ms |
| 16,000 | PostgreSQL | 31 ms | 46 ms |
| 16,000 | MySQL 8.4 | 49 ms | 257 ms |

| Caveat | Detail |
|---|---|
| MariaDB at 16,000 components is not in the table | The run ends at its hour limit in the MySQL tree read before it, a read the trend does not take |
| The bar is the backlog trend's 0.25 s over 367,577 occurrences | That model holds far more rows than this one's 4,000 code findings |

## Security testing figures

Justifies how time to judge reads first proposals and how the figures read
the queue's rows (`design-docs/analysis-figures.md`).
`TestMeasureTheSecurityTestingFigures` under `make measure`: the hub's build of
16,000 components and 84,000 findings, 4,000 of them code findings opened a
week apart over two years, every tenth closed as fixed, 200 confirmed, 104
earlier runs of the series, and the build then read as a release. Every
dependency finding is closed in the last thirteen weeks and copied twice, as
distinct occurrences, onto the other product's build: 240,957 dependency
closings in the deployment. Each figure
is asked four times, as loaded and again refreshed; the second fastest of the
last three is shown, the slower of the two states.

| Figure | PostgreSQL | MySQL 8.4 | MariaDB |
|---|---|---|---|
| Time to judge, the product, 104 weeks | 104 ms | 728 ms | 303 ms |
| Time to fix, the product, 104 weeks | 76 ms | 494 ms | 197 ms |
| Time to fix, the product, 13 weeks | 67 ms | 500 ms | 190 ms |
| Analyzer precision | 41 ms | 336 ms | 138 ms |
| Analysis coverage, 104 weeks | 8 ms | 3 ms | 4 ms |
| Code findings by release | 45 ms | 258 ms | 91 ms |

| Shape | Measured |
|---|---|
| First proposals asked per finding as a correlated test | 7.96 s as loaded on PostgreSQL, against 195 ms with the decisions joined to the findings and grouped |
| The queue's test of a closed finding, on MySQL 8.4 | 26.6 s per statement for 400 closed code findings: the open one is looked up through the build's open findings, 84,000 rows per closed code finding. Time to judge took 53 s through it, and 726 ms reading open findings alone |
| The same test on MariaDB and PostgreSQL | 86 ms and 1.25 s for the statement alone |
| Time to fix reading every closing in the deployment for the occurrences closed in the window | 5.94 s at 13 weeks and 4.83 s at 104 weeks as loaded on PostgreSQL, against 67 ms and 76 ms reading the product's code findings alone. MySQL 8.4 and MariaDB took the same time either way: 502 ms and 186 ms at 13 weeks |

| Caveat | Detail |
|---|---|
| Beneath a component is not in the table | It adds the tree walk the trend's table measures, which on MySQL and MariaDB at this size outlasts the run |
| One build of the product | The figures read every build of the product; this model holds one, and the other product's build holds only closings |

## Figures across products

Justifies reading home's Security testing figures once across products
(`design-docs/analysis-figures.md` § Figures across products).
`TestMeasureTheSecurityTestingFiguresAcrossProducts` under `make measure`: the
model of § Security testing figures, with the reader holding security testing
material in both products. Each across-products read is set beside the same
figure for the hub's product alone, asked as home asks it: the queue's counts,
twelve weeks of trend, and one week of time to judge and coverage. Each is
asked four times, as loaded and again refreshed; the second fastest of the last
three is shown, the slower of the two states. Before is the queue with each
closed code finding and each decision asked of its row; after is the forms of
§ Code finding queue. Both were measured in one session, each engine's pair
back to back.

| Read | PostgreSQL before | PostgreSQL after | MySQL 8.4 before | MySQL 8.4 after | MariaDB before | MariaDB after |
|---|---|---|---|---|---|---|
| Counts across products | 184 ms | 112 ms | 3.31 s | 1.23 s | 2.44 s | 862 ms |
| The product's queue, one row | 631 ms | 190 ms | 4.20 s | 678 ms | 17.2 s | 207 ms |
| Trend across products | 274 ms | 39 ms | 567 ms | 354 ms | 416 ms | 331 ms |
| The product's trend | 261 ms | 32 ms | 332 ms | 17 ms | 192 ms | 21 ms |
| Time to judge across products | 548 ms | 86 ms | 825 ms | 709 ms | 521 ms | 514 ms |
| The product's time to judge | 532 ms | 87 ms | 597 ms | 224 ms | 333 ms | 30 ms |
| Coverage across products | 14 ms | 11 ms | 3 ms | 3 ms | 4 ms | 5 ms |
| The product's coverage | 10 ms | 10 ms | 3 ms | 4 ms | 4 ms | 5 ms |

| Reading | |
|---|---|
| Counts | Counting without rows skips the page's statements; across both products the counts read every product's code findings, as one product's queue does its own |
| The other figures | Across products costs about one more product's read, and saves a request per product |
| As loaded and refreshed | After, MySQL and MariaDB answer every read across products in under 0.5 s once statistics are refreshed; the slower figure above is as loaded |

| Caveat | Detail |
|---|---|
| Runs vary on the same server | PostgreSQL before took 70 ms to 780 ms for the counts across runs of the session, with plans following which tables the server had refreshed |
| The other product holds dependency closings alone | It adds rows to read and nothing to count |

## Code finding queue

Justifies reading whether a code finding opened anew and whether another
analyzer agrees as windows over the scope's code findings, and whether a
decision stands or waits as a set read from the decisions, each asked of a row
by identifier, and keeping a list by state by its conditions
(`design-docs/analysis-queue.md` § Code finding queue and
`design-docs/analysis-queue.md` § Grouped code findings).
`TestMeasureTheCodeFindingQueueOfTheHubBuild` under `make measure`: one build
of 16,000 components and 84,000 findings, two analyzers' 4,000 code findings
each a line apart under rules of three weakness families, every tenth code
finding closed and every third dependency finding, each at one of 100
moments over a year. Each read is timed on the statistics the load
leaves and again after every table is analyzed; a page is every statement of
one request.

| Engine | Statistics | Queue page before | Queue page after | Fixed list before | Fixed list after | Slowest statement before | Slowest statement after |
|---|---|---|---|---|---|---|---|
| PostgreSQL 16 | As loaded | 2.5 s | 0.20 s; 1.95 s in one run of three | 1.0 s | 0.18 s; 1.91 s in that run | 0.89 s | 0.08 s; 1.01 s in that run |
| PostgreSQL 16 | Analyzed | 0.23 s | 0.22 s | 0.20 s | 0.18 s | 0.11 s | 0.09 s |
| MySQL 8.4 | As loaded | past 30 s | 0.67 s | past 30 s | 0.58 s | past 30 s | 0.43 s |
| MySQL 8.4 | Analyzed | 0.32 s | 0.42 s | 0.31 s | 0.30 s | 0.11 s | 0.24 s |
| MariaDB 11.4 | As loaded | past 30 s | 0.21 s | past 30 s | 0.20 s | past 30 s | 0.10 s |
| MariaDB 11.4 | Analyzed | 0.17 s | 0.28 s | 0.11 s | 0.19 s | 0.08 s | 0.15 s |
| SQLite | As loaded | 0.47 s | 0.47 s | 0.40 s | 0.66 s | 0.19 s | 0.32 s |
| SQLite | Analyzed | 0.42 s | 0.35 s | 0.34 s | 0.89 s | 0.23 s | 0.20 s |

`TestMeasureTheCodeFindingQueueOverRescanHistory` gives the same build the
history of many scans: each code finding closed and seen again eight times on
the build, and the code findings in four more builds of the product, every
tenth closed there too; 104,000 code findings, 68,000 closed.

| Engine | Statistics | Queue page before | Queue page after | Fixed list before | Fixed list after | Slowest statement after |
|---|---|---|---|---|---|---|
| PostgreSQL 16 | As loaded | 2.17 s | 1.28 s | 1.30 s | 1.52 s | 0.72 s |
| PostgreSQL 16 | Analyzed | 5.17 s | 2.05 s | 4.31 s | 2.28 s | 1.44 s |
| MySQL 8.4 | As loaded | past 2 minutes a statement, measured in review | 6.22 s | | 6.78 s | 4.87 s |
| MySQL 8.4 | Analyzed | | 5.66 s | | 6.02 s | 4.81 s |
| MariaDB 11.4 | As loaded | | 2.59 s | | 3.37 s | 2.00 s |
| MariaDB 11.4 | Analyzed | | 2.46 s | | 3.34 s | 2.02 s |
| SQLite | As loaded | | 1.69 s | | 2.61 s | 1.07 s |
| SQLite | Analyzed | | 2.99 s | | 4.80 s | 3.01 s |

On rescan history the windows are the saving: each closed row asked whether
its code finding opened anew reads every open finding of its build, and the
windows read each code finding once. § Queue reads over rescan history has
what the windows and the counts cost since.

Each form below was planned by some engine through every open finding of a
build or of a rule, or every decision of a product, with statistics as loaded
unless the row says otherwise:

| Form | Engine, as loaded | Cost |
|---|---|---|
| Opened anew, asked of each closed finding | MySQL 8.4, MariaDB 11.4 | Past 30 s a statement |
| Opened anew, the open ones joined to the rows | PostgreSQL 16 | 9.4 s, the set read once per row |
| Opened anew, occurrence and build asked together | SQLite | 0.42 s against 0.18 s |
| Opened anew, the closed and the open each a set, joined | MariaDB 11.4 | Past 30 s, the open set read again for each closed finding |
| Agreement, asked of each row | MySQL 8.4 | 12 s |
| Agreement, a set joined to the rows | PostgreSQL 16 | 1.8 s |
| Agreement, a set with the family among the joins | MySQL 8.4 | 11 s for the set |
| Agreement, two sets paired by build and file | PostgreSQL 16 | 5.5 s; MySQL 8.4 keyed one by build alone, 7 s |
| Agreement, a set asked of each row ungrouped | MariaDB 11.4 | Past 30 s, every row compared with the whole set |
| A state tested on its worked-out value | PostgreSQL 16, analyzed | 8.7 s for the page, against 0.1 s |
| A decision standing or waiting, asked of each row as NOT EXISTS | PostgreSQL 16 | An anti join reading every decision of the product once per code finding, without the occurrence; 502 ms for time to judge against 163 ms |
| A decision waiting, asked of each row as NOT EXISTS | MySQL 8.4 | The same anti join, about 0.45 s of time to judge |
| A decision standing or waiting, tested as a worked-out value | PostgreSQL 16, analyzed | One row in two hundred estimated; 2.4 s for the page |
| A decision set joined from the scope's builds | MariaDB 11.4 | Every open finding of each build read before the decisions, 0.3 s a set |

| Caveat | Detail |
|---|---|
| Statements are capped at 30 s on MySQL and MariaDB | A capped read answers an error, so its page is past 30 s |
| Statistics as loaded differ from run to run | A server refreshes them in the background; each form above failed in at least one of several runs, and the forms kept passed in every run |
| The windows cost on analyzed statistics | MySQL, MariaDB and SQLite read every code finding of the scope's builds once per set, where a correlated test reached a handful |
| The statement bar is the backlog trend's 0.25 s | MySQL as loaded and SQLite read about 0.3 s for one statement |
| PostgreSQL as loaded, one run of three | JIT compiled for about 1 s a statement that runs in about 90 ms, set off by estimates with one table analyzed and the rest as loaded; intermittent |
| Before on rescan history | Measured on PostgreSQL alone here; MySQL before is the review's measurement |

## Queue reads over rescan history

Justifies reading agreement through one named window over the open code
findings, reading a code finding's state only where a count reads it, from
the decision sets, and asking whether the build still ships a row's component
without the closing-scan index (`design-docs/analysis-queue.md` § Code finding
queue and `design-docs/analysis-queue.md` § Grouped code findings). The
measures of § Code finding queue and § Figures across products. Before is the
forms § Code finding queue lists; after is the forms named here. Each cell
gives every run, each engine's before and after back to back; another
measurement shared the host in each run.

Rescan history, `TestMeasureTheCodeFindingQueueOverRescanHistory`: 104,000
code findings, 68,000 closed.

| Engine | Statistics | Queue page before | Queue page after | Fixed list before | Fixed list after | Page's slowest statement before | Page's slowest statement after | Fixed list's slowest statement after |
|---|---|---|---|---|---|---|---|---|
| MySQL 8.4 | As loaded | 5.63 s, 6.81 s | 1.34 s, 1.30 s | 5.83 s, 6.99 s | 2.15 s, 2.12 s | 4.10 s, 4.94 s | 0.67 s, 0.64 s | 1.15 s, 1.13 s |
| MySQL 8.4 | Analyzed | 5.07 s, 5.97 s | 1.41 s, 1.28 s | 5.30 s, 6.52 s | 2.16 s, 2.10 s | 4.06 s, 4.76 s | 0.65 s, 0.63 s | 1.16 s, 1.13 s |
| MariaDB 11.4 | As loaded | 2.22 s, 2.28 s | 1.34 s, 1.25 s | 2.86 s, 2.98 s | 2.44 s, 2.31 s | 1.37 s, 1.40 s | 0.66 s, 0.63 s | 1.33 s, 1.23 s |
| MariaDB 11.4 | Analyzed | 2.14 s, 2.31 s | 1.27 s, 1.21 s | 2.90 s, 2.97 s | 2.42 s, 2.31 s | 1.37 s, 1.46 s | 0.65 s, 0.63 s | 1.32 s, 1.24 s |
| PostgreSQL 16 | As loaded | 1.08 s, 1.08 s | 0.82 s, 0.82 s | 1.24 s, 1.29 s | 1.21 s, 1.21 s | 0.54 s, 0.53 s | 0.41 s, 0.41 s | 0.58 s, 0.58 s |
| PostgreSQL 16 | Analyzed | 1.73 s, 1.75 s | 0.79 s, 0.81 s | 1.95 s, 1.97 s | 1.26 s, 1.24 s | 1.15 s, 1.18 s | 0.45 s, 0.46 s | 0.57 s, 0.57 s |
| SQLite | As loaded | 1.55 s | 1.30 s | 2.39 s | 2.68 s | 0.91 s | 0.92 s | 1.27 s |
| SQLite | Analyzed | 2.62 s | 1.07 s | 4.12 s | 3.26 s | 1.83 s | 0.68 s | 1.73 s |

The hub's build, `TestMeasureTheCodeFindingQueueOfTheHubBuild`:

| Engine | Statistics | Queue page before | Queue page after | Slowest statement before | Slowest statement after |
|---|---|---|---|---|---|
| MySQL 8.4 | As loaded | 531 ms, 569 ms | 317 ms, 320 ms | 193 ms, 268 ms | 117 ms, 122 ms |
| MySQL 8.4 | Analyzed | 306 ms, 423 ms | 270 ms, 287 ms | 166 ms, 228 ms | 130 ms, 147 ms |
| MariaDB 11.4 | As loaded | 180 ms, 179 ms | 189 ms, 181 ms | 91 ms, 88 ms | 80 ms, 78 ms |
| MariaDB 11.4 | Analyzed | 249 ms, 244 ms | 235 ms, 232 ms | 127 ms, 123 ms | 121 ms, 119 ms |
| PostgreSQL 16 | As loaded | 187 ms, 172 ms | 154 ms, 150 ms | 85 ms, 84 ms | 67 ms, 60 ms |
| PostgreSQL 16 | Analyzed | 183 ms, 185 ms | 191 ms, 171 ms | 76 ms, 72 ms | 75 ms, 67 ms |
| SQLite | As loaded | 549 ms | 568 ms | 373 ms | 370 ms |
| SQLite | Analyzed | 477 ms | 386 ms | 266 ms | 244 ms |

Home's figures across two products, `TestMeasureTheSecurityTestingFiguresAcrossProducts`,
the slower of as loaded and refreshed:

| Read | Engine | Before | After |
|---|---|---|---|
| Counts across products | MySQL 8.4 | 1.07 s, 1.33 s | 119 ms, 107 ms |
| Counts across products | MariaDB 11.4 | 660 ms, 748 ms | 80 ms, 77 ms |
| Counts across products | PostgreSQL 16 | 153 ms, 164 ms | 84 ms, 109 ms |
| The product's queue, one row | MySQL 8.4 | 694 ms, 726 ms | 115 ms, 117 ms |
| The product's queue, one row | MariaDB 11.4 | 177 ms, 182 ms | 92 ms, 85 ms |
| The product's queue, one row | PostgreSQL 16 | 180 ms, 198 ms | 120 ms, 153 ms |
| Time to judge across products | MySQL 8.4 | 615 ms, 696 ms | 40 ms, 38 ms |
| Time to judge across products | MariaDB 11.4 | 375 ms, 403 ms | 23 ms, 23 ms |
| Time to judge across products | PostgreSQL 16 | 53 ms, 60 ms | 53 ms, 77 ms |
| Counts across products | SQLite | 1.07 s | 825 ms |
| The product's queue, one row | SQLite | 519 ms | 396 ms |
| Time to judge across products | SQLite | 14 ms | 13 ms |

| Saving | Measured |
|---|---|
| The first and last analyzer through one named window | MySQL 8.4 sorted and passed over the rows once per window written out: 3.9 s against 1.8 s for the agreement set over 104,000 code findings |
| Agreement read over the open code findings alone | 0.82 s against 2.17 s for the queue's page statement on MySQL 8.4; a closed code finding never agrees |
| The fixed list's agreement over the closed ones not opened anew | 1.3 s against 2.2 s for its page statement on MySQL 8.4, against every closed one |
| A file told by its path's digest alone | 0.35 s against 0.46 s for the agreement set over 36,000 open code findings on MySQL 8.4; the path as written put a text column in the sort |
| State, waiting and rule columns only where a count reads them | 0.16 s of 0.36 s for the queue's count on MySQL 8.4, which works out a materialized derived table's every column |
| A decision standing or waiting asked from the decision sets in counts | 0.13 s against 0.22 s for the counts across products on MySQL 8.4, analyzed; as loaded MySQL read the decision table whole for each code finding, 0.17 s of one statement |
| Whether the build ships a component, asked without the closing-scan index | 3 ms against 0.48 s for the page's rows on MySQL 8.4 as loaded, which read every live node through that index for each row |

| Form | Engine | Cost |
|---|---|---|
| An index on a finding's build, kind and closing | MySQL 8.4 | As loaded, still read every finding of each build through the index the build leads; analyzed, no change |
| An index on a decision occurrence's occurrence and product | MySQL 8.4 | Analyzed, still read through the index the product leads; no change |
| The fixed list's agreement told after a second window for opening anew, in one statement | MySQL 8.4 | 1.8 s to 1.9 s for the page against 1.3 s |
| Opening anew over an index in occurrence and build order | MySQL 8.4 | Still sorted; 0.28 s against 0.32 s for the set, and a write cost on every finding |
| The scope's builds bound as values in the agreement set | MySQL 8.4 | 0.46 s either way |

| Caveat | Detail |
|---|---|
| What is left over rescan history | Each statement reads the scope's 104,000 code findings. On MySQL 8.4 joining them alone takes 0.2 s, telling which opened anew 0.4 s, and the agreement set over 36,000 open ones 0.35 s |
| The slowest statements over rescan history | On MySQL 8.4, the queue's counts, 0.70 s with opening anew, and the fixed list's page, 1.17 s, which tells opening anew for the list and again for its agreement |
| SQLite's fixed list as loaded | Telling opening anew for the agreement costs SQLite more than reading every closed code finding: 2.68 s against 2.39 s |
| Another measurement shared the host | Runs of one engine and side differ by up to a fifth |
| SQLite is one run of each side | Measured alone; run beside the other measures it read up to twice as long |
