# Analysis measurements

Measurements behind the analyzer rules. Each section names the rule it
justifies.

## Contents

- [Producer output](#producer-output)
- [Trend of code findings](#trend-of-code-findings)
- [Security testing figures](#security-testing-figures)
- [Figures across products](#figures-across-products)
- [Code finding queue](#code-finding-queue)

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
windows read each code finding once. MySQL's slowest statement is the page's
agreement windows, 3.9 s over 104,000 rows.

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

