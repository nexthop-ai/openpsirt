# Analysis measurements

Measurements behind the analyzer rules. Each section names the rule it
justifies.

## Contents

- [Producer output](#producer-output)
- [Trend of code findings](#trend-of-code-findings)
- [Security testing figures](#security-testing-figures)

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
earlier runs of the series, and the build then read as a release. Each figure
is asked four times, as loaded and again refreshed; the second fastest of the
last three is shown, the slower of the two states.

| Figure | PostgreSQL | MySQL 8.4 | MariaDB |
|---|---|---|---|
| Time to judge, the product, 104 weeks | 195 ms | 726 ms | 413 ms |
| Time to fix, the product, 104 weeks | 86 ms | 386 ms | 186 ms |
| Analyzer precision | 56 ms | 251 ms | 131 ms |
| Analysis coverage, 104 weeks | 9 ms | 3 ms | 5 ms |
| Code findings by release | 65 ms | 292 ms | 158 ms |

| Shape | Measured |
|---|---|
| First proposals asked per finding as a correlated test | 7.96 s as loaded on PostgreSQL, against 195 ms with the decisions joined to the findings and grouped |
| The queue's test of a closed finding, on MySQL 8.4 | 26.6 s per statement for 400 closed code findings: the open one is looked up through the build's open findings, 84,000 rows per closed code finding. Time to judge took 53 s through it, and 726 ms reading open findings alone |
| The same test on MariaDB and PostgreSQL | 86 ms and 1.25 s for the statement alone |

| Caveat | Detail |
|---|---|
| Beneath a component is not in the table | It adds the tree walk the trend's table measures, which on MySQL and MariaDB at this size outlasts the run |
| One build | The figures read every build of the product; this model holds one |
