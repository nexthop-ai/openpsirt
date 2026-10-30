# Analysis measurements

Measurements behind the analyzer rules. Each section names the rule it
justifies.

## Contents

- [Producer output](#producer-output)
- [Trend of code findings](#trend-of-code-findings)

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
