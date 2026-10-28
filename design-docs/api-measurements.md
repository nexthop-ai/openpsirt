# API measurements

Benchmark runs behind the API rules. Each section names the rule it justifies.

## Contents

- [Package kinds](#package-kinds)

## Package kinds

Justifies reading the kinds in Go after the statement, with nothing stored
(`design-docs/api-lists.md` § Package kinds). The full-size fixture, every one of
its 6,843 components with a package identifier carrying an issue and the kernel
carrying 4,943: 241,313 findings, 11,785 rows, eight kinds.

| Engine | The kinds read | The list's first page |
|---|---|---|
| SQLite | 60 ms | 230 ms |
| PostgreSQL | 145 ms | 450 ms |
| MySQL | 250 ms | 380 ms |
| MariaDB | 148 ms | 410 ms |

Grouping the findings themselves by fold took 300 to 590 ms on the same data.
