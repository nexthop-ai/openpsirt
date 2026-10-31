# Remediation measurements

Benchmark runs behind the remediation rules.

## Contents

- [VEX document reads](#vex-document-reads)
- [Statements as loaded](#statements-as-loaded)
- [Failed alternatives](#failed-alternatives)

## VEX document reads

Justifies `design-docs/remediation-vex.md` § Reads.
`TestMeasureTheVEXDocumentOfTheHubBuild` under `make measure`: one build of
16,000 components and 84,000 findings, every third dependency finding closed at
one of 100 moments over a year. Three kernel binaries each carry an agreed
decision that 100 issues do not apply, and a fourth one that 100 apply. Of the
closed findings, every tenth is patched by a claim the build declares and every
tenth beside it closed by a supplier's statement. A read is timed four times and
the first is not kept; the median of the rest is shown, and the slowest
statement among them.

The joined form joins the build's open node and image version beside every
finding and works out the decisions of every open finding of the build. The
two-level form is the one § Reads describes.

| Engine | Read, analyzed | Joined | Two levels |
|---|---|---|---|
| PostgreSQL 16 | The document | 345 ms | 245 ms |
| PostgreSQL 16 | With suppliers | 462 ms | 378 ms |
| PostgreSQL 16 | The statements published | 453 ms | 261 ms |
| PostgreSQL 16 | Slowest statement | 123 ms | 92 ms |
| MySQL 8.4 | The document | 3.10 s | 422 ms |
| MySQL 8.4 | With suppliers | 3.35 s | 586 ms |
| MySQL 8.4 | The statements published | 3.51 s | 434 ms |
| MySQL 8.4 | Slowest statement | 1.71 s | 156 ms |
| MariaDB 11.4 | The document | 776 ms | 236 ms |
| MariaDB 11.4 | With suppliers | 898 ms | 355 ms |
| MariaDB 11.4 | The statements published | 1,155 ms | 251 ms |
| MariaDB 11.4 | Slowest statement | 377 ms | 107 ms |
| SQLite | The document | 681 ms | 477 ms |
| SQLite | With suppliers | 798 ms | 742 ms |
| SQLite | The statements published | 936 ms | 503 ms |
| SQLite | Slowest statement | 258 ms | 242 ms |

The same reads on the statistics the load leaves:

| Engine | Read, as loaded | Joined | Two levels |
|---|---|---|---|
| PostgreSQL 16 | The document | Past 30 s a statement | 320 ms |
| PostgreSQL 16 | With suppliers | Past 30 s a statement | 434 ms |
| PostgreSQL 16 | The statements published | Past 30 s a statement | 315 ms |
| MariaDB 11.4 | The document | Unfinished at 25 min | 59.5 s, 33 s of it a closed read |
| SQLite | The document | 42.8 s | 15.3 s |
| SQLite | With suppliers | 57.9 s | 33.0 s |
| SQLite | The statements published | 51.8 s | 21.0 s |
| SQLite | Slowest statement | 18.1 s, the decided groups | 20.7 s, a closed read |

| Reading | |
|---|---|
| The bar | 0.25 s a statement. Analyzed, the two-level form meets it on every engine |
| A closed read as loaded | The findings closed by a patch or a supplier's statement read in one form in both columns, and dominate every as-loaded read where they are slow: 14 s to 21 s on SQLite, 33 s and past on MariaDB |
| PostgreSQL as loaded | The run's background analysis reaches some tables before its as-loaded reads; § Statements as loaded holds a database with none |

## Statements as loaded

Each statement on its own, on a database held right after the load with its
statistics frozen: PostgreSQL never analyzed, MySQL with InnoDB's persistent
statistics still empty. A statement stopped at 30 s is shown as past it.

| Statement | PostgreSQL, joined | PostgreSQL, two levels | MySQL 8.4, joined | MySQL 8.4, two levels |
|---|---|---|---|---|
| The groups the document states | Past 30 s | 864 ms | 1.19 s | 88 ms |
| The groups the published statements apply to | Not run | 291 ms | Not run | 68 ms |
| The occurrences the document states one by one | Past 30 s | 859 ms | 1.73 s | 205 ms |
| The findings the build's patches closed | Past 30 s | 91 ms | Past 30 s | Past 30 s |
| The findings suppliers' statements closed | Not run | 98 ms | Not run | Past 30 s |

| Reading | |
|---|---|
| PostgreSQL | Never analyzed, it estimates a lookup on each key at one row and joins the graph or the decisions unkeyed |
| MySQL and MariaDB | A plan is chosen from whatever the background statistics have reached; a lookup per row that is not on a primary key can go through the index on a closing scan, or a build's whole set of open findings |
| The decided read | The issues decided are a few hundred of 8,327, so reading them first bounds every engine |
| A closed read on MariaDB | One plan seen: the closed findings read issue by issue, the graph read whole for each finding's stated identifier, and the build's findings read whole for each latest-row check; stopped at 27 min |

## Failed alternatives

Each alternative read the same answers, and was measured against the rule it
lost to.

| Alternative | Measured | Loses to |
|---|---|---|
| The open node and image version joined beside each finding | Past a minute on PostgreSQL as loaded | The identifier asked of each row |
| The open image version tested where an index serves it | 31 s on MariaDB as loaded, for 2,700 rows | The open version picked in the aggregate |
| The stated identifier as a function of joined columns | 5.3 s on PostgreSQL as loaded | The identifier asked of each row |
| The decided issues as a derived table joined to the findings | 500 ms on PostgreSQL as loaded | The issues read first, as a list |
| The occurrences read against the decided issues as a constant list | 757 ms on PostgreSQL as loaded | The issues read first, restricting the findings |
| The closed reads as a window over the build's findings | 1.46 s on MySQL and 1.18 s on MariaDB, analyzed | The checks asked per issue and component |
| The open occurrences as a row value `NOT IN` a subquery | Past a minute on MySQL | The checks asked per issue and component |
| The open occurrences as `NOT IN` the build's whole open set | 0.60 s on MySQL and 0.66 s on MariaDB, analyzed | The checks asked per issue and component |
| The open occurrences as `NOT IN` the open set of the closed issues, read once | MySQL as loaded 0.28 s; analyzed, MariaDB 0.26 s against 0.07 s and SQLite 0.8 s to 1.15 s against 0.13 s | The checks asked per issue and component |
| The latest row at an occurrence as `IN` the grouped maxima | 1.7 s on PostgreSQL as loaded | The latest row asked of each row |
| The latest row as a scalar maximum per row | Past a minute on MySQL as loaded | The latest row asked of each row |
| The component's shipping asked with its open check in the aggregate | 1.15 s on PostgreSQL as loaded, through the root index | The shipping asked per issue and component |
