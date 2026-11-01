# Remediation measurements

Benchmark runs behind the remediation rules.

## Contents

- [VEX document reads](#vex-document-reads)
- [A long-lived product](#a-long-lived-product)
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
statement among them. Each engine runs alone.

The joined form joins the build's open node and image version beside every
finding and works out the decisions of every open finding of the build. The
two-level form is the one `design-docs/remediation-vex.md` § Reads describes.

| Engine | Read, analyzed | Joined | Two levels |
|---|---|---|---|
| PostgreSQL 16 | The document | 345 ms | 350 ms |
| PostgreSQL 16 | With suppliers | 462 ms | 492 ms |
| PostgreSQL 16 | The statements published | 453 ms | 412 ms |
| PostgreSQL 16 | Slowest statement | 123 ms | 99 ms |
| MySQL 8.4 | The document | 3.10 s | 363 ms |
| MySQL 8.4 | With suppliers | 3.35 s | 502 ms |
| MySQL 8.4 | The statements published | 3.51 s | 366 ms |
| MySQL 8.4 | Slowest statement | 1.71 s | 145 ms |
| MariaDB 11.4 | The document | 776 ms | 232 ms |
| MariaDB 11.4 | With suppliers | 898 ms | 326 ms |
| MariaDB 11.4 | The statements published | 1,155 ms | 221 ms |
| MariaDB 11.4 | Slowest statement | 377 ms | 83 ms |
| SQLite | The document | 681 ms | 385 ms |
| SQLite | With suppliers | 798 ms | 590 ms |
| SQLite | The statements published | 936 ms | 399 ms |
| SQLite | Slowest statement | 258 ms | 178 ms |

The same reads on the statistics the load leaves:

| Engine | Read, as loaded | Joined | Two levels |
|---|---|---|---|
| PostgreSQL 16 | The document | Past 30 s a statement | 4.80 s |
| PostgreSQL 16 | With suppliers | Past 30 s a statement | 50.2 s, 47.5 s of it a closed read |
| PostgreSQL 16 | The statements published | Past 30 s a statement | 4.78 s |
| MySQL 8.4 | The document | Not run | 4 min 16 s |
| MySQL 8.4 | With suppliers | Not run | 9 min 22 s, 5 min 21 s of it a closed read |
| MySQL 8.4 | The statements published | Not run | 4 min 12 s |
| MariaDB 11.4 | The document | Unfinished at 25 min | 60.4 s, 32.2 s of it a closed read |
| MariaDB 11.4 | With suppliers | Not run | A closed read stopped past 14 min |
| SQLite | The document | 42.8 s | 15.2 s |
| SQLite | With suppliers | 57.9 s | 28.8 s |
| SQLite | The statements published | 51.8 s | 15.0 s |
| SQLite | Slowest statement | 18.1 s, the decided groups | 14.3 s, a closed read |

| Reading | |
|---|---|
| The bar | 0.25 s a statement. Analyzed, the two-level form meets it on every engine |
| A closed read as loaded | In the two-level form the findings closed by a patch or a supplier's statement dominate every as-loaded read where they are slow: seconds on PostgreSQL, minutes on MySQL and MariaDB. The joined form is slower before it reaches them |
| PostgreSQL as loaded | The run's background analysis reaches some tables before its as-loaded reads, and how many varies by run; § Statements as loaded holds a database with none |
| The build's bound | The decided issues the build holds open cost PostgreSQL 54 ms a statement on one build against 2 ms for every decided issue of the product, read at each level of the document: 350 ms against 239 ms for the document. MySQL reads the document in 363 ms against 380 ms, MariaDB in 232 ms against 253 ms, SQLite in 385 ms against 354 ms |

## A long-lived product

The same build as a long-lived product holds it: each kernel binary and the
root an image with 1,000 closed versions behind its open one, and 100,000
issues the build does not hold each decided in the product. Timed as § VEX
document reads times it.

The unbounded form is the two-level form with the open image version picked
out in an aggregate over every version of the node, and every issue decided
in the product read first.

| Engine | Read, analyzed | Joined | Unbounded | Two levels |
|---|---|---|---|---|
| PostgreSQL 16 | The document | 626 ms | 4.15 s | 559 ms |
| PostgreSQL 16 | With suppliers | 737 ms | 4.38 s | 686 ms |
| PostgreSQL 16 | The statements published | 828 ms | 4.27 s | 681 ms |
| PostgreSQL 16 | Slowest statement | 240 ms | 1.68 s | 122 ms |
| MySQL 8.4 | The document | 3.39 s | 6.61 s | 695 ms |
| MySQL 8.4 | With suppliers | 3.43 s | 8.58 s | 844 ms |
| MySQL 8.4 | The statements published | 3.78 s | 7.25 s | 833 ms |
| MySQL 8.4 | Slowest statement | 1.81 s | 1.85 s | 154 ms |
| MariaDB 11.4 | The document | 1.82 s | 6.42 s | 602 ms |
| MariaDB 11.4 | With suppliers | 1.94 s | 8.07 s | 704 ms |
| MariaDB 11.4 | The statements published | 2.49 s | 6.57 s | 726 ms |
| MariaDB 11.4 | Slowest statement | 962 ms | 1.70 s | 171 ms |
| SQLite | The document | 1.25 s | 4.90 s | 970 ms |
| SQLite | With suppliers | 1.37 s | 5.52 s | 1.18 s |
| SQLite | The statements published | 1.72 s | 5.29 s | 1.25 s |
| SQLite | Slowest statement | 594 ms | 2.08 s | 268 ms |

The two-level form on the statistics the load leaves:

| Engine | Read, as loaded | Two levels |
|---|---|---|
| PostgreSQL 16 | The document | 765 ms |
| PostgreSQL 16 | With suppliers | 36.7 s, 36.0 s of it a closed read |
| PostgreSQL 16 | The statements published | 991 ms |
| MySQL 8.4 | The document | 10 min 5 s |
| MySQL 8.4 | With suppliers | 15 min 45 s |
| MySQL 8.4 | The statements published | Unfinished at the run's 4 h limit |
| MariaDB 11.4 | The document | 57.1 s, 31.3 s of it a closed read |
| SQLite | The document | 60.8 s |
| SQLite | With suppliers | 74.8 s |
| SQLite | The statements published | 68.8 s |

| Reading | |
|---|---|
| Rebuilds | An image's closed versions stay beside its node. Read through every version of the node, each row costs the image's history |
| Decided issues | A product's decided issues outnumber a build's. Every one of them listed, the findings are read against 100,300 issues where the build holds 300 |
| Slowest statement | Analyzed, on the three servers the issues decided that the build holds open, 122 ms to 171 ms. On SQLite the occurrences stated one by one, 268 ms, past the bar |

## Statements as loaded

Each statement on its own, on statistics frozen before the load: automatic
analysis off on every table on PostgreSQL, InnoDB's automatic recalculation off
on MySQL. A statement stopped at 30 s is shown as past it; a read stops at its
first failed statement, and a statement it never reached is shown as not run.
Two runs, the slower shown.

| Statement | PostgreSQL, joined | PostgreSQL, two levels | MySQL 8.4, joined | MySQL 8.4, two levels |
|---|---|---|---|---|
| The groups the document states | Past 30 s | 46 ms | Past 30 s | 22.7 s |
| The groups the published statements apply to | Not run | 46 ms | Not run | 23.2 s |
| The issues decided that the build holds open | Not run | 130 ms | Not run | Under 20 ms |
| The occurrences the document states one by one | Not run | 43 ms | Not run | Not run |
| The findings the build's patches closed | Not run | 4.27 s | Not run | Past 30 s |
| The findings suppliers' statements closed | Not run | Past 30 s | Not run | Not run |

| Reading | |
|---|---|
| PostgreSQL | Never analyzed, it estimates a lookup on each key at one row and joins the graph or the decisions unkeyed |
| MySQL and MariaDB | A plan is chosen from whatever the background statistics have reached; a lookup per row that is not on a primary key can go through the index on a closing scan, or a build's whole set of open findings |
| The decided read | The issues decided are a few hundred of 8,327, so reading them first bounds every engine |
| The two-level forms | The unbounded form reads each statement within a tenth of these, on both engines |

## Failed alternatives

Each alternative read the same answers, and was measured against the rule it
lost to.

| Alternative | Measured | Loses to |
|---|---|---|
| The open node and image version joined beside each finding | Past a minute on PostgreSQL as loaded | The identifier asked of each row |
| The open image version picked out in an aggregate over every version of the node | Analyzed, with every component an image and 1,000 rebuilds behind the kernel binaries and the root: 4.9 s against 0.21 s for the document on MariaDB. Never analyzed: 209 ms against 44 ms for the decided groups on PostgreSQL | The open version asked of each node |
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
| The shipping and none-open checks in WHERE | Past 30 s for the patched findings on PostgreSQL never analyzed, against 4.27 s in HAVING | The checks asked per issue and component in HAVING |
| The build's open issues read apart and met with the decided issues in the application | Analyzed, one build: 20 ms against 54 ms on PostgreSQL, 56 ms against 10 ms on MySQL. Long-lived: 250 ms against 130 ms on MySQL | The build asked in the statement |
| The build asked of each decision occurrence as a value | Analyzed, long-lived: 187 ms against 130 ms on PostgreSQL, 338 ms against 130 ms on MySQL, 223 ms against 166 ms on MariaDB | The build asked in the statement |
