# Remediation measurements

Benchmark runs behind the remediation rules.

## Contents

- [VEX document reads](#vex-document-reads)
- [A long-lived product](#a-long-lived-product)
- [Statements as loaded](#statements-as-loaded)
- [Closed reads as sets](#closed-reads-as-sets)
- [Open reads as sets](#open-reads-as-sets)
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
two-level form groups each issue at each component, then each name and stated
package identifier, asking the stated identifier and the open image version of
each row; § Open reads as sets holds the form `design-docs/remediation-vex.md`
§ Reads describes.

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
| A closed read as loaded | In the two-level form the findings closed by a patch or a supplier's statement dominate every as-loaded read where they are slow: seconds on PostgreSQL, minutes on MySQL and MariaDB. The joined form is slower before it reaches them. § Closed reads as sets holds them read as sets |
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

## Closed reads as sets

Justifies the closed reads of `design-docs/remediation-vex.md` § Reads. The
grouped form asks the shipping, open and latest checks of each issue and
component in `HAVING`, in one statement. The sets form is the one
`design-docs/remediation-vex.md` § Reads describes.

Each closed read on its own, over the fixture of § VEX document reads, timed
three times. Never analyzed is every table's statistics removed and background
statistics off before the load; background is the statistics the server
gathers on its own during the load. A statement past 30 s is stopped.

| Engine | Statistics | Read | Grouped | Sets |
|---|---|---|---|---|
| PostgreSQL 16 | Never analyzed | Patched | 72 to 80 ms | 83 to 85 ms |
| PostgreSQL 16 | Never analyzed | Suppliers' statements | 76 to 80 ms | 122 to 125 ms |
| PostgreSQL 16 | Background, three runs | Patched | 70 ms; 4.5 s; 22.0 s | 55 to 74 ms |
| PostgreSQL 16 | Background, three runs | Suppliers' statements | 37.8 s; past 30 s; 62 to 71 ms | 79 to 81 ms |
| PostgreSQL 16 | Analyzed | Patched | 83 to 130 ms | 52 to 55 ms |
| PostgreSQL 16 | Analyzed | Suppliers' statements | 64 to 75 ms | 70 to 72 ms |
| MySQL 8.4 | Never analyzed | Patched | Past 60 s | 143 to 146 ms |
| MySQL 8.4 | Never analyzed | Suppliers' statements | Past 60 s | 135 to 140 ms |
| MySQL 8.4 | Background | Patched | Past 30 s, three runs | 137 to 147 ms |
| MySQL 8.4 | Background | Suppliers' statements | Past 30 s, three runs | 186 to 192 ms |
| MySQL 8.4 | Analyzed | Patched | 115 to 129 ms | 109 to 116 ms |
| MySQL 8.4 | Analyzed | Suppliers' statements | 129 to 139 ms | 200 to 213 ms |
| MariaDB 11.4 | Background | Patched | Past 30 s | 53 to 58 ms |
| MariaDB 11.4 | Background | Suppliers' statements | Past 30 s | 76 to 88 ms |
| MariaDB 11.4 | Analyzed | Patched | 77 to 81 ms | 59 to 66 ms |
| MariaDB 11.4 | Analyzed | Suppliers' statements | 86 to 96 ms | 69 to 89 ms |
| SQLite | No `sqlite_stat1` | Patched | 13.5 to 14.4 s | 146 to 152 ms |
| SQLite | No `sqlite_stat1` | Suppliers' statements | 13.6 to 13.7 s | 307 to 308 ms |
| SQLite | Analyzed | Patched | 140 to 151 ms | 94 to 98 ms |
| SQLite | Analyzed | Suppliers' statements | 147 to 156 ms | 115 to 120 ms |

The same, through `TestMeasureTheVEXDocumentOfTheHubBuild`: the document, with
suppliers, and the statements published.

| Engine | Product | Statistics | Grouped | Sets |
|---|---|---|---|---|
| PostgreSQL 16 | One build | As loaded | 532 ms; stopped past 30 s at the suppliers' statements; 687 ms | 511 / 645 / 639 ms |
| PostgreSQL 16 | One build | Analyzed | 361 / 486 / 407 ms | 313 / 426 / 365 ms |
| PostgreSQL 16 | Long-lived | As loaded | 810 ms; stopped past 30 s at the suppliers' statements; 674 ms | 1.20 / 1.29 / 1.62 s |
| PostgreSQL 16 | Long-lived | Analyzed | 636 / 768 / 781 ms | 463 / 577 / 553 ms |
| MySQL 8.4 | One build | As loaded | Stopped past 30 s at a closed read; 525 ms; 358 ms | Stopped past 30 s at the occurrences stated one by one; 541 ms; 362 ms |
| MySQL 8.4 | One build | Analyzed | 360 / 513 / 373 ms | 356 / 563 / 387 ms |
| MySQL 8.4 | Long-lived | As loaded | Stopped past 30 s at the decided issues; 1.08 s; 1.04 s | Stopped past 30 s at the decided issues; 1.11 s; 1.08 s |
| MySQL 8.4 | Long-lived | Analyzed | 688 / 897 / 825 ms | 707 / 877 / 841 ms |
| MariaDB 11.4 | One build | As loaded | Each stopped past 30 s at a closed read | 29.6 / 30.2 / 31.3 s, 12.5 s of it the occurrences stated one by one |
| MariaDB 11.4 | One build | Analyzed | 206 to 213 / 306 to 315 / 209 to 216 ms, three runs | 200 to 233 / 304 to 333 / 211 to 237 ms, three runs |
| MariaDB 11.4 | Long-lived | As loaded | Each stopped past 30 s at a closed read | 25.9 / 26.1 / 27.4 s, 10.7 s of it the occurrences stated one by one |
| MariaDB 11.4 | Long-lived | Analyzed | 599 / 716 / 739 ms | 575 / 671 / 705 ms |
| SQLite | One build | As loaded | 18.0 / 33.6 / 18.1 s, 17.6 s of it a closed read | 1.21 / 1.65 / 1.35 s |
| SQLite | One build | Analyzed | 435 / 739 / 415 ms | 375 / 562 / 396 ms |
| SQLite | Long-lived | As loaded | 71.4 / 75.0 / 70.6 s | 46.5 / 47.5 / 55.9 s, 23.7 s of it the decided groups |
| SQLite | Long-lived | Analyzed | 993 ms / 1.20 / 1.31 s | 1.01 / 1.22 / 1.29 s |

| Reading | |
|---|---|
| Plans as loaded | Grouped, each engine probes the build's findings or graph per closed finding through whichever index its statistics favor: PostgreSQL the build's whole finding index for the latest row, SQLite and MySQL the build's open findings for the open check, MySQL every open node through the closing scan's index for the shipping check. Which statistics turn it catastrophic differs by run, so never analyzed is no worst case on PostgreSQL |
| Sets as loaded | On this fixture every closed read stays under 0.35 s on every engine, never analyzed or as the background left it |
| Sets as loaded, many builds | MySQL reads the findings of the closed issues through the issue index across every build holding them: 2.6 s with 11 builds holding the issues, against 0.22 s analyzed |
| Sets analyzed | As fast as grouped or faster on every engine but MySQL, where the suppliers' statements read the findings of their issues once more: 200 to 213 ms against 129 to 139 ms, 50 ms more for the document with suppliers |
| Sets, a long history | With 50 rows at each occurrence, 310,000 findings closed and 620,000 rows of their issues, SQLite reads the suppliers' statements in 1.4 to 1.6 s against 0.55 to 0.61 s grouped, analyzed, since every row of the issues reaches the application. The other three engines stay faster than grouped |
| As loaded, what remains | The open reads: the occurrences stated one by one on MariaDB and MySQL, the decided groups and occurrences on SQLite, the decided issues on MySQL for a long-lived product. § Open reads as sets holds them read as sets |

## Open reads as sets

Justifies the reads from decisions in `design-docs/remediation-vex.md` § Reads.
The statement form asks each finding's decisions inside one statement: the
decided groups, and each occurrence's matching decisions one by one, beside
the decided issues bounded by each decision occurrence's occurrence in the
build. The sets form is the one `design-docs/remediation-vex.md` § Reads
describes, with the closed reads as sets in both.

Through `TestMeasureTheVEXDocumentOfTheHubBuild`, over the fixture of § VEX
document reads and its long-lived product: the document, with suppliers, and
the statements published. A statement past 30 s is stopped.

| Engine | Product | Statistics | Statement form | Sets |
|---|---|---|---|---|
| PostgreSQL 16 | One build | As loaded | 623 / 784 / 809 ms | 265 / 405 / 333 ms |
| PostgreSQL 16 | One build | Analyzed | 351 / 466 / 424 ms | 174 / 286 / 187 ms |
| PostgreSQL 16 | Long-lived | As loaded | 796 / 947 ms / 1.03 s | 321 / 487 / 418 ms |
| PostgreSQL 16 | Long-lived | Analyzed | 523 / 655 / 662 ms | 232 / 357 / 288 ms |
| MySQL 8.4 | One build | As loaded | Stopped past 30 s at the occurrences stated one by one; 597 ms; 392 ms | 398 / 580 / 413 ms |
| MySQL 8.4 | One build | Analyzed | 387 / 605 / 388 ms | 360 / 575 / 367 ms |
| MySQL 8.4 | Long-lived | As loaded | Stopped past 30 s at the decided issues; 1.22 s; 1.21 s | 747 / 934 / 883 ms, the slowest statement 279 to 362 ms, the decided issues |
| MySQL 8.4 | Long-lived | Analyzed | 1.06 / 1.25 / 1.19 s | 606 / 681 / 755 ms, the slowest statement 195 to 223 ms |
| MariaDB 11.4 | One build | As loaded | 28.5 / 28.5 / 30.5 s, 11.6 s of it the occurrences stated one by one | 186 / 315 / 227 ms |
| MariaDB 11.4 | One build | Analyzed | 221 / 325 / 230 ms | 184 / 288 / 189 ms |
| MariaDB 11.4 | Long-lived | As loaded | 26.6 / 27.0 / 29.3 s | 473 / 578 / 544 ms, the slowest statement about 200 ms, the decided issues |
| MariaDB 11.4 | Long-lived | Analyzed | 678 / 759 / 803 ms | 227 / 359 / 288 ms |
| SQLite | One build | As loaded | 1.31 / 1.73 / 1.46 s | 311 / 786 / 375 ms |
| SQLite | One build | Analyzed | 415 / 600 / 434 ms | 273 / 465 / 293 ms |
| SQLite | Long-lived | As loaded | 47.3 / 47.4 / 55.0 s, 23.6 s of it the decided groups | 429 / 845 / 493 ms |
| SQLite | Long-lived | Analyzed | 973 ms / 1.14 / 1.27 s | 242 / 392 / 249 ms |

The decided issues alone, each form timed three times on the statistics the
load leaves and after analysis. The occurrence form asks, of each decision
occurrence, an open finding of the build at its occurrence and issue; the
issue form asks, of each issue, such a finding; the set form bounds the issue
by the build's open issues as one set.

| Engine | Product | Occurrence form, as loaded / analyzed | Issue form | Set form |
|---|---|---|---|---|
| PostgreSQL 16 | One build | 126 to 130 / 51 to 55 ms | 37 to 39 / 4 ms | 36 to 38 / 4 ms |
| PostgreSQL 16 | Long-lived | 124 to 140 / 130 to 144 ms | 43 to 46 / 45 to 49 ms | 43 to 50 / 45 to 47 ms |
| MySQL 8.4 | One build | 14 to 16 / 9 to 12 ms | 13 / 13 ms | 13 / 13 ms |
| MySQL 8.4 | Long-lived | Past 30 s / 133 to 135 ms | 209 to 212 / 129 to 132 ms | 208 to 214 / 128 to 129 ms |
| MariaDB 11.4 | One build | 11 to 14 / 5 to 7 ms | Not run | 11 to 13 / 10 to 11 ms |
| MariaDB 11.4 | Long-lived | 186 / 168 to 218 ms | 180 to 184 / 57 to 59 ms | 174 to 179 / 56 to 60 ms |
| SQLite | One build | 7 / 7 to 9 ms | 4 / 4 ms | 11 / 14 ms |
| SQLite | Long-lived | 103 to 105 / 98 to 99 ms | 167 to 168 / 164 to 170 ms | 45 / 17 to 18 ms |

| Reading | |
|---|---|
| The causes | As loaded, MariaDB and MySQL read every decision of the product at each open occurrence stated one by one, SQLite every open finding of the build per decided group, and MySQL every finding at the kernel occurrence per decision occurrence for the decided issues |
| Sets as loaded | On this fixture every read of a document stays under 1 s on every engine. The slowest statement is the decided issues on MySQL and MariaDB for a long-lived product, 0.2 to 0.36 s, which reads the product's decision occurrences of the build's open issues |
| Sets analyzed | Faster than the statement form on every engine and fixture |
| What grows with rows | The set form reads the build's open issues once per document, so it grows with the build's open findings, never with the product's decisions per finding. Against the occurrence form on one build it costs 4 ms more on MySQL, 5 ms on MariaDB and 7 ms on SQLite, and the document reads it once where the statement form read it twice |
| What is fixed | The sets add a statement per document for the issues each decision occurrence is filed under, and one for the identifiers |
| The answers | Matched in the application against the statement form, on SQLite for one build and a long-lived product, public and public with private: the same covered and affected groups and occurrences, row for row |

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
| The closed reads as a window over the build's findings | 1.46 s on MySQL and 1.18 s on MariaDB, analyzed | The closed findings read as sets |
| The open occurrences as a row value `NOT IN` a subquery | Past a minute on MySQL | The closed findings read as sets |
| The open occurrences as `NOT IN` the build's whole open set | 0.60 s on MySQL and 0.66 s on MariaDB, analyzed | The closed findings read as sets |
| The open occurrences as `NOT IN` the open set of the closed issues, read once | MySQL as loaded 0.28 s; analyzed, MariaDB 0.26 s against 0.07 s and SQLite 0.8 s to 1.15 s against 0.13 s | The closed findings read as sets |
| The latest row at an occurrence as `IN` the grouped maxima | 1.7 s on PostgreSQL as loaded | The latest row asked of each row |
| The latest row as a scalar maximum per row | Past a minute on MySQL as loaded | The latest row asked of each row |
| The component's shipping asked with its open check in the aggregate | 1.15 s on PostgreSQL as loaded, through the root index | The closed findings read as sets |
| The shipping and none-open checks in WHERE | Past 30 s for the patched findings on PostgreSQL never analyzed, against 4.27 s in HAVING | The closed findings read as sets |
| The build's open issues read apart and met with the decided issues in the application | Analyzed, one build: 20 ms against 54 ms on PostgreSQL, 56 ms against 10 ms on MySQL. Long-lived: 250 ms against 130 ms on MySQL | The build asked in the statement |
| The build asked of each decision occurrence as a value | Analyzed, long-lived: 187 ms against 130 ms on PostgreSQL, 338 ms against 130 ms on MySQL, 223 ms against 166 ms on MariaDB | The build asked in the statement |
| The shipping, open and latest checks asked per issue and component in `HAVING`, in one statement | Past 30 s for a closed read as loaded on PostgreSQL, MySQL and MariaDB, 13.5 s on SQLite with no statistics | The closed findings read as sets |
| The latest row read apart from the open findings of the closed issues, as grouped maxima | 178 to 225 ms against 115 to 120 ms for the suppliers' statements on SQLite, analyzed | The findings of the closed issues read once |
| The latest row read by the closed findings' occurrences as a constant list | 359 to 411 ms against 115 to 120 ms for the suppliers' statements on SQLite, analyzed | The findings of the closed issues read once |
| Every finding of the build read once for the suppliers' statements | 180 to 213 ms against 200 to 213 ms on MySQL, analyzed, and every finding of a build read where no supplier's statement closed any | The closed findings read first, then the findings of their issues |
| The decided issues asked of each decision occurrence at its occurrence in the build | Past 30 s on MySQL as loaded, long-lived, against 208 to 214 ms | The build's open issues as one set |
| The decided issues asked of each issue as a correlated open finding of the build | 167 ms against 45 ms on SQLite as loaded, long-lived; elsewhere within the set form's runs | The build's open issues as one set |
| Every issue the product decided read whole, and met with the build's in the application | Long-lived, as loaded: 188 to 194 ms on MySQL, 111 to 142 ms on MariaDB, 76 to 100 ms on PostgreSQL, 70 to 79 ms on SQLite, and it grows with every build the product had | The build's open issues as one set |
| The decided groups and occurrences asked of each finding inside one statement | Past 30 s on MySQL, 28.5 s on MariaDB, 23.6 s on SQLite, as loaded | The sets matched in the application |
| The decided issues bounded by the names filed under the build's open issues | 273 to 283 ms against 222 to 224 ms on MySQL as loaded, long-lived; the same analyzed | The build's open issues as one set |
