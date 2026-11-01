# Remediation measurements

Benchmark runs behind the remediation rules.

## Contents

- [VEX document reads](#vex-document-reads)
- [A long-lived product](#a-long-lived-product)
- [Statements as loaded](#statements-as-loaded)
- [Closed reads as sets](#closed-reads-as-sets)
- [Open reads as sets](#open-reads-as-sets)
- [Closed reads over history](#closed-reads-over-history)
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

Justifies reading the closed findings as sets, in
`design-docs/remediation-vex.md` § Reads. The grouped form asks the shipping,
open and latest checks of each issue and component in `HAVING`, in one
statement. The every-row form reads the build's closed findings into the
application row by row, then the findings of their issues, every row of them
for the suppliers' statements. The bounded form § Reads describes is measured
against both in § Closed reads over history.

Each closed read on its own, over the fixture of § VEX document reads, timed
three times. Never analyzed is every table's statistics removed and background
statistics off before the load; background is the statistics the server
gathers on its own during the load. A statement past 30 s is stopped.

| Engine | Statistics | Read | Grouped | Every row |
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

| Engine | Product | Statistics | Grouped | Every row |
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
| Every row as loaded | On this fixture every closed read stays under 0.35 s on every engine, never analyzed or as the background left it |
| Every row as loaded, many builds | MySQL reads the findings of the closed issues through the issue index across every build holding them: 2.6 s with 11 builds holding the issues, against 0.22 s analyzed |
| Every row analyzed | As fast as grouped or faster on every engine but MySQL, where the suppliers' statements read the findings of their issues once more: 200 to 213 ms against 129 to 139 ms, 50 ms more for the document with suppliers |
| Every row, a long history | With 50 rows at each occurrence, 310,000 findings closed and 620,000 rows of their issues, SQLite reads the suppliers' statements in 1.4 to 1.6 s against 0.55 to 0.61 s grouped, analyzed, since every row of the issues reaches the application. The other three engines stay faster than grouped |
| As loaded, what remains | The open reads: the occurrences stated one by one on MariaDB and MySQL, the decided groups and occurrences on SQLite, the decided issues on MySQL for a long-lived product |

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

The shapes of § Closed reads over history, against the bounded closed reads
alone, one engine at a time.

| Engine | Shape | Statistics | Statement form | Sets |
|---|---|---|---|---|
| PostgreSQL 16 | Long history | As loaded | 359 / 845 / 381 ms | 303 / 753 / 326 ms |
| PostgreSQL 16 | Long history | Analyzed | 391 / 903 / 426 ms | 304 / 763 / 313 ms |
| PostgreSQL 16 | Many builds | As loaded | 286 / 626 / 272 ms | 155 / 499 / 173 ms |
| PostgreSQL 16 | Many builds | Analyzed | 241 / 576 / 270 ms | 161 / 501 / 171 ms |
| MySQL 8.4 | Long history | As loaded | past 30 s / 2.86 s / 1.48 s | 1.37 / 2.71 / 1.30 s |
| MySQL 8.4 | Long history | Analyzed | 1.27 / 2.69 / 1.32 s | 1.27 / 2.67 / 1.35 s |
| MySQL 8.4 | Many builds | As loaded | past 30 s / 794 ms / 512 ms | 934 ms / 1.79 s / 915 ms |
| MySQL 8.4 | Many builds | Analyzed | 454 / 802 / 470 ms | 331 / 652 / 321 ms |
| MariaDB 11.4 | Long history | As loaded | 31.1 / 30.0 / 31.7 s | 344 ms / 1.01 s / 370 ms |
| MariaDB 11.4 | Long history | Analyzed | 467 ms / 1.11 s / 482 ms | 342 ms / 1.06 s / 385 ms |
| MariaDB 11.4 | Many builds | As loaded | 34.2 / 33.5 / 33.8 s | 247 / 551 / 260 ms |
| MariaDB 11.4 | Many builds | Analyzed | 260 / 551 / 268 ms | 174 / 479 / 215 ms |
| SQLite | Long history | As loaded | 1.29 / 1.90 / 1.45 s | 535 ms / 1.13 s / 555 ms |
| SQLite | Long history | Analyzed | 408 / 896 / 454 ms | 435 / 954 / 469 ms |
| SQLite | Many builds | As loaded | 984 ms / 1.17 s / 1.15 s | 166 / 323 / 187 ms |
| SQLite | Many builds | Analyzed | 328 / 495 / 343 ms | 169 / 393 / 200 ms |

| Reading | |
|---|---|
| The causes | As loaded, MariaDB and MySQL read every decision of the product at each open occurrence stated one by one, SQLite every open finding of the build per decided group, and MySQL every finding at the kernel occurrence per decision occurrence for the decided issues |
| Sets as loaded | On this fixture every read of a document stays under 1 s on every engine. The slowest statement is the decided issues on MySQL and MariaDB for a long-lived product, 0.2 to 0.36 s, which reads the product's decision occurrences of the build's open issues |
| Sets analyzed | Faster than the statement form on every engine and fixture |
| What grows with rows | The set form reads the build's open issues once per document, so it grows with the build's open findings, never with the product's decisions per finding. Against the occurrence form on one build it costs 4 ms more on MySQL, 5 ms on MariaDB and 7 ms on SQLite, and the document reads it once where the statement form read it twice |
| What is fixed | The sets add a statement per document for the issues each decision occurrence is filed under, and one for the identifiers |
| Sets over history | Faster than the statement form or within 0.06 s of it in every cell, but MySQL with many builds as loaded: 1.79 s with suppliers against 794 ms, the closed reads' open findings 0.6 s a read against 66 ms in the run of the statement form, the same statement on statistics MySQL had not settled |
| Issues with a flaw recorded here | The sets name fewer issues to it, and MySQL with a long history analyzed then reads it through the issue index, 0.9 to 1.3 s against 0.10 to 0.15 s. The kind index of § Closed reads over history takes it to 2.5 ms in both |
| Past 1 s | MySQL with a long history: the two groupings of the closed reads, 1.0 to 1.2 s each. PostgreSQL never analyzed, one build: 5.07 s with suppliers, 4.6 s of it the latest row check, the same statement 0.3 s in the run of the statement form. MariaDB with a long history, with suppliers: 1.01 to 1.06 s. SQLite with a long history as loaded, with suppliers: 1.13 s |
| The answers | Matched in the application against the statement form, on SQLite for one build and a long-lived product, public and public with private: the same covered and affected groups and occurrences, row for row |

## Closed reads over history

Justifies the bounded closed reads of `design-docs/remediation-vex.md` § Reads:
the closed findings grouped in their statement, the latest row asked by key,
and the open findings of the closed issues read once. Grouped and every row are
the forms of § Closed reads as sets; bounded is the form § Reads describes.

| Shape | What the build holds |
|---|---|
| One build | The build of § VEX document reads |
| Long-lived | The build as § A long-lived product holds it |
| Long history | 50 rows at each occurrence of an issue a patch or a supplier's statement closed in the build, each closed as the occurrence is: 267,750 rows closed by them among about 785,000 rows of their issues |
| Many builds | Every finding of the build, copied into ten more builds of the product: 84,319 findings in each of eleven |

Timed as § VEX document reads times it: the document / with suppliers / the
statements published, as loaded and after every table is analyzed. A statement
past 30 s is stopped. The long-lived product's every-row cells, and its grouped
cells but PostgreSQL's, are the runs of § Closed reads as sets.

| Engine | Shape | Statistics | Grouped | Every row | Bounded |
|---|---|---|---|---|---|
| PostgreSQL 16 | One build | As loaded | 283 ms / past 30 s / 284 ms | 575 / 753 / 700 ms | 1.86 s / 536 ms / 211 ms |
| PostgreSQL 16 | One build | Analyzed | 348 / 462 / 406 ms | 333 / 435 / 403 ms | 301 / 637 / 370 ms |
| PostgreSQL 16 | Long-lived | As loaded | 597 / 714 / 687 ms | 1.20 / 1.29 / 1.62 s | 523 / 829 / 531 ms |
| PostgreSQL 16 | Long-lived | Analyzed | 606 / 738 / 752 ms | 463 / 577 / 553 ms | 487 / 849 / 649 ms |
| PostgreSQL 16 | Long history | As loaded | 394 ms / 1.08 s / 407 ms | 422 ms / 1.27 s / 418 ms | 359 / 845 / 381 ms |
| PostgreSQL 16 | Long history | Analyzed | 1.31 / 3.27 / 1.17 s | 419 ms / 1.34 s / 475 ms | 391 / 903 / 426 ms |
| PostgreSQL 16 | Many builds | As loaded | 1.29 s / 1.23 s / 983 ms | 319 / 417 / 323 ms | 286 / 626 / 272 ms |
| PostgreSQL 16 | Many builds | Analyzed | 962 ms / 1.21 s / 981 ms | 287 / 383 / 327 ms | 241 / 576 / 270 ms |
| MySQL 8.4 | One build | As loaded | past 30 s / 549 ms / 394 ms | past 30 s / 579 ms / 385 ms | past 30 s / 610 ms / 374 ms |
| MySQL 8.4 | One build | Analyzed | 385 / 534 / 372 ms | 389 / 564 / 364 ms | 374 / 612 / 382 ms |
| MySQL 8.4 | Long-lived | As loaded | past 30 s / 1.08 s / 1.04 s | past 30 s / 1.11 s / 1.08 s | past 30 s / 1.28 s / 1.13 s |
| MySQL 8.4 | Long-lived | Analyzed | 688 / 897 / 825 ms | 707 / 877 / 841 ms | 703 / 972 / 882 ms |
| MySQL 8.4 | Long history | As loaded | past 30 s / past 30 s / past 30 s | past 30 s / 3.47 s / 1.45 s | past 30 s / 2.86 s / 1.48 s |
| MySQL 8.4 | Long history | Analyzed | 1.36 / 6.86 / 1.37 s | 2.25 / 3.60 / 2.28 s | 1.27 / 2.69 / 1.32 s |
| MySQL 8.4 | Many builds | As loaded | past 30 s / 1.44 s / 862 ms | past 30 s / 848 ms / 936 ms | past 30 s / 794 ms / 512 ms |
| MySQL 8.4 | Many builds | Analyzed | 852 ms / 1.35 s / 847 ms | 588 / 790 / 598 ms | 454 / 802 / 470 ms |
| MariaDB 11.4 | One build | As loaded | past 30 s / past 30 s / past 30 s | 28.4 / 27.9 / 30.6 s | 28.8 / 30.7 / 31.7 s |
| MariaDB 11.4 | One build | Analyzed | 228 / 330 / 227 ms | 258 / 375 / 264 ms | 204 / 484 / 215 ms |
| MariaDB 11.4 | Long-lived | As loaded | past 30 s / past 30 s / past 30 s | 25.9 / 26.1 / 27.4 s | 29.1 / 28.9 / 30.8 s |
| MariaDB 11.4 | Long-lived | Analyzed | 599 / 716 / 739 ms | 575 / 671 / 705 ms | 596 / 869 / 721 ms |
| MariaDB 11.4 | Long history | As loaded | past 30 s / past 30 s / past 30 s | 29.5 / 32.2 / 31.5 s | 31.1 / 30.0 / 31.7 s |
| MariaDB 11.4 | Long history | Analyzed | 26.3 / 52.6 / 25.9 s | 649 ms / 1.34 s / 648 ms | 467 ms / 1.11 s / 482 ms |
| MariaDB 11.4 | Many builds | As loaded | past 30 s / past 30 s / past 30 s | 30.8 / 31.7 / 32.4 s | 34.2 / 33.5 / 33.8 s |
| MariaDB 11.4 | Many builds | Analyzed | 25.5 / 52.6 / 26.9 s | 671 ms / 1.09 s / 689 ms | 260 / 551 / 268 ms |
| SQLite | One build | As loaded | 15.2 / 29.3 / 15.7 s | 1.11 / 1.48 / 1.24 s | 1.11 / 1.26 / 1.31 s |
| SQLite | One build | Analyzed | 396 / 599 / 398 ms | 338 / 518 / 346 ms | 265 / 464 / 271 ms |
| SQLite | Long-lived | As loaded | 71.4 / 75.0 / 70.6 s | 46.5 / 47.5 / 55.9 s | 50.7 / 50.5 / 60.4 s |
| SQLite | Long-lived | Analyzed | 993 ms / 1.20 s / 1.31 s | 1.01 / 1.22 / 1.29 s | 938 ms / 1.10 s / 1.20 s |
| SQLite | Long history | As loaded | 17.1 / 32.4 / 17.4 s | 3.02 / 6.68 / 3.20 s | 1.29 / 1.90 / 1.45 s |
| SQLite | Long history | Analyzed | 2.03 / 2.75 / 1.97 s | 566 ms / 2.81 s / 583 ms | 408 / 896 / 454 ms |
| SQLite | Many builds | As loaded | 15.7 / 30.9 / 16.3 s | 1.64 / 2.29 / 1.79 s | 984 ms / 1.17 s / 1.15 s |
| SQLite | Many builds | Analyzed | 1.30 / 2.15 / 1.32 s | 1.01 / 1.67 / 1.04 s | 328 / 495 / 343 ms |

Each closed read alone, through the store: the patches / the suppliers'
statements.

| Engine | Shape | Statistics | Grouped | Every row | Bounded |
|---|---|---|---|---|---|
| PostgreSQL 16 | One build | As loaded | 88 ms / past 30 s | 100 / 124 ms | 75 / 308 ms |
| PostgreSQL 16 | One build | Analyzed | 113 / 93 ms | 79 / 91 ms | 73 / 317 ms |
| PostgreSQL 16 | Long history | As loaded | 229 / 795 ms | 265 / 837 ms | 213 / 447 ms |
| PostgreSQL 16 | Long history | Analyzed | 1.12 / 1.73 s | 262 / 874 ms | 217 / 533 ms |
| PostgreSQL 16 | Many builds | As loaded | 752 / 249 ms | 57 / 69 ms | 58 / 305 ms |
| PostgreSQL 16 | Many builds | Analyzed | 716 / 240 ms | 58 / 69 ms | 48 / 325 ms |
| MySQL 8.4 | One build | As loaded | 153 / 145 ms | 130 / 203 ms | 149 / 214 ms |
| MySQL 8.4 | One build | Analyzed | 139 / 146 ms | 128 / 177 ms | 157 / 222 ms |
| MySQL 8.4 | Long history | As loaded | 1.19 / 5.52 s | 1.07 / 2.10 s | 1.24 / 1.31 s |
| MySQL 8.4 | Long history | Analyzed | 1.10 / 5.28 s | 1.09 / 2.19 s | 1.13 / 1.30 s |
| MySQL 8.4 | Many builds | As loaded | 19.9 s / 525 ms | 211 / 183 ms | 218 / 292 ms |
| MySQL 8.4 | Many builds | Analyzed | 385 / 481 ms | 179 / 187 ms | 193 / 293 ms |
| MariaDB 11.4 | One build | As loaded | past 30 s / past 30 s | 66 / 80 ms | 70 / 267 ms |
| MariaDB 11.4 | One build | Analyzed | 78 / 88 ms | 70 / 80 ms | 66 / 255 ms |
| MariaDB 11.4 | Long history | As loaded | past 30 s / past 30 s | 287 ms / 1.85 s | 253 / 620 ms |
| MariaDB 11.4 | Long history | Analyzed | 25.4 / 27.1 s | 263 / 658 ms | 252 / 635 ms |
| MariaDB 11.4 | Many builds | As loaded | past 30 s / past 30 s | 687 / 989 ms | 63 / 289 ms |
| MariaDB 11.4 | Many builds | Analyzed | 25.6 / 25.8 s | 231 / 389 ms | 58 / 272 ms |
| SQLite | One build | As loaded | 14.5 / 14.3 s | 158 / 311 ms | 72 / 128 ms |
| SQLite | One build | Analyzed | 160 / 173 ms | 105 / 125 ms | 62 / 156 ms |
| SQLite | Long history | As loaded | 15.3 / 15.6 s | 1.20 / 3.04 s | 387 / 519 ms |
| SQLite | Long history | Analyzed | 1.76 s / 690 ms | 380 ms / 2.24 s | 299 / 462 ms |
| SQLite | Many builds | As loaded | 14.3 / 14.3 s | 170 / 306 ms | 71 / 129 ms |
| SQLite | Many builds | Analyzed | 447 / 487 ms | 183 / 309 ms | 68 / 162 ms |

| Reading | |
|---|---|
| Grouped over history | Each check is asked per closed row, so the history multiplies it: analyzed, 52.6 s with suppliers on MariaDB for a long history and for many builds, and 5.3 s for the suppliers' statements on MySQL with a long history |
| Every row over history | Every row of the closed issues reaches the application: 2.24 s for the suppliers' statements on SQLite with a long history, analyzed, and 1.85 s on MariaDB as loaded |
| Bounded, per row | The grouping statements read each closed row of the build once, as grouped does: with a long history, 267,750 rows, 1.1 s for the patches on MySQL in either form, 0.2 to 0.4 s on MariaDB and SQLite, 0.12 to 0.16 s on PostgreSQL |
| Bounded, per occurrence | The latest row check costs each highest closed row one range, asked 200 at a time by constants: analyzed, about 84 µs on PostgreSQL, 12.7 ms of each statement's 16.4 ms the planning of its 200 terms, 51 to 67 µs on MariaDB, 16 to 31 µs on SQLite and 15 to 37 µs on MySQL. On one build analyzed it is what the suppliers' statements cost beyond grouped: 317 ms against 93 ms on PostgreSQL, 255 ms against 88 ms on MariaDB. Every form asking it by correlation is faster analyzed and stops past 20 s on MySQL as loaded (§ Failed alternatives) |
| Issues with a flaw recorded here | Asked of every issue a document names. Through the issue index, every finding of each issue is read for its kind: 1.3 s on MySQL with a long history analyzed, 1.0 to 1.7 s on SQLite as loaded. Through the kind index, 2.5 ms and 7 to 14 ms |
| PostgreSQL never analyzed | It takes the build named in every term of the latest row check to the build's own index, then tests every row of the build against the terms: 280 ms a statement, 4.07 s for the suppliers' statements of one build, where grouped stops past 30 s |
| Past 1 s as loaded | The open reads: the occurrences stated one by one on MariaDB, 27 to 34 s a document in every shape, and on MySQL; the decided issues on MySQL and the decided groups on SQLite for a long-lived product; on SQLite two of them 0.4 to 0.5 s each in every shape, the document 1.1 to 1.9 s; on PostgreSQL never analyzed two of them 0.85 s each for one build, the document 0.5 to 1.9 s from run to run. MySQL with a long history: the two groupings, 1.19 s each |
| Past 1 s analyzed | MySQL with a long history: the patches' grouping 1.03 s and the suppliers' 1.12 s, each reading 267,750 rows at about 4 µs, as grouped reads the patches; the document 1.27 s, with suppliers 2.69 s, published 1.32 s against 1.37 s grouped. MariaDB with a long history: 1.11 s with suppliers, 0.55 s of it the two groupings. SQLite: 0.94 to 1.20 s for a long-lived product, from the open reads |

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
| The latest row at an occurrence as `IN` the grouped maxima | 1.7 s on PostgreSQL as loaded | The closed findings read as sets |
| The latest row as a scalar maximum per row | Past a minute on MySQL as loaded | The closed findings read as sets |
| The component's shipping asked with its open check in the aggregate | 1.15 s on PostgreSQL as loaded, through the root index | The closed findings read as sets |
| The shipping and none-open checks in WHERE | Past 30 s for the patched findings on PostgreSQL never analyzed, against 4.27 s in HAVING | The closed findings read as sets |
| The build's open issues read apart and met with the decided issues in the application | Analyzed, one build: 20 ms against 54 ms on PostgreSQL, 56 ms against 10 ms on MySQL. Long-lived: 250 ms against 130 ms on MySQL | The build asked in the statement |
| The build asked of each decision occurrence as a value | Analyzed, long-lived: 187 ms against 130 ms on PostgreSQL, 338 ms against 130 ms on MySQL, 223 ms against 166 ms on MariaDB | The build asked in the statement |
| The shipping, open and latest checks asked per issue and component in `HAVING`, in one statement | Past 30 s for a closed read as loaded on PostgreSQL, MySQL and MariaDB, 13.5 s on SQLite with no statistics | The closed findings read as sets |
| The latest row read apart from the open findings of the closed issues, as grouped maxima | 178 to 225 ms against 115 to 120 ms for the suppliers' statements on SQLite, analyzed, read with every row | The latest row asked by key |
| The latest row read by the closed findings' occurrences as a constant list | 359 to 411 ms against 115 to 120 ms for the suppliers' statements on SQLite, analyzed, read with every row | The latest row asked by key |
| Every finding of the build read once for the suppliers' statements | 180 to 213 ms against 200 to 213 ms on MySQL, analyzed, and every finding of a build read where no supplier's statement closed any | The closed findings read first, then the open findings of their issues |
| Every row of the closed issues read into the application, open and closed | With a long history, analyzed: 2.24 s against 460 ms for the suppliers' statements on SQLite, 2.19 s against 1.19 s on MySQL. As loaded with many builds, MySQL 2.6 s in one run and 183 ms in another, against 240 ms | The closed findings grouped in their statement |
| The closed findings grouped by the issue first | 1.6 s against 0.3 s for the suppliers' statements on SQLite with a long history, analyzed, walking the occurrence index over the whole table | The groups led by the closure |
| The latest row asked of each highest closed row by a correlated subquery | Past 30 s on MariaDB as loaded in every shape; on MySQL as loaded, 8 to 10 minutes for 2,678 rows with a long history, through the build's open index | The rows after it asked as a set |
| The same, with the build compared as an expression MySQL cannot look up | 267 to 282 ms for 500 rows on MySQL as loaded, against about 3 ms for 200 as a set | The rows after it asked as a set |
| The highest row at each occurrence read as a set, with no row to follow | 40 ms for 200 occurrences on MySQL as loaded, against about 3 ms | The rows after the highest closed row |
| The build asked once, outside the terms | 66 s for the suppliers' statements on SQLite as loaded with a long history, 5 s a statement through the build's index, against 50 ms | The build named in every term |
| 500 occurrences to a statement | 78 ms against 9.4 ms for 200 on MariaDB, one build: the cost of the list grows faster than its length. 25 and 50 cost 40 µs an occurrence against 50 µs | 200 occurrences to a statement |
| Each key column as its own `IN` list, with the lowest row to follow | Faster on PostgreSQL: 35 ms against 305 ms a statement never analyzed, through the build's index, and 4.7 ms against 20 ms with a long history on background statistics, through the primary key from the lowest row. The ranges are the product of the lists, 1,900 for 200 keys with 10 occurrences and 190 issues, past what MySQL and MariaDB cost by looking in the index; through the primary key, a statement grows with the age of its oldest row | The terms as conjunctions |
| The occurrence index without the build | 923 ms against 161 ms for the latest row check on MariaDB as loaded with many builds, 416 ms against 156 ms analyzed. No difference on SQLite with a long history | The occurrence index carrying the build, the kind and the row |
| The grouping index carrying the patch, the statement and the occurrence | MySQL with a long history: 1.07 s against 1.12 s for the patches, analyzed, and the documents stopped past 30 s at an open read | The closed findings named closed |
| The open findings of the closed issues with no visibility named | With many builds as loaded, MariaDB reads each issue's open rows of every build, 458 ms against 28 ms a read, and MySQL the build's open findings, 55 ms against 10 ms | Every visibility named |
| The closed findings with no closing time named | MariaDB as loaded with many builds reads the whole table, 193 ms against 28 ms | The closed findings named closed |
| An index leading with the build and the closing reason | SQLite with statistics then read the issues recorded elsewhere without the index it skips through, about 1 s | The closed findings named closed |
| The rows after each highest closed row asked by a correlated subquery through the occurrence index, the rows named by identifier | Analyzed, 7 to 47 ms against 47 to 302 ms as a set on every engine and shape. MySQL as loaded counts the build as one distinct value, takes the build's open index for each row, and stops past 20 s in some runs and not others | The rows after it asked as a set |
| The same, the highest row at the occurrence in the select list | 20 to 30 ms on MySQL and PostgreSQL analyzed; MySQL as loaded past 20 s through the build's open index | The rows after it asked as a set |
| The same, with the build a constant or compared as an expression | MySQL as loaded reads every finding of the issue through the issue index | The rows after it asked as a set |
| The build's rows at the closed issues read once, the highest at each occurrence | With a long history: 1.7 s on SQLite, 2.7 s on MariaDB and 1.4 s on MySQL analyzed, against 76 ms, 180 ms and 81 ms | The rows after it asked as a set |
| The build's open rows and rows closed for another reason at the closed issues, the highest at each occurrence | 63 ms against 225 ms on PostgreSQL for one build analyzed; with a long history 1.6 s on SQLite, 742 ms on MariaDB and 1.42 s on MySQL, against 83 ms, 164 ms and 96 ms | The rows after it asked as a set |
| The grouping and the latest row check in one statement | 19 ms on PostgreSQL analyzed for one build; past 20 s never analyzed | The rows after it asked as a set |
| Each occurrence its own statement, joined by `UNION ALL` | One build: 322 to 346 ms on PostgreSQL and 115 to 154 ms on MySQL, against 216 to 233 ms and 47 to 53 ms | The terms as conjunctions |
| The terms as a row value `IN` a list, the highest row read | One build: 204 ms against 216 ms on PostgreSQL analyzed and 212 ms against 4.2 s never analyzed; 30 ms against 47 to 53 ms on MySQL. Slower on MariaDB, 17 ms against 10 ms a statement | The terms as conjunctions |
| The issues listed once each for the flaws recorded here | No change: 1.19 s against 1.28 s on MySQL with a long history analyzed | The kind and issue index |
| The issue index carrying the kind | MySQL refuses to drop it: a foreign key needs it | The kind and issue index |
| The decided issues asked of each decision occurrence at its occurrence in the build | Past 30 s on MySQL as loaded, long-lived, against 208 to 214 ms | The build's open issues as one set |
| The decided issues asked of each issue as a correlated open finding of the build | 167 ms against 45 ms on SQLite as loaded, long-lived; elsewhere within the set form's runs | The build's open issues as one set |
| Every issue the product decided read whole, and met with the build's in the application | Long-lived, as loaded: 188 to 194 ms on MySQL, 111 to 142 ms on MariaDB, 76 to 100 ms on PostgreSQL, 70 to 79 ms on SQLite, and it grows with every build the product had | The build's open issues as one set |
| The decided groups and occurrences asked of each finding inside one statement | Past 30 s on MySQL, 28.5 s on MariaDB, 23.6 s on SQLite, as loaded | The sets matched in the application |
| The decided issues bounded by the names filed under the build's open issues | 273 to 283 ms against 222 to 224 ms on MySQL as loaded, long-lived; the same analyzed | The build's open issues as one set |
