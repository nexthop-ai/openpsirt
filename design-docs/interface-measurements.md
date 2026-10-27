# Interface measurements

Benchmark runs behind the interface's reads: the component screen, the catalog,
the findings list's ways down, the dependency tree's walk and its search.

## Contents

- [Component screen](#component-screen)
- [Catalog reads](#catalog-reads)
- [Ways down on the list](#ways-down-on-the-list)
- [Tree walk](#tree-walk)
- [Tree search](#tree-search)

## Component screen

The bench image: two builds, a kernel of 322,616 open occurrences, PostgreSQL 16
on one processor, 1 ms and 100 Mbit to the server.

| The page's reads, for the kernel | Alone | Four at once |
|---|---:|---:|
| The component read | 0.28 s | 1.1 s |
| Where it sits in the build | 0.18 s | 0.39 s |
| The twelve weeks | 0.14 s | 0.35 s |
| The whole screen: the component read, then where it sits and the twelve weeks side by side | 0.55 s | 1.9 s |
| The same build's findings list, for comparison | 0.14 s | 0.37 s |

| Step, bench kernel, PostgreSQL | As built | Alternative |
|---|---:|---:|
| Counts, bands, each binary's count, where it could go, what is promised | 243 ms as one pass | 164 + 47 + 123 + 152 ms as four statements |
| Grouping before counting | 17,866 rows worked, 174 returned | 13,938 rows returned one per issue and fix per component |
| Source package from the list already read | 175 ms | 204 ms joined for the fold key |
| A component's own count in the tree | 42 ms grouped first | 103 ms counted distinct, over 325,389 occurrences |
| One step through the graph, 45 parents carrying nothing | 3 ms, two statements | 32 ms, the whole build counted and joined |
| Beneath each neighbor | 5,331 walk rows and 10,769 issue rows | 302,269 rows sorted for 270 answers, 345 ms |
| Union skipped for a neighbor reaching one carrying component | 29 ms saved of 182 | |
| Reading the occurrences from the table, the floor | 100 ms of the pass's 243 | |

Each binary's count read in its own statement: 47 ms on PostgreSQL, 219 ms on
SQLite for the measurement fixture's kernel.

The issues beneath what the walk reaches, named as values against walked again:

| Case | Named as values | Walked again |
|---|---:|---:|
| Measurement kernel's 34 consumers, SQLite | 208 ms | 343 ms |
| Statistics after a large scan, PostgreSQL | 0.28 s | 4.2 s |
| Statistics after a large scan, MariaDB | 0.14 s | 14.2 s |
| Bench image, neighbors of its own root | 0.53 s | 0.77 s |

The measurement fixture's kernel, 204,000 occurrences, statistics settled:

| Read | PostgreSQL | SQLite | MySQL | MariaDB |
|---|---:|---:|---:|---:|
| The component read, no fix named | 92 ms | 353 ms | 479 ms | 544 ms |
| The component read, a fix on six issues in seven | 0.14 s | 0.38 s | 0.50 s | 0.51 s |
| Where it sits, 34 consumers above | 154 ms | 358 ms | 172 ms | 141 ms |
| That build's findings list | 110 to 144 ms | | | |

## Catalog reads

| Read | Time |
|---|---:|
| A list of two products, counted | 0.39 s |
| A liveness probe | 1 ms |
| A product holding 8,839 findings, against one holding 28 | 0.39 s against 0.24 s |

## Ways down on the list

| Case | Rows read |
|---|---:|
| Thirty mutually dependent components, the climb from the page | 33 nodes, 874 edges |
| The same, carrying each route's start and length in the statement | 1,651,800 |
| A switch image's every edge read into memory and walked in the application | 18,561 rows, 3 to 18 ms, scaling with the graph |

## Tree walk

| Case | Time |
|---|---:|
| The root's thirty children, full-size image | 0.08 s |
| 2,140 children of a real product of 12,147 components | 0.19 s |
| Recording distance as well as reach: 1,612,405 rows for 43,904 pairs | 9.0 s |

## Tree search

The demo's switch image, 6,867 components and 297,881 open findings, counted
per matched component against in one pass:

| Term | SQLite | PostgreSQL | MySQL | MariaDB |
|---|---|---|---|---|
| `li`, 698 matches | 17.1 s → 0.24 s | 1.38 s → 0.09 s | 0.33 s → 0.37 s | 33.5 s → 0.13 s |
| `open` | 12.7 s → 0.24 s | 0.30 s → 0.08 s | 16 ms → 0.35 s | 13 ms → 0.13 s |
| `ssl`, 6 matches | 0.15 s → 0.22 s | 6 ms → 75 ms | 14 ms → 0.36 s | 12 ms → 0.13 s |
