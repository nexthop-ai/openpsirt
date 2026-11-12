# Data model measurements

Benchmark runs behind the inventory delta and comparison rules in
`design-docs/data-model-graph.md`.

## Contents

- [Inventory delta timings](#inventory-delta-timings)
- [Comparison timings](#comparison-timings)
- [Stated-name lookup timings](#stated-name-lookup-timings)

## Inventory delta timings

Measured on 2026-09-25 over a year of nightly scans, one engine at a time, on
builds of about 700 components.

| Question | SQLite | PostgreSQL | MySQL | MariaDB |
|---|---|---|---|---|
| A page of fifty uploads' counts, behind 73 nights and behind 365 | 4–6 ms | 3–5 ms | 5–6 ms | 4–5 ms |
| Listing an upload that moved seven names, behind 73 nights and behind 365 | 2–5 ms | 2–5 ms | 2–5 ms | 2–5 ms |
| Listing the upload that removed a file inventory, 54,098 names | | 0.43 s | | |

On a real switch image of 6,866 components, listing an upload that moved five
names:

| Read | SQLite | PostgreSQL |
|---|---|---|
| The build's rows, read once | 17 ms | 10 ms |
| Only the rows of the names moved | 10–15 ms | 4.5 ms |

Reading the build's rows costs the difference, and keeps an upload moving tens
of thousands of names under a second.

## Comparison timings

Comparing the master branch of a switch image built for two platforms, 6,866
components against 6,748: 211 names differ, in 18 to 29 ms on each of the four
engines, measured on 2026-09-27, one engine at a time.

## Stated-name lookup timings

Measured on 2026-11-12, one engine at a time, by
`TestMeasureSearchingByTheNameABuildStated`: one product of eight builds of
the full-size switch image, 52 weekly rescans moving two hundredths of the
packages on the build read, 57,967 nodes and 6,843 open findings. The
lookup is the components the product's builds stated under the name; the
page is the findings list's first fifty groups, the lookup included.

| Filter | Stated components | PostgreSQL lookup, page | MySQL lookup, page |
|---|---|---|---|
| Search `ssl` | 10 | 5.7 ms, 34 ms | 13 ms, 39 ms |
| Search `lib` | 648 | 7.2 ms, 53 ms | 12 ms, 52 ms |
| Search `linux-image` | 2 | 5.9 ms, 30 ms | 11 ms, 36 ms |
| Component `openssl` | | 0.74 ms, 19 ms | 0.15 ms, 19 ms |

Across products, by
`TestMeasureSearchingByTheNameABuildStatedAcrossProducts`: a reader granted
sixteen products, each of eight builds of the full-size switch image and one
build carrying an issue on every package, 878,976 nodes and 302,224 open
findings. The page is the list across products. Without a search the first
page is 488 ms on PostgreSQL and 1.14 s on MySQL. The lookup reads every
node of every build in scope, so it grows with the nodes the reader's
products hold.

| Filter | Stated components | PostgreSQL lookup, page | MySQL lookup, page |
|---|---|---|---|
| Search `ssl` | 6 | 81 ms, 216 ms | 390 ms, 589 ms |
| Search `lib` | 428 | 94 ms, 277 ms | 366 ms, 742 ms |
| Search `linux-image` | 1 | 73 ms, 199 ms | 325 ms, 442 ms |
