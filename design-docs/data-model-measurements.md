# Data model measurements

Benchmark runs behind the inventory delta and comparison rules in
`design-docs/data-model-graph.md`.

## Contents

- [Inventory delta timings](#inventory-delta-timings)
- [Comparison timings](#comparison-timings)

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
