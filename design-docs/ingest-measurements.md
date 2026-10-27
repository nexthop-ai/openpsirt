# Ingest measurements

Measurements behind the ingest rules. Each section names the rule it justifies.
`make measure` re-runs the receipt page.

## Contents

- [Receipt page timings](#receipt-page-timings)
- [Supplier directory volume](#supplier-directory-volume)
- [Claim writes](#claim-writes)
- [Rating mixture](#rating-mixture)

## Receipt page timings

Justifies the run indexes (`design-docs/ingest-receipts.md` § Receipt cost).
A page of receipts reads the receipts, what each run on it opened and closed,
each upload's documents, what each upload changed in the inventory, and the last
run. The counts are the cost; every other read is a few milliseconds.

The full-size switch image (`internal/sbom/testdata`) built nightly, with
twenty issues arriving a night. The first night opens 241,279 findings, 11,751
issues at components.

| Shape | Packages moving a night | Issues at components opened and closed a night | Findings after a year |
|---|---:|---:|---:|
| Quiet | A thousandth | About 20 opened, under 1 closed | 480,243 |
| Restamped | A hundredth | About 350 opened, 330 closed | 1,159,943 |

Restamped is a build whose container images changed identity every build.

The page of fifty, first read discarded, best of three, in ms, without the
indexes and with them, one engine at a time:

| Engine | Shape | Night 1 | Night 30 | Night 365 |
|---|---|---:|---:|---:|
| PostgreSQL | Quiet | 103 / 81 | 125 / 58 | 145 / 20 |
| PostgreSQL | Restamped | 108 / 71 | 284 / 308 | 510 / 74 |
| MySQL | Quiet | 256 / 45 | 268 / 84 | 23 / 23 |
| MySQL | Restamped | 233 / 47 | 1,075 / 262 | 2,923 / 515 |
| MariaDB | Quiet | 83 / 50 | 111 / 90 | 18 / 19 |
| MariaDB | Restamped | 86 / 49 | 382 / 260 | 730 / 160 |
| SQLite | Quiet | 923 / 13 | 921 / 28 | 1,804 / 19 |
| SQLite | Restamped | 914 / 17 | 1,952 / 67 | 4,984 / 60 |

| Reading | |
|---|---|
| Night 30, restamped, PostgreSQL | Every finding of the build was opened by a run on the page, 458,895 rows. The planner reads the table, and the distinct count is the cost either way |
| Night 365, quiet, MySQL and MariaDB | Without the indexes both read the runs' few rows through the index their foreign key carries |
| Night 365, restamped, MySQL | Each count reads the other run column's index with the build alone as prefix, every finding of the build, from the index. A sixth of the cost without the indexes |

Twelve builds of the image, 3,497,476 findings, one build at its tenth night
with every container image changing identity nightly: about 1,050 issues at
components opened and 1,000 closed a night, 11,300 findings each way. The page
holds the run that opened the build.

| Count read through | Page | What the count reads |
|---|---:|---|
| No run index | 253 ms | 17,927 table pages, the build's every finding |
| The run indexes, before a vacuum | 185 ms | 348,715 index entries and 301,897 table rows |
| The run indexes, after a vacuum | 67 ms | The same entries, no table row |

A night costs up to 7 percent more with the two indexes, averaged over the
year: 3.75 s and 3.83 s on PostgreSQL restamped, 3.39 s and 3.42 s quiet.

## Supplier directory volume

Justifies the per-wake bound (`design-docs/ingest-suppliers.md` § The pass) and the
window (`design-docs/ingest-suppliers.md` § Configuration). Five publishers on 2026-09-23, from their listings and sampled
documents, at twenty documents a wake every five minutes, up to 5,760 a day.

| Publisher | Shape | Listed in a year | Listed in 30 days | Drains in | Digest served |
|---|---|---|---|---|---|
| Red Hat, advisories | Directory | 28,984 | 10,596 | 17 days, both directories together | SHA-256 |
| Red Hat, VEX | Directory | 68,238 | 7,614 | | SHA-256 |
| SUSE, advisories | Directory | 42,268 | 33,438 | About 7 days, from a second host | SHA-256 |
| Cisco | Directory | 1,229 | 155 | About 5 hours | SHA-512 |
| NCSC-NL | Directory | 503 | 75 | About 2 hours | SHA-512 |
| Siemens | Feed | 178 | 18 | About 45 minutes | SHA-512 |

| Reading | |
|---|---|
| A year's listing is mostly revisions | A publisher restamps an entry on every revision: 25,743 of Red Hat's 28,984 advisory entries fall in the last 90 days. A distribution's steady state is a few hundred entries a day |
| The size limits hold with room | The largest listing is 3.7 MB against 64 MB; Red Hat's sampled advisories run to a median of 55 KB and a largest of 5.2 MB against 256 MB |
| A pass is mostly the pause between requests | A Red Hat document arrives in a quarter of a second |
| Red Hat's VEX directory is fetched and set aside whole | It is listed beside the advisories, and nothing in a directory says which profile its documents are |

## Claim writes

Justifies writing one document's claims in batches
(`design-docs/ingest-claims.md` § CSAF bounds). A real distribution advisory
about a kernel holds 95,139 claims. In seconds:

| Engine | A row at a time | In batches | Revising, every claim set aside and written again |
|---|---:|---:|---:|
| PostgreSQL | 27.9 | 5.4 | 6.1 |
| MariaDB | 10.0 | 1.2 | 3.1 |
| MySQL | 9.0 | 1.4 | 3.0 |
| SQLite | 7.3 | 1.3 | 2.2 |

## Rating mixture

Justifies keeping one rating per generation and never recomputing one
(`design-docs/ingest-scanner.md` § Ratings a report carries).

| Population | Measured |
|---|---|
| 5,037 issues published in a two-week window | 1,939 carry a rating: 1,245 under version 3 alone, 167 under version 4 alone, 527 under both |
| Version 4 ratings claiming nothing about exploitation | Of 531, 528 score exactly as published and 3 differ by a tenth; on all three the scheme's reference calculator agrees with this implementation |
| A scanned estate of 6,883 issues | 4,959 carry a vector: 4,815 under version 3, 143 under version 4, one under version 2, which nothing here scores. Seven of the 143 state an exploit maturity. The other 1,924 carry a severity word alone |
