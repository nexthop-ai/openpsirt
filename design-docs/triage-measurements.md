# Triage measurements

Benchmark runs behind the triage rules. Each section names the rule it
justifies. `make measure` re-runs the harness-driven ones.

## Contents

- [Kernel upgrade promise](#kernel-upgrade-promise)
- [Review queue reach](#review-queue-reach)

## Kernel upgrade promise

Justifies reading a promise's source packages first and writing it in one
transaction (`design-docs/triage-promises.md` § Promised work). Under
`make measure`, 425,680 open findings in two products: the kernel carries 6,000
issues under 34 consumers, 204,000 findings in a build of 737 graph nodes. The
read resolves every occurrence the promise covers; the act writes a row at each.

| | PostgreSQL | MySQL | MariaDB | SQLite |
|---|---|---|---|---|
| The build's findings list, first page | 0.14 s | 0.29 s | 0.11 s | 0.14 s |
| The read, statistics as the load left them | 1.6 s | 1.4 s | 1.0 s | 1.4 s |
| The read, PostgreSQL's own refresh held off | 1.9 s; 22 s as a subquery | — | — | — |
| The read, statistics refreshed | 1.0 s | 1.3 s | 1.1 s | 1.2 s |
| The whole act | 9.7 s | 5.3 s | 4.4 s | 5.8 s |
| Writing the rows, per row | 43 µs | 20 µs | 17 µs | 23 µs |

The act's time is the writing, and it reads back no identifier of a row it
writes. A row's cost is the act less the read, over 204,000 rows. On PostgreSQL
the difference is the decision occurrence table's four foreign keys, each checked
with a query per row (`design-docs/database-queries.md` § Bulk inserts).

The refresh-held-off row runs against PostgreSQL alone, with
`ALTER SYSTEM SET autovacuum = off` and `SELECT pg_reload_conf()` before the run
and `ALTER SYSTEM RESET autovacuum` after. The 22 s is the same read with the
folds as a subquery inside it.

## Review queue reach

Justifies asking whether every row is in reach over the grouping
(`design-docs/triage-approval.md` § Queue entries).

| Shape | Measured |
|---|---|
| A correlated subquery in the `HAVING` | PostgreSQL prices it once per group at the cost of running it alone, and compiles a plan priced past 100,000 before running: the review-queue count over 133,549 rows is priced at 515,000 and spends 150 ms compiling a 30 ms statement |
| A join over the grouping finding no row | Priced at 12,600, runs in 22 ms, compiles nothing |
| `NOT EXISTS` over the grouping | MySQL reads every row to build the set of decisions out of reach: 33 ms against 22 ms for 3,000 decisions of 132,000 rows |
