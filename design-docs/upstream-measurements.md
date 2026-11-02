# Upstream measurements

Benchmark runs behind the upstream rules. Each section names the rule it
justifies.

## Contents

- [A fork reading its upstream](#a-fork-reading-its-upstream)
- [Offers for review](#offers-for-review)

## A fork reading its upstream

Justifies reading every hour and applying statements on every run
(`design-docs/upstream.md` § Settings, § Statements applied). The full-size
switch image shipped by the upstream and by a fork on PostgreSQL, every
component with a package identifier carrying one issue: 6,843 issues at
components. The upstream publishes, signed, that 76 of the distribution
packages' issues do not apply because the code is absent. The fork reads it
over TLS from a server on the same machine.

| Measured | |
|---|---|
| Documents read and recorded on the first read | 76, every one holding for anybody, each checked against its digest and its signature |
| The first read | 0.40 s |
| A read over nothing that moved | 18 ms: one request for the description and one for the feed, answered that nothing moved |
| The fork's run over its build | 0.58 s before it trusts the upstream, 0.60 s with the 76 statements standing |
| Findings that run closes | 508: the 76 issues at every occurrence the image ships them |

## Offers for review

Justifies reaching a finding through the issue a statement names
(`design-docs/upstream.md` § Offers for review). A database v0.9.0's demo built
and filled, 414,683 findings and 2,074 VEX statements, upgraded to v0.11.0's
schema and analyzed, on one host. The servers keep their data in memory. The
second pair of columns adds 2,472 upstream statements awaiting review: 2,074
naming no component shipped here and 398 taken from open findings. Each figure
is the median of five reads as the administrator, cut off at 120 s.

| Engine | None waiting, the issue as a filter | None waiting, asked first | 2,472 waiting, the issue as a filter | 2,472 waiting, joined through the issue |
|---|---|---|---|---|
| SQLite | 1.39 s | 0.9 ms | Past 120 s | 91 ms |
| PostgreSQL 16 | 29 ms | 3.9 ms | Past 120 s | 270 ms |
| MySQL 8.4 | 3.2 ms | 0.65 ms | Past 120 s | 280 ms |
| MariaDB 11.4 | 2.1 ms | 1.8 ms | Past 120 s | 190 ms |

With the issue as a filter, SQLite read every open finding through the index on
whether it is closed and looked for a statement beside each. PostgreSQL, MySQL
and MariaDB read every finding at each statement's component and tested the
issue on each. Joined through the issue, every engine starts from the
statements and reads a finding through the index on its issue. Read through
the join with nothing waiting, PostgreSQL takes 37 ms, most of it planning. On
SQLite, without the analysis an upgrade makes, both forms run past 120 s
(`design-docs/database-measurements.md` § Statistics after an upgrade).
