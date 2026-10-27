# Database schema

Rules about what the schema holds: which indexes exist and what each serves,
how planner statistics are kept fresh, how wide text columns are, and why each
column nobody queries is kept.

Satisfies REQ-71.

## Contents

- [Indexes](#indexes)
- [Planner statistics](#planner-statistics)
- [Column widths](#column-widths)
- [Columns no query reads](#columns-no-query-reads)
- [Limits](#limits)

## Indexes

| Rule | Reason |
|---|---|
| No index repeats the front of another | A B-tree on `(a, b)` answers a lookup on `a` as well as one on `(a)`, and the narrower one costs every write. A unique constraint declares an index unseen, which is where repeats arise |
| A test reads the schema from the database, on SQLite alone | What an operator ends up with is what matters. The engines agree on an index's columns, and reading index metadata is spelled four ways |
| Dropping a repeating index never costs a foreign key its index on MySQL and MariaDB | The constraint that made the wider index leads with the same column |

| Pair | Reported |
|---|---|
| A narrower index leading a wider one | Yes |
| A narrower unique index leading a wider one that is not unique | No: dropping it loses the rule it enforces |
| Either index partial | No: it holds only the rows a condition admits |
| A column that is an expression | Read as a column no other index's column equals |

The indexes serving the hottest reads, on the finding, decision occurrence and
notification tables. Timings are PostgreSQL 16 on one processor unless an
engine is named; `design-docs/database-measurements.md` § Index reads has the
rest.

| Index | Columns | Serves |
|---|---|---|
| What is open in a build | Build, closed, deadline | One build's deadline report, as a range at the end of the prefix: 205 ms a page against 256 ms through the deployment-wide index, for 183,788 open findings |
| Deadlines running out | Closed, the build's claim, deadline | The deadline report across the deployment: 248 ms against 343 to 392 ms without it |
| Grouping | Build, closed, visibility, issue, component, the three urgency columns, opened, closing reason, holder | The findings list, its total and the backlog trend, from the index alone. The last two columns take the trend from 16,500 pages to 578 and 172 ms to 88 ms over 375,843 findings, for 0.4 MB more index |
| Occurrences waiting, by decision | State, decision | The review queue's page and count: 22 ms each, against 81 ms and 40 ms, with 33,150 waiting among 133,549 |
| What a run changed | Build, the run that opened a finding, issue, component, visibility, the run that closed it; and the same with the two runs swapped | A receipts page's opened and closed counts, from the index alone. A run's own screen reads ratings and exploitation from the table. Led by the run instead, MySQL and MariaDB counted 1.04 s and 599 ms against 231 ms and 237 ms; MySQL a year in is the one case the other order wins, 134 ms against 467 ms (`design-docs/ingest.md` § Receipt cost) |
| Who is being told | Kind, cleared, person | The notify sweep's read of who holds an open condition of each kind. Kind and an open row are the prefix on all four engines, the null included, and MySQL and MariaDB group people from the index unsorted. 0.33 ms a read against 46 ms on PostgreSQL, and all 28 kinds in 18 ms against 2.9 s on MySQL (`design-docs/notifications.md` § Delivery) |

| Rule | Reason |
|---|---|
| The widest key is the notification index's, about 780 bytes on MySQL and MariaDB | Their row format allows 3,072 |
| The grouping index has eleven columns | MySQL allows sixteen |
| The two wider v0.8.0 indexes cost a write nothing measurable | Copying 375,843 findings took 6.5 to 8.6 s against 6.1 to 7.9 s with v0.7.0's |
| On PostgreSQL the finding table is vacuumed after a fiftieth of it changes and analyzed after a hundredth | An index-only scan reads the table for every page changed since the last vacuum, and the default fifth is more than a nightly scan rewrites. With 46,980 of 375,843 rewritten, the package-kind count read the table 413,331 times in 246 ms at the default, and not at all in 64 ms at a fiftieth |
| The vacuum settings are written once, by migration 42 | Values an operator sets on the table afterwards stay. The other engines have no such setting |

## Planner statistics

| Rule | Reason |
|---|---|
| Every table is analyzed at start, on every engine | A server refreshes estimates after about a tenth of a table changes, so a database loaded before that, restored, or on a stalled server arrives with estimates that describe nothing |
| An upgrade is followed by a start that analyzes | MySQL and MariaDB analyze only tables an upgrade rebuilds. A v0.7.0 demo upgraded on MySQL 8.4 held 7,746 issues and 2 products under estimates of none, and a decision audit page ran over four hours; analyzed, 5 ms |
| A server is not asked again after a scan | Its own background refresh follows the writes. SQLite is asked after every scan (`design-docs/database.md` § SQLite settings) |
| A failed refresh is logged and the start goes on | Stale estimates make a statement slow, never wrong |
| The refresh has a quarter of the startup deadline | The rest of the start keeps its time |
| A table something else holds is stepped over and named in the log | An analysis needs a shared lock, so waits only behind a schema change or a vacuum, never another replica's start. PostgreSQL steps over it in the statement and says so as a warning alone; MySQL and MariaDB wait a second for the metadata lock, where the server default is a year |
| The startup deadline starts again once an automatic migration finishes | A migration is unbounded |

Analyzing every table at start took 140 ms on MySQL 8.4 over 381,337 findings
and 683 ms on PostgreSQL 16 over 381,305, and does not grow with the table:
InnoDB samples a fixed number of pages per index and PostgreSQL a fixed number
of rows. On MySQL 8.4 and MariaDB 11.4 an analysis beside a 15 s read of the
same table took about 60 ms, and a query after it waited for nothing.

## Column widths

| Rule | Reason |
|---|---|
| Text a producer supplies has no width unless an index carries it: a component's name and version, what it was forked from, a fix's version list | No format bounds them, and a width would fail the scan carrying an unusual value, which reads as a product that stopped having problems |
| Text an index carries has the name width, 191 characters | Index key length is tightest on MySQL |
| Text a producer or a document supplies past the width is cut in characters: an issue's identifier, a claim's justification and versions, a key's name | Two values agreeing that far are one value, and a refusal would fail the scan |
| A name a person types past the width is refused, naming the width | A series, a response window, a notice outside, an assignment rule. The typist can shorten it |
| A value too long to index whole is keyed on its SHA-256 digest | A reference's address as given, an upstream document's address, a component's fold |

Against the reference producer's real output, 6,845 components: longest
version 49 characters, name 120, package identifier 140, nothing over 191.

## Columns no query reads

A column is a claim like code: one written, never read, and wanted by nobody
is a defect.

| Column | Read by |
|---|---|
| Which parser read a scan | A person. The document is deleted for a branch, so after a parser changes nothing else says which records need re-uploading |
| Whether this deployment ran the scan | Nothing. Always true; a producer sending its own findings is not built, and a schema assuming otherwise could not take it |
| How large a stored document is | A person asking whether retention is affordable. Derivable only by reading the blobs |
| When an identity was bound to a person | The audit trail for the one decision editing a role cannot undo |
| What sent a refused upload | A person finding which pipeline is broken |
| What a refused document said it was built from | A person, for an out-of-order refusal: what it said the time was |
| What a refused upload hashed to | A person comparing against what the producer sent, and telling one broken document retried from a differently broken one each night |
| Who took an agreement to an advisory back | A person asking who stopped a document. An edit takes agreements back as a side effect, so this is often not who meant to withdraw |
| When an edition of an advisory was written | A person reconstructing what an advisory covered when agreed to; which flaws it named is read from when each was added and removed |

## Limits

| Limit | Detail |
|---|---|
| A value cut to the width is stored cut | The name width is 191 characters, so two identifiers agreeing that far are one issue |
