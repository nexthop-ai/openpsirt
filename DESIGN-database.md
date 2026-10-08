# Database

Engine support, migrations, locking, connection handling and the portability
rules the four supported engines impose.

Satisfies REQ-03, REQ-06, REQ-71, REQ-72, REQ-73.

## Contents

- [Supported engines](#supported-engines)
- [Engine-specific code](#engine-specific-code)
- [Engine detection](#engine-detection)
- [Connection encryption](#connection-encryption)
- [Migrations](#migrations)
- [Migration locks](#migration-locks)
- [Identifier quoting](#identifier-quoting)
- [Pattern matching](#pattern-matching)
- [Affected-row counts](#affected-row-counts)
- [Recursion bound](#recursion-bound)
- [Absence and failure](#absence-and-failure)
- [Collation](#collation)
- [Replica coordination](#replica-coordination)
- [Retryable transactions](#retryable-transactions)
- [Reads a write depends on](#reads-a-write-depends-on)
- [Connection pool](#connection-pool)
- [SQLite settings](#sqlite-settings)
- [Indexes](#indexes)
- [Columns no query reads](#columns-no-query-reads)
- [Column widths](#column-widths)
- [Text truncation](#text-truncation)
- [Test harness](#test-harness)
- [Not built](#not-built)
- [Limits](#limits)

## Supported engines

| Engine | Role | Version floor |
|---|---|---|
| PostgreSQL | Production | 14 |
| MySQL | Production | 8.0 |
| MariaDB | Production | 10.6 |
| SQLite | Development and testing only | 3.35 |

A floor is a release series: the oldest series this application's queries and
schema are written against. It is not a statement that upstream still
publishes fixes for that series — MySQL 8.0 and MariaDB 10.6 are both past
upstream end of life and are still admitted, because raising a floor refuses
deployments that start today and that is a decision rather than upkeep.

Nor is it a statement about the server in front of it. Upstream publishes per
patch release, and which patch release an operator runs is a property of that
deployment — a floor admitting the series admits every unpatched release in it.
So this is a compatibility floor, and keeping a deployment current is the
operator's responsibility, which this document says rather than implying it is
handled.

The release number carries a patch level anyway, because servers report one and
a comparison that discards it cannot tell two releases of a series apart.
PostgreSQL is the exception that proves the shape: since 10 it numbers releases
as series and patch, so its patch level is its second part and the same
comparison orders it correctly.

MySQL and MariaDB are separate targets. They share a wire protocol and a driver
and have diverged in JSON handling, sequences, partitioning and collation
defaults, so a query proved on one says nothing about the other.

Supporting all four rules out:

- PostgreSQL JSON operators and GIN indexes on JSON
- `RETURNING`, which MySQL 8 does not have
- PostgreSQL full-text search
- Arrays, partial indexes, `DISTINCT ON`

`WITH RECURSIVE` works everywhere, so graph traversal needs no engine-specific
path.

## Engine-specific code

Queries above this package are written once and run unchanged everywhere.
Engine-specific code is confined to these places:

| Location | Reason |
|---|---|
| Schema migrations | Data-definition language differs |
| The migration lock | Every engine spells advisory locking differently |
| Connection setup | Driver-specific settings |
| Recognizing what an engine is telling us | All three drivers carry an error type of their own, SQLite included. Three questions, three functions: whether a failure is a lost race worth retrying (REQ-71), whether it is a unique constraint refusing a duplicate, and whether it came from the engine at all rather than from the caller asking for something impossible. Each is a different code in a different error type per engine, and each is asked somewhere a wrong answer is silent — a retry that never happens, a constraint message shown to a person, a broken database answered as a mistyped request |
| Subtracting two moments | No portable expression yields seconds from two timestamps: one returns an interval, one a number of days, the rest something else |
| Inserting a row another writer may already have written | Two of them want `ON CONFLICT DO NOTHING` and the other two `ON DUPLICATE KEY UPDATE` setting the key to itself. Not `INSERT IGNORE`, which on those two also turns a value too wide for its column, a dangling reference and a missing value into warnings, and writes the row cut to fit or skips it while reporting success. For a table whose rows are facts rather than somebody's state, where two writers describing the same thing are agreeing |
| The job queue's locking | The only query outside this package, because the queue owns the statement |
| Typing a composed expression as a moment | A `CASE` over bound values is untyped, and PostgreSQL refuses to write it into a timestamp column. The cast target differs: PostgreSQL takes a zoned timestamp, MySQL and MariaDB a six-digit datetime, and SQLite stores text and takes none |
| The test harness | It names every engine to choose a connection and to say which one ran, rather than to write a query — and the check that each engine ran is what keeps that naming honest |
| Leasing the harness's slots | A test binary holds a lock the server keeps for its connection, and the two families spell it differently: a named lock on MySQL and MariaDB, an advisory lock on PostgreSQL, whose key is a number |
| Listing the harness's own databases | PostgreSQL keeps databases in a catalog of its own, where the standard information schema describes only the one connected to, and there is no portable third spelling |
| Listing the tables of the harness's SQLite schema | SQLite keeps its schema in a catalog of its own. The servers are asked the same question through the information schema |
| Commit durability on the harness servers | A global setting on the two MySQL-protocol servers, relaxed so the suite runs faster. PostgreSQL asks per session in the connection string, so it has nothing to branch on |
| Refreshing planner statistics before a measurement | A server refreshes its statistics once about a tenth of a table has changed, and a measurement queries seconds after a bulk load, before that happens. PostgreSQL spells the request `ANALYZE` and the MySQL-protocol servers `ANALYZE TABLE`. SQLite is asked the way a deployment asks after a scan |
| Refreshing planner statistics in a deployment | SQLite gathers none unless asked, and the servers keep their own. § SQLite settings has the measurement |
| A test choosing which engine it runs on | The same act as the row above, written at the call site: `dbtest.Only(t, database.SQLite, …)` says a question has the same answer everywhere and is asked once. Allowed anywhere, because it selects an engine rather than branching a query on one — which is the distinction the whole rule is about |
| Migration 37 | Changing an existing table is spelled per engine: PostgreSQL drops or restores a column's refusal of a null where the other two servers restate the column, MySQL and MariaDB drop a foreign key by a word of their own, SQLite rebuilds the table with its foreign keys suspended, and PostgreSQL alone is told to move its identity past rows carried across. The catalog is asked which indexes a table already has |
| Asking each engine what words it reserves | One statement per engine, because each publishes its keywords somewhere of its own and two publish nothing a query can read. It is not a query the application runs: it regenerates the word list the quoting gate reads, and the gate exists because the four engines do not reserve the same words |

This list is the complete set, and where an engine may be named is checked by
grep rather than trusted: `make confined` refuses a dialect named anywhere but
the places it allows. It allows them by path, and four of its paths are whole
directories — this package, the test harness, and the two tools that enforce
this rule and regenerate the reserved words — so a new branch inside any of them
passes it, and the row naming that branch here is kept by review. It reads the tests
too: a branch in a test is a branch, and the one thing it lets past there is an
engine named to choose which engine runs.

What it looks for is the branch rather than the SQL: the two upsert idioms as
bun spells them, and asking a handle which engine it is. A gate blind to the
idiom the code actually uses is a sentence rather than a check.

A list of exceptions kept by hand grows without saying so, because each new one
arrives under a comment calling itself one of the few places an engine has to
be asked — and two of them turn out to be the same expression written twice in
two packages.

### Silently wrong query shapes

Not engine-specific code — one query written once — but shapes an engine gets
wrong. Most are a silent wrong answer rather than an error, which is why they are
written down; the last is refused outright by two of the four, which is the
same lesson arriving loudly.

| Shape | What happens |
|---|---|
| `COUNT(DISTINCT …)` beside a window function | **MariaDB 11.4 returns no rows at all.** No error, an empty page, and a total from a second statement saying there was something to show. The findings list pages with `COUNT(*) OVER ()` and counts packages and consumers with `COUNT(DISTINCT)`; the two cannot sit in one statement, so the distinct counts moved to the statement that decorates the page |
| `SUM(CASE … END)` where an integer is wanted | Comes back as a decimal on two of the four, and the cast that fixes it is spelled per engine. Counted as two `COUNT`s instead, which reads the same everywhere |
| Ordering by a column the grouping does not determine | MySQL refuses it outright, and it is right to: a tie-break on a column that varies within a row is not a tie-break |
| A correlated subquery in the select list, grouped on the same expression | MySQL and MariaDB refuse it under their default mode: the expression reads columns the grouping does not carry, whatever it is repeated in. Written as a join instead, which groups on a column and answers the same everywhere — at the cost of multiplying rows, so what is counted is distinct identifiers |

## Engine detection

The URL states which engine to expect. The server is asked anyway, because a
MySQL-protocol connection may be either MySQL or MariaDB and the URL cannot
settle it. Believing the URL would apply the wrong version floor and admit an
unsupported server. Detection reads the version string; MariaDB names itself in
its own.

A server below the floor stops the process at startup, with the version found
and the version required both named. The alternative is a failure much later, in
whichever query first needs something the server cannot do.

The connection is asked one further question at startup: what encryption it
negotiated. On its own that answer never stops a start — a server that will not
say is still a server that answered the version question. It stops one where
the deployment has said that encryption is required.

## Connection encryption

Every engine negotiates opportunistically, and neither driver says which way it
went, so a deployment believing the connection to its findings is encrypted has
nowhere to look. The two drivers disagree about the default: one negotiates
where the server offers it, the other connects in cleartext unless asked.

| | |
|---|---|
| The default | Encrypted where the server offers it, cleartext where it does not, no certificate checked. The same on every engine, so one URL grammar no longer means two transports |
| What it is not | A guarantee. A deployment needing one says so in the URL, and whatever the URL says about the transport is left as written — this sets a floor, it does not override an answer only the deployment can give |
| How anybody knows | The connection is asked what it negotiated, and the answer is in the line that logs the engine and version. A production engine connected in cleartext is warned about by name, with the setting that fixes it |
| Required is a stated choice | A deployment says that encryption is required, and a connection that did not get it is refused as the process starts. Taking whatever the server offers stays available and is the other choice; what changed is that it is chosen rather than the only behavior |
| Required is asked of the connection, never of the URL | The engines spell the transport differently and each spelling has several values, so a check reading the URL would be three parsers agreeing about what "encrypted" means — and would still be wrong about a server that ignored what was asked for |
| Required is also imposed on every connection the pool opens | The question is asked of one connection at startup, and the pool opens connections for the life of the process. A transport that falls back to cleartext — `sslmode` of `prefer` or `allow`, `tls=preferred`, or none named — is replaced by one that does not, and one that asks for cleartext is refused, as is `allowFallbackToPlaintext` set true. One the deployment named that cannot fall back is left as written. A MySQL value is read as the driver reads it, in any case and with 0 and 1 as false and true |
| A PostgreSQL URL naming no mode | The driver takes `PGSSLMODE` there, and a mode in the URL overrides it, so the environment's mode is judged in the URL's place. A mode is appended only where that one is weak, so a `verify-full` set in the environment is never replaced by one checking no certificate |
| A server that will not say is refused under it | What the requirement asks for is certainty, and "we could not find out" is not it |
| Required against SQLite is refused | A file opened directly has no connection to encrypt. Accepting it would make the setting one that changes nothing, which is worse than not offering it |

Asked rather than assumed, because the intention and the outcome differ exactly
when it matters: a server that does not offer encryption is answered in
cleartext by a deployment that asked for it.

## Migrations

Embedded in the binary and applied at startup by default, so a deployment is one
artifact and an upgrade is deploying it. Automatic application can be disabled,
and `openpsirt migrate up|status` runs them separately for an operator who
would rather use different credentials at a time they choose.

With automatic application off, the schema is compared before anything is
served. The binary and the schema move independently, and uncompared, a build
carrying a new migration starts, grants administrators, answers the readiness
probe — which is a ping — and fails every request touching the new table. In a
rolling deployment the probe passing is what retires the last replica that
worked.

| Applied version | What happens |
|---|---|
| Behind what the binary carries | Refused at startup, naming both versions and what to run. The previous replica stays up, which is what a startup refusal buys over a readiness failure |
| Equal | Served, and the two versions are logged |
| Ahead | Refused at startup, and by `openpsirt migrate up`, naming both versions. A database is only ever upgraded (§ Forward only), so a later release's schema is one this binary may not read |

What the binary carries is the highest version among the embedded migration
sources, read from their file names, which is the same rule the migration
library applies to them.

Version zero means nothing is applied, and nothing else. The bookkeeping
table is looked for before the version is read, so a read-only inspection does
not create it. Selecting from the table to find out answers three questions at
once and cannot tell them apart — it is not there, this credential may not read
it, or the database is unreachable — and all three read as the first, so
`migrate status` would print version 0 for a fully populated database whose
credentials omit that one table. The reasonable thing to do about "nothing is
applied" is to migrate it.

The catalog is asked instead, which answers only the question being put to it.

| Engine | Asked | Tells an absent table from an unreadable one |
|---|---|---|
| PostgreSQL | `pg_class` | Yes |
| MySQL, MariaDB | The information schema | No |
| SQLite | `sqlite_master` | There are no privileges to have |

PostgreSQL is asked through `pg_class` rather than its information schema
because every information schema here is filtered by privilege: a role with no
rights on a table does not see the table listed, which is the same conflation
again. `pg_class` is readable by any role. MySQL and MariaDB offer no
unfiltered catalog, so on those two the two cases stay indistinguishable —
bounded by what runs next, which is the version query or a migration, both of
which fail with the engine's own permission message rather than silently.

Migrations are written in Go rather than SQL files, because they branch on the
engine. A timestamp column has no portable spelling: PostgreSQL has no
`DATETIME`, and MySQL's `TIMESTAMP` is a 32-bit value that can acquire an
implicit default and an on-update clause depending on server configuration.

The migrations applied are the ones registered in the binary, and no directory
is read. The migration library otherwise globs the process's working directory:
a stray `.sql` file there refuses every start, a numbered one is applied under
the migration credential, and a numbered `.go` file narrows what is applied to
the registered migrations with a file beside them.

| An upgrade that fails | What the error says |
|---|---|
| On an empty database | The failure alone: there is nothing to recover |
| On MySQL or MariaDB | That the schema is left part changed, and the backup taken before the upgrade is what recovers it; and that a database an unreleased build made is recreated rather than migrated |
| On PostgreSQL or SQLite | That a database an unreleased build made is recreated rather than migrated. Data definition is transactional there, so a failed migration leaves nothing part changed |

The version a database holds cannot say whether a release or an unreleased
build made it, so both recoveries are named rather than one chosen by a
version threshold.

The chain is one part per release.

| Migrations | What they are |
|---|---|
| 1 to 36 | The ones the v0.1.0 release shipped, as that release tagged them. A database v0.1.0 built has applied exactly these, so none of them changes again |
| 37 | v0.2.0: v0.1.0's schema changed into v0.2.0's, and the rows moved with it. A database v0.2.0 built has applied it as the release tagged it, so it and every declaration it reads never change again |
| 38 | v0.3.0: v0.2.0's schema changed into v0.3.0's, and the rows moved with it. § The v0.3.0 upgrade says what it does. A database v0.3.0 built has applied it as the release tagged it, so it and every declaration it reads never change again |
| None | v0.4.0 changes no schema. Its record carries migration 38 as its last |
| 39 | v0.5.0: v0.4.0's schema changed into v0.5.0's, and the rows moved with it. § The v0.5.0 upgrade says what it does. A database v0.5.0 built has applied it as the release tagged it, so it and every declaration it reads never change again |
| 40 | v0.6.0: v0.5.0's schema changed into v0.6.0's, and the rows moved with it. § The v0.6.0 upgrade says what it does. A database v0.6.0 built has applied it as the release tagged it, so it and every declaration it reads never change again |
| 41 | The untagged release: v0.6.0's schema changed into the next release's. § The untagged upgrade says what it does. Edited until a tag ships it, and every schema change before that tag edits it rather than adding a migration beside it |

Each tagged release keeps a record of its migrations: the files it shipped for
them, the digest of each below its license header, its last migration, and the
schema they build on each of the four engines, captured from the tag.

| Held by the record | Why |
|---|---|
| Each file a release shipped is the file it tagged, and each file numbered or named as the release's is one it shipped | A database the release built has applied exactly those. An edit changes a schema deployments already hold without changing the version they recorded |
| The migrations up to a release's last build, on every engine, the schema the tag built | The files alone do not fix it: the column spellings and widths they use are read from helpers a later change is free to edit. On SQLite the description also says whether each table's key is `AUTOINCREMENT` and whether each index is partial, which the engine's column and index listings leave out |
| The SQLite records of v0.1.0 to v0.4.0 | Each carries a line per table saying whether its key is `AUTOINCREMENT`, and `partial=0` on every index line: none of those releases built a partial index. Those lines were added to records taken before the description named the two facts, and every other line is as the tag captured it. The addition corrects the record to what those releases always built, and changes no schema |

Below 1.0 there is no compatibility (REQ-76), and a schema change edits what
declares the table rather than adding a migration beside it — within the
untagged release's migration. Once a release has tagged a migration, a change is
a migration after it.
The chain collapses into a single initial migration before 1.0, beside one
migration that upgrades a database the last 0.x release built. A database an
earlier 0.x release built is upgraded to that release first.

Migrations 1 to 36 each create something. Migrations 37 to 41 change existing
tables.

### Forward only

A database is only ever upgraded (REQ-72). Going back to an earlier release is restoring
the backup taken before the upgrade, which works on every engine and is exact.

| Rule | |
|---|---|
| No migration is applied downward | There is no `openpsirt migrate down`, and migration 40 and every migration after it register no way back |
| A database ahead of the binary is refused | At startup and by `openpsirt migrate up`, naming both versions and the backup. Its schema may hold what this binary cannot read |
| The upgrade note says to take a backup first | `docs/configuration.md` § Every upgrade |
| A migration a release tagged keeps the down function it shipped with | Its file is frozen by digest (§ Release records), so the function stays and nothing calls it. The collapse before 1.0 removes them |
| Upgrade tests run one way | A test reaches an earlier release's schema by emptying the database and applying migrations up to that release's last, never by walking down |

A migration is its statements and nothing else. What every one of them does
around those statements — asking which engine this is, refusing an engine there
are no spellings for, running each statement, naming the one that failed — is
one place. A copy per migration becomes a spelling per migration: one prints
the whole statement rather than its first line, so a failed table declaration
reports ninety lines of data definition, and another names the table and not
the statement. Dropping a table and dropping an index are the same rule — two
engines name an index's table and the other two refuse to — and held in copies,
the next migration is free to write it again with one arm missing.

### Migrations that stop half way

On MySQL and MariaDB a migration cannot be rolled back. Both commit
implicitly before and after every data-definition statement, so the transaction
each migration is given is decorative there. A failure at statement N leaves 1
to N-1 committed, the rollback removes nothing, and no version is recorded — so
the next start runs the same migration from statement 1 and fails on a name
already taken. Nothing recovers from that on its own; every replacement process
fails its startup probe in turn.

So on those two engines a statement is preceded by a question: does the thing
it creates already exist? If it does, it is stepped over and the step is
logged, and the migration reaches its end and records its version. The other
two have transactional data definition and never meet this, so they are not
asked.

| | |
|---|---|
| Why a probe rather than a keyword | MariaDB accepts `IF NOT EXISTS` on both a table and an index; MySQL accepts it only on a table. A probe is what the two have in common |
| What is stepped over | Only the exact object the statement names. One that cannot be identified is run, and fails as it always did — a skip on any collision could hide a real one |
| What it cannot tell apart | A statement that collides with something an earlier run made, and one that collides with something the same migration made two statements ago. The log is what surfaces the second |

CI runs the success path on four engines, which is where this hides: the
engines agree about what a migration does and disagree only about what is left
when one stops half way. So a migration stopped half way, with a table and an
index already made, is run again on both of these engines, and `make
check-engines` fails when either did not run it.

### Release upgrades

Each release after v0.1.0 that changes the schema carries one migration that
changes the schema the release before it built into its own, and moves the rows
with it: 37 carries a database from v0.1.0 to v0.2.0, 38 from v0.2.0 to v0.3.0,
39 from v0.4.0 to v0.5.0, and 40 from v0.5.0 to v0.6.0. v0.4.0 changes no schema and
carries none. A database a release built applies the ones after its own; a
fresh install walks the whole chain. They are shaped the way every migration after 1.0 will be.

| Rule | |
|---|---|
| Every table and index is made by the release's own statement | The release's declaration of each table it creates or changes sits beside its migration, with the reasoning for each. A column it adds is declared as that statement declares it. What the migration writes itself is the order, the rows, and how an existing table is changed on each engine |
| One transaction of its own | Registered without the migration library's transaction, because SQLite's foreign keys have to be switched off before a transaction begins, and because the rows it moves are read back by name |
| Not retried in place | Migrations 37 and 38 open that transaction directly rather than through the one retrying helper, and the releases that shipped them froze them. On PostgreSQL and SQLite a lost race fails the migration and the next start runs it again whole. On MySQL and MariaDB it leaves the schema part changed, as § Migrations says of any failed upgrade. A later release's migration takes its transaction through the helper |
| PostgreSQL, MySQL and MariaDB alter a table where it stands | A column every existing row fills is added with a default and the default dropped, which leaves it declared as the release declares it and costs no row rewrite on any of the three |
| SQLite rebuilds a table it cannot alter | It cannot drop a default or change whether a column takes a null. A replacement is made by the release's statement, the rows copied across by column name with their identifiers, the original dropped, and the replacement renamed. The indexes the table had from other migrations are read from the catalog first and made again |
| SQLite's foreign keys are off while it rebuilds | Dropping a table others point at is refused otherwise. The setting is ignored inside a transaction, so it is made before one begins, and every reference is checked before the transaction commits |
| Rows written with their own identifiers keep them | References into a moved table still land. PostgreSQL's identity does not move past a value it did not generate, so it is moved past them; the other three move on the insert |
| A column added is last in its table on the three servers | A table SQLite rebuilds has it where the release declares it. No query reads a column by position |
| On MySQL and MariaDB a failure part way is recovered from a backup | Both commit every data-definition statement as it runs, so the transaction does not hold the migration together there, and the version is not recorded. The operator page says to take one first |

What v0.1.0's rows become under migration 37:

| In v0.1.0 | After the upgrade |
|---|---|
| An embargo extension | A disclosure movement whose act is an extension, under the same identifier. v0.1.0 refused a move that was not later |
| An issuance, keyed on a product and an issue | An advisory per product and issue, with one edition, the one issue it covers, and its issuances beneath it keeping their identifiers, ordinals, digests and summaries |
| The name an advisory was issued under | The advisory's identifier. v0.1.0 used the issue's own identifier as the tracking identifier, and a revision that changed it would read as a second document. For an issue filed under a CVE since, it is the name minted for the flaw, kept among its aliases; that is wrong only for an issue refiled before its first issuance, and nothing v0.1.0 kept says which came first. These names were not minted from the configured prefix, so they are numbered in year zero, where no advisory minted from it lands |
| The first release date of an issued advisory | Frozen as the earliest recording of the issue in the product, which is what v0.1.0's document said |
| The document an issuance sent | Not kept by v0.1.0, and nothing can work it out again. Stored as null, which is what the column says for an issuance that kept only its digest; a published directory reads only issuances that kept their bytes, so it serves the advisory once it is issued again |
| A reported flaw | A reference minted the way one is today: the product's name, the year it was recorded, and six random digits. Judged when it was recorded, by whoever recorded it: v0.1.0 wrote a report only together with its flaw, which is the act a report is judged by today |
| A VEX statement | From a statement set, with no document name of its own: v0.1.0 read nothing else. The version it is about is read from its package identifier the way an upload is read today, and is empty where the identifier names none |
| The weaknesses of a flaw recorded here | The first named is primary. v0.1.0 wrote them in the order named, in one statement. An issue a scanner reported has none marked until a scan reports it again |
| A finding | Not exploited here. v0.1.0 had no record of that |
| A notification | Carried alone. Only a kind of message v0.1.0 did not have is carried together |
| A column v0.1.0 did not have and that takes a null | Null |
| A grant of undisclosed reading or triage | Carried unchanged, per product, across the estate, in a group binding and in a personal token's holds. It reaches undisclosed work alone, where in v0.1.0 it reached disclosed work too. Nothing grants the disclosed role on upgrade; the operator does, as the upgrade note in `docs/configuration.md` says |
| The disclosure extension threshold, under the name v0.1.0 gave it | Left under that name by migration 37, which nothing reads since. Migration 38 carries it to the disclosure movement threshold where that is unset, and removes it |

A test on each of the four engines builds a database to migration 36, writes a
row into every table, every column holding a value, plus the rows each move
above reads, and applies migration 37. It compares every column, index and
constraint against a database that walked the chain empty, compares every
value the release held with what the upgrade left, and checks each move in the
table above.

The upgrade over a v0.1.0 database holding 524,288 findings, which is the
largest table and one every engine changes:

| Engine | Time |
|---|---|
| PostgreSQL 16 | 0.7 s |
| SQLite | 7.5 s |
| MySQL 8.4 | 12.1 s |
| MariaDB 11.4 | 19.3 s |

### The v0.3.0 upgrade

Migration 38. Every change is a column added, which all four engines make where
the table stands, so no table is rebuilt.

| Column | What it holds |
|---|---|
| When a recorded flaw was first rated in its product | What its deadline counts from (REQ-33) |
| Whether a report was found here | Only a report sent in carries a disclosure date (REQ-37). A report is from outside unless somebody says otherwise |
| The license an inventory declares for a component | Empty on every row it finds. `DESIGN-findings.md` § Component licenses says what fills it |

What v0.2.0's rows become:

| In v0.2.0 | After the upgrade |
|---|---|
| A report | Sent in from outside. v0.2.0 wrote a report only where somebody said who told us |
| A recorded flaw with a severity in force in its product, published or rated there | Rated at the earliest recording of it in that product, which is when v0.2.0 started its clock. Its deadline, where it holds one, is counted from there on the windows for our own products as this release ships them. The settings that change those windows arrive with this release, so none is set yet. A deadline another rule took away stays away |
| A recorded flaw with no severity in force | Not rated, and without a deadline |
| A recorded flaw no report is the record of | Found here, which is what v0.2.0 meant by recording one with nobody named. It gives up its disclosure date. It gains no report, because v0.2.0 kept nothing saying who recorded it, so a later claim about it may be accepted as it rather than ruled a duplicate |
| A scanned finding | Unchanged |
| A component | No license |
| The disclosure extension threshold, under the name v0.1.0 gave it | Carried to the disclosure movement threshold where that is unset, and removed. Where both are set, the movement threshold is what v0.2.0 read, and it stands |
| The patch branch switch | Removed. The deployment's configuration turns the lookups on in v0.3.0 |

Tests on each of the four engines:

| Test | What it holds |
|---|---|
| A v0.2.0 database, a row in every table | Upgraded, every column, index and constraint matches a database that walked the chain empty, and every value it held is still there |
| A v0.1.0 database, a row in every table | Carried through migrations 37 and 38, it matches a database that walked the chain empty, and holds what it held |
| Recorded flaws of each kind | A recorded flaw rated as published and recorded in two builds days apart, one rated only by its product, one rated by nobody, one with no report, and a scanned finding, each against the table above |
| v0.3.0's declarations | Each table the release declares, each built beside the real one under a scratch name, are described exactly as the chain builds them: every column with its type, nullability and default, every constraint and every index. An index another migration adds is named as such |
| Renamed and unread settings | The threshold under v0.1.0's name, from a v0.1.0 and a v0.2.0 database, reads under the new name afterwards and the old row is gone; set under both names, the new one stands; the patch branch switch is gone |

### The v0.5.0 upgrade

Migration 39. The administrative trail gains the actor of each change, and the
person beside it takes a null where the actor is configuration. PostgreSQL,
MySQL and MariaDB alter the table where it stands; SQLite rebuilds it from the
release's declaration. Each name an issue answers to gains whether a person
typed it, a column added with its default on all four engines. A graph node
gains two columns that hold a null, and a build's claim gains its subject's
name folded and the version it was made about, which every engine adds where
the table stands. A notification
gains the team it is about, and a destination its platform, channel, topic and
the product or team it belongs to, with a reference for each; SQLite rebuilds
both tables from the release's declarations. What a person chose about chat,
and what has been carried to them there, are two new tables, and so are a
release an advisory marks affected, what an agreement to an advisory saw
about each release, and the builds a claim was made on. An issue gains the
day the known-exploited catalog listed it, a column that holds a null. A
movement of an embargo gains the ruling that recorded it and the claim its date
counts from, and its two dates take a null; SQLite rebuilds the table from the
release's declaration. A saved filter
loses its product, and its name becomes unique to its person. PostgreSQL, MySQL
and MariaDB alter the table where it stands, and MySQL and MariaDB drop and
declare again the person's key, which the unique index serves; SQLite rebuilds
it from the release's declaration.

| In v0.4.0 | After the upgrade |
|---|---|
| A trail row | A person's, keeping its person |
| A name an issue answers to | Not typed by a person, whoever recorded it: v0.4.0 kept nothing beside the name saying so |
| An administrator named in configuration, whose administration no group derived | Administration granted here cleared. They administer through the name, as `DESIGN-access.md` § The administration trail and the section on configuration's administration describe |
| Any other account | Unchanged |
| An open graph node | Gains columns for the package identifier and platform enumeration its build states, filled with its component's. The next scan of its build writes its own. The scan file is not kept, so a build nobody sends again keeps the component's |
| A closed graph node | Gains the two columns, holding nothing |
| A component's identity | Worked out again with the package identifier and the name with a version hashed apart. No two rows meet: two rows v0.4.0 held apart differ in what is hashed |
| A scan or refused upload's sender, recorded as a name | The key holding the name, else the person holding it, recorded as a key or a person and its identifier. A name held by neither is left as it is |
| An issue | Read as itself: it states its own identifier as the issue it is read as. v0.4.0 merged nothing |
| Merges | Two new tables, empty: the record of an issue merged into another, and of a decision a merge superseded. v0.4.0 refused the report that would have merged two issues |
| A rating claim | Unchanged, with no reason for withdrawal. Every claim v0.4.0 withdrew, a person withdrew |
| A notification | About no team |
| A destination | A webhook belonging to the deployment |
| A saved filter's query | In the words the findings list reads. The single word for known-exploited or fix-version-known becomes that flag, a word that narrowed nothing is dropped, and hidden components joined by commas become one parameter each. Every other parameter is kept as written |
| A saved filter | Its person's, in no product. Its query loses its scope and its grouping: the branch, the variant, a subtree of one build and its three qualifiers, what differs between builds, what is spread over variants, the run that opened it, and the view. Every other parameter is kept as written |
| One person's saved filters of one name in several products | The oldest keeps the name, the lower identifier where two are as old. One that, without its scope, is the same query preparing the same claim as an older one of that name is dropped: it is that filter twice. Each other is renamed after its product's display name, else its name, as `Kernel (Router)`, from the spelling it was saved under. Every name the person holds is reserved first, so a rename already held takes a number after it, as `Kernel (Router) 2`. A rename fits the 120 characters the endpoints take a name at: the product is cut to 60 first, and then the end of the filter's name goes |
| One person keeping more saved filters than the per-person limit | Kept. The list says how many it leaves out, and saving another is refused until they are under it |
| A key's or a personal token's name, stored as typed | Stored folded, as a username is. A key's name is unique across the deployment and a token's to the person holding it. Senders are read by the names v0.4.0 recorded before this |
| Two or more keys, or two or more of one person's tokens, whose names fold to one | The first keeps the folded name and stays as it was: one in force before a withdrawn one, then the oldest. Each other still in force is withdrawn at the moment of the upgrade, and a trail row records it with the upgrade as the actor, naming a token's owner as a withdrawal by a person does. One withdrawn already is left as it was. Each other is named by the folded name and its number, as `ci #7`, because the name is unique across withdrawn ones too. Every first holder is reserved before any is numbered, so one already named like a number keeps that name and the number moves past it, as `ci #7.2` |
| A key or token whose name is only spaces | Named `key #7` or `token #7` by its number, and left in force: it clashes with nothing |
| A build's claim about a named subject | Gains the subject's name folded, beside the producer's spelling. A claim naming only a package identifier gains nothing |
| An issue | Listed in the known-exploited catalog on no day: v0.4.0 read none. The first scan stating one re-clocks the issue's open exploited findings, as `DESIGN-remediation.md` § Deadlines describes |
| A movement of an embargo | A person's, naming no ruling |
| A flaw recorded here, undisclosed and open in a product with no disclosure date there, under a duplicate ruling in force covering a claim from outside | Dated by each such ruling in the order they took effect, where it brings the date earlier: the earliest claim from outside the ruling covers, by arrival or else by recording, plus the disclosure window. The first gives the date; a later one bringing it in past the movement threshold is recorded waiting for a second person and moves nothing. Each is a movement from its ruling, asked by its proposer when it took effect. A claim found here, a withdrawn ruling and a flaw with a date on any place there contribute nothing, unless every place holds exactly the date its rulings give, which is a flaw an earlier upgrade dated and a roll back kept |
| A build's claim | Gains the version it was made about, holding nothing. v0.4.0 kept no version beside a claim, so each covers what it covered before and keeps its identity. A claim whose document states its version only as a branch is read again with the version on the next scan, closing the stored one and opening one in its place, once |
| An advisory | Marks no release affected, and its agreements record no release's status. Two new tables, empty: v0.4.0 stated no release known not affected |
| A claim | Records no build it was made on. A new table, empty: v0.4.0 kept none, and nothing is guessed |

A username is the rule a key's and a token's name follow: the first to hold a
name keeps it, and a later one folding to it is refused. An upgrade cannot
refuse a credential that already exists, so the later one is withdrawn where a
person would be refused. A pipeline or script sending with it is refused from
the upgrade on and needs a new one; the key list or the owner's token list shows
it withdrawn under its numbered name, and the trail row says when. The names
move through placeholders nothing holds, so no step writes a name another row
still has.

One v0.4.0 database per engine holds the rows every check below puts in it,
and is upgraded once. Each check reads its own rows by what identifies them,
and asserts the upgrade as a subtest named for what it holds. Building v0.4.0
empties the database and applies every migration up to v0.4.0's last, which is
most of what a check costs, so the checks share the build.

| Check, on each of the four engines | What it holds |
|---|---|
| A v0.4.0 database with named, derived and granted administrators | Upgraded, only the named-only one's grant here is cleared, and they still administer |
| A v0.4.0 trail row | Upgraded, a person's, with its person |
| A v0.4.0 name for an issue | Upgraded, not typed by hand, and a name written after can say it was |
| A v0.4.0 database with components, open and closed nodes, and scans sent by a key, a person and a name nobody holds | Upgraded, each identity is the graph's, the open node holds its component's identifiers, the closed one none, and each sender is a key or a person |
| A v0.4.0 destination | Upgraded, a webhook belonging to the deployment |
| v0.5.0's declarations | Every table the release declares, built beside the real one under a scratch name, is described exactly as the chain builds it |
| A v0.4.0 database holding issues | Upgraded, every issue is read as itself and the merge tables are empty |
| A v0.4.0 saved filter in the old words, and one in the new | Upgraded, the first reads in the list's words and the second is unchanged |
| A v0.4.0 database with two people's saved filters: one name in several products with the oldest written after a younger one, a name the rename would take already held, a twin of the oldest once its branch goes, a product named longer than a filter may be, a filter named as long as one may be, a name held once with a scope and a grouping, a filter preparing a claim, and the other person's filter of the same name | Upgraded, the oldest keeps the name, one is renamed after its product and one is numbered past the name already held; the twin is dropped; both long renames fit the width the endpoints take; the name held once keeps its name and loses its scope and grouping; the claim is unchanged; the other person's is untouched; no filter names a product, and a second filter of one name for one person is refused |
| A v0.4.0 database with keys named in mixed capitals, three pairs folding to one name | Upgraded, every name is folded, and the key in force and then the older keeps a shared name and authenticates, including one moving onto a name a withdrawn key still holds. The other in force is withdrawn and refused, with one trail row by the upgrade; those withdrawn already keep their withdrawal time. Each is numbered, past a key already named like the number. A spaces-only key is numbered and stays in force, and a scan sent under a mixed-case name reads as that key |
| A v0.4.0 database with two people's tokens named in mixed capitals, three of one person's pairs folding to one name | Upgraded, as for keys, per person: the kept tokens authenticate, the duplicate in force is withdrawn and refused with one trail row naming its owner, those withdrawn already keep their withdrawal time, a spaces-only name and a name shaped like a number are handled as for keys, and the other person's token of the same name is untouched |
| A v0.4.0 database with claims about a name with a capital outside ASCII, a lower-case name, and a package identifier alone | Upgraded, each named claim holds its name folded and the other holds nothing, and none states a version |
| A v0.4.0 database with an undated flaw and a dated one under duplicate rulings — one covering a claim found here beside one from outside, one withdrawn, one bringing the date in within the threshold and one past it — and an exploited issue | Upgraded, the undated flaw is dated by the first and moved by the one within the threshold, the one past it waits, each is a movement naming its ruling and proposer, the dated flaw keeps its date, and the issue is listed on no day |
| A v0.4.0 claim | Upgraded, it records no build it was made on |

### The v0.6.0 upgrade

Migration 40. A window gains the window it counts from, a column that holds a
null, with a reference to the window table, and whether it counts from the
release of the fix, a column every existing window fills as false; SQLite
rebuilds the table from the release's declaration. A notice gains the reference
its recipient gave it and what it said about malice, two columns that hold a
null and that every engine adds where the table stands. The places a notice
named and the releases a record names as carrying its fix are new tables. A
group's role on a product is replaced by one naming its product by name, and a
group's role on every product is a new table. Configuration is the only source
of either and is applied at every start, so the role mappings v0.5.0 holds are
dropped rather than carried. Mappings to admin and audit are in a table this
leaves alone. A
key and a token each gain the name in force, filled from the name for every
credential not withdrawn, and the uniqueness of the name moves to it: a key's
across the deployment, a token's within its owner. The new rule is made before
the old one is dropped, because MySQL and MariaDB serve a token's owner key from
whichever of the two leads with the owner; SQLite rebuilds both tables.

| Check, on each of the four engines | What it holds |
|---|---|
| A v0.5.0 window and a notice answering it | Upgraded, the window counts from the moment the attack became known rather than from a notice or the fix, the notice says nothing about a reference or malice, the record names no fix release, and each declaration describes the table the migrations built |
| A v0.5.0 group mapping to a role on a product, and one to admin | Upgraded, the role mapping is gone and the admin mapping remains |
| A v0.5.0 key and token in force and one of each withdrawn | Upgraded, the one in force holds its name in force and the withdrawn one holds none, and the withdrawn name is accepted again |

### The untagged upgrade

Migration 41. Each change is a column added to a table the release declares
anew, the declaration being the tagged one with the column beside it.

| Table | Gains | Every engine |
|---|---|---|
| `finding` | The CVE record lines that closed it as unaffected, and the supplier's statement answering it | Two columns holding a null, added where the table stands |
| `scan_run` | The CVE record snapshot it read | A column holding a null, added where the table stands |
| `vex_statement` | The product the statement's component ships inside: its package identifier, its name and its version | Three columns holding a null, added where the table stands. A statement uploaded before the upgrade names none until it is uploaded again |
| `vex_issuance` | Which kind of document went out, every existing row taking this deployment's own, and its revisions numbered per build and kind | A column filled as it is added. The rule numbering revisions per build is replaced by one numbering them per build and kind, added before the old one is dropped, because MySQL and MariaDB refuse to drop the index a foreign key is served by. SQLite rebuilds the table |

| Rule | |
|---|---|
| The supplier's statement on a finding is a reference without a foreign key | A statement is superseded and never deleted, so the reference cannot dangle, and a column holding a null is added where the finding table stands on SQLite rather than rebuilding it |

| Check, on each of the four engines | What it holds |
|---|---|
| A v0.6.0 database | Upgraded, no finding holds record lines or a statement, no run a snapshot, no statement a product, and each declaration describes the table the migrations built |
| A VEX document a v0.6.0 deployment recorded as gone out | Upgraded, it is this deployment's own document. The other kind's first revision is accepted beside it, and a second first revision of the same kind is refused |

### Release records

A release's migrations are frozen by `make release-freeze`, on a branch from
the head of `main` that lands before the tag, and the release workflow refuses
a tag whose release is not frozen, by `make release-check`, before it builds
anything.
`DESIGN-packaging.md` § The release procedure says where the two sit.

| Step | What happens |
|---|---|
| 1. The untagged release carries one migration | Numbered after the previous release's last. Its table declarations are named for it, `v030` for v0.3.0: one digit per part of the version, so a release with a part past nine has no code and is refused, since v0.1.10 and v0.11.0 would both read as `v0110`. Every schema change before the tag edits that migration and those declarations |
| 2. Rehearse, from every earlier release, on each engine | A database the earlier release's own image built and seeded is upgraded by this tree and checked, as § Upgrade rehearsal says |
| 3. Freeze, on a branch from the head of `main` | With the four engines running: the schema the chain builds is described on each, then every file the release owns is listed with its digest and the release's last migration. A version older than one already recorded is refused: the last migration in the tree is the newer release's, and would be claimed |
| 4. Land the record through a pull request | The digest test and the schema test hold the tree to it from then on |
| 5. Check, then tag | `make release-check` on the commit to be tagged, then the tag. The release workflow checks the record again before anything is built |
| 6. The next schema change | A new migration, numbered after the tagged release's last, for the next release |

| The check refuses | Why |
|---|---|
| A release with no record | Nothing would hold what it shipped once the next change lands |
| A file the release owns that its record does not list, or lists with another digest | The record is stale: the tree moved after the freeze |
| A migration numbered past the release's last | It would ship with nothing holding it |
| Declarations named for a release nothing froze | The same, for the tables a migration reads |
| A record missing one engine's schema, or holding an empty one | The schema test cannot hold that engine |
| A tag that is not a release | A release is `vX.Y.Z`, and a release candidate `vX.Y.Z-rc.N`, held to the record of the release it precedes. Any other suffix is refused, so the output of `git describe` is never read as a release |

A file a release owns is a migration numbered after the previous release's
last up to its own, or a declaration named for it. A release that changes no
schema owns no file: its record lists none and carries the previous release's
last migration as its own.

| Situation | What to do |
|---|---|
| The release's migration needs a fix after the freeze, before the tag or between release candidates | Edit the release's migration and declarations, freeze it again in the same pull request, and recreate a database a release candidate built |
| A release is tagged | Its record is what it shipped. `make release-freeze` refuses a version whose tag exists, and a schema change is a migration numbered after its last, for the next release |
| A patch to an older line, after a newer release is recorded | Not cut. A tag is refused unless it is on `main`, and `main` holds the newer release's record and migrations, so every release is newer than the last one recorded |

### Upgrade rehearsal

`make upgrade-rehearsal FROM=<release> ENGINE=<engine>` upgrades a database an
earlier release built and filled itself. It is a step of the release
checklist above, run from every earlier release on each of the four engines.
It builds images and scans the demo's inventories, so it runs locally and not
in the gate.

| Stage | What it does |
|---|---|
| The release's database | The release's image is built from its tag, and its own demo targets run unedited against an empty database of the rehearsal's own: products, inventories, the scans, a VEX document, judgments and an approval, an assignment, and a recorded flaw |
| What it held | Its status report's open findings per build, and every table's row count with it stopped |
| The upgrade | This tree's image applies the migrations on their own. The version reached is this tree's last migration |
| The rows | Each table's count against what the upgrade tables above say: a table both sides hold keeps its count, a table only the upgrade holds starts empty, and a table the upgrade fills or removes holds what that table says |
| What the upgrade note asks | From a release whose note asks an operator to act, the rehearsal acts as it says before serving. From v0.1.0, that is the disclosed role granted beside every undisclosed one |
| Served | This tree's server on the upgraded database reports the same open findings per build, and no GET its API document lists answers 5xx. A GET with a path parameter the seed has no name for is skipped |

| Rule | |
|---|---|
| The release seeds itself | A fixture written today records what this tree thinks the release wrote. The release's own targets write what a deployment of it holds |
| Only the docker command is wrapped | The containers, network and ports are renamed so a demo already running is untouched, and the application is pointed at the rehearsal's database. Nothing in the release's targets is edited |
| Counted with nothing running | A server runs passes that write rows. Counted between the migrations alone, a changed count is the migration's |
| An engine `make engines-up` made is joined to the rehearsal's network | It publishes its port on this machine's loopback alone, which no container reaches. The container publishing the port the URL names joins the rehearsal's network and is addressed by its name, which holds on Docker Desktop, rootless Docker and Podman alike. An engine on another host is reached through `host.docker.internal` |
| Everything it made is removed | Pass or fail: its containers, network and database. The release's worktree, both images, the run's directory with its logs, and the scanner's database are kept. `-keep` leaves everything in place |

## Migration locks

| Lock | Excludes | Mechanism |
|---|---|---|
| Migration mutex | Other goroutines in this process | An ordinary mutex |
| Advisory lock | Other instances on the same database | `pg_advisory_lock`, which belongs to the database; `GET_LOCK` on a name carrying the database, since a MySQL named lock belongs to the server; an operating-system lock on a file beside a SQLite database |

Both are required. The in-process mutex exists because the migration library
keeps its dialect in package-level state, so two goroutines migrating at once
race on it regardless of any database lock. The advisory lock exists because a
rolling deployment starts several instances at once.

SQLite takes its lock outside the database, because it cannot take one inside.
The handle migrates on a single connection, so a lock held on a pinned
connection would hold the only connection the migration needs.

A migration that changes a table's shape on SQLite turns foreign keys off on a
connection and then opens its transaction. On a wider pool the transaction can
land on a connection where they are still on, and the connection they were
turned off on goes back into the pool that way. So the pool is narrowed to one
connection for the migration and put back as it was afterwards.

Assuming one process instead is enforced by one chart template, while the
binary accepts a SQLite URL with a warning. Four processes against one file
with no lock: one migrates and three fail on the migration library's own
bookkeeping. Nothing is corrupted and the schema ends correct, so what the lock
buys is those three waiting and finding the work already done.

The operating system's own advisory locking rather than a lock file written and
removed by hand, because the kernel drops it when a process ends however it
ends. A file left behind by a crash is one nothing will ever remove, and every
start afterwards refuses for a reason that stopped being true. A platform
without that locking refuses rather than returning a lock that locks nothing.

The advisory lock is taken on a pinned connection rather than on the pool. These
are session locks: released from the pool, the release can land on a different
connection, and neither engine reports that as an error — it fails to release and
the lock is held for the life of the process. The release result is read rather
than assumed, because both engines report "you did not hold this" as a value.

The wait is bounded on both engines. An unbounded wait means an instance wedged
mid-migration blocks every replacement silently, and the startup probe kills each
in turn.

| Rule | |
|---|---|
| The pinned connection is used every half minute while the lock is held | It is checked out of the pool for the whole migration, beyond the pool's idle timeout. Idle, a server's or an intermediary's idle timeout ends the session, the server releases the lock, and a waiting replica migrates the half-migrated schema |
| A keep-alive use carries no deadline | Both drivers close a connection whose query outlives its context, and the lock goes with the session, so a use that times out in a network stall is the same lost lock by another route |
| A lock not held at its release fails the migration | The session was lost part way, and another instance may have migrated alongside. The work finished; what it ran under is not certain, and that is an error rather than a warning |
| A pool of one connection is refused before the lock is taken, on the three servers | The lock holds one connection and the migration runs on another, so a pool of one waits for ever with nothing logged. The refusal names `OPENPSIRT_DB_MAX_OPEN` |

The bound is a session setting, and it is unwound before the connection goes
back — on every path, including the failing ones. Left set, one pooled
connection carries a five-minute bound while the others carry the server
default, and the same query afterwards either waits or is canceled depending
on which connection the pool hands out.

## Identifier quoting

Every identifier in the schema is quoted. A reserved word is only reserved when
bare, so leaving identifiers unquoted makes the set of usable column names the
intersection of four engines' keyword lists — a set nobody knows, growing with
every release, whose violations appear only on whichever engine somebody is least
likely to be developing against. A column named `rank` was accepted by three
engines and refused by the fourth, where it had become a window function.

A column reference a statement composes is quoted through one function, which
is the package's to own. The character it uses is the engine's own answer
rather than the standard quote the schema is written in: two of the four name
the backtick and take both, so either works today, and asking makes it true of
an engine that does not.

Owned nowhere, every caller writes identifiers bare and a helper takes a column
name as an ordinary string parameter, with nothing between it and a name
arriving from a query parameter but the habit of passing a literal. What a
caller may pass is a named type: a quoted column, or an expression the caller
composed and stands behind.

Two engines quote with backticks by default, so their connections are asked for
standard quoting. Backticks keep working and string literals are untouched: this
changes what a double quote means, not what a quote means.

The mode is appended to what is already in force, never assigned. Assigning
replaces the mode, and what it replaces includes whatever else an operator set:
a nine-character string stored in a four-character column then comes back four
characters long, with no error, on those two engines.

Strictness is named in the same breath rather than inherited. Appending alone
keeps whatever the server already held, and a server whose mode omits
strictness is the configuration that produces that truncation — routinely set
that way for older applications. Naming it makes the mode a property of this
application rather than of the server it was pointed at, and the set is
deduplicated, so naming one a server already holds changes nothing.

The gate reads three places. `AS <word>` is the syntax for inventing a name,
and matching that alone leaves a table renamed in a migration, which names no
alias, and a table alias declared in a model's own struct tag both invisible.
An alias of `as` — a word all four engines reserve — works only because the
library quotes what a tag declares, and the first raw expression naming it is a
syntax error on every one of them. Inside the migrations the gate reads the
data-definition keywords as well, with the comments beside them stripped first:
the prose that makes a schema legible is full of the words an engine
reserves.

A name a query invents needs the same care. `GROUPS` is a reserved word in
MySQL 8, where it names a window frame type, so a grouped count wrapping its
subquery in `AS groups` parses on three engines and is a syntax error on the
fourth — which the handler above turns into a 500 with the driver's message
discarded.

A name a query invents is checked for being bare, not for being reserved.
Compared against the list of words the four engines reserve, a name nobody has
reserved yet passes — and MySQL 8.0 reserved `rank`, `groups`, `lead` and
`cume_dist` with nothing refreshing the list, which is a strictly weaker
property than the rule it is meant to enforce. A quoted name does not match the
pattern at all, so every hit is by construction an unquoted one and the fix is
one pair of quotes.

The list of reserved words stays, for the other half. A name a migration
declares is not invented — every engine accepted it when the migration ran —
and the question there is whether it collides with a word one of them reserves,
which is what a list of those words answers.

Where a query is written is not what makes it a query. Reading only the
arguments of the query builder's own methods leaves every statement held in a
constant, returned from a helper or handed to the raw-query constructor
unchecked, under an all-clear. Every string literal that looks like a statement
is read, and `FROM "` or `JOIN "` is what marks one: every table here is
quoted, so that appears in SQL and not in prose, where matching the bare
keywords reports English sentences.

A table a query names is quoted too, and is checked outside the migrations.
A table is declared rather than invented, so the alias pattern cannot see one
at all, and nothing looked: they were bare in four hundred and eighty-eight
places and quoted in a handful, in the same clauses whose aliases were quoted.
What the migrations made is read first, and a word this schema has no table of
is not a table — which is how a clause keyword is told from a name without a
list of keywords that would go stale the same way the reserved list does.

The two halves are admitted differently, and for a reason. The alias half
reads only a literal recognizable as a query, because "as" is a word in nearly
every English sentence here. The table half reads every literal, because what
admits one is this schema's own table names — and a query whose tables are all
bare carries no quoted table to be recognized by, which is precisely the query
nothing was looking at. A table expression that is a table name and nothing
else is admitted where a method that names a table is being called, since no
pattern over the text alone tells `"person"` the table from `"person"` the kind
of subject.

Test queries are held to it too. They run against the same four engines,
and twenty-two of them named a table bare. The checker's own package is the one
exemption: a bare table in its fixtures is the input, not a defect.

A clause assembled in a variable is read where it is handed over. Three of
them reached the builder through a local built from literals a line earlier,
and a check that reads only what is written at the call read none of it — which
is the fragment nobody else has read either. Every literal a function puts in a
variable is gathered, which is more than any one run assembles, because reading
too much can only report a name somebody wrote bare somewhere in that function.
What was already read where it was written is left out, so one defect is
reported once.

A name that reaches SQL from outside the file is still invisible, because the
check reads source as text and there is no parser here for four dialects. That
is the safe direction for a check that fails a build. It looks only inside the
builder's own methods: reading doc comments too reports the English word "as"
as an invented name.

The schema is also read back from the database and checked there, on the same
principle as the index test: what matters is what an operator ends up with.

Two tests hold silent truncation, which is the worst shape a portability
difference can take: nothing fails and the data is wrong. Each was checked by
reverting the fix and watching it fail.

## Pattern matching

A search box is not a pattern language. Typing "50%" means a name containing
"50%", not every name containing "50"; "a_b" means what it says.

| Rule | Reason |
|---|---|
| Every value in a `LIKE` is escaped, and every clause states its escape character | SQLite has no default escape character at all, so omitting the clause makes a backslash mean one thing on three engines and another on the fourth |
| The escape character is `#`, and never a backslash | MySQL and MariaDB treat a backslash as an escape inside a string literal, so `ESCAPE '\'` is an unterminated string: a syntax error on two engines and parsed happily by the other two |
| The escaping lives here, with the other engine differences | Written out per package it is unexported in one and copied into the next, and the predicates in the package after that have none |
| A pattern the code wrote is not escaped; a value somebody supplied is | A trailing `/%` matching an ecosystem prefix is the pattern. The ecosystem inside it is not |

What its absence costs: the picker deciding who may be named on an embargoed
case answers a term of "%" with every person the deployment can offer, in one
request.

Folding happens in Go. `LOWER()` on SQLite is ASCII-only, so a term carrying a
non-ASCII capital compared against `LOWER()` of a column is found on three
engines and missed on the fourth. The component-name search, and the name a
build's claim is about, compare against a folded copy made on the way in. A
key's name and a personal token's are themselves stored folded. Issue identifiers, package identifiers,
descriptions and the person picker compare against `LOWER()` of the column,
which differs only outside ASCII.

## Affected-row counts

A conditional write reports a lost race only through the number of rows the
update touched. Zero means somebody got there first.

Two engines report rows *changed* by default; the other two report rows
*matched*. Under the first reading, a write whose condition held but whose
values were already correct reports zero, and the caller announces a conflict
that never happened — an approval refused with "the reasoning changed while
this was agreed to", for a decision nobody has touched.

The connection asks for matched rows on the engines that need it. The alternative
— writing every conditional update so its values are guaranteed to differ —
leaves a portability quirk for every future caller, and the one who forgets is
handed a false conflict rather than an error.

A test asserts the count on all four engines, checked by removing the setting and
watching exactly the two fail.

Reading the count is a helper rather than a rule people remember. "The row was
not there" and "I could not tell you" are different answers, and the callers
act on the first one — a count read as zero becomes "somebody got there first",
"you no longer hold this job", or a refusal for a write that committed. A count
that cannot be read is a fault.

No current driver returns an error there, which is why the helper exists rather
than the rule. Nothing fails today when a caller gets it wrong, and nothing
would report it on the day one starts.

## Recursion bound

| Engine | Stops a recursive statement after | Told |
|---|---|---|
| MySQL | a thousand rounds, with an error | `cte_max_recursion_depth` of a million |
| MariaDB | a thousand rounds, returning what it has, with a warning | `max_recursive_iterations` of a million |
| PostgreSQL, SQLite | nothing | nothing |

The walks down a build's graph carry no depth, so their rounds are the length of
the longest chain in the build, and a chain past a thousand is a legal document.
Short of the setting, MySQL fails the count beneath the tree's root and MariaDB
answers it short without saying so. A walk adds a component once, so no walk
takes more rounds than a build has components, which a million is past. Set on
the connection, named per engine because each refuses the other's name, and left
alone where the database URL sets it. A test walks a chain of 1,100 on all four,
and fails on those two without the setting.

## Absence and failure

A row that is not there and a read that could not be made are different answers,
and a store that wraps both alike makes every caller above it wrong at once.

| Rule | Reason |
|---|---|
| A reader says which of the two it hit | The caller chooses a status from it. Wrapped alike, the only status available is the one that asserts something the read never established |
| Absence is a sentinel each package words for itself | A caller matches on the sentinel through the wrapping. Matching on a message is the same mistake as reading an engine's error text |
| A failed read names the act, and the act reaches the log | "Look up product 12" is what an operator needs. What the driver said is not a thing to publish |
| One helper, not a rule people remember | Made by hand at every call site, it is made differently at most of them |
| A handler's error arm asks which error it holds before it answers 404 | An arm answering 404 for any error turns an outage into "that does not exist", and inside a transaction it drops the cause the retry helper reads. A gate reports an arm whose first statement answers 404 whatever the error was |
| A read that fills in part of an answer fails the answer | Left out, a field reads as its absence: a limit as no limit, a narrowed token as one reaching everything, a release note as leaving nothing out |
| A credential that cannot be looked up is a fault | Answered 503 with a time to ask again, and logged. Answered as not authorized, an outage sends every caller to sign in again |

Two readers of one two-column select telling the two apart differently is the
ordinary shape: `TargetFor` and `ExistingTarget` are that select, and a caller
of the one that does not turns its error into "nothing has been scanned there".

What that costs: a database nobody can reach reports to every authenticated
caller that their products, builds, issues and findings do not exist.

## Collation

Two of the four compare text case-insensitively by default. Left alone,
declaring `Widget` and then filing a scan against `widget` resolves on one pair
and creates a second product on the other, so the declaration rule that exists to
catch a typo would behave differently depending on which database an operator
runs.

The tables that need it are created with binary comparison.

## Replica coordination

Replicas are identical and there is no leader. Every one serves requests, reads
scans and runs vulnerability scans. Nothing is held in a process that decides
anything: sessions are rows, settings and roles are read per request, and the
only in-memory lock stops a single process migrating twice.

| Coordination | Mechanism |
|---|---|
| Two workers taking one job | A conditional update. Row locking sits beside it for throughput and is not the guarantee — see `DESIGN-queue.md` |
| Two replicas migrating at startup | A database-level lock with a bounded wait |
| Two scans of one build | The apply takes the build's own row first, so the second waits rather than interleaving |
| Two uploads checking the room left | The upload's transaction writes a fresh value into one fixed lock row before it sums what is held, so the second waits, and on a cluster the two writes conflict at certification. A write of the value already held is matched and not written on MySQL and MariaDB, so it never reaches certification |
| An administrator changing a setting | Read per request, so a change takes effect on every replica at once |

SQLite cannot take part, being a single file, so a scaled deployment runs on one
of the three servers.

## Retryable transactions

A clustered deployment certifies a write across nodes **at `COMMIT`**. Two nodes
that touched the same rows both run every statement successfully, and one is told
at the end that the whole transaction was rolled back. Code written for a single
server checks each statement, sees them all succeed, and never learns that none
of them happened.

Every transaction is therefore retryable as a whole, through one helper, on the
failures that mean a race was lost: deadlock, lock-wait timeout, serialization
failure. Anything else is reported rather than retried — an unrecognized failure
treated as retryable turns a constraint violation into a deployment that hammers
its database and hangs.

Nothing a transaction depends on may be read outside it. A retry re-runs the
closure against a database that has moved, so a value read before the
transaction began, or carried over from the attempt that failed, describes a
world that no longer exists. Anything a closure uses but does not fetch is a
defect.

| Read inside the write | What it decides |
|---|---|
| The limits on an act answering many issues | Whether the act is refused. A limit a caller left unset is the deployment's setting |
| How many findings one judgment may write | Whether a judgment across many places, or an extension of an agreed one, is refused |
| The longest a personal token may last | The ceiling the new token is held to |
| Whether the writer may write a note about an issue | Whether the note is written |
| Where each added build holds a recorded flaw's component | Which rows the flaw opens. A build that stopped shipping it is refused |
| What each part of a build is called, on recording that its VEX document went out | Whether the document names the build as it is now called; a rename in between is refused and asked again |

A read made before the transaction as an early refusal is repeated inside it;
the one inside decides.

A statement that fails inside a transaction is not always recoverable. On
PostgreSQL a failed statement aborts the whole transaction: every command after
it is refused until the block ends, whatever the caller made of the failure. So
a statement whose failure is the ordinary answer — an insert refused by a
primary key, where being refused is how a second replica learns the row is
already there — cannot sit bare inside a transaction. It stands on a savepoint
of its own, rolled back on refusal, and the transaction carries on; SAVEPOINT is
plain SQL on all four engines. Three of the four engines carry on after a failed
statement without one, so the quick loop never sees this.

An act is one transaction, and an act is what a person asked for. Recording
somebody and granting them the roles named, declaring a team and putting people
on it, filling in a stream's parent and recording when it went out, storing a
graph with what the build argued about its own patches: each is one request, and
written as a statement per part a refusal partway through answers "nothing
happened" over a database where half of it did. The caller then corrects the
request and sends it again, and the half that landed lands twice.

The record of an administrative act is inside it. The act and the row saying
who made it are one change: a setting moved with nobody recorded as having moved
it is the state the record exists to prevent, and a write that succeeded beside
a record that failed produced exactly that. A failure to record fails the act,
and the caller retries a request that changed nothing.

What follows the commit is what is not part of the act:

| Outside | Why |
|---|---|
| A job queued for what was written | A job pointing at an uncommitted graph is worse than one queued a moment late, so it is asked for after the commit — and a full backlog is not the write's failure |
| Work handed back when somebody loses their last role | A consequence of the withdrawal rather than part of it, and bounded by how much that person was holding rather than by the request |
| The deadline rewrite a policy change forces | Bounded by how much is open, measured at nineteen seconds against 441,108 findings, which is longer than a request |

A store handed a transaction joins it rather than refusing. Three spellings
exist:

| Spelling | Correct where |
|---|---|
| Refuse | The method owns the retry boundary. It decides what a retry re-reads, and cannot decide that from inside a transaction it does not control |
| Join | The requirement is only "both statements or neither", which the caller's transaction meets. Refusing makes the method uncallable from inside one |
| Join, and hand the race back | The method resolves a lost race by going again, and cannot from inside a caller's transaction: the failed statement has already aborted it on one engine, and the other half of the act is the caller's to re-run. It says it lost, and the caller's helper takes the whole act again |

The third is a named error the retry helper recognizes, beside the engine codes
it reads. The condition is one a query expresses rather than one an engine
reports — a conditional update that matched nothing because another writer moved
the row — so nothing in a driver's vocabulary says it. A handler answers it as
a fault that carries it: the helper reads the cause and goes again, and where
nothing goes again the caller is told 500 in words of the handler's own.

The joining spelling is a named helper rather than an `if` on the handle's type,
because written by hand it reads as a fallback to writing outside a transaction.
The reads rule reaches further in that case, not less far: the closure may be
re-run by a retry it cannot see.

The helper names every handle it accepts, and refuses the rest. A test for one
handle type is failed by a handle that merely embeds it, and an arm answering
that failure by running each statement as its own autocommit is no transaction,
no retry and nothing said — while the two spellings differ by four characters.
A handle nothing recognizes is a fault rather than a further silent path.

Giving up does not back off first. Nothing follows the last attempt, so a wait
before returning an error already decided holds the caller and its connection
for an interval that buys nothing — under exactly the sustained contention that
path exists to report.

## Reads a write depends on

A transaction is not a lock. At the isolation every engine opens with, a plain
read inside one answers from a snapshot, and the write that follows lands on
whatever the row holds when it runs.

| Two writers, one row | What happens |
|---|---|
| Both read | Neither waits. A plain select takes no lock on any of the three servers |
| Both write | The second waits for the first to commit, then writes over what it never saw |
| Both report what they replaced | Both name the value they read, and only one of them replaced it |

A value read inside the transaction and reported to the caller is carried in
the write or it is a guess. The update matches on the key *and* on what the
read answered with; a match of no rows means the row moved, and the attempt is
taken again in a new transaction. Reading again inside the failed one does not
work — MySQL and MariaDB fix the snapshot at the opening select, so the second
read is as stale as the first.

The damage is in the record rather than in the value: the row ends up holding
what the last writer wrote, and the trail says that writer replaced something
nothing ever held. That is the settings trail, where "who raised the floor to
critical, and from what" is the question being asked of it.

| Write | What it matches on beside the key |
|---|---|
| Agreeing to or withdrawing a rating | The state the claim was read in |
| Holding rows of a claim back, and setting them aside | Still waiting, and still the claim they were read from |
| Filling in what a tag was cut from | An empty parent; a lost race reads back what won and refuses a different branch |
| Changing a setting | The value read |

A locking read — `SELECT ... FOR UPDATE` — is the other answer, and is not used
for this: it is spelled per engine, and the condition works the same on all
four. See [Engine-specific code](#engine-specific-code).

Bounded retries rather than a loop. Two writers resolve in one more attempt,
three can take two, and contention that nothing resolves is reported rather
than spun on.

## Connection pool

The failure worth designing against is a far end that goes without a FIN or an
RST — a firewall dropping an idle flow, a load balancer timing out, a database
failing over. This side still believes the socket is fine, so the pool hands it
out, the query writes into nothing, and the read blocks until TCP retransmission
gives up: roughly fifteen minutes on common defaults, with nothing logged.

Go's pool cannot detect this. It never validates a connection before handing it
out, and the two driver hooks it calls before reuse inspect only local state.
The defense is to ensure a connection is never idle long enough to be killed.

| Setting | Default | Reason |
|---|---|---|
| Idle timeout | 1 minute | The load-bearing one. Must be shorter than the shortest idle timeout in the path: firewall, load balancer, or the server's own |
| Lifetime | 30 minutes | Recycles regardless of use, so connections redistribute after a failover instead of holding a machine that is no longer primary |
| Max open | 25 | Unbounded, a burst opens more than the server permits, and PostgreSQL is expensive per connection |
| Max idle | 25 | Go's default is 2, low enough that moderate load churns connections continuously |

Go's cleaner never runs more than once a second, however short the idle timeout
is set. A value below a second reaps no faster.

## SQLite settings

| Setting | Reason |
|---|---|
| The configured pool, as on the servers | In WAL mode readers block neither each other nor the writer. On one connection every request waits for the slowest read in flight: eight requests from one home page took 12.5 s together, and 4.4 s for the slowest alone |
| One connection to an in-memory database | Every connection to one opens a database of its own |
| Every transaction takes the write lock as it begins | A transaction begun deferred that reads and then writes cannot wait for a writer that committed after its read. Its snapshot is stale, so it fails at once and the busy timeout never applies |
| A busy timeout of a minute | Writers take turns on the one write lock. Without a timeout, a write that finds the lock held fails at once with "database is locked" rather than waiting its turn. The longest writer is a scan's apply, one transaction: 26.1 s for 321,067 findings, which a minute covers twice over |
| One connection while migrating | A migration's connection settings have to reach the transaction it opens. § Migration locks says why |
| One connection in the test harness | A read through the root handle inside a transaction then waits for ever on the connection the transaction holds, and the test's deadline reports it. On a wider pool the read answers from a second connection, outside the transaction, and nothing reports it |
| Write-ahead log, synchronous NORMAL | The default is a rollback journal synced twice per commit, and a scan applies hundreds of thousands of rows through it. In WAL mode a commit appends to the log, readers do not block the writer, and NORMAL syncs at a checkpoint. A process crash loses nothing; a power loss can lose the last commits, never consistency |
| Planner statistics refreshed at start and after every scan | SQLite gathers none unless asked, and without them it picks an index by how many equalities it matches rather than how many rows lie behind it. On a demo of 361,429 findings the review queue took 4.1 s and the list of what is running out 2.5 s; with statistics, 0.08 s and 0.13 s. A whole analysis, 0.66 s for those findings, because a scan changes how rows divide more than how many there are: after a second build added a tenth to the findings, statistics analyzed only on growth still described one build, and the findings list took 2.1 s where it takes 0.57 s. Sampling the first rows of each index took 71 ms and misjudged which findings were assigned. The servers keep their own |
| A connection lives a minute, and a refresh closes the idle ones | A connection reads the statistics when it opens and never again, and a schema change does not make it read them again. On a pool open across a refresh, the review queue took 4.1 s on each connection but the one that ran the analysis. Closing the idle ones reaches the rest at once; the lifetime bounds the ones in use at the time |

The pragmas are set on the connection string, and a URL may add its own after
them. The test harness adds `synchronous(OFF)`.

## Indexes

No index repeats the front of another. A B-tree on `(a, b)` answers a lookup on
`a` exactly as well as one on `(a)`, so an index whose columns lead another
index on the same table is maintained on every insert and update to those
columns and earns nothing.

Eight existed. Seven repeated the front of a unique constraint, which is where
they come from: a constraint declares an index without saying the word, so the
obvious index on a foreign key gets written beside one that already covers it.

A test asks the schema rather than the source, because what matters is what an
operator ends up with. It runs on SQLite alone — the one place in this suite
where that is deliberate rather than a compromise, since the engines do not
disagree about which columns an index is on, and reading index metadata is
spelled four different ways.

One exception, measured. The narrow index on what is open in a build leads the
wider covering one, and scanning the narrow one reads fewer pages. Over hundreds
of thousands of findings that is a trade. The same argument does not carry to
the decision table, which holds thousands of rows.

Dropping an index never costs a foreign key its index on the two engines that
require one: in every case the constraint that made the wider index leads with
the same column.

## Columns no query reads

Code doing something no design document describes gets re-examined, and a column
is the same kind of claim.

| Column | Read by |
|---|---|
| Which parser read a scan | A person. The document is deleted for a branch, so after a parser changes there is no other way to tell which stored records need re-uploading |
| Whether this deployment ran the scan | Nothing yet. Always true today; a producer sending its own findings is intended and not built, and a schema assuming we ran it could not take that later |
| How large a stored document is | A person asking whether retention is affordable. Derivable from the chunks, and kept because deriving it means reading the blobs to answer a question about their size |
| When a finding last moved | A finding open for years outlives whatever record of the change was kept elsewhere |
| When an identity was bound to a person | The audit trail for the one decision that cannot be undone by editing a role |
| What sent the upload that was refused | A person. "Which of our pipelines is the broken one" is the first question a deployment with several asks, and a refusal that names only the build does not answer it |
| What the refused document said it was built from | A person, for the out-of-order failure specifically: the refusal says the clock did not move, and this is what it said the time was |
| What the refused upload hashed to | A person, comparing the refusal against what the producer believes it sent. It is also how a producer retrying one broken document is told apart from one sending a differently broken document each night, which are different faults and read the same in the count |
| Who took an agreement to an advisory back | A person asking who stopped a document going out. An edit takes agreements back as a side effect of moving the words, so the person recorded here is often not the one who set out to withdraw anything |
| When an edition of an advisory was written | A person reconstructing what an advisory covered when somebody agreed to it. An edition records the title and the moment; which flaws it named is read from when each was added and taken off, which needs the moment |

A column that is written, never read, and has no answer to "who would want it" is
a defect. That is how the redundant indexes above were found.

## Column widths

Text a producer supplies is not given a width: a component's name, its version,
what it was forked from, an issue's identifier, a fix's version list. Nothing in
any format bounds these, and a column with a width turns a merely unusual value
into a failure of the whole scan that carried it — which is indistinguishable
from a product that stopped having problems.

The exception is text carrying a unique index, which needs a width. There the
value is refused with a sentence rather than shortened: a decision keyed on a
truncated version would be compared against the finding's full one, match
nothing, and say so nowhere.

Measured against the reference producer's real output: 6,845 components, longest
version 49 characters, longest name 120, longest package identifier 140, nothing
over 191.

## Text truncation

A cut is made on a character boundary, never at a byte offset.

| Rule | Reason |
|---|---|
| A value shortened to fit a width is cut between characters | A byte offset lands inside a multi-byte character about two times in three, and what is left is not valid UTF-8 |
| The write is refused by three engines of four | PostgreSQL refuses invalid UTF-8 outright, MySQL and MariaDB refuse it in strict mode, and SQLite stores it — which is the engine the quick loop runs |
| The two directions are separate operations | Keeping the head leaves the partial character at the end and keeping the tail leaves it at the front, so one of them trims backward and the other forward |
| Both live in one place | Every site wrote its own slice, and the ones that were correct were written by people who had already been bitten. The cut is one fact, so it is written once and called |

What it costs where it is missing is the failure that reports nothing: the
value being shortened is usually a message saying why something else failed, so
the refused write is the one recording a failure, and the operator is left with
neither.

A lookup key is cut in characters, which is how its column is declared; a
value bounded for a byte budget is cut in bytes. Both cut on a character
boundary.

## Test harness

The harness runs a test against every database available to it. SQLite always
runs; the production engines run when the environment points at them and are
skipped loudly otherwise.

The schema is built once per test binary, not once per test. On SQLite a file is
migrated on first use and copied per test; on each server the binary gets a
database of its own, named for the package and the checkout it is tested from.
The name hashes the directory as well as the import path, which is identical in
two checkouts, so one cannot drop the other's database mid-run.

| Rule | |
|---|---|
| The SQLite template is kept in this user's cache directory, readable by nobody else | Its name is derived from files anybody can read, so in the shared temporary directory another user could put a file there under it first |
| A harness call that cannot run beside the others says why | On SQLite a package's tests run in parallel, and the testing package panics on a second harness call in one test function or on one after `t.Setenv`. The failure names the rule instead |
| An engine left out is skipped with the reason, and a test holds the harness to it | A skip that passed silently would read as the engine having run |

| A test pins | Runs on |
|---|---|
| What a query returns, hides, conflicts on or spells | Every engine |
| Routing, authorization mapping, or a response's shape | SQLite and PostgreSQL, because nothing it pins varies by engine |

The line is drawn at SQL rather than at the package: a handler test that pins a
query keeps all four.

The harness also offers a handle whose `COMMIT` can be made to fail.

| | |
|---|---|
| Why it exists | A retry that is never exercised is a retry nobody has tested. The failure a cluster produces arrives at commit, on a transaction whose every statement already succeeded, and nothing else here can produce one — so the code that runs when it happens was reachable by no test at all |
| What it does | Refuses a stated number of commits, in the words this engine's lost-race check matches, rolling the work back the way a refused commit does. A hook runs between the refusal and the retry, which is where a test puts what another worker did in the meantime |
| What a test asserts with it | Both directions. That a value from the attempt which was rolled back does not survive into the next one, and that the work still happens — and that the path under test committed something the handle could refuse, because a write outside a transaction passes every other assertion by never running the code they are about |
| Why it is SQLite underneath | What is pinned does not vary by engine: the retry is driven by the error, and the error is synthesized. Opened with the pragmas every other SQLite connection gets, so foreign keys are enforced on it |

The rule has to be applied. Routing rules, VEX statements, teams, saved filters
and the administration trail have handler tests on the two-engine form, and
between them they hold a `LIKE` with an explicit escape, a case-folded `IN`, and
conditional updates read for whether the row was still there — three of the
exact shapes the four-engine matrix exists to catch. Those are pinned by store
tests on every engine, and the handler tests keep the two-engine form, which is
right for what they pin.

CI provides all four engines and then checks that all four ran, because a skipped
engine passes silently.

What the suite pins:

- Every engine is identified, with its version parsed
- MariaDB is distinguished from MySQL by asking the server
- A server below the floor is refused, proved against a real old server rather
  than against arithmetic
- Migrations apply and are idempotent on every engine, and a database ahead of the binary is refused
- The advisory lock excludes a second connection while held and admits it once
  released, driven directly from two pools
- Reading the schema version performs no schema changes

## Not built

Nothing is purged and nothing is partitioned. REQ-73 describes purging as
exporting rows to a compressed file before dropping them. No table is
partitioned, no retention pass runs, and nothing writes rows to a file before
removing them. The only deletion of old data is expired sessions, a plain
conditional delete.

This is stated because three documents leaned on it as though it were load
bearing: one explaining which engines are supported by it, one explaining where
attachments live by it, and the security checklist sending a reviewer to audit
the allowlisting of partition names that do not exist. The column to partition on
and the granularity are open questions.

## Limits

- The concurrency test does not cover the advisory lock. Every caller
  serializes on the in-process mutex first, so a test driving goroutines
  through the normal path passes with the advisory lock deleted entirely. It
  pins the mutex and nothing else.
- Queries are not bounded. No statement timeout, no blanket driver read
  timeout. Any such bound eventually kills legitimate slow work — a large
  report, an ingest transaction over tens of thousands of components — and the
  usual result is per-query exceptions until the bound means nothing. It would
  also cut off a migration part way through.
- Connections are not validated on checkout, because there is no hook for it. A
  validation helper with a short deadline exists for callers that would
  otherwise block on a dead connection, and readiness uses it. It costs a round
  trip per use and can only say a connection was alive a moment ago.
- A page size is clamped in one place. Every list takes a limit, and each had
  its own clamp written beside it — twenty-one of them, six different pairs of
  numbers. One helper takes what was asked, the most this list will give, and
  what it gives when nobody says.
- A SQLite write waiting on the write lock does not stop when its request
  does. The busy wait ignores the context: a write given 300 ms waited out
  the whole timeout, 55 s, and only then failed. So a write behind a scan's
  apply holds its goroutine and its connection until the lock comes free or
  the minute passes, whoever it was for. The driver offers no busy handler to
  replace it with. Writes queued in the process instead would respect the
  context, and would miss every write that is not a transaction.
- Index key length is tightest on MySQL, and package identifiers get long.
  Index a hash, not the raw string.
- Timestamp semantics differ between engines. Store UTC and be explicit about
  types.
- Migration 37 is kept or collapsed on the measurement above. The lasting test
  compares an upgraded database with one that walked the same chain empty, so
  a column the migration leaves out is missing from both and nothing notices.
  That the chain builds the schema the per-table migrations it replaced built
  was checked once, when it was written, and matched on all four engines.
