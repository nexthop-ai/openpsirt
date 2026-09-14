# Database

Engine support, migrations, locking, connection handling and the portability
rules the four supported engines impose.

Satisfies REQ-03, REQ-06, REQ-71, REQ-72, REQ-73.

## Contents

- [Supported engines](#supported-engines)
- [Engine-specific code](#engine-specific-code)
- [Engine detection](#engine-detection)
- [Migrations](#migrations)
- [Migration locks](#migration-locks)
- [Identifier quoting](#identifier-quoting)
- [Affected-row counts](#affected-row-counts)
- [Collation](#collation)
- [Replica coordination](#replica-coordination)
- [Retryable transactions](#retryable-transactions)
- [Connection pool](#connection-pool)
- [SQLite settings](#sqlite-settings)
- [Indexes](#indexes)
- [Columns no query reads](#columns-no-query-reads)
- [Column widths](#column-widths)
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
| Recognizing what an engine is telling us | Three questions, three functions: whether a failure is a lost race worth retrying (REQ-71), whether it is a unique constraint refusing a duplicate, and whether it came from the engine at all rather than from the caller asking for something impossible. Each is a different code in a different error type per engine, and each is asked somewhere a wrong answer is silent — a retry that never happens, a constraint message shown to a person, a broken database answered as a mistyped request |
| Subtracting two moments | No portable expression yields seconds from two timestamps: one returns an interval, one a number of days, the rest something else |
| Inserting a row another writer may already have written | Two of them want `ON CONFLICT` and the other two want `INSERT IGNORE`. For a table whose rows are facts rather than somebody's state, where two writers describing the same thing are agreeing |
| The job queue's locking | The only query outside this package, because the queue owns the statement |
| The test harness | It names every engine to choose a connection and to say which one ran, rather than to write a query — and the check that each engine ran is what keeps that naming honest |
| A test choosing which engine it runs on | The same act as the row above, written at the call site: `dbtest.Only(t, database.SQLite, …)` says a question has the same answer everywhere and is asked once. Allowed anywhere, because it selects an engine rather than branching a query on one — which is the distinction the whole rule is about |

This list is the complete set and is checked by grep rather than trusted —
`make confined`, which refuses a dialect named anywhere but the places above
and holds the same list, so widening one without the other is what fails. It
reads the tests too: a branch in a test is a branch, and the one thing it lets
past there is an engine named to choose which engine runs.

What it looks for is the branch rather than the SQL: the two upsert idioms as
bun spells them, and asking a handle which engine it is. Those were absent
from it at first, which made the one live branch in the tree written that way
invisible to it — a gate that cannot see the idiom the code actually uses is a
sentence rather than a check. The
sentence asserted that check before anything performed it, which is the shape
this list was written about: it stated three while there were five, because
each new one arrived under a comment calling itself one of the few places an
engine has to be asked. Two turned out to be the same expression written twice
in two packages.

### Silently wrong query shapes

Not engine-specific code — one query written once — but shapes an engine gets
wrong. Each is a silent wrong answer rather than an error, which is why they are
written down.

| Shape | What happens |
|---|---|
| `COUNT(DISTINCT …)` beside a window function | **MariaDB 11.4 returns no rows at all.** No error, an empty page, and a total from a second statement saying there was something to show. The findings list pages with `COUNT(*) OVER ()` and counts packages and consumers with `COUNT(DISTINCT)`; the two cannot sit in one statement, so the distinct counts moved to the statement that decorates the page |
| `SUM(CASE … END)` where an integer is wanted | Comes back as a decimal on two of the four, and the cast that fixes it is spelled per engine. Counted as two `COUNT`s instead, which reads the same everywhere |
| Ordering by a column the grouping does not determine | MySQL refuses it outright, and it is right to: a tie-break on a column that varies within a row is not a tie-break |

## Engine detection

The URL states which engine to expect. The server is asked anyway, because a
MySQL-protocol connection may be either MySQL or MariaDB and the URL cannot
settle it. Believing the URL would apply the wrong version floor and admit an
unsupported server. Detection reads the version string; MariaDB names itself in
its own.

A server below the floor stops the process at startup, with the version found
and the version required both named. The alternative is a failure much later, in
whichever query first needs something the server cannot do.

## Migrations

Embedded in the binary and applied at startup by default, so a deployment is one
artifact and an upgrade is deploying it. Automatic application can be disabled,
and `openpsirt migrate up|down|status` runs them separately for an operator who
would rather use different credentials at a time they choose.

Migrations are written in Go rather than SQL files, because they branch on the
engine. A timestamp column has no portable spelling: PostgreSQL has no
`DATETIME`, and MySQL's `TIMESTAMP` is a 32-bit value that can acquire an
implicit default and an on-update clause depending on server configuration.

Before the first release a migration is edited rather than added to (REQ-72). A
change to a table edits the migration that created it, and anybody holding a
development database recreates it. The migrations that exist are kept only
because walking the chain up and down catches an ordering mistake between two of
them, and they collapse into a single initial migration before the first
release.

Ten of them did the opposite and have been folded back into the migrations
that created their tables. What that cost while they stood: a four-statement
engine-specific rollback that existed only because a column was added later,
four files to read to know what one table holds, and ten more migrations for
the collapse to unpick. Every migration now creates something.

## Migration locks

| Lock | Excludes | Mechanism |
|---|---|---|
| Migration mutex | Other goroutines in this process | An ordinary mutex |
| Advisory lock | Other instances on the same database | `pg_advisory_lock`, which belongs to the database; `GET_LOCK` on a name carrying the database, since a MySQL named lock belongs to the server; nothing on SQLite |

Both are required. The in-process mutex exists because the migration library
keeps its dialect in package-level state, so two goroutines migrating at once
race on it regardless of any database lock. The advisory lock exists because a
rolling deployment starts several instances at once.

The advisory lock is taken on a pinned connection rather than on the pool. These
are session locks: released from the pool, the release can land on a different
connection, and neither engine reports that as an error — it fails to release and
the lock is held for the life of the process. The release result is read rather
than assumed, because both engines report "you did not hold this" as a value.

The wait is bounded on both engines. An unbounded wait means an instance wedged
mid-migration blocks every replacement silently, and the startup probe kills each
in turn.

## Identifier quoting

Every identifier in the schema is quoted. A reserved word is only reserved when
bare, so leaving identifiers unquoted makes the set of usable column names the
intersection of four engines' keyword lists — a set nobody knows, growing with
every release, whose violations appear only on whichever engine somebody is least
likely to be developing against. A column named `rank` was accepted by three
engines and refused by the fourth, where it had become a window function.

Two engines quote with backticks by default, so their connections are asked for
standard quoting. Backticks keep working and string literals are untouched: this
changes what a double quote means, not what a quote means.

The mode is appended to what is already in force, never assigned. Assigning
replaces the mode, and what it replaces includes the strictness that makes an
oversized value an error rather than a quiet truncation. The first version
assigned, and a nine-character string stored in a four-character column came
back four characters long, with no error, on those two engines.

The gate reads three places, because it read one. `AS <word>` is the syntax for
inventing a name and was the whole of what it matched — so a table renamed in a
migration, which names no alias, and a table alias declared in a model's own
struct tag were both invisible to it. The settings table was aliased `as`, which
all four engines reserve, and worked only because the library quotes what a tag
declares; the first raw expression naming that alias would have been a syntax
error on every one of them. Inside the migrations it reads the data-definition
keywords as well, with the comments beside them stripped first — the prose that
makes a schema legible is full of the words an engine reserves.

A name a query invents needs the same care. A grouped count wrapped its subquery
in `AS groups`, and `GROUPS` is a reserved word in MySQL 8, where it names a
window frame type. Three engines parsed it and one returned a syntax error,
which the handler above turned into a 500 with the driver's message discarded.

There are about two hundred and thirty invented names in the tree, so this is a
gate rather than an audit. The words each engine reserves are held in one list
with its provenance, asked of the running servers rather than typed, and a check
reads every `AS` inside a query-building call.

The check reads source as text, because SQL is inside the strings and there is no
parser here for four dialects. That makes it blind to an alias built by
concatenation, which is the safe direction for a check that fails a build. It
looks only inside the builder's own methods: a version that read doc comments
reported eighteen names, every one the English word "as".

Two tests hold silent truncation, which is the worst shape a portability
difference can take — nothing fails and the data is wrong. Both were checked by
reverting the fix and watching them fail.

## Affected-row counts

A conditional write reports a lost race only through the number of rows the
update touched. Zero means somebody got there first.

Two engines report rows *changed* by default; the other two report rows
*matched*. Under the first reading, a write whose condition held but whose
values were already correct reports zero, and the caller announces a conflict
that never happened. It surfaced as an approval refused with "the reasoning
changed while this was being agreed to", for a decision nobody had touched.

The connection asks for matched rows on the engines that need it. The alternative
— writing every conditional update so its values are guaranteed to differ —
leaves a portability quirk for every future caller, and the one who forgets is
handed a false conflict rather than an error.

A test asserts the count on all four engines, checked by removing the setting and
watching exactly the two fail.

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

**A statement that fails inside a transaction is not always recoverable.** On
PostgreSQL a failed statement aborts the whole transaction: every command after
it is refused until the block ends, whatever the caller made of the failure. So
a statement whose failure is the ordinary answer — an insert refused by a
primary key, where being refused is how a second replica learns the row is
already there — cannot sit inside a transaction with the work that follows it.
It runs on its own, and what needs the retry goes in the transaction. Three of
the four engines carry on after a failed statement, so the quick loop never
sees this.

A store handed a transaction joins it rather than refusing. Both spellings exist:

| Spelling | Correct where |
|---|---|
| Refuse | The method owns the retry boundary. It decides what a retry re-reads, and cannot decide that from inside a transaction it does not control |
| Join | The requirement is only "both statements or neither", which the caller's transaction meets. Refusing makes the method uncallable from inside one |

The joining spelling is a named helper rather than an `if` on the handle's type,
because written by hand it reads as a fallback to writing outside a transaction.
The reads rule reaches further in that case, not less far: the closure may be
re-run by a retry it cannot see.

## Connection pool

The failure worth designing against is a far end that goes without a FIN or an
RST — a firewall dropping an idle flow, a load balancer timing out, a database
failing over. This side still believes the socket is fine, so the pool hands it
out, the query writes into nothing, and the read blocks until TCP retransmission
gives up: roughly fifteen minutes on common defaults, with nothing logged.

Go's pool cannot detect this. It never validates a connection before handing it
out, and the two driver hooks it calls before reuse inspect only local state.
**The defense is to ensure a connection is never idle long enough to be killed.**

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
| One connection | SQLite has a single writer. More connections add contention rather than concurrency: transactions on different connections collide instead of queueing |
| A busy timeout | Without one, a concurrent access fails immediately with "database is locked" rather than waiting its turn |
| Write-ahead log, synchronous NORMAL | The default is a rollback journal synced twice per commit, and a scan applies hundreds of thousands of rows through it. In WAL mode a commit appends to the log, readers do not block the writer, and NORMAL syncs at a checkpoint. A process crash loses nothing; a power loss can lose the last commits, never consistency |

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

## Test harness

The harness runs a test against every database available to it. SQLite always
runs; the production engines run when the environment points at them and are
**skipped loudly** otherwise.

The schema is built once per test binary, not once per test. On SQLite a file is
migrated on first use and copied per test; on each server the binary gets a
database of its own, named for the package and the checkout it is tested from.
The name hashes the directory as well as the import path — the import path alone
was identical in two checkouts, and one dropped the other's database mid-run.

| A test pins | Runs on |
|---|---|
| What a query returns, hides, conflicts on or spells | Every engine |
| Routing, authorization mapping, or a response's shape | SQLite and PostgreSQL, because nothing it pins varies by engine |

The line is drawn at SQL rather than at the package: a handler test that pins a
query keeps all four.

The rule has to be applied, and a whole area arrived on two engines. Routing
rules, VEX statements, teams, saved filters and the administration trail were
written with handler tests on the two-engine form, and every one of them pins
what a query returns. Between them they hold a `LIKE` with an explicit escape, a
case-folded `IN`, and conditional updates read for whether the row was still
there — three of the exact shapes the four-engine matrix exists to catch.

The fix was a store test rather than a change to the handler tests, whose
two-engine form is right for what they pin.

CI provides all four engines and then checks that all four ran, because a skipped
engine passes silently.

What the suite pins:

- Every engine is identified, with its version parsed
- MariaDB is distinguished from MySQL by asking the server
- A server below the floor is refused, proved against a real old server rather
  than against arithmetic
- Migrations apply, are idempotent, and roll back on every engine
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

- **The concurrency test does not cover the advisory lock.** Every caller
  serializes on the in-process mutex first, so a test driving goroutines through
  the normal path passes with the advisory lock deleted entirely. It pins the
  mutex and nothing else.
- **Queries are not bounded.** No statement timeout, no blanket driver read
  timeout. Any such bound eventually kills legitimate slow work — a large report,
  an ingest transaction over tens of thousands of components — and the usual
  result is per-query exceptions until the bound means nothing. It would also cut
  off a migration part way through.
- **Connections are not validated on checkout**, because there is no hook for it.
  A validation helper with a short deadline exists for callers that would
  otherwise block on a dead connection, and readiness uses it. It costs a round
  trip per use and can only say a connection was alive a moment ago.
- **A page size is clamped in one place.** Every list takes a limit, and each had
  its own clamp written beside it — twenty-one of them, six different pairs of
  numbers. One helper takes what was asked, the most this list will give, and what
  it gives when nobody says.
- **Index key length is tightest on MySQL**, and package identifiers get long.
  Index a hash, not the raw string.
- **Timestamp semantics differ between engines.** Store UTC and be explicit about
  types.
