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
- [Cutting text to a width](#cutting-text-to-a-width)
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
schema are written against. **It is not a statement that upstream still
publishes fixes for that series** — MySQL 8.0 and MariaDB 10.6 are both past
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
| Inserting a row another writer may already have written | Two of them want `ON CONFLICT` and the other two want `INSERT IGNORE`. For a table whose rows are facts rather than somebody's state, where two writers describing the same thing are agreeing |
| The job queue's locking | The only query outside this package, because the queue owns the statement |
| The test harness | It names every engine to choose a connection and to say which one ran, rather than to write a query — and the check that each engine ran is what keeps that naming honest |
| Listing the harness's own databases | The one query in the harness that does branch. PostgreSQL keeps databases in a catalog of its own, where the standard information schema describes only the one connected to, and there is no portable third spelling |
| A test choosing which engine it runs on | The same act as the row above, written at the call site: `dbtest.Only(t, database.SQLite, …)` says a question has the same answer everywhere and is asked once. Allowed anywhere, because it selects an engine rather than branching a query on one — which is the distinction the whole rule is about |
| Asking each engine what words it reserves | One statement per engine, because each publishes its keywords somewhere of its own and two publish nothing a query can read. It is not a query the application runs: it regenerates the word list the quoting gate reads, and the gate exists because the four engines do not reserve the same words |

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

The connection is asked one further question at startup: what encryption it
negotiated. That answer never stops a start — a server that will not say is
still a server that answered the version question.

## Connection encryption

Every engine negotiates opportunistically, and neither driver says which way it
went. So a deployment that believed the connection to its findings was
encrypted had nowhere to look, and the two drivers disagreed about the default:
one negotiated where the server offered it, the other connected in cleartext
unless asked.

| | |
|---|---|
| The default | Encrypted where the server offers it, cleartext where it does not, no certificate checked. The same on every engine, so one URL grammar no longer means two transports |
| What it is not | A guarantee. A deployment needing one says so in the URL, and whatever the URL says about the transport is left as written — this sets a floor, it does not override an answer only the deployment can give |
| How anybody knows | The connection is asked what it negotiated, and the answer is in the line that logs the engine and version. A production engine connected in cleartext is warned about by name, with the setting that fixes it |

Asked rather than assumed, because the intention and the outcome differ exactly
when it matters: a server that does not offer encryption is answered in
cleartext by a deployment that asked for it.

## Migrations

Embedded in the binary and applied at startup by default, so a deployment is one
artifact and an upgrade is deploying it. Automatic application can be disabled,
and `openpsirt migrate up|down|status` runs them separately for an operator who
would rather use different credentials at a time they choose.

**With automatic application off, the schema is compared before anything is
served.** The binary and the schema then move independently, and nothing
compared them: a build carrying a new migration started, granted
administrators, answered the readiness probe — which is a ping — and failed
every request touching the new table. In a rolling deployment the probe passing
is what retires the last replica that worked.

| Applied version | What happens |
|---|---|
| Behind what the binary carries | Refused at startup, naming both versions and what to run. The previous replica stays up, which is what a startup refusal buys over a readiness failure |
| Equal | Served, and the two versions are logged |
| Ahead | Served. That is a rollback, and the migrations a newer binary applied are additive — refusing would leave a bad deployment with no way back |

What the binary carries is the highest version among the embedded migration
sources, read from their file names, which is the same rule the migration
library applies to them.

**Version zero means nothing is applied, and nothing else.** The bookkeeping
table is looked for before the version is read, so a read-only inspection does
not create it. Selecting from the table to find out answers three questions at
once and cannot tell them apart — it is not there, this credential may not read
it, or the database is unreachable — and all three read as the first, so
`migrate status` printed version 0 for a fully populated database whose
credentials omitted that one table. The reasonable thing to do about "nothing
is applied" is to migrate it.

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

**A migration is its statements and nothing else.** What every one of them does
around those statements — asking which engine this is, refusing an engine there
are no spellings for, running each statement, naming the one that failed — is
one place. Thirty-three copies of it had already become four spellings of one
failure: two printed the whole statement rather than its first line, so a failed
table declaration reported ninety lines of data definition, and two more named
the table and not the statement. Dropping a table and dropping an index are the
same: two engines name an index's table and the other two refuse to, and that
rule stood in two independent copies with a third migration free to write it a
third time with one arm missing.

### Migrations that stop half way

**On MySQL and MariaDB a migration cannot be rolled back.** Both commit
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

CI runs the success path on four engines, which is why this was invisible: the
engines agree about what a migration does and disagree only about what is left
when one stops half way.

## Migration locks

| Lock | Excludes | Mechanism |
|---|---|---|
| Migration mutex | Other goroutines in this process | An ordinary mutex |
| Advisory lock | Other instances on the same database | `pg_advisory_lock`, which belongs to the database; `GET_LOCK` on a name carrying the database, since a MySQL named lock belongs to the server; an operating-system lock on a file beside a SQLite database |

Both are required. The in-process mutex exists because the migration library
keeps its dialect in package-level state, so two goroutines migrating at once
race on it regardless of any database lock. The advisory lock exists because a
rolling deployment starts several instances at once.

**SQLite takes its lock outside the database, because it cannot take one
inside.** The handle is capped at a single connection — the file has one writer
— so a lock held on a pinned connection would be holding the only connection
the migration needs. What stood instead was the assumption that SQLite is only
ever used by one process, enforced by one chart template while the binary
accepts a SQLite URL with a warning. Four processes against one file with no
lock: one migrated and three failed, on the migration library's own
bookkeeping. Nothing was corrupted and the schema ended correct, so what the
lock buys is those three waiting and finding the work already done.

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
an engine that does not. It owned none, so every caller wrote identifiers bare
and two helpers took a column name as an ordinary string parameter — with
nothing between them and a name arriving from a query parameter except that
every caller happened to pass a literal. What a caller may pass is a named type
now: a quoted column, or an expression the caller composed and stands behind.

Two engines quote with backticks by default, so their connections are asked for
standard quoting. Backticks keep working and string literals are untouched: this
changes what a double quote means, not what a quote means.

The mode is appended to what is already in force, never assigned. Assigning
replaces the mode, and what it replaces includes whatever else an operator set.
The first version assigned, and a nine-character string stored in a
four-character column came back four characters long, with no error, on those
two engines.

Strictness is named in the same breath rather than inherited. Appending alone
keeps whatever the server already held, and a server whose mode omits
strictness is the configuration that produces that truncation — routinely set
that way for older applications. Naming it makes the mode a property of this
application rather than of the server it was pointed at, and the set is
deduplicated, so naming one a server already holds changes nothing.

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

**A name a query invents is checked for being bare, not for being reserved.**
The check compared each one against a list of 321 words the four engines
reserve, which is a strictly weaker property than the rule it was the
enforcement of: a name nobody has reserved *yet* passed, and MySQL 8.0 reserved
`rank`, `groups`, `lead` and `cume_dist` with nothing refreshing the list. A
quoted name does not match the pattern at all, so every hit is by construction
an unquoted one and the fix is one pair of quotes. There were 1,418 of them
against 34 already quoted, so no reader could tell which was the convention.

The list of reserved words stays, for the other half. A name a migration
*declares* is not invented — it was accepted by every engine when the migration
ran — and the question there is whether it collides with a word one of them
reserves, which is what a list of those words answers.

Where a query is written is not what makes it a query. Reading only the
arguments of the query builder's own methods left every statement held in a
constant, returned from a helper or handed to the raw-query constructor
unchecked — thirty-eight bare names, under an all-clear. Every string literal
that looks like a statement is read now, and `FROM "` or `JOIN "` is what
marks one: every table here is quoted, so that appears in SQL and not in
prose, where matching the bare keywords reported sixty-odd English sentences.

**A table a query names is quoted too, and is checked outside the migrations.**
A table is declared rather than invented, so the alias pattern cannot see one
at all, and nothing looked: they were bare in four hundred and eighty-eight
places and quoted in a handful, in the same clauses whose aliases were quoted.
What the migrations made is read first, and a word this schema has no table of
is not a table — which is how a clause keyword is told from a name without a
list of keywords that would go stale the same way the reserved list does.

**The two halves are admitted differently, and for a reason.** The alias half
reads only a literal recognizable as a query, because "as" is a word in nearly
every English sentence here. The table half reads every literal, because what
admits one is this schema's own table names — and a query whose tables are all
bare carries no quoted table to be recognized by, which is precisely the query
nothing was looking at. A table expression that is a table name and nothing
else is admitted where a method that names a table is being called, since no
pattern over the text alone tells `"person"` the table from `"person"` the kind
of subject.

**Test queries are held to it too.** They run against the same four engines,
and twenty-two of them named a table bare. The checker's own package is the one
exemption: a bare table in its fixtures is the input, not a defect.

**A clause assembled in a variable is read where it is handed over.** Three of
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
builder's own methods: a version that read doc comments reported eighteen
names, every one the English word "as".

The schema is also read back from the database and checked there, on the same
principle as the index test: what matters is what an operator ends up with.

Two tests hold silent truncation, which is the worst shape a portability
difference can take — nothing fails and the data is wrong. Both were checked by
reverting the fix and watching them fail.

## Pattern matching

A search box is not a pattern language. Typing "50%" means a name containing
"50%", not every name containing "50"; "a_b" means what it says.

| Rule | Reason |
|---|---|
| Every value in a `LIKE` is escaped, and every clause states its escape character | SQLite has no default escape character at all, so omitting the clause makes a backslash mean one thing on three engines and another on the fourth |
| The escape character is `#`, and never a backslash | MySQL and MariaDB treat a backslash as an escape inside a string literal, so `ESCAPE '\'` is an unterminated string: a syntax error on two engines and parsed happily by the other two |
| The escaping lives here, with the other engine differences | It was written out twice, unexported in one package and copied into another, while four predicates in two further packages had none |
| A pattern the code wrote is not escaped; a value somebody supplied is | A trailing `/%` matching an ecosystem prefix is the pattern. The ecosystem inside it is not |

What that cost where it was missing: the picker deciding who may be named on
an embargoed case answered a term of "%" with every person the deployment
could offer, in one request.

Folding happens in Go and again in the engine. Folding in Go is Unicode-aware
and `LOWER()` on SQLite is ASCII-only, so a term carrying a non-ASCII capital
is found on three engines and missed on the fourth wherever the column has no
folded copy. The component half has one; the issue half does not, and issue
identifiers are ASCII in every scheme anybody publishes — which is why this is
written down rather than fixed.

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

Reading the count is a helper rather than a rule people remember. "The row was
not there" and "I could not tell you" are different answers, and the callers
act on the first one — a count read as zero becomes "somebody got there first",
"you no longer hold this job", or a refusal for a write that committed. A count
that cannot be read is a fault.

No current driver returns an error there, which is why the helper exists rather
than the rule. Nothing fails today when a caller gets it wrong, and nothing
would report it on the day one starts.

## Absence and failure

A row that is not there and a read that could not be made are different answers,
and a store that wraps both alike makes every caller above it wrong at once.

| Rule | Reason |
|---|---|
| A reader says which of the two it hit | The caller chooses a status from it. Wrapped alike, the only status available is the one that asserts something the read never established |
| Absence is a sentinel each package words for itself | A caller matches on the sentinel through the wrapping. Matching on a message is the same mistake as reading an engine's error text |
| A failed read names the act, and the act reaches the log | "Look up product 12" is what an operator needs. What the driver said is not a thing to publish |
| One helper, not a rule people remember | The split was made by hand at thirty-eight call sites and made correctly at five |

The correct spelling already existed six times in the catalog beside readers
that did not have it — `TargetFor` and `ExistingTarget` are the same two-column
select, and only one of them told the two apart. `ExistingTarget` has
twenty-three callers, twenty-one of which turned its error into "nothing has
been scanned there".

What that cost: a database nobody could reach reported to every authenticated
caller that their products, builds, issues and findings did not exist.

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

**An act is one transaction, and an act is what a person asked for.** Recording
somebody and granting them the roles named, declaring a team and putting people
on it, filling in a stream's parent and recording when it went out, storing a
graph with what the build argued about its own patches: each is one request, and
written as a statement per part a refusal partway through answers "nothing
happened" over a database where half of it did. The caller then corrects the
request and sends it again, and the half that landed lands twice.

Two things stay outside it, deliberately:

| Outside | Why |
|---|---|
| A job queued for what was written | A job pointing at an uncommitted graph is worse than one queued a moment late, so it is asked for after the commit — and a full backlog is not the write's failure |
| The row the append-only trail gets | Written inside, it would describe a grant a later refusal rolled back, and the trail cannot take a line out again |

A store handed a transaction joins it rather than refusing. Both spellings exist:

| Spelling | Correct where |
|---|---|
| Refuse | The method owns the retry boundary. It decides what a retry re-reads, and cannot decide that from inside a transaction it does not control |
| Join | The requirement is only "both statements or neither", which the caller's transaction meets. Refusing makes the method uncallable from inside one |

The joining spelling is a named helper rather than an `if` on the handle's type,
because written by hand it reads as a fallback to writing outside a transaction.
The reads rule reaches further in that case, not less far: the closure may be
re-run by a retry it cannot see.

**The helper names every handle it accepts, and refuses the rest.** A test for
one handle type is failed by a handle that merely embeds it, and the arm that
answered the failure ran each statement as its own autocommit — no transaction,
no retry, nothing said, and the two spellings differ by four characters. A
handle nothing recognizes is a fault rather than a further silent path.

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

**A value read inside the transaction and reported to the caller is carried in
the write or it is a guess.** The update matches on the key *and* on what the
read answered with; a match of no rows means the row moved, and the attempt is
taken again in a new transaction. Reading again inside the failed one does not
work — MySQL and MariaDB fix the snapshot at the opening select, so the second
read is as stale as the first.

The damage is in the record rather than in the value: the row ends up holding
what the last writer wrote, and the trail says that writer replaced something
nothing ever held. That is the settings trail, where "who raised the floor to
critical, and from what" is the question being asked of it.

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

## Cutting text to a width

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

A width is measured in characters and the bound here is in bytes, so a name
outside ASCII is shortened further than the column requires. That is the safe
direction — the bound belongs to a lookup key, and the full value is stored
beside it without one.

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

The harness also offers a handle whose `COMMIT` can be made to fail.

| | |
|---|---|
| Why it exists | A retry that is never exercised is a retry nobody has tested. The failure a cluster produces arrives at commit, on a transaction whose every statement already succeeded, and nothing else here can produce one — so the code that runs when it happens was reachable by no test at all |
| What it does | Refuses a stated number of commits, in the words this engine's lost-race check matches, rolling the work back the way a refused commit does. A hook runs between the refusal and the retry, which is where a test puts what another worker did in the meantime |
| What a test asserts with it | Both directions. That a value from the attempt which was rolled back does not survive into the next one, and that the work still happens — and that the path under test committed something the handle could refuse, because a write outside a transaction passes every other assertion by never running the code they are about |
| Why it is SQLite underneath | What is pinned does not vary by engine: the retry is driven by the error, and the error is synthesized |

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
