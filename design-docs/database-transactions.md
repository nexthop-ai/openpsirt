# Database transactions

How replicas coordinate through the database, how every transaction survives a
cluster refusing it at commit, how a write guards what it read, and how a read
tells absence from failure.

Satisfies REQ-03, REQ-06, REQ-71.

## Contents

- [Replica coordination](#replica-coordination)
- [Retryable transactions](#retryable-transactions)
- [Reads a write depends on](#reads-a-write-depends-on)
- [Absence and failure](#absence-and-failure)
- [Limits](#limits)

## Replica coordination

Replicas are identical and there is no leader (REQ-03). Every replica serves
requests, reads scans and runs vulnerability scans. Nothing held in a process
decides anything: sessions are rows, settings and roles are read per request,
and the one in-memory lock stops a process migrating twice.

| Coordination | Mechanism |
|---|---|
| Two workers taking one job | A conditional update; row locking beside it is for throughput (`design-docs/queue.md` § Exclusive handout) |
| Two replicas migrating at start | A database-level lock (`design-docs/database-migrations.md` § Migration locks) |
| Two scans of one build | The apply takes the build's row first, so the second waits rather than interleaving, and a scan applies whole (REQ-06) |
| Two uploads checking the room left | The upload's transaction writes a fresh value into one fixed lock row before summing what is held, so the second waits and a cluster conflicts the two at certification. A write of the value already held is not written on MySQL and MariaDB, so never certified |
| An administrator changing a setting | Read per request, so it applies on every replica at once |

## Retryable transactions

A cluster certifies a write at `COMMIT`: two nodes touching the same rows both
run every statement successfully, and one is then told the transaction rolled
back.

| Rule | Reason |
|---|---|
| Every transaction runs through one helper that retries it whole on a lost race: deadlock, lock-wait timeout, serialization failure | |
| Any other failure is reported, never retried | A constraint violation retried hammers the database and hangs |
| Nothing a transaction depends on is read outside it | A retry re-runs the closure against a moved database |
| A read made before the transaction as an early refusal is repeated inside it, and the inside one decides | |
| A statement whose refusal is an ordinary answer stands on its own savepoint, rolled back on refusal | PostgreSQL aborts the whole transaction after a failed statement, such as an insert a primary key refuses. The other three carry on, so SQLite never shows it |
| An act is one transaction, and an act is what a person asked for | Recording a person with their roles, a team with its members, a tag's parent with when it went out, a graph with what the build argued about its patches. Split, a refusal partway leaves half a write, and the resent request lands it twice |
| The record of an administrative act is inside it | A failure to record fails the act |
| Giving up does not back off first | Nothing follows the last attempt |

| Read inside the write | What it decides |
|---|---|
| The limits on an act answering many issues | Whether the act is refused. A limit a caller left unset is the deployment's setting |
| How many findings one decision may write | Whether a decision across many occurrences, or an extension of an agreed one, is refused |
| The longest a personal token may last | The new token's ceiling |
| Whether the writer may write a note about an issue | Whether the note is written |
| Where each added build holds a recorded flaw's component | Which rows the flaw opens. A build that stopped shipping it is refused |
| What each part of a build is called, on recording that its VEX document went out | Whether the document names the build as now called; a rename in between is refused and asked again |
| The VEX document recorded as gone out | Generated inside the recording transaction on every attempt |
| The product a supplier, an uploaded VEX document or an uploaded advisory names | Which product they are recorded against |
| The claims a document makes, folded and paired | Which standing claims it repeats and which it sets aside. Copied from the caller's on every attempt |
| The moment a write is dated | When the act happened. Read from the clock on every attempt, so a retried attempt is not dated before the write it lost to |

| Inside the act | Reason |
|---|---|
| A job queued for what was written | Queued after, a failure reports a landed write as failed, or leaves rows nothing picks up |
| Work handed back when somebody stops reading it | Done after, a failure leaves work with somebody who cannot open it. Bounded by what they held (`design-docs/access-assignment.md` § Lost reading) |

| Job | A full queue |
|---|---|
| Parsing an upload | Refuses the upload with 503, storing nothing |
| Applying a saved assignment rule to what is open | Refuses the rule with 503, recording nothing. Work arriving in the product also sweeps |
| Placing work a scan, an analyzer run or a recorded flaw opened | Not the arrival's failure. The next arrival or rule in the product sweeps (`design-docs/access-assignment.md` § The sweep) |
| Scanning an inventory a read stored | Not the read's failure. The periodic pass asks again once the queue drains |

| Outside the act | Reason |
|---|---|
| The deadline rewrite a policy change forces | Bounded by what is open: nineteen seconds against 441,108 findings, longer than a request |
| A read naming things in the answer | `design-docs/api-refusals.md` § Refusal shape holds the rule |

A store method handed a transaction takes one of three spellings.

| Spelling | Correct where |
|---|---|
| Refuse | The method owns the retry boundary and decides what a retry re-reads |
| Join | The requirement is "both statements or neither", which the caller's transaction meets |
| Join, and hand the race back | The method resolves a lost race by going again, which it cannot do inside a caller's transaction. It returns a named error the retry helper recognizes beside the engine codes, and the caller's helper takes the whole act again |

| Rule | Reason |
|---|---|
| A handler answers a handed-back race as a fault carrying it | The helper reads the cause and goes again. Where nothing does, the caller is told 500 in the handler's own words |
| Joining is a named helper, never an `if` on the handle's type | By hand it reads as a fallback to writing outside a transaction |
| The helper names every handle it accepts and refuses the rest as a fault | A handle embedding a transaction fails a type test, and falling back to autocommit is no transaction and no retry, silently |

## Reads a write depends on

A transaction is not a lock. At the isolation every engine opens with, a plain
read answers from a snapshot and a write lands on whatever the row holds.

| Two writers, one row | What happens |
|---|---|
| Both read | Neither waits; a plain select locks nothing on the three servers |
| Both write | The second waits for the first to commit, then writes over what it never saw |
| Both report what they replaced | Both name the value they read; only one replaced it |

| Rule | Reason |
|---|---|
| A write carries what its read answered: it matches the key and the value read, and a match of none takes the attempt again in a new transaction | Otherwise the trail says a writer replaced a value nothing held |
| A new transaction, never a second read in the failed one | MySQL and MariaDB fix the snapshot at the opening select |
| A locking read is not used for this | `SELECT ... FOR UPDATE` is spelled per engine; the condition works on all four |
| Retries are bounded | Two writers resolve in one more attempt, three in two; unresolved contention is reported |

| Write | What it matches on beside the key |
|---|---|
| Agreeing to or withdrawing a rating | The state the claim was read in |
| Holding occurrences of a decision back, and setting them aside | Still waiting, and still the decision they were read from |
| Filling in what a tag was cut from | An empty parent; a lost race reads back the winner and refuses a different branch |
| Changing a setting | The value read |
| Bringing a retired product, release or variant back | Still retired. A match of none records no return to use |
| Collecting an upload nothing refers to | Still unattached, and not redacted since the page was read |
| Moving a code finding recorded as a flaw, taking it back out, or disclosing its flaw | The visibility read, the flaw undisclosed, and the last analysis run describing the code finding, which a run writes before anything else about it |
| Recording a code finding as a flaw; revising, withdrawing, approving, setting aside, sending back or undoing the approval of a decision | The decision's stamp as read, set to a new value |

| Decision stamp rule | Reason |
|---|---|
| The stamp is a row of its own beside the decision | InnoDB locks the parent of every child row it checks, so a stamp on the decision row would wait on any transaction inserting a row naming the decision |
| A decision with no stamp row holds zero; its first stamp inserts the row, and a duplicate key there is a lost race | |
| The stamp is read before the flaw record is asked about, and a flaw record reads the stamp of the decision standing at the code finding before asking whether it confirms it | A flaw record and a withdrawal of its confirmation each read the other's absence, and only one matches |
| A decision writer sets the stamp last in its transaction | The row is locked least, and two writers lock stamps in one order |
| Reaffirming writes no stamp | It acts on a lapsed decision, and a decision confirming a code finding does not lapse |

| Rule | Reason |
|---|---|
| An insert that can lose a race on a unique key hands the race back | Recording a person, authorizing a sign-in name, numbering an advisory or its edition, numbering a revision of a report or its note. Taken again whole, it finds the other writer's row or numbers after it |
| A revision's number is read before the row whose text it keeps | An edit committing between them takes the number, and the attempt goes again |
| A bound counted before an insert takes turns on a row of the owner's first, an ordinary update writing a new value every time | Otherwise two transactions each count one under a person's saved-filter limit and both add. A new value, because MySQL and MariaDB skip an unchanged row and a cluster certifies only written rows |
| That row is one per person in the lease table, made before the transaction opens, and nothing takes it as a lease | |

## Absence and failure

A row that is not there and a read that could not be made are different
answers.

| Rule | Reason |
|---|---|
| A reader says which it hit | The caller chooses a status from it |
| Absence is a sentinel each package words for itself, matched through wrapping | Matching on a message is reading an engine's error text |
| A failed read names the act, and the act reaches the log | The driver's words are not published |
| One helper makes the distinction | |
| A handler's error arm asks which error it holds before answering 404 | Otherwise an outage is "that does not exist" and the retry helper loses the cause. A gate reports an arm answering 404 for any error |
| A read filling part of an answer fails the answer | Left out, a field reads as absence: a limit as none, a narrowed token as reaching everything, a release note as leaving nothing out |
| A credential that cannot be looked up is a fault, answered 503 with a time to ask again and logged | Answered as unauthorized, an outage sends every caller to sign in again |

## Limits

| Limit | Detail |
|---|---|
| SQLite takes no part in coordination | A scaled deployment runs on a server engine (`design-docs/database.md` § Supported engines) |
