# Work queue

Background work held as rows in the application's own database, and the
leases that pick one replica for work that must happen once.

Satisfies REQ-03, REQ-06, REQ-69.

## Contents

- [Job structure](#job-structure)
- [Exclusive handout](#exclusive-handout)
- [Failure handling](#failure-handling)
- [Claim renewal](#claim-renewal)
- [Passes on a timer](#passes-on-a-timer)
- [Leases](#leases)
- [Backlog refusal](#backlog-refusal)
- [Configurable bounds](#configurable-bounds)
- [Failure records](#failure-records)
- [Transaction boundary](#transaction-boundary)
- [Limits](#limits)

## Job structure

A job is a row, so work survives a restart and an upload is answered before it
is parsed (REQ-06). A worker that dies mid-job leaves the job claimed until the
claim goes stale.

| Field | Holds |
|---|---|
| Kind | Which worker may claim it |
| Reference | The thing worked on |
| State | Queued, claimed, done, or failed |

| Rule | Reason |
|---|---|
| A job holds no payload | The queue stays small however large its subject |
| Kinds are defined with the queue: read a scan, scan for vulnerabilities, sweep the assignment rules, apply an analyzer's run to its build | |
| A kind is stored in the row | Renaming one leaves queued work nothing claims |

## Exclusive handout

Two workers never receive the same job, on any engine and any number of
replicas (REQ-03).

| Rule | Reason |
|---|---|
| The claim is a conditional update repeating the conditions that made the job claimable | A second worker's update matches nothing, identically on all four engines |
| `FOR UPDATE SKIP LOCKED` sits beside it on the servers | Throughput only: without it every worker selects the oldest job and all but one make a wasted round trip |
| SQLite uses no locking clause | Every transaction takes the file's write lock as it begins, which already excludes every other claim |
| A worker claims only its own kind, inside the claim | |

## Failure handling

| Behavior | Reason |
|---|---|
| Retry with a growing delay | A briefly unavailable dependency is not hammered |
| A limit on attempts | A job that can never succeed would crowd out work that could |
| A failed job is kept with its last error, never deleted | The row is the evidence of why it failed |
| The limit is charged on the reclaim as well as on a reported failure | A killed worker reports nothing, so the count its claim incremented is the only record. Otherwise a job that kills its worker is reclaimed for ever |
| A claim that can no longer be reclaimed is failed by a pass of its own, on one replica | Left claimed, it reads as work in progress. Folded into the claim, it is a range update every worker runs on every poll, which on MySQL deadlocks six workers; on every replica it is the same contention between processes |
| Work abandoned by its worker records that in place of a reason | A reader tells "this failed" from "nothing was left alive to say" |
| Work that cannot start yet is put back untried, with a delay and the reason | Something it needs has not arrived. The attempt is given back, so waiting never fails a job, and the reason sits where a failure's would |

### Failed jobs

Failed jobs have an operator surface: a list of what stopped and why, and a way
to put one back.

| Rule | Reason |
|---|---|
| Failed jobs are listed; waiting work is counted | Waiting work moves under a reader, and a count says whether the queue is filling |
| Waiting work is counted per kind, against the bound | The bound is per kind, so a total hides one producer's backlog |
| Work held by a worker that stopped reporting counts as waiting | Counted as running, a queue mid-reclaim reads as empty |
| Reading any of it is administration | A failed parse quotes its cause, which can carry a component name or package address the reader holds nothing on |
| Putting a job back starts its attempts again | Whoever does it decided the cause is dealt with |
| The last error survives being put back | It is the previous run's evidence |
| Only a failed job is put back | Returning a running job hands the work to two workers, which on an ingest looks like real change |
| The listing is capped | A deployment whose queue has gone wrong has the longest list |

## Claim renewal

The claim timeout bounds how long a worker may go silent, not how long a job
may take. A running worker renews its claim on an interval well inside the
timeout, so several renewals may fail before the claim is at risk.

| Event | Behavior |
|---|---|
| Renewal refused because another worker holds the job | The work is canceled and the worker told the claim was lost, not that the work failed |
| Renewal fails for any other reason | Reported and retried next interval. The claim is lost only when the timeout passes with nothing landing |
| The job ends | Renewal stops first and the worker waits for it, so nothing else writes the job while the ending is written |
| The claim went stale while the work ran | The finishing statement carries the claim's condition, so only the holder finishes. A refused finish is reported as "no longer held" and logged |
| Shutdown mid-job | The job is handed back as a failed attempt. The ending writes run on their own context, detached from the cancellation and bounded by a few seconds |
| The work never returns | Renewal stops at the ceiling on one hold, the work is canceled, and the attempt is this job's failure |

| Rule | Reason |
|---|---|
| Settling a job is one sequence owned by the queue | A context outliving the cancellation, the ending recorded on it, a stale claim told from a failed write, a takeover noticed. Per-worker copies disagree |
| What a worker does about its own failure is passed in as a closure | The workers differ there alone: the reader records a failure against the scan as well, except on a cancellation or a takeover |

### The ceiling on one hold

| Rule | Reason |
|---|---|
| One claim is renewed for at most a fixed span, four claim timeouts by default | A worker wedged inside its work otherwise renews for ever, since renewal ends only on finishing or losing the claim |
| The claim timeout does not cover this | A wedged worker renews on time |
| The ceiling far exceeds the longest single unit of work | Too low, it cuts legitimate work off mid-run |
| A ceiling reached is logged at the level an operator sees | The worker is not coming back, and nothing else says so |
| It is recorded as this job's failed attempt, never a handover | Nobody else holds the job, and counting it eventually fails a job that wedges every worker |
| A killed subprocess is given a delay to release its pipes | A helper it spawned can hold a pipe open, and waiting on the copy blocks past the deadline, which is how a worker wedges |
| Zero is no ceiling, for a caller whose work has no upper bound | No caller here builds a queue that way: every bound comes from a setting, which refuses zero |

## Passes on a timer

One implementation runs every periodic pass: a first tick at once, then the
interval; a non-positive interval takes the pass's default; the context ends
the loop.

| Rule | Reason |
|---|---|
| The first tick is immediate | Whatever accumulated while the process was down is waiting |
| Reporting stays with each pass | Each logs different things |
| A failed pass is logged and the loop goes on | What it failed to do is still there next time |
| One implementation | Copies diverge over what nothing tests: trace context, cold-start spreading, first-run delay |

## Leases

A pass on a timer runs on every replica, since none is a leader (REQ-03).
Discrete work is settled by claiming its row; a recurring pass has no row, so
it takes a **lease** on the work's name under the same conditional update.

| Property | Behavior |
|---|---|
| Expiry | A lease lapses rather than only being handed back |
| Retention | The holder asks for it again each cycle |
| Release | Handed back on a clean shutdown by every pass that takes one, once its last cycle has ended, whether the stop came during a cycle or between two, on a bounded context of its own. A deadline rewrite a request started is ended once the server stops taking requests, and the shutdown waits for its release within the same grace |
| Holder | The host and process an operator reads, plus random characters, since replicas on the host network share a name and every container process is the first |
| First use | The row is made inside the taking transaction, leaving a row another replica made alone. A cluster refusing that at commit makes the take go again |
| Duration | Outlasts a cycle, sized from how often the pass runs, so a replica stopping without release holds the work a few passes. Not renewed mid-pass. A process restarted in place after a crash is a new holder and waits out every lease the old one held, up to the mail and webhook leases' full length |

| Work shape | On losing the race | Passes |
|---|---|---|
| May be skipped | Does nothing this cycle and asks again next | Asking public indexes what upstream released; deciding which builds are due a scan; failing work whose worker never came back |
| Must happen | Waits for its turn, then applies. A failed take is a missed turn, asked again at the next poll; the wait ends only with its context | Rewriting deadlines after a policy change. One process runs one rewrite at a time per database, and changes arriving meanwhile are one more run reading the newest policy |

Work that waits reads what it decides from after its turn comes, inside what
serializes it.

One row of the lease table is a lock that nothing takes as a lease: an upload
writes a fresh value into it to serialize the check of room left
(`design-docs/attachments.md` § Quota and removal).

## Backlog refusal

New work is refused once its kind's queue is deeper than a limit an
administrator sets, and the caller is told to retry.

| Rule | Reason |
|---|---|
| Counted per kind | The cap keeps a runaway producer from pushing everyone behind it. Counted across kinds, a bulk change to the assignment rules would refuse every scan upload |
| The depth counts work held by a worker that stopped reporting | Mid-reclaim every row is claimed by dead workers, and a waiting count reads empty |
| A stored setting, read as work is queued | The refusal lands on a build server, and its remedy cannot be a new binary or a restart |
| Back-pressure, not an exact bound | Producers adding at once each count what committed, so the backlog can pass the limit by as many as are adding. An exact bound takes a lock per kind, spelled per engine |
| An upload refused for a full queue raises an alert naming the build, the limit, and how to raise it | The producer may not retry. A deep queue still taking work alerts nobody. Not built: the refusal is answered 503, neither logged nor recorded as a refused upload, and the System screen marks the kind at its limit |

## Configurable bounds

| Bound | Decides |
|---|---|
| Attempts | How many times a job is tried before it fails |
| Claim timeout | How long a claim is honored with nothing heard from its holder |
| Heartbeat | How often a running job renews its claim |
| The ceiling on one hold | How long one claim may be renewed altogether |
| Backoff | How long a failed job waits, multiplied by the attempt |
| Queue depth | When new work of a kind is refused (§ Backlog refusal) |

| Rule | Reason |
|---|---|
| The first five are read from the environment at start | The settings store reads the database, so the queue reading it inverts that import. A change needs a restart |
| Queue depth is a stored setting | Its refusal lands on a build server |
| Zero or negative is refused | The rule every setting is held to, so "no ceiling" cannot be asked for from the environment |
| The process refuses to start when the heartbeat is not shorter than the claim timeout, or the hold ceiling not larger, naming the pair | The first hands running work to a second worker; the second cancels normal work. Both would read as a fault in the work |
| The defaults live where the queue is built, and the configuration reference prints them | One spelling. The chart carries none; a deployment wanting one sets the environment variable |

## Failure records

| Rule | Reason |
|---|---|
| A failed job's reason is capped (REQ-69) | It comes from a parser, a scanner's output or a driver, and is handed to whoever asks about their upload |
| The cap cuts on a character boundary | A cut inside a multi-byte character leaves a tail three engines refuse, failing the write the cap protects |
| The cap is generous and the cut is marked | The first lines make a complaint actionable. The worker's log line carries the whole |

## Transaction boundary

The caller states whether a job commits with the rows it is about.

| Mode | Used for | Failure it prevents |
|---|---|---|
| Commit with the rows | Work describing what the same transaction wrote, such as an upload | A job committed alone can be claimed before its rows exist; rows committed alone wait on nothing |
| Queue on its own | Work no write of the act describes: a build the periodic pass finds due, the next batch of an assignment sweep, an overtaken scan read again | None: a failure to queue returns to the asker and leaves no rows waiting |

Every write the queue makes, queueing, claiming, renewing, finishing, failing,
putting back, and taking or releasing a lease, runs through the retry helper
(`design-docs/database-transactions.md` § Retryable transactions).

| Rule | Reason |
|---|---|
| No queue write runs as a bare statement | A cluster refuses at commit, and a write outside a transaction cannot be retried |
| Finishing is retried, never reported up | Reported up, a finished job is recorded failed and handed out again, and the work runs twice |
| An ending whose commit was refused asks the row | It covers a takeover and a commit whose answer was lost. A finish reads as done; a failure and a postponement as unclaimed with their reason; a put-back as no longer failed |
| A refused lease take is retried, never read as a lost race | A replica told it lost a race stops sweeping, silently, on every replica at once |
| The moment a write compares against is read inside each attempt | A retry runs after a pause. A stale moment misses a job that went stale meanwhile, and shortens a retaken lease by the pause |

## Limits

| Limit | Detail |
|---|---|
| Two workers can run one job | The second claim is legitimate to the database when the holder has not been heard from. The renewal interval bounds the window |
| On SQLite the claim timeout is the bound on one unit of work | A renewal is a write and cannot land while the job's own transaction holds the file's write lock. The timeout must exceed the longest unit of work, or a second worker claims once the transaction commits and the job runs twice; so it is not shortened to the renewal interval. Renewal protects the other three engines |
| No queue library is used | The mature Go queues tie to one engine or need a separate service |
| Row locking is verified as not load-bearing | The exclusivity test runs on every engine with the locking clause and without it, and the arm without it fails when the conditional update stops repeating its state; locking hides that defect. The switch is reachable only from the package's tests |
