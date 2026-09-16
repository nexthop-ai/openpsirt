# Work queue

Background work held as rows in the application's own database, and the
selection of one replica for work that must happen once.

Satisfies REQ-03, REQ-06, REQ-69.

## Contents

- [Job structure](#job-structure)
- [Exclusive handout](#exclusive-handout)
- [Failure handling](#failure-handling)
- [Claim renewal](#claim-renewal)
- [Passes on a timer](#passes-on-a-timer)
- [Leases](#leases)
- [Backlog refusal](#backlog-refusal)
- [Bounds a deployment sizes](#bounds-a-deployment-sizes)
- [What a failed job records](#what-a-failed-job-records)
- [Transaction boundary](#transaction-boundary)
- [Limits](#limits)

## Job structure

A job is a row. Work survives a restart, and a worker that dies mid-job leaves
the job claimed until the claim goes stale.

| Field | Holds |
|---|---|
| Kind | Which worker may claim it |
| Reference | The thing being worked on |
| State | Queued, claimed, done, or set aside |

A job holds no payload. The reference points at the subject, so the queue stays
small however large that subject is.

Kinds are constants defined with the queue rather than with the worker that runs
them: read a scan, scan for vulnerabilities, sweep the routing rules. A kind is
also stored in the row, so renaming one leaves queued work that nothing claims.

## Exclusive handout

Two workers never receive the same job. The guarantee is a **conditional
update**: the claiming statement repeats the conditions that made the job
claimable, so it succeeds only if the job is still claimable. A second worker's
update matches nothing. This behaves identically on all four engines.

`FOR UPDATE SKIP LOCKED` is a throughput measure and not the guarantee. Without
it every worker selects the oldest job and all but one performs a round trip for
nothing. SQLite uses none: one process, one connection, so the surrounding
transaction already excludes every other claim.

A worker claims only its own kind, as part of the claim rather than as a check
afterwards.

## Failure handling

| Behavior | Reason |
|---|---|
| Retry with a growing delay | A briefly unavailable dependency is not hammered while it recovers |
| A limit on attempts | A job that can never succeed would otherwise retry forever and crowd out work that could |
| Set aside, never deleted | The row is kept with its last error, which is the evidence of why it failed |
| The limit is charged on the reclaim as well as on a reported failure | A worker that is killed reports nothing, so the only record of the attempt is the count the claim itself incremented. Charged only where a worker reports, a job that kills its worker is reclaimed for ever and the set-aside state is never reached |
| A claim that can no longer be reclaimed is set aside by a pass of its own | A job left in the claimed state reads everywhere else as work somebody is doing, and a worker that died is not something any act by a person is the moment to notice. Folded into the claim instead, it is a range update every worker runs on every poll over the rows every other worker is claiming — which on MySQL deadlocks six workers against one another rather than handing out work |
| One replica buries | Every replica running the same range update is the same contention between processes that folding it into the claim caused between workers |
| Work abandoned by its worker records that, in place of the reason nobody reported | Downstream it is the same failure. Somebody reading the row has to be able to tell "this failed" from "nothing was left alive to say" |

### Work that stopped being retried

Set-aside work has an operator surface: a list of what stopped and why, and a
way to put one back.

| Rule | Reason |
|---|---|
| The list is set-aside work alone | Waiting and running work needs no attention, and a list of it invites acting on a state that moves underneath the reader. What is set aside has stopped moving by definition |
| Putting a job back starts its attempts again | Whoever does it has decided the cause is dealt with. A job returned with one attempt left is set aside again by the next transient failure |
| The last error survives being put back | It is the evidence of the previous run, and the decision to try again is not a reason to destroy it |
| Only set-aside work is put back | Returning a running job hands the same work to two workers, which on an ingest looks like real change rather than an error |
| The listing is capped | A read on an interactive route carries a bound, and a deployment whose queue has gone wrong is where the list is longest |

## Claim renewal

The claim timeout bounds how long a worker may go silent, not how long a job may
take. A running worker renews its claim on an interval well inside the timeout,
so several renewals may fail before the claim is at risk.

| Event | Behavior |
|---|---|
| Renewal refused, another worker holds the job | The work is canceled and the worker is told the claim was lost, not that the work failed |
| Renewal fails for any other reason | Reported and retried next interval. The claim is not lost until the timeout passes with nothing landing |
| The job ends | Renewal stops first and the worker waits for it, so nothing else writes to the job while the ending is written |
| Settling a job is one sequence, owned by the queue | Opening a context that outlives a cancellation, recording the ending against it, telling a stale claim apart from a write that failed, and noticing a takeover were written out in each worker down to the comment paragraph, and the copies had begun to disagree. A third worker would have been a third reading of the rule for a job finished by a worker that no longer holds it |
| What a worker does about its own failure is passed in | It is the one respect the workers genuinely differ: the reader records the failure against the scan as well as the job, and must not on a cancellation or where the job went to another worker. Passed as a closure rather than a flag, so the difference is visible where it is made |
| The claim went stale while the work ran | Only the claim holder finishes a job: the finishing statement carries the claim's condition. A refused finish is reported as "no longer held" and logged |
| Shutdown mid-job | The job is handed back as a failed attempt. The writes recording an ending run under their own context, detached from the cancellation and bounded by a few seconds |
| The work never returns | Renewal stops at a ceiling on the whole hold, the work is canceled, and the attempt is recorded as this job's failure |

### The ceiling on one hold

Renewal is bounded in total, not only per renewal.

| Rule | Reason |
|---|---|
| One claim is renewed for at most a fixed span, four claim timeouts by default | Renewal otherwise has two exits — the work finishing and the claim being taken away — so a worker wedged inside its unit of work renews for ever |
| The claim timeout does not cover this | It bounds a worker going silent, and a wedged worker is not silent: it is renewing on time and reporting nothing |
| What the ceiling costs where it is too low | Legitimate work is cut off mid-run, which is the same hazard the claim timeout carries, so the ceiling exceeds the longest single unit of work by a wide margin |
| A ceiling reached is logged at the level an operator sees | A worker that reached it is not coming back, and nothing else here says so |
| It is recorded as this job's failed attempt, not as a handover | Nobody else holds the job. Counting the attempt is what eventually sets the job aside rather than handing it to a succession of workers that each wedge in turn |
| A subprocess is given a delay to release the pipes once it is killed | Killing a process does not close a pipe a helper it spawned still holds, and waiting on the copy blocks past the deadline that killed it — which is how a worker wedges in the first place |

Zero is no ceiling, for work whose caller states that it has no upper bound.
That is asked for rather than arrived at by omission.

## Passes on a timer

One shape, in one place: a first tick at once, then the interval; a
non-positive interval takes the pass's own default; the context ends the loop.

| Rule | Reason |
|---|---|
| The first tick is immediate | A process that has just started is the moment a sweep is most worth running, because whatever accumulated while it was down is waiting |
| Reporting stays with each pass | They log different things — what was collected, what was sent and what failed, a line per unit of work. A helper that owned the logging would be the call site written out again with a worse vocabulary |
| A failed pass is logged and the loop goes on | A pass that cannot run is not a reason to stop serving, and what it failed to do is still there next time |

It was written out once per pass, and some of those copies had already diverged
over whether the log line carries the trace context. Anything about how passes
are scheduled — spreading goroutines that would otherwise wake together on a
cold start, a measurement per pass, a first-run delay — was an edit per copy,
and a missed one would have diverged in silence because nothing tested any of
them.

## Leases

A pass that runs on a timer runs on every replica, because no replica is a
leader. Discrete work is settled by claiming its row; a recurring pass has no
row, so it takes a **lease** on the name of the work under the same conditional
update.

| Property | Behavior |
|---|---|
| Expiry | A lease lapses rather than only being handed back |
| Retention | The holder keeps it by asking for it again each cycle |
| Release | Handed back on a clean shutdown |
| Duration | Outlasts a cycle of the work. Not renewed mid-pass |

| Work shape | On losing the race | Passes |
|---|---|---|
| May be skipped | Does nothing this cycle, asks again next | Asking public indexes what upstream released; deciding which builds are due a scan; setting aside work whose worker never came back |
| Must happen | Waits for its turn, then applies | Rewriting deadlines after a policy change |

Work that waits reads what it decides from **after** its turn comes. Anything
the work decides from is fetched inside the thing that serializes it.

## Backlog refusal

New work is refused once the queue for its kind is deeper than a limit an
administrator sets. The caller is told to retry.

| Rule | Reason |
|---|---|
| Counted per kind | The cap exists so a runaway producer cannot push everyone else's work behind its own. Counted across every kind it does the opposite: the producer that filled the queue keeps its place while every other producer is refused, so a bulk change to the routing rules refuses every scan upload in the deployment |
| The depth counts work held by a worker that has stopped reporting | Counting only what is waiting reads a queue in the middle of a reclaim cycle as empty: every row sits in the claimed state, held by workers that died, and the one number an operator has says there is nothing to do |
| A setting rather than a number in the binary | The producer a refusal lands on is a build server. An estate that pushes work in faster than the workers drain it has no remedy for a compiled-in number short of a new binary, and waiting is not one when the thing waiting is a build |
| Read as the work is queued | A number an administrator changes takes effect on the next upload rather than on the next restart |

## Bounds a deployment sizes

Five bounds are read from the environment as the process starts. How deep the
queue may get is the sixth and is a stored setting.

| Bound | What it decides |
|---|---|
| Attempts | How many times a job is tried before it is set aside |
| Claim timeout | How long a claim is honored with nothing heard from the worker holding it |
| Heartbeat | How often a running job renews its claim |
| The ceiling on one hold | How long one claim may be renewed for altogether |
| Backoff | How long a failed job waits, multiplied by the attempt |

| Rule | Reason |
|---|---|
| The environment, not a stored setting | The settings store reads the database, so the database and the queue cannot read a setting without inverting that import. What it costs is that changing one needs a restart, which is said here rather than discovered |
| How deep the queue may get is the exception | That refusal lands on a build server, and the operator meeting it needs a remedy that is not a restart |
| Zero or negative is refused rather than taken | The rule every setting is held to. So "no ceiling on one hold" cannot be asked for from the environment: it is what a caller whose work has no upper bound of its own states where the queue is built |
| Two pairs are compared as the process starts | A heartbeat no shorter than the claim timeout hands running work to a second worker; a hold ceiling no larger than the claim timeout cancels work that is running normally. Both read as a fault in the work rather than in the configuration, so the process refuses to start and names the pair |
| The defaults live where the queue is built | Every reader takes them from there rather than carrying its own, so two spellings cannot disagree. The configuration reference prints them in its Default column as it does for every other setting, which is the one restatement and the one an operator reads; the chart carries none, and a deployment that wants one sets the environment variable |

## What a failed job records

A job that failed keeps the reason, bounded.

| Rule | Reason |
|---|---|
| The reason is capped | It comes from whatever failed — a parser, a scanner's output, a driver — and is handed back to whoever asks about their upload. Unbounded, one job writes as much as its cause felt like saying into a column every reader of that job carries |
| The cap cuts on a character boundary | A cut at a byte offset splits a multi-byte character and leaves a tail three of the four engines refuse to store, so the bound meant to keep a write small is what makes it fail |
| The cap is generous and the cut is marked | The first lines of a parser's complaint are what make it actionable. The worker's own log line carries the whole of it either way |

## Transaction boundary

The caller states whether a job commits with the rows it is about.

| Mode | Used for | Failure mode it prevents |
|---|---|---|
| Commit with the rows | Work describing something the same transaction wrote, such as an upload | A job committed alone can be claimed before its rows exist; rows committed without their job are work nobody picks up |
| Queue afterwards | Work that merely follows a write, such as sweeping routing rules after a rule is recorded | None. A failure to queue is logged rather than returned, because the rule is recorded either way and an error would invite a retry that records it twice |

Every write the queue makes of its own — queueing, claiming, renewing,
finishing, failing, setting aside, putting back, and taking or handing back a
lease — goes through the retry helper rather than running as a statement on its
own.

| Rule | Reason |
|---|---|
| A cluster refuses at commit, not at the statement | See `DESIGN-database.md` § Retryable transactions. A write outside a transaction cannot be retried at all: the failure arrives where there is nothing left to go again |
| Finishing is the write where it costs most | Reported up rather than retried, a job that finished is recorded by its caller as failed and handed out again. The work runs twice, which on an ingest looks like real change |
| A finish whose commit was refused asks the row rather than assuming | A second attempt covers both "somebody else holds it now" and "the commit succeeded and the answer never arrived". Work that is finished is finished, and reporting a lost claim for it would record a failure against a job that succeeded |
| A lease take that is refused would read as losing a race | A replica told it lost a race it never ran stops sweeping, with nothing logged, on every replica at once |

## Limits

- **Two workers can run one job.** The conditional update cannot prevent it:
  from the database's point of view the second claim is legitimate, because the
  row says the holder has not been heard from. The renewal interval bounds the
  window.
- **The claim timeout is not shortened to match the renewal interval.** On
  SQLite the pool is one connection, so a renewal waits behind the job's own
  statement and a long transaction can hold it for minutes. **On that engine
  a renewal cannot succeed at all while the work holds the connection**, so
  the claim timeout is not a safety margin there — it is the bound, and it has
  to exceed the longest single unit of work a deployment runs. Past it the
  claim goes stale, and once the work's own transaction commits a second
  worker's claim succeeds and the job runs twice, which on an ingest looks
  like real change. The renewal is kept because it is the whole of the
  protection on the other three engines.
- **No queue library is used.** The mature Go queues either tie to one database
  engine or require a separate service — one would cut engine support from four
  to one, the other adds a component to every deployment.
- **Row locking is verified as non-load-bearing.** The exclusivity test runs
  twice on every engine, once with the locking clause and once without it, and
  the second arm is the one that fails when the conditional update stops
  repeating the state it expects: with locking in place the same defect passes,
  because locking hides it. The switch is reachable only from the package's
  test surface, never from an option a deployment can set.
