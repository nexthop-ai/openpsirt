# Work queue

Background work held as rows in the application's own database, and the
selection of one replica for work that must happen once.

Satisfies REQ-03, REQ-06, REQ-69.

## Contents

- [Job structure](#job-structure)
- [Exclusive handout](#exclusive-handout)
- [Failure handling](#failure-handling)
- [Claim renewal](#claim-renewal)
- [Leases](#leases)
- [Backlog refusal](#backlog-refusal)
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

## Claim renewal

The claim timeout bounds how long a worker may go silent, not how long a job may
take. A running worker renews its claim on an interval well inside the timeout,
so several renewals may fail before the claim is at risk.

| Event | Behavior |
|---|---|
| Renewal refused, another worker holds the job | The work is canceled and the worker is told the claim was lost, not that the work failed |
| Renewal fails for any other reason | Reported and retried next interval. The claim is not lost until the timeout passes with nothing landing |
| The job ends | Renewal stops first and the worker waits for it, so nothing else writes to the job while the ending is written |
| The claim went stale while the work ran | Only the claim holder finishes a job: the finishing statement carries the claim's condition. A refused finish is reported as "no longer held" and logged |
| Shutdown mid-job | The job is handed back as a failed attempt. The writes recording an ending run under their own context, detached from the cancellation and bounded by a few seconds |

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
| May be skipped | Does nothing this cycle, asks again next | Asking public indexes what upstream released; deciding which builds are due a scan |
| Must happen | Waits for its turn, then applies | Rewriting deadlines after a policy change |

Work that waits reads what it decides from **after** its turn comes. Anything
the work decides from is fetched inside the thing that serializes it.

## Backlog refusal

New work is refused once the pending queue is deeper than a configured limit.
The caller is told to retry.

## Transaction boundary

The caller states whether a job commits with the rows it is about.

| Mode | Used for | Failure mode it prevents |
|---|---|---|
| Commit with the rows | Work describing something the same transaction wrote, such as an upload | A job committed alone can be claimed before its rows exist; rows committed without their job are work nobody picks up |
| Queue afterwards | Work that merely follows a write, such as sweeping routing rules after a rule is recorded | None. A failure to queue is logged rather than returned, because the rule is recorded either way and an error would invite a retry that records it twice |

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
- **Row locking is verified as non-load-bearing** by removing it entirely and
  observing that the exclusivity test still passes.
