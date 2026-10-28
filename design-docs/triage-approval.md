# Approval

The second person: who may argue, agree and read, how an agreement is given and
taken back, which decisions need one, and the queue where they wait.

Satisfies REQ-24, REQ-28, REQ-40, REQ-42, REQ-43.

## Contents

- [Approval](#approval)
- [Rights](#rights)
- [Set-aside rows](#set-aside-rows)
- [Partial approval](#partial-approval)
- [Sending back](#sending-back)
- [The deferral threshold](#the-deferral-threshold)
- [The review queue](#the-review-queue)
- [Limits](#limits)

## Approval

The proposer and the approver are always different people, with no override, so
a deployment with one person approves nothing.

| Rule | Reason |
|---|---|
| An approval names one revision of the reasoning (REQ-28) | Another pair of eyes read those words |
| Nobody who proposed a row or wrote any reasoning of a decision agrees to it, asked both when an agreement is given and when a re-affirmation carries one (REQ-24) | |
| The moved-row count is the control, so an engine that cannot report it refuses | Rows move only while the approved revision stands |
| Reasoning is revised, never overwritten, every revision readable | |
| Editing the reasoning takes back the approval; the decision returns marked previously approved | |
| Revising an ended decision brings it back, refused where another decision now stands at an occurrence, naming it | Its rows retake their occurrences |
| Withdrawing, revising and sending back need no approval | Only hiding risk needs a second person |
| Undoing a bulk approval returns its whole recorded batch to proposed | The decisions stand; the agreement goes |
| Undoing returns only approved rows to proposed, and withdrawing changes only proposed or approved rows | A lapsed row returned to waiting is unique to nothing, and rewritten loses when it stopped |
| A withdrawn approval stays on the record | |
| A withdrawal records who made it, apart from who agreed | A proposer revising their words must not read as the approver undoing |
| A carried agreement is marked carried wherever the approver's name appears (`design-docs/triage-lapse.md` § Re-affirmation) | The approver never read the re-affirmer's reasoning |
| Whether a decision waits is answered when it is made, and every read says so (REQ-24) | A short deferral takes effect at once, and a proposal silent about waiting reads as in force |

### Approval as a set

Approving approves every waiting row of a decision in one transaction; rows
approved, withdrawn, lapsed or sent back stay.

1. The author of the current reasoning, read once.
2. One approval row naming the revision, with what it covered counted in one
   statement, narrowed to what the approver may read.
3. One update moving the rows, conditioned on that revision still standing.
4. The matched count checked, refusing the whole decision if short.

A test pins the statement count: 500 rows with two set aside take 15 statements
on SQLite, against 1,760 rows taking 15.6 s one at a time on the demo, where 500 rows were 2,500 statements.

## Rights

| Act | Needs |
|---|---|
| Propose, revise, withdraw | Triage on the product, at the finding's visibility |
| Approve, undo an approval | The approver capability or triage, and reading the finding |
| Comment, or edit your own | Either of the above |
| Read what was decided | Reading the finding |

| Rule | Reason |
|---|---|
| A triager may approve another's decision about disclosed or undisclosed work; a code finding's decision takes the approver capability (`design-docs/analysis-triage.md` § Code finding triage) | The control is two different people |
| Reading is the finding's visibility alone (REQ-43) | Narrower, one reader holding private reading was told none of a finding's 91 decision rows existed |
| Writing is a rule apart from reading | |
| Every check reads product and visibility from the row | |
| An occurrence stating no visibility is undisclosed, normalized before the check | |
| Unreachable and non-existent answer the same (REQ-42) | |

Nothing under a finding carries a visibility of its own (REQ-40): the decision,
its revisions, approvals, comments and every person named are read at the
finding's, so disclosing a finding discloses the whole record. A visibility
column on any of them would read as a tightening and silently defeat this.

| Rule | Reason |
|---|---|
| A decision occurrence copies its finding's visibility, which issue disclosure rewrites in the act that discloses (`design-docs/access-disclosure.md` § Issue disclosure) | Reports and exports answer reach from the row |
| An occurrence is written public where its issue has no undisclosed finding left in the product when the row is written | A disclosure may land between reading and writing |

## Set-aside rows

The queue entry carries its **outliers**. An approver may set some aside: the
rest is approved, and those become a returned decision, the proposer's, sent
back, with the reason as a comment on each.

| Rule | Reason |
|---|---|
| A reason is required | |
| A row outside the decision refuses the act | A stray identifier is likelier a mistake |
| The proposer may not set aside their own rows | It approves the rest |

The outliers are five stored signals, over the decision's distinct issues:

1. This product recorded as attacked through it.
2. Known exploited.
3. Rated critical or high, by our assessment where one stands.
4. A fix available, from the open findings its rows match that the reader may
   see.
5. Where the narrowing record names a term, a description lacking it.

Ordered in that order then by name, capped at twenty, with counts behind the cap.

| Rule | Reason |
|---|---|
| An attacked issue is never behind the cap | Agreeing is refused while one is in the decision (`design-docs/incidents.md` § Decisions against an incident) |
| A row names every occurrence of its issue, and setting it aside sets all aside | |
| Every act over many issues carries the table | Set-aside rows and re-made decisions are refused over an attacked issue too |
| Signals are read with one identifier per issue and product | One kernel issue holds 133,549 rows in one estate, past a statement size an engine accepts |

## Partial approval

The author's side of the same mechanism: the rows named become a decision of
their own carrying its argument, with the reason as a comment, waiting for the
author to revise it. The outliers are shown to the author too.

| Rule | Reason |
|---|---|
| A reason is required | |
| A row outside the decision refuses the act | |
| Naming all of what is still argued is refused | That is a revision or a withdrawal |
| A row agreed, withdrawn or lapsed cannot be held back | |
| Splitting is the author's act and setting aside the approver's, each refused to the other | An author holding rows back while agreeing to the rest approves their own decision |

## Sending back

Sending back takes a decision out of the approval list until its author
revises. A reason is required and travels as a comment.

| Rule | Reason |
|---|---|
| Not a state: the decision is still proposed | A fifth state for whose turn it is would be reasoned about everywhere |
| It suppresses nothing while back | A short deferral would otherwise hide the finding while its author is told it applies to nothing |
| It needs no approval | |
| Nobody sends back a decision whose current words are their own | |
| Everybody whose words went back is told, linked to the finding at the version, or to the decision where no readable open finding describes it | The finding is where words are revised |

## The deferral threshold

A deferral shorter than a configured threshold stands without a second person.
Short is measured against the total the finding has been put off for, each
deferral counting what it asked for while it held, from the request to its
return date, cut short where taken back or lapsed.

| Rule | Reason |
|---|---|
| A deferral taken back or lapsed counts for the part that ran | Erased, withdrawing and deferring again hides an occurrence forever under the line |
| Overlapping deferrals at one occurrence count once | Two rows of one decision, or a re-affirmed date, would double it |
| One taken back before it held counts nothing | Correcting a mistake is not avoiding work |
| One asking for a past date counts nothing, and is refused | |
| The threshold is whole days, refused otherwise; one stored between days reads as the later day, by gate and form alike | The form and gate never disagree |
| Whether a decision needs a second person, and the threshold, are read inside the writing transaction | A threshold lowered between answer and write stores a decision as needing nobody |
| The repeated-deferral report counts the same way, grouped on product and issue, never on displayed names | Two products displayed alike would merge |

## The review queue

Each entry carries the current reasoning, whether it was agreed before, and how
long the finding has been put off. The queue shows only work the reader can do,
narrowed in the query.

### Queue entries

One entry per decision, newest first: a representative row, its occurrence and
reasoning, the rows, issues and occurrences covered, and every build reached by
matching. The count beside the queue counts decisions.

An entry says what it is about (REQ-28): the build, the issue and its report,
component and version, severity and exploitation, upstream's action, both ends
of the path, how many occurrences the issue sits at and how many the decision
covers. It is read from the matching open finding, by occurrence and versions
while live and by occurrence once lapsed, in a handful of statements a page.

Two counts say what would make an approver disagree (REQ-28): what was already
agreed about the issue at other occurrences, by outcome, and what else at this
occurrence nobody answered.

| Rule | Reason |
|---|---|
| Builds, outlier fix versions and counts are narrowed per product to what the reader may see | |
| A decision is shown only to somebody who may act on every row | |
| Reach over every row is asked once per decision, over the grouping, as a join finding no row | 29 ms against 78 ms per row on PostgreSQL, 39 against 73 on SQLite, for 3,000 decisions of 133,000 rows (`design-docs/triage-measurements.md` § Review queue reach) |
| The first count is of approved decisions only | Proposals would let two queued people count each other |
| The decision's own occurrence is not excluded | An occurrence has no product, so excluding it drops other products' decisions |
| A run is the second signal | A run is how forty get waved through |
| Both counts are read for the page in two statements | |
| The second count reaches rows through the issue first | From the row first, SQLite takes 1.0 s against 0.016 s for a kernel occurrence of 6,000 issues in a product of 3,060 rows, and 2.2 s against 0.13 s for the first card; other engines stay under 0.05 s, statistics refreshed |
| The page and its total are one statement, a window count; a page past the end counts alone, and `limit=0` answers the total | The badge and tab counts ask the total |
| A card's size and earliest row are aggregates over readable rows, and only that row is read | |

### Queue contents

Three lists, one per reason a decision waits; a decision may be in two.

| Reason | Holds | Shown to | Answered by |
|---|---|---|---|
| Approval | A decision awaiting a second person, nothing sent back | Whoever may approve every row, never a proposer or author of it | Approving, sending back, or setting rows aside |
| Expired deferral | A deferral, proposed or agreed, past its date | Whoever may decide every row, the proposer included | A new decision |
| Missed fix date | A promised upgrade or patch, proposed or agreed, past its date | Whoever may decide every row, the proposer included | A new version or date, or a new decision |

| Rule | Reason |
|---|---|
| A decision that needed nobody waits for no approval | |
| A lapsed decision is in none, only its author's To reaffirm (`design-docs/triage-lapse.md` § Whole-action re-affirmation) | |
| A promise past its date stays in force | A commitment has no expiry |
| Moving a promise withdraws every agreement on it (`design-docs/remediation.md` § Commitment changes) | |
| The queue count and a product's waiting count read the approval list alone | |

A rating of an issue and a moved disclosure date wait for a second person too,
listed apart (`design-docs/interface-review.md` § The review queue).

### Queue filters

The queue and its export share filters. A decision is kept where one waiting row
satisfies every filter, and is shown whole.

| Filter | Meaning |
|---|---|
| Reason | Which list; approval by default |
| Own decisions | The reader's own; on the approval list, theirs nobody has agreed to |
| Product | Made in one product |
| Proposer | Made by one sign-in identity. An unknown name empties the queue, answering alike whether it exists |
| Age | Proposed at least this many days ago, on the entry's clock |
| Severity | Covering an issue rated this or worse by the rating in force in its product |
| Outcome | Of these outcomes |
| Release | Covering an open finding in a branch or tag of this name, by the builds-covered match, narrowed to readable findings |

## Limits

| Limit | Detail |
|---|---|
| Neither partial approval nor setting aside narrows within a fold | One decision covers the whole fold; splitting serves only decisions spanning folds |
