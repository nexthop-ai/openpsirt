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

The proposer and the approver are always different people, with no override.

| Rule | Reason |
|---|---|
| An approval names one revision of the reasoning (REQ-28) | A second pair of eyes read particular words; an approval free of them would stand after a rewrite, and nothing would report it |
| Nobody who proposed any row of a decision or wrote any of its reasoning agrees to it, asked by both writes that make a row stand on an agreement: one given now, and one a re-affirmation carries (REQ-24) | |
| The moved-row count is the control, so an engine that cannot report it refuses | The rows move only while the approved revision still stands, checked by counting what moved; read as optional, the check is skipped after the approval row is written |
| The reasoning is revised, never overwritten, and every revision is readable | |
| Editing the reasoning takes back the approval; the decision returns to the queue marked as previously approved | |
| Revising a decision that has ended brings it back, and is refused where another decision now stands | Its rows retake their occurrences. An occurrence decided since is refused naming the decision standing there, as proposing there is |
| Withdrawing, revising and sending back need no approval | Hiding risk needs a second person; putting it back on the table does not |
| Undoing works at the size it was done: a bulk approval records what it covered, and undoing returns the whole batch to proposed | The decisions stand; the agreement is what was taken back |
| Undoing and withdrawing leave an ended row as it ended: only approved rows return to proposed, and only proposed or approved rows become withdrawn | A lapsed row holds no live key, so returned to waiting nothing keeps it unique, and rewritten as withdrawn it loses when and why it stopped |
| A withdrawn approval stays on the record | It says a second person once agreed, and to which words |
| A withdrawal records who made it, apart from who gave the agreement | A proposer revising their own words withdraws every agreement on them, which must not read as somebody else undoing their agreement |
| A carried agreement says it was carried, wherever an approver's name appears against it | A re-affirmation stands on its predecessor's agreement with reasoning the approver never read; as an ordinary approval it claims they agreed today to unseen text (`design-docs/triage-lapse.md` § Re-affirmation) |
| Whether a decision waits for a second person is answered when it is made, and every read of a decision says so | A short deferral takes effect at once, and its author is told. A proposed decision that says nothing about a wait reads as in force, which shows a dismissal nobody agreed to as settled (REQ-24) |

### Approval as a set

Approving a decision approves every waiting row in it in one transaction, under
the rules each row is approved under. A row already approved, withdrawn or
lapsed is left alone; a row sent back is with its author and stays.

1. The author of the decision's current reasoning, read once.
2. One approval row, naming the revision and carrying what it covered, counted
   in one statement over every row and narrowed to what the approver may read.
3. The rows moved to approved in one update, conditioned on the decision still
   resting on that revision.
4. The matched count checked against what was meant, refusing the whole decision
   where it falls short, so a revision landing between leaves nothing half
   agreed.

| Rule | Reason |
|---|---|
| A bounded number of statements whatever the size | A decision over a kernel is two thousand rows. One row at a time, 1,760 rows took 15.6 s on the demo and 500 rows were 2,500 statements; as a set, 500 rows with two set aside are 15 statements on SQLite |
| A test pins the statement count | The count is what a per-row loop cannot satisfy |

## Rights

Arguing, agreeing and reading are separate questions.

| Act | Needs |
|---|---|
| Propose, revise, withdraw | Triage on the product, at the finding's visibility |
| Approve, undo an approval | The approver capability or triage, and reading the finding |
| Comment, or edit your own comment | Either of the above |
| Read what was decided | Reading the finding |

| Rule | Reason |
|---|---|
| A triager may approve somebody else's decision about disclosed or undisclosed work | Two triagers agreeing to each other's work is a small team's ordinary shape, and the control is that the two differ. A decision about a code finding takes the approver capability (`design-docs/analysis.md` § Code finding triage) |
| Reading is the finding's own visibility and nothing else (REQ-43) | Narrower, a reader sees "deferred" with no way to see why; one deployment's reader holding private reading was told none of a finding's 91 decision rows existed |
| Writing is a rule apart from reading | Commenting leaning on the reading rule lets a reader comment on what they may not argue |
| Every check reads the product and visibility from the row | Never from what a caller stated |
| An occurrence stating no visibility is undisclosed, normalized before the check | Normalized only before the write, it passes the check for disclosed work and is stored undisclosed |
| Unreachable and non-existent give the same answer (REQ-42) | Guessing identifiers says nothing |

Nothing under a finding carries a visibility of its own (REQ-40). A decision,
every revision of its reasoning, every approval, every comment and every person
named in them is read at the finding's visibility, so disclosing a finding
discloses the whole record of what was decided, by whom and when. A reader shown
a conclusion without the argument cannot check it, and a disclosure timeline
stopping at the finding is one nobody outside can evidence. A visibility column
on a comment or a decision reads as a tightening and defeats this silently.

A decision occurrence carries a copy of its finding's visibility, so a report or
an export answers who may reach it from the row.

| Rule | Reason |
|---|---|
| Issue disclosure rewrites the copy in the act that turns the findings public, and nothing else under a finding holds one (`design-docs/access.md` § Issue disclosure) | |
| An occurrence is written public where its issue has no undisclosed finding left in the product when the row is written | The visibility a proposal carries is read before the write, and a disclosure may land between |

## Set-aside rows

The queue entry carries its **outliers**, the rows unlike the rest. An approver
may set some aside: the rest is approved as one decision, and the rows set aside
become a returned decision derived from the original, the proposer's, sent back,
with the reason recorded on each as a comment. Otherwise an approver chooses
between refusing all and agreeing to all.

| Rule | Reason |
|---|---|
| A reason is required | |
| Setting aside a row outside the decision is refused | A stray identifier is likelier a mistake than a wish |
| The proposer may not set rows of their own decision aside | Setting aside approves the rest in the same act |

The outliers are five signals, already stored, counted over the distinct issues
in the decision:

1. This product recorded as attacked through it.
2. Known to be exploited.
3. Rated critical or high, by our assessment where one stands.
4. A fix available, read from the open findings the decision's rows match that
   the reader may see.
5. Where the record of how the set was narrowed names a term, a description not
   carrying it.

They are ordered attacked here, exploited, worst rated, then by name, capped at
twenty, with counts of how many are behind the cap.

| Rule | Reason |
|---|---|
| An issue this product was attacked through is never behind the cap | Agreeing is refused while one is in the decision (`design-docs/incidents.md` § Decisions against an incident), so it is the row an approver must be able to set aside |
| A row names every occurrence of its issue, and setting it aside sets them all aside | Agreeing to one occurrence of an issue is agreeing to the issue |
| Every act over many issues carries the table | Rows set aside, and a decision re-made after it lapsed, are refused over an attacked issue too; without the table the only answer is refusing them whole |
| The signals are read with one identifier per issue and per product | One kernel issue holds 133,549 rows in one measured estate, and one per row is a statement past the size an engine accepts |

## Partial approval

The proposer's side of the same mechanism: the rows named become a decision of
their own, derived from the original, carrying its argument, with the reason as a
comment, sitting with their author until the argument for them is stated again.
Revising gives them one. The outliers are shown to the author too, who faces the
approver's choice: hold part back, or argue all of it as one.

| Rule | Reason |
|---|---|
| A reason is required | As for setting rows aside |
| Naming a row outside the decision is refused | A stray identifier is likelier a mistake than a wish |
| Naming all of what is still argued is refused | That is a revision or a withdrawal |
| A row already agreed, withdrawn or lapsed cannot be held back | It is not still being argued |
| Splitting is the author's act and setting aside the approver's, each refused to the other | An author holding rows back while agreeing to the rest would approve their own decision |
| Narrowing within a fold is not offered | One decision covers the whole fold. A decision still spans several folds, about many issues at one component or carried across builds, which is why splitting is needed |

## Sending back

Sending a decision back takes it out of the approval list and returns it when
the author revises. A reason is required and travels as a comment. Without it, a
missing sentence costs somebody's work by withdrawal, or becomes a comment on a
decision that looks untouched in the queue.

| Rule | Reason |
|---|---|
| Not a state of its own | The decision is still proposed, and what changed is whose turn it is. A fifth state would be reasoned about everywhere the other four are |
| It suppresses nothing while back, and revising puts it back | A short deferral that needed nobody would otherwise go on hiding the finding while the notice to its author says it applies to nothing |
| It needs no approval | As revising and withdrawing need none |
| Nobody sends back a decision whose current words are their own | That is theirs to revise |
| Everybody whose words went back is told, sent to the finding (the build, the issue, the component at the version), or to the decision where no open finding the sender may read still describes it | A decision revised row by row rests on several people's words, and the finding is where words are revised |

## The deferral threshold

A deferral shorter than a configured threshold stands on its own: a quick "not
this sprint" is ordinary triage, and a queue holding every routine act stops
being read.

Short is measured against everything the finding has already been put off for,
so four twenty-nine-day deferrals are not a year nobody approved. Each deferral
counts what it asked for, for as long as it held: from when it was asked to the
date it returns on, cut short where it was taken back or lapsed first.

| Rule | Reason |
|---|---|
| A deferral taken back counts for the part that ran | Erased, withdrawing and deferring again, which needs nobody, hides an occurrence indefinitely under the line |
| A deferral that lapsed counts for the part that ran | A lapse ends its effect as a withdrawal does |
| Overlapping deferrals at one occurrence count once | One decision at two versions writes two rows over one stretch, and a re-affirmed deferral carries its date; summed, the total doubles |
| One taken back before it held counts for nothing | Correcting a mistake is not avoiding the work |
| One asking for a date already past counts for nothing, and is refused at submission | Counted as a negative, a back-dated request subtracts from the total |
| The threshold is a whole number of days, refused otherwise; one stored between two days reads as the later whole day, by the gate and the form alike | The form never calls a deferral standing on its own that the gate sends to a second person |
| Whether a decision needs a second person is worked out in the writing transaction, which also reads the threshold | Answered before the transaction and taken on trust, a threshold lowered between stores a decision as needing nobody under a policy saying it does |
| The repeated-deferral report counts the same way, grouped on the product and the issue, never on displayed names | Two products a catalog displays alike merge into one row, inventing a pattern and misplacing a real one |

## The review queue

Each entry carries the reasoning as it stands, whether it was agreed before, and
how long the finding has been put off: a list where judging a row means opening
it gets approved unread. The queue shows only work the reader can do, narrowed in
the query.

### Queue entries

One entry per decision, newest first, with a representative row, its occurrence
and reasoning, how many rows, issues and occurrences it covers, and every build
it reaches by matching. The count beside the queue counts decisions.

An entry says what it is about (REQ-28): the build to open, the issue and what
the report says of it, the component and version, how bad and whether it is
exploited, what upstream has done, the two ends of the way down, how many
occurrences the issue sits at, and how many the decision covers. All are read
from the open finding the row matches, by occurrence and versions while live and
by occurrence alone once lapsed, in a handful of statements per page.

It carries what would make an approver disagree (REQ-28), as two counts and no
argument: what was already agreed about the same issue at other occurrences, by
outcome; and how much else at the same occurrence nobody has answered. Not
looking them up becomes a choice.

| Rule | Reason |
|---|---|
| The builds named, the fix versions behind the outliers and the counts are narrowed per product to what the reader may see | A decision somebody may read matches findings they may not |
| A decision is shown only to somebody who may act on every row | An argument does not come in halves, and the size on the card would be wrong |
| Whether every row is in reach is asked once per decision, by the statement over the grouping, as a join finding no row | Counting expired deferrals among 3,000 decisions of 133,000 rows: 29 ms against 78 ms per row on PostgreSQL, 39 ms against 73 ms on SQLite. Asked in the `HAVING`, PostgreSQL spends 150 ms compiling a 30 ms statement (`design-docs/triage-measurements.md` § Review queue reach) |
| The first count is of approved decisions only | Counting proposals lets two people in a queue count each other as evidence |
| The decision's own occurrence is not excluded from it | An occurrence has no product in it, so excluding it drops a decision in another product shipping the same pair; the decision's own rows are proposed, so they never count |
| A run is the second signal | A decision in a run of forty is usually right, and a run is how forty get waved through |
| Both counts are read for the page in two statements | Fifty cards a row at a time is a hundred round trips |
| The second count reaches each row through the issue first | The index on a row's product, issue and occurrence then answers each finding in one seek. From the row first, SQLite reads every row in the product once per finding: 1.0 s against 0.016 s for a kernel occurrence of 6,000 issues in a product of 3,060 rows, and 2.2 s against 0.13 s for the queue's first card. The other engines answer that card under 0.05 s either way, measured after refreshing their statistics |
| The page and its total are one statement, the total a window count; a page past the end counts alone, and `limit=0` answers the total alone | The rail's badge and each tab's count ask for the total |
| A card's size and earliest row are aggregates over the rows the reader may read, and only that earliest row is read | |

### Queue contents

Three lists, one per reason a decision waits. Each is asked for by its reason,
and a decision waiting for two is in both.

| Reason | Holds | Shown to | Answered by |
|---|---|---|---|
| Approval | A decision awaiting a second person, nothing sent back | Whoever may approve every row of it, never somebody who proposed a row or wrote its reasoning | Approving, sending back, or setting rows aside |
| Expired deferral | A deferral, proposed or agreed, whose date has passed | Whoever may decide on every row, the proposer included | A new decision |
| Missed fix date | A promised upgrade or patch, proposed or agreed, whose date has passed | Whoever may decide on every row, the proposer included | Moving the promise to a new version or date, or a new decision |

| Rule | Reason |
|---|---|
| A decision that needed nobody waits for no approval | A deferral under the threshold is in force when made |
| A decision the code moved out from under is in none of the lists | It is its author's to re-affirm, in the To reaffirm list (`design-docs/triage-lapse.md` § Whole-action re-affirmation) |
| An expired deferral or a missed fix date is anybody's in the product | Any triager may decide it again |
| A promise with a passed date stays in force | A commitment has no expiry of its own, so the passed date is the one sign it did not hold |
| Moving a promise withdraws every agreement on it | `design-docs/remediation.md` § Commitment changes |
| The count beside the queue and a product's waiting count read the approval list alone | |

A rating of an issue and a moved disclosure date wait for a second person too.
Neither is a decision, and each is listed apart (`design-docs/interface.md` § The
review queue).

### Queue filters

The queue and its export take the same filters. A decision is kept where one of
its waiting rows satisfies every filter, and is then shown whole.

| Filter | Meaning |
|---|---|
| Reason | Which of the three lists; approval where none is named |
| Own decisions | Only the reader's own. On the approval list, what they proposed and nobody has agreed to |
| Product | Decisions made in one product |
| Proposer | Decisions one person made, by sign-in identity. A name nobody holds leaves the queue empty, so an unapplied filter never reads as one that worked, and the answer is the same whether the name exists or not |
| Age | Proposed at least this many days ago, on the clock the age beside each entry reads |
| Severity | Covering an issue rated this badly or worse by the rating in force in the decision's product |
| Outcome | Decisions of these outcomes |
| Release | Covering an open finding in a branch or tag of this name, by the match naming the builds a decision covers, narrowed to findings the reader may see. A decision names no release, so one with nothing open under it in a release is not about that release |

## Limits

| Limit | Detail |
|---|---|
| A deployment with one person approves nothing | The two people are the control, with no override |
