# Lapse and re-affirmation

How a decision is marked as no longer applying, and how its author re-makes it:
one occurrence, one decision whole, or many decisions at once.

Satisfies REQ-25, REQ-27, REQ-28, REQ-42.

## Contents

- [Lapse marking](#lapse-marking)
- [Re-affirmation](#re-affirmation)
- [Whole-action re-affirmation](#whole-action-re-affirmation)
- [Re-affirmation across decisions](#re-affirmation-across-decisions)
- [Limits](#limits)

## Lapse marking

A decision stops applying the moment its versions move, because what applies is
matched on them (`design-docs/triage.md` § Expiry). Marking is how somebody finds
out: unmarked, the finding reappears as though nobody had looked, and the
reasoning sits on a row nothing points at.

### Moved versions

A scan, having recorded the versions that moved, marks the decisions they moved
out from under, and those become their authors' work.

| Rule | Reason |
|---|---|
| One statement, never one per occurrence | A real image holds tens of thousands of occurrences, and a sweep costing a write per occurrence gets turned off |
| Marked a bounded batch at a time, ending at a batch that came back short | A short batch named everything lapsable at that moment; what changed since is the next sweep's. 1.2 s a read over 133,549 live rows on PostgreSQL |
| A rebuild that moved nothing marks nothing | Rebuilds are nightly |
| A decision lapses when either version moves | |
| Covering is asked of the product: a sweep marks only where this build holds the occurrence at other versions and no open finding anywhere in the product still matches the decision's versions | One branch moving while another ships the decided version leaves the decision covering the other; it is marked once the last build holding its versions has moved |
| A decision covering nothing in the product is not marked | A component that is gone closed its findings; one still present at another version is the question to answer again |
| Only the scanned build's product is swept | The same pair of names sits in other products, and their decisions are theirs |
| The comparison uses the expression that wrote the version | Two spellings lapse a decision on one path and keep it on the other |
| Failing to mark is reported and not fatal | What the scan found is correct, and the marking is a prompt |

### A worse rating

A decision a severity bears on also lapses when its issue is rated worse
(REQ-25). § Re-affirmation says which decisions those are and what rated worse
means.

| Rule | Reason |
|---|---|
| Swept after every scan, over the issues the build has open | An issue is one row for the deployment, so one build's report can raise the rating a decision in another product was made against |
| Swept when a rating is put in force here, agreed or withdrawn | Withdrawing a milder rating puts the published one back, which can be worse |
| Proposed decisions lapse as well as approved ones | Agreed later, a decision against the lower rating stands on a baseline already wrong |
| Compared per decision, per issue, per product | The rating in force is each product's own |
| The proposer is told why | `design-docs/notifications.md` § Decision outcomes |
| Why a decision lapsed is worked out when read, never stored; both reasons can hold | A version matching nothing open and a rating in a higher band are facts about the present |
| Failing to mark is reported and not fatal | The decision stands until the next scan with the issue open sweeps |
| A decision covering nothing open in its product is not marked | Its proposer would be told of a finding open where none is, and re-affirming would re-make nothing |
| Covering is asked of the issue the decision is read as, which the sweep has already joined | A decision under a merged name covers the findings held under the other. 1.37 s for the sweep after a rescan of 324,508 open findings beside 133,549 rows, and 64.3 s through an existence test on the name nested in the covering test |

### Merged issues

A decision also lapses when a report merges two issues and it is the one with
less standing of two live decisions at one occurrence. The merge records which
decision stands in its place, and the lapse is written in the transaction
applying the report. `design-docs/findings-issues.md` § Merged issues holds the
rule; `design-docs/notifications.md` § Decision outcomes says who is told.

### Stopped standing

A lapse and a deferral whose date has passed are separate mechanisms, and a
deferral that ran out on code that then moved is both.

| Where | Answer |
|---|---|
| The decision list | One filter answers both, and a row in both counts once. The decisions whose date has passed are read once as a set and each row tested against it: 22 ms to count 133,000 rows on PostgreSQL, against 170 ms asking each row's decision |
| The review queue | An expired deferral is in the Expired deferrals list while it stands. Once it lapses it is in none of the queue's lists, and only in its author's To reaffirm |

## Re-affirmation

Two people already agreed. A version bump is a prompt to re-check, so the
person who made the decision may re-make it with a fresh reason and no second
approver; full approval on every bump produces rubber-stamping.

| Sent back for full approval | Reason |
|---|---|
| Nobody agreed to the previous decision | Nothing to carry. Asked of the agreements on the row, never its state: a decision lapses from proposed too, and reading "lapsed" as agreement lets one person propose a dismissal, wait for a bump, re-affirm it, and have it stand needing nobody |
| A severity risen since, on a decision it bears on | The agreement was that this did not matter much, not about what it became |

| Decision | A risen severity bears on it | Reason |
|---|---|---|
| Not applicable: component not present | No | Absent code is not dangerous at any severity |
| Not applicable: vulnerable code not present | No | The same |
| Not applicable: not in execute path | No | Code that never runs is not dangerous at any severity |
| Already fixed | No | The fix ships whatever the rating says |
| Not applicable: cannot be controlled by an adversary | Yes | A higher rating is often a new way in |
| Not applicable: inline mitigations exist | Yes | A mitigation is weighed against what the issue lets an attacker do |
| Deferred, will not fix | Yes | Both accept the risk, and the severity is the risk |
| Upgrade needed, patch needed | Yes | Both accept the risk until their date |
| Affected, wrong match | No | Affected hides nothing; a wrong match is about identity |

Rated worse is a higher band (low, medium, high, critical), never a higher score
within one: 7.5 to 7.6 is the same decision. A decision about an unrated issue is
measured from medium, as a deadline reads one.

| Rule | Reason |
|---|---|
| The band is read from the rating in force, as the baseline was: this product's word where it has one, else the published score, else the published word | Deadlines, filters and the minimum severity band on the word instead |
| The score is read ahead of the published word | The word is recorded at first sight and not revised, while the score moves with reports; banded on the word, no re-rating by the world lapses a decision |
| A product's own word overrides both | It is the rating in force here. Agreeing a word below the published one can still lapse a decision, where the word is above the published score the decision was made against |
| How bad it was judged is kept on the row, as the rating in force here, never the published score | An issue's severity is rewritten in place, so read now it compares with itself; a product that assessed an issue down holds a baseline nobody else works to |
| A changed justification is no trigger: a re-affirmation copies the justification, and changing it is proposing a new decision | |
| A count of re-affirmations is no trigger | It fires on nothing having changed |
| What may be carried is read from the row, never supplied | A stale copy carries a withdrawn agreement, and an invented one carries none that existed. A withdrawn decision keeps its approval rows, so otherwise a bump undoes a withdrawal |
| Whether a second person is needed and the carried agreement are asked by one function | Two spellings disagree, and the disagreement is the state above |
| The carried agreement names the agreement it came from, and is marked carried everywhere an approver's name appears against the decision | The reasoning is the re-affirmer's own and nobody else read it; somebody agreed to earlier words on an earlier day |
| The carried agreement is guarded on the revision | An agreement is to particular words |
| All of it is one transaction | Stopped part way, a decision stands that nobody agreed to and no queue shows |
| Only an occurrence that lapsed, with nothing decided there since, is re-affirmed | A standing row re-made at another version carries its agreement to an occurrence no second person saw |
| Re-affirming a whole decision, or many, asks the same of each decision named | A decision with a withdrawn row was taken back by its author |

## Whole-action re-affirmation

A bump lapses every row of the decision it moved under, so re-making them is
one act at the grain the decision was made at.

| Rule | Reason |
|---|---|
| One act, one reasoning, one new decision | Deciding one kernel issue writes a row at each of its 45 occurrences in one action; restoring them must not be 45 requests with 45 typed justifications |
| The rows are resolved here, never named | A caller naming them chooses which agreements carry forward, from rows read before the write |
| Each lapsed occurrence is re-made at the versions it has now, in every build it is open in; one open nowhere is not re-made | An occurrence open at two versions is two rows; one open nowhere is a finding that closed |
| The proposer's act alone | An approver re-making it becomes proposer while their own agreement is carried, one person on both sides |
| Any row escalating sends the whole act back (REQ-28) | An approver works at the unit the proposer acted at; per row, 44 rows stand and one waits |
| The carried agreement is one row, taking effect on all rows together | One agreement must not appear 45 times, nor half the act stand while half waits |
| A row is not re-made where a row of another decision, made at its occurrence after it stopped standing, replaced it | The later one is what the occurrence last said: the re-making decision, a fresh one, or one made and withdrawn. A decision made before the row stopped replaces nothing: two branches at two versions hold sibling decisions keyed apart. Rows of one decision do not replace each other |
| A row whose versions are still open is re-made at them alone | It lapsed for a rating with its code unmoved; at every open version it takes on builds it never covered and collides with a sibling |

The lapsed population is reached by the findings list's `lapsed` state and by
the review queue's To reaffirm tab, listing the reader's own lapsed decisions.
The act sits on the decision, or on several from that tab (§ Re-affirmation
across decisions).

| Not listed or offered | Reason |
|---|---|
| A decision with a withdrawn row | Its author took it back, and a withdrawal leaves an already-lapsed row as it was |
| A row at a code finding past its end of life, and a decision with no other row | `design-docs/analysis.md` § End of life |

## Re-affirmation across decisions

A bump on a large component lapses many decisions at once: a kernel stable
release every kernel decision, a distribution point release many packages, a new
release branch everything. Each is its own argument, so one act re-makes several
lapsed decisions of one person's.

| Rule | Reason |
|---|---|
| The decisions are the person's own lapsed decisions nothing replaced, listed for them, and the lapse message links there | Work handed back is found without searching |
| Decisions are named; their rows are resolved as the whole-action form resolves them. One with no lapsed row nothing replaced answers as not there | |
| Each is re-made whole by the rules re-affirming it alone follows: its own outcome, justification, dates and version, at each occurrence's versions now, carrying its own earlier agreement | |
| One reasoning, shared by every decision | The reason is what somebody checked; the argument is each decision's own |
| A second person is decided per decision; within one, any row escalating sends the whole decision back (REQ-28) | Each carries its own agreement |
| A decision somebody else made refuses the whole act, naming its issues | Re-affirming is the proposer's right; named, the rows can be taken out |
| Authorization is asked of every row before anything is said about who made it (REQ-42) | A decision the subject may not act on answers as not there |
| The limits count every row written across every decision; the larger issue limit holds only where no decision goes back to an approver; a promise to upgrade is not counted (REQ-27) | Held per decision, many decisions each under the limit write without bound under one sentence |
| Refused whole or written whole, in one transaction | A selection half re-made is one to work out again |

The response says, per decision, which lapsed, which re-makes it, and whether it
waits. The decisions are re-made one after another, a bounded number of
statements each: 300 decisions at two occurrences each in 0.25 s on SQLite and
2.3 s on PostgreSQL.

## Limits

| Limit | Detail |
|---|---|
| Removing a mitigation lapses nothing | A mitigation is configuration, which moves no version and which nothing here watches (`design-docs/triage.md` § Mitigations) |
