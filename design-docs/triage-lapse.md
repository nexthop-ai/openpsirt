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

A decision stops applying when its versions move (`design-docs/triage.md` §
Expiry). Marking tells its author, so the finding does not reappear as never
looked at.

### Moved versions

A scan, having recorded what moved, marks the decisions it moved out from under.

| Rule | Reason |
|---|---|
| One statement, never one per occurrence | A sweep costing a write per occurrence gets turned off |
| Marked in bounded batches until one comes back short | 1.2 s a read over 133,549 live rows on PostgreSQL |
| A rebuild that moved nothing marks nothing | |
| Either version moving lapses a decision | |
| Marked only where this build holds the occurrence at other versions and no open finding in the product still matches the decision's versions | Another branch may still ship the decided version |
| A decision covering nothing in the product is not marked | |
| Only the scanned build's product is swept | |
| The comparison uses the expression that wrote the version | |
| Failing to mark is reported, not fatal | The marking is a prompt |

### A worse rating

A decision a severity bears on also lapses when its issue is rated worse
(REQ-25); § Re-affirmation defines both.

| Rule | Reason |
|---|---|
| Swept after every scan, over the issues the build has open | One build's report can raise a rating another product decided against |
| Swept when a rating here is put in force, agreed or withdrawn | Withdrawing a milder rating can restore a worse one |
| Proposed decisions lapse as well as approved | |
| Compared per decision, issue and product | |
| The proposer is told why (`design-docs/notifications-work.md` § Decision outcomes) | |
| Why it lapsed is worked out when read; both reasons can hold | |
| Failing to mark is reported, not fatal | |
| A decision covering nothing open in its product is not marked | |
| Covering is asked of the issue the decision is read as, already joined | 1.37 s after a rescan of 324,508 findings beside 133,549 rows, against 64.3 s with a nested existence test on the name |

### Merged issues

When a report merges two issues, the live decision with less standing of two at
one occurrence lapses, in the transaction applying the report, the merge naming
its replacement (`design-docs/findings-issues.md` § Merged issues;
`design-docs/notifications-work.md` § Decision outcomes).

### Stopped standing

| Where | Answer |
|---|---|
| The decision list | One filter covers lapsed decisions and passed deferral dates, a row in both counted once; the passed decisions are read once as a set: 22 ms for 133,000 rows on PostgreSQL, against 170 ms per row |
| The review queue | An expired deferral is in Expired deferrals while it stands; once it lapses, only in its author's To reaffirm |

## Re-affirmation

A bump prompts a re-check, so the decision's maker may re-make it with a fresh
reason and no second approver.

| Sent back for full approval | Reason |
|---|---|
| Nobody agreed to the previous decision | Asked of its agreements, never its state, since a proposed decision lapses too |
| A severity risen since, on a decision it bears on | The agreement was about the lower risk |

| Decision | A risen severity bears on it | Reason |
|---|---|---|
| Not applicable: component not present | No | Absent code is harmless at any severity |
| Not applicable: vulnerable code not present | No | The same |
| Not applicable: not in execute path | No | Code that never runs is harmless |
| Already fixed | No | The fix ships regardless |
| Not applicable: cannot be controlled by an adversary | Yes | A higher rating is often a new way in |
| Not applicable: inline mitigations exist | Yes | A mitigation is weighed against the attack |
| Deferred, will not fix | Yes | Both accept the risk |
| Upgrade needed, patch needed | Yes | Both accept it until their date |
| Affected, wrong match | No | Affected hides nothing; a wrong match is identity |

Rated worse is a higher band (low, medium, high, critical), never a higher score
within one: 7.5 to 7.6 is the same decision. An unrated issue is measured from medium.

| Rule | Reason |
|---|---|
| The band is read from the rating in force: this product's word, else the published score, else the published word | Deadlines, filters and the minimum severity band on the word |
| The score is read ahead of the published word | The word is fixed at first sight; the score moves with reports |
| A product's own word overrides both, so agreeing a word below the published one can still lapse a decision made against a lower published score | |
| The baseline stored on each row is the rating in force in its product when decided | Stored as the published score, a product that assessed an issue down holds a baseline nobody worked to |
| A changed justification is no trigger: re-affirming copies it, and changing it is a new decision | |
| A count of re-affirmations is no trigger | |
| What may be carried is read from the row, never supplied | A withdrawn decision keeps its approvals, which a supplied copy would carry |
| One function decides the second person and writes the carried agreement | |
| The carried agreement names its origin, is guarded on the revision, and shows as carried | |
| All of it is one transaction | |
| Only a lapsed occurrence with nothing decided since is re-affirmed | |
| Re-affirming a whole decision or many asks the same of each; one with a withdrawn row is refused | Its author took it back |

## Whole-action re-affirmation

A bump lapsing every row of a decision is answered by one act at the grain it
was made at.

| Rule | Reason |
|---|---|
| One act, one reasoning, one new decision | One kernel issue writes 45 rows in one action |
| The rows are resolved here, never named | |
| Each lapsed occurrence is re-made at its current versions in every build it is open in; one open nowhere is not re-made | |
| The proposer's act alone | An approver doing it sits on both sides |
| Any row escalating sends the whole act back (REQ-28) | An approver works at the proposer's unit |
| The carried agreement is one row, effective on all rows together | |
| A row replaced by a later decision of another made at its occurrence after it stopped standing is not re-made; an earlier sibling at another version replaces nothing, nor do rows of one decision | The later one is what the occurrence last said |
| A row whose versions are still open is re-made at them alone | It lapsed for a rating, its code unmoved |

Lapsed decisions are reached by the findings list's `lapsed` state and the
queue's To reaffirm tab, the reader's own. Neither lists nor offers a decision
with a withdrawn row, nor a row at a code finding past its end of life, nor a
decision with no other row (`design-docs/analysis-triage.md` § End of life).

## Re-affirmation across decisions

One act re-makes several of one person's lapsed decisions, as a kernel stable
release, a point release or a new branch lapses many at once.

| Rule | Reason |
|---|---|
| The person's own lapsed decisions nothing replaced, listed for them, linked from the lapse message | |
| Decisions are named, rows resolved as the whole-action form does; one with no such row answers as not there | |
| Each is re-made whole by the single rules, with its own outcome, justification, dates, version and agreement | |
| One reasoning shared by all | The reason is what was checked |
| The second person is decided per decision, any row escalating its whole decision (REQ-28) | |
| A decision somebody else made refuses the whole act, naming its issues | |
| Every row is authorized before anything is said about its author (REQ-42) | |
| The limits count every row written across every decision, the larger only where nothing goes back to an approver; a promise to upgrade is not counted (REQ-27) | Per decision, many under the limit write without bound |
| Refused whole or written whole | |

The response says per decision what lapsed, what re-makes it, and whether it
waits. 300 decisions at two occurrences each take 0.25 s on SQLite and 2.3 s on
PostgreSQL.

## Limits

| Limit | Detail |
|---|---|
| Nobody but its maker carries a lapsed decision's agreement forward | Anybody else proposes it afresh, for a second person, so a decision whose maker has gone loses its agreement at the first lapse |
