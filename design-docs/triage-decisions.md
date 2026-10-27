# Decisions and their record

What one decision holds, what each act lands on, how the record is read back,
and the comments, notes and labels beside it.

Satisfies REQ-29, REQ-40, REQ-43, REQ-53, REQ-57, REQ-65, REQ-66.

## Contents

- [Decisions](#decisions)
- [The decision and its rows](#the-decision-and-its-rows)
- [Act placement](#act-placement)
- [Readback](#readback)
- [The whole decision](#the-whole-decision)
- [Decision lists on a finding](#decision-lists-on-a-finding)
- [Extensions](#extensions)
- [Decision outcomes](#decision-outcomes)
- [Comments and reasoning](#comments-and-reasoning)
- [Notes on an issue](#notes-on-an-issue)
- [Labels](#labels)

## Decisions

A decision writes one row per occurrence, and per issue where it covers many;
each row is keyed and lapses on its own (`design-docs/triage.md` § Decision
identity). The **decision** is the one argument with its reach that a second
person agrees to, and the queue, approval, sending back and undoing work on it.

| Kind | What it is |
|---|---|
| finding | One issue in one component, at the occurrences it sits at. A re-affirmation is one too |
| together | A bulk decision: many issues at one component |
| extension | An approved decision carried to a new issue at the same component and consumer, with the same justification |
| returned | The rows an approver set aside from a decision they agreed the rest of |

A decision records its action, who took it and when, how a bulk set was
narrowed, and, for an extension or a returned decision, its source.

## The decision and its rows

| On the decision | On each row |
|---|---|
| The outcome | The occurrence, and the two upstream versions |
| The justification, and the mitigation one of them takes | Its state, and when it ended |
| The date a deferral looks again on | Whether it needs a second person: a short deferral does not, measured per occurrence |
| The date a promise acts by, and an upgrade's version | The finding's visibility, the stricter of two where an occurrence is private |
| The version an already-fixed decision names | How bad it was judged, read from the occurrence |
| The reasoning, every revision, and which stands | The VEX statement it was started from, where there was one |
| The approvals and comments | |
| The builds it was made on | |

| Act | Builds recorded as made on |
|---|---|
| A decision on a finding, from its screen or the findings list panel | The build in the path, and every build named beside it |
| A decision about one occurrence | The build in the path |
| A bulk decision | The build the selection was made in |
| A promise to upgrade | Every build it names |
| Carrying to a new line | That line |
| Re-affirming, and rows set aside by approver or proposer | The builds of the decision it re-makes |
| A decision recorded before builds were kept | None |

| Rule | Reason |
|---|---|
| The words live on the decision, once | Per row, a decision at forty-four occurrences is forty-four separately revisable copies. The demo held 11 decisions, 155 rows and five distinct pieces of reasoning |
| An action recording two outcomes or versions is refused | It is two decisions, and taking the first loses the other |
| The decision and its first reasoning are written in one transaction | A decision without reasoning reaches the queue with nothing to review |

## Act placement

| Act | On |
|---|---|
| Approve, send back, set rows aside, point elsewhere | The decision |
| Hold part of it back | The decision, by its author; the rows named become a decision |
| Revise the reasoning | The decision: one text, one history |
| Withdraw | The decision; taking back part is setting rows aside |
| Comment | The decision |
| Re-affirm | One occurrence, whose version moved |
| Re-affirm the whole decision | The decision, where every row lapsed under one bump |
| Re-affirm many | Several of one person's lapsed decisions, each re-made as its own |

| Rule | Reason |
|---|---|
| One approval row per decision | An approver agrees to the words once; per row, a kernel decision wrote two thousand agreements, each able to outlive the words |
| Recording is set-based, rows written in batches as the scan apply writes | 507 occurrences for the demo's worst decision is 1.4 s one row at a time on MySQL; on SQLite 500 occurrences take 6 statements, pinned by a test |

## Readback

Each way of adding to a decision has a way to read it: the reasoning it rests
on, earlier justifications, who agreed to which, and the discussion. Decisions
list across products and filter by outcome, state, and passed deferral date, so
dismissals and approvals are reportable (REQ-53).

| Rule | Reason |
|---|---|
| Each list carries the reasoning and names with the row | A bare product and issue number is two more requests per row |
| Who may read it is the finding's own visibility: the decision, revisions, approvals, actors and comments | Disclosure makes the record mean all of them |

Undoing a bulk approval:

| Rule | Reason |
|---|---|
| Narrows to what the person undoing may reach | A batch may span products |
| Takes back only their own agreements | Two reviewers may hold batches of one name |
| Leaves whole a decision it reaches only part of | The agreement is one row on the decision |
| Leaves whole a decision about a code finding recorded as a flaw | Its flaw is judged instead (`design-docs/analysis.md` § Flaw records) |
| Reports what returned to waiting | Ended decisions and those another agreement holds stay |

A code finding recorded as a flaw is in no list of held work; its flaw is
(`design-docs/analysis.md` § Code finding assignment).

## The whole decision

One read answers everything about one decision.

| Part | Holds |
|---|---|
| What it says | Outcome, reason, mitigation, dates, upgrade version and current justification; no occurrence and no row state |
| What became of it | One word over every row, as the proposer's list reads it, with when and by whom; rows that ended differently read as mixed. Come back means an approval on record and none standing; for an approved decision, "was this ever approved" answers about the agreement read |
| What it wrote | Rows, distinct issues, distinct occurrences |
| Present reach | Folds, packages, consumers and findings its live rows cover, matched as a finding matches a decision, and every build they reach |
| Reach when it stopped | Per withdrawn and per lapsed rows where any exist: the rows, distinct occurrences, the latest stop, and every build holding an open finding at one of them when its row stopped. A partly lapsed decision splits between this and present reach |

| Reach when it stopped | Reason |
|---|---|
| Worked out on request from the rows and each finding's opening and closing | Both moments are on the rows |
| Each row at its own moment; a finding counts where it opened by then and had not closed | |
| Matched by occurrence, never version | A lapse is the version moving |
| The findings list narrows to one decision's occurrences, optionally by its row's state there | |

| Rule | Reason |
|---|---|
| The state shown is the decision's, never a row's | One row approved beside forty-three sent back read as approved |
| What it covers is worked out when asked; what somebody consented to is stored with their approval | A build appearing later is covered by matching |
| Refused whole or answered whole | |
| Lists showing rows a reader may read omit the reasoning of a decision they may read only part of: the audit log, decision occurrences, one occurrence, and the earlier, similar and elsewhere decisions on a finding | The reasoning covers every occurrence |
| A case grant reaches it | An offer then refused reads as a fault |
| While a flaw is undisclosed, its readers reach a decision at an included code finding's occurrence (`design-docs/analysis.md` § Disclosure inclusion) | |
| Every count and reach is narrowed to findings the reader may see | A count leaks where no row is shown |

## Decision lists on a finding

| List | Holds |
|---|---|
| Standing | Live decisions at any of its occurrences, newest first, with occurrences covered, builds reached the reader may see, and who agreed when |
| Previous | Lapsed or withdrawn decisions there, newest first, with when they ended and their last reasoning |
| Similar | At most five approved not-applicable decisions about other issues at the same occurrences, with reasoning and issue count: what an extension can carry |

Each is narrowed to what the reader may see. `design-docs/triage-evidence.md`
§ Decided elsewhere holds the fourth block.

| Rule | Reason |
|---|---|
| Standing is matched by key, the build's occurrences and versions read by the finding store, never the request | Matched by occurrence alone, a decision at one version stands on another |
| Each entry gives its rows' standing here and the decision's state, approved only where every live row is | |
| Sent-back rows carry when, and the approver's reason | |
| A decision occurrence records when it stopped applying | |
| A similar decision's issue count covers every row the reader may see | A sample is not the count |

## Extensions

An extension records an approved decision against a new issue at the same
occurrences, as a decision of its own. Checked inside the writing transaction:

1. Every row of the source is approved.
2. The new rows sit at the source's occurrences, in the same product, for an
   issue the source does not cover, asked of every row of the source.
3. The outcome and justification are the source's; one stating no statement
   scope takes the source's, and one stating another is refused.

A second person agrees, and the queue names the source. Whether rejecting a
source reaches its extensions is not decided.

## Decision outcomes

A person's page of what they proposed and what became of it, narrowed to what
they may still read. Its rows are narrowed as well as its list, or undisclosed
rows count into the totals and can be shown as the representative.

## Comments and reasoning

| | Revising the reasoning | Adding a comment |
|---|---|---|
| The approval on it | Withdrawn | Untouched |
| What it said before | Readable | Readable behind an "edited" mark |

| Rule | Reason |
|---|---|
| History keeps the wording each replacement removes, written with the edit in one transaction | A change recorded without its old text looks like history and is not |
| The history is read only when asked | |
| Who may read a comment is asked of its decision | |
| Nobody edits another's words | |
| Access to the decision is settled before anything about the comment is answered (REQ-42) | Otherwise "not yours" and "no such comment" differ, and identifiers can be walked |
| Reasoning, revisions, comments and notes pass the one text policy before storage, and the API returns markdown with what each reference resolved to (REQ-65, REQ-66; `design-docs/text.md`) | |

## Notes on an issue

A **note** tells whoever decides something without recording a decision
(REQ-29). It changes nothing: ranking, deadline, or what the product triages.

| Rule | Reason |
|---|---|
| Keyed on the issue and the product, like a rating (REQ-29), reaching every build and lapsing on no version | One issue is often several list rows: 786 of 5,840 open issues on the seeded image, at most eleven |
| Reading asks whether the reader may read a finding of that issue in that product, at its visibility (REQ-43); writing asks for triage there | A product the reader holds nothing on answers as an issue not there |
| One undisclosed occurrence makes the whole thread undisclosed | One thread cannot be public in part |
| Only the author changes one, and the earlier text is kept in the same transaction | It goes public at disclosure |
| A name after `@` is told where that person may read the subject; one reaching nobody is reported without why | As a comment's mentions |

### Two records, not one

| | Hangs off | Is about |
|---|---|---|
| A comment | A decision | The argument, at its occurrences |
| A note | An issue in a product | The issue here |

A decision is keyed on occurrences and a note on an issue, and the decision's
record stays what people wrote about it, which lets an approval point at one
revision (REQ-28). What is true of one copy and not another is a comment.
`design-docs/interface.md` § The finding screen draws both.

## Labels

A finding takes free-text **labels** (REQ-57), filterable, so marks such as
customer-escalated or waiting on a vendor stay out of the reasoning.

| Rule | Reason |
|---|---|
| No vocabulary is fixed; a product's labels are offered back, most used first, as a filter's suggestions | None has been earned, and a label gone universal has a shape of its own, which the counts evidence |
| What is in use is narrowed to findings the asker may read | "Waiting on the reporter" beside an embargoed issue is its disclosure |
| The grain is one issue, in one fold, in one product | The unit a decision covers |
| Put on every package of the fold the product holds the issue at; read from any package of the fold, once each, so a package joining the fold carries them; taken off all through any one | |
| Each package's word at its own visibility: writes reach packages whose findings the caller may triage; a word shows where its package carries a finding the reader may see, and the filter asks at the row's visibility | A word on an undisclosed package does not show through a disclosed one |
| Matched regardless of capitals and shown as typed; labeling a labeled finding succeeds and keeps the first spelling | |
| Labeling is triage; a reader sees labels without the control | |
| Each list group carries its labels, read for the page in one statement, each a filter | |
| Called a label in every register | |
