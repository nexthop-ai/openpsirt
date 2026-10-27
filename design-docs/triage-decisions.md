# Decisions and their record

What one decision holds, what each act lands on, how the record is read back,
and the comments, notes and labels written beside it.

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
- [Limits](#limits)

## Decisions

A decision about a finding writes one row per occurrence; a decision about many
issues writes one per issue and per occurrence. Rows stay that fine because each
is keyed and lapses on its own (`design-docs/triage.md` § Decision identity). The
**decision** is what a second person reads and agrees to: one argument with its
reach. The review queue, approval, sending back and undoing all work on
decisions.

| Kind | What it is |
|---|---|
| finding | One decision about one issue in one component, covering the occurrences it sits at. A re-affirmation is one too |
| together | A bulk decision: one decision about many issues at one component |
| extension | An approved decision carried to a new issue at the same component under the same consumer, with the same justification |
| returned | The rows an approver set aside from a decision they agreed the rest of |

A decision records what sort of action it was, who took it and when, how a bulk
set was narrowed, and, for an extension and a returned decision, which decision
it came from.

## The decision and its rows

The decision carries what it says; its rows carry where it lands and when it
stops applying.

| On the decision | On each row |
|---|---|
| The outcome | The occurrence, and the two upstream versions it was made against |
| The justification, and the mitigation that goes with one of them | Its state, and when it ended |
| The date a deferral looks again on | Whether that row needs a second person: a short deferral does not, and the threshold is measured per occurrence |
| The date a promise acts by, and the version an upgrade moves to | The finding's visibility, the stricter of two where an occurrence is private |
| The version an already-fixed decision names | How bad it was judged to be, read from the occurrence |
| The reasoning, every revision of it, and which revision stands | The VEX statement the argument was started from, where there was one |
| The approvals given for it, and the comments about it | |
| The builds it was made on | |

| Act | Builds it records as made on |
|---|---|
| A decision on a finding, from its screen or the findings list panel | The build in the path, and every build named beside it |
| A decision about one occurrence | The build in the path |
| A bulk decision over several issues | The build the selection was made in |
| A promise to upgrade | Every build the promise names |
| Carrying a decision to a new line | The line it is carried to |
| Re-affirming, one decision or many, and the rows an approver or the proposer set aside | The builds the decision it re-makes recorded |
| A decision recorded before the builds were kept | None; nothing is guessed |

| Rule | Reason |
|---|---|
| The words live on the decision, once | Per row, a decision at forty-four occurrences is forty-four copies of one sentence, each revisable on its own. The demo held 11 decisions, 155 rows, 155 revisions and five distinct pieces of reasoning, and every payload field was constant across every row of every decision |
| An action recording two outcomes or versions is refused | A set that disagrees is two decisions somebody meant to record as one, and taking the first loses the other half |
| The decision and its first reasoning are written together, in one transaction | A decision with no reasoning reaches the queue with nothing to review |

## Act placement

| Act | On |
|---|---|
| Approve, send back, set rows aside, point elsewhere | The decision |
| Hold part of it back | The decision, by its author. The rows named become a decision of their own |
| Revise the reasoning | The decision: one text, one history, one set of approvals to withdraw |
| Withdraw | The decision. Taking back part of an argument is setting rows aside, a different act with a different record |
| Comment | The decision. A note on one occurrence of forty-four is one nobody else reading the decision sees |
| Re-affirm | One occurrence: a version moved under one row, so that row's decision is re-made |
| Re-affirm the whole decision | The decision, where every row lapsed under one bump |
| Re-affirm many | Several lapsed decisions of one person's, each re-made as its own decision |

| Rule | Reason |
|---|---|
| Revising, withdrawing and commenting land where approval does | Five hundred rows recorded and agreed in one act must not take five hundred acts to unpick |
| One approval row per decision, never per occurrence | An approver reads the words once and agrees once. Per row, a decision over a kernel wrote two thousand copies of one agreement, each able to stand after the words changed |
| Recording is set-based: rows are written in batches, as the scan apply writes | One decision covers every occurrence it sits at, 507 for the demo's worst case, which one row at a time is 1.4 s on MySQL. On SQLite 500 occurrences take 6 statements, and a test pins the count |

## Readback

Each way of adding to a decision has a way of reading the result: the decision
with the reasoning it rests on, the earlier justifications, who agreed to which,
and the discussion. Decisions list across products and filter by outcome, by
state, and by whether a deferral's date has passed, so dismissals and approvals
are reportable in their own right (REQ-53); otherwise the only list is the
review queue, which holds what nobody has agreed to yet.

| Rule | Reason |
|---|---|
| Each list carries the reasoning and the names with the row | A row saying product 4, issue 91 is two more requests to understand, fifty times a page |
| Who may read it is the finding's own visibility | The decision, its revisions, the approvals, who acted, and the comments. Comments are included, because disclosure makes the record mean all three together |

Undoing a bulk approval:

| Rule | Reason |
|---|---|
| Narrows to what the person undoing may reach | A batch is one reviewer's afternoon and may span products |
| Takes back only the agreements the person undoing gave | A batch is named by whoever gives it, so two reviewers may each hold one of the same name |
| Leaves alone whole a decision it reaches only part of | The agreement is one row keyed on the decision; returning only part leaves the rest approved under an agreement the record says was withdrawn |
| Leaves alone whole a decision about a code finding recorded as a flaw | Its flaw is judged instead, and nothing else changes the decision (`design-docs/analysis.md` § Flaw records) |
| Reports what returned to waiting | A decision another agreement still stands on, and one that has ended, stay where they are, so candidates are not the number moved |

A code finding recorded as a flaw is in no list of held work: its flaw is held
and listed as itself (`design-docs/analysis.md` § Code finding assignment).

## The whole decision

One read answers everything about one decision.

| Part | Holds |
|---|---|
| What it says | The outcome, the reason, the mitigation, the dates, the version an upgrade moves to, and the justification as it stands. It names no occurrence and carries no row state |
| What became of it | One word over every row, the word the proposer's own list reads, with when and by whom. Rows that ended differently read as mixed. A decision marked as having come back has an approval on record and stands on none; for a decision currently approved, "was this ever approved" answers about the agreement being read |
| What it wrote | Rows, distinct issues, distinct occurrences |
| Present reach | Folds, packages, consumers and findings its live rows cover, matched as a finding asks whether a decision applies, and every build they reach. A withdrawn or lapsed row covers nothing |
| Reach when it stopped | One part for withdrawn rows and one for lapsed rows, each present only where such a row exists: the rows, the distinct occurrences, the latest moment one stopped, and every build holding an open finding at one of those occurrences when that row stopped. A partly lapsed decision reports its lapsed part here and the rest as present reach |

| Reach when it stopped | Reason |
|---|---|
| Worked out on request from the rows and each finding's opening and closing | Both moments are already on the rows |
| Each row is asked at its own moment | The rows of one part stop on different days |
| A finding counts where it opened at or before that moment and had not closed by it | A finding closed before a withdrawal, or opened after it, was never covered |
| Matched by occurrence, never by version | A lapse is the version moving, so matched on versions a lapsed row reaches nothing |
| Narrowed to findings the reader may see | As the present reach is |
| The findings list narrows to one decision's occurrences, optionally by the state of its row there | What sits there now is one link away, and the list stays the one place findings are listed |

| Rule | Reason |
|---|---|
| The state shown is the decision's, never a representative row's | A row's state standing in is how one row approved beside forty-three sent back read as approved |
| What it covers is worked out when asked | A decision reaches by matching, so a build appearing later is covered with nobody acting. What somebody consented to is stored with their approval, a different question |
| Refused whole or answered whole | Half the words would be about findings the reader may not see |
| A list of rows a reader may read leaves off the reasoning of a decision they may read only part of: the audit log, the list of decision occurrences, one occurrence alone, and the earlier, similar and elsewhere decisions beside a finding | The reasoning is about every occurrence of the decision |
| A case grant reaches it | Somebody brought into one issue is offered its decisions by every list, and an offer then refused reads as a fault |
| While a flaw is undisclosed, its readers reach a decision at an included code finding's occurrence | The readers of the flaw's undisclosed work and its case read the code finding, and the same narrowing adds its decisions (`design-docs/analysis.md` § Disclosure inclusion) |
| The counts are narrowed to findings the reader may see | A decision somebody may read can match findings they may not, and a count leaks where no row is shown |

## Decision lists on a finding

| List | Holds |
|---|---|
| Standing | Live decisions covering any of its occurrences, newest first, with how many occurrences each covers, every build it reaches that the reader may see, and who agreed and when |
| Previous | Decisions at its occurrences that lapsed or were withdrawn, newest first, with when they ended and the reasoning as it last stood |
| Similar | Approved not-applicable decisions about other issues at the same occurrences, at most five, each with its reasoning and how many issues it covers: what an extension can carry |

Each list is narrowed to what the reader may see. `design-docs/triage-evidence.md`
§ Decided elsewhere holds the fourth block.

| Rule | Reason |
|---|---|
| Standing is matched by key, with the build's own occurrences and versions read by the finding store, never taken from the request | The same pair of names sits in every build at whatever version each ships, so matched by occurrence alone a decision at one version stands on a build shipping another |
| Each entry carries how its rows here stand and the decision's state as a whole, approved only where every live row is | |
| Rows sent back carry when, and the approver's reason | |
| A decision occurrence records when it stopped applying | An approval's withdrawal date exists only where somebody had agreed |
| A similar decision's issue count is over every row of it the reader may see | A bulk decision writes thousands of rows, and a count over a sample is not the count |

## Extensions

An extension records an approved decision against a new issue at the same
occurrences, as a decision of its own: every nightly scan adds issues to
components already carrying agreed decisions.

Read inside the writing transaction:

1. The source is approved: every row, none withdrawn or lapsed.
2. The new rows sit at occurrences the source sits at, in the same product, and
   name an issue the source does not cover. Each is asked of every row of the
   source, because a decision covers as many issues as the act that wrote it.
3. The outcome and justification are the source's. An extension stating no
   statement scope takes the source's, and one stating another is refused.

| Rule | Reason |
|---|---|
| A second person agrees, as for any dismissal | |
| The queue marks it an extension and names its source | The approver knows the argument was read once already |
| Whether rejecting a source reaches its extensions is not decided | |

## Decision outcomes

A person's own page of what they proposed and what became of it.

| Rule | Reason |
|---|---|
| Narrowed to what they may still read | Losing a product's reading leaves no list of its issues on a personal page |
| The rows are narrowed as well as the page | The page lists a decision if any row is readable, and its rows need not agree about visibility; unnarrowed, the undisclosed rows count into the totals and can be returned as the representative |

## Comments and reasoning

| | Revising the reasoning | Adding a comment |
|---|---|---|
| The approval standing on it | Withdrawn | Untouched |
| What it said before | Kept and readable | Kept, readable behind an "edited" mark |

| Rule | Reason |
|---|---|
| The kept text is the wording a replacement takes away, written at the moment it is replaced | The comment row holds what it says now |
| The edit and its history are written together | An edit beside a failed history write is a record of a change with nothing saying from what |
| The history is read only when asked for | |
| Who may read a comment is asked of the decision | One question asked twice is two answers waiting to disagree |
| Nobody edits somebody else's words | An edit anybody could make is a forgery with a timestamp |
| Access to the decision is settled before anything about the comment is answered (REQ-42) | The row is read first to find its decision, but no answer turns on it until the asker is let in; otherwise "not your comment" and "no such comment" differ, and anybody holding triage anywhere walks the identifiers |
| The reasoning, a revision, a comment and a note pass the one text policy before storage, and the API returns the markdown with what each reference resolved to (REQ-65, REQ-66) | `design-docs/text.md` holds the policy |

## Notes on an issue

A **note** is what somebody wants whoever decides to know, written without
recording a decision (REQ-29). It changes nothing: what ranks, a deadline, or
what the product triages. A comment hangs off a decision, and assignment takes
only a person or a team, so a note is the first thing somebody can say.

| Rule | Reason |
|---|---|
| Keyed on the issue and the product, like a rating (REQ-29) | One issue is often several list rows: 786 of 5,840 open issues on the seeded image, the worst at eleven. A note on one row would be hidden from the others |
| It reaches every build of the product and lapses on no version | It is about the issue here |
| Reading asks whether the reader may read a finding of that issue in that product, at its visibility (REQ-43) | A product the reader holds nothing on answers as an issue that is not there |
| Writing asks for triage on that product at that visibility | Saying something on the record about work is part of arguing it |
| One undisclosed occurrence makes the whole thread undisclosed | A note is one thread for the issue, and the stricter direction is safe; the finding screen applies the same rule |
| Only the author changes one, and what it said before is kept, both written together | A note goes public at disclosure, and a record whose earlier text is lost is readable rather than checkable |
| A name after an `@` is told where that person may read what the note is about | The rule and query a comment's mentions use. A name reaching nobody is reported without saying why |

### Two records, not one

| | Hangs off | Is about |
|---|---|---|
| A comment | A decision | The argument somebody made, at its occurrences |
| A note | An issue in a product | The issue here, however many rows it sits on |

A decision is keyed on its occurrences and a note on an issue, so one record
cannot hold both, and the decision's record stays exactly what people wrote
about the decision, which lets an approval point at one revision (REQ-28).
Something true of one copy and not another, such as "we do not call that
function in the vendored build", is a comment. `design-docs/interface.md` § The
finding screen draws both.

## Labels

A finding takes free-text **labels** (REQ-57), filterable, with no fixed
vocabulary. People mark work regardless, such as customer-escalated,
release-blocker or waiting on a vendor, and with nowhere else it lands in the
reasoning, where nothing filters it and an approver reads it as argument.

| Rule | Reason |
|---|---|
| No vocabulary is fixed; what is in use in a product is offered back, most used first, as what a filter suggests | None has been earned. A label that becomes universal is a signal: "waiting on vendor" has a subject, an expected reply and a staleness of its own, which a string never reasons about, and the counts are the evidence for promoting it |
| What is in use is narrowed to findings the asker may read | Free text typed during an embargo says what it is about: "waiting on the reporter" beside an undisclosed issue is the disclosure |
| The grain is one issue, in one fold, in one product | The unit a decision covers and the finding screen shows. A kernel flaw at sixty occurrences is one thing being labeled, and a label is about the work, not a release |
| Put on, read and taken off across the fold | Putting one on writes it on every package of the fold the product holds the issue at. The screen, a list row and the filter read the words on any package of the fold, once each, so a package joining the fold carries them. Taking one off through any package takes it off all |
| Each package's word at that package's visibility | Putting on and taking off reach the packages whose findings of the issue the caller may triage. A word is read where its package carries a finding of the issue in the product the reader may see; the filter asks at the row's visibility. A word on an undisclosed package is not shown through a disclosed one |
| Matched regardless of capitals and shown as typed; labeling what already carries the label succeeds and keeps the first spelling | The folded form shown back reads as the tool rewriting somebody's words |
| Labeling is triage; a reader sees labels and is not offered the control | A label changes what a filtered list answers |
| On the row: each group's labels are read for the page in one statement, and each is a filter | |
| Called a label in every register | One thing under two names makes neither searchable |

## Limits

| Limit | Detail |
|---|---|
| Nothing under a finding carries a visibility of its own (REQ-40) | `design-docs/triage-approval.md` § Rights holds the rule |
