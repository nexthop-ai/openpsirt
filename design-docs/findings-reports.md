# Vulnerability reports

A report is the record that a reported problem arrived. It stands whether or not
the problem turns out to be a flaw, because receiving and answering it is the
evidence. A public intake form is out of scope; this is the inside half.

Satisfies REQ-24, REQ-27, REQ-28, REQ-37, REQ-85.

## Contents

- [Reports](#reports)
- [Report references](#report-references)
- [Three roles](#three-roles)
- [The case](#the-case)
- [Judgment](#judgment)
- [Report visibility](#report-visibility)
- [Dispositions](#dispositions)
- [Limits](#limits)

## Reports

| Rule | Reason |
|---|---|
| A report exists without an issue | Whether it is a flaw is decided afterwards |
| It carries the reported problem; empty is refused at recording and every edit | A report of only who wrote in is unanswerable. A report written with a hand-recorded flaw carries the flaw's summary |
| It may carry a one-line title | A mailed report has a subject at best |
| Everything about the reporter is optional | Anonymous is ordinary; a flaw found here has no reporter |
| It says whether it was found here | That decides the disclosure date and whether an answer is owed, nothing else |
| One row per issue, never per finding | One person's address is not copied per build |
| **It records the product it was reported against, which decides who reads it** | An issue spans products once a CVE is recorded; a reporter's details stay with the product they wrote to, and a message in one product answers nobody in another |
| A merged issue answers each product with its own report: the first received the reader may read | A message on what nobody here may read is refused as no such report |
| Credit preference is apart from the reported name | "Anonymous" and a handle are real answers |
| The received date starts the embargo (REQ-37), falling back to when recorded; an unreadable date is none | A report found here starts none |
| The acknowledgement is the first message recorded as sent; its day and recorder are the acknowledged date and who | Derived, so they cannot disagree. The unanswered condition fires at once and clears when one is recorded |
| The reported problem goes through the submission policy (REQ-67) | It is outsider text rendered as markdown |

The upgrade gives every report v0.10.0 left empty on a flaw recorded here that
flaw's summary; any other empty report stays empty.

## Report references

The product, `R`, the year and six random digits. The `R` keeps references and
minted flaw names apart.

| Rule | Reason |
|---|---|
| Drawn, never counted; a collision draws again in the transaction | A count discloses how many claims arrived and when |
| Matched without regard to capitals; the typed form is folded to the stored minted form | Engines compare loosely in different ways |

## Three roles

| Recorded | Written by |
|---|---|
| Who wrote it down, and when | Recording the report |
| Who answered the reporter, and when | Recording the first sent message |
| Who judged the claim, and when | Accepting it, or a ruling taking effect; for a ruling, the proposer and when they proposed |

A flaw recorded without a prior report is written down and judged in one act.

## The case

A report is worked as a case (REQ-85).

| Part | Rule |
|---|---|
| Edits | Title, reported problem and reporter details change while open: unjudged and no ruling waiting. Every replaced version is kept with who and when, numbered from one, version one the report as recorded; a no-op edit keeps nothing |
| Edits once judged | Refused; a decision is of particular words (REQ-28) |
| Correspondence | A message records direction, day and text, and may reference the report's files. Nothing is sent from here |
| Message days | Today by default; more than a day ahead is refused. A message is never edited or removed |
| Correspondence on a flaw found here | Refused; nobody outside to write to |
| Notes | Markdown by somebody working the report, editable by its author, every wording kept. A mention reaches only readers of the product's reports; an unknown name is returned unnotified, worded alike whether or not the person exists |
| After a decision | Notes and messages still accepted, readable from the issue under the report rule |
| Assignment | One person or one team's queue (`design-docs/access-assignment.md` § Assignment), only to a reader of the product's reports or a team with one. Taking or handing back needs the right to work it; giving away needs the assigner right too. A holder who stops reading gives back, and a team does where no member still reads (`design-docs/access-assignment.md` § Lost reading) |
| Assignment once judged | Refused. A report under a waiting ruling may still be handed over |
| Held lists | Open reports by holder (a person with their teams' queues, a team, or nobody), narrowed to products where the reader reads reports, or to one when asked. A team's queue is not in nobody's list |
| Assignment rules | A rule may place a product's reports, naming no package or occurrence; it places a new unheld report and sweeps open unheld ones when added. First match wins |
| Hand-over | Releasing a person's work, and an administrator's hand-over, move their open reports with their findings |
| Notices | The person given a report is told unless they gave it. Unanswered, messages and notes reach the report audience (`design-docs/notifications-work.md` § Report audience); a mentioned name gets the mention instead. Nothing leaving the deployment names the report |
| History | Every act, oldest first, assembled from the rows that hold each |

## Judgment

A report is pointed at an existing issue, or recorded as a new flaw, which also
asks builds, severity and embargo. Accepting as an existing issue reaches issues
a scan reported. A second report about a recorded flaw is a duplicate.

An outside report ruled a duplicate of a flaw found here gives the flaw a
disclosure date counted from the report's arrival (REQ-37); a flaw with a date
keeps the earlier one.

| Rule | Detail |
|---|---|
| The date is set in the ruling's own write | With the disclosure window read there |
| It counts from the earliest outside claim the ruling covers | Arrival, or recording where arrival is unstated |
| It reaches the flaw's undisclosed open occurrences in the ruling's product, where they have no date or a later one | A scanned issue's reporter counts down elsewhere |
| It is an embargo movement, act `duplicate`, naming the ruling and the claim | |
| A first date needs nobody | |
| Bringing a date earlier is a shortening, held to the movement threshold (`design-docs/access-disclosure.md` § Disclosure-date movements) | The arrival is typed by the recorder, so a ruling is no route around the control |
| Withdrawing replays the embargo record without every withdrawn ruling, in the order each movement took effect (agreed, where it waited) | Where the answer is where the embargo stands, nothing moves; otherwise the occurrences take it, possibly no date, recorded as `duplicate-undone` |
| The ruling form states the date it would set and whether it waits for a second person, asked of the server under the right to propose; nothing is shown where no date would start | |
| Duplicates ruled before rulings set dates were dated by the v0.5.0 upgrade | |

| Refusal | Reason |
|---|---|
| Already judged, asked in the write too | Two judges would both succeed |
| Another report is that issue's record | A second is a duplicate ruling |
| A ruling holds the report, asked in the write | |
| The issue is not one the judge may be told of | Resolving then refusing would map which identifiers are open |
| Recording a flaw from a report accepts the report in the same write; naming a reporter too is refused; already judged or under a ruling is refused | One report is the record |
| The judge may not work reports here, asked before any name is resolved, including a duplicate's issue and, for a non-reader, the issue whose duplicates are listed | Otherwise filed and unfiled names answer differently |

## Report visibility

An unjudged report is undisclosed: this is the **report rule**.

| Act | Asks for |
|---|---|
| Reading a report, its list, attachments, versions, correspondence, notes, history, a ruling, an issue's duplicates, held lists | The right to read undisclosed work in that product |
| Recording, editing, messaging, noting, taking or handing over, judging, attaching, proposing or withdrawing a ruling | The right to triage undisclosed work there |
| Agreeing to a ruling | The approver capability or that triage right, over the read right |

| Rule | Reason |
|---|---|
| Asked before any reference is resolved; a non-reader is told it is not there, a reader who may not act is refused in words | |
| Every reader, including through the issue it became | Asked as the issue's own visibility, filing hands a stranger's words to every triager of announced work |
| Judging never widens it; what should be read there is attached to the issue | `design-docs/attachments.md` § Fetch authorization |
| A reference resolves only in its own product; unminted, other-product and unreadable answer alike | |
| A case grant reaches no reports | It is about one issue |

## Dispositions

A judged report carries one of five. Accepted is written by pointing at an
issue; the rest by a **ruling**: one act, one reason, one or more reports in one
product.

| Disposition | Second person | Reason required | Meaning |
|---|---|---|---|
| Accepted | No | No | The claim is an issue here |
| Duplicate | No | No | An issue already open here, which the ruling names |
| Not reproducible | No | Yes | Nobody could make it happen |
| Out of scope | Yes | Yes | About something this product does not answer for |
| Rejected | Yes | Yes | Not a flaw |

| Rule | Reason |
|---|---|
| Rejected and out of scope wait for a second person who is not the proposer (REQ-24) | Both hide risk with nothing left to work |
| A duplicate names an issue open in this product, resolved against what the proposer may be told of | |
| Not reproducible needs nobody | The reporter is still owed an answer; a reproduction is met by withdrawing |
| A duplicate of an issue not open here is refused, telling the proposer to reject instead | Open: not closed, not suppressed by the build, not dismissed; a deferral or promised upgrade counts as open |
| Reasons go through the submission policy and are never edited (REQ-28) | Different words are a new ruling |
| A ruling is approved, sent back or undone as one act (REQ-28) | |
| Bounded by the bulk action limit, counted in reports written (REQ-27); a report named twice, or in another case, is written once | Nothing re-checks a rejection |
| Every report named is in the product and unanswered, asked in the write, or nothing is written | |
| A waiting ruling holds its reports, which read as unjudged until it takes effect | |
| Withdrawing needs nobody, reopens every covered report unanswered, and is also send-back and undo; the proposer may withdraw their own | |
| A withdrawn ruling stays on record with what it covered | |
| Rulings are read and approved under the report rule; across products, an unreadable product contributes nothing, not even to a count | |

### Duplicates on the issue

The reports ruled duplicates of an issue are listed on it with what arrived
with each, under the report rule.

### The unanswered condition

A ruling answers what a report is, not the reporter: a rejected report with no
sent message is still unanswered. A report found here is never raised.

## Limits

| Limit | Detail |
|---|---|
| A ruling carries one disposition and one reason for every report it covers | Different reasons are different rulings; splitting one is withdrawing it and proposing two |
| Accepting takes no ruling and no second person | It re-exposes risk, and the issue carries its own triage |
