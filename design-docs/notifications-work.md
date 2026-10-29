# Work notices

What a person is told about work: decision outcomes, code findings, what has sat
still, vulnerability reports, the digest, embargoes and response windows.

Satisfies REQ-24, REQ-28, REQ-38, REQ-47, REQ-48, REQ-77.

## Contents

- [Decision outcomes](#decision-outcomes)
- [Code finding notices](#code-finding-notices)
- [Staleness conditions](#staleness-conditions)
- [Report audience](#report-audience)
- [Work arriving by rule](#work-arriving-by-rule)
- [The digest](#the-digest)
- [Embargo notices](#embargo-notices)
- [Response window notices](#response-window-notices)
- [Limits](#limits)

## Decision outcomes

Approval is silent; a view records outcomes instead, asked by its own statement.
A queue of pending work shows approved, withdrawn, lapsed and undone alike, as a
row vanishing. The word is read from a decision's rows every time, because a
decision has no state of its own.

| Word | Meaning |
|---|---|
| Waiting, sent back, approved, withdrawn, lapsed | As named |
| Undone | Waiting again after somebody had agreed |
| Several ways | An approver agreed to most of a bulk set and set some aside |

An undo and a lapse each notify: an undo reverses what the proposer relied on; a
lapse hands work back. The lapse and the merge messages are wired at the
deployment, never inside the scan, because what a scan does and who hears of it
are separate.

| Lapse message | Reason |
|---|---|
| One per person per sweep, counting their rows, gathered over every bounded batch | One a decision is a channel nobody reads |
| A sweep failing part way still tells | Earlier batches are committed |
| Says why: the code moved, or the issue was rated worse | They ask different things (`design-docs/triage-lapse.md` § Lapse marking) |
| Links to the review queue's To reaffirm tab | The work is every lapsed decision |
| Sent by the scan's sweep and by a rating put in or out of force here | |

A merge keeps one of two answers in a product and ends the other, and nobody
chooses which (`design-docs/findings-issues.md` § Merged issues), so the
product's triagers are told, never whoever merged.

| Merge message | Reason |
|---|---|
| Only where the two differ: another outcome, rating or date of attack | Two that agree collapse to one |
| To everybody who triages the product: privately where either decision is private, and for a rating claim or incident unless a finding of the issue there is disclosed | It names both issues, so it is as private as the more private |
| Names both issues and the product, linking to the standing decision, or for the other two to the issue | |
| Sent by the merging scan once applied, to each person in turn | One person not told leaves the rest told |

## Code finding notices

A decision on a code finding is told as any decision is: waiting, sent back and
left, rows set aside, lapsed, an agreement an edit took back, an agreement taken
back with its batch, a mention in its notes. Each line is withheld as security testing work
(`design-docs/notifications.md` § The notification list).

| Notice | Kind | To | Clears |
|---|---|---|---|
| A decision waiting for a second person | condition | Approver capability and `security-testing-read`, never its proposer | Approved, sent back or withdrawn |
| A decision sent back and left | condition | Its author, while they read security testing work | Revised or withdrawn |
| A dismissal lapsed by a probable pairing | event | Its proposer, once per run after it commits | Acknowledged |
| An agreement taken back by an edit | event | Every approver whose agreement it was | Acknowledged |
| Recorded as a flaw | event | The product's security testing triagers but the recorder; the flaw tells what any flaw tells | Acknowledged |
| Included in its flaw's disclosure, or taken out | event | The security testing triagers but whoever did it | Acknowledged |
| An agreed dismissal or not-a-security-issue ruling withdrawn, returning it to the queue | event | The security testing triagers but whoever withdrew it | Acknowledged |
| Assigned | event | The assignee, while they read it at every visibility it is open at. Never a team, never the assigner, nobody for a hand-back | Acknowledged |
| A suppression rule outgrowing its approval | condition | Whoever may approve at security testing visibility, never its proposer | Approved again at its size, retired, or narrower |
| A suppression rule waiting for approval | condition | The same, after a decision's waiting period; one per rule, since one approval answers every code finding it names | Approved or retired |
| Code findings in a team's queue | condition | Members reading the product's security testing work, after the queue period | Taken, judged, recorded as a flaw or closed |

| Rule | Reason |
|---|---|
| A decision's rows are counted at three visibilities, and its audience reads or approves at each | |
| A code finding sent back links to the code finding | A rule names no finding page |
| Agreeing to a dismissal tells nobody; withdrawing tells only where it was agreed | An unagreed dismissal never removed work |
| A flaw record or inclusion names no flaw, its link answering the flaw to whoever may read it | `design-docs/analysis-flaws.md` § Disclosure inclusion |
| An assignment names the rule, path, line and the build assigned from, withheld as security testing work while open at security testing visibility | |
| Queued code findings count one per occurrence per team and product, apart from other queued work, naming the team | `design-docs/kinds.md` § Consumers; apart, a disclosed-only member hears nothing of security testing work |
| One a decision stands on, or recorded as a flaw, is not waiting | |
| Team assignment reaches a code finding notice through the queue alone | A series alert concerns no team |

## Staleness conditions

They report that no event occurred, which nothing driven by an act can.

| Condition | Told to | Period |
|---|---|---|
| A decision waiting for approval | Whoever may approve every occurrence it covers: approver capability or triage at each visibility, over reading all. Never its proposer | Its own setting |
| A ruling on reports waiting for approval | Approver capability or triage of undisclosed work, over reading it, never its proposer. One per ruling, linking to the product's reports narrowed to what waits. Undisclosed | The decision's |
| A deferral whose end approaches | The proposer | Its own |
| A decision sent back and untouched | The proposer | Its own |
| Work sitting in a team queue | The team; code findings to members reading security testing work | Its own |
| A report nobody has answered | § Report audience | None |
| A claim nobody has judged | § Report audience, with the reference it was minted with, pointing at the report | None |

| Rule | Reason |
|---|---|
| A sent-back decision and an ending deferral link to the review queue narrowed to the reader's own decisions; a queue link asks only for narrowings the queue reads | The approver queue leaves those out |
| A rejected report with no message sent is still unanswered | A ruling answers the claim, not the reporter |
| A report about an issue long closed stops being raised; an unjudged claim is raised until answered | |
| Each is bounded by what the person may read | |
| Only a deferral in force is announced, by the compliance rate's test | Each clause is false of a waiting one |
| Sitting still means no decision standing at the versions the code holds now, by the findings list's expression | |
| The queue counts per team and product, in issues at a component whatever their visibility, undisclosed where any occurrence is; the others count per decision | One rule places thousands of findings |

## Report audience

| Holder | Told |
|---|---|
| A person | That person, where they read the product's reports |
| A team's queue, unclaimed | Its members who read the product's reports |
| Nobody | Everybody who may triage undisclosed work in the product |
| A person or queue nobody here can tell | As nobody: a holder who left or stopped reading the reports, or a queue with no reading member |

The unanswered condition, a reporter writing back, a message sent and a note use
it, and everybody told may open the report.

## Work arriving by rule

Digest content, never an interruption (REQ-47): a rule's message reports no act
and asks no reply. It adds no switch, and an undisclosed arrival contributes a
number and no name.

## The digest

It carries only what nothing else told the reader:

| Content | Detail |
|---|---|
| Work that became yours without a message | Assigned to yourself, when nothing could send, or before you had an address |
| Findings nobody owns | For whoever asks |
| Vulnerability reports in your teams' queues | A count, never a name; a rule placing a report in a queue tells nobody |

Both switches are off by default and derive from no role.

| Rule | Reason |
|---|---|
| Assembled as its reader | The sweep holds no rights |
| Nothing is repeated; an event records what it was about apart from a condition's uniqueness key | The key would merge unrelated events |
| It pages past what it already said | Filtering one page empties a full holder's digest |
| An empty digest is not sent, and the clock moves | A daily "nothing" stops people opening it |
| A digest that cannot be assembled moves the clock | It is tried tomorrow and crowds out no reader |
| A first digest reports nothing under "nobody owns" | There is no "since" |
| "Nobody owns" is about the assignee alone, proposals and pending approvals included | 8,400 rows against 7,471 on one real build; the screen narrows its own list instead |
| One message is bounded and says how many of how many it lists | |
| Disclosed findings are named with issue, component and build; undisclosed are counts by severity, known exploited and unowned, naming nothing, the product included | The aggregate protects the path, not the recipients (REQ-48) |
| Lateness is excluded | A passed embargo raises its own alert |

## Embargo notices

An embargo running out is announced before its date (REQ-38), at a lead time the
deployment sets, two weeks by default, inside the application, since mail may
not name an undisclosed issue.

| Rule | Reason |
|---|---|
| Two conditions: approaching and arrived | Approaching clears when the date arrives, opening the other, or when the date moves past the lead time |
| One per occurrence the finding sits at | The link and the holder are per occurrence |
| A condition naming several names is keyed by each name with its length | Two name sets joining to one text are two |
| The approaching notice says extending needs a second person and time | |
| To administrators and to whoever holds it while they read undisclosed work in the product | An assignment outlives its role |
| A VEX publisher revising a cited statement raises an alert | A dismissal was approved on that evidence |
| "Cited" is recorded: a decision started from a statement carries which | Inferred, every nearby decision alerts |

## Response window notices

A declared window runs from an incident saying its product was attacked, from
the first notice for the window it counts from, or from the release of a fix the
record names (REQ-77). `design-docs/incidents.md` holds the windows and notices.

| Rule | Reason |
|---|---|
| Three conditions: running, near its end, passed; running and near clear when the end arrives, and passed opens | |
| Worked out from the shelf, read once per sweep for all three | They agree on each moment |
| Running is raised from the window's start | Windows are a day to a fortnight |
| A window waiting on another window's notice raises nothing until it is recorded | It has no end |
| A window counting from the fix raises nothing until a stated release date of a named tag has come | |
| Near is raised at the warning the window names, beside running; none without one | |
| Only for a product the window applies to; one per incident and window | |
| Cleared by a notice naming the window, clearing the incident, or retiring the window; nobody dismisses it | |
| To whoever may triage the product, at the issue's visibility | They record the notice |
| No window declared, nothing said | None ships |
| The sentence says the time, what it counts from, and that nothing is recorded | Whether anybody owed anything is not the tool's to say |

## Limits

| Limit | Detail |
|---|---|
| A staleness period, where a condition has one, is a deployment setting | `design-docs/analytics.md` § Settings |
