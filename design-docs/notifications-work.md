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

Approval stays silent; the gap is closed by a view recording outcomes, asked by
a statement of its own rather than the queue with a filter. A queue of pending
work shows approved, withdrawn, lapsed and undone alike, as a row vanishing.

The word is read from a decision's rows every time, because a decision has no
state of its own and a stored word needs every path to update it. Seven words:

| Word | Meaning |
|---|---|
| Waiting, sent back, approved, withdrawn, lapsed | As named |
| Undone | Waiting again after somebody had agreed, which the proposer may find surprising |
| Several ways | An approver agreed to most of a bulk set and set some aside |

An undo and a lapse each notify: an undo reverses what the proposer relied on,
and a lapse hands work back with a decision out of force. Both are wired at the
deployment, never inside the scan, which reads what was ingested.

| Lapse message | Reason |
|---|---|
| One per person per sweep, counting their rows, gathered over every bounded batch | A version bump lapses many at once, and one message a decision is a channel nobody reads |
| A sweep failing part way still tells | Earlier batches are committed |
| Says why: the code moved, or the issue was rated worse | They ask different things of the re-affirmer (`design-docs/triage.md` § Lapse marking) |
| Links to the review queue's To reaffirm tab | The work is every lapsed decision, not one of three hundred |
| Sent by the scan's sweep and by a rating put in or out of force here | The two places a proposer's own work comes back |

A merge ending one of two answers in a product tells the product's triagers,
never whoever made it (`design-docs/findings-issues.md` § Merged issues holds the
merge).

| Merge message | Reason |
|---|---|
| Only where the two differ: another outcome, rating or date of attack | Two that agree collapse to one and nothing read changes |
| To everybody who triages the product: privately where either decision is private, and for a rating claim or incident unless a finding of the issue there is disclosed | The tool chose between two answers by standing, so the product looks. It names both issues, so it is as private as the more private |
| Names both issues and the product, linking to the standing decision, or for the other two to the issue | Where the ended one is compared |
| Sent by the merging scan once applied, to each person in turn | One person not told leaves the rest told |

## Code finding notices

A decision on a code finding is told on every other decision's terms: waiting,
sent back and left, rows set aside, lapsed, an agreement an edit took back, an
agreement taken back with its batch, and a mention in its notes. Each line is
withheld as internal (`design-docs/notifications.md` § The notification list).

| Notice | Kind | To | Clears |
|---|---|---|---|
| A decision waiting for a second person | condition | Whoever may approve at internal visibility, approver capability and `internal-read`, never its proposer | Approved, sent back or withdrawn |
| A decision sent back and left | condition | Its author, while they read internal work | Revised or withdrawn |
| A dismissal lapsed by a probable pairing | event | Its proposer, once per run after it commits | Acknowledged |
| An agreement taken back by an edit | event | Every approver whose agreement it was | Acknowledged |
| A code finding recorded as a flaw | event | The product's internal triagers but the recorder. The flaw tells what any recorded flaw tells | Acknowledged |
| Included in its flaw's disclosure, or taken back out | event | The internal triagers but whoever did it | Acknowledged |
| An agreed dismissal or not-a-security-issue ruling withdrawn, returning it to the queue | event | The internal triagers but whoever withdrew it | Acknowledged |
| A code finding assigned | event | The assignee, while they read it at every visibility it is open at. Never a team, never the assigner, nobody for a hand-back | Acknowledged |
| A suppression rule outgrowing its approval | condition | Whoever may approve at internal visibility, never its proposer | Approved again at its size, retired, or narrower |
| A suppression rule waiting for approval | condition | The same, once it has waited a decision's waiting period | Approved or retired |
| Code findings in a team's queue | condition | Members reading the product's internal work, after the queue period | Taken, judged, recorded as a flaw or closed |

| Rule | Reason |
|---|---|
| A decision's rows are counted at three visibilities, and its audience reads or approves at each | An undisclosed reader reads no internal row |
| A code finding sent back links to the code finding | A rule names no finding page |
| Agreeing to a dismissal tells nobody; withdrawing tells only where it was agreed | A withdrawal returns work, and an unagreed dismissal never removed it |
| A flaw record or inclusion names no flaw, and its link answers the flaw to whoever may read it | An internal triager reads nothing of an internal-only code finding's case (`design-docs/analysis.md` § Disclosure inclusion) |
| An assignment names the rule, path and line, and the build it was assigned from, and is withheld as internal while open at internal visibility | It names no more than the page |
| A waiting suppression rule is one condition per rule | It dismisses nothing while waiting, and one approval answers all it names |
| Queued code findings count one per occurrence per team and product, apart from other queued work, naming the team | A code finding is one piece of work at its occurrence (`design-docs/kinds.md` § Consumers); apart, a disclosed-only member hears nothing internal |
| A code finding a decision stands on, or recorded as a flaw, is not waiting | |
| Team assignment reaches a code finding notice through the queue alone | A flaw record, inclusion or assignment is one act told to the table's people; a series alert concerns no team |

## Staleness conditions

These report that no event occurred, which nothing driven by an act can do.

| Condition | Told to | Period |
|---|---|---|
| A decision waiting for approval | Whoever may approve every occurrence it covers: approver capability or triage at each visibility, over reading all of them. Never its proposer | Its own setting: somebody else's turn |
| A ruling on reports waiting for approval | Under the report rule: approver capability or triage of undisclosed work, over reading it, never its proposer. One per ruling, linking to the product's reports narrowed to what waits. Undisclosed | The decision's, since it is the same act |
| A deferral whose end approaches | The proposer | Its own: enough warning to redo the work |
| A decision sent back and untouched | The proposer | Its own: the author's turn |
| Work sitting in a team queue | The team; code findings to members reading internal work (§ Code finding notices) | Its own: nobody's turn |
| A report nobody has answered | The report's audience (§ Report audience) | None: never acceptable |
| A claim nobody has judged | The report's audience. Carries the reference it was minted with and points at the report | None |

| Rule | Reason |
|---|---|
| A sent-back decision and an ending deferral link to the review queue narrowed to the reader's own decisions | The approver queue leaves those out |
| Every queue link asks only for narrowings the queue reads; another opens it on its default | |
| A ruling answers what a claim is, not the reporter, so a rejected report with no message sent is still unanswered | |
| A report about an issue long closed stops being raised; an unjudged claim is raised until answered | One is history; the other has no issue to close |
| Each is bounded by what the person may read | An alert is no way back in |
| Team queue work is raised | Assigned to a team, it looks handled and is not |
| Only a deferral in force is announced, by the test the compliance rate and outcome filter use | Each clause is false of a deferral still waiting |
| Sitting still means undecided: no decision standing at the versions the code holds now, by the findings list's expression | |
| The queue is counted per team and product, in issues in a component whatever their visibility, undisclosed where any occurrence is; the others per decision | One rule places thousands of findings; a decision is one act however many rows |

## Report audience

Who hears about a vulnerability report turns on who holds it.

| Holder | Told |
|---|---|
| A person | That person, where they read the product's reports |
| A team's queue, unclaimed | Its members who read the product's reports |
| Nobody | Everybody who may triage undisclosed work in the product |
| A person or queue nobody here can tell | As nobody: one who left or no longer reads the reports, or a queue with no reading member |

The unanswered condition, a reporter writing back, a message sent and a note all
use it, and everybody told may open the report.

## Work arriving by rule

Digest content, never an interruption (REQ-47): immediate mail is for explicit
human acts, and a rule's message reports no act and asks no reply. It adds no
switch to the digest, and an undisclosed arrival contributes a number and no
name.

## The digest

Everything else leaves at once, so the digest carries only what nothing else
told the reader:

| Content | Detail |
|---|---|
| Work that became yours without a message | Assigned to yourself, when nothing could send, or before you had an address |
| Findings nobody owns | For whoever asks |
| Vulnerability reports in your teams' queues | A count, never a name; a rule placing a report tells nobody else |

Both switches are off by default and derived from no role, since a role says
what somebody may do, not what they want to read.

| Rule | Reason |
|---|---|
| Assembled as its reader | Every query narrows by the subject; the sweep holds no rights |
| Nothing is repeated: an event records what it was about, apart from a condition's uniqueness key | The key would deduplicate two unrelated events |
| It pages past what it already said | Filtering one page leaves a holder with a page of told items an empty digest, and rule-assigned work is named nowhere else |
| An empty digest is not sent, and the clock moves | A daily "nothing" stops people opening it; an unmoved mark reports a quiet week as new |
| A digest that cannot be assembled moves the clock | Tried tomorrow, as a refusing mailbox is, so it crowds out no reader |
| A first digest reports nothing under "nobody owns" | There is no "since" |
| "Nobody owns" is about the assignee alone, including proposals and pending approvals | 8,400 rows against 7,471 on one real build. The screen asking the same narrows its own list instead |
| One message is bounded and says how many of how many it lists | Otherwise fifty of four hundred reads as fifty |
| Disclosed findings are named with issue, component and build; undisclosed become counts by severity, known exploited and unowned, naming nothing, the product included | A bare count says not whether to open the tool now; the aggregate protects the path, not the recipients (REQ-48) |
| Lateness is excluded | A passed embargo raises its own alert |

## Embargo notices

An embargo running out is announced before its date (REQ-38), at a lead time
set by the deployment, two weeks by default, inside the application, because
mail may not name an undisclosed issue.

| Rule | Reason |
|---|---|
| Two conditions: approaching and arrived | One alert would keep saying "coming" past the date. Approaching clears when the date arrives, opening the other, or when the date moves past the lead time |
| One per occurrence the finding sits at | The link and the holder are per occurrence |
| A condition naming several names is keyed by each name with its length | Two name sets joining to one text are two conditions |
| The approaching notice says extending needs a second person and takes time | It is why the warning is early |
| To administrators and to whoever holds it, the second only while they read undisclosed work in the product | An assignment outlives the role that allowed it |
| A VEX publisher revising a cited statement raises an alert | The decision stands, but a dismissal was approved on that evidence |
| "Cited" is recorded: a decision started from a statement carries which | Inferred from issue and component, every decision a publisher spoke near would alert |

## Response window notices

A window a deployment declares runs from an incident saying its product was
attacked, from the first notice for the window it counts from, or from the
release of a fix the record names (REQ-77). `design-docs/incidents.md` holds the
windows and notices; this is what is said.

| Rule | Reason |
|---|---|
| Three conditions: running, near its end, passed | They clear differently. Running and near clear when the end arrives, and passed opens |
| Worked out from the shelf, read once per sweep for all three | The shelf and the conditions agree on each moment |
| Running is raised from the moment the window starts | Windows are a day to a fortnight and incidents rare |
| A window waiting on another window's notice raises nothing until it is recorded | It has no end to say |
| A window counting from the fix raises nothing until a stated release date of a named tag has come | |
| Near is raised at the warning the window names, beside running, and not at all without one | |
| Only for a product the window applies to | |
| One per incident and window | Each is answered separately |
| Cleared by a notice naming the window, clearing the incident, or retiring the window; nobody dismisses it | |
| To whoever may triage the product, at the issue's visibility | They record the notice. What leaves about an undisclosed issue is a link |
| No window declared, nothing said | None ships |
| The sentence says the time, what the window counts from, and that nothing is recorded | Whether anybody owed anything is not the tool's to say |

## Limits

| Limit | Detail |
|---|---|
| Every period here is a setting, apart from an unanswered report's | `design-docs/analytics.md` § Settings lists them |
