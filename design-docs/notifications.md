# Notifications

What a notification is, what triggers one, the area inside the application, and
who may read a notification afterwards.

Satisfies REQ-24, REQ-28, REQ-37, REQ-42, REQ-43, REQ-49.

## Contents

- [Events and conditions](#events-and-conditions)
- [Triggers and kinds](#triggers-and-kinds)
- [The in-application area](#the-in-application-area)
- [Links](#links)
- [Mentions](#mentions)
- [Dates and times](#dates-and-times)
- [The notification list](#the-notification-list)
- [Ownership of a notification](#ownership-of-a-notification)
- [Not built](#not-built)
- [Limits](#limits)

| Document | Holds |
|---|---|
| `design-docs/notifications-alerts.md` | New criticals, sharp inventory moves, analyzer alerts, reports that must come back empty, absent holders |
| `design-docs/notifications-work.md` | Decision outcomes, code findings, staleness, reports, the digest, embargoes, response windows |
| `design-docs/notifications-delivery.md` | What a message may carry, sweeps, mail, outbound HTTP |
| `design-docs/notifications-chat.md` | Slack and Zulip |
| `design-docs/notifications-measurements.md` | Benchmark runs |

## Events and conditions

| Kind | Ends when | Examples |
|---|---|---|
| Event | The person acknowledges it | You were assigned this; your decision was sent back; somebody named you |
| Condition | It stops being true | A build stopped being scanned; a decision is waiting for approval |

A condition names what it is about. The pass deriving conditions reconciles:
what is true is opened, what stopped being true is cleared, and a second run
changes nothing (REQ-49).

| Rule | Reason |
|---|---|
| Derived every sweep, never remembered | Otherwise every path that approves, withdraws, sends back or lapses must clear it, and one forgets |
| A condition that returns is a new row | "Cleared, then came back" stays visible |
| Acknowledging a condition hides it, never resolves it, and the screen shows which | The thing is still true |
| A standing condition's sentence, link, undisclosed mark, product and issue are restated each sweep on the same row | Its sentence carries a count, and every read narrows by those |
| Everybody holding a condition is handed a list each sweep, even empty | A condition clears only by being left off, so a demoted administrator would go on being told |
| Somebody holding none of a kind and found none is not reconciled for it | Reconciling is a transaction per person per kind |
| A reconcile writes a batch of rows a statement, choosing each restated row's values by its identifier | A row a statement is about a hundred times slower (`design-docs/notifications-measurements.md` § Reconcile batches) |
| Who may do what is read once per sweep | |
| A role across every product counts in every audience as a role on each product | `design-docs/access.md` § A role across every product |

## Triggers and kinds

| Trigger | Kind | Notes |
|---|---|---|
| Work arriving | event | |
| A decision sent back | event | It sits in its author's queue unannounced otherwise |
| Somebody named you | event | § Mentions |
| An agreement taken back | event | A reviewer undoing a bulk approval, or an exploitation record returning a decision that sets it aside to the queue, which reaches somebody outside the exchange |
| A decision the code moved under | event | It hands work back to somebody who did nothing |
| A merge meeting two answers that disagree in one product | event | Two decisions at one occurrence, two rating claims, or two incidents dated differently. `design-docs/notifications-work.md` § Decision outcomes |
| An approval an edit withdrew | event | To everybody whose agreement a revised reasoning or moved promise took back, once each, never the editor (REQ-24, REQ-28) |
| A build that stopped being scanned | condition | Derived for every declared build from when it was last scanned |
| An embargo whose date arrived | condition | Reaching the date discloses nothing (REQ-37). Clears when the date moves or the finding is disclosed |
| An embargo date approaching | condition | `design-docs/notifications-work.md` § Embargo notices |
| A decision, or a ruling on reports, waiting for a second person | condition | To whoever may approve it, never its proposer |
| A decision sent back and not revised | condition | An event cannot report being ignored |
| A deferral running out | condition | Before the date; after it the finding returns as late work |
| Work sitting in a team queue | condition | Per team and product, with a count |
| Open reports in a team queue | condition | Apart from findings, to members who read the product's reports; folded in, an undisclosed report withholds the whole count from a disclosed-only reader |
| Somebody away still holding work | condition | `design-docs/notifications-alerts.md` § Absent holders |
| A VEX publisher revising a cited statement | condition | `design-docs/notifications-work.md` § Embargo notices |
| A report received and not acknowledged | condition | To the report's audience. Clears when the first message sent to the reporter is recorded |
| A report given to you | event | To its assignee unless they assigned it, only where they read the product's reports. Never a team. Undisclosed |
| A reporter writing back; a message sent to a reporter | event | To the report's audience but whoever recorded it. Undisclosed |
| A note on a report | event | To the audience but its author and anybody named, who get the mention. An edit tells only names its new text holds. Undisclosed |
| An issue somebody holds disclosed | event | To every holder of an occurrence but whoever made it public, with the issue's detail. `design-docs/access.md` § Issue disclosure |
| Somebody brought onto one case | event | The grant is all they reach, so the notice is how they learn of it. `design-docs/access.md` § Case collaborators |
| Somebody granted one code finding recorded as a flaw | event | `design-docs/analysis.md` § Code finding collaborators |
| An upload that changed much of a build | event | `design-docs/notifications-alerts.md` § An inventory that moved sharply |
| Analyzer drops; an incomparable newest run; a series gone quiet | event; condition; condition | `design-docs/notifications-alerts.md` § Analyzer alerts |
| Code finding assigned, recorded as a flaw, in or out of disclosure, or returned by a withdrawn dismissal; a suppression rule outgrowing its approval | events; condition | `design-docs/notifications-work.md` § Code finding notices |
| A response window running, near its end, passed | condition | `design-docs/notifications-work.md` § Response window notices |

| Silent | Reason |
|---|---|
| A new build | Arriving is the ordinary state of a nightly scan |
| An approval | It is what the proposer asked for |
| Work handed back because its holder stopped reading it, as any hand-back (`design-docs/access.md` § Lost reading) | It leaves their counts, the absence alert and their digest next sweep, and waits unassigned |
| Being unassigned | Removal is no act directed at the holder |

## The in-application area

The channel that always exists, so a deployment without mail still hears its
alerts. Everybody has one; role changes the content, not the mechanism.

## Links

Every notification carries a link into the interface, built in one place, one
builder per destination.

| Rule | Reason |
|---|---|
| An address spelled by hand elsewhere in the server fails a test | |
| Every builder is called with names holding every separator, and each result is matched against the interface's route table, query parameters included (`design-docs/interface.md` § The route table) | A builder added without a sample fails the same test |
| Each part is escaped for where it lands: path segment or query value | A name holding a slash opens another screen |
| A part of dots alone yields the front page; builders are also called with "." and "..", and the route check refuses a segment of dots | A browser resolves dot segments before sending, encoded or not |
| A private notification's message carries the front page, from the same builders | `design-docs/notifications-delivery.md` § Outbound content |

## Mentions

A name after an `@` is resolved when the text is saved, and whoever it names is
told at once.

| Rule | Reason |
|---|---|
| Only somebody who could already read it, from the editor's autocomplete query | On an undisclosed finding the notification is the disclosure |
| An unheld name and one held by a non-reader are not distinguished | Otherwise it answers who can see undisclosed work |
| Never the author; never a failure of the write | |
| Plain `@ana` where the name is letters, digits and `. _ : @ -`, starting and ending with a letter or digit; delimited `@\<ana+psirt@example.com>` otherwise | The plain form stops at the first other character, so `ana+psirt@example.com` or `auth0\|abc` names somebody else. The backslash keeps markdown from reading a tag. `@<…>` is read too where markdown leaves it text or links it |
| Inside the brackets a backslash escapes the next character, and the editor escapes ``\ < > * _ ` [ ] ~`` | A `>` ends the brackets early; `_svc_` reads as emphasis |
| A run of text is read whole | The parser splits runs, cutting a name holding a space |

## Dates and times

Composed once for every channel.

| Rule | Reason |
|---|---|
| A day is the UTC day a moment falls on | One moment is one day everywhere, the day the interface shows (`design-docs/interface.md`) |
| A time within a day is to the minute in UTC, and says UTC | A response window ends at an hour |

## The notification list

Narrowed in the data-access layer with a subject (REQ-42 and REQ-43). A row stays
readable while the reason it was sent holds, read against the audiences its rule
names.

| A row is readable when | Because |
|---|---|
| It is about nothing undisclosed | |
| It names a product where this person reads undisclosed work now | The role is why it arrived |
| It is about internal work, where they read internal work now | An undisclosed reader reads no internal finding |
| It names an issue they were brought onto, one case at a time | Widened to the product, a case grant hands over its embargo list |
| It is about a code finding recorded as a flaw they were granted | That grant reaches its one line |
| They administer the deployment | The embargo notice names administrators, who grant roles anyway |

| Rule | Reason |
|---|---|
| Rows are filtered, never deleted; a role granted back returns them | That somebody was told is what an auditor wants after a leak |
| A private row carries its product or the write is refused; a row about internal work is private | Unattributable, it shows to everybody or nobody |
| The product and the issue are columns | Never parsed from a digest's match string |
| Reading another person's list is an administrator's act alone, refused in the store | It exists to investigate a leak |
| That read includes read and cleared rows, and is narrowed by products the asker holds a role on: disclosed rows in any, undisclosed where they read undisclosed work, case-granted issues; nothing about no product or an unheld one, count included | Granting themselves the product is recorded; this read is not |
| The badge goes through the same conditions as the list | |

## Ownership of a notification

| Rule | Reason |
|---|---|
| Reading and acknowledging check whose it is; another's answers as nonexistent | The identifier is caller-supplied |
| The subject kind is checked, never inferred; a test gives a key the person's own number | Key and person identifiers collide |
| The body is stored | It describes a moment |

## Not built

| Not built | Detail |
|---|---|
| Teams and Google Chat | `design-docs/notifications-chat.md` § Chat says what each needs |
| A message when assignment, by hand or by rule, gives work to a team | A team's channel hears through the queue condition alone |
| The HTML part of a mail | It would be the composed text escaped, with the link as an anchor; a renderer is needed only for typed notes, which mail does not carry |

## Limits

| Limit | Detail |
|---|---|
| Events are not collapsed | Assigned the same finding twice is two things that happened |
| A report's watchers are its audience | Nobody joins or leaves a report but by who holds it. Findings and code findings have no watch list |
