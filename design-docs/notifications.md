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

The rest of the area:

| Document | Holds |
|---|---|
| `design-docs/notifications-alerts.md` | Operational alerts: new criticals, sharp inventory moves, analyzer alerts, reports that must come back empty, absent holders |
| `design-docs/notifications-work.md` | Notices about work: decisions, code findings, staleness, reports, the digest, embargoes, response windows |
| `design-docs/notifications-delivery.md` | What a message may carry, sweeps, mail, outbound HTTP |
| `design-docs/notifications-chat.md` | Slack and Zulip |
| `design-docs/notifications-measurements.md` | Benchmark runs |

## Events and conditions

| Kind | Ends when | Examples |
|---|---|---|
| Event | The person acknowledges it | You were assigned this; your decision was sent back; somebody named you |
| Condition | It stops being true | A build stopped being scanned; a decision is waiting for approval |

A condition names what it is about. The pass deriving conditions reconciles:
what is true is opened, what stopped being true is cleared, and running it twice
changes nothing (REQ-49).

| Rule | Reason |
|---|---|
| Derived every sweep, never remembered | Otherwise every path that approves, withdraws, sends back or lapses a decision must clear a notification, and the one that forgets tells somebody about finished work |
| A condition that returns is a new row | "Cleared, then came back" stays visible |
| Acknowledging a condition hides it, never resolves it, and the screen shows the difference | The thing is still true; somebody may have decided to live with it |
| A standing condition states what is true now | Its sentence carries a count. The row stays and its sentence, link, undisclosed mark, product and issue are restated, because every read narrows by those |
| Everybody holding a condition is handed a list each sweep, even an empty one | A condition clears only by being left off a list, so a demoted administrator would go on being told |
| Somebody holding none of a kind and found none is not reconciled for it | Reconciling is a transaction per person per kind |
| A reconcile writes a batch of rows a statement, choosing each restated row's column values by its identifier | Opening 152,859 conditions for 204 people took about 700 s a row at a time and 7 to 8 s a batch at a time (`design-docs/notifications-measurements.md` § Reconcile batches) |
| Who may do what is read once per sweep | Every condition reads the same people and grants |
| A role across every product counts in every audience as a role on each product | Per-product grants alone treat an estate reader as nobody (`design-docs/access.md` § A role across every product) |

## Triggers and kinds

| Trigger | Kind | Notes |
|---|---|---|
| Work arriving | event | The category worth interrupting somebody for |
| A decision sent back | event | It sits in its author's queue otherwise unannounced |
| Somebody named you | event | § Mentions |
| An agreement taken back | event | A reviewer undoing a bulk approval, or an exploitation record returning a decision that sets it aside to the queue, which reaches somebody outside the exchange |
| A decision the code moved under | event | It hands work back to somebody who did nothing |
| A merge meeting two answers that disagree in one product | event | `design-docs/notifications-work.md` § Decision outcomes |
| An approval an edit withdrew | event | To everybody whose agreement a revised reasoning or moved promise took back, once each, never to the editor (REQ-24, REQ-28) |
| A build that stopped being scanned | condition | A sweep derives every declared build with when it was last scanned |
| An embargo whose date arrived | condition | Reaching the date discloses nothing (REQ-37). Clears when the date moves or the finding is disclosed |
| An embargo date approaching | condition | `design-docs/notifications-work.md` § Embargo notices |
| A decision waiting for a second person, or a ruling on reports waiting | condition | To whoever may approve it, never its proposer |
| A decision sent back and not revised | condition | An event cannot report it has since been ignored |
| A deferral running out | condition | Before the date; after it the finding returns as late work |
| Work sitting in a team queue | condition | Per team and product, with a count |
| Open reports in a team queue | condition | Apart from findings, to members who read the product's reports, because a report is undisclosed and folded in would withhold the whole count from a disclosed-only reader |
| Somebody away still holding work | condition | `design-docs/notifications-alerts.md` § Absent holders |
| A VEX publisher revising a cited statement | condition | `design-docs/notifications-work.md` § Embargo notices |
| A report received and not acknowledged | condition | To the report's audience. Clears when the first message sent to the reporter is recorded |
| A report given to you | event | To its assignee, unless they assigned it, only where they read the product's reports. Never to a team. Undisclosed |
| A reporter writing back | event | A message recorded as received, to the report's audience but its recorder. Undisclosed |
| A message sent to a reporter | event | A message recorded as sent, to the audience but its recorder. Undisclosed |
| A note on a report | event | To the audience but its author and anybody named, who get the mention instead. An edit tells only the names its new text holds. Undisclosed |
| An issue somebody holds disclosed | event | To every holder of an occurrence but whoever made it public, with the issue's detail. `design-docs/access.md` |
| Somebody brought onto one case | event | The grant is all they may reach, so the notice is how they learn of it. Described under case collaborators |
| Somebody granted one code finding recorded as a flaw | event | `design-docs/analysis.md` § Code finding collaborators |
| An upload that changed much of a build | event | `design-docs/notifications-alerts.md` § An inventory that moved sharply |
| Analyzer drops, an incomparable newest run, a series gone quiet | event, condition, condition | `design-docs/notifications-alerts.md` § Analyzer alerts |
| A code finding assigned, recorded as a flaw, included in or taken out of disclosure, or returned to the queue by a withdrawn dismissal; a suppression rule outgrowing its approval | events; condition | `design-docs/notifications-work.md` § Code finding notices |
| A response window running, near its end, passed | condition | `design-docs/notifications-work.md` § Response window notices |

The report's audience is `design-docs/notifications-work.md` § Report audience.

| Rule | Reason |
|---|---|
| A new build notifies nobody | Arriving is the ordinary state of a nightly scan; what it changed is on the receipts and the trend |
| Approval notifies nobody | It is what the proposer asked for |
| Work handed back because its holder stopped reading it notifies nobody, as no hand-back does (`design-docs/access.md` § Lost reading) | It leaves the holder's counts, the absence alert and their digest next sweep, and waits unassigned |

## The in-application area

The channel that always exists, so a deployment that never configured mail still
hears its operational alerts. Everybody has one: a triager sees work arriving, a
proposer a decision sent back, an approver what waits on them, an administrator
that the tool is unwell. Role changes the content, not the mechanism.

## Links

Every notification carries a link into the interface, built in one place, one
builder per destination.

| Rule | Reason |
|---|---|
| An address spelled by hand elsewhere in the server fails a test | Nothing holds a hand-built link to the interface's routes |
| Every builder is called with names holding every separator, and each result is matched against the interface's route table, query parameters included (`design-docs/interface.md` § The route table) | A builder added without a sample fails the same test |
| Each part is escaped for where it lands: a path segment as one, a query value as one | A name holding a slash opens another screen |
| A part of dots alone yields the front page; builders are also called with "." and "..", and the route check refuses a segment of dots | A browser resolves dot segments before sending, encoded or not |
| A private notification's message carries the front page, from the same builders | `design-docs/notifications-delivery.md` § Outbound content |

## Mentions

A name after an `@` is resolved when the text is saved, and whoever it names is
told at once.

| Rule | Reason |
|---|---|
| Only somebody who could already read it, from the query the editor's autocomplete uses | On an undisclosed finding the notification is the disclosure |
| An unheld name and one held by a non-reader are not distinguished | Both reach nobody; a refusal saying which answers who can see undisclosed work |
| Never the author | |
| Never a failure of the write | The words are on record first |
| Plain `@ana` where the name is letters, digits and `. _ : @ -`, starting and ending with a letter or digit; delimited `@\<ana+psirt@example.com>` otherwise | The plain form stops at the first other character, so `ana+psirt@example.com` or `auth0\|abc` would name somebody else. The backslash keeps markdown from reading a tag or address. The editor writes whichever the identity needs, and `@<…>` is read too where markdown leaves it text or links it |
| Inside the brackets a backslash escapes the next character, and the editor escapes ``\ < > * _ ` [ ] ~`` | A `>` ends the brackets early, and `_svc_` reads as emphasis and splits the run |
| A run of text is read whole | The parser splits runs at will, cutting a name holding a space |

## Dates and times

The text is composed once for every channel, so these hold everywhere.

| Rule | Reason |
|---|---|
| A day is the UTC day a moment falls on | One moment is one day to every reader whatever the server's zone, and the day the interface shows (`design-docs/interface.md`) |
| A time within a day is to the minute in UTC, and says UTC | A response window ends at an hour, and a zoneless time reads as local |

## The notification list

Narrowed in the data-access layer with a subject, like every read (REQ-42 and
REQ-43); the list and its badge go through one set of conditions. A row stays
readable while the reason it was sent holds, because a notification is a message
addressed under a rule, and the audiences those rules name are what a later read
asks about.

| A row is readable when | Because |
|---|---|
| It is about nothing undisclosed | No rule narrows it |
| It names a product where this person reads undisclosed work now | The role is why it arrived, so withdrawing the role takes it away |
| It is about internal work, in a product where they read internal work now | An undisclosed reader reads no internal finding |
| It names an issue they were brought onto, one case at a time | Widened to the product, a case grant hands over its embargo list |
| It is about a code finding recorded as a flaw they were granted, one at a time | That grant is a product and an occurrence, and the line granting it is the one line it reaches |
| They administer the deployment | The embargo notice names administrators as an audience; an administrator grants roles, so this hands them nothing new |

| Rule | Reason |
|---|---|
| Rows are filtered, never deleted, and granting a role back returns them | The record that somebody was told is what an auditor wants after a leak, and there is more than one way to lose a role |
| A row marked private carries its product, or the write is refused; a row about internal work is marked private | A private row attributable to nothing shows to everybody or nobody; refused, it fails at the producer |
| The product and the issue are columns | A read never narrows by a shape parsed from a digest's match string |
| Reading a list addressed to somebody else is an administrator's act alone, refused in the store | It exists to investigate a leak |
| That read includes read and cleared rows | The question is what was sent |
| That read is narrowed by the products the asker holds a role on: disclosed rows in any, undisclosed where they read undisclosed work, issues a case grant names; nothing about no product or an unheld one, count included | The flag decides who may ask, not what is seen. Granting themselves the product lands in the administrative record, which this read does not |
| The badge count goes through the same conditions as the list | A badge disagreeing with its list is a total ignoring a filter |

## Ownership of a notification

| Rule | Reason |
|---|---|
| Reading and acknowledging check whose a notification is; another's answers as one that does not exist | The identifier is a caller-supplied number |
| The subject kind is checked, never inferred | Key and person identifiers come from different tables and collide; a test gives a key the person's own number |
| The body is stored, not derived on read | It describes a moment, and the finding may since have moved |

## Not built

| Not built | Detail |
|---|---|
| Teams and Google Chat | `design-docs/notifications-chat.md` § Chat says what each needs |
| A message when a rule assigns work to a team | It arrives without a notification; the team channel hears through the queue condition |
| The HTML part of a mail | Every body is server-composed text, so the part would be that text escaped with the link as an anchor; a renderer is needed only for typed notes, which mail does not carry |

## Limits

| Limit | Detail |
|---|---|
| Events are not collapsed | Assigned the same finding twice is two things that happened |
| A report's watchers are its audience, with no list of their own | Nobody joins or leaves a report except by who holds it. Findings and code findings have no watch list |
