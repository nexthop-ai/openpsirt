# Notifications

What a person is told, through which channel, and when.

Satisfies REQ-46, REQ-47, REQ-48, REQ-49.

## Contents

- [Events and conditions](#events-and-conditions)
- [What is told](#what-is-told)
- [The in-application area](#the-in-application-area)
- [Mentions](#mentions)
- [New criticals in a shipped release](#new-criticals-in-a-shipped-release)
- [Staleness conditions](#staleness-conditions)
- [Absent holders](#absent-holders)
- [Work arriving by rule](#work-arriving-by-rule)
- [Claim outcomes](#claim-outcomes)
- [The digest](#the-digest)
- [What leaves the deployment](#what-leaves-the-deployment)
- [Reading what you were told](#reading-what-you-were-told)
- [Delivery](#delivery)
- [Mail](#mail)
- [Outbound HTTP](#outbound-http)
- [Embargo notices](#embargo-notices)
- [Ownership of a notification](#ownership-of-a-notification)
- [Not built](#not-built)
- [Limits](#limits)

## Events and conditions

| Kind | Ends when | Examples |
|---|---|---|
| Event | The person acknowledges it | You were assigned this; your claim was sent back; somebody named you |
| Condition | It stops being true | A build stopped being scanned; a claim is waiting for approval |

A condition names what it is about, and the pass that derives conditions
reconciles rather than appends: what is true is opened, what has stopped being
true is cleared, and running the same pass twice changes nothing.

| Rule | Reason |
|---|---|
| A condition that returns is a new row, not an edit of an old one | It makes "this cleared, then came back" visible |
| Acknowledging a condition hides it rather than resolving it | The thing it is about is still true. Worth offering because somebody may have decided to live with it, and worth distinguishing on screen |
| A standing condition states what is true now, not what was true when it opened | A condition's sentence carries a count, and the row was written once and left alone, so a queue that grew overnight reported the number it had when somebody first looked. The row stays the same row; the sentence changes |
| Derived every sweep and never remembered | The alternative needs every path that approves, withdraws, sends back or lapses a claim to clear a notification. The one that forgets leaves somebody told about work that finished a month ago |

## What is told

| Trigger | Kind | Notes |
|---|---|---|
| Work arriving | event | The category that deserves interrupting somebody for |
| A claim sent back | event | It goes straight back into its author's queue, so silence leaves it sitting |
| Somebody named you | event | A name after an `@`, resolved when the text is saved |
| An agreement taken back | event | Approval is silent because it is what the proposer asked for; an undo reverses something they were relying on |
| A decision the code moved under | event | It hands work back to somebody who did nothing to cause it |
| An approval an edit withdrew | event | **Not built.** The people who granted it should be told, so it does not quietly stop counting |
| A build that stopped being scanned | condition | A sweep derives every declared build with when it was last scanned and reconciles |
| An embargo whose date arrived | condition | Reaching the date discloses nothing (REQ-37). Clears when the date moves or the finding is disclosed |
| A claim waiting for a second person | condition | To whoever may approve it, never to its proposer |
| A claim sent back and not revised | condition | The event told them at the moment it was sent back; an event cannot report that it has since been ignored |
| A deferral running out | condition | Before the date. What follows the date is the finding arriving back as late work |
| Work sitting in a team queue | condition | Per team and product, with a count |
| Somebody away still holding work | condition | Below |
| A VEX publisher revising a cited statement | condition | Below |
| A report received and not acknowledged | condition | Prompt acknowledgment is the part of coordinated disclosure a reporter judges |
| Somebody brought onto one case | event | The grant is the whole of what they may reach, so the notice is how they learn it exists. Described where the grant is, under case collaborators |
| An embargo date approaching | condition | Before the date rather than on it, so somebody can act. Described under embargo notices below |

A new build notifies nobody. A build arriving is the ordinary state of a tool
scanned nightly. What a build *changed* is on the receipts and in the trend.

## The in-application area

The channel that always exists. A self-hosted operator who never configured mail
would otherwise have every operational alert sent into a void.

Everyone has one. A triager sees work arriving, a proposer sees a claim sent
back, an approver sees what waits on them, an administrator sees that the tool
itself is unwell. What differs by role is the content, not the mechanism.

## Mentions

A name written after an `@` is resolved when the text is saved, and whoever it
names is told at once.

| Rule | Reason |
|---|---|
| Only somebody who could already read it | From the same query the editor's autocomplete uses. On an undisclosed finding the notification would be the disclosure |
| A name nobody holds and a name held by somebody who may not read this are not distinguished | Both reach nobody. A refusal naming which would answer, one comment at a time, whether a given person can see undisclosed work |
| Never the author | They are not asking themselves a question |
| Never a failure of the write | The words are on record by the time anybody is told |

## New criticals in a shipped release

An operational alert rather than a dashboard line, outside the opt-in digest: a
category somebody has to opt in to is silent on the deployment that most needs
it.

| Rule | Reason |
|---|---|
| A condition | It clears when the finding closes or somebody answers it |
| Tags only | A critical on a branch is ordinary work in progress. Sending both would make the alert as frequent as the findings list |
| To whoever may read it and may triage it, not to administrators | This one names an issue, a component and a build. An administrator does not read a product by administering it (REQ-42), so administrators alone would disclose to people who may not read it and stay silent for the people who can act. Reading alone is not enough: interrupting somebody who cannot act is noise |

## Staleness conditions

Every other message is driven by an act. This category reports that no event
occurred, which nothing driven by an event can do.

| Condition | Told to |
|---|---|
| A claim waiting for approval | Whoever may approve it, never its proposer |
| A deferral whose end is approaching | The proposer |
| A claim sent back and untouched | The proposer |
| Work sitting in a team queue | The people on that team |

Each carries its own period, which is a setting. Four periods rather than one:
a claim waiting on a second person is somebody else's turn, one sent back is the
author's own, a deferral needs enough warning to do the work again before it
lapses, and a queue is nobody's turn at all.

Every one is bounded by what the person may read. An alert is not a way back in
to something somebody has lost the reading of.

The team queue is the one that needs stating. Work routed to a team is neither
owned nor unowned, so it sits in a gap where it looks handled and is not.

A deferral that is not in force has no end to announce. The notice states that a
date is coming, what it covers, and that the finding returns as work when it
passes — every clause false about a claim still waiting for a second person. The
sweep asks the same "is this in force" test the compliance rate and the outcome
filter ask, spelled once for all three.

Sitting still means undecided, by the same test every screen uses: a claim
standing at the versions the code holds now. The expression is shared with the
findings list.

The queue is counted per team and product; the others per claim. A claim is one
person's action and one thing to read, however many rows it wrote. A queue is a
population: one routing rule places thousands of findings in a sweep.

## Absent holders

An administrator is told when somebody has not signed in for a configured period
and still holds assigned work (REQ-45).

| Rule | Reason |
|---|---|
| Both halves are required | An account nobody has used in a month is harmless if it holds nothing. Work stuck behind somebody who is not here is the problem |
| It asks rather than acts | Long leave and having left look identical from here, and nothing detects somebody leaving |
| Never having signed in counts as absent, measured from when they were added | Otherwise an administrator adding a colleague and assigning them something raises an alert in the same breath |
| Counted in pieces of work rather than findings | "6 items" meaning 288 findings would make an ordinary absence look like a catastrophe |

## Work arriving by rule

Digest content, never an interruption. Immediate mail is for explicit human
actions, and a rule is not one: the message would report no act and ask for no
reply.

It adds no third switch to the digest. A switch per category is how a settings
screen becomes unreadable, and how every switch ends up left at its default. What
already applies still applies: an undisclosed arrival contributes a number and
not a name.

## Claim outcomes

Approval stays silent. The gap silence leaves is closed with a view rather than
more mail, and that requires the view to record outcomes — both of the queue's
tabs showed pending work, so approved, withdrawn, lapsed and undone all presented
identically, as the row disappearing.

The view carries what happened, as a separate question asked by a separate
statement rather than the queue with a filter.

A claim has no state of its own; its rows do, so the word is read from the rows
every time. A stored word would need every path that approves, withdraws, sends
back or lapses one to update it.

Seven words: waiting, sent back, approved, withdrawn, lapsed, undone, and
several ways.

| Word | Why it is distinct |
|---|---|
| Undone | Drawn apart from waiting though the claim is waiting in both, because somebody had agreed and the proposer is entitled to find that surprising |
| Several ways | An approver agreeing to most of a bulk set and setting some aside leaves a claim that is genuinely two things |

An undo and a lapse each notify. Neither is an expected outcome: an undo
reverses something the proposer was relying on, and a lapse hands the work back
having taken a judgment out of force.

The lapse message is wired at the deployment rather than inside the scan. What a
scan does and how anybody hears about it are separate concerns, and this package
reads what has been ingested, so a scanner reaching it directly would close a
cycle. It links to the decision rather than the finding, because naming the
finding needs somebody to read it as and nobody is acting.

## The digest

Everything else leaves immediately, so a daily message carrying what was left
would carry nothing — and a channel that arrives empty is one people stop
opening.

The digest carries what nothing else told the reader, and there are exactly two
of those:

| Content | Detail |
|---|---|
| Work that became yours without a message | The immediate one is not sent when somebody assigns something to themselves, when nothing could send at that moment, or when the person had no address yet |
| Findings nobody owns | For whoever asks. Somebody triaging a product wants to know what arrived; somebody who only holds their own assigned work does not |

Both switches are off by default, and neither is derived from a role. A role says
what somebody may do, not what they want to read.

| Rule | Reason |
|---|---|
| Assembled as its reader | Every query narrows by the subject it is handed. The sweep holds no rights of its own |
| Nothing is repeated | An event records what it was about, kept apart from the name a condition clears against, which is a uniqueness key and would deduplicate two unrelated events into one |
| It pages past what it has already said | Filtering one page rather than paging until enough survive gave a holder with a page's worth of already-told items an empty digest. Routed work arrives deliberately without a message, so the digest is the only place it is named |
| A digest with nothing in it is not sent, and the clock still moves | A daily "nothing" is how somebody stops opening the daily message. Leaving the mark unmoved would make a quiet week report itself as new the following Monday |
| A first digest reports nothing under "nobody owns" | There is no "since" to measure against |
| One message is bounded | What is over the bound stays in the application |

It names what has been disclosed and gives numbers for what has not. A public
finding is listed with its issue, component and build. Undisclosed ones become a
count and the figures that say how urgent they are: how many at each severity,
how many known to be exploited, how many nobody owns.

A bare count is not enough — "three undisclosed" does not say whether to open the
tool now or after coffee. **The figures name nothing, including the product.**
What the aggregate protects is not the recipients, who already hold the right to
read these, but the path the message takes to reach them.

Lateness is excluded. An embargo whose date has passed already raises an alert of
its own.

## What leaves the deployment

A message about an undisclosed finding carries no detail — that there is
something, and a link. Not the identifier, not the component, not the summary,
and not in the subject line, which a preview shows without anybody opening
anything.

| Rule | Reason |
|---|---|
| The in-application area is not held to this | Reaching a notification there means holding a credential and passing the visibility check. A message cannot re-check its reader: it sits on a mail server this deployment does not run, in an inbox, on a lock screen, and in whatever it is forwarded to |
| A disclosed finding is not held to this | The identifier, component, version and build are in the message, because that is what makes it worth opening, and none of it is anything a vulnerability database does not already publish |
| The line is the finding's own visibility | The same field every query narrows by, so a message cannot disagree with what the screen would show the same person |
| The address is part of what must say nothing | A path carrying the identifier and the component announces both to every server the message crosses. A private message carries the deployment's front door, and the notification area behind it says which thing and where. It travels with the composed message rather than being built per channel, because an address built a second time is built without this rule |

Narrowing the recipients and emptying the body are different controls: the first
stops it reaching somebody who should not know, the second stops it being
disclosed by the delivery itself.

Who hears about an embargo is narrower than who hears about the tool's health.
Administrators, and whoever holds it — the second only where they may still read
undisclosed work in that product. An assignment can outlive the role that
allowed it.

## Reading what you were told

Narrowed in the data-access layer, with a subject, like every other read
(REQ-42 and REQ-43). The list and its badge go through one set of conditions.

A notification stays readable while the reason it was sent still holds. Not
"while you could read the finding it names" — a notification is a message
addressed to somebody under a rule recorded here, and the audiences those rules
name are what a later read has to ask about.

| A row is readable when | Because |
|---|---|
| It is about nothing undisclosed | Most of the table, and no rule narrows it |
| It names a product where this person reads undisclosed work now | The role is the reason it arrived, so withdrawing the role is what takes it away |
| It names an issue they were brought onto, one case at a time | A case grant is a pair. Widening it to the product would hand a collaborator the rest of that product's embargo list, which is the whole of what the grant is not |
| They administer the deployment | Administering is not reading, and every other read here says so — but the embargo notice names administrators as an audience of its own, and a message sent under that rule and withheld under this one is written for somebody who cannot open it. An administrator grants roles, so it hands them nothing they could not hand themselves |

Filtered, never deleted. Destroying the row destroys the record that somebody
was told, which is what an auditor most wants after a leak. Granting the role
back returns the line, because they were told and that is a fact about a moment.
It also avoids a clear-on-revoke path somebody has to remember, and there is
more than one way to lose a role.

A row marked private carries the product it is about, or the write is refused. A
private row attributable to nothing could only be shown to everybody or to
nobody. Refusing where it is written makes that a failure at the producer rather
than a leak, or a silent disappearance, at the reader.

The product and the issue are columns. Not parsed back out of the string a
digest matches on: what a read narrows by cannot rest on a shape another pass
invented.

Reading a list addressed to somebody else is an administrator's act. Every other
read of this table is somebody reading their own. This one exists so that a leak
can be investigated, and it is the only reason to look at what was sent to
another person — so it is refused for anybody else, in the store, where the rest
of this table's rules are.

| Rule | Reason |
|---|---|
| Read and cleared rows are included | The question is what was sent, not what is waiting. A line already acknowledged is still a line they were sent |
| Not narrowed by what that person may read now | Hiding the private half would answer the question with exactly the part that does not matter: a line about an undisclosed finding, sent while they held the role that reached it, is what the investigation is for |

## Delivery

| Rule | Reason |
|---|---|
| A sweep reconciles everybody it has told, not only everybody it should tell | Reconcile makes one person's open set exactly what it is handed, so somebody never handed a list is never reconciled and their alert stands after the thing was answered. This arises the moment who hears about something depends on who holds it |
| Nobody is told they were unassigned | A name being removed is not an action directed at the person who held it, and a queue that gets shorter says so already |
| A failure to tell somebody is logged, not returned | The assignment happened and the claim was sent back; answering the caller with an error invites a retry that does the first thing twice |
| More than one process sweeps | The chart ships two replicas, each running its own watch. The unique index makes a duplicate one row, and the pass treats a duplicate as the answer already being there — without that it would abort, and every administrator after the one it failed on would be told nothing that cycle |
| **A duplicate is recognized as one, and every other failure is reported** | Read as "somebody has this one" whatever went wrong, a lost connection during a sweep answered "already claimed" for every destination and the cycle reported nothing sent and nothing failed — which is what a quiet queue looks like too, so an operator could not tell them apart |
| **A sweep's lease covers a cycle of the work, not the gap between cycles** | The lease is not renewed while the work runs, which is what its own contract says: taken for the interval instead, a batch of two hundred messages to a server answering slowly outlived it by an hour, a second replica took it, read the same rows and sent every one of them again — because what marks a message sent is written after each individual send. Sized from the batch and what one message may take |

## Mail

A channel behind one interface, so what may be said is decided once for every
channel there will be. Mail carries the markdown as its text part.

| Rule | Reason |
|---|---|
| What is unsent is the work list | A sweep reads notifications nobody has carried out yet, sends them, and marks them. A failed message needs no state of its own; a deployment that configures mail after a week finds the week waiting |
| Tried five times, then left alone | A mailbox that refuses every time has gone. The row stays unsent and stays readable |
| Somebody with no address is sent nothing | Expressed in the query rather than the loop, so a deployment where nobody has one does no work |
| Credentials are refused over a connection the server would not secure | The sweep offers STARTTLS and will not send a password without it |
| Nothing logs the password, and nothing redacts it | A formatter that redacted the configuration was written and removed by the gate refusing exported code nothing reaches. If anything ever formats the configuration, the redaction goes in with it |

## Outbound HTTP

One signed HTTP request per notification kind and per operational condition,
configured per deployment. That covers Slack, Teams, a tracker driven by
automation and paging without an adapter each.

This is the first egress to an address an operator types, which makes it a
request-forgery primitive unless governed (REQ-69):

| Control | Detail |
|---|---|
| https only | The body is authenticated and not encrypted, and what it says is what somebody is being told about a vulnerability |
| A redirect is refused, never followed | A redirect asks this deployment to send a signed request somewhere else. A receiver that moved should be reconfigured, which is visible |
| A private address is allowed | The one place this differs from a sign-in provider's endpoints. A provider's address arrives in a discovery document from outside; this one was typed by the operator, whose chat server is reasonably on their own network |

| Rule | Reason |
|---|---|
| Every request is signed over the timestamp and the body | A receiver can distinguish one of ours from one anybody could make, and cannot be handed yesterday's again. The timestamp is inside the signature |
| The signing secret is stored recoverably | Every other credential is hashed because it authenticates somebody to this deployment; this one authenticates this deployment to somebody else. No endpoint returns it |
| What it carries is what the channel rules already allow | Composed by the same code that composes a mail, the address included. A rule enforced in two places is enforced in one and a half, and the address is the part a channel would otherwise build for itself |
| Tracked per destination and per thing said, not per notification | A condition is opened once for every person who should hear it, and a channel wants it once. An event has no such identity and is tracked by its own |
| The claim is staked before the request is made | A row with no sent-at stops a second replica, or the next sweep, sending the same thing while the first is in flight |

## Embargo notices

An embargo running out is announced before its date (REQ-38), at a lead time
somebody sets — two weeks by default — inside the application rather than by
mail, because mail may not name an undisclosed issue.

Two conditions, not one. An embargo that is coming and one that has arrived
clear differently, and a single alert would go on saying "coming" after the date
had passed. The approaching one clears when the date arrives, at which point the
other opens, or when the embargo is extended past the lead time.

The approaching notice states that extending needs a second person and that
arranging it takes time, which is the reason for warning early rather than on the
day.

A VEX publisher revising a cited statement raises an alert. The decision stands
whatever they now say, but somebody approved a dismissal on the strength of that
evidence.

"Cited" is recorded rather than inferred. A decision started from a VEX
statement carries which statement that was. Inferring it from the issue and the
component would raise an alert about every decision at a place a publisher
happens to have spoken about.

## Ownership of a notification

A notification identifier is a number a caller supplies, so reading and
acknowledging both check whose it is. One belonging to somebody else answers
exactly as one that does not exist.

A key is not a person. Identifiers for keys and people come from different
tables and collide as a matter of course, so the subject kind is checked rather
than inferred from the number: without it, a key numbered three reads and
acknowledges the notifications of person three. A test pins that by giving the
key the person's own number.

The body is stored rather than derived at read time. It describes a moment: the
finding it names may since have been decided, closed or reopened.

## Not built

| Not built | Detail |
|---|---|
| A chat adapter | Behind the same interface mail uses. A chat adapter translates rather than forwarding markdown, and mostly sends a summary and a link |
| The HTML part of a mail | The only remaining reader for the server-side renderer, and the reason it is kept rather than deleted |

## Limits

- **Events are not collapsed.** Being assigned the same finding twice is two
  things that happened, and the second is the one they have not seen.
- **The badge count is counted through the same conditions as the list.** A badge
  that disagrees with the list under it is the same class of mistake as a total
  that ignores a filter.
