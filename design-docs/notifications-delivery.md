# Notification delivery

What a message leaving the deployment may carry, how sweeps deliver it, and the
mail and outbound HTTP channels.

Satisfies REQ-46, REQ-47, REQ-48, REQ-69.

## Contents

- [Outbound content](#outbound-content)
- [Delivery](#delivery)
- [Mail](#mail)
- [Outbound HTTP](#outbound-http)
- [Limits](#limits)

## Outbound content

A message about an undisclosed finding says that there is something, and links
(REQ-48): no identifier, component or summary, in the subject line least of all,
which a preview shows unopened.

| Rule | Reason |
|---|---|
| The in-application area is not held to this | Reaching it needs a credential and the visibility check; a message sits on servers, inboxes, lock screens and forwards nobody re-checks |
| A disclosed finding is not held to this | Identifier, component, version and build make it worth opening, and a vulnerability database publishes them already |
| The line is the finding's own visibility | The field every query narrows by, so a message agrees with the screen |
| A private message's address is the deployment's front door, composed with the message and carried by every channel | A path carrying identifier and component announces both to every server crossed; an address built a second time is built without this rule |
| Narrowing recipients and emptying the body are separate controls | One stops the wrong person knowing; the other stops the delivery disclosing |

## Delivery

| Rule | Reason |
|---|---|
| A sweep reconciles everybody it has told, not only who it should tell | Somebody never handed a list is never reconciled, which arises once audiences depend on who holds a thing |
| Who it has told is read per kind, by one call for every condition | Two spellings one argument apart leave somebody never reconciled |
| That read goes through an index on kind, open, and person | Every other index leads with the person. With 152,859 open conditions a steady sweep takes 4.3 s with it and 5.0 s without (`design-docs/notifications-measurements.md` § Sweep index) |
| A sweep with no administrator recorded still derives everything not addressed to administrators alone | Returning early strands every triager's alert |
| Nobody who has left is in any audience | Their grants stay on purpose. Every sweep starts from people still here, an event for a departed person records nothing, and the mail, digest and direct-chat sweeps skip them in the query, covering rows opened before they left |
| Nobody is told they were unassigned | Removal is no act directed at them |
| A failure to tell is logged, never returned | The act happened; an error invites a retry doing it twice |
| More than one process sweeps, and a duplicate is the answer already being there | The chart ships two replicas, each watching. The unique index makes a duplicate one row; aborting on it tells nobody after the failure that cycle |
| A batch refused for a duplicate is opened again a row at a time, each statement on a savepoint | Another process opened one row and the rest are true; PostgreSQL refuses everything after a failed statement in a transaction |
| A duplicate is recognized as one, and every other failure is reported | Read as "somebody has this", a lost connection reports nothing sent and nothing failed, which looks like a quiet queue |
| A sweep's lease covers one cycle of work, sized from the batch and what one message may take | The lease is not renewed mid-work. Sized to the interval, a slow server's batch outlives it, and a second replica resends every message, since sent is marked after each send |
| A webhook cycle sends one batch across every destination | One request budget, so one lease covers any number; many destinations drain slower |
| Each destination is offered an equal part of what remains, unspent parts passing on, the first offered rotating each cycle | A destination refusing or hanging spends only its own part |
| A delivery records when its latest attempt began | An attempt begun under twice the one-request bound ago, neither gone nor failed, is in flight and left alone. A failed or abandoned one is retaken by an update repeating the attempt count read, so two takers make one attempt |

## Mail

A channel behind one interface, so what may be said is decided once for every
channel (REQ-46). Mail carries the text as its plain-text part. It is immediate
only for what a person must act on; the rest is the digest (REQ-47).

| Rule | Reason |
|---|---|
| The unsent notifications are the work list: a sweep sends and marks them | A failed message needs no state; mail configured a week late finds the week waiting |
| A condition the application withdrew is not carried | Nothing reconciles it, and a private one would say nothing at all |
| A server and a sender are configured together or not at all, refused at startup, with which one arrived logged | Half reads as no mail configured, indistinguishable from choosing none |
| Tried five times, then left alone | The mailbox has gone. The row stays unsent and readable |
| Somebody with no address is sent nothing, in the query | A deployment where nobody has one does no work |
| Credentials are refused over a connection the server would not secure: STARTTLS is offered, and no password goes without it | |
| Nothing logs the password, and nothing redacts it | Nothing formats the configuration; anything that does adds the redaction with it |

## Outbound HTTP

One signed request per notification kind and per operational condition,
configured per deployment: Slack, a tracker driven by automation, paging, with
no adapter each. Teams takes one only through a tenant workflow turning the body
into a card (`design-docs/notifications-chat.md` § Chat). The host is one an
administrator configured, which REQ-69 lets it reach anywhere, and it is still a
request-forgery primitive governed by:

| Control | Detail |
|---|---|
| https only | The body is authenticated, not encrypted, and says what somebody is told about a vulnerability |
| A redirect is refused, never followed | It asks for a signed request elsewhere; a moved receiver is reconfigured visibly |
| A private address is allowed | The operator typed it, unlike a sign-in provider's discovered endpoints; their chat server is on their network |
| The request goes through the process's one outbound client, carrying every control and the common User-Agent | `design-docs/access.md` § Outbound provider fetches. A second client misses changes to the shared refusals |

| Rule | Reason |
|---|---|
| Every request is signed over a timestamp and the body, the timestamp inside the signature | A receiver tells ours apart and cannot be replayed yesterday's |
| A signing secret is at least 16 characters, refused by the store | Every caller recording a destination is held to it |
| The signing secret is stored recoverably and returned by no endpoint | It authenticates this deployment to somebody else |
| No endpoint returns a destination's address, only its host | For Slack and Teams the path is the credential. A destination is told apart and retired by name and kind |
| The subject and text are escaped as markdown line by line, by the release note's rule, then `&`, `<` and `>` become `&amp;`, `&lt;` and `&gt;`; the line holding the composed address stays an address and the link field is sent as is | Teams renders markdown links, and Slack and Teams read `<!channel>` and `<address\|label>`. Bodies carry names nobody here chose; the application's own text has no markdown. Mail carries the text unescaped |
| It carries what the channel rules allow, composed by the mail's code, address included | A rule in two places is enforced in one and a half |
| Tracked per destination and per thing said | A condition opens once per person; a channel wants it once. An event is tracked by its identity unless it names what it is one of |
| A condition's delivery covers one opening of it | An opening lasts while any holder's row is open. Claimed for the row first in the window, it moves to another row staying open across that row's clearing; once no row was open, a reopening is news and is taken again. A holder demoted or leaving is no return for everybody else |
| An event saying one sentence to many names what it is one of; a personal event carries none | Otherwise twenty-five readers post twenty-five identical messages a night and crowd out every other kind |
| The claim is staked before the request | A row with no sent-at stops a replica or the next sweep resending |
| A sweep reads what this destination has not settled | Read as "not cleared", events are never cleared, so past two hundred the same window is re-read forever, silently |
| A destination's kind is a kind some notification is, or every kind; a mistyped one is refused naming the kinds | It would list as working and receive nothing |
| A destination's reason is why the last settled delivery failed, and nothing once one has gone since | |
| A destination's name is matched folded to lower case, its typed spelling kept for the listing | Two names differing in capitals are one destination. Migration 43 folded v0.8.0's names; two folding to one key under one kind stay two, the second listed under a numbered key (`design-docs/database.md` § Migrations) |
| A destination's kind is normalized where written | Compared loosely, one believed retired keeps receiving, undisclosed findings included |
| Reading and changing destinations is refused in the data layer, naming fields one by one | The table's own rule (REQ-42 and REQ-43); embedding the row lets the secret reach a careless caller |

## Limits

| Limit | Detail |
|---|---|
| Slack shows a backslash before each character a webhook's text escaped as markdown | One text goes to Slack, whose markup has no backslash escape, and to Teams, which renders markdown. A stray backslash costs less than a link labelled anything |
