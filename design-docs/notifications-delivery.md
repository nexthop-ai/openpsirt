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
(REQ-48): no identifier, component or summary, the subject line included.

| Rule | Reason |
|---|---|
| The in-application area is exempt | Reaching it needs a credential and the visibility check; a message sits on servers, lock screens and forwards |
| A disclosed finding is exempt, carrying identifier, component, version and build | A vulnerability database publishes them already |
| The line is the finding's own visibility | The field every query narrows by |
| A private message's address is the front page, composed with the message and carried by every channel | A path announces identifier and component to every server; an address built twice is built without this rule |
| Narrowing recipients and emptying the body are separate controls | One stops the wrong person knowing; the other stops the delivery disclosing |

## Delivery

| Rule | Reason |
|---|---|
| A sweep reconciles everybody it has told, not only who it should tell | Somebody never handed a list is never reconciled |
| Who it has told is read per kind, by one call for every condition, through an index on kind, open and person | Every other index leads with the person; the index takes a steady sweep over 152,859 conditions from 5.0 s to 4.3 s (`design-docs/notifications-measurements.md` § Sweep index) |
| A sweep with no administrator recorded still derives everything not addressed to administrators alone | |
| Nobody who has left is in any audience: sweeps start from people still here, an event for a departed person records nothing, and the mail, digest and direct-chat sweeps skip them in the query, covering rows opened before they left | Their grants stay on purpose |
| A failure to tell is logged, never returned | An error invites a retry doing the act twice |
| Several processes sweep, and a duplicate is the answer already being there | The chart ships two replicas; aborting tells nobody after the failure |
| A batch refused for a duplicate is opened again a row at a time, each statement on a savepoint | PostgreSQL refuses everything after a failed statement in a transaction |
| A duplicate is recognized as one, and every other failure is reported | Read as "somebody has this", a lost connection looks like a quiet queue |
| A sweep's lease covers one cycle of work, sized from the batch and what one message may take | It is not renewed mid-work; sized to the interval, a slow batch outlives it and a second replica resends, since sent is marked after each send |
| A webhook cycle sends one batch across every destination | One request budget, so one lease; many destinations drain slower |
| Each destination is offered an equal part of what remains, unspent parts passing on, the first offered rotating each cycle | A destination refusing or hanging spends only its own part |
| A delivery records when its latest attempt began; one begun under twice the one-request bound ago and unsettled is in flight | A failed or abandoned one is retaken by an update repeating the attempt count read, so two takers make one attempt |

## Mail

A channel behind one interface, so what may be said is decided once (REQ-46).
Mail carries the text as its plain-text part, and is immediate only for what a
person must act on (REQ-47).

| Rule | Reason |
|---|---|
| The unsent notifications are the work list, sent and marked | Mail configured a week late finds the week waiting |
| A condition the application withdrew is not carried | Nothing reconciles it |
| A server and a sender are configured together or not at all, refused at startup, logging which arrived | Half reads as no mail configured |
| Tried five times, then left unsent and readable | |
| Somebody with no address is sent nothing, in the query | |
| STARTTLS is offered, and no password goes without it | |
| Nothing logs the password, and nothing redacts it | Nothing formats the configuration; whatever does adds the redaction |

## Outbound HTTP

One signed request per notification kind and per operational condition,
configured per deployment: Slack, a tracker, paging, with no adapter each. Teams
takes one only through a tenant workflow turning the body into a card
(`design-docs/notifications-chat.md` § Chat). REQ-69 lets a configured host be
reached anywhere; these controls govern it:

| Control | Detail |
|---|---|
| https only | The body is authenticated, not encrypted |
| A redirect is refused | A moved receiver is reconfigured visibly |
| A private address is allowed | The operator typed it, unlike a discovered sign-in endpoint |
| The process's one outbound client, with its controls and User-Agent | `design-docs/access-signin.md` § Outbound provider fetches |

| Rule | Reason |
|---|---|
| Every request is signed over a timestamp and the body, the timestamp inside the signature | A receiver tells ours apart and refuses a replay |
| A signing secret is at least 16 characters, refused by the store | Every caller recording a destination is held to it |
| The signing secret is stored recoverably and returned by no endpoint | It authenticates this deployment to somebody else |
| No endpoint returns a destination's address, only its host | For Slack and Teams the path is the credential. A destination is told apart and retired by name and kind |
| The subject and text are escaped as markdown line by line, by the release note's rule, then `&`, `<` and `>` become entities; the line holding the composed address and the link field are sent as they are | Teams renders markdown links, and Slack and Teams read `<!channel>` and `<address\|label>`. Mail carries the text unescaped |
| It is composed by the mail's code, address included | |
| Tracked per destination and per thing said; an event by its identity unless it names what it is one of | A channel wants a condition once, not once per holder |
| A condition's delivery covers one opening: claimed for the row first in the window, moving to another row open across that row's clearing, and taken again only after no row was open | A holder demoted or leaving is no return for everybody else |
| An event saying one sentence to many names what it is one of; a personal event carries none | Otherwise twenty-five readers post twenty-five messages a night |
| The claim is staked before the request | |
| A sweep reads what this destination has not settled | Read as "not cleared", events never clear, and past two hundred the same window is re-read forever |
| A destination's kind is a kind some notification is, or every kind; a mistyped one is refused naming the kinds | It would list as working and receive nothing |
| A destination's reason is why the last settled delivery failed, and nothing once one has gone since | |
| A destination's name is matched folded to lower case, its typed spelling kept for the listing | Migration 43 folded v0.8.0's names; two folding to one key under one kind stay two, the second under a numbered key (`design-docs/database-upgrades.md` § The v0.9.0 upgrade) |
| A destination's kind is normalized where written | Compared loosely, a retired one keeps receiving |
| Destinations are read and changed through the data layer, field by field | REQ-42 and REQ-43; an embedded row leaks the secret |

## Limits

| Limit | Detail |
|---|---|
| Slack shows a backslash before each character a webhook's text escaped as markdown | One text goes to Slack, which has no backslash escape, and to Teams, which renders markdown |
