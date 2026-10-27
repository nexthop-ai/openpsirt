# Chat

Slack and Zulip: who a notification reaches, which channel carries it, how a
cycle groups and delivers messages, and how text is escaped.

Satisfies REQ-47, REQ-48, REQ-69, REQ-80, REQ-81.

## Contents

- [Chat](#chat)
- [Chat recipients](#chat-recipients)
- [Channel scope](#channel-scope)
- [Grouped chat messages](#grouped-chat-messages)
- [Chat delivery](#chat-delivery)
- [Chat markup](#chat-markup)
- [Limits](#limits)

## Chat

Each platform is reached through a bot whose credential is deployment
configuration. A bot posts to channels an administrator names and messages
people directly. Chat carries every notification as it happens (REQ-80); mail
stays quiet and leaves the rest to the digest (REQ-47).

| Platform | Reaches a channel | Reaches a person | Finds a person |
|---|---|---|---|
| Slack | Posts to a channel it was added to, by ID or name | Posts to the person, shown in the app's conversation with them | By the address their workspace holds, with the scope reading addresses |
| Zulip | Posts to a channel under a topic, `OpenPSIRT` where the destination names none | A direct message to their account | By the address, which the organization lets the bot see |

| Rule | Reason |
|---|---|
| The credential is configuration and never enters the database | One bot per deployment, as one mail server. The operator's secret store holds it, and nothing returns it |
| Which channel receives what is a destination an administrator sets | Routing changes without a redeploy, beside the webhooks |
| A channel on a platform this deployment does not offer is refused | Nothing could post to it |
| A person is found by their recorded address | Linking accounts by hand reaches nobody until everybody has |
| Somebody the platform has no account for is sent nothing in chat, and the notifications are settled | They keep the area and mail; the next cycle does not ask again |
| Chat is composed by the mail's code | What may leave about an undisclosed finding is decided once (REQ-48) |

Teams and Google Chat are not built. Teams retired its incoming webhooks in
2026; the replacement takes a card, and a direct message needs a tenant workflow
or a registered bot. Google Chat takes text from a channel webhook, and a direct
message needs a Chat app installed for the people it reaches.

## Chat recipients

Each kind is somebody's own or shared; a table over every kind says which, and
a test holds the table against the list of kinds.

| Kind | Examples | Where it goes |
|---|---|---|
| Somebody's own | Assigned, named, a decision sent back or waiting on them, an approval withdrawn or undone, a lapse, brought into a case, an issue they hold disclosed, a deferral running out | To them directly, never a channel |
| Shared, disclosed | A critical on a release, a quiet build, a sharp inventory move, a team queue, an answer a merge superseded, stale vulnerability data, a silent supplier, an upstream failing or read again | The most specific channel covering it. Directly only where no offered-platform channel covers it, or to people who asked for what the channels carry |
| Shared, undisclosed | An embargo approaching or due, a response window, a queue holding undisclosed work | Directly to each person it names; the deployment's channel is told that there is something |

| Person's setting | Default | Effect |
|---|---|---|
| Direct messages | On | Off sends nothing directly on any platform |
| What the channels carry | Off | On sends shared notifications directly too. Refused with direct messages off |

| Rule | Reason |
|---|---|
| Both settings are the person's own; an administrator sets neither | Like the digest's switches |
| What somebody reads in the application before a cycle reaches it is not sent to them | |
| Nothing opened more than a day ago is carried to chat | A backlog from before configuration or a refusing day buries what is new; it stays in the application |

## Channel scope

A chat channel belongs to the deployment, one product or one team. A webhook
belongs to the deployment, because its receiver is automation that filters.

| Channel | Carries |
|---|---|
| A team's | Shared, disclosed notifications naming the team: work in its queue |
| A product's | Shared, disclosed notifications about the product no team channel covers |
| The deployment's | Shared notifications no narrower channel covers, and that there is something undisclosed, with the way in |

| Rule | Reason |
|---|---|
| A notification reaches the most specific covering channel and no broader one, and not also the people it names unless they asked | |
| A channel narrower than the deployment says nothing about undisclosed work (REQ-81) | Nothing sees who sits in a channel, and a team mixes clearances, so even "something undisclosed" tells of an embargo. It reaches cleared people directly |
| The deployment's channel carries the fact and a link, as a webhook does | An administrator set it up to hear everything |
| A queue holding one undisclosed occurrence is undisclosed as a whole | Its team channel says nothing until the last leaves |
| A channel is refused a kind that is somebody's own | It would list as configured and receive nothing |
| A channel belongs to a product or a team, never both | The scopes rank against each other |
| A channel names its channel, and a topic only on Zulip | Slack has no topics |
| A channel takes no address and no secret | The platform credential reaches it |
| The product and team are resolved after the caller is established as an administrator | Resolved first, the refusal says whether a name exists |
| A team's channel carries only the queue condition | It is the one notification naming a team; assignment to a team, by hand or rule, makes none |

## Grouped chat messages

A cycle runs each minute, and what one person or channel is told in a cycle is
one message (REQ-80). A destination takes one kind or every kind, so a channel
for two kinds is two destinations, and what both take is composed once, each
thing once.

| Content | How it is said |
|---|---|
| One thing | Its subject as heading, its sentence and its link |
| Several things | A count as heading, then a line per kind and product: one thing is its subject and first line; several are subject, product and how many |
| Anything undisclosed among several | One line with how many, and the way in |
| More than twelve lines | Twelve, and how many more were left out |

| Rule | Reason |
|---|---|
| Grouped by kind and product | Notifications record no producing scan, feed, rule or person, and bursts mostly come from a sweep after the act; a night of scans is many of one kind in one product |
| A person's message is composed from at most a thousand notifications, one message a cycle | A larger backlog goes a thousand at a time |

## Chat delivery

| Rule | Reason |
|---|---|
| One sweep per deployment, held by a lease | As mail and webhooks; otherwise every replica sends |
| A channel's delivery is tracked per destination and per thing said | A condition held by six is one line to a channel |
| A person's delivery is tracked per notification and per platform | Mail and each platform carry independently; one failing is no retry of another |
| The claim is staked before the request | |
| Tried five times, then left alone in the application | |
| A cycle sends to at most fifty people per platform | Finding and sending are two requests, and the lease is sized from a cycle's requests |
| A platform asking to be sent less is a failed attempt | The next cycle retries |
| A refusal is recorded without the request's address | Finding a person puts their address in it |
| Slack is asked not to unfurl | Unfurling has Slack fetch every address from this deployment |
| Slack at the host the application names, Zulip at the one configured, over https, following no redirect, through the webhook's client | Both hosts are named, not chosen by a document, which is what REQ-69 lets a request reach |

## Chat markup

Every string is plain text until the platform's rule escapes it, since
component names, publisher names and supplier failure text are chosen
elsewhere.

| Platform | Escaped | Kept as markup |
|---|---|---|
| Slack | `&`, `<` and `>`, which open links, mentions and channel pings. A link's label is one line | The heading's bold and composed links, their `&` escaped |
| Zulip | Markdown, by the release note's rule, which escapes what mentions and channel links open with | The heading's bold and composed links, with parentheses and spaces in the address percent-encoded |

Slack's emphasis has no escape and opens nothing, so it is left alone.

## Limits

| Limit | Detail |
|---|---|
| A chat account registered to somebody's address is taken to be theirs | The platform's administrator controls which addresses accounts hold; a deployment not trusting them should not configure the bot |
