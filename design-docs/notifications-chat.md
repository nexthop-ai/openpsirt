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

A bot per platform, its credential deployment configuration, posts to channels
an administrator names and messages people directly. Chat carries every
notification as it happens (REQ-80); mail leaves the rest to the digest
(REQ-47).

| Platform | Reaches a channel | Reaches a person | Finds a person |
|---|---|---|---|
| Slack | A channel it was added to, by ID or name | The app's conversation with them | By their workspace address, with the scope reading addresses |
| Zulip | A channel under a topic, `OpenPSIRT` by default | A direct message | By the address, which the organization lets the bot see |

| Rule | Reason |
|---|---|
| The credential stays in the operator's secret store and never enters the database | Nothing can return it |
| Which channel receives what is a destination an administrator sets | Routing changes without a redeploy |
| A channel on a platform not offered is refused | |
| A person is found by their recorded address | Linking accounts by hand reaches nobody until all have |
| Somebody without a platform account gets nothing in chat, and the notifications are settled | They keep the area and mail |
| Chat is composed by the mail's code | REQ-48 is decided once |

Teams and Google Chat are not built. Teams' incoming webhooks were retired in
2026; the replacement takes a card, and a direct message needs a tenant workflow
or a registered bot. Google Chat takes text from a channel webhook, and a direct
message needs a Chat app installed for the people it reaches.

## Chat recipients

A table over every kind says whether it is somebody's own or shared, and a test
holds it against the list of kinds.

| Kind | Examples | Where it goes |
|---|---|---|
| Somebody's own | Assigned, named, a decision sent back or waiting on them, an approval withdrawn or undone, a lapse, brought into a case, an issue they hold disclosed, a deferral running out | To them directly, never a channel |
| Shared, disclosed | A critical on a release, a quiet build, a sharp inventory move, a team queue, an answer a merge superseded, stale data, a silent supplier, an upstream failing or read again | The most specific covering channel; directly only where no offered-platform channel covers it, or to people who asked for what the channels carry |
| Shared, undisclosed | An embargo approaching or due, a response window, a queue holding undisclosed work | Directly to each person it names; the deployment's channel hears that there is something |

| Person's setting | Default | Effect |
|---|---|---|
| Direct messages | On | Off sends nothing directly |
| What the channels carry | Off | On sends shared notifications directly too; refused with direct messages off |

| Rule | Reason |
|---|---|
| Both settings are the person's own | |
| What somebody read in the application before a cycle reached it is not sent | |
| Nothing opened more than a day ago is carried | An old backlog buries what is new |

## Channel scope

A chat channel belongs to the deployment, one product or one team. A webhook
belongs to the deployment; its receiver filters for itself.

| Channel | Carries |
|---|---|
| A team's | The queue condition naming the team, the one notification naming a team |
| A product's | Shared, disclosed notifications about the product no team channel covers |
| The deployment's | Shared notifications no narrower channel covers, and that there is something undisclosed, with a link |

| Rule | Reason |
|---|---|
| A notification reaches the most specific covering channel only, and not the people it names unless they asked | |
| A channel narrower than the deployment says nothing about undisclosed work (REQ-81) | Nobody sees who sits in a channel, and a team mixes clearances |
| A queue holding one undisclosed occurrence is undisclosed as a whole | |
| A channel is refused a kind that is somebody's own | It would receive nothing |
| A channel belongs to a product or a team, never both | The scopes rank against each other |
| A channel names its channel, and a topic only on Zulip; it takes no address and no secret | |
| The product and team are resolved after the caller is established as an administrator | Otherwise the refusal says whether a name exists |

## Grouped chat messages

A cycle runs each minute, and what one person or channel is told in a cycle is
one message (REQ-80). A destination takes one kind or every kind; a channel's
destinations are composed into its one message, each thing once.

| Content | How it is said |
|---|---|
| One thing | Its subject as heading, its sentence and its link |
| Several things | A count as heading, then a line per kind and product: one thing is its subject and first line; several are subject, product and count |
| Anything undisclosed among several | One line with how many, and the way in. Nothing names what they are |
| More than twelve lines | Twelve, and how many more |

| Rule | Reason |
|---|---|
| Grouped by kind and product | Notifications record no producing scan, rule or person; a night of scans is one kind in one product |
| A person's message holds at most a thousand notifications, one message a cycle | |

## Chat delivery

| Rule | Reason |
|---|---|
| One sweep per deployment, held by a lease | |
| A channel's delivery is tracked per destination and thing said; a person's per notification and platform | Mail and each platform carry independently |
| The claim is staked before the request | |
| Tried five times, then left in the application; a platform asking to be sent less is a failed attempt | |
| At most fifty people per platform per cycle | Finding and sending are two requests, and the lease is sized from them |
| A refusal is recorded without the request's address | It holds the person's address |
| Slack is asked not to unfurl | Unfurling fetches every address from this deployment |
| Slack at the host the application names, Zulip at the one configured, over https, following no redirect, through the webhook's client | Both hosts are named, which REQ-69 allows |

## Chat markup

| Platform | Escaped | Kept as markup |
|---|---|---|
| Slack | `&`, `<` and `>`. A link's label is one line | The heading's bold and composed links, their `&` escaped |
| Zulip | Markdown, by the release note's rule, covering what mentions and channel links open with | The heading's bold and composed links, parentheses and spaces in the address percent-encoded |

Slack's emphasis has no escape and opens nothing, so it is left alone.

## Limits

| Limit | Detail |
|---|---|
| A chat account registered to somebody's address is taken to be theirs | The platform administrator controls account addresses; a deployment not trusting them should not configure the bot |
