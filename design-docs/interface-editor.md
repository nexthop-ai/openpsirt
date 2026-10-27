# Editor and drafts

The markdown editor, drafts and what a tab remembers across sign-out, file
attachment from the editor, mentions, and the people pickers.

Satisfies REQ-34, REQ-43, REQ-59, REQ-65, REQ-67.

## Contents

- [The editor](#the-editor)
- [Drafts](#drafts)
- [File attachment](#file-attachment)
- [Mentions and assignment pickers](#mentions-and-assignment-pickers)
- [Limits](#limits)

## The editor

A formatting toolbar over a plain textarea with Write and Preview tabs. What is
stored is markdown, and a rich-text editor eventually disagrees with what is
published.

| Rule | Reason |
|---|---|
| Every toolbar control is a button, never only a shortcut | It works on a phone |
| Toolbar marks are bundled-font characters or icons from the rail's set (`design-docs/interface-look.md` § Interface-wide rules) | |
| Preview is the published renderer | |
| Preview returns warnings beside the rendering (REQ-67) | What would be refused says so before submit |
| An attached file's reference goes in at the cursor when the upload lands; the field stays editable meanwhile | What was typed is kept |
| An edited piece's earlier wording is read by the panel showing it, mounted when "edited" is pressed, and an edit refreshes it | |

## Drafts

Unsent text is kept and restored (REQ-59). A draft is written to the browser as
somebody types and cleared only once the server has taken it, so a refused
submission, an expired session and a closed tab leave the words.

| Rule | Reason |
|---|---|
| Restoring is into an empty field only, once per draft key; a key first seen with text in the field is settled then | The key changes under an open editor; cleared prefill stays cleared |
| What is on screen is stored under the key it was typed under | Key and text move in separate renders |
| Storage a browser refuses is tolerated on every read and write | The text on screen is the real thing |
| A draft key names everything the text is about, the build and the version included | One name ships at two versions |
| A draft keeps the answer as well as the prose: outcome, justification, date, fixed version | The prose is about the answer |
| A revision opens on its draft where one was left | Restoring only into an empty field would lose it |
| A draft is restored into the form it was typed in, and is no default; an explicit "start from this" beats it | It is this person's answer to this finding |
| Where a draft lives and under whose name is decided in one place | |
| A draft is kept under the identity that wrote it, encoded into the key; text typed before anybody is recognized is not kept | A session can expire silently; the separator is a colon, which an identity may hold |
| Signing out clears every draft the browser holds, every writer's, before the request ending the session | Drafts hold private triage text; a sign-out that cannot reach the server is when clearing matters most |
| A sign-out the server did not complete stays on the page and offers it again; drafts are cleared either way; a refusal for want of any session reads as signed out | The server clears the cookie only on ending the session |
| Signing out clears what the tab remembers: the scope, the last decision recorded, the list positions. The look and the rail fold stay | The tab survives a same-tab sign-out; a preference is meant to |
| Somebody else signing in clears it too: the tab records whose its state is, and a different person clears it before anything reads it. State with no owner is cleared when the first person is recognized; until the session is known, nothing recorded for a person is read | A lapsed session is resumed by signing in, which is no sign-out |

## File attachment

The editor carries an attach control wherever an issue is in hand: a
justification, a comment, editing one. It stores the file against that issue and
writes the reference at the cursor (REQ-65): an image as an image, anything else
as a link, by the type the server decided.

| Rule | Reason |
|---|---|
| A refusal is shown beside the control: a file over the deployment's size, a deployment with no room | |
| A reference becomes a path on this origin before anything renders it | Its scheme is unknown to browsers, so the sanitizer would drop it |
| An image pointing anywhere else loses the whole element | Such text is refused at submission; an older one would draw a broken icon |
| The finding lists what is attached beside rendering it, a removed file listed saying so and why | A file in an unread revision is still record |

## Mentions and assignment pickers

Autocomplete after `@` offers the people who can read findings of that
visibility in that product, and nobody else (REQ-43). On an undisclosed finding a
mention itself says a finding exists.

| Rule | Reason |
|---|---|
| Asking who may be mentioned on undisclosed work is a question about undisclosed work; a non-reader is answered as though the product were not there | Otherwise it enumerates who holds private access |
| The term after `@` is read from the text before the cursor | It stays right however the text is edited |
| What is typed is sent and the server narrows, matching display names and identities | A local filter over a first page misses people |
| The holder pickers ask the same endpoint (REQ-34) | People who may read it can open what they are handed; the people list is administration |
| A box people type `@` into offers names at the visibility discussed: a decision at its most careful row's, a code finding's decision at internal | |
| The bulk decision form offers no mentions | It carries no visibility to ask with |

The team-member picker and the case picker are typed against the list. The team
picker narrows the candidates it holds in the browser; the case picker sends the
term to the endpoint.

| Rule | Reason |
|---|---|
| An offer shows the identity beside the name where they differ | Two colleagues can share a display name |
| What is typed matches an identity exactly before capitals are ignored, and ignoring them resolves only where one person is left | A provider's identities differing in capitals are two people |
| The button stays disabled until what is typed resolves to somebody offered | Neither picker brings anybody into the deployment |
| The list opens on focus | Somebody adding to a team looks rather than recalls |

## Limits

| Limit | Detail |
|---|---|
| A sign-in redirect leaves the page | A draft is saved first and the person returns to it (`design-docs/interface.md` § An expired session) |
