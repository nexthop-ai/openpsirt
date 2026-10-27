# API refusals

The status codes the API answers with, the shape of a refusal, and what an
error's text may publish.

Satisfies REQ-42, REQ-61, REQ-66.

## Contents

- [Status codes](#status-codes)
- [Refusal shape](#refusal-shape)
- [Limits](#limits)

## Status codes

| Code | Meaning |
|---|---|
| 201 | Something now exists, its identifier in the answer |
| 202 | Accepted and not done: only an upload, answered before it is read |
| 204 | Done, with nothing to say |
| 400 | An undeclared query parameter, an unreadable query string, or a NUL character in typed input, naming the input |
| 403 | An act the caller may not do on a product they can see: an issue act or an assignment rule without its role |
| 404 | Not there, **or** not the caller's: one answer |
| 409 | A conflict with what the request names: a scan older than the one held, a role granted the wrong way for the mode, an approval by the decision's proposer, a scan filed against a retired product, release or variant, a name corrected after a document naming it went out, a build renamed while its document was generated, retiring something retired, a name another row holds |
| 422 | Understood and not storable as written, such as a promise naming a release past end-of-life |

| Rule | Reason |
|---|---|
| Not found and not yours are one answer, for a product, a decision identifier, a person and a credential (REQ-42) | Otherwise names are learned by guessing |
| A name reaching nothing, or what the caller may not have, answers 404; an act refused on something already shown answers 403 or 422 | |
| The sentences are kept in one place | |
| Every store refusal is typed, and every handler meeting one answers it as a name reaching nothing | Unmapped, it answers 500 where a stranger gets 404, naming which of product, branch or tag, and variant is undeclared. A case collaborator meets these on every product-wide read |
| A streamed answer is refused before its first byte | After it, only the file can say the export stopped, behind a 200 |

## Refusal shape

`application/problem+json` for everything, the credential check and the sign-in
callbacks in front of the router included; `text/plain` reads to a client as a
transport fault. Each fault travels as its own detail carrying the line and the
offending text, so an interface can point at it.

| Error | Answer |
|---|---|
| A refusal, alone or wrapped | Its own sentence, at its mapper's status |
| A sentinel a mapper has an arm for | That arm's answer |
| A lost race or a failed query, told apart by the engine's error types | 500 in fixed words, the cause carried to the retry helper |
| Anything else, a connection failure and an object store's answer included | 500 in fixed words |

| Rule | Reason |
|---|---|
| A message is published only when it is a refusal: every caller-facing sentence a store, the catalog or the document parser writes is typed as one, and a sentinel stays matched through it | An error type a caller reads fields of, such as a fault in writing, a name reaching several components, references a ruling could not find, or a missing reason, declares itself one. Everything else is logged with its cause |
| An error's text is publishable when it is a refusal carrying nothing an engine or driver put in it, one test wherever asked | A failed scan run's receipt asks only the second half, since the scanner's words tell a producer why |
| The harness each route package runs over its mappers fails a fault body carrying any detail of its cause, its error list included | |
| A connection not made or cut short is read from the network's and each driver's own error | |
| The document parser states a file ending inside a value in its own words; a read failing beneath the parser is a fault | The driver's cut-connection error would hide a truncated upload, which the sender fixes |
| A failed upload's receipt carries the refusal's sentence, or a fixed sentence otherwise, a job that died first included | |
| A failed scan run's receipt carries the scanner's own words, or a fixed sentence where the database or its driver failed | |
| An act that committed is answered as done; a later read naming things in the answer is logged where it fails, its names left blank | A fault answer would get the act repeated, and an append-only notice held twice |
| A 404 is never built from an error's text, and a gate checks it | A driver error would reach a caller as "that product does not exist" with host, port and driver |
| The catalog's not-declared error is the one exception, composed from the supplied names and fixed words, once the sentinel matched | A refused pipeline must know which of product, branch and variant |
| A read that could not be made is a fault, never a 404, split by one helper | |
| A process with no database or no queue answers everything but the probes with one 500 sentence from the router, before a caller is resolved | No handler is reached without both |

### NUL characters

A NUL character in typed input is refused 400 naming the input. PostgreSQL and
SQLite refuse such a string as a fault; MySQL and MariaDB drop the character.

| Input | Where it is checked |
|---|---|
| A query parameter, by name | Once for every operation, after unknown parameters are refused |
| A path value, by name | The same check |
| A form field, by name | Where every multipart form is read, before the operation parses it |
| A string or a key in a JSON body, by its place | The one reader of JSON bodies, reported as an unreadable body |

Names are taken in order, so a request holding two is refused naming the same
one every time.

## Limits

| Limit | Detail |
|---|---|
| An uploaded file's contents are not checked for NUL | A file is not typed input, and each reader handles its own bytes |
