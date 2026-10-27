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
| 201 | Something now exists, and its identifier is in the answer |
| 202 | Accepted and not yet done: only an upload, which answers before it is read |
| 204 | Done, with nothing worth saying |
| 400 | A query parameter the operation does not take, a query string that cannot be read, or a NUL character in typed input. The refusal names the input |
| 403 | An act the caller may not do on a product they can see: an issue act or an assignment rule without the role it asks for |
| 404 | The thing is not there, **or** is not the caller's. Deliberately one answer |
| 409 | The request conflicts with the state of what it names: a scan older than the one held, a role granted the wrong way for the deployment's mode, an approval by the decision's own proposer, a scan filed against a retired product, release or variant, a name corrected after a document naming it went out, a build renamed while its document was generated, retiring something already retired, a name another row holds |
| 422 | Understood and not storable as written, such as a promise naming a release past end-of-life |

| Rule | Reason |
|---|---|
| Not found and not yours are one answer, for a product, a decision identifier, a person and a credential (REQ-42) | Otherwise somebody holding one product learns every other name by guessing |
| A name reaching nothing, or reaching what the caller may not have, answers 404; an act they may not do on something already shown answers 403 or 422 | Two routes answering one condition with 404 and 422 disclose the difference |
| The sentences are kept in one place | Spellings multiply and describe the wrong thing |
| Every store refusal is typed, and every handler that can meet one answers it as a name reaching nothing is answered | An unmapped refusal falls through to 500 where a stranger gets 404, and the fault's text names which of product, branch or tag, and variant is undeclared. A case collaborator meets these on every product-wide read |
| A streamed answer is refused before its first byte | Once the status has gone, only the file can report that the export stopped early, behind a 200 |

## Refusal shape

`application/problem+json` for everything, including the handlers in front of
the router: the credential check and the sign-in callbacks, which are ordinary
handlers because a redirect from a provider is no API call. A `text/plain` answer
there reads to a client as a transport fault.

A refusal states where to look: each fault travels as its own detail carrying
the line and the offending text, so an interface can point at it.

| Error | Answer |
|---|---|
| A refusal, alone or wrapped in a caller's context | Its own sentence, at the status its mapper gives |
| A sentinel a mapper has an arm for | That arm's answer |
| A lost race or a failed query, told apart by the engine's error types | 500 in fixed words, with the cause carried to the retry helper |
| Anything else, a connection failure and an object store's answer included | 500 in fixed words |

| Rule | Reason |
|---|---|
| A message is published only when it is a refusal | Every sentence a store, the catalog or the document parser writes for a caller is typed as one, and a sentinel stays matched through it. An error type carrying fields a caller reads, such as a fault in a piece of writing, a name reaching several components, references a ruling could not find, or a missing reason, declares itself one. Everything else is logged with its cause |
| Whether an error's text may be published is one test: a refusal carrying nothing an engine or a driver put in it | A failed scan run's receipt asks only the second half, because the scanner's own words tell a producer why |
| The harness every route package runs over its mappers reads the whole body a fault answers, its error list included, and fails any detail of the cause | |
| A connection not made or cut short is read from the network's and each driver's own error for it | |
| The document parser states a file ending inside a value in its own words | Its error would otherwise be a driver's cut connection, and a truncated upload is the sender's to fix. A read failing beneath the parser is a fault |
| A failed upload's receipt carries the refusal's sentence where the cause is a refusal, and a fixed sentence otherwise, a job that died before saying why included | |
| A failed scan run's receipt carries the scanner's own words, and a fixed sentence where the failure came from the database or its driver | |
| An act that committed is answered as done; a later read naming things in the answer, such as who recorded it or which window it counts against, is logged where it fails and its names left blank | Answered as a fault, the caller repeats the act, and an append-only record such as a notice is held twice |
| A 404 is never built from an error's own text, and a gate checks it | Over a reader returning the driver's error, a connection failure would reach a caller as "that product does not exist" with the host, port and driver |
| The catalog's own not-declared error is the one exception, composed from the names supplied and fixed words, reached only once the sentinel matched | A refused pipeline needs to know which of product, branch and variant it was |
| A read that could not be made is a fault, never a 404, split by one helper | Made per route, it is made differently per route |
| A process with no database or no queue answers every request but the probes with one 500 sentence, written by the router before a caller is resolved | No handler is reached without both. The sentence says nothing of the request, which did not cause it |

### NUL characters

A NUL character in typed input is refused with a 400 naming the input. PostgreSQL
and SQLite refuse a string holding one, failing the request as a fault; MySQL
and MariaDB drop it, so deployments would disagree.

| Input | Where it is checked |
|---|---|
| A query parameter, by name | Once for every operation, after unknown parameters are refused |
| A path value, by name | The same check |
| A form field, by name | Where every multipart form is read, before the operation parses it |
| A string or a key in a JSON body, by its place | The one format every JSON body is read through, reported as the body could not be read |

Names are taken in order, so a request holding two is refused naming the same
one every time.

## Limits

| Limit | Detail |
|---|---|
| An uploaded file's contents are not checked for NUL | A file is not typed input, and each reader keeps its own handling of the bytes it carries |
