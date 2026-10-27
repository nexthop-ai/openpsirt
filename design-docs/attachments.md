# Attachments

Files on an issue or a report: references, authorization, storage, delivery,
limits, redaction and the reaper.

Satisfies REQ-42, REQ-43, REQ-69, REQ-70.

## Contents

- [References in text](#references-in-text)
- [Attachment subjects](#attachment-subjects)
- [Fetch authorization](#fetch-authorization)
- [Storage](#storage)
- [Delivery](#delivery)
- [Response headers](#response-headers)
- [Quota and removal](#quota-and-removal)
- [Write and delete ordering](#write-and-delete-ordering)
- [Limits](#limits)

## References in text

A reference is `attachment:` and an opaque identifier, as the target of an
ordinary markdown link or image. No address of the store appears in stored
text. `design-docs/text.md` § Images and attachments holds what submission
accepts.

| Rule | Reason |
|---|---|
| Never a URL | A URL pins the storage arrangement into every justification ever written, and moving buckets would rewrite the record a decision rests on |
| Unguessable, never sequential | Authorization protects a file; this keeps its existence from being found by counting |
| Recognized from the parsed document, never by searching the text | A reference in a fenced block or code span is shown, not made |
| Only an identifier this deployment minted resolves | Matching loosely would let text name rows by pattern. Submission refuses anything else, and the renderer keeps only references that pass |

## Attachment subjects

A file hangs off the product and exactly one of two things in it: an issue, or
a report nobody has judged. A file naming both or neither is refused at upload.

| Rule | Reason |
|---|---|
| An issue in the product, never a finding row | A decision, an embargo and a comment use that unit. Bound to one of forty-eight rows, a file becomes unreachable the day that row closes while its siblings stay open |
| A report that has not been judged takes files of its own | It has no issue yet, and a screenshot is often the whole of what was sent |
| A file stays with its report once the report gains an issue | What was sent is a fact about the report; on the issue it would no longer say which of two reports it came in |
| Visibility is the issue's, never stored on the attachment | A visibility stored at upload freezes, and an embargo ends: the file becomes readable along with the words describing it |

| State | Meaning |
|---|---|
| Attached to text | The ordinary case. A file attached while composing is bound to the issue alone until that text is saved |
| Attached to the issue | Evidence for a recorded flaw, attached the moment it arrives. The caller asks for it; it is not the default |
| Attached to the report | What arrived with a report, attached the moment it arrives, and kept on the report when it is judged. A report ruled a duplicate is listed on the issue it duplicates, and its files are reached through it there |
| Attached to nothing | Collected by the reaper |

## Fetch authorization

Every fetch is authorized against the visibility of what the attachment hangs
off, before anything is served (REQ-70).

A file on an issue is checked in this order:

1. The issue is in this product at all.
2. It is disclosed, or this reader may see undisclosed work here.
3. This reader holds a grant on this one case (REQ-43).

| Rule | Reason |
|---|---|
| The first step is never skipped | Asking only the second collapses "no undisclosed findings here" and "no findings here at all", so an issue filed against another product reads as public, and any reader could confirm a name exists anywhere in the deployment |
| A file on a report takes the report's answer: the right to read unannounced work in that product, judged or not (`design-docs/findings-reports.md` § Report visibility) | The record and what arrived with it have one answer |
| A file on a report never follows the issue the report turned out to be | What a stranger sent is reviewed by nobody, so judging the report a disclosed issue must not publish it; a file meant to be read there is attached to the issue |
| A duplicate's files are listed where the issue it duplicates is read, under the report's answer | Somebody who reads the issue and may not read reports sees neither the duplicate nor its files |
| Attaching to a report needs the right to triage unannounced work there | Attaching is working the report |
| A file the reader may not see and one that does not exist answer identically, in the same words (REQ-42) | |
| A refusal states that the issue is not there, never that the file is not yours | A file existing and not being yours says the issue exists |
| No bucket is ever public | A private finding's file in a readable bucket is invisible from inside the application: every screen looks right while something else serves the bytes |

## Storage

An object store reached through the S3-compatible API, never the database.

| Rule | Reason |
|---|---|
| Not the database | Blobs inflate every backup and replica, and retention over rows is a different mechanism from retention over objects |
| The S3 API | MinIO, Ceph and every cloud provider speak it, so one implementation covers self-hosted and managed |
| A filesystem backend for development | Mirrors what SQLite does for the database |
| The store is optional | With none configured, attachments are off and everything else works |
| The official AWS SDK for Go, v2 | Measured against a signer written here; its credential chain is what a cloud deployment needs and the part untestable anywhere else |
| Object-store requests may reach private addresses | The request-forgery restriction is for a host a document chose, and the operator typed this one (REQ-69). The endpoint is read from the environment once, at startup, and no administrator can change it, so the exemption adds nothing to what whoever deploys the process holds |
| Both backends store exactly the bytes they were told to expect; a shorter or longer body is refused and nothing stored | An upload's digest is always of the whole file |
| A longer body's excess is sent to the object store as a failure before its last declared byte | A server that has read the declared length can accept it before the client notices more |
| The local store is confined structurally: names go through a directory handle that cannot be escaped | Never a path comparison |

### Store credentials

| Rule | Reason |
|---|---|
| Configured credentials win over the environment's | An operator naming a key means that key |
| A key without its secret, a secret without its key, and a session token with no key and no name in the endpoint are refused at startup | Dropped, the process runs as whatever identity the environment offers, and nothing says the configured one went unused |
| The published directory is never the attachment store, refused at startup | One bucket name on one endpoint (both unset counting as the provider's default), one folder, or a folder holding or inside the other. Everything in the directory is served to anybody, and an attachment only after its visibility is checked (REQ-70) |
| A refusal names the settings of the store it is about | The attachment store and the provider directory's store are configured alike under two prefixes, and naming the other's setting sends the operator to settings that are fine |

### The filesystem store

The store holds attachments in development and the provider directory in
production, where the same names are written every pass.

| Rule | Reason |
|---|---|
| A file is written beside its name and renamed into place | A failure part way leaves nothing a later read mistakes for a whole file |
| The file written beside has a name of its own per write | A killed process leaves it behind, and under a fixed name every later write of that key would be refused. Two writers of one key do not collide |
| One left behind for an hour is removed when its key is next written | No write takes that long, and nothing else removes it |

### Unencrypted store access

An endpoint that is not `https` is refused, and two things lift that (REQ-70).

| Lifts it | Reason |
|---|---|
| The endpoint reaches no further than this machine, asked of the address, never matched against a table of spellings | Nothing crosses a network. A table leaves the rest of `127.0.0.0/8` and the IPv6 forms out, refusing a local store on its own loopback address, whose only way past would log a plaintext store accepted across a network |
| An operator states the network is one they accept it on | An installation with no TLS in front of the object store it already runs can run this |

| Rule | Reason |
|---|---|
| Refused as the deployment starts, never at the first upload | With everything else a misconfigured store is refused for |
| The refusal names the setting that would accept it | Whoever meets it is the operator the allowance is for |
| A deployment that lifted it is told at every start | An attachment is delivered as a redirect, so the signed address is a bearer token anybody on the path may spend, which the setting does not show, and whoever set it is rarely whoever reads the logs a year later |
| Neither the refusal nor the notice repeats a password | An endpoint may carry credentials, which a notice at every start would log at every start |
| An endpoint carrying credentials is split before anything is given the address | The name and password are handed over as credentials, which makes signing well defined, and the address the client holds carries nothing to leak. What a person is shown and what the client uses are one string |
| An upload to a plaintext store sends its payload unsigned, with a checksum only where the operation requires one | An upload streams through its digests and cannot be rewound, and over plain HTTP the client would hash the body first, which a stream refuses. Over https a trailing checksum covers a stream |
| The published directory's object store is held to the same rules and announced at every start in words of its own | Its files are public, and what crosses the path is the write: anybody on it may change what the public reads |
| Distinct from serving this application without TLS | That one is cookies coming in, this one a file going out, and a deployment may want either alone |

## Delivery

| Content | Sent by |
|---|---|
| An inline image | The application |
| Everything else | A redirect to a short-lived signed URL |

Both are authorized identically and first.

| Rule | Reason |
|---|---|
| The application carries an inline image itself | A page here may load images from this origin alone (REQ-69), so an image redirected into an operator's bucket is refused by the browser with nothing to say why. A policy assembled from configuration fails open when the configuration is wrong |
| What the application carries is bounded by the raster allowlist and the upload size limit | A log or an archive is not an inline image and is redirected |

## Response headers

| Header | Rule |
|---|---|
| Content type | Chosen by this deployment, never the uploaded one |
| Disposition | `Content-Disposition: attachment` |
| File name | The uploaded name without its directory, with control and format characters, quotes, backslashes and slashes replaced, cut to 120 bytes. A right-to-left override before `fdp.exe` shows a program as a document |
| Inline display | A small allowlist of raster image types. A vector image is a document with a scripting engine |

The signed URL carries these as response overrides, never what was stored, so
they survive the redirect.

## Quota and removal

| Rule | Reason |
|---|---|
| Whether a file hangs off the issue is a boolean the framework parses | Compared with the literal "true", any other spelling reads false: the file is reaped a day later and the uploader told it worked |
| A maximum file size, a deployment quota and one person's share of it, all configurable | The deployment ceiling is one account's to reach alone, and reaching it costs everybody else's next upload: a triager's evidence on an active embargo in another product answering "no room" |
| The file size takes no value above 512 MiB, and a stored value past it reads as 512 MiB | The scan route's request at the shipped inventory bound; scratch space is sized for the largest request a route takes |
| Never deleted while anything references it | Removal is an explicit administrative redaction, recorded, leaving the reference and a tombstone |
| Unattached uploads are reaped | A file on an abandoned form is bytes nothing will reach |
| One object per attachment, never content-addressed | Deduplicating by digest lets a redaction blank a file somebody else relies on. The digest is kept beside the row, so a redaction says what it removed once the bytes are gone |
| Attaching is triage work, never read work | Tested as a read, a role granting only the reading of disclosed findings on one product writes files into the store |
| A collaborator brought onto the case may attach | Evidence is usually why they were brought in |

### Upload admission

The request is admitted before its form is read.

1. The person is authorized to attach to the issue or the report, in the words the handler refuses in.
2. The request is bounded at the maximum file size plus a megabyte for the form. One declaring more is refused unread; one not declaring its length is cut off at the bound.
3. It takes a place among the uploads one server reads at once (`design-docs/ingest.md` § Request handling).

| Rule | Reason |
|---|---|
| Both bounds are checked before anything is carried, and again inside the writing transaction | The first refuses an upload that cannot be kept before transfer; the second, because the first was read before the bytes were |
| The second check is serialized across uploads: each writing transaction first writes a fresh value into one fixed row of the lease table, which nothing takes as a lease | A total read beside another upload's uncommitted row misses it, so two uploads would both fit and both commit. The write makes the next upload wait for this commit, and is what two cluster nodes conflict on (`design-docs/database.md` § Replica coordination) |
| Uploads are serialized per deployment while a quota or a share is set | Each holds the lock for two reads and an insert |

## Write and delete ordering

The row is written after the bytes, and the bytes are removed if the row cannot
be. The other order leaves a reference to something that never arrived; this
one leaves bytes with no row for as long as the failing write takes.

| Operation | Order | Reason |
|---|---|---|
| Redaction | Row, then file | A file removed with nothing saying so reads as a store that lost it. A failed delete leaves the row marked over bytes still stored; asking again deletes them before answering that the file is gone |
| Reaper | Row, then file | The row carries the guard, and a guard run after the unlink cannot prevent the loss. Inverted, text naming the file between the reaper's page and its delete leaves the bytes gone and the record standing over nothing |

Bytes surviving a deleted row are recoverable, because the key is logged; a
record surviving its bytes is not, and it is what a person clicks.

| Rule | Reason |
|---|---|
| A row the reaper could not claim leaves its bytes alone | Somebody attached it during the pass, which is ordinary: text naming an attachment is saved after the transaction that wrote it |
| A row the reaper could not finish does not end the pass | Returning on the first failure abandons the rest of the page, so one undeletable object stalls collection for ever |
| What the reaper destroyed and what it could not are named, never counted | It is the one writer here destroying somebody's data, and a key is what an orphan is found by |

## Limits

| Rule | Reason |
|---|---|
| Uploads are not scanned for malware | An operator handling files from outside their organization should know. Scanning belongs in front of the bucket, where an operator can choose it |
