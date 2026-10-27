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

A reference is `attachment:` and an opaque identifier, as a link or image
target. Stored text holds no store address. What submission accepts is
`design-docs/text.md` § Images and attachments.

| Rule | Reason |
|---|---|
| Never a URL | Moving buckets would rewrite the record decisions rest on |
| Unguessable, never sequential | A file's existence is not found by counting |
| Recognized from the parsed document | A reference in a fenced block or code span is shown, not made |
| Only a minted identifier resolves | Loose matching names rows by pattern |

## Attachment subjects

A file hangs off the product and exactly one of an issue or an unjudged report;
naming both or neither is refused at upload.

| Rule | Reason |
|---|---|
| An issue, never a finding row | Bound to one of forty-eight rows, a file is lost when that row closes |
| An unjudged report takes files of its own | Its screenshot is often all that was sent |
| A file stays with its report once the report gains an issue | It records which report it came in |
| Visibility is the issue's, never stored on the file | A stored visibility outlives the embargo's end |

| State | Meaning |
|---|---|
| Attached to text | The ordinary case; while composing, bound to the issue alone until the text is saved |
| Attached to the issue | Evidence for a recorded flaw, on arrival, when the caller asks |
| Attached to the report | What arrived with it, kept there once judged. A duplicate is listed on the issue it duplicates, and its files reached through it |
| Attached to nothing | Collected by the reaper |

## Fetch authorization

Every fetch is authorized against what the file hangs off, before anything is
served (REQ-70). A file on an issue is checked in order:

1. The issue is in this product at all.
2. It is disclosed, or the reader may see undisclosed work here.
3. The reader holds a grant on this one case (REQ-43).

| Rule | Reason |
|---|---|
| The first step is never skipped | Without it an issue filed elsewhere reads as public here, and a reader confirms names across the deployment |
| A file on a report takes the report's answer: reading unannounced work in that product, judged or not (`design-docs/findings-reports.md` § Report visibility) | |
| It never follows the issue the report became | A stranger's upload is reviewed by nobody; a file to publish is attached to the issue |
| A duplicate's files are listed on the issue it duplicates under the report's answer | A reader of the issue who may not read reports sees neither |
| Attaching to a report needs the right to triage unannounced work there | Attaching works the report |
| A file the reader may not see and one that does not exist answer identically (REQ-42) | |
| A refusal says the issue is not there, never that the file is not yours | Otherwise it confirms the issue |
| No bucket is ever public | A readable bucket serves private files while every screen looks right |

## Storage

An object store through the S3-compatible API, never the database.

| Rule | Reason |
|---|---|
| Not the database | Blobs inflate every backup and replica |
| The S3 API | MinIO, Ceph and every cloud speak it |
| A filesystem backend for development | As SQLite is for the database |
| The store is optional; without it attachments are off | |
| The official AWS SDK for Go, v2 | Measured against a signer written here; its credential chain is what a cloud needs and cannot be tested elsewhere |
| Authorization sits in the store, above both backends, which implement one interface beneath it | Neither backend decides what may be reached |
| Object-store requests may reach private addresses | The operator typed this host, read once at startup and unchangeable by an administrator (REQ-69) |
| Both backends store exactly the bytes expected; a shorter or longer body is refused and nothing stored | A digest is always of the whole file |
| A longer body's excess reaches the object store as a failure before its last declared byte | A server can accept the declared length before the client notices more |
| The local store is confined by a directory handle that cannot be escaped, never a path comparison | |

### Store credentials

| Rule | Reason |
|---|---|
| Configured credentials win over the environment's | |
| A key without its secret, a secret without its key, and a session token with no key and no name in the endpoint are refused at startup | Dropped, the process runs as whatever the environment offers, silently |
| The published directory is never the attachment store: refused at startup for one bucket on one endpoint (both unset is the provider default), one folder, or folders nested either way | The directory is public; an attachment is served only after its check (REQ-70) |
| A refusal names the settings of the store it is about | The two stores share setting names under two prefixes |

### The filesystem store

It holds attachments in development and the provider directory in production,
rewriting the same names each pass.

| Rule | Reason |
|---|---|
| A file is written beside its name and renamed into place | A failure leaves no partial file to read |
| The file beside has a name of its own per write | A killed write under a fixed name would block every later write of the key; two writers do not collide |
| One left for an hour is removed when its key is next written | Nothing else removes it |

### Unencrypted store access

An endpoint that is not `https` is refused, unless (REQ-70):

| Lifts it | Reason |
|---|---|
| The endpoint reaches no further than this machine, asked of the address | A table of spellings misses the rest of `127.0.0.0/8` and IPv6, forcing a local store through the allowance that logs a plaintext store across a network |
| An operator states the network is one they accept it on | An installation without TLS in front of its store can still run this |

| Rule | Reason |
|---|---|
| Refused as the deployment starts, with every other misconfigured store | |
| The refusal names the setting that would accept it | |
| A deployment that lifted it is told at every start | A redirect's signed address is a bearer token anybody on the path may spend |
| Neither the refusal nor the notice repeats a password | An endpoint may carry credentials |
| An endpoint carrying credentials is split before the client is given the address; the name and password go as credentials | Signing is well defined, and the client's address carries nothing to leak |
| An upload to a plaintext store sends its payload unsigned, with a checksum only where the operation requires one | It streams through its digests and cannot be rewound for hashing; over https a trailing checksum covers it |
| The published directory's object store follows the same rules and is announced at every start in its own words | There the path carries writes to what the public reads |
| Distinct from serving this application without TLS | Cookies coming in, files going out |

## Delivery

| Content | Sent by |
|---|---|
| An inline image | The application |
| Everything else | A redirect to a short-lived signed URL |

Both are authorized identically and first.

| Rule | Reason |
|---|---|
| The application carries an inline image itself | Pages load images from this origin alone (REQ-69); a policy built from configuration fails open |
| It is bounded by the raster allowlist and the upload size limit | A log or an archive is redirected |

## Response headers

| Header | Rule |
|---|---|
| Content type | Chosen by this deployment, never the uploaded one |
| Disposition | `Content-Disposition: attachment` |
| File name | The uploaded name without its directory, with control and format characters, quotes, backslashes and slashes replaced, cut to 120 bytes. A right-to-left override before `fdp.exe` shows a program as a document |
| Inline display | A small allowlist of raster image types; a vector image is a document with a scripting engine |

The signed URL carries these as response overrides, so they survive the
redirect.

## Quota and removal

| Rule | Reason |
|---|---|
| Whether a file hangs off the issue is a boolean the framework parses | Compared with "true", other spellings read false and the file is reaped a day later |
| A maximum file size, a deployment quota and one person's share, all configurable | One account could otherwise fill the deployment and refuse another product's embargo evidence |
| The file size takes nothing above 512 MiB; a stored value past it reads as 512 MiB | The scan route's request at the shipped inventory bound sizes scratch space |
| Never deleted while referenced; removal is a recorded administrative redaction leaving the reference and a tombstone | |
| Unattached uploads are reaped | |
| One object per attachment, never content-addressed; the digest is kept beside the row | A shared object lets one redaction blank another's file; the digest says what a redaction removed |
| Attaching is triage work, never read work | Otherwise a read-only role on disclosed findings writes into the store |
| A collaborator brought onto the case may attach | |

### Upload admission

The request is admitted before its form is read:

1. The person is authorized to attach, in the handler's own refusal words.
2. The request is bounded at the maximum file size plus a megabyte; one declaring more is refused unread, one declaring nothing cut off at the bound.
3. It takes one of the places for uploads one server reads at once (`design-docs/ingest.md` § Request handling).

| Rule | Reason |
|---|---|
| Both bounds are checked before carrying and again inside the writing transaction | The first was read before the bytes |
| The second check is serialized: each writing transaction first writes one fixed row of the lease table, which nothing takes as a lease | Otherwise two concurrent uploads both fit; cluster nodes conflict on that row (`design-docs/database.md` § Replica coordination) |
| Uploads are serialized per deployment while a quota or share is set, each holding the lock for two reads and an insert | |

## Write and delete ordering

The row is written after the bytes, and the bytes removed if the row fails;
bytes are briefly without a row, never a row without bytes.

| Operation | Order | Reason |
|---|---|---|
| Redaction | Row, then file | A failed delete leaves the marked row over stored bytes, deleted on the next request before it answers gone |
| Reaper | Row, then file | The row carries the guard. File first, text naming the file mid-pass leaves a record over nothing |

Orphaned bytes are recoverable from the logged key; a record without bytes is
not.

| Rule | Reason |
|---|---|
| A row the reaper could not claim leaves its bytes alone | Text naming an upload is saved after the upload commits |
| A row the reaper could not finish does not end the pass | One undeletable object would stall collection |
| What the reaper destroyed and failed to destroy is named by key, never counted | |

## Limits

| Rule | Reason |
|---|---|
| Uploads are not scanned for malware | Scanning belongs in front of the bucket, an operator's choice |
