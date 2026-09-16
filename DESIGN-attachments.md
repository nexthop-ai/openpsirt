# Attachments

Files hanging off a finding: storage, references, authorization, limits,
redaction and the reaper.

Satisfies REQ-70.

## Contents

- [References in text](#references-in-text)
- [What an attachment hangs off](#what-an-attachment-hangs-off)
- [Fetch authorization](#fetch-authorization)
- [Storage](#storage)
- [Delivery](#delivery)
- [Response headers](#response-headers)
- [Quota and removal](#quota-and-removal)
- [Write and delete ordering](#write-and-delete-ordering)
- [Limits](#limits)

## References in text

A reference is `attachment:` followed by an opaque identifier, as the target of
an ordinary markdown link or image. No address of the store appears in stored
text.

| Property | Reason |
|---|---|
| Not a URL | A URL pins the storage arrangement into every justification and comment ever written. Moving buckets would mean rewriting the record a decision rests on |
| Unguessable, not sequential | Authorization protects a file; this stops the existence of one being discoverable by counting |
| Recognized from the parsed document, not by searching the text | A reference inside a fenced block or code span is being shown rather than made |

This is the one scheme added to what a link may use beside `http`, `https` and
`mailto`. An image may use no other — see `DESIGN-text.md`.

## What an attachment hangs off

An attachment hangs off **the issue in the product** — the unit a decision, an
embargo and a comment already use. Not the finding row: text is written against
a decision, a decision covers every place an issue sits at, and binding a file to
one of forty-eight rows would make it unreachable the day that row closed while
its siblings stayed open.

Visibility is the issue's and is never stored on the attachment. Storing a
visibility at upload would freeze it: an embargo ends, and the file documenting
it becomes readable along with the words describing it.

| State | Meaning |
|---|---|
| Attached to text | The ordinary case. A file attached while composing is bound to the issue alone until that text is saved |
| Attached to the issue | Evidence for a recorded flaw. Attached the moment it arrives. The caller requests this; it is not the default |
| Attached to nothing | Collected by the reaper |

## Fetch authorization

Every fetch is authorized against the visibility of the issue the attachment
hangs off, before anything is served, in this order:

1. Is the issue in this product at all?
2. Is it disclosed, or may this reader see undisclosed work here?
3. Does this reader hold a grant on this one case? (REQ-43)

Asking only the second collapses "no undisclosed findings in this product" and
"no findings in this product at all" into one answer, so an issue filed against
another product reads as public here. Any reader of any product could then
confirm whether a name exists anywhere in the deployment, one request at a time.

A file the reader may not see and a file that does not exist answer identically,
in the same words (REQ-42).

No bucket is ever public. A private finding's attachment in a readable bucket
would be invisible from inside the application: every screen would look correct
while the bytes were served by something else.

## Storage

An object store reached through the S3-compatible API. Never the database.

| Decision | Reason |
|---|---|
| Not the database | Blobs inflate every backup and every replica, and a retention pass over rows is a different mechanism from one over objects |
| The S3 API | MinIO, Ceph and every cloud provider speak it, so one implementation covers self-hosted and managed alike |
| A filesystem backend for development | Mirrors what SQLite does for the database |
| The store is optional | With none configured, attachments are off and everything else works |
| The official AWS SDK for Go, v2 | Measured against a signer written here. The credential chain is what a cloud deployment needs and is the part that cannot be tested anywhere else |
| Object-store requests are not restricted to public addresses | The restriction exists for an address that arrived from outside, and this one the operator typed in: a store on their own network is the ordinary deployment. The endpoint is read from the environment once, at startup, and no administrator can change it from inside the application — so the exemption adds nothing to what whoever deploys the process already holds, and the control is who may deploy it |

The transport lives beside the store. The store decides what may be reached and
by whom; the object-store and filesystem backends implement one interface behind
it. A separate package would put that interface at a package boundary, where a
second implementation is tempted to reach past it.

### Reaching the store in the clear

An endpoint that is not `https` is refused, and two things lift that (REQ-70).

| Lifts it | |
|---|---|
| The endpoint reaches no further than this machine | Nothing crosses a network, so there is no path to be on. This is the development backend's neighbor and needs no saying. Asked of the address rather than compared against a table of three spellings, which left the rest of `127.0.0.0/8` and the IPv6 forms outside it — a local store given its own loopback address was refused, and the only way past it recorded in the deployment log that a plaintext store had been accepted across a network |
| An operator states that the network is one they accept it on | The store somebody already runs is the constraint. An installation with no TLS in front of its object store should be able to run this, rather than be told it configured the tool wrongly |

| Rule | |
|---|---|
| Refused as the deployment starts, not at somebody's first upload | With everything else a misconfigured store is refused for |
| The refusal names the setting that would accept it | Whoever meets it is the operator the allowance exists for, and a refusal saying only what is forbidden leaves them reading source to find the way through |
| A deployment that lifted it is told at every start | An attachment is delivered as a redirect, so the signed address is a bearer token: anybody on the path may spend it for the file it names. That is invisible from the setting that allows it, and the person who set it is rarely the person reading the logs a year later |
| Neither the refusal nor the notice repeats a password | An endpoint may carry credentials, and a notice at every start would otherwise write them to the log at every start |
| An endpoint carrying credentials is split before anything is given the address | The name and password are handed over as credentials, which is what makes the signing well-defined, and the address the client is given carries nothing to leak by any route. What a person is shown and what the client uses stop being two strings that can drift |
| Distinct from serving this application without TLS | That one is cookies on the way in, this one a file on the way out, and a deployment can want either without the other |

## Delivery

| Content | Sent by |
|---|---|
| An inline image | The application |
| Everything else | A redirect to a short-lived signed URL |

Both are authorized identically and first.

A page served here may load images from this origin and nothing else (REQ-69),
so an `img` whose source redirects into an operator's bucket is refused by the
browser with nothing on the page or in a log to say why. Carrying those bytes
here keeps the policy constant; a policy assembled from configuration fails open
when the configuration is wrong.

What the application carries is bounded by the raster allowlist and by the upload
size limit. A log or an archive is not an inline image and is redirected.

## Response headers

| | |
|---|---|
| Content type | Chosen by this deployment, never the uploaded one |
| Disposition | `Content-Disposition: attachment` |
| Inline display | A small allowlist of raster image types only. A vector image is a document with a scripting engine |

The signed URL carries these as response overrides rather than whatever was
stored, so both survive the redirect.

## Quota and removal

| Rule | Detail |
|---|---|
| Whether a file hangs off the issue is a boolean the framework parses | Compared against the literal "true", every other spelling read as false and marked the file for deletion a day later, with the uploader told it had worked |
| A maximum file size, a per-deployment quota, and one person's share of it | All three configurable. The deployment-wide ceiling is one account's to reach alone, and what reaching it costs is everybody else's next upload — a triager's evidence on an active embargo in another product answering "no room" |
| Never deleted while anything references it | Removal is an explicit administrative redaction, recorded, leaving the reference and a tombstone |
| Unattached uploads are reaped | A file attached to an abandoned form is bytes nothing will ever reach |
| One object per attachment, never content-addressed | Deduplicating by digest would let a redaction blank a file somebody else relies on. The digest is kept beside the row, so a redaction can state what it removed once the bytes are gone |

Both bounds are checked twice: before anything is carried, so an upload that
cannot be kept is refused rather than transferred and discarded; and inside the
writing transaction, because the first answer was read before the bytes were.

Attaching is triage work. It asked the read test — whether the subject may see
the issue the file hangs off — so a role granting nothing but the ability to
read disclosed findings on one product could write files into the store. A
collaborator brought onto the case may attach, because evidence is usually why
they were brought in.

## Write and delete ordering

The row is written after the bytes and removed if it cannot be. The other order
leaves a reference to something that never arrived. This order can leave bytes
with no row for as long as the failing write takes, and those are removed on the
way out.

| Operation | Order | Reason |
|---|---|---|
| Redaction | Row, then file | A file removed with nothing saying so reads as a store that lost it |
| Reaper | Row, then file | The row carries the guard, and a guard run after the unlink can only fail to clean up after the loss it exists to prevent: text naming the file between the reaper's page and its delete left the bytes gone, the delete matching nothing, and the record standing over nothing — reported as a collection that happened |

Inverting the reaper's order inverts which side can be orphaned. Bytes
surviving a deleted row are recoverable, because the key is named in the log;
a record surviving its bytes is not, and it is what a person clicks.

| Rule | Reason |
|---|---|
| A row the reaper could not claim leaves its bytes alone | Somebody attached it while the pass was running, which is the ordinary case rather than a contrived one: text naming an attachment is saved after the transaction that wrote it |
| A row the reaper could not finish does not end the pass | Returning on the first failure abandoned every row after it in the page, so one undeletable object stalled collection for ever |
| What it destroyed and what it could not are named, not counted | It is the only writer here that destroys somebody's data and the only one that kept no record of it. A key is what an orphan can be found by |

The local store is confined structurally: names go through a directory handle
that cannot be escaped, rather than a path comparison this package performs.

## Limits

- **Uploads are not scanned for malware.** An operator handling files from
  outside their organization should know this does nothing about it. Scanning
  belongs in front of the bucket, where an operator can choose it.
- **A refusal states that the issue is not there, never that the file is not
  yours.** Telling somebody a file exists but is not theirs tells them the issue
  exists.
- **Only an identifier this deployment minted resolves.** Matching loosely would
  let text name rows by pattern. Submission refuses anything else, and the
  renderer keeps only the references that pass.
