# Upload receipts

What a producer and a person read back about uploads: receipts, a build gone
quiet, documents retrieved, and the list of every kind of upload.

Satisfies REQ-09, REQ-13, REQ-19, REQ-44, REQ-52.

## Contents

- [Last upload per build](#last-upload-per-build)
- [Receipts](#receipts)
- [Receipt cost](#receipt-cost)
- [Document retrieval](#document-retrieval)
- [Upload listing](#upload-listing)
- [Limits](#limits)

## Last upload per build

A build nothing files against changes no number. Every declared build is
reported with when a scan last arrived, longest-silent first, and whether that
is longer than the deployment allows.

| Rule | Reason |
|---|---|
| A build never filed against is reported from its declaration | A declared, unwired build fails silently |
| Quiet is a setting in whole days, shipping at a week; a stored fraction reads as the next whole day everywhere | Screen and alert agree |
| A release out of support is never quiet (REQ-52), and is still listed with its age | |
| Only a scan that could be read counts as heard from | A nightly parse failure is what this is for |
| A scan upload turned away is recorded against the build, with when and why, one per build, replaced | Quiet says nothing arrived, not whether anybody tried |
| Recording that refusal is best-effort | Failing it would hide the refusal from the producer |
| It is a person's question; a pipeline key reads only receipts | |

## Receipts

Acceptance is issued before reading, so each upload to a build is listed newest
first with how far it got.

| State | Meaning |
|---|---|
| Taken | Not yet read |
| Read | Awaiting a vulnerability scan |
| Done | Scanned |
| Refused | With the reason |

| Rule | Reason |
|---|---|
| The states are this deployment's, never the queue's | |
| A sender is recorded as a key or a person, with its identifier | Names collide across keys and people |
| A key reads every receipt of a build it may upload to, whoever sent it (REQ-44) | A rotated key's re-send answers with the first upload's scan |
| Which builds a key reads is decided in the store from the subject: one release or variant, or its whole product | |
| A read whose job died is failed in fixed words | The job's error may carry an address; a refusal arrives through the scan row |
| An upload is answered by the earliest successful run finishing after its parse; a failed run only while nothing has succeeded since | One crash would otherwise poison every waiting receipt |
| Each finding records its opening and closing runs, and every receipt item each run's scanner and database versions (REQ-13) | Work done on a bad feed week has to be found |
| The opening run is recorded, never the newest | |
| No run is invented where there is none: a recorded finding (REQ-19), or a pruned run | |

## Receipt cost

| Count | Rule |
|---|---|
| What each run changed | Worked out when asked, as issues at components, attributed to the newest read upload the run covered and omitted elsewhere |
| Components described and components placed | Stored at read; a document placing none is a list, unable to answer "why is this here" |
| Names gained, lost and changed since the upload before | Worked out when read (`design-docs/data-model.md` § Inventory delta), against what the build held whoever sent it |

| Rule | Reason |
|---|---|
| A key that reads no findings reads these counts | They are arithmetic over its own documents |
| Which names moved is a listing of its own, on the receipt's terms | |
| An upload moving much of a build is told to the product's readers after commit (`design-docs/notifications.md` § An inventory that moved sharply); a message that cannot be composed is logged | |
| The counts read only the page's runs' findings, through an index on each run column carrying every counted column | Unindexed, the count grows with the calendar |
| A page holding a first scan reads most of the build, until fifty scans follow | |
| An index-only read misses findings written since the last vacuum; the finding table is vacuumed after a fiftieth changes (`design-docs/database.md` § Indexes) | |

`design-docs/ingest-measurements.md` § Receipt page timings has the page on all
four engines over a year.

## Document retrieval

A tag's documents are returned as kept (REQ-09).

| Rule | Reason |
|---|---|
| The bytes as arrived | The receipt's hash covers them |
| Named through the scan, narrowed in the store | Whoever reads the receipt reads the document, by one path |
| Named `.xml` or `.json` by its first character | Tools go by extension |

## Upload listing

| Kind | Sent to | Listed by |
|---|---|---|
| SBOM | The build | Its receipts (§ Receipts) |
| Static analysis run, as SARIF | The build | Its runs (`design-docs/analysis.md` § Receipts) |
| VEX document | The product | § Document uploads |
| Supplier advisory | The product, by upload or feed | § Document uploads |

One read lists every kind for a build with its count and its newest's outcome,
through each kind's own list, so each kind's reader rule holds.

| Status | SBOM | Static analysis run | VEX document, supplier advisory |
|---|---|---|---|
| In progress | Taken, being read or scanned | Queued, or waiting for the inventory | — |
| Completed | Scanned | Applied, or kept beside a run built later | Statements recorded |
| Failed | Unusable, with the reason | Unreadable, or its tool did not run, with the reason | — |
| Refused | The last turned away, after the newest taken | The same, per series | Turned away, with the reason |

| Rule | Reason |
|---|---|
| A kind the caller may not read is left out | A key reads its build's SBOMs and runs; a person reads runs where they read internal findings |
| A turned-away SBOM or run is newest only after the newest taken, and is not counted | Only the last is kept |
| A turned-away VEX document or advisory is listed and counted | |
| The list is per build, carrying the product's documents; a product-wide list is not built | |

### Document uploads

Every VEX document and supplier advisory arriving for a product is recorded,
taken or turned away.

| Recorded | Detail |
|---|---|
| Kind, publisher, publisher's name for it | As far as read |
| Client file name, or fetched address | |
| SHA-256 of what arrived | Absent where refused before read whole |
| Uploader, or the supplier's feed | Spelled as a scan's sender |
| Arrival time, outcome, and what a refused sender was told | |
| Statements recorded and set aside | A fact about the moment |

| Rule | Reason |
|---|---|
| One row per arrival, never replaced | Nothing retries on a timer |
| A taken document is recorded in its statements' transaction | |
| A refused document upload is recorded wherever it is turned away after admission: the form bound, the reader, the publisher and name checks | |
| A 500 or above, including a request shed at the upload limit, is not a refusal | |
| A fetched document is recorded where it concerned something shipped, set aside an earlier claim, or arrived whole and was refused (malformed, misshapen, or mismatching its digest) | A distribution lists tens of thousands about nothing here |
| A document a feed could not fetch whole, and a statement set beside the advisories, are not recorded | The supplier's record says what stopped |
| A trusted upstream's documents are not recorded here (`design-docs/upstream.md`) | |

### Document lists

| Rule | Reason |
|---|---|
| A product's VEX documents and supplier advisories are each listed, every arrival newest first | |
| A row names a person by identity and display name, a key by name, or the supplier | |
| The newest taken upload of a document is current: a publisher's VEX document, or an advisory by publisher and name | It is what stands |
| Read by a person who may know the product exists, decided in the store; a key reads none | |

## Limits

| Limit | Detail |
|---|---|
| Document uploads are recorded from v0.11.0 | A database upgraded from v0.10.0 holds statements with no upload record; the administrative trail says who. The lists and the Uploads screen say earlier uploads are unlisted and still apply |
