# Upload receipts

What a producer and a person read back about uploads: receipts, a build gone
quiet, documents retrieved, and the list of every kind of upload.

Satisfies REQ-09, REQ-13, REQ-19, REQ-44, REQ-52.

## Contents

- [Last upload per build](#last-upload-per-build)
- [Receipts](#receipts)
- [Receipt counts](#receipt-counts)
- [Document retrieval](#document-retrieval)
- [Upload listing](#upload-listing)
- [Limits](#limits)

## Last upload per build

A build nothing files against reports no new findings, closes nothing, fails
nothing, and every number about it holds still. Every declared build is
reported with when a scan last arrived, longest-silent first, and whether that
is longer ago than the deployment allows.

| Rule | Reason |
|---|---|
| Longest-silent first | An alphabetical list buries the one that stopped |
| A build nothing was ever filed against is reported, measured from declaration | A name nobody declared is refused loudly; a declared build never pointed at fails silently |
| How long counts as quiet is a setting, shipping at a week | A nightly build missing a night is no alert, and a pipeline switched off is noticed that week |
| It is a whole number of days, refused otherwise; a stored value between two days reads as the later whole day everywhere | The scanning screen states and flags in days, so screen and alert agree |
| A release out of support is never reported as quiet (REQ-52), and is still listed with how long it has been | "Not scanned, and that is fine" and "not listed" are different answers |
| Only a scan that could be read counts as heard from | A build whose upload fails to parse nightly is what this report is for |
| An upload turned away is recorded against the build, and the report says when and why | Quiet says nothing arrived, not whether anybody tried: a pipeline nobody wired up against one failing nightly and reporting success to its own log. A refusal never becomes a scan |
| One refusal per build, replaced | A producer retrying an unreadable document writes one a minute, and the question is whether it is refused now |
| Recording a refusal is best-effort, there alone | Failing it would turn a refusal the producer needs to read into a fault they cannot |
| It is a person's question | A pipeline key reads the receipts of a build it may upload to and nothing more |

## Receipts

The acceptance a build received was issued before anything was read, so it
cannot carry the answer. What was filed against a build is listed newest
first, each with how far it got.

| State | Meaning |
|---|---|
| Taken | Not yet read |
| Read | Awaiting a vulnerability scan |
| Done | Scanned |
| Refused | With the reason |

| Rule | Reason |
|---|---|
| The four states are this deployment's, never the queue's | Reading and scanning are two jobs, and a producer has no business knowing which queue holds its work |
| A sender is recorded as a key or a person, with its identifier | A key's name is unique only among keys in force, and a key may share a person's name, so a name would credit the wrong sender |
| A key reads every receipt of a build it may upload to, whoever sent it (REQ-44) | A rotated or second key re-sends what another sent, and the answer is the first upload's scan |
| Which builds a key reads is decided in the store, from the subject | A handler's narrowing is one the next handler forgets. A key pinned to one release or variant reads that build's receipts and refuses every other; a product-wide key reads every build of its product |
| A read whose job died is failed on the receipt, in fixed words | Marking the scan row may be what failed, and the job's last error carries whatever failed, a dropped connection's address included. A refusal reaches the receipt through the scan row |
| The run answering an upload is the earliest successful run to finish after it was parsed; a failed run answers only while nothing has succeeded since | A run covers a build, not an upload. Taking the earliest run whatever became of it, one scanner crash poisons every waiting receipt for ever |
| Each finding records the run that opened it and the run that closed it, and every receipt item carries each run's scanner and database versions (REQ-13) | A feed shipping bad data for a week is corrected afterwards, and the work done on it has to be found |
| The opening run is recorded, never the newest | A later run finding the same thing does not reopen it |
| The versions are on every receipt the run answers | They are a property of the run; a page spanning a scanner upgrade is what this screen is read to notice |
| No run is invented where there is none | A finding a person recorded (REQ-19) was produced by nobody, and one whose run was pruned is still a finding |

## Receipt counts

| Count | Rule |
|---|---|
| What each run changed | Counted when asked, from the runs the findings point at, as issues at components. Attributed to the newest upload the run covered and omitted from the rest, since one fact down three rows reads as three changes. Only an upload that was read counts as covered, by arrival order |
| Components described, and components placed in the graph | Stored once a scan is read. The pair matters: a component nothing places is ordinary, and a document placing none is a list, whose findings cannot answer "why is this here" |
| Names gained, lost and held at different versions since the upload before | Worked out when read (`design-docs/data-model.md` § Inventory delta), against what the build held before, whoever sent it, since two keys for one variant describe one artifact. A build that expected three dependency moves and got two hundred had its base image or lockfile change |

| Rule | Reason |
|---|---|
| A key that reads no findings reads these counts | They are arithmetic over the documents that key sent |
| Which names moved is a listing of its own, reached on the receipt's terms | |
| An upload moving much of a build is told to whoever may read the product (`design-docs/notifications.md` § An inventory that moved sharply), worked out after the writes commit; a message that cannot be composed is logged | The inventory is stored, so the upload does not fail |
| The counts read only the page's runs' findings, through an index on each run column carrying every column the count reads | Unindexed, a count reads every finding the build ever had, growing with the calendar; covered, it never reads the table |
| A page whose runs opened most of the build reads most of it | A first scan opens every finding, so until fifty scans follow it, the page holds the run that opened everything |
| An index-only read depends on the visibility map, so a finding written since the last vacuum is read from the table; the finding table is vacuumed after a fiftieth of it changes (`design-docs/database.md` § Indexes) | |

`design-docs/ingest-measurements.md` § Receipt cost has the page on all four
engines over a year: the two indexes cost a night up to 7 percent.

## Document retrieval

A tag's documents are kept so a release can be re-scanned (REQ-09), and
returned so "send me the SBOM you scanned for v2.4" is not answered from a
build system whose copy may have moved.

| Rule | Reason |
|---|---|
| The bytes as they arrived, never parsed or re-serialized | The receipt's hash covers what was received |
| Named through the scan it belongs to | Whoever reads the receipt reads what it describes; a document identifier resolving alone would be a second way in |
| Narrowed in the store | A key reads what was filed on a build it may upload to, and the two endpoints cannot differ |
| Named `.xml` or `.json` by its encoding, told from its first character by the reader's rule | A copy named for the other encoding is misread by any tool going by extension |

## Upload listing

Each kind of upload has its own path, body and receipt.

| Kind | Sent to | Listed by |
|---|---|---|
| SBOM | The build | Its receipts (§ Receipts) |
| Static analysis run, as SARIF | The build | Its runs (`design-docs/analysis.md` § Receipts) |
| VEX document | The product | Its uploads (§ Document uploads) |
| Supplier advisory | The product, by upload or by a supplier's feed | Its uploads (§ Document uploads) |

One read lists every kind for a build, with how many of each are held and what
became of the newest, reading each kind's own list, a page of one, so each
kind's rule for who reads it applies unchanged.

| Status | SBOM | Static analysis run | VEX document, supplier advisory |
|---|---|---|---|
| In progress | Taken, being read or scanned | Queued, or waiting for the build's inventory | — |
| Completed | Scanned | Applied, or kept beside a run built later | Its statements recorded |
| Failed | Taken and unusable, with the reason | Unreadable, or its tool did not run, with the reason | — |
| Refused | The last upload turned away, where it came after the newest taken | The same, per series | Turned away, with the reason |

| Rule | Reason |
|---|---|
| A kind the caller may not read is left out | A pipeline key reads the SBOMs and runs of a build it may send to. A person reads the runs where they read internal findings in the product |
| An SBOM or run turned away is the newest only where it came after the newest taken | It is kept once per build or series and replaced, so an older refusal says nothing of the upload after it |
| The count is what the kind's own list holds | An SBOM or run turned away is not counted, since only the last is kept. A VEX document or supplier advisory turned away is listed and counted |
| The list is per build, with the product's documents on every build of it | The SBOM and SARIF paths name a build and the other two a product. A product-wide list of every build's uploads is not built |

### Document uploads

Every VEX document and supplier advisory arriving for a product is recorded,
taken or turned away. Its statements hold what it says.

| Recorded | Detail |
|---|---|
| Kind, publisher, and the publisher's name for it | As far as it was read; empty where it was turned away first |
| The client's file name, or the address a feed fetched | |
| SHA-256 of the bytes that arrived | For a fetched advisory as for an upload. Absent where turned away before it was read whole |
| Who uploaded it, or which supplier's feed fetched it | Spelled as a scan's sender is, so a key and a person are never one sender |
| When it arrived | |
| Completed or refused, and what the sender was told | |
| Statements recorded and earlier ones set aside | As taken: a fact about the moment, so stored |

| Rule | Reason |
|---|---|
| One row per arrival, never replaced | An administrator uploads by hand and a feed steps past a document once read or refused; nothing retries on a timer |
| A taken document is recorded in the transaction recording its statements | They cannot disagree about whether it was taken |
| A refusal is recorded wherever the upload is turned away once its sender is admitted: by the form bound before the operation runs, by the reader, and by the publisher and name checks | |
| An answer of 500 or above is not a refusal, a request shed at the upload limit included | It is this deployment failing |
| A fetched document is recorded where it said something about a component this product ships, set aside something an earlier copy said, or arrived whole and was refused | A distribution lists tens of thousands of advisories about nothing shipped here |
| A feed's refusal is a document that arrived whole and was stepped over: malformed, misshapen, or mismatching its served digest, with the publisher and name where parsed that far | |
| A document a feed could not fetch whole is not recorded: withdrawn, refused by the publisher, past the size bound, or at an address the client refuses; nor is a statement set listed beside the advisories | Nothing arrived, and the supplier's record says what stopped the pass |
| A trusted upstream's documents are not recorded here | They are read on a schedule from the upstream (`design-docs/upstream.md`) |

### Document lists

| Rule | Reason |
|---|---|
| A product's VEX documents and its supplier advisories are each a list of these records, every arrival a row, newest first | Taken and turned away alike |
| A row names who uploaded it, a person by sign-in identity and display name, a key by name, or the supplier whose feed fetched it | |
| The newest taken upload of a document is marked current: a publisher's VEX document, or one advisory by publisher and its name | What the current one said is what stands |
| Read by a person who may know the product exists, decided in the store | As SBOM receipts are for a person. A pipeline key reads none of these |

## Limits

| Limit | Detail |
|---|---|
| Document uploads are recorded from v0.11.0 | A database upgraded from v0.10.0 holds statements and no record of the uploads that made them; who uploaded them is in the administrative trail. The lists, and an empty tab on the Uploads screen, say earlier uploads are not listed and their statements still apply |
