# Ingest

A scan from arrival to application: the upload, the arrival decision, storage
and retention, and applying a scan.

Satisfies REQ-03, REQ-06, REQ-07, REQ-08, REQ-09, REQ-10, REQ-12, REQ-17,
REQ-18, REQ-21.

## Contents

- [The upload](#the-upload)
- [Producer behavior](#producer-behavior)
- [Request handling](#request-handling)
- [The arrival decision](#the-arrival-decision)
- [Document storage](#document-storage)
- [Retention](#retention)
- [Scan application](#scan-application)
- [Concurrent scans of one build](#concurrent-scans-of-one-build)
- [Scheduled rescanning](#scheduled-rescanning)
- [Limits](#limits)

## The upload

A build sends, in one request, its inventory (every component that ships, with
its edges) and its suppressions (`design-docs/ingest-claims.md`
§ Build-declared suppressions). An upload is accepted, queued and answered
202 before it is read (REQ-06).

| Rule | Reason |
|---|---|
| The document names its format; the endpoint names none (`design-docs/ingest-formats.md`) | |
| The vulnerability scan runs here, on data produced here, never sent (REQ-10) | An inventory is reproducible and a report is not, and a producer's own scanner makes products incomparable |
| The model has room for a producer's vulnerability report; nothing reads one, the reader skips `vulnerabilities`, and every run is recorded as ours | A run records its scanner and whether this deployment ran it |
| One reported issue fans out across every occurrence of its component here (REQ-17) | A report never saw the graph |
| A static analyzer's run has an upload of its own | `design-docs/analysis.md` |

## Producer behavior

| Observation | Consequence |
|---|---|
| The graph is incomplete on purpose | A parentless non-root component is ordinary: not refused, no parent synthesized |
| The shipped version is often a placeholder | The real identity is in the pedigree |
| One issue arrives under several schemes | Identity spans the aliases (REQ-18) |
| Severity arrives as a word, often with the method unspecified | A number is taken where a report carries one; the feeds carry numbers (REQ-12) |
| A scanner does not read pedigree | A fork with `pedigree.ancestors` matched nothing; the same package with its distribution in the identifier matched 43 advisories |
| A component with no distribution context in its identifier matches nothing | Silently |

| Rule | Reason |
|---|---|
| Pedigree is kept | It explains a finding, and expiry keys on the upstream version, since a fork's revision moves for packaging reasons |
| Suppressions are applied here, never by the producer | A finding filtered upstream vanishes unchanged, which reads as the scanner fault REQ-21 makes unsuppressable |

## Request handling

One request is one authorization and one transaction: an inventory landing
without its suppressions reports every carried patch as open.

| Order | Step | Reason |
|---|---|---|
| 0 | Admission before the form is read: the sender authorized for the build, a declared length past the request bound refused, a place held among the uploads this server reads at once | The form streams to a temporary file. The handler asks step 1 again |
| 1 | The build is declared and the sender may file, one query naming which of product, branch or tag, or variant is missing (REQ-07) | An unauthorized sender may not measure the backlog |
| 2 | The backlog is not too deep | Cheapest refusal once the sender is known |
| 3 | One pass reads the inventory's header and hashes it; claim documents are hashed beside it | Every hash covers the bytes that arrived |
| 4 | The arrival decision | § The arrival decision |
| 5 | Documents stored and work queued, in one transaction | Scan row, documents and job exist together or not at all |

| Refused with | Condition |
|---|---|
| Not found | The product, branch or tag, or variant is not declared; the message names which |
| Bad request | The build time is ahead of this deployment's clock |
| Conflict | Something newer, or with the same build time, is held; or the product, branch or tag, or variant is retired |
| Unprocessable | The inventory cannot be read at all, or more suppression documents arrived than one scan may carry |
| Payload too large | Over twice the document bound, refused unread where the length is declared |
| Service unavailable | Too much is waiting, or the server reads `upload.max-concurrent` uploads already; the second carries a retry time |

| Rule | Reason |
|---|---|
| A scan refused past authorization is recorded against the build (`design-docs/ingest-receipts.md` § Last upload per build) | |
| A refusal before it, such as a name not declared or a sender who may not file there, records nothing | A sender who may not file cannot write rows about a build |
| A refusal by the request's own validation is not recorded | A missing part or an over-long query parameter is refused before the operation reads which product it names |
| An unreadable upload is recorded with what was wrong, and the producer is handed it among the errors | |
| Already held is a success | The ordinary case is a retry after a timeout that succeeded |
| A part's label is not trusted | A command-line client labels a file as opaque bytes |
| A part over a few kilobytes spills to a temporary file for the request | The packaging provides a writable temporary path under a read-only root |
| The temporary path holds at most `upload.max-concurrent` of the largest requests | The setting bounds uploads read at once across the scan, attachment and import routes, held until answered, when spilled files go. Four at the shipped values, up to 512 MiB a scan |
| The places are one pool per server, with no share per sender or route | A place is held only after authorization and until the read deadline |
| An upload a sender may not make spills nothing | It is refused before the form is read; a product the sender may not see answers as undeclared |

## The arrival decision

Answered from metadata before contents are read.

| Order | Question | Reason |
|---|---|---|
| 1 | Is the build time in the future? | A scan dated ahead blocks every later one |
| 2 | Is this submission already held? | Answered with success; failing a landed scan breeds retry logic that swallows errors |
| 3 | Is it newer than what is held? (REQ-06) | Uploads arrive out of order, and an older one silently reopens closed findings |

| Rule | Reason |
|---|---|
| A submission is identified by the inventory and the suppression documents, each hashed as arrived, folded in a fixed order (REQ-08) | Unchanged inventory beside changed judgments is new, and is taken |
| The claim digests are sorted before folding | Part order does not decide whether a retry is recognized |
| A submission taken and unreadable is not held: the same bytes are taken again, the failed row and documents replaced by the attempt | One row per set of bytes, resendable once fixed |
| A failed scan the graph names keeps its row and identifier, and its documents are replaced | |
| Equal build times are refused unless the inventory is the one held, and then the later arrival is in force | The same inventory with new judgments is the picture held, re-argued |
| Ordering is by build time, with a few minutes of clock skew tolerated | |
| Two uploads of one file racing are answered as already held, the loser re-run in a fresh transaction | In the failed one, PostgreSQL has aborted and MySQL and MariaDB read a snapshot without the row |
| Two refusals of one build racing are one recorded refusal | |
| A document stating no build time is dated on arrival, and the answer says so | Both formats leave it optional and cyclonedx-maven writes none; dated zero, every later scan is refused as not newer |
| Timestamps are rounded to what the database keeps | No engine stores nanoseconds, so a scan would compare newer than itself |

## Document storage

Documents live in the database: replicas share no filesystem (REQ-03), and the
object store is optional.

| Rule | Reason |
|---|---|
| Content is split across rows | Tens of megabytes in one value pass two engines' maximum packet size, which no client can discover |
| Every statement is bounded | One real image opens tens of thousands of graph rows and over 300,000 findings, too much SQL for two engines |
| A membership test over a long list is split and OR-ed | A subtree or a build's dismissed aliases is thousands of identifiers |
| The hash is computed from the bytes as stored | |
| Fixed-width character columns are not used | They blank-pad on some engines, breaking an exact match on a hash |

## Retention

Nightly scans are transient; tagged releases are kept and fetched back
(REQ-09).

| Stream kind | Contents | Reason |
|---|---|---|
| Nightly branch | Deleted once read | The next night supersedes it |
| Tagged release | Inventory and suppressions kept | A re-scan years later needs both, or it undoes every argument |

| Rule | Reason |
|---|---|
| Kind, size and hash of what arrived outlive the contents | Recovery is a re-send, which the hash checks |
| A released document answers 410, and on screen is no link | |
| A document is read a part at a time, so one released mid-read ends in an error: the reader fails, and a download already answered 200 ends short and is logged | Part of a document is never parsed as all of it |
| That error is a fault, passed through the parser as one | The receipt carries the fixed sentence, never a refusal of whole bytes |

## Scan application

A worker claims the scan and reads its documents, then applies what they
describe in one transaction (REQ-06).

| Rule | Reason |
|---|---|
| Every replica serves requests and works the queue | |
| Suppression documents are read here, though applied after the vulnerability scan | An unreadable one is reported while the producer has the build in front of them |
| What the build argued is stored against the build | The next scan applies it, when the documents may be gone |
| The scan job is queued in the applying transaction; a full backlog leaves it to the periodic pass | |
| A branch's documents are released after commit; a failure there is logged | |
| A failure is recorded against the scan as well as the job | |
| A read cut short by shutdown is not recorded against the scan | Nothing is wrong with the document |
| The queue is polled every few seconds when idle | Notification exists on one engine only |

## Concurrent scans of one build

| Hazard | Guard |
|---|---|
| A scan read after a newer one applied | Recorded as overtaken, never failed, and not applied (REQ-06) |
| Which is newer | The later build time, then the later arrival; a re-send at one build time with new judgments whose first read failed is applied on retry |
| Scans out of identifier order | Intervals are stamped with scan identifiers, so scans apply in identifier order; a lower one than last applied is overtaken, a re-sent failure gets a new identifier, and a job waiting on a replaced scan is set aside |
| A newer scan arrives during a parse | Asked again after the build row is taken, as well as before |
| The newer one fails | After its last failure, the newest still standing is read again where the build lacks it and nothing is reading it; the receipt reports the latest reading |
| A read fails and its retry succeeds | The failure marks the scan failed meanwhile; the applying attempt clears it and makes it newest. The overtaken scan is not re-read while a retry is to come |
| Two applies for one build | Applying takes the build row by an ordinary update, so the second waits on every engine |

## Scheduled rescanning

A pass queues a scan for every build holding an inventory not scanned within
the interval (REQ-10).

| Rule | Reason |
|---|---|
| A build with no inventory is not scanned | An empty answer reads as a clean one |
| A build already waiting is not queued again, compared as identifiers, never joined | A job's reference is text and a build's identifier a number, with no portable conversion |
| A pass queues a slice at a time, and stops at a full queue with what is due left due | Arriving inventories are not pushed behind routine work |
| One replica asks, under a lease (`design-docs/queue.md`) | |
| The interval is a setting, shipping at a day | The scanner's databases are published daily |
| Nothing is discovered | The components come from the build |

## Limits

| Limit | Detail |
|---|---|
| A build dated on arrival is ordered by when it was sent | An older undated document sent late is taken as newest |
