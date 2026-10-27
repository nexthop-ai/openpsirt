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

A build sends two things, in one request:

| Part | Contents |
|---|---|
| Inventory | Every component that ships, with its dependency edges |
| Suppressions | What the build says it fixed with a patch of its own, or argues does not apply (`design-docs/ingest-claims.md` § Build-declared suppressions) |

| Rule | Reason |
|---|---|
| The document says which format it is, and nothing about the endpoint names one (`design-docs/ingest-formats.md` § The formats read) | An upload takes any format read |
| The vulnerability data is produced here, never sent (REQ-10) | An inventory is reproducible and a vulnerability report is not, so a year-old release re-scans against today's data without a rebuild |
| The scan runs here | A producer running its own scanner measures each product with whatever version its pipeline installed, so two products' counts differ by their build images |
| The model has room for a producer's vulnerability report, and nothing reads one | A run records which scanner produced it and whether this deployment ran it. The upload takes an inventory and suppressions only, the reader skips a `vulnerabilities` array, and every run is recorded as ours |
| Fanning one reported issue out across every occurrence of its component is this deployment's work (REQ-17) | A report names a package at a version and never saw the graph |
| A static analyzer's run arrives through an upload of its own | `design-docs/analysis.md` |

## Producer behavior

Measured against a real producer's output.

| Observation | Consequence |
|---|---|
| The graph is incomplete on purpose | A producer emits the edges it can derive and records the rest as a note. A component with no parent that is not the root is ordinary: the file is not refused, and no parent is synthesized |
| The shipped version is often meaningless | A locally built package carries a placeholder version, with the real identity in its pedigree |
| Identifiers for one issue vary | Which scheme arrives depends on which database matched, so identity spans the aliases (REQ-18) |
| Severity arrives as a word | Often with the method given as unspecified. A number is taken where the report carries one, and the feeds carry numeric scores (REQ-12) |
| A scanner does not read pedigree | Given a fork with its ancestor in `pedigree.ancestors`, the reference scanner matched nothing; given no pedigree and the distribution in the package identifier, it matched 43 advisories |
| A component with no distribution context in its identifier is one nothing matches | That is invisible, never an error |

| Rule | Reason |
|---|---|
| Pedigree is kept | It explains a finding to its reader, and expiry is keyed on the upstream version, because a fork's own revision moves for packaging reasons |
| Suppressions are applied here, never by the producer | A finding a producer filtered out stops appearing with its component, version and pedigree unchanged, which is a scanner fault's signature and the closure REQ-21 makes unsuppressable |

## Request handling

One request is one authorization and one transaction (REQ-06): an inventory
landing without its suppressions reports every carried patch as outstanding.
Nothing expensive runs before a step that may refuse it.

| Order | Step | Reason |
|---|---|---|
| 0 | Admission, before the form is read: the sender is authorized for the build, a declared length past the request bound is refused, and a place is held among the uploads this server reads at once | The form streams to a temporary file as it is read. The handler asks step 1 again |
| 1 | The build is declared and the sender may file against it, in one query naming which of product, branch or tag, or variant is missing (REQ-07) | An unauthorized sender may not measure how far behind the deployment is |
| 2 | The backlog is not too deep | The cheapest refusal once the sender is known; refused later, tens of megabytes are stored and discarded on a deployment already behind |
| 3 | One pass reads what the inventory says about itself and hashes it, and the claim documents are hashed beside it | Every hash covers the bytes that arrived, never a value the sender supplied |
| 4 | The arrival decision | § The arrival decision |
| 5 | The documents are stored and the work queued, in one transaction | A scan row without documents is unreadable, documents without a job are work nobody picks up, and a job without either fails on nothing |

| Refused with | Condition |
|---|---|
| Not found | The product, branch or tag, or variant is not declared. The message names which |
| Bad request | The build time is ahead of this deployment's clock |
| Conflict | Something newer, or something with the same build time, is held; or the product, branch or tag, or variant is retired |
| Unprocessable | The inventory could not be read at all, or more suppression documents arrived than one scan may carry |
| Payload too large | The request is larger than twice the document bound, refused unread where it declares its length |
| Service unavailable | Too much is waiting to be read, or this server is reading as many uploads as `upload.max-concurrent` allows. The second carries a time to retry after |

| Rule | Reason |
|---|---|
| Every refusal past authorization is recorded against the build; one before it records nothing | A sender who may not file against a build cannot write rows about it |
| The reason recorded for an unreadable upload is what was wrong with it, and the producer is handed it among the answer's errors | |
| A refusal by the request's own validation is not recorded | A missing document part or a query parameter past its bound is refused before the operation runs, before anything reads which product it names |
| Already held is a success | The ordinary case is a retry after a timeout that had succeeded |
| The label on a part is not trusted; reading it decides what it is | An ordinary command-line client labels a file as opaque bytes |
| A part above a few kilobytes is spilled to a temporary file for the length of the request | The deployment needs a writable temporary path under a read-only root filesystem, which the packaging provides |
| The temporary path holds at most `upload.max-concurrent` of the largest requests | The setting bounds the uploads one server reads at once across the scan, attachment and import routes, and a place is held until the request is answered, because the spilled files are removed then. Four at the shipped values, each up to 512 MiB for a scan |
| The places are one pool per server, with no share per sender or route | The pool bounds the temporary path. A place is held only after authorization and only until the read deadline, so one sender holding every place is an issued credential sending slowly on purpose |
| An upload a sender may not make spills nothing | A pipeline key for another product, or a person holding no role on it, is refused before the form is read, in the handler's words. A product the sender may not see answers as one nobody declared |

## The arrival decision

Three questions answered from a scan's metadata before its contents are read.

| Order | Question | Reason |
|---|---|---|
| 1 | Is the build time in the future? | Once the current scan is dated ahead, nothing legitimate is newer and that variant takes no further scans |
| 2 | Is this submission already held? | Answered with success. Failing it turns a landed scan into a red build, and the usual response is retry logic that swallows errors |
| 3 | Is it newer than what is held? | Uploads arrive out of order, and an older one replaces today's picture with yesterday's, reopening closed findings with no visible symptom |

| Rule | Reason |
|---|---|
| A submission is identified by everything in it: the inventory and the suppression documents, each hashed as it arrived, folded in a fixed order (REQ-08) | The claims are content. An unchanged inventory beside changed judgments is a new submission and is taken; otherwise the build's arguments about itself are discarded behind a success |
| The claim digests are sorted before they are folded | The order the parts were sent in does not decide whether a retry is recognized |
| A submission taken and unreadable is not held: the same bytes are taken again as a new scan, the failed row and its documents removed and the attempt written in their place | Otherwise the bytes can never be sent again once the fault is fixed. One row per set of bytes remains |
| A failed scan the graph already names keeps its row and identifier, and its documents are replaced | |
| Equal build times are refused, unless the inventory is the one held; then the later arrival is in force | Two documents at one build time is a coin toss over which is current. The same inventory with different judgments is the picture held, re-argued |
| Ordering is by build time, never arrival, with a few minutes of clock skew tolerated | Build machines are seconds out, not hours |
| Two uploads of one file racing to write are answered as a file already held: the loser's insert meets the other's row, and the act runs again in a fresh transaction, where the check finds it | Read in the failed transaction, PostgreSQL has aborted it and MySQL and MariaDB read a snapshot without the row |
| Two refusals of one build racing to write are one recorded refusal | The loser finds no row to replace and meets the other's insert |
| A document stating no build time is dated when it arrives, and the answer says so | Both formats leave it optional and cyclonedx-maven writes none. Dated as the zero time, the first is taken and every later scan of the variant refused as not newer |
| Timestamps are rounded to what the database keeps | No engine stores nanoseconds, so unrounded a value read back is older than the one in memory: a scan compares as newer than itself, and a second file claiming the same build time is accepted |

## Document storage

Documents live in the database: several replicas run (REQ-03), so a file on
the receiving node is not there for the worker, and an object store is
optional.

| Rule | Reason |
|---|---|
| Content is split across rows | A value of tens of megabytes passes the maximum packet size on two of the four engines, a server setting no client can discover. Bounded rows fit every default in circulation and read as a stream |
| Every statement is bounded, not only the one carrying a document | One real image opens tens of thousands of graph rows and over 300,000 findings. One statement each is tens of megabytes of SQL, which two engines refuse and all four hold in memory |
| A membership test over a long list is split and OR-ed | A condition cannot be issued in pieces as a write can, and a subtree or the aliases of a build's dismissals is thousands of identifiers |
| The hash is computed from the bytes as stored | A sender's hash describes the file they meant to send |
| Fixed-width character columns are not used | They blank-pad on some engines, so a hash read back carries trailing spaces and fails an exact match |

## Retention

Nightly scans are transient; tagged releases are kept and fetched back
(REQ-09).

| Stream kind | Contents | Reason |
|---|---|---|
| Nightly branch | Deleted once read | The next night supersedes it, and keeping them grows storage with the calendar |
| Tagged release | Inventory and suppressions both kept | A re-scan years later needs what it contained and what the build argued about its carried patches; without the second, the next re-scan undoes every argument |

| Rule | Reason |
|---|---|
| The record of what arrived outlives the contents: kind, size, and the hash of the bytes as received | Recovery is asking the build to send the file again, and the hash checks the second copy. Without the record, an upload whose contents are gone reads as one that arrived with nothing |
| A document whose contents were released answers 410; on screen, one held is a link and one released is not | A link answering 410 is a control that looks like it works |
| A document is read back a part at a time, so one released while it is read ends in an error: the background reader fails the read, and a download already answered 200 ends short of its declared length and is logged | Part of a document is never parsed as all of it |
| That error is a fault, and the parser passes a failed read beneath it through as one | The receipt carries the fixed sentence, never a refusal of bytes that arrived whole |

## Scan application

A worker claims the scan, reads its documents, and applies what they describe.

| Rule | Reason |
|---|---|
| Every replica serves requests and works the queue | A separate worker deployment is a second thing to run |
| The suppression documents are read here, though applying them waits on the vulnerability scan | An unreadable one is a fault in what the build sent, found while the producer has the build in front of them |
| What the build argued is stored against the build, not the scan | The next vulnerability scan applies it, when the documents may be gone |
| The scan job is queued in the transaction that applies the scan | The graph and the work to scan it commit together. A full backlog does not fail the read: the periodic pass queues the scan once the queue drains |
| A branch's documents are released after the apply commits, and a failure there is logged and leaves the scan applied | |
| A failure is recorded against the scan as well as the job | A retrying job is visible only to the operator |
| A read cut short by a shutdown is not recorded against the scan | Nothing is wrong with the document, and the mark would outlive the retry that stored it |
| The queue is polled: an idle reader asks again after a few seconds, and a queue that is not empty drains at the speed of the work | A notification mechanism exists on one engine and nothing portable replaces it |

## Concurrent scans of one build

Uploads are accepted in arrival order and read in whatever order workers pick
them up.

| Hazard | Guard |
|---|---|
| A scan reaches the reader after a newer one is applied | It is not applied, and is recorded as overtaken, never as a failure. Applied, it would reopen everything the newer one closed |
| Which is newer | The later build time, and at one build time the later arrival, asked in the order the newest scan is chosen in. A build re-sent at one build time with different judgments, whose first read failed, is applied on its retry |
| Scans out of identifier order | The graph stamps every interval with the scan that opened or closed it, so scans are applied in identifier order. A scan with a lower identifier than the build last applied is set aside as overtaken, a failed submission sent again gets a new identifier, and a job still waiting to read a scan replaced this way is set aside too |
| A newer scan arrives while an older one is parsed | Asked again in the applying transaction after the build row is taken, as well as before the parse. A parse takes minutes |
| The newer one is unread, and then fails | Once a scan fails for the last time, the newest that still stands is read again, where the build does not show it and nothing is on its way to reading it. A scan can be read more than once, and its receipt reports the latest reading |
| A read fails and its retry succeeds | The failed attempt marks the scan failed, so its receipt says so while the retry waits. The applying attempt makes it accepted, clears the failure, and makes it the build's newest, in the transaction that applies it. The scan it overtook is not read again while a retry is to come, or it would be applied first and reopen what the newer one closes |
| Two applies for one build interleave | Applying takes the build row first, by an ordinary update, so every engine locks and the second worker waits. Both would otherwise compute and write the same difference |

## Scheduled rescanning

A release built a year ago keeps its components and gets a different answer
every month, so a pass queues a scan for every build holding an inventory not
scanned within the interval (REQ-10).

| Rule | Reason |
|---|---|
| A build with no inventory is not scanned | An empty answer reads exactly like a clean one |
| A build already waiting is not queued again | The pass looks far more often than anything is due, since an administrator may shorten the interval |
| What is queued is compared as identifiers, never joined | A job's reference is text and a build's identifier a number, and no conversion inside a query is spelled alike on the four engines |
| A pass queues a slice at a time | A deployment tracking many builds would fill the queue in one pass and push arriving inventories behind work that is not urgent |
| A full queue stops the pass, and what is due stays due | A full queue is a fact about how much is in flight, not a failure |
| One replica asks, settled by a lease (`design-docs/queue.md`) | Two reading the list at once would both see a build as due |
| The interval is a setting, shipping at a day | The scanner's databases are published daily |
| Nothing is discovered | The component list comes from the build; what moves between scans is what is known about it |

## Limits

| Limit | Detail |
|---|---|
| A build dated on arrival is ordered by when it was sent | An older undated document sent late is taken as the newest. Documents stating a time are ordered by it |
