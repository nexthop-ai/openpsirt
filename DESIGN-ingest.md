# Ingest

What happens to a scan between arrival and application.

Satisfies REQ-03, REQ-05, REQ-06, REQ-07, REQ-08, REQ-09, REQ-10, REQ-11,
REQ-12, REQ-13, REQ-14, REQ-16, REQ-17, REQ-18, REQ-31, REQ-44, REQ-66,
REQ-69.

## Contents

- [What arrives](#what-arrives)
- [Producer behavior](#producer-behavior)
- [Request handling](#request-handling)
- [The arrival decision](#the-arrival-decision)
- [Document storage](#document-storage)
- [Retention](#retention)
- [Reading a scan](#reading-a-scan)
- [Concurrent scans of one target](#concurrent-scans-of-one-target)
- [Parsing](#parsing)
- [Tolerated and refused](#tolerated-and-refused)
- [Unread fields](#unread-fields)
- [Build-declared suppressions](#build-declared-suppressions)
- [Scheduled rescanning](#scheduled-rescanning)
- [Scanner warnings](#scanner-warnings)
- [Scan coverage](#scan-coverage)
- [Receipts](#receipts)
- [Reading back a document](#reading-back-a-document)
- [Administrator-supplied VEX](#administrator-supplied-vex)
- [The offline scanner database](#the-offline-scanner-database)
- [Analyzer findings](#analyzer-findings)
- [Limits](#limits)

## What arrives

A build sends two things, in one request:

| Part | Contents |
|---|---|
| Inventory | Every component that ships, with its dependency edges |
| Suppressions | Findings the build has already argued are not applicable, usually because it carries a patch |

**CycloneDX is the format read. SPDX is intended and not built** (REQ-05); what
is missing is a fixture carrying enough metadata to write the reader against.
`TODO.md` records it.

**The vulnerability data is produced here rather than sent.** The inventory is
reproducible and a vulnerability report is not, since new issues are disclosed
daily, so a producer emitting both would have to give up one of the two
properties. Keeping the inventory standalone lets a year-old release be
re-scanned against today's data without rebuilding anything.

Running the scan here also makes counts comparable between products. A producer
running its own scanner measures each product with whatever version its pipeline
installed, so a difference between two products may be only a difference in
their build images.

**The model keeps room for a producer-supplied vulnerability report, and nothing
reads one.** A run records which scanner produced it and whether this deployment
ran it, so a producer's own findings would carry their provenance. The upload
takes an inventory and suppressions and nothing else, the reader skips a
`vulnerabilities` array, and every run is recorded as ours.

**Fanning one reported issue out across the places it occupies is this
deployment's work.** A vulnerability report says "this package at this version"
and stops; it never saw the graph. That step is where one line in a report
becomes the number of decisions a person has to make.

## Producer behavior

Measured against a real producer's output rather than assumed from the
specification.

| Observation | Consequence |
|---|---|
| The graph is incomplete on purpose | Edges are emitted where the producer can derive them; what it cannot resolve it records as a note. A component with no parent that is not the root is ordinary. Refusing the file rejects a legitimate scan, and synthesizing a parent reports a dependency nobody declared |
| The shipped version is often meaningless | A locally-built package commonly carries a placeholder version, with the real identity in its pedigree |
| Identifiers for one issue vary | The same vulnerability arrives under different schemes depending on which database matched it. That choice is a scanner's preference, so identity spans the aliases (REQ-18) |
| Severity arrives as a word | A rating, not a vector, often with the method given as unspecified. A number is taken where the report carries one, and the feeds carry numeric scores (REQ-12) |

**A scanner does not read pedigree.** Measured: given a forked package carrying
its ancestor in `pedigree.ancestors`, the reference scanner matched nothing;
given the same package with no pedigree at all but with its distribution named
in the package identifier, it matched **forty-three advisories**. What it matches
on is the identifier and the distribution context.

Pedigree is kept for two other reasons: it explains a finding to whoever reads
it, and expiry is keyed on the upstream version, because a fork's own revision
moves for packaging reasons unrelated to whether a vulnerability is still there.

**Suppressions are applied here, not upstream.** The build's judgment about its
own carried patches is never refuted; what changed is where it is applied.
Receiving results a producer already filtered made a suppressed finding simply
stop appearing — component present, version unchanged, pedigree unchanged —
which is indistinguishable from a scanner fault, and lands in the bucket REQ-21
makes unsuppressable by design.

## Request handling

One request means one authorization and one transaction. A build whose inventory
landed and whose suppressions did not would have every carried patch reported as
an outstanding vulnerability.

The order is chosen so nothing expensive happens before anything that might
refuse it.

| Order | Step | Placement reason |
|---|---|---|
| 1 | Is the target declared, and may this sender file against it? | One query, naming which of product, stream or variant is missing. First, because how far behind the deployment is is not something an unauthorized sender may measure |
| 2 | Is the backlog too deep? | The cheapest refusal once the sender is known. Deciding afterwards means storing tens of megabytes and discarding them, on a deployment already behind |
| 3 | What does the inventory say about itself, and what is its hash? | One pass over the file answers both. The hash covers the bytes that arrived, not a value the sender supplied |
| 4 | The arrival decision | Below |
| 5 | Store the documents and queue the work | One transaction. A scan row without documents is unreadable, documents without a job are work nobody picks up, and a job without either is a worker failing on something that was never there |

| Refused with | Condition |
|---|---|
| Not found | The product, stream or variant is not declared. The message names which |
| Bad request | The build time is ahead of this deployment's clock |
| Conflict | Something newer, or something with the same build time, is already held |
| Unprocessable | The inventory could not be read at all |
| Service unavailable | Too much is already waiting to be read |

**Already held is a success**, because the ordinary case is a retry after a
timeout that had in fact succeeded.

| Rule | Reason |
|---|---|
| The label on a part is not trusted | What a part is gets decided by reading it. A build pushing a file with an ordinary command-line client labels it as opaque bytes |
| A large part is not held in memory | Parts above a few kilobytes are spilled to a temporary file for the length of the request. The deployment therefore needs a writable temporary path despite a read-only root filesystem, which the packaging provides |

## The arrival decision

Three questions answered from a scan's metadata before anything reads its
contents. Parsing is expensive; refusing is not.

| Order | Question | Refusal reason |
|---|---|---|
| 1 | Is the build time in the future? | Once the current scan is dated ahead, nothing legitimate is ever newer and that variant takes no further scans at all |
| 2 | Have we already taken this exact file? | Answered with success. Failing it turns a landed scan into a red build, and the usual response is retry logic that swallows errors |
| 3 | Is it newer than what is held? | Uploads do not arrive in the order they were made. Taking an older one replaces today's picture with yesterday's, reopening closed findings with no visible symptom |

**Equal build times are refused.** Neither is newer, so choosing between them
would be a coin toss over which picture is current.

**Ordering is by build time, not arrival.** A few minutes of clock skew is
tolerated, because build machines are seconds out rather than hours.

**Timestamps are rounded to what the database keeps.** Go carries nanoseconds and
no supported engine stores them, so without rounding a value written and read
back is fractionally *older* than the one in memory: a scan compares as newer
than itself, and a second file claiming the same build time is accepted. A latent
fault on every engine, exposed by one and passed by the others on timing luck.

## Document storage

Documents live in the database. More than one replica runs, so a file on the
receiving node is not there for whoever takes the work, and an object store is
optional by requirement, so ingest cannot make it mandatory.

| Rule | Reason |
|---|---|
| Content is split across rows | A single value of tens of megabytes runs into a maximum packet size on two of the four engines, and that limit is server configuration rather than anything a client can discover. Bounded rows stay inside every default in circulation and let a document be read as a stream |
| Every statement is bounded, not only the one carrying a document | One real image opens tens of thousands of graph rows and produces over three hundred thousand findings. Sent as one statement each, those are tens of megabytes of SQL, which two engines refuse outright and all four hold in memory |
| The hash is computed from the bytes as they are stored | A hash the sender supplied describes the file they meant to send |

## Retention

| Stream kind | Contents | Reason |
|---|---|---|
| Nightly branch | Deleted once read | The next night supersedes it, and keeping them grows storage with the calendar rather than with what is tracked |
| Tagged release | Inventory and suppressions both kept | Re-scanning years later needs what it contained *and* what the build had already argued about its carried patches. Keeping only the first would undo every one of those arguments on the next re-scan |

**The record of what arrived outlives the contents**: kind, size, and the hash of
the bytes as received. A re-parse means asking the build to send the file again,
which is the whole recovery path, and without the hash the second copy is taken
on trust. An upload whose contents are gone would otherwise read back as one
that arrived with nothing.

**A document whose contents were released answers 410, not 404.** On screen, one
still held is a link and one released is not: a link that answered 410 is a
control that looks like it works.

## Reading a scan

A worker claims the scan, reads its documents, and applies what they describe.
Every replica does both; a separate worker deployment would be a second thing to
run and get wrong for an installation this size.

**The suppression documents are read here** even though applying them waits on
the scan itself. A document that cannot be read is a fault in what the build
sent, and finding that out while the producer still has the build in front of
them is worth more than finding out later. What the build argued is stored
against the **target** rather than the scan, because it is what the next
vulnerability scan has to apply, and by then the documents may be gone.

**A failure is recorded against the scan, not only against the job.** A job that
keeps retrying is visible only to whoever operates the deployment, which is the
wrong person to be the only one who knows.

**A read cut short by a shutdown is not recorded against the scan.** Nothing is
wrong with the document, and marking it failed would leave the receipt saying so
after a retry had stored it.

**The queue is polled.** A notification mechanism exists on one of the four
engines and nothing portable replaces it, so an idle reader asks again after a
few seconds. A queue that is not empty drains at the speed of the work rather
than the speed of the poll.

## Concurrent scans of one target

Uploads are accepted in arrival order and read in whatever order workers pick
them up.

| Hazard | Guard |
|---|---|
| A scan reaches the reader after a newer one has been applied | An overtaken scan is not applied, and that is recorded rather than treated as a failure. Applying it would replace today's picture with yesterday's and reopen everything the newer one closed |
| The newer one may not have been read yet, and may then fail | Once a scan has failed, the newest that still stands is read again, where the build does not already show it and nothing is on its way to reading it. A scan can be read more than once, and the latest reading is what its receipt reports |
| Two applies for one target interleaving | Applying takes the target row first — an ordinary update, so every engine takes the lock and the second worker waits. Both would otherwise read the same open rows, compute the same difference and write it |

## Parsing

**The header is read separately from the contents.** Everything the arrival
decision turns on is answered by a pass that skips the contents. Parsing a file
about to be refused is work nobody asked for, and on the largest producer it is
most of the cost of taking the file. Skipping is not free — the reference
producer sorts its keys, putting tens of thousands of components ahead of the
metadata — but walking past a value is far cheaper than building something from
it.

**Read as a stream, with four bounds, all settable per read**: document size,
component count, edge count, and nesting depth. Edges need their own bound,
because a thousand components can declare a million edges between them.

**The depth bound is why the document is walked rather than decoded.** Decoding
has no depth limit anyone can set, so a file nested far enough to exhaust the
process would be discovered by running out of memory. Nesting is bounded
everywhere, including inside the parts nothing reads.

**An oversized document is refused as oversized.** Truncating it and letting the
reader fail reports a malformed file, which sends whoever sees the message
looking at their build instead of at the limit.

| Rule | Reason |
|---|---|
| The file's own identifiers resolve edges and are then discarded | Those names are the producer's, and nothing guarantees they are stable between builds or consistent between producers. The test replaces every identifier in a real document and asserts the components, identities and graph are unchanged |
| Two components sharing one identifier are refused | Every edge naming it would be a coin toss |
| Nesting becomes an edge | A component containing components is the producer stating what is assembled from what. For some producers it is the only structure stated |
| An edge whose ends resolve to one component is dropped and counted | Content-derived identity can discover that two of a document's identifiers describe the same component. The producer could not have known, so it is not a producer error, and storing it would be a component depending on itself |

## Tolerated and refused

The specification requires very little, and producers differ enormously in what
they fill in. **A document that is valid and sparse is not a broken one.**

| Tolerated | Behavior |
|---|---|
| The document names no component of its own | What the scan was filed against stands in. The root is excluded from identity and expiry anyway |
| A component states no version | Kept and counted. What it costs is matching, and it ships either way |
| An edge names something the document never describes | Dropped and counted. The missing component is not invented |
| Unread fields | Ignored. A producer carrying more than is read is the ordinary case |

**The counts matter as much as the tolerance.** Each is a number that should be
stable build to build, so a change says the producer changed.

| Refused | Reason |
|---|---|
| Not the format read, or a major version not written against | A reader that guesses eventually guesses wrong on a file that looks close enough |
| A component with no name | It cannot be identified, so it cannot be tracked |
| Two components sharing one identifier | Every edge naming it is ambiguous |
| A build time nothing can read | The build time orders scans against each other |
| Past any of the four bounds | A broken or hostile file has to fail rather than exhaust the process |

**Reading is all or nothing.** A partial inventory is indistinguishable from a
product that shrank, and acting on one closes findings that are still somebody's
problem. This concerns a *failed parse* rather than producer variation.

Everything a refusal quotes back came from the file, so what it quotes is bounded
in length: an error is one of the few places a scan file's contents reach a
person.

## Unread fields

A field nobody reads because it was considered and a field nobody reads because
nobody noticed it look identical in the code.

**Every key path the recorded documents contain is written down**, with what is
done with it: acted on, or seen and deliberately left alone. A document
containing a path that list does not have fails the check. The reverse is checked
too — a path the reader acts on that no recorded document contains is a branch
nothing exercises.

This checks the recorded documents, not what is accepted. The reader itself
ignores anything it does not recognize.

**A minor revision of the format is read, and is now shown to be.** The reader
checks the major version and refuses what it has not been written against;
anything within that major version parses. That made every revision accepted **by
construction rather than by evidence**, and the gap was live: the reference
producer moved to 1.7 while every fixture stated 1.6, so the inventory this
deployment's own image carries and the one the demo ingests were both revisions
nothing had been tested against.

A fixture at the newer revision closed it — the document the image ships, read
through the same reader, asserting the parts a revision could move: the root, the
component count, the edges, and the package identifiers the graph is keyed on. It
also brought eight key paths nothing had decided about.

## Build-declared suppressions

A build's claims arrive two ways, and they are not equally precise.

| Source | Precision |
|---|---|
| On the component | A patch in a component's pedigree recording which vulnerability it fixes. It arrives attached to the thing it is about |
| In a document of its own | Statements naming what they apply to by package identifier: one version, every version of a package, or a whole source tree |

Both are read into one shape with the origin recorded, because the second can
point at something that cannot be resolved and the first cannot.

**The vocabulary is kept rather than translated.** A build saying "we carry the
fix" and one saying "the vulnerable code is never reached" make different claims.
Two of the four statuses remove a finding from what somebody has to look at; the
other two say the build looked.

**A carried patch reports as fixed.** The vulnerable code was there and a patch
resolved it, which is not the same statement as the vulnerability never having
applied. Only what a patch *claims* is read: a patch names a vulnerability in its
own name or in a header saying what it fixes.

| Matching rule | Reason |
|---|---|
| Qualifiers and subpaths are discarded before comparing | A claim is written as the package and the version; the same package in an inventory carries the architecture it was built for |
| A claim naming no version covers every version | The format says so, and it is how a build states something about whatever it ships |
| A claim against a source tree matches a component of that name, or a fork of one | The build knows which packages came out of a tree and this deployment does not |
| A claim is matched at every place its component sits | The fan-out is ours either way |

**A claim that matched nothing is reported, not dropped.** A build's judgment
that went nowhere means a finding it already answered comes back as noise. The
producer's automatically-extracted claims name source trees rather than packages,
so this is the ordinary case.

| Choice | Reason |
|---|---|
| A claim naming an unreadable status refuses the document | A claim that cannot be acted on is one the build believes it made |
| A claim with no justification is kept rather than refused | The format requires one for a single status, and what to do about an unjustified claim is a triage question |
| Both shapes read into one thing, with the origin recorded | They differ in precision rather than meaning |
| Only a security claim is read from a patch | A patch resolves defects and improvements as readily as vulnerabilities |

## Scheduled rescanning

An inventory arriving queues one scan and nothing asks for the next, so a release
built a year ago has the same components it always had and a different answer
every month — and it is the build an advisory published this morning is most
likely to be about.

A pass queues a scan for every build holding an inventory not scanned within the
interval.

| It does not | Reason |
|---|---|
| Scan a build with no inventory | A run that found nothing against a build that has nothing is an empty answer reading exactly like a clean one |
| Queue a second scan for a build already waiting | The pass looks far more often than anything is due, because the interval is a setting an administrator may shorten. What is already queued is compared as identifiers rather than joined: a job's reference is text and a build's identifier is a number, and converting one inside a query has no spelling the four engines agree on |
| Ask for more than a slice at a time | A deployment tracking many builds would fill the queue in one pass and push arriving inventories behind work that is not urgent |
| Fail when the queue is full | It stops. What is due stays due, and a full queue is a fact about how much is in flight |

**One replica asks**, settled by a lease (`DESIGN-queue.md`). Two reading the same
list at the same moment would both see the same build as due, because the check
that nothing is queued is made when the list is read.

**The interval is a setting, shipping at a day.** The databases the scanner reads
are published daily.

**This does not discover.** The component list still comes from the build. What
changes between one scan and the next is what is known about those components.

## Scanner warnings

Warnings were read only when the scanner failed, which discarded the case that
matters: a run that answers and states that its answer is coarse. They are
recorded on the run, kept apart from the failure, and travel with the receipt.

**Today it captures nothing.** A scan runs over an inventory written here from
the components held — name, version, package identifier and CPE — not over the
document that arrived. The scanner is told far less than the producer said, so
the warnings it would raise about a producer's document it has no grounds to
raise about ours.

The case that prompted this: given the producer's document, the scanner reports
that Go binaries carry no function symbols and it is falling back to module
granularity; given ours it says nothing, because ours carries no notion of a
binary. The findings are the same either way. Recorded rather than fixed, because
carrying a producer's metadata as far as the scanner changes what an inventory is
here.

**Two things reported per match are kept**, as evidence for the question REQ-13
asks:

| Kept | Use |
|---|---|
| The version range the match fired on | For a distribution's package reached by identifier it names no packaging revision and so cannot see a backported fix. Read beside the version that ships, a range naming no revision is the whole argument in a line |
| The body of data that answered | Finer than the two words the match kind records |

Both are kept as the scanner wrote them and **never parsed**. Deciding whether a
version falls inside a range needs an ordering per ecosystem.

## Scan coverage

Every other failure here is loud. **Silence is the failure that is not**: a build
nothing files against reports no new findings, closes nothing, fails nothing, and
every number about it holds still.

Every declared build is reported with when a scan last arrived, **longest-silent
first**, and whether that is longer ago than the deployment allows. An
alphabetical list buries the one that stopped among the ones that are fine.

| Rule | Reason |
|---|---|
| A build nothing has ever been filed against is reported too, measured from declaration | A pipeline pointed at a name nobody declared is refused loudly; a build declared and never pointed at anything fails silently |
| How long counts as quiet is a setting, shipping at a week | Long enough that a nightly build missing one night is not an alert, short enough that a pipeline switched off is noticed in the week it happened |
| A release out of support is never reported as quiet (REQ-52) | It is still listed and still states how long it has been: "not scanned, and that is fine" and "not listed" are different answers |
| It is a person's question | A pipeline key sees the receipts for what it sent and nothing more |

## Receipts

The acceptance a build received was issued before anything was read, so it cannot
carry the answer, and a build that never checks again goes green on a file
nothing could read.

What was filed against a build can be asked for, newest first, each reporting how
far it got: **taken and not yet read, read and awaiting a vulnerability scan,
done, or refused with the reason.** A key sees the uploads it sent itself.

The four states are this deployment's, not the queue's. Reading and scanning are
two jobs with different rhythms, and a producer has no business knowing which
queue its work is sitting in.

**Which run answers an upload** is a rule rather than a lookup, because a run
covers a build rather than an upload: **the earliest successful run to finish
after that upload was parsed.** A run that failed answers it only while nothing
has succeeded since. The first version took the earliest run to finish after
parsing whatever became of it, so a scanner that fell over once poisoned every
receipt already waiting on it, permanently.

**What each run changed** is counted when asked for rather than stored, from the
runs the findings already point at, as issues at components rather than places.
The count is attributed to the newest upload that run covered and omitted from
the rest, because one fact repeated down three rows reads as three changes.

**Which run produced a finding is recorded on it** (REQ-13): the one that opened
it and the one that closed it, with the scanner and vulnerability-database
versions of each run on every receipt item. A feed shipping bad data for a week
is corrected afterwards, and the work done on the strength of it has to be found.

| Rule | Reason |
|---|---|
| The run that opened it, not the newest | A later run finding the same thing does not reopen a finding |
| The versions go on every receipt the run answers | They are a property of the run rather than a change it made. A page of receipts spanning a scanner upgrade is what somebody reads that screen to notice |
| Absent rather than invented where there is no run | A finding a person recorded (REQ-19) was produced by nobody, and one whose run has been pruned is still a finding |

**Two numbers are kept once a scan has been read**: how many components the
inventory described, and how many of them anything placed in the graph. The pair,
not either alone — a component nothing places is ordinary, but a document that
places *none* is a list rather than a graph, whose every finding will be
individually correct and unable to answer "why is this here".

## Reading back a document

A tag's documents are retained so a release can be re-scanned later. Nothing
returned one, so "send me the SBOM you scanned for v2.4" was answered from the
build system, which is the copy that may have moved since.

| Rule | Reason |
|---|---|
| The bytes as they arrived, not parsed and not re-serialized | The hash on the receipt covers what was received, so anything rewritten on the way out would fail the check the hash exists for |
| Named through the scan it belongs to | Whoever may read the receipt may read what it describes. A document identifier resolving on its own would be a second way in that has to remember the same rule |
| Narrowed in the store, not the handler | A key reads back what it sent and nothing more, so the two endpoints cannot come to differ |

## Administrator-supplied VEX

VEX statements arrive by administrator upload (REQ-31), as a conforming VEX or
CSAF-VEX document and nothing else. Both are read into the same claim: one puts
the status on a statement and the other in which list a product identifier
appears in, and what a publisher is telling this deployment does not depend on
which file they wrote it in.

| Rule | Reason |
|---|---|
| A CSAF product identifier is resolved through the tree that defines it | It is somebody else's key, not a name. The tree may arrive after the claims referring to it, so identifiers are collected as they are read and resolved once the document closes. An identifier the tree never defines is dropped, and a claim left pointing at nothing is refused |
| A CSAF *advisory* is refused | It is a document about somebody's own flaws. Reading one as claims about what a build ships would take their advisory as this build's argument and every product it names as a suppression. The profile is checked rather than assumed |
| The reader is the one the build's own suppressions go through | One parser rather than one per distribution's format keeps the hostile-input surface to a size somebody can reason about |
| Uploading again from the same publisher sets aside what they said before rather than deleting it | What an approval was granted on the strength of has to stay readable. The document's digest is kept with every statement, so a revision can be noticed |

What is done with the statements is not an ingest question: they are evidence and
a prefill, never applied (REQ-31).

## The offline scanner database

Produced by a build target rather than described in a document (REQ-12). What
stood behind the offline requirement was one configuration variable and a
paragraph, and a requirement whose only implementation is instructions somebody
follows by hand is one that gets discovered broken by the operator who most needs
it.

`make scanner-db` writes a bundle and its checksum.

| Rule | Reason |
|---|---|
| Built with the scanner the image carries, not whatever is installed on the machine | The format is the scanner's, so a bundle built by a different version may not load, and the version that produced a finding is part of what the finding means |
| Verified before it is declared | The target runs that same scanner against the bundle with the network off and auto-update refused, which is the configuration on the far side of the gap |
| The verification is a target of its own | So it can be run on the far side. "It built" and "it loads where it has to" are different claims |

## Analyzer findings

Findings from a static analyzer or a fuzzer are intended scope and **are not
built** (REQ-14). What has been decided is recorded because the parts expensive
to retrofit were settled early.

| Decision | Reason |
|---|---|
| Scoped to a product, a release and a variant | A finding that cannot say which build it is about cannot be compared release to release |
| SARIF is the default interchange, and not the only path | It is what the analyzers already emit. Native output would mean one reader per tool with nothing in common |
| One adapter per source, normalizing into the internal model | The same seam the inventory producers arrive through, so the rest of the system never learns which tool produced anything |
| Some sources are pulled rather than pushed | A hosted analyzer has its own store and no reason to call this deployment. There is no request to refuse, so a source that starts returning nothing has to be noticed the way a build that stopped being scanned is |
| Identity is computed here, never taken from the producer | An analyzer's identifier for a result is stable until the tool is upgraded or the file is reformatted, and a finding whose identity moves reopens as new |

## Limits

- **The bounds are set from what reading costs, not from what a document looks
  like.** They were round numbers several times the largest real producer:
  measured, an edge holds about half a kilobyte of heap while being read and a
  component about one and a third, so a ceiling of two million edges and a quarter
  of a million components accepted a document taking about **1.3 GB against the
  512 MiB the chart ships as a limit**. That file was guaranteed to kill the
  process, in the background reader that runs *after* the upload was answered 202.
  The budget is now about half the shipped limit for one document, and a test
  measures the per-unit cost with a wide bound.
- **The reader's bounds are configuration, not constants.** Five existed as a
  defaults function every deployment ran unchanged.
- **A component's name is folded on the way in, into a column of its own.** The
  four engines do not fold alike outside ASCII: a VEX statement about a component
  named with any letter outside it matched on three engines and not the fourth, so
  which engine a deployment ran decided whether the publisher's judgment reached
  the finding. Folding on write also leaves the index usable.
- **So is an issue's identifier, and every name it goes by.** Comparing through
  `LOWER` put a function on the indexed side, and the plan scanned the whole
  vulnerability table and the whole alias table once per statement — thirty seconds
  where the answer should take a fraction of one.
- **Only the first ancestor supplies upstream identity.** Anything further back is
  history, and a scanner matches against the fork point.
- **Fixed-width character columns are not used.** They blank-pad on some engines,
  so a hash read back carries trailing spaces that make an exact-match lookup fail.
- **A component with no distribution context in its identifier is one nothing will
  match**, and that is invisible rather than an error.
