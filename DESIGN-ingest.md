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
- [The formats read](#the-formats-read)
- [What each format states](#what-each-format-states)
- [Tolerated and refused](#tolerated-and-refused)
- [Unread fields](#unread-fields)
- [Build-declared suppressions](#build-declared-suppressions)
- [Scheduled rescanning](#scheduled-rescanning)
- [Scanner warnings](#scanner-warnings)
- [What a scan run may produce](#what-a-scan-run-may-produce)
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

CycloneDX, SPDX 2.x and SPDX 3.x are the formats read (REQ-05). A document says
which it is and the reader is chosen from that, so an upload takes any of them
and nothing about the endpoint names one.

The vulnerability data is produced here rather than sent. The inventory is
reproducible and a vulnerability report is not, since new issues are disclosed
daily, so a producer emitting both would have to give up one of the two
properties. Keeping the inventory standalone lets a year-old release be
re-scanned against today's data without rebuilding anything.

Running the scan here also makes counts comparable between products. A producer
running its own scanner measures each product with whatever version its pipeline
installed, so a difference between two products may be only a difference in
their build images.

The model keeps room for a producer-supplied vulnerability report, and nothing
reads one. A run records which scanner produced it and whether this deployment
ran it, so a producer's own findings would carry their provenance. The upload
takes an inventory and suppressions and nothing else, the reader skips a
`vulnerabilities` array, and every run is recorded as ours.

Fanning one reported issue out across the places it occupies is this
deployment's work. A vulnerability report says "this package at this version"
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

A scanner does not read pedigree. Measured: given a forked package carrying its
ancestor in `pedigree.ancestors`, the reference scanner matched nothing; given
the same package with no pedigree at all but with its distribution named in the
package identifier, it matched **forty-three advisories**. What it matches on is
the identifier and the distribution context.

Pedigree is kept for two other reasons: it explains a finding to whoever reads
it, and expiry is keyed on the upstream version, because a fork's own revision
moves for packaging reasons unrelated to whether a vulnerability is still there.

Suppressions are applied here, not upstream. The build's judgment about its own
carried patches is never refuted; what changed is where it is applied. Receiving
results a producer already filtered made a suppressed finding simply stop
appearing — component present, version unchanged, pedigree unchanged — which is
indistinguishable from a scanner fault, and lands in the bucket REQ-21 makes
unsuppressable by design.

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

Already held is a success, because the ordinary case is a retry after a timeout
that had in fact succeeded.

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

| Rule | Reason |
|---|---|
| Equal build times are refused | Neither is newer, so choosing between them would be a coin toss over which picture is current |
| Ordering is by build time, not arrival | A few minutes of clock skew is tolerated, because build machines are seconds out rather than hours |
| Timestamps are rounded to what the database keeps | Go carries nanoseconds and no supported engine stores them, so without rounding a value written and read back is fractionally *older* than the one in memory: a scan compares as newer than itself, and a second file claiming the same build time is accepted. A latent fault on every engine, exposed by one and passed by the others on timing luck |

## Document storage

Documents live in the database. More than one replica runs, so a file on the
receiving node is not there for whoever takes the work, and an object store is
optional by requirement, so ingest cannot make it mandatory.

| Rule | Reason |
|---|---|
| Content is split across rows | A single value of tens of megabytes runs into a maximum packet size on two of the four engines, and that limit is server configuration rather than anything a client can discover. Bounded rows stay inside every default in circulation and let a document be read as a stream |
| Every statement is bounded, not only the one carrying a document | One real image opens tens of thousands of graph rows and produces over three hundred thousand findings. Sent as one statement each, those are tens of megabytes of SQL, which two engines refuse outright and all four hold in memory |
| A membership test over a long list is split and OR-ed | A condition cannot be issued in pieces the way a write can, and a subtree or the aliases of a build's dismissals is thousands of identifiers. Split, each piece stays inside what all four accept |
| The hash is computed from the bytes as they are stored | A hash the sender supplied describes the file they meant to send |

## Retention

| Stream kind | Contents | Reason |
|---|---|---|
| Nightly branch | Deleted once read | The next night supersedes it, and keeping them grows storage with the calendar rather than with what is tracked |
| Tagged release | Inventory and suppressions both kept | Re-scanning years later needs what it contained *and* what the build had already argued about its carried patches. Keeping only the first would undo every one of those arguments on the next re-scan |

The record of what arrived outlives the contents: kind, size, and the hash of
the bytes as received. A re-parse means asking the build to send the file again,
which is the whole recovery path, and without the hash the second copy is taken
on trust. An upload whose contents are gone would otherwise read back as one
that arrived with nothing.

A document whose contents were released answers 410, not 404. On screen, one
still held is a link and one released is not: a link that answered 410 is a
control that looks like it works.

## Reading a scan

A worker claims the scan, reads its documents, and applies what they describe.
Every replica does both; a separate worker deployment would be a second thing to
run and get wrong for an installation this size.

The suppression documents are read here even though applying them waits on the
scan itself. A document that cannot be read is a fault in what the build sent,
and finding that out while the producer still has the build in front of them is
worth more than finding out later. What the build argued is stored against the
**target** rather than the scan, because it is what the next vulnerability scan
has to apply, and by then the documents may be gone.

A failure is recorded against the scan, not only against the job. A job that
keeps retrying is visible only to whoever operates the deployment, which is the
wrong person to be the only one who knows.

A read cut short by a shutdown is not recorded against the scan. Nothing is
wrong with the document, and marking it failed would leave the receipt saying so
after a retry had stored it.

The queue is polled. A notification mechanism exists on one of the four engines
and nothing portable replaces it, so an idle reader asks again after a few
seconds. A queue that is not empty drains at the speed of the work rather than
the speed of the poll.

## Concurrent scans of one target

Uploads are accepted in arrival order and read in whatever order workers pick
them up.

| Hazard | Guard |
|---|---|
| A scan reaches the reader after a newer one has been applied | An overtaken scan is not applied, and that is recorded rather than treated as a failure. Applying it would replace today's picture with yesterday's and reopen everything the newer one closed |
| The newer one may not have been read yet, and may then fail | Once a scan has failed, the newest that still stands is read again, where the build does not already show it and nothing is on its way to reading it. A scan can be read more than once, and the latest reading is what its receipt reports |
| Two applies for one target interleaving | Applying takes the target row first — an ordinary update, so every engine takes the lock and the second worker waits. Both would otherwise read the same open rows, compute the same difference and write it |

## Parsing

The header is read separately from the contents. Everything the arrival decision
turns on is answered by a pass that skips the contents. Parsing a file about to
be refused is work nobody asked for, and on the largest producer it is most of
the cost of taking the file. Skipping is not free — the reference producer sorts
its keys, putting tens of thousands of components ahead of the metadata — but
walking past a value is far cheaper than building something from it.

Read as a stream, and bounded in every dimension a producer controls, all
settable per read: document size, component count, file count, edge count,
claim count, nesting depth, and how many documents may arrive with one scan.
Edges need their own bound, because a thousand components can declare a
million edges between them.

| Rule | Reason |
|---|---|
| The depth bound is why the document is walked rather than decoded | Decoding has no depth limit anyone can set, so a file nested far enough to exhaust the process would be discovered by running out of memory. Nesting is bounded everywhere, including inside the parts nothing reads |
| An oversized document is refused as oversized | Truncating it and letting the reader fail reports a malformed file, which sends whoever sees the message looking at their build instead of at the limit. This holds for a third party's VEX document as well, which was read to the limit and handed on: over-sized became malformed, and the digest recorded was over the part that fitted |
| The component bound is charged where a component is read, not where one is recorded | Charged at the recording, the header pass — which records nothing — counted none of them, so a document putting its components inside the root component's own nested array was walked in full during a read that happens inside the upload request, with only the size bound saying how many there could be. The same document read whole was refused. A bound that holds on one of two paths through the same parser is a bound somebody routes around |
| The header pass holds nothing it walked past | Charging the walk is what stops a document nobody could have meant; holding nothing is what keeps the pass cheap for the documents that are fine, and this pass runs inside the upload request, so what it holds is held per concurrent upload. It was charging and holding: the count was the fix and the retention was not |
| A suppression document's product identifiers are charged against the component bound | The claim bound counts claims, and one claim names any number of products — so a document holding a single statement that lists millions of identifiers was inside every bound in force, and the map holding them was charged against nothing |
| The claim bound is spent across a scan's documents rather than per document | Every other bound is per document, and a scan carries as many as a build attaches. Passed whole to each, a producer sending fifty each inside the limit made this hold fifty times what the limit allows |
| How many documents arrive with one scan is bounded too | It is what makes every per-document bound mean something: without it they are multiplied by a number nothing decides |

| Rule | Reason |
|---|---|
| The file's own identifiers resolve edges and are then discarded | Those names are the producer's, and nothing guarantees they are stable between builds or consistent between producers. The test replaces every identifier in a real document and asserts the components, identities and graph are unchanged |
| Two components sharing one identifier are refused | Every edge naming it would be a coin toss |
| Nesting becomes an edge | A component containing components is the producer stating what is assembled from what. For some producers it is the only structure stated |
| An edge whose ends resolve to one component is dropped and counted | Content-derived identity can discover that two of a document's identifiers describe the same component. The producer could not have known, so it is not a producer error, and storing it would be a component depending on itself |

## The formats read

Three vocabularies for two formats, sharing one reader. What a vocabulary knows is which keys its format uses
and what they mean; how a component is deduplicated, how an edge is resolved
and where a bound is charged are the reader's, and neither half knows the
other's business (REQ-05).

| Rule | Reason |
|---|---|
| **The document chooses the reader, never the request** | An endpoint taking a format parameter is a parameter a build sets wrong, and the answer is then a refusal about the parameter rather than about the file |
| **A top-level key is read by the format that owns it**, before the document has necessarily said which format it is | The declaration arrives in no guaranteed position: a producer sorting its keys puts SPDX's packages ahead of its own `spdxVersion`. Requiring the declaration first would refuse documents that are well formed |
| **The formats claim no key in common**, which a test asserts rather than a reader assuming | A key claimed twice would make the routing a coin toss, and it is a property of the tables rather than of anything checkable while reading |
| **Which vocabulary read each key is recorded**, and a document that used two is refused | The keys being disjoint is not on its own enough. A handler writes to the document before anything has checked what the document is, and both formats state an identity — so a file carrying both keys is stored under whichever came last, which is a different identity for the same bytes depending only on how its producer sorted them |
| **A document declaring no format is refused** | A fragment, a hand-edited file, or something else entirely whose keys happen to look familiar. Guessing from the contents is what the declaration exists to make unnecessary |
| **Half a declaration is not a declaration** | CycloneDX states its format and its version in two keys, and either alone leaves the other unstated. An unstated version is a version this was not written against, which is what the by-name refusal is for |
| **A major version is read only where it has been written against** | Refused by name where it is read, so a file that was never going to be read is dropped before the rest of it is walked |

**SPDX 2.2 and 2.3 are one vocabulary.** The later revision adds fields and
adds nothing this reads, so one reader covers both and a document stating
either is read.

**SPDX 3.x is a third vocabulary rather than a branch in the second.** It
shares no key path with 2.x: a document is a context and one flat graph of
typed elements — packages, files, relationships, people, tools, licenses and
the document's own record in one array, in no stated order. Three vocabularies
and one reader is what the seam was for.

| Difference | What it costs |
|---|---|
| **An element announces what it is in a field that may arrive after the fields it governs** | An element is read into one neutral shape and interpreted when it closes. That is what a component read from either other format already does, and it holds one element rather than a document, so the walk stays bounded |
| **The header is inside the contents** | A document's creation record is one entry of the same array its packages are in. The header read therefore walks the whole graph and builds nothing from it, which is as cheap as this format allows rather than as cheap as the others are |
| **A document carries several creation records** | Anything it imported brought its own. The one the document points at is the document's; where it points at nothing the first read stands in, because reporting no build time at all has every later scan of that target refused as not newer |
| **One relationship states a list of ends** | The edge bound is charged per end rather than per relationship, as each is read |
| **An element does not say what it is until it has been read** | Every entry is charged against the component bound on the way in, because what a bound stops is the walk; the ones that turn out to be paths hand that charge back and take the file bound instead. So the walk is bounded throughout and the two are still sized the way they differ |
| **Identifiers are absolute** | Nothing here depends on their shape. Every one but the document's own resolves the document to itself and is discarded, which is what the other formats' in-file identifiers are for too |

**A path and a package may not share an identifier**, and this format states
both in one array — so the check runs where a package is bound and where a path
is recorded, since which of the two a producer writes first is its business.

**The version is stated in two places and either will do.** The context carries
it, and so does every creation record; a producer need not emit the first. Read
from one place only, a document stating it in the other would be refused as
saying nothing.

## What each format states

The internal shape is the same from either, because it is the shape the graph
is stored in rather than either format's. What differs is where a producer put
each fact.

| Fact | CycloneDX | SPDX 2.x | SPDX 3.x |
|---|---|---|---|
| The document's own identity | `serialNumber` | `documentNamespace` | the document element's own identifier |
| When the producer made it | `metadata.timestamp` | `creationInfo.created` | the creation record the document points at |
| What the document is about | the component under `metadata`, stated inline | an identifier pointing at one of the packages | identifiers on the document or inventory element, and `describes` |
| What ships | `components` | `packages` | graph entries typed as a package |
| A component's identity within the file | `bom-ref` | `SPDXID` | `spdxId` |
| The version | `version` | `versionInfo` | `software_packageVersion` |
| The package identifier and the database key | fields of the component | external references, by type | a field of the package, or external identifiers by type |
| Structure | `dependencies`, and one component nested in another | relationships, stated either way round | relationships, stated one way round |
| What a component was built from | a pedigree, describing the ancestor | a relationship pointing at another package | the same, spelled `ancestorOf` or `descendantOf` |
| What a carried patch resolves | a patch in the pedigree, naming the vulnerability | **cannot be stated** | **cannot be stated** |

**The root is resolved at the end rather than where it is named.** One format
states it inline with everything it says about it; the other points at a
package that may not have been read yet. A document pointing at several things
has no single root — the tracked unit stands in, as it does for a document
naming none — because picking one of them states a hierarchy the producer did
not.

**What is counted is what the pointers resolve to, not how many there are.** A
format offers more than one place to state the root — a list beside the
contents, and a relationship saying the same thing — and a producer that fills
in both has named one component twice rather than two components. Counting the
statements reads that as several roots and leaves the document with none, so a
document that said the same thing twice would be read as though it had said
nothing.

**The first of each identifier stands.** A real producer emits eight spellings
of one database key, differing in where it put a hyphen, and nothing here can
say which spelling an advisory used. Taking the first is the same answer
everything downstream has already been given, rather than a preference invented
here.

**The words for nothing are nothing.** SPDX requires several fields to be
present and offers `NOASSERTION` and `NONE` for a producer with no value for
one. Taken literally a package carries the version `NOASSERTION`, which a
person reads as a version and a scanner tries to match.

### Which relationships are structure

SPDX states a hundred and forty kinds of relationship and most of them are not
a dependency graph: what generated a file, what a document amends, what a
package was evidenced by. The test applied is whether the relationship says one
component is part of another in the sense the graph is walked in — the same
question a CycloneDX `dependsOn` answers.

| Read as | Types |
|---|---|
| An edge | `CONTAINS`, `CONTAINED_BY`, `DEPENDS_ON`, `DEPENDENCY_OF`, `DYNAMIC_LINK`, `STATIC_LINK`, `HAS_PREREQUISITE`, `PREREQUISITE_FOR`, `RUNTIME_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF`, `PROVIDED_DEPENDENCY_OF` |
| What the document is about | `DESCRIBES` and `DESCRIBED_BY`, between the document and a package |
| What a component was derived from | `ANCESTOR_OF` and `DESCENDANT_OF` |
| Nothing | Everything else |

**A type stated either way round is the same edge.** A producer may say a
program contains a library or that the library is contained by the program, and
the graph does not have two shapes.

**What built something is not what shipped.** A build tool, a test dependency
and a development dependency are statements about the build rather than about
what is in the product, so none of them places a component under another. The
component is still held and still counted as sitting under nothing, which is
the same treatment CycloneDX build tooling gets by arriving under `formulation`
rather than beside the contents.

**A derivation is a pointer rather than a description**, which is what makes it
weaker than the other format's pedigree: it can only name something the
document also describes. It fills in an upstream nothing else stated and never
replaces one, and it is charged against the claim bound rather than the edge
bound, because an unbounded array of them is the same hazard under a different
name.

**The third version drops the reversed spellings**, so a type is an edge or it
is not and there is no direction to get wrong.

| Read as | Types |
|---|---|
| An edge | `contains`, `dependsOn`, `hasDynamicLink`, `hasStaticLink`, `hasPrerequisite`, `hasOptionalComponent`, `hasOptionalDependency`, `hasProvidedDependency` |
| What the document is about | `describes` |
| What a component was derived from | `ancestorOf`, `descendantOf` |
| Nothing | Everything else |

### Lifecycle scopes

The third version annotates a relationship with the phase it matters in —
build, design, development, runtime, test or other. **The specification does not
say that any of them means the target does not ship**, and inferring it is the
one judgment in this area the format leaves to a reader.

| Scope | Read as |
|---|---|
| `test` | Places nothing. The target is still held and still counted as sitting under nothing, which is the same treatment `TEST_DEPENDENCY_OF` gets in the second version |
| Everything else | Places its target under the element the relationship is stated from |

**Reading `build` as "does not ship" is wrong for every compiled language**: a
crate or a module linked into a binary is stated as a build-phase dependency
and is inside what the product ships. The two errors are not equal, and
`Limits` says what that costs.

### Files are not components

A file is a path rather than a package: nothing matches a vulnerability against
one, and a scan of a real image catalogs five files for every package it found.
Holding them would grow the graph with nodes no finding can ever hang off.

The identifiers are kept even so. The structure a producer states is mostly
between a package and the files it installed — 91 of the 125 relationships in
the fixture — and an edge naming one has to be dropped knowingly. Dropped
without knowing, it reads as a graph with a hole in it, and a count meant to say
the producer's derivation changed moves instead with how much file detail the
producer was configured to emit. So the two are counted apart.

**They are bounded apart from components**, and the ceiling was set by
measurement rather than by analogy. A real scan catalogs 4,964 files against 89
packages on one image and 21,643 against 480 on another — forty-five to
fifty-six files per package — so a switch operating system's 6,866 packages
would arrive with something above 300,000 files. Charged against the component
ceiling of 100,000 that is a real inventory refused; raised until it fits, the
component bound has stopped bounding components. They also cost very different
amounts to hold: 133 bytes for a path against 766 for a component, because a
path is only the identifier and a component is a described thing.

## Tolerated and refused

The specification requires very little, and producers differ enormously in what
they fill in. A document that is valid and sparse is not a broken one.

| Tolerated | Behavior |
|---|---|
| The document names no component of its own | What the scan was filed against stands in. The root is excluded from identity and expiry anyway |
| A component states no version | Kept and counted. What it costs is matching, and it ships either way. Counted once over the deduplicated inventory rather than as each statement is read: a document naming the same unversioned component in ten relationships describes one component that ships without a version, and where a second description does state one the count is asked about the combination, which is what is stored |
| An edge names something the document never describes | Dropped and counted. The missing component is not invented |
| An edge names a file rather than a package | Dropped and counted separately. A file is below the level anything here tracks |
| An edge end is the format's word for nothing | Read as nothing. "Contains nothing" is a statement a producer makes, and reading it literally puts an identifier nothing describes into the count that says the graph has a hole in it |
| A relationship naming what a build is about, stated by anything other than the document | Left out. Taken as a root claim, any element could make itself the build's root and re-parent the whole inventory under it |
| Unread fields | Ignored. A producer carrying more than is read is the ordinary case |

Two things a document states twice are resolved once it has closed rather than
as they are read, because key order is the producer's choice and which of two
fields wins must not be: who supplied a component, which two of the three
vocabularies state two ways each, and what a component was built from.

The counts matter as much as the tolerance. Each is a number that should be
stable build to build, so a change says the producer changed.

| Refused | Reason |
|---|---|
| Neither format, or a major version not written against | A reader that guesses eventually guesses wrong on a file that looks close enough |
| Keys from two formats | Whichever handler ran last has already written over the other's answer, and nothing here can say which half the producer meant. The same rule for a suppression document, where reading half of one dropped the other half's claims without a word |
| Half of one format's declaration | An unstated version is a version this was not written against |
| A file and a component sharing one identifier | The same coin toss two components sharing one is refused for, and worse: the edge resolves to the component and invents a dependency nobody stated |
| A component with no name | It cannot be identified, so it cannot be tracked |
| Two components sharing one identifier | Every edge naming it is ambiguous |
| A build time nothing can read | The build time orders scans against each other |
| Past any of the bounds | A broken or hostile file has to fail rather than exhaust the process |

Reading is all or nothing. A partial inventory is indistinguishable from a
product that shrank, and acting on one closes findings that are still somebody's
problem. This concerns a *failed parse* rather than producer variation.

Everything a refusal quotes back came from the file, so what it quotes is bounded
in length: an error is one of the few places a scan file's contents reach a
person.

## Unread fields

A field nobody reads because it was considered and a field nobody reads because
nobody noticed it look identical in the code.

Every key path the recorded documents contain is written down, with what is done
with it: acted on, or seen and deliberately left alone. A document containing a
path that list does not have fails the check. The reverse is checked too — a
path the reader acts on that no recorded document contains is a branch nothing
exercises.

This checks the recorded documents, not what is accepted. The reader itself
ignores anything it does not recognize.

A minor revision of the format is read, and is now shown to be. The reader
checks the major version and refuses what it has not been written against;
anything within that major version parses. That made every revision accepted
**by construction rather than by evidence**, and the gap was live: the reference
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

**Only one of the two formats can carry the first**. SPDX has a
relationship saying a file is a patch for a package and no way to say which
vulnerability that patch resolves, so an inventory in that format carries no
claims and a build with carried patches states them in a document of its own.
Deriving the link from the patch's filename would report a suppression nobody
made.

**So the format a scan arrived in is carried out of the reader**, because what
a claim is closed by is difference: a claim the build no longer argues is a
claim the build withdrew. That reading only holds where the build had somewhere
to argue it. A scan whose format cannot attach a claim to a component says
nothing about carried patches whether or not they are still carried, so
closing on its silence would have a product's first scan in the other format
close every claim it held at once and reopen every finding they suppressed,
with nothing saying why.

A claim of an origin the scan could not have stated is left open and counted,
so the receipt says how many were carried forward rather than restated. A claim
the scan *could* have stated and did not is still closed, or the difference
stops meaning anything at all.

Both are read into one shape with the origin recorded, because the second can
point at something that cannot be resolved and the first cannot.

The vocabulary is kept rather than translated. A build saying "we carry the fix"
and one saying "the vulnerable code is never reached" make different claims. Two
of the four statuses remove a finding from what somebody has to look at; the
other two say the build looked.

A carried patch reports as fixed. The vulnerable code was there and a patch
resolved it, which is not the same statement as the vulnerability never having
applied. Only what a patch *claims* is read: a patch names a vulnerability in
its own name or in a header saying what it fixes.

| Matching rule | Reason |
|---|---|
| Qualifiers and subpaths are discarded before comparing | A claim is written as the package and the version; the same package in an inventory carries the architecture it was built for |
| A claim naming no version covers every version | The format says so, and it is how a build states something about whatever it ships |
| A claim against a source tree matches a component of that name, or a fork of one | The build knows which packages came out of a tree and this deployment does not |
| A source tree is named either way it can be named | As a bare name where the document carried no package identifier, and as a package identifier of the generic type where it carried one. The two are the same claim and are matched the same |
| A source tree named with a version is matched on it, against the component's own version and against what it was built from | A stated version is a version the build stated. Read as covering every version, a claim about one release suppresses a live finding on another |
| A claim is matched at every place its component sits | The fan-out is ours either way |

A claim that matched nothing is reported, not dropped. A build's judgment that
went nowhere means a finding it already answered comes back as noise. The
producer's automatically-extracted claims name source trees rather than
packages, so this is the ordinary case.

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

| Rule | Reason |
|---|---|
| One replica asks, settled by a lease (`DESIGN-queue.md`) | Two reading the same list at the same moment would both see the same build as due, because the check that nothing is queued is made when the list is read |
| The interval is a setting, shipping at a day | The databases the scanner reads are published daily |
| This does not discover | The component list still comes from the build. What changes between one scan and the next is what is known about those components |

## Scanner warnings

Warnings were read only when the scanner failed, which discarded the case that
matters: a run that answers and states that its answer is coarse. They are
recorded on the run, kept apart from the failure, and travel with the receipt.

Today it captures nothing. A scan runs over an inventory written here from the
components held — name, version, package identifier and CPE — not over the
document that arrived. The scanner is told far less than the producer said, so
the warnings it would raise about a producer's document it has no grounds to
raise about ours.

The case that prompted this: given the producer's document, the scanner reports
that Go binaries carry no function symbols and it is falling back to module
granularity; given ours it says nothing, because ours carries no notion of a
binary. The findings are the same either way. Recorded rather than fixed, because
carrying a producer's metadata as far as the scanner changes what an inventory is
here.

Two things reported per match are kept, as evidence for the question REQ-13
asks:

| Kept | Use |
|---|---|
| The version range the match fired on | For a distribution's package reached by identifier it names no packaging revision and so cannot see a backported fix. Read beside the version that ships, a range naming no revision is the whole argument in a line |
| The body of data that answered | Finer than the two words the match kind records |

Both are kept as the scanner wrote them and **never parsed**. Deciding whether a
version falls inside a range needs an ordering per ecosystem.

## What a scan run may produce

The scanner runs as a subprocess of the process serving the API, and its report
is read into that process. It is bounded the way a scan file is, from the same
budget, and every bound is configurable.

| Bounded | Rule |
|---|---|
| The report's size | Past the ceiling the run fails. It is not read in part: half a report reads as a product that stopped having problems, which is the failure every other rule here exists to prevent |
| What the scanner said while running | Past the ceiling the excess is dropped and the run stands. A scanner with a lot to say still scanned |
| How many matches one report states | Charged as each match is read rather than after the array, because what a bound stops is the walk |
| How many addresses one match points at | Bounded separately, because the two multiply: a report inside the match ceiling is still a report of one match pointing at everything |
| One execution's wall-clock time | A scanner that has stopped making progress fails as a run that failed rather than holding a worker. It stays below the ceiling on one hold (`DESIGN-queue.md`), and the process refuses to start where it does not |

A report's size is components × matches × references, and a producer controls
the first factor by uploading a scan file — so nothing about it is bounded by
anything this deployment chose unless it is bounded here.

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

Which run answers an upload is a rule rather than a lookup, because a run covers
a build rather than an upload: **the earliest successful run to finish after
that upload was parsed.** A run that failed answers it only while nothing has
succeeded since. The first version took the earliest run to finish after parsing
whatever became of it, so a scanner that fell over once poisoned every receipt
already waiting on it, permanently.

What each run changed is counted when asked for rather than stored, from the
runs the findings already point at, as issues at components rather than places.
The count is attributed to the newest upload that run covered and omitted from
the rest, because one fact repeated down three rows reads as three changes.

Which run produced a finding is recorded on it (REQ-13): the one that opened it
and the one that closed it, with the scanner and vulnerability-database versions
of each run on every receipt item. A feed shipping bad data for a week is
corrected afterwards, and the work done on the strength of it has to be found.

| Rule | Reason |
|---|---|
| The run that opened it, not the newest | A later run finding the same thing does not reopen a finding |
| The versions go on every receipt the run answers | They are a property of the run rather than a change it made. A page of receipts spanning a scanner upgrade is what somebody reads that screen to notice |
| Absent rather than invented where there is no run | A finding a person recorded (REQ-19) was produced by nobody, and one whose run has been pruned is still a finding |

Two numbers are kept once a scan has been read: how many components the
inventory described, and how many of them anything placed in the graph. The
pair, not either alone — a component nothing places is ordinary, but a document
that places *none* is a list rather than a graph, whose every finding will be
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

**A lifecycle scope is read the way that keeps a component**, and the
two errors it sits between are not equal. Keeping too much adds something to
triage, which somebody sees and acts on; dropping too much removes a finding
nobody ever learns about. Measured against the format's own example 11: its
three dependencies are stated unscoped in the second version and scoped `build`
in the third, which is one application described twice — so read as not
shipping, that document loses every component it has.

**The third version is read against the specification's documents and no
producer's output.** Nothing this deployment ingests emits it; the scanner
shipped here emits 2.3 and tag-value. The four fixtures are hand-written and
small by construction, so which shapes a real producer actually uses is not yet
evidence anything here has.
