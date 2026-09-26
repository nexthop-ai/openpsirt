# Data model

What a scan is filed against, and the structures it produces.

Satisfies REQ-07, REQ-08, REQ-14, REQ-15, REQ-16, REQ-17, REQ-18, REQ-20,
REQ-25, REQ-32, REQ-52, REQ-54.

## Contents

- [Vocabulary](#vocabulary)
- [Streams](#streams)
- [Release dates](#release-dates)
- [End of support](#end-of-support)
- [Variants and targets](#variants-and-targets)
- [Declaration before use](#declaration-before-use)
- [Names](#names)
- [Engine differences](#engine-differences)
- [The dependency graph](#the-dependency-graph)
- [Component identity](#component-identity)
- [Upstream name and version](#upstream-name-and-version)
- [The fold](#the-fold)
- [Duplicate descriptions](#duplicate-descriptions)
- [History as intervals](#history-as-intervals)
- [Inventory delta](#inventory-delta)
- [Place identity](#place-identity)
- [Path traversal](#path-traversal)
- [Limits](#limits)

## Vocabulary

A scan is filed against **(product, stream, variant)**. All three are declared
before anything may target them.

| Word | Means |
|---|---|
| Product | A thing that ships |
| Stream | A branch or a tag of that product |
| Variant | One of the ways the product is built |
| Build | One stream built as one variant, and the pair a scan is filed against |
| Place | A component and what directly pulled it in |
| Finding | One component at one place in one build. Twelve places is twelve findings (REQ-17) |
| Group | One issue at one component across every place it sits at. The row the findings list returns, and the thing somebody decides about |
| Report | A claim somebody sent us, and the record that it arrived. It exists before anybody has judged it, and it points at an issue only once somebody has (`DESIGN-findings.md` § Reports) |

Each word names one thing, and the unit a scan is filed against is called a
build wherever it is named. The finding-versus-group distinction is the
difference between the twenty-five thousand rows a scan produces and the four
hundred things somebody has to look at, and every count here is one or the
other.

| Term | Usage |
|---|---|
| Build | The word in prose, in responses and on screens. The table is called `target`, and the name stops there |
| Release | Not a level of the hierarchy. It is the act of shipping and the version a fix arrives in |
| Place | Spelled `places` everywhere, never "locations" |

| Verb | Means | Not |
|---|---|---|
| Approve | A second person agrees to a claim | Agree, as a state |
| Decided | A group whose every place is answered by a standing decision | Agreed. The wire value is `agreed`, and that is the only place the word appears for this |
| Withdraw | Taking back something recorded: a claim, an approval, a role | Revoke, retract, remove, cancel. Retiring a team or a rule is the exception, being not a taking-back |
| Hand back | Returning work to nobody | Release, which would make that word mean a third thing |

## Streams

Branches and tags share one table. They differ in one respect — a branch moves
and a tag does not — and share a product, variants, findings, an end-of-life date
and declaration before use.

A tag records the branch it was cut from, where known. That parent is what lets a
branch be compared against its last release, and what a new line seeds its
decisions from.

| Rule | Reason |
|---|---|
| The parent can be filled in afterwards (REQ-15) | A pipeline that does not know declares the tag without it, and release readiness then reports that nothing has ever been released from the branch — indistinguishable from a branch that shipped nothing. Declaring the tag again with the branch named records it |
| Naming a different branch is refused | A tag is one frozen point |

## Release dates

When a release went out is recorded as a date of its own (REQ-54). The day a tag
was declared here is an accident of administration: a tag is recorded so scans
can be filed against it, which happens before the release, months after, or while
backfilling a year of them.

The release-over-release chart orders and labels its points by this date.
Ordered by declaration time it is a chart of when somebody typed: a release
recorded late sorts after ones that came out before it, and a year entered in
an afternoon plots as a single day.

It falls back to the declaration date where nobody has stated one. It is the one
of the two values that changes — the parent fills in and never moves, while the
date is a fact about the world somebody may have got wrong.

## End of support

A date, not a flag (REQ-15). A date answers "what goes out of support next
quarter", takes effect without anybody remembering, and is how lifecycle policies
are published.

| Rule | Reason |
|---|---|
| Set on a release, or on a product for every release with no date of its own | |
| A release with no date inherits rather than copying | A copy would stop following the product the next time it moved, and nobody would see that happen. A screen shows a release's date *and* whose it is |
| Reversible | Extended support happens, and the alternative is recreating a release to undo a date |
| Absent is not past | A release nobody has dated is supported until somebody says otherwise |

Nothing is deleted or hidden past the date. What ends is what is expected of the
deployment, in two places:

| Effect | Detail |
|---|---|
| No deadline | A finding on a release out of support carries none. The overdue figure would otherwise fill permanently with releases nobody will fix. See `DESIGN-triage.md` |
| Silence is expected | A build that stops being scanned is not reported as quiet (REQ-52). It is still listed and still states how long it has been: "not scanned, and that is fine" and "not listed" are different answers. See `DESIGN-ingest.md` |

The comparison is spelled once, in the catalog, because the same fact decides
both effects and what a screen says.

## Variants and targets

| | Definition |
|---|---|
| Variant | Declared once per product, name unique within it. What a product is built as — a chip, an architecture, an operating system — is a property of the product and does not change because a new release came out |
| Target | One release built as one variant. Recorded on first use, because nothing new is named: a scan saying this release was built as that variant reports a fact |

That pair is what a scan is filed against and what everything downstream points
at, so one identifier runs from a scan through its graph to a finding.

The variant list is not restated per release. Somebody made to retype it will
eventually retype it differently, and `win`, `windows` and `win32` across three
releases are three variants as far as everything downstream is concerned.

A variant introduced later does not appear in earlier releases: those have no
target for it.

Each variant records whether it is customer-facing, which feeds ranking. It
defaults to customer-facing, so an unclassified artifact ranks as though it
ships. An administrator corrects it; a pipeline declaring the variant again
with the other value is refused, because it moves what everybody is told to
work on first.

### Catalog corrections

A product, a release and a variant are each named once and everything
downstream points at them, so what one is called can be wrong and stay wrong.
The rules below hold at all three levels, except where a row says otherwise.

| Rule | |
|---|---|
| The matching name and the spelling shown move together | A name people type is matched without regard to capitals, and both halves are derived from one string. Moved apart, a variant is matched as one thing and shown as another |
| A name another variant of the product holds is refused, retired ones included | The name stays spoken for while a variant is retired, which is what lets declaring it again bring that variant back rather than making a second |
| A name is refused once a document naming it has been published | A published OpenVEX document is identified by the build it describes, and a published advisory names each affected release in its product tree the same way. The product, the release and the variant are all inside that identifier. Renamed afterwards, the next document names the same thing differently: a reader holding the first reads it as a second document rather than as a revision of theirs, and one matching the identifier against an advisory finds it absent, which reads as no longer affected about a customer who still is. What went out is not rewritten, so nothing there can be corrected to match: an issued document, advisory or VEX, is kept as the bytes that were sent |
| A release is asked about the advisories that named it, rather than about its product | A release reaches an advisory's product tree by holding one of the issues that advisory covers, so that is the question. Asked of the product, a release no advisory ever named would be refused because a sibling release was named once — and a release cannot be retired and declared again to get round it, because the second one holds none of the first one's history |
| An issue taken back off an advisory still counts | It was on the document that went out, which is the document readers hold |
| A product's displayed name moves freely | It is what a screen shows, what a report is titled with, and what a published document names the product in prose. Nothing is identified by it. A release and a variant have no displayed name set apart from their name, so for those the two move together |
| Whether a variant reaches customers stays correctable | It is in no document and is not what anything is identified by. It feeds ranking, so correcting it is worth doing and is an administrator's act |
| What a release is does not move here | Whether it is a branch or a tag, and the branch a tag was cut from, say what a release is rather than what it is called |

### Catalog retirement

A product, a release and a variant are retired rather than deleted, the way a
team is retired and a person deactivated. The row stays and everything filed
against it stays with it.

Retiring is not an end-of-support date, and the two sit beside each other. A
date records that support ended, takes the deadline off what is open, and hides
nothing — an auditor asks about a release long after it stops being supported.
Retiring says the thing is not tracked here.

| Rule | |
|---|---|
| It is offered nowhere | The list of what a product is built as stops naming it, and so does every picker reading that list |
| A release still names it among what it was built as | The findings filed against it are still open and still somewhere, and a release that stopped naming where they are reads as a release that does not hold them |
| No scan may be filed against it | Declaration before use decides what a scan may name, and a retired variant is no longer declared. The refusal says to declare it again, because what has to change is a build script somebody maintains |
| Everything already filed against it still resolves by name | Its findings, its decisions and the documents published for it are all reached by resolving the name |
| Declaring it again brings it back | A pipeline runs the declaration on every build and the name is still spoken for, so the alternative is a build script that starts failing because an administrator tidied a list. What it reaches has to match, the way any declaration of something already declared does |
| Retiring a product writes nothing onto its releases and variants | They are reached through the product, so they leave every list with it. A date written onto each of them would be a bulk write whose only effect is to make bringing the product back a second bulk write that has to remember exactly what it changed |
| A retired variant is still named by the releases built as it, and a retired product or release is named by nothing | Only the variant has a second list that answers a different question — what a release was actually built as, where the findings filed against it sit. A retired product is reached by a link somebody kept, and the page for it says it is retired |
| Retiring one already retired is refused | Answered as done, two administrators retiring it at once would both record having done it |

Renaming, correcting what a variant reaches and retiring anything are
administrative acts, and each leaves a record of who did it and what it held
before.

## Declaration before use

A scan naming something undeclared is refused, and the refusal names which part
is missing — product, stream or variant.

Creating whatever a scan names is the alternative. A pipeline with a typo in a
stream name then produces a stream that looks genuine, with its own findings,
counts and place in every report, while the real stream appears to have stopped
being scanned.

Declaring is idempotent, including against another writer. Declaring what
is already there succeeds and changes nothing, because a pipeline that has to
know whether it is the first one is not usable from CI — and nothing
coordinates CI pipelines, so two arriving together is the ordinary case rather
than the exotic one.

| Rule | Reason |
|---|---|
| A declaration that loses to another writer reads what won and confirms it | The read and the write are two statements, so both callers find nothing and both insert. The unique index refuses one of them, and the refusal is not the loser's to report |
| Once more and no further | A row that keeps disappearing is not a race, and a retry with no bound is a loop |
| Declaring something *else* under a known name is still refused | Idempotence is about the same declaration arriving twice. A tag redeclared as a branch, or a product redeclared with another display name, is a name quietly changing meaning |

The same holds for the build a scan is filed against: two pipelines filing the
first scan for one release and variant at once must not produce two rows, which
would be two histories for one thing somebody ships.

## Names

Bounded: no leading or trailing spaces, nothing empty, and a length keeping a
unique index inside every engine's key-length limit. Uniqueness is within the
parent — a product name globally, a stream and a variant within their product.

Capitals do not distinguish two names. These are typed by hand into build
scripts, so a pipeline saying `sonic` against a product declared `SONiC` is the
same typo problem declaration-before-use exists to catch.

What is stored for matching is the normalized form. The spelling somebody wrote is
kept beside it and is what is shown back.

Normalizing the value is what makes this behave identically on every engine: a
lower-case value compares the same under any collation, and the unique
constraint means one thing on all four. Configuring a collation per engine is
the alternative, and it makes the rule a property of the deployment.

An identity a sign-in provider hands over is compared exactly. It is not typed
here and not ours to reinterpret; deciding that two accounts are one person
merges access nobody granted.

## Engine differences

Only column declarations differ. Everything queried is portable.

| Declaration | Reason |
|---|---|
| Generated keys | Three different spellings for the same idea |
| Timestamps | One engine has no `DATETIME`; another's `TIMESTAMP` can acquire an implicit default and an on-update clause |
| Booleans | One engine has no boolean type |
| Text lengths | A unique index needs a bounded width on some engines |

One behavioral difference beyond the declarations: a stream points at its parent
branch, and MySQL and MariaDB enforce that self-reference during a bulk delete
where PostgreSQL and SQLite do not. Code clearing streams detaches the parent
first.

## The dependency graph

A scan describes a set of components and which of them depends on which. Stored
as nodes and edges, never flattened: a flat list cannot answer "why is this
here".

| | Definition |
|---|---|
| Component | A package at a version. One row, however many products ship it |
| Node | That component's presence in one variant |
| Edge | One node depending on another |

A component reached by several parents is one node with several edges. Storing a
node per route would multiply the graph by its own sharing, and the routes are
derivable from the edges.

The root — the product itself — is a node like any other, flagged. Its version
changes on every build and its name differs per variant, so it is excluded from
identity and expiry (REQ-08). The flag is what lets everything walking upward
stop there. A scan naming no root of its own is filed against the unit it was
sent for.

The flag is reconciled like any other column. A node kept from the previous
scan has everything refreshed, this included: left alone, a build that promotes
a component to its own root — or demotes the old one — carries the previous
answer until that node happens to close. Everything walking upward stops at the
flag, so two flagged nodes or none is a tree that draws wrongly from the top.

The root is also not one of the build's components. It is what the components
are in, and a count including it says one more than the inventory lists.

| Refused | Reason |
|---|---|
| A component with no name | It cannot be identified, so it cannot be tracked. A component with no *version* is kept: the format does not require one, nothing can match a vulnerability against a version nobody stated, and it ships regardless |
| An edge naming a component the snapshot does not list | Inventing the component reports a dependency nobody declared. An edge naming something the document never described is dropped and counted at read time, so one reaching here means the snapshot was built wrong |

## Component identity

Derived from what the component is — the package identifier where the producer
emits one, name and version where it does not — and hashed to a fixed width.

Identifiers the file supplies are not used. Nothing guarantees they are stable
between builds or consistent between producers, and an identity that moves takes
every triage decision attached to it along.

A package identifier is read for what it says rather than byte for byte: escapes
decoded, the ecosystem lowercased, and the qualifying parts — architecture,
distribution, the source package a binary came from — excluded.

Measured on a public switch operating-system image: 8,374 described components
named 7,858 packages, and every one of the 516 collisions was the same name at
the same version. A build that merges two sources emits the same package twice,
once with those qualifiers and once without, sometimes escaping the version
differently and sometimes disagreeing with itself about the architecture. Taking
the identifier verbatim would count those packages twice, split their findings
across both halves, and leave only one half carrying the identifier a scanner
matches on.

Architecture is excluded specifically because what a product is built as is
already the variant. Including it states the dimension twice, and the same
package then reads as two in a report that has already separated them by variant.

The reduction is the one the identifier specification describes, applied the same
way to every ecosystem. Nothing here knows which producer wrote a document,
because the inventories this will be given come from build systems nobody has
seen.

### Component references

A request names a component the way a reader does: by name, narrowed where the
name is not enough.

| Part | Needed where |
|---|---|
| Name | Always |
| Version | The build ships the name at more than one version |
| Ecosystem | A source repository and the package built from it share a name and a version |
| Namespace | One package is described under two namespaces. 170 names in one real switch image arrived this way, once as the distribution's and once as the producer's own |

| Rule | |
|---|---|
| The four parts are identity without the qualifiers | Every choice a refusal offers resolves exactly one component |
| A part left empty matches anything | A caller that never meets the ambiguity sends nothing more |
| Except where the part before it was named and exactly one match has nothing in it | A version with no ecosystem then names the component with no identifier, and an ecosystem with no namespace the one with no namespace. The choice offered for such a component carries nothing in that part, so leaving it out is the only way to name it. apko describes each package once more as a directory with no identifier, at the same name and version. A name alone still matches every component of that name |
| A name matching several is refused with the choices, each carrying all four parts | A choice missing one leads back to the same refusal |
| Where an issue is open at only one of the matches, that one is taken | One choice is not a choice |
| Findings rows, tree nodes, the rows of the tree of one's own work, the steps of a way down, component packages, and the unassigned, late, disposed, blocking and claim lists carry the ecosystem and namespace | A screen can send back only what it was given |
| The finding and its reach, decision, assignment and tags, a component's neighbors, trend, open issues and decision about them, and a list narrowed beneath one, take all four and narrow the same way | A route taking fewer resolves a name the others refuse |

## Upstream name and version

Carried alongside the identity (REQ-18). A shipped fork often has a version
string of its own while the vulnerability lives on the upstream one, and the
upstream name is what a build's own suppressions use, since a patch is written
against a source tree rather than the binaries cut from it.

Producers state it two ways: the format has a place for it, and several hang it
off the package identifier. Both are read. In the measured image 30 components
state it the format's way and 537 hang it off the identifier, 16 of them both,
so reading only the format's own mechanism captures a twentieth of what is there.

A bare upstream name with no version is not a lesser answer. For a binary cut
from a differently named source package it is the whole of what is knowable, and
it is the half that matching a claim needs.

## The fold

The binary packages one source package was built at one version are one thing to
a person. curl, libcurl4t64 and libcurl3t64 are one bump; treating them as three
is three acts that can disagree with each other. Every component carries a
fold key, written as the scan is applied.

| Part of the key | Separates |
|---|---|
| Package type | Two ecosystems using one word — the Debian `python3-protobuf` and the PyPI `protobuf` |
| Distribution release | Two distributions using one word — Debian's busybox at `1:1.37.0-6+b8` and Alpine's at `1.37.0-r31` |
| Source package | The binaries cut from it, which is the grouping itself |
| Version it was built at | One source shipped twice in one build |

The source package's name alone is not enough, and the fourth part is the one
that looks optional. Measured on the demo: keyed on all four, 41 groups fold
and none of them holds binaries that disagree about which issues they carry or
which version fixes them. Keyed on the name alone, 72 fold and 14 disagree. The
kernel is the clearest of them — an image at source version 6.12.41-1 carrying
5,088 issues beside the perf and header packages at 6.12.107-1 carrying 607 and
none, one source at two versions in one build with one of them already fixed.

| Rule | |
|---|---|
| **It groups; it does not identify** | Identity stays derived from the component's own content (REQ-08), a finding stays keyed on its place (REQ-17), and a decision stays keyed on that place and expires on its own version (REQ-25). When a producer starts stating a source package for something it did not, the grouping moves and no record does |
| **Written on the way in, read as a column** | The grouping was an expression six queries each spelled for themselves, which is a key that comes apart. A column also groups on an index rather than on a function of four columns |
| **Hashed rather than spelled out** | A readable composite would have to be bounded to carry an index, and two keys agreeing to that bound would merge two source packages into one row — which, under one judgment covering the whole fold, writes decisions across both |
| **A component stating no source package is its own** | Coverage is producer-supplied and thin: 564 of 786 Debian packages, 10 of 18 Alpine, 2 of 188 PyPI, and none of 1,684 Go modules or 3,880 generic components. Leaving those out of every grouping would leave the majority ungrouped |
| **Folded for capitals, like every other matched name** | The four engines do not fold alike outside ASCII, so it is folded here rather than asked of one of them |
| **Cut to a number of characters, not a number of bytes** | Every indexed name column here is declared in characters — PostgreSQL, MySQL and MariaDB all count a `VARCHAR`'s length that way — and the fold key hashes four cut names. Cut at the same number of *bytes*, a name in a script taking three bytes a character was cut to a third of the width the column holds, so two components whose names differ only past that third folded together and one judgment covered both. The cut could also land inside a character, which hashes mangled parts and stores invalid UTF-8 |
| **It does not reach the two records that name what shipped** | The disposition register is one row per issue and place, and a VEX or CSAF statement is one per issue and component — the binary a customer's scanner matched on, not the source it was cut from. Folding either would publish a claim about a package nobody received |

Folding at ingest is a different proposal, and the measurement refuses it. 82
of the 117 groups hold binaries pulled in by different parents,
so a folded node answers what pulls this in wrongly for each of them:
`libcurl3t64-gnutls` has 30 distinct parents where `libcurl4t64` and `curl` have
one each. And 54 live edges run between packages of one source package, so a
folded node depends on itself and the graph acquires cycles the inventory does
not have.

## Duplicate descriptions

A document describing the same package twice is describing one component, and
the two descriptions are not always the same. In the measured image, keeping
whichever arrives first discards the vulnerability-database identifier for 204
components, on nothing but which half the producer emitted first.

The first statement of anything stands, and anything it did not state is taken
from the next description that does. Nothing is overwritten: two producers
disagreeing is not something a reader can settle.

The platform enumeration is kept and excluded from identity. A scanner given one
matches things a package identifier alone misses — vendor firmware, operating
systems, appliances, anything never published to a package ecosystem. Deriving
identity from both would move the identity of every component carrying the
second.

It is captured at ingest because a scan file is not kept once read. What is
discarded there is recoverable only by asking the producer to build again.

## History as intervals

Every node and edge records the scan that opened it and, once gone, the scan that
closed it. An open row is what is present now; a closed row is what a past
release contained.

| Rule | Reason |
|---|---|
| Rows are closed, never deleted | What a release shipped is a question asked years later |
| An unchanged build writes nothing | Applying a scan compares against what is open and writes only the difference. Scans arrive nightly and change very little, so storage that grew per scan would grow with the calendar (REQ-20). A test asserts it, and has been watched to fail with the comparison broken |
| One transaction | A half-applied graph is indistinguishable from components having been removed, which would close findings that are still present |

## Inventory delta

What one scan made of a build's contents: the names that arrived, the names that
went, and the names held at a different set of versions. A fact about the
documents a build sent, true as they are read.

| Rule | Reason |
|---|---|
| Counted by name | An upgrade is one dependency that moved. Counted by component it is one arrival and one departure, so a build that upgraded three things reports six |
| A name at two versions at once is one entry | A vendored tree ships one routinely, and one copy going is that name at fewer versions |
| The root is excluded from both sides | It is not one of the build's components, its version is not stored, and its name differs per variant |
| The earliest scan applied to a build has none | It is the first picture rather than a change to one |
| Worked out when asked, never stored | The rows that answer it are the rows applying the scan already wrote (REQ-20) |

The comparison is read off the intervals. A node stands immediately before a
scan where it opened earlier and had not closed by then, and at the scan where
it opened no later and has not closed since. A node the scan closed stands on
the near side of it.

Accepted scans of one build rise in identifier as they rise in build time, since
a scan not newer than the one a build holds is refused on arrival. The interval
columns hold scan identifiers, so that is what makes a comparison keyed on them
a comparison in time.

The names a scan opened or closed a row of are the whole of what it can have
moved, and narrowing to them is speed rather than meaning: a name none of them
touched stands at the same versions on both sides, or on neither side where it
reached the build later, and both are counted as no change.

| Rule | Reason |
|---|---|
| Each name is compared only at the scans that touched it | The work is what the page's uploads changed, not that times the number of uploads on the page |
| Rows that stood on neither side of any scan on the page are not read | Without that bound the cost grows with the calendar: on SQLite a page of fifty took 78 ms behind 73 nights and 264 ms behind 365 |
| The build's rows are read once, by the build, and matched to the names in the application | Joined to the names in one statement, PostgreSQL looked each name's rows up through the index led by the build, where the component is the third column. One upload that removed a file inventory touched 54,902 names and took 40.5 s; read once, it takes 0.76 s for the page |

Over a year of nightly scans a page of fifty uploads takes 4 to 6 ms on SQLite,
3 to 5 ms on PostgreSQL, 5 to 6 ms on MySQL and 4 to 5 ms on MariaDB, behind 73
nights of history and behind 365. Measured on 2026-09-25, one engine at a time.

### The names behind the counts

The counts and the names behind them are one fold over the same rows. A listing
that disagreed with the number beside it leaves a reader with two answers and
no way to tell which is the build's.

| Rule | Reason |
|---|---|
| Removals first, then arrivals, then names at new versions | A build that stopped describing a dependency looks exactly like one that stopped shipping it, which is what somebody opens a listing to find |
| Every version of a name, on each side | The count says a name moved; which copy of a vendored tree moved is what the versions say |
| The name as a producer wrote it | Identity is the folded name, and two producers writing one dependency in different capitals are one dependency. Either spelling names the same thing to a reader |
| Versions are ordered as text | A reader wants the same order twice, and ordering them properly is per-ecosystem work that would answer confidently for a pair it cannot order |
| A page is cut after the comparison | The names compared are the scan's own change; the rows read are the build's rows standing on either side of it |

Over a year of nightly scans that cost stays flat: listing an upload that moved
seven names takes 2 to 5 ms on each of the four engines, behind 73 nights of
history and behind 365, measured on 2026-09-25. Listing the upload that removed
a file inventory, 54,098 names, takes 0.43 s on PostgreSQL.

Those builds are 700 components. On a real switch image of 6,866, listing an
upload that moved five names takes 17 ms on SQLite and 10 ms on PostgreSQL. A
statement reading only the rows of the names moved takes 10 to 15 ms and 4.5 ms
for the same listing; reading the build's rows costs the difference, and is
what keeps an upload moving tens of thousands of names to under a second rather
than one lookup per name.

### The size a change is against

A count alone does not say whether a build is unlike itself, so what the change
is against is read with it: the names the build held immediately before the
scan, counted the way the change is counted and excluding the root. Forty names
moving is a rebuild on an inventory of two thousand and a different build on an
inventory of sixty.

## Place identity

The unit of triage is a component at a place: the pair of this component and the
thing that directly depends on it. Names only, no versions, hashed. Where the
thing above is the root, the component's name stands alone, because the root's
name differs per variant.

A chain of names from the top down is the other form. Measured against a real
switch image:

| | Chain of names | Component and its consumer |
|---|---:|---:|
| Places in one image | 134,509 | 27,366 — the edge count |
| Worst single component | 49,170 | 63 |

The worst case is one shared library: ten sub-packages built from its source,
each depending on the others, and one package depending on all ten, so every
route arriving at that family multiplies through it. A vulnerability there
produces 49,170 findings for one issue.

The same component has 48 direct consumers: the containers that ship it, its own
siblings, and the six packages that call it. Nothing is lost — which container
something runs in is one step further up, and the whole route is walkable.

## Path traversal

Under the definition above a place *is* an edge, so no row per route is stored.
The questions asked of the graph are answered by walking it.

| Question, on the worst component in a real image | PostgreSQL | MySQL |
|---|---:|---:|
| What directly pulled this in? (48 answers) | 3 ms | 11 ms |
| Everything above it, up to the image (78 answers) | 8 ms | 18 ms |

Precomputing would cost writes on every scan and bound nothing: how many routes
exist is a property of the producer's graph.

Recursive traversal is portable across all four engines. Every walk is one
`WITH RECURSIVE` statement bounded at sixty-four steps: upward from the components
on a page, downward from a component for the set beneath it, and downward from a
row of the tree's children for the distinct issues under each.

The downward walks are spelled `CROSS JOIN ... WHERE`, which is an inner join
everywhere and, on SQLite, the instruction to keep the recursion's queue on the
outside of the join. Left to itself the planner puts the edge table there and
scans every edge once per queued row: 6.6 s to list what sits under a build's
root, against 0.018 s.

## Limits

| Limit | Detail |
|---|---|
| Two builds of one version with different feature flags are one thing to the graph (REQ-16) | Both report the same name and version. An edge means the inventory said so, not that the code takes that path at run time. It matters where a dismissal rests on reachability, which is why such a claim is keyed on the versions in hand and asked again when they move |
| A finding of a kind with no dependency path gets no tree view (REQ-14) | For something a scanner found in a source file the answer is the file. The finding model carries a kind from the start, and the screens that assume a path check for one rather than drawing an empty tree |
| Two artifacts distinguished only by a package qualifier are one component | A component is tracked for which vulnerabilities apply to it, and a qualifier does not change that |
| Which product a build belongs to is asked in one place | Two walks of the same three tables cannot drift where there is one |
| A group's state is read from what its places say, never from the absence of a decision | Counting "no decision here" as undecided puts a withdrawn claim in no bucket at all: in none of the four states, and in the total |
| A place identity carries no build and no product | That is what lets a judgment travel between builds shipping the same versions, and why every list correlating decisions requires a product to be named |
| Where an issue sits, and the disclosure queue, link to a finding by name and version alone | The first groups one issue's places by component name, so one row can stand for two components of that name. Where a build holds that name at that version as two, the link lands on the choice between them |
