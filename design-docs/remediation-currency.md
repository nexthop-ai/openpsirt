# Upstream currency

The newest version a public package index states for a component this
deployment builds, the names never sent, and the report of what has no answer.

Satisfies REQ-42.

## Contents

- [Currency pass](#currency-pass)
- [Indexes asked](#indexes-asked)
- [Answer classes](#answer-classes)
- [Names held back](#names-held-back)
- [Unanswered components](#unanswered-components)
- [Limits](#limits)

## Currency pass

Off unless an administrator turns it on. A request carries one component's name
and nothing else, no version, build or product, to a public index that records
every request.

| Rule | Reason |
|---|---|
| One replica asks, under a lease | The pace, two hundred components a pass a quarter of a second apart, is a rate per deployment on services somebody else runs |
| The lease is renewed every twenty-five components or once half of it has gone, whichever is first | A component is one request to most indexes, two to Maven Central and up to five to nuget.org, so a slow index outlasts a lease renewed by count alone and a second replica starts asking |
| A pass that has lost the lease stops | |
| An index that fails is asked once a pass; its components stay due and the window is read again without that ecosystem | Otherwise an index egress cannot reach fills every window |
| The candidates are built from the ecosystems with an index, never from its complement | Otherwise an unaskable ecosystem is recorded empty, spending a slot: an image with ten thousand distribution packages spent fifty passes writing nothing |
| A distribution package is not asked about | The distribution is the maintainer, and its release date says nothing about the software inside |
| The candidates are components some build still carries; one no build carries keeps its last answer | The report of names with no answer reads the same set |
| A package is asked once a pass, however many of its versions are stored | |
| The window takes the never-asked first | |

## Indexes asked

| Ecosystem | Index | The newest version |
|---|---|---|
| Go | The module proxy | What it answers as latest, with its time |
| npm | The npm registry | The `latest` tag, dated from the full document where it comes back |
| PyPI | pypi.org | The version it names, dated by its earliest file |
| Cargo | crates.io | The newest stable version, else the newest |
| Maven | Maven Central's repository | The furthest release its metadata lists by the Maven ordering, else the furthest pre-release; dated by when the repository last modified that version's project document |
| NuGet | nuget.org's registration | The furthest listed release by the NuGet ordering, else the furthest listed pre-release; dated by publication |

| Rule | Reason |
|---|---|
| An index listing every version is read with the ecosystem's ordering (`design-docs/remediation-versions.md`) | Maven Central's metadata calls the last publication "release": 3.0.0-beta3 for log4j-core while 2.26.1 was the newest release |
| A pre-release is offered only where a package has published nothing else | |
| A Maven version marked preview, pre, ea, eap or dev is a pre-release; the Maven ordering is left as it is | Maven orders those words above the release, and publishers use them for versions ahead of one |
| An unlisted NuGet version is passed over | Its owner withdrew it; nuget.org dates it to 1900 |
| A paged NuGet registration is read from its newest page back, at most four pages | The answer is usually on the last page; the bound caps a package whose newest pages are all pre-releases |
| Where the bound stops the walk with no release, the package is recorded as asked with no version | A release may sit on an unread page |
| A page is read only from the registration it came from | A page named elsewhere, or an address with a dot segment, is not followed |
| A Maven group or artifact that is empty, `.` or `..` is recorded as unaskable, never asked | It names another place in the repository |
| A PyPI name is asked as PyPI spells it: lower case, each run of hyphens, underscores and dots one hyphen | Otherwise the index redirects, and the client follows no redirect |

## Answer classes

| Answer | Recorded | Reason |
|---|---|---|
| A version | Yes | |
| The index has never heard of it | Asked, with no version | A private module or a vendored fork, neither a fault |
| A refusal the index will repeat | Asked, with no version | A package withdrawn, a region blocked, a name no request can carry, an unreadable document, a status other than a bad day's, a refused redirect |
| A bad day: too many requests, the index unwell, or no answer | Nothing | It stays due and the next pass asks again |

| Rule | Reason |
|---|---|
| Everything that is not a bad day is recorded | An unrecorded repeating refusal holds the head of every later pass for ever |
| A Maven project document failing as a bad day fails the whole answer | |
| Where npm's full document is refused and the abbreviated one falls into a bad day, the answer is the bad day | |
| A previous answer is never overwritten by an empty one | Not-found also answers a renamed package and some transient conditions, and would leave the hole for a month |
| A version answered with no date keeps the date held while the version is unmoved | npm's abbreviated document and a missing Maven project document answer the version alone |
| A name the Maven or NuGet asker refuses before sending is reported as unreadable | It was never sent |

## Names held back

A name this deployment calls its own is never sent. Three sources, unioned:

| Source | Yields |
|---|---|
| The namespace this deployment publishes under, already required for CSAF and VEX | The host, the host reversed (a Maven group or Java package), and each label short of the top-level domain |
| What each build declared itself to be, read from the scan record | The account, scope or group beside the name, and for a Go module path the account after its host, whatever suffix, subdirectory or forge group follows. A root is the product built here. The component standing for the product is stored by name alone, so the record is the source |
| What the deployment stated | Whatever else an operator named |

| Rule | Reason |
|---|---|
| A name is matched a part at a time, exactly or followed by a separator | Anywhere in the string over-matches; only exactly misses the family of names an organization publishes |
| A name without a dot is matched against each dotted part too | `com.skunkworks` never begins with `skunkworks` |
| The segment beside the package's name is taken, never the whole namespace | A forge host is shared by everybody |
| Nothing is derived from the root's own name | A product called "core" would hold back every package starting so |
| A label naming a kind of registration is dropped, from a closed handful | Under a second-level registration the generic part is nobody's name |
| Biased toward holding back, and it says what it held | Over-excluding shows on screen and in the report; under-excluding sends a name nobody can take back |
| A held-back component is recorded as though asked | Unrecorded, it holds the head of every pass |
| Anything an index said about a held-back name is dropped | Kept, the version never refreshes, the component never reaches the report, and the row goes stale in a day rather than in thirty, spending a slot daily |
| A name a reader may not be told is not in the list the report carries, though classification runs against every root | A label derived from a root names a product's scope (REQ-42), and a name never sent must not read as sent |
| Identifiers are taken newest first | A nightly build states a new identifier each night; unordered, two callers derive different sets and a name held back yesterday goes out today |
| The roots are read per pass, the other sources at startup | A product declared this morning must not leave this afternoon |

## Unanswered components

One report: what was held back says what the default costs, and what no index
knew is the list an operator reads to decide what else to hold back. A name
promoted from the second appears in the first afterwards.

| Why there is no answer | Meaning |
|---|---|
| It is ours | Never sent. The names matched against travel with the report |
| Not known, or refused | Sent, with no version back; the two are one row |
| The identifier cannot be read | Nothing turns it into a request. Kept apart because it is a fault in an accepted document, meaningless on the list of names to hold back |

| Rule | Reason |
|---|---|
| The classification is derived at read time | Held-back and unknown names are recorded alike, and the report follows a change to the list at once, not after a month of backoff |
| A component the pass has not reached is not on it | A first day's backlog is not index failure |
| Narrowed to the products the reader may read | Package identifiers say what products are made of (REQ-42) |

## Limits

| Rule | Reason |
|---|---|
| Holding back is a better default, never a control | Certainty about what leaves needs the feature off, which is how it ships |
