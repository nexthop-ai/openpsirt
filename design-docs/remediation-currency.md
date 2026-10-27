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

Off unless an administrator turns it on, because a request sends a component's
name to a public index, which records every request.

| Rule | Reason |
|---|---|
| A request carries one component's name and nothing else: no version, build or product | For an open-source dependency the name is public; for something built here it names a project, a team or an unannounced product |
| One replica asks, settled by a lease | The pace, two hundred components a pass a quarter of a second apart, is a rate per deployment on free services somebody else runs |
| The lease is taken again every twenty-five components or once half of it has gone, whichever comes first | Two hundred components with a timeout each runs past several intervals, so a slow index otherwise hands the pass to a second replica mid-flight. A component is one request to most indexes, two to Maven Central and up to five to nuget.org, so a count alone lets a slow index outlast the lease |
| A pass that has lost the lease stops | Two replicas asking is at somebody else's expense |
| An index that fails is asked once a pass; its components stay due, and the window is read again without that ecosystem for the rest of the pass | Otherwise a deployment whose egress misses one index fills every window with that index's never-asked components |
| The candidates are built from the ecosystems with an index, never from its complement | An unaskable ecosystem otherwise reaches the asker, finds none and is recorded empty, spending a slot: an image with ten thousand distribution packages spent fifty passes writing nothing |
| A distribution package is not asked about | The distribution is the maintainer, and its release date says nothing about the age of the software inside |
| The candidates are components some build still carries; one no build carries keeps its last answer | A name in a build last year is not one to send tonight. The report of names with no answer reads the same set |
| A package is asked once a pass, however many of its versions are stored | The question is about the package, so every version in the window takes the one answer |
| The window takes the never-asked first | |

## Indexes asked

| Ecosystem | Index | The newest version |
|---|---|---|
| Go | The module proxy | What it answers as the latest, with its time |
| npm | The npm registry | The `latest` tag, dated from the full document where it comes back |
| PyPI | pypi.org | The version it names, dated by its earliest file |
| Cargo | crates.io | The newest stable version, or the newest of any where there is none |
| Maven | Maven Central's repository | The furthest along release its metadata lists, by the Maven ordering, or the furthest pre-release where there is none. Dated by when the repository last modified that version's project document |
| NuGet | nuget.org's registration | The furthest along listed release, by the NuGet ordering, or the furthest listed pre-release where there is none. Dated by when it was published |

| Rule | Reason |
|---|---|
| An index listing every version is read with the ecosystem's own ordering (`design-docs/remediation-versions.md`) | Maven Central's metadata names as "release" whatever was published last: 3.0.0-beta3 for log4j-core while 2.26.1 was the newest release |
| A pre-release is offered only where a package has published nothing else | Being behind a release candidate is not a claim to act on |
| A Maven version marked preview, pre, ea, eap or dev is a pre-release | Maven orders those words above the release as unknown words, and publishers use them for versions ahead of one. Only the question of whether a version is a release reads them; the ordering is left as Maven has it |
| An unlisted NuGet version is passed over | Its owner withdrew it from what anybody choosing a version is offered, and nuget.org dates it to 1900 |
| A paged NuGet registration is read from its newest page back, at most four pages | Pages run oldest to newest, so the answer is usually on the last; the bound stops a package whose newest pages hold only pre-releases costing a request per page |
| Where the bound stops the walk with no release found, there is no answer, and the package is recorded as asked with no version | A release may sit on an unread page, so the newest pre-release is not offered |
| A page is read only from the registration it came from | An index naming a page anywhere else, or an address carrying a dot segment, is not followed |
| A Maven group or artifact that is empty, `.` or `..` is not asked, and is recorded as unaskable | It names a different place in the repository |
| A PyPI name is asked as PyPI spells it: lower case, each run of hyphens, underscores and dots one hyphen | Asked another way the index redirects, and the client follows no redirect |

## Answer classes

| Answer | Recorded | Reason |
|---|---|---|
| A version | Yes | The thing asked for |
| The index has never heard of it | Asked, with no version | A private module and a vendored fork both look like this, and neither is a fault |
| A refusal the index will repeat | Asked, with no version | A package withdrawn, a region blocked, a name no request can carry, a document nothing can read, a status other than a bad day's, a redirect the client refuses. An answer never coming is still an answer |
| A bad day: too many requests, the index unwell, or no answer | Nothing | It stays due and the next pass asks again |

| Rule | Reason |
|---|---|
| Everything that is not a bad day is recorded | An unrecorded repeating refusal holds the head of every later pass for ever, since the window takes the never-asked first |
| A Maven project document failing as a bad day fails the whole answer | Its date is asked for again too |
| Where npm's full document is refused and the abbreviated one falls into a bad day, the answer is the bad day | |
| A previous answer is never overwritten by an empty one | An index answers not-found for a renamed package and some transient conditions, and destroying a version in hand would leave the hole for a month |
| A version answered with no date keeps the date held while the version has not moved | npm's abbreviated document, and a Maven project document that did not come back, answer the version alone |
| A name the Maven or NuGet asker refuses before sending is reported as unreadable | It was never sent, so "not known, or refused" would put a name nobody asked about on the list somebody holds back from |

## Names held back

A name this deployment calls its own is never sent. Three sources, unioned:

| Source | Yields |
|---|---|
| The namespace this deployment publishes under | The organization in the three spellings ecosystems use: the host, the host reversed (a Maven group and a Java package), and each label short of the top-level domain. It is already required for CSAF and VEX and already means "who we are" |
| What each build declared itself to be | The account, scope or group the identifier is published under: the segment beside the name, and for a Go module path the account after its host, whatever major-version suffix, module subdirectory or forge group follows. A root is the product built here, so its publisher is this deployment. Read from the scan record, because the component standing for the product is stored by name alone |
| What the deployment stated | Whatever else an operator named |

| Rule | Reason |
|---|---|
| A name is matched a part at a time, exactly or followed by a separator | Matched anywhere, one organization's name holds back every package holding those letters; matched only exactly, it misses the family of names the organization publishes |
| A name without a dot is matched against each dotted part as well | A Maven group starts with a top-level domain, so `com.skunkworks` never begins with `skunkworks` |
| The segment beside the package's name is taken, never the whole namespace | A forge host is shared by everybody; taking it holds back most of an ecosystem, which makes an operator turn the feature off |
| Nothing is derived from the root's own name | A product called "core" would hold back every package starting that way |
| A label naming a kind of registration, not an organization, is dropped | Under a second-level registration the generic part is nobody's name. It is a closed handful, never a list of each country's registrations |
| Biased toward holding back, and it says what it held | Over-excluding loses an answer, which shows on the screen and in the report; under-excluding sends a name to somebody else's service, which shows nowhere and cannot be taken back |
| A held-back component is recorded as though asked | Unrecorded, it holds the head of every later pass for ever |
| Anything an index said about a held-back name is dropped | All of it was obtained by sending that name. Kept, the version stands with nothing to refresh it, the component never reaches the report of what was held back, and the row goes stale in a day, spending a slot daily |
| A name a reader may not be told is not in the list the report carries | A label derived from a root is the name a product is published under, so the list states the scope of a product nobody announced to that reader (REQ-42). Classification still runs against every root, so a name never sent never reads as sent |
| Identifiers are taken newest first | A build's identifier carries its version, so a product built nightly states one every night and the bound falls on builds. Unordered, two callers derive different sets and a name held back yesterday goes out today |
| The roots are read per pass, the other two sources at startup | A product declared this morning is one whose name must not leave this afternoon; the others are configuration and change on a redeploy |

## Unanswered components

One report of two questions asked together: what was held back says what the
default costs, and what no index knew or answered is the list an operator reads
to decide what else to hold back. A name promoted from the second appears in the
first afterwards, which shows the promotion worked.

| Why there is no answer | Meaning |
|---|---|
| It is ours | Never sent. The names it was matched against travel with the report, so a row can be checked |
| Not known, or refused | Sent, with no version back. A refusal is recorded exactly as an unknown name, so the two are one row |
| The identifier cannot be read | Nothing turns it into a request. Kept apart because it is a fault in a document this deployment accepted, and on the list of names to hold back it means nothing |

| Rule | Reason |
|---|---|
| The classification is derived, never stored | A held-back name and an unknown one are recorded identically; the list applied again at read time tells them apart, and the report follows a change to the list at once instead of after a month of backoff |
| A component the pass has not reached is not on it | It is waiting, and a first day's backlog reported as index failures makes the list useless the day somebody reads it |
| Narrowed to the products the reader may read | A list of package identifiers across the estate says what products are made of (REQ-42) |

## Limits

| Rule | Reason |
|---|---|
| Holding back is a better default, never a control | A deployment needing certainty about what leaves it keeps the feature off, which is how it ships |
