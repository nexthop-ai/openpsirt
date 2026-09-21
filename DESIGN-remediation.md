# Remediation

Declared fix intent, how the tool determines whether it arrived, and the
documents generated from what was decided.

Satisfies REQ-15, REQ-19, REQ-24, REQ-28, REQ-33, REQ-34, REQ-35, REQ-36, REQ-39.

Neighboring pieces: the escalation view, per-item time remaining and the SLA
compliance rate are in `DESIGN-reporting.md`; the assignment model is in
`DESIGN-access.md`, which defines the party a thing is assigned to.

## Contents

- [Declaration, not completion](#declaration-not-completion)
- [The unit](#the-unit)
- [Resolution](#resolution)
- [Deadlines](#deadlines)
- [Pending upgrades](#pending-upgrades)
- [Upstream currency](#upstream-currency)
- [Version ordering](#version-ordering)
- [Promise states](#promise-states)
- [Build-declared suppressions](#build-declared-suppressions)
- [External links](#external-links)
- [Publication](#publication)
- [The advisory](#the-advisory)
- [Editorial state](#editorial-state)
- [The CSAF document](#the-csaf-document)
- [The VEX document](#the-vex-document)
- [Issuance records](#issuance-records)
- [Publisher identity](#publisher-identity)
- [Not built](#not-built)
- [Limits](#limits)

## Declaration, not completion

A fix is declared and never completed. A judgment promising work states which
releases it is for; whether the fix arrived is answered by the next scan of each
of those releases (REQ-35).

The stored row is the declaration and nothing else: which build, which fold, who
said so, and when. There is no state column, no completed-at, and nothing to
move along.

A declaration arrives with the judgment that argued for it, from the two
outcomes that promise work — a bump, recorded against the component, and a
backport, recorded against the issue. There is no way to record where a fix
will land without saying what was decided. Bare intent carries no version, no
date and no reasoning, so nothing can lapse and nobody is asked to agree to it:
a promise in the shape of a record and not in its effect.

The alternative — planned, in progress, done, moved by a person — is how every
tracker works, and is wrong here because independent evidence already exists. A
scan of the release either finds the issue or does not. A second record of the
same fact is one somebody has to keep true, and the way that fails is the tool
reporting a fix that shipped in nobody's release.

A flaw recorded by hand is the exception (REQ-19). No scan reports one, so there
is no second opinion to check a declaration against, and refusing the
declaration leaves the finding open forever. That class is closed by a person,
with who, when and why on the record. `DESIGN-findings.md` carries the shape.

## The unit

A commitment is one build moving one fold: a source package, at the version it
was built at, going to another version. That is the piece of work somebody
actually does, and it is one row.

A release is named by its stream and its variant together, never by one of them:
the same branch built two ways is two builds, and a plan naming only the branch
would claim a fix for hardware nobody built for.

Acting on the plan acts on the product, not on the build in the path. A route
names a finding so a screen has somewhere to link to; what is planned belongs to
the work that finding is part of.

### Coverage by matching

A finding is covered when its component folds to the commitment's key in the
commitment's build. Nothing is written onto findings.

| Consequence | |
|---|---|
| Changing the version a release is moving to is one row | Keyed per issue and per component and per target version, a change means rewriting every row of it |
| An issue published tonight is covered by this morning's commitment | With nobody acting. Keyed per issue it is not covered until somebody declares it too |
| A sibling package moves with its source | curl, libcurl4t64 and libcurl3t64 are one bump, so a commitment recorded against one covers all of them |
| No version comparison decides coverage | An upgrade covers everything open on the fold rather than only what records this version as its fix. What an ordering is used for is reading a set of candidates, never deciding what a commitment reaches |

A build has one commitment per fold, enforced by the database rather than by a
check somebody remembers. A release moves a package to one version; two rows
saying otherwise is a plan a coordinator cannot read.

### Commitment changes

| Where it came from | How it changes |
|---|---|
| A judgment somebody agreed to | Through the act that revises the claim, which withdraws every agreement on it and returns its rows to the queue. A reason is required, and the revisions are where what was promised in October survives being changed in November |
| Intent nobody argued for | The row is edited |

Changing the version or the date under a standing agreement is refused, naming
the claim to revise. An approver agreed to a version by a date; rewriting either
half quietly would leave the agreement standing over a promise nobody read,
which is the failure REQ-28 exists to prevent.

| Rule | |
|---|---|
| **The gate is worked out again** | Moving the date moves the thing the gate is about. Withdrawing the agreements and leaving the rows recorded as needing nobody put a promise first made inside the deadline back in force at any later date somebody chose — in force, suppressing what it covered, and listed in no queue |
| It is measured over what the claim covers now | The builds come from the commitments the claim wrote and the places from its own rows, read inside the transaction that writes. A deadline moves when the policy or the rating moves, so the one it was made against is not the one it is judged by |
| A date already past is refused | It says the work will have happened before now |
| The reasoning goes through the text policy | Every path that stores typed text runs it before storing, and this one reached the write through an inner act that did not |

## Resolution

A commitment is answered by the next scan of the build it was made for, never by
anybody marking it done (REQ-35). Each stands at landed, lapsed or planned, and
those three are worked out on every read — nothing stores them, nothing refreshes
them, and nothing has to be invalidated when a scan closes a finding.

A roll-up across the builds one issue was promised in is not built. "Two of
three chosen releases are clear" is the reading, and its only source is a
screen offering a set of builds to tick with no version, no date and no
reasoning attached — which is the shape this refuses. What is built answers per
build, the grain a commitment is made at, and where an issue stands across
several is read from the findings list, which has a row per build.

## Deadlines

There are no per-item due dates. A deadline comes from how urgent the finding is
(REQ-33). Moving one is a deferral, which carries a reason and an approval
threshold, and the deferral date becomes the effective target. Deferred items are
reported apart from plainly overdue ones. A plan says where, not when.

The clock starts at the latest of three moments, never the earliest and never
now: when the finding was first seen here, when exploitation was learned, and
when the fix became available. All three have passed, so recounting reaches the
same answer every time — which is what keeps a deadline from restarting nightly
and never arriving.

| Case | Counted from |
|---|---|
| The fix already existed when the finding opened | The sighting. The ordinary case, and the response time genuinely is from when it was learned |
| The flaw was seen before upstream released anything | **The fix.** Counting from the sighting sets a deadline against a version that did not exist, which is the common case for an inventory made of distribution packages |
| The issue became exploited later | The learning. Counted from the opening, an issue exploited after six months lands three days before anybody knew |

A finding with no deadline states which reason applies:

| Reason | Reported as | Precedence |
|---|---|---|
| Below the line its product triages at | `below-the-line` | The narrowest statement about this finding, so it is the one stated |
| **Upstream has released no fix, or has declined to** | `nothing-to-take` | Above the release, being about this finding rather than about what it sits in. The declining half is the same rule read one step further: a fix that was never going to arrive is as absent as one that has not arrived yet, and unlike a missing fix it will not turn up |
| **Its release is a tag, so it cannot change** | `out-of-support` | Above end-of-life, being the more fundamental statement: a supported tag is as unfixable as a retired one |
| Its release is past end-of-life (REQ-15) | `out-of-support` | |

Four reasons share three words. A tag reports as out of support, which is not
what it is — a supported tag carries no deadline for a more fundamental reason
than a retired one does. Stated here rather than left as a difference between
this table and the wire, and a word of its own is worth adding the day somebody
needs to tell the two apart.

There is no further reason, because a deadline is worked out at ingest for
everything else. Left blank, the column reads as missing data on the one screen
whose purpose is noticing what is running out.

A deadline nobody can meet is not a deadline, which is the one statement all
four make. Where upstream has released nothing there is no version to take, and
the only act that stops the clock is a person recording a judgment — which is
the act the deadline exists to ask for and cannot be the answer to. An overdue
list carrying rows no upgrade would answer is one people stop reading, and what
they stop reading is the rest of it.

How much of a real overdue list that is has not been measured here. The
proportion belongs beside this rule once somebody has it from a deployment, and
it is left out rather than estimated: a figure nobody can re-run is one a reader
has to take on trust, which is the opposite of what a number is for.

A scanner that did not answer is not upstream saying no. Reading silence as
"no fix exists" is a claim about the world made out of a gap in a report, and it
is the direction that loses a deadline somebody could have met. So an unstated
fix state stays on the clock.

This cuts overdue counts, and that is a correction rather than an
improvement. Anyone tracking the figure should be told why it moved. What it
does not do is flatter a response time: if a two-year-old issue was genuinely
learned of today, the response time is from today, and the accusation hiding in
the objection — that we should have known sooner — is a question about scanning
coverage rather than about where a clock starts.

What has no deadline is absent from every figure built on one, which is the
point and also the gap: nothing overdue, nothing due soon, and nothing in the
compliance rate. Three of the reasons already have somewhere to be seen — the
line is stated wherever a list hides something, a tag's findings are read at the
release, and what upstream has done is a column of the findings list and a
filter over it. End-of-life does not, so releases out of support are a report of
their own; `DESIGN-reporting.md` holds it.

A tag was built once and is what somebody received. No work will land in it
whatever a date says, so a deadline on one is unmeetable the moment it is
written. Measured on the demo without this rule: all 26 open findings on its
one tag carry a deadline, every one of them unmeetable by construction. Real
deployments accumulate tags while branches do not, so that side grows — and it
inflates every overdue count, the compliance rate among them.

The reason is derived rather than stored, and derived where the triage line is
applied, so the two cannot disagree. The deadline itself is stored, because
deriving it costs a pass over every open finding per urgency band — and it is
rewritten whenever the answer moves rather than only when the ranking does, so
a fix appearing upstream starts a clock that was not running and a fix withdrawn
stops one.

## Pending upgrades

The fix-bundle query inverted (REQ-35). A triager reads an upgrade and the
issues it closes, in the findings list's by-upgrade view; a coordinator reads a
build and the upgrades it is waiting on, here. One query read from either end,
and both ends are drawn.

Both ends key their rows on the fold, so an upgrade reads the same from either
direction.

The version in hand and the version being moved to are both stored with the
commitment. They are read off the findings that are still open, and landing the
upgrade closes them — so a plan deriving them went blank on an upgrade exactly
as the upgrade succeeded.

What each row reports is what is still open under it, counted from the findings
rather than from anything written down: the distinct issues the upgrade would
close here, and how many places those sit at. Nothing is declared done by hand — a
build is clear when it stops holding them.

## Upstream currency

What the public index for an ecosystem says the newest version is, for the
components this deployment builds rather than the ones a distribution
maintains. Off unless an administrator turns it on: it is the one thing here
that reaches the network.

| Rule | Reason |
|---|---|
| One replica asks, settled by a lease | These are free services somebody else runs, and the politeness the pass is built around — two hundred at a time, a quarter of a second apart — is a rate per deployment rather than per replica |
| The lease is taken again as the pass runs | Sized from the interval between cycles it is a guess at how long a pass takes, and the arithmetic says so: two hundred requests with a timeout each is far past several intervals. A slow index then hands the pass to a second replica mid-flight and both ask |
| A pass that has lost the lease stops | Two replicas asking is what the lease exists to prevent, and it is at somebody else's expense |
| The candidates are the ecosystems there is an index for | Maintained as the complement of one of them, every other unaskable ecosystem passed the filter, reached the asker, found none and was recorded empty — spending one of the pass's slots. An image with ten thousand distribution packages spent fifty passes writing nothing |
| A distribution package is not asked about | The distribution is the maintainer, and the date it released says nothing about the age of the software inside |

What comes back is classified, because the classes want opposite treatment.

| Answer | Recorded | Reason |
|---|---|---|
| A version | Yes | The thing being asked for |
| The index has never heard of it | Asked, with no version | A private module and a vendored fork both look like this, and neither is a fault. Recorded so the question is not asked again tomorrow |
| A refusal the index will repeat | Asked, with no version | A package withdrawn, a region blocked, a name that cannot be turned into a request, a document nothing can read. An answer we will never get is still an answer about this component |
| A bad day — too many requests, or the index itself unwell | Nothing | The one class worth coming back to: it stays due and the next pass asks again |

Everything that is not a bad day is recorded. Read as one, a refusal the index
repeats every time leaves the component unrecorded, and the window takes the
never-asked first — so it holds the head of every pass afterwards for ever,
with the components behind it never reached.

A previous answer is never overwritten by an empty one. An index returns
not-found for a renamed package and for some transient conditions, and letting
one of those destroy a version already in hand would sit on the hole for a
month.

### Names held back

What a request carries is a component's name. One per component, the name
and nothing else — no version, no build, no product. For an open-source
dependency that is public knowledge. For something built here it is the name of
a project, a team, or a product nobody has announced, and a public index
records every request made of it.

So a name this deployment calls its own is never sent. Three sources, unioned:

| Source | What it yields |
|---|---|
| The namespace this deployment publishes under | The organization in the three spellings the ecosystems use: the host, the host reversed, which is what a Maven group and a Java package are, and each label short of the top-level domain. Already required for CSAF and VEX and already meaning "who we are", so a deployment that publishes anything has said this once |
| What each build declared itself to be | The account, scope or group that identifier is published under. A root is the product this deployment builds, so who publishes it is this deployment by construction. Taken from the scan record rather than from the stored component, because the component standing for the product is stored by its name alone — a version on it would give the product a new identity every night |
| What the deployment stated | Whatever else an operator named, for what the other two cannot reach |

| Rule | Reason |
|---|---|
| A name is matched a part at a time, either exactly or followed by a separator | Matched anywhere in the string, one organization's name holds back every package containing those letters; matched only exactly, it misses the family of names the organization actually publishes, which is most of what it is for |
| The segment beside the package's name, never the whole namespace | A forge host is shared by everybody. Taking it would hold back most of an ecosystem while reporting that it was protecting one organization, which is the failure that makes an operator turn the feature off rather than tune it |
| Nothing is derived from the root's own name | A product called "core" would hold back every package whose name starts that way. A default that wrong is one nobody tunes |
| A label that names a kind of registration rather than an organization is dropped | Where a deployment publishes under a second-level registration, the generic part is nobody's name. It is a closed handful rather than a list of where each country's registrations begin, which is a file this does not have |
| It is a better default, not a control | A deployment needing certainty about what leaves it leaves the whole feature off, which is where it ships. This is what stops an ordinary deployment leaking its own names by turning on something that reads as harmless |
| Biased toward holding back, and it says what it held | Over-excluding loses an answer, which is visible on the screen that would have shown it and in the report beside it. Under-excluding sends a name to somebody else's service, which is visible nowhere and cannot be taken back |
| A held-back component is recorded as though it had been asked about | The window takes the never-asked first. Left unrecorded it holds the head of every pass afterwards for ever, with the components behind it never reached — the same failure the classification above exists for |
| Anything an index said about a held-back name is dropped | All of it was obtained by sending that name. Kept, the version stands on a screen with nothing that will refresh it, the component never reaches the report of what was held back, and the row goes stale in a day rather than in thirty — one of the pass's slots every day, sending nothing |
| A name a reader may not be told is not in the list the report carries | A label derived from a root is the name a product is published under, so the whole list states the scope of a product nobody announced to that reader (REQ-42). The classification still runs against every root, because a name the pass never sent must not read as sent |
| Identifiers are taken newest first | What a build declares itself to be carries its version, so a product built nightly states a new one every night and the bound falls on builds rather than products. Unordered, two callers deriving this separately get different sets and a name held back yesterday goes out today |
| The roots are read per pass, the rest at startup | A product declared this morning is one whose name should not leave this afternoon. The other two come from configuration and change on a redeploy |

### Unanswered components

Two questions that are one report, because they are asked together: what was
held back says what the default is costing, and what no public index has heard
of is the list an operator reads to decide what else should be held back. A
name promoted from the second appears in the first afterwards, which is how
somebody knows the promotion worked.

| Why there is no answer | |
|---|---|
| It is ours | Never sent. The names it was matched against travel with the report, so a row can be checked rather than taken on trust |
| No index knows it | Sent, and nothing had heard of it. A private module and a vendored fork both look like this, and neither is a fault |
| The identifier cannot be read | Nothing can turn it into a request. Kept apart from the one above because it is a fault in a document this deployment accepted rather than a fact about the world, and reading it as "no index knows this" would put it on the list of names somebody is about to hold back, where it means nothing |

The classification is derived rather than stored. A held-back name and one no
index knows are recorded identically, because the pass must record both. What tells them apart
is the same list applied again at read time, which also means the report
follows a change to the list immediately instead of waiting for a month of
backoff to expire.

A component the pass has not reached is not on it. It is waiting rather
than unanswered, and reporting a first day's backlog as though the indexes had
failed would make the list useless on the day somebody reads it.

Narrowed to the products the reader may read. A package identifier says what a
build is made of, so a list of them across the estate is an answer about
products rather than about the deployment (REQ-42).

## Version ordering

Where a component could go is every version the findings open against it name as
their fix. Two counts are answered for each, because they are two questions.

| Count | |
|---|---|
| What that release fixed | How many of what is open name that exact version. This is the release's own security content, and it is what the scanner said without any comparison |
| What reaching it closes | That, plus everything fixed at or before it. This is the question somebody choosing between two versions asks, and it is the one that needs an ordering |

Sorted on the first, the version worth taking sinks. Measured on the demo's
kernel: of 168 open, 158 have a fix across 13 named releases, the 6.12.100-1
release fixed 49, and the newest named, 6.12.107-1, fixed 2 while carrying every
fix before it. A list ranked on what each release fixed puts the version that
closes everything near the bottom.

| Rule | Reason |
|---|---|
| An ordering is per ecosystem, and only where its algorithm is written down | Debian's, RPM's, Alpine's and dotted numeric releases are written here. Everything else is left unordered rather than approximated, because an ordering claimed before its algorithm exists is the confident wrong answer |
| An algorithm is transcribed from the project that defines it | The tilde and caret rules, a numeric run outranking an alphabetic one, a leading zero turning a version part into text: each is a decision somebody made rather than something to reason out from a description |
| The cases that check it are written here, not taken | The projects that publish those suites are GPL-licensed and this one is Apache-2.0, so their files are not taken — the same answer the SBOM fixtures already give about the sample source beside the documents they do take. What is kept is the knowledge: a case per rule, with the ones that reverse the obvious answer marked as such. What is lost is that nobody else chose them, so a pair nobody here thought of is not covered, and each case says which rule it pins in exchange |
| A scheme is added by adding its algorithm, never by mapping it onto one already here | Every scheme here is unlike the others in some detail that only shows on a pair nobody thought to try. Sharing a scheme is right where an ecosystem genuinely uses it — the language ecosystems do — and elsewhere it is the confident wrong answer wearing a familiar name |
| The spelling decides, not the ecosystem | A runtime published through a language index and naming itself after its own toolchain has the scheme and not the spelling. One version a comparison refuses leaves the whole set unranked: a list ordered except for the entry nobody could place is not ordered |
| Every scheme can refuse, including the ones whose comparison answers for any two strings | The distribution schemes do. Debian's and RPM's walk runs and always produce an ordering, so they read as schemes that never fail. What an advisory wrote where a version belongs — "unfixed", a sentence — then outranked every real release, because a letter sorts above a digit, and was presented as the upgrade closing the most. Each scheme decides what a version of it looks like before comparing, and the rule is its own: for the two distribution schemes, that the version begins with a digit and holds only the characters a version may |
| Where a scheme's own tool falls back, this refuses | Alpine compares what it can read and sorts the rest as text; RPM orders any two strings at all. Both are reasonable for a package manager resolving a dependency it has to resolve somehow, and neither is right here, where the answer is a recommendation rather than a resolution. So a version that does not read leaves the pair unordered, and a published suite's own "invalid" list is what says which those are |
| Unranked means the two counts are equal and say so | An exact match still counts. What is never done is inferring that one version reaches another, so nothing overstates what an upgrade would close |
| Which scheme applies is read from the package identifier | Two ecosystems spell some versions identically and order them differently, so reading the shape of the string would order a package by whichever scheme its version happened to resemble |
| The scanner already compared versions to match the finding | So refusing to compare does not make the tool comparison-free — it leaves it unable to rank what it has already been told. What is new here is saying which of the answers is furthest along, not deciding which findings apply |

A wrong order is worse than none, which is why the refusal is part of the
mechanism rather than a gap in it: the answer arrives as a recommendation
somebody schedules a release around, and the scan that would catch it runs after
the release.

## Promise states

Three states, derived on every read and set by nobody.

| State | Condition |
|---|---|
| Landed | Nothing left open under it here, which the scans say |
| Lapsed | The date past with work outstanding |
| Planned | Everything else |

| Rule | Reason |
|---|---|
| The date is on the commitment, and the claim that argued for it is a citation | What somebody decided and what a release is waiting on are one fact. Changing it goes through the claim, so the two cannot come to disagree |
| There is no "replanned" | Re-promising writes a new date and the standing promise is the one read. A state nothing can distinguish from another is a word rather than a fact |
| A lapsed promise returns the upgrade, not its findings | One item, to whoever is carrying it — reported as a party only where one party holds all of what is still open under it. Answering the findings again one at a time is what the bulk promise was made instead of |
| A finding returns on its own only when the package moved and it did not close | A decision is keyed on the upstream version it was made against, so the existing key distinguishes "the plan was wrong about specifics" from "the plan did not happen" |

Stored rather than derived, these would be a third opinion capable of being wrong
about both the scans and the calendar.

## Build-declared suppressions

What a build says it deals with itself is readable as a history rather than a
list of what is true tonight. A carried patch is the only way a backport is
visible here — the fix is in the package, the version has not moved, and no
comparison of versions finds one — so the build declaring it is the sole
evidence.

| Rule | Reason |
|---|---|
| The stretch of scans is what makes it a history | The interesting row is the claim that *stopped*: somebody dropped a patch and the finding it answered is back. A list of what stands would not contain that row |
| Narrowed on what the claim says it is about, not on a package the build still carries | A claim naming something that has gone is what somebody asking why a patch stopped working wants |
| The two kinds are distinguished on the row | A claim attached to a component is a patch declaring what it fixes; a claim in a document of its own names something to be matched. A claim that suppresses nothing says so |

## External links

A claim carries a link to work happening elsewhere, and nothing is sent to
it (REQ-36): the link is stored and read by people. One link per claim rather
than one per release, because the conversation about a promise is one
conversation. What is not built is the tracker hand-off — opening or updating an
item in whatever system that link points at.

The signed outbound request (REQ-46) is a different thing and it is built;
`DESIGN-notifications.md` owns it, including the egress controls and the one
place a private address is deliberately permitted. Recorded here as unbuilt, it
read as there being no egress path at all, so the most review-worthy egress in
the deployment sat behind a document saying it did not exist.

| Rule | Reason |
|---|---|
| Nothing fetches what a link points at | A tool that fetched an address a person typed is a request-forgery primitive. Stored as text, shown as a link, encoded on the way out |
| Sent empty, it is cleared | A stale link sends somebody to a ticket that closed for a different reason |
| Anybody who may argue about a claim may point it somewhere | A link is a note about where the conversation is rather than a judgment |

Assigning notifies; planning does not (REQ-34). Somebody is told when work is put
on them. Saying which releases the work is meant to reach is done to the work.

## Publication

Nothing here is built apart from the document. A CSAF document is generated
and reachable at the advisory routes; nothing sends it anywhere. The rules below are
what publication would be, kept here because the document they are about exists
and the shape it would be published in is what makes its content right.

Publication covers a vulnerability in this deployment's own product. A known CVE
in a shipped third-party component is dependency hygiene a consumer reads out of
the inventory.

| Rule | Reason |
|---|---|
| A pluggable output with several adapters, not one integration | Publishing routes differ completely by product: an open-source project uses its forge's advisory system, an appliance vendor publishes on its own site. One integration would be one of those wearing the name of the general case |
| The triage record is ours; the published advisory is the platform's | Neither is a copy of the other and neither syncs |
| CSAF is the adapter that matters for commercial products | Nearly free from what is already held, because VEX is a CSAF profile and the dismissal vocabulary was aligned to it from the start |
| A forge's advisory system is one adapter | Draft privately, request an identifier, publish, and use its temporary private fork for fix work under embargo. Applies to nothing hosted elsewhere |
| Publishing aggregates | One advisory covers a product and a version range, not a path. A reader is asking "am I affected", and the answer is a version |
| Optional and configured per deployment | Nobody should need an account anywhere to use this |

## The advisory

An advisory is a record of its own, under an identifier this deployment mints.
It names the issues it covers and the products each of those is covered in.

| Rule | |
|---|---|
| An advisory is keyed on itself | Not on the product and the issue. The standard carries vulnerabilities as an array and means the document's tracking identifier to be the publisher's own name for the document, so a key made of one product and one issue cannot express a document about two and hands out somebody else's name for one of them |
| The identifier is minted here | A year and a number under a prefix the deployment configures. It is the name a reader cites the document by and the name a revision of it keeps, so it belongs to the document rather than to whichever issue was first |
| An advisory names many issues, across many products | Several embargoed flaws released together is one document on one date, which is what coordinated release is. One issue in two products is two entries, because the releases that carry it differ |
| An issue is named once per product | The pair is what a status is stated about. Named twice, a reader gets two answers about one release and the document is refused |
| Only a flaw recorded here | An issue a scanner reported against a third-party component is dependency hygiene a consumer reads out of the inventory. Refused when it is added rather than when the document is generated, so the refusal names the issue somebody chose |
| An advisory with no issues generates nothing | The standard requires at least one, and a document about nothing is not a draft of anything |
| An advisory is read whole or not at all | Somebody who may not see every issue it covers is told it does not exist, which is the answer a name nobody minted gets. A document with one of its products left out reads as a complete statement about a product it says nothing about, and a row saying one went out is as much a disclosure as the document |
| One covering nothing is its minter's alone | Covering nothing it satisfies every narrowing there is, and its title is prose somebody typed that goes on to be the document's. The same holds for one whose issues were all taken off |
| An issue taken off leaves its record | Who removed a flaw from a document is a question a deleted row does not answer. Naming it again revives that record rather than writing a second, which is also what keeps the pair unique |

An advisory is the rare, deliberate document. A vendor does not notify a
customer per inherited issue: those reach the release note and the disposition
register, and a customer reads them at upgrade time. What an advisory is
written for is a flaw recorded here, an embargo reaching its date, or an
inherited issue severe enough to say something about before the next release
cut — single or low double digits a year. The trigger is a non-public issue
becoming public.

## Editorial state

Where a document is in its life, read from what people did about it. A document
a second person agrees to is the publisher's settled word; one that has gone out
with nobody agreeing to what it says now is published and still being worked on;
anything else is being written.

| Status | Reached by |
|---|---|
| `final` | An agreement stands on what it says now, whether or not it has gone out |
| `interim` | It has gone out, and no agreement stands on what it says now |
| `draft` | Neither |

The agreement is asked before the issuance. A document is generated before it
is published, so the bytes an operator sends have to say what they are — and
asked in the other order the one file that actually goes out says it is a
draft.

The embargo answers a different question and is answered elsewhere. A document
about disclosed flaws can be unfinished, and one about an embargoed flaw can be
ready to go — so how far a document may travel is its distribution label, read
from whether anything it covers is still held back, and the editorial state
says whether this is the publisher's settled word.

### Editions and agreement

An edition is what an advisory says at a point. It carries the title, which is
the prose this deployment chose; what it covered at that moment is recoverable
from when each flaw was named on it and taken off.

| Rule | |
|---|---|
| An agreement names an edition | A second pair of eyes reads particular words. One naming the advisory would still be standing after somebody rewrote them, and nothing would report that (REQ-24 and REQ-28) |
| Retitling, naming a flaw and taking one off each open a new edition | All three change what the document says. An approver read a document covering three flaws, and a fourth added under their agreement is one nobody read |
| Opening an edition takes back every agreement standing on the one it replaced | The record says a second person did once agree, and to which edition |
| Changing what an advisory says needs a triage role on every product it covers | An advisory is read whole or not at all, so what it says about one product is part of the same document as what it says about another. Retitling, agreeing, taking an agreement back, and naming or removing a flaw all ask for it |
| The roles that may agree are the triage pair rather than the approver role a claim takes | Agreeing to an advisory is agreeing to a statement about every product it covers, which is what the triage roles are held per product for |
| Neither the person who started the advisory nor the author of the edition standing may agree to it | Whoever started it chose the name a reader cites it by and, in the ordinary case, the flaws it covers. There is no override, so a deployment with one person publishes no advisory — the control working rather than a gap in it |
| Taking an agreement back is an act of anybody who may change what the advisory says, and takes back every agreement standing | What it stops is the document going out rather than one person's opinion of it, so it needs no agreement of its own |
| An advisory goes out once an agreement stands on what it says | The text is the company speaking. Whether the flaws behind it are public is not asked: an advisory about an embargoed flaw sent to a coordinating body is what coordinated disclosure is made of, and the distribution label is what keeps it safe |
| An issuance names the edition that went out | The advisory moves on and what was published does not, so a record of March's document read through the advisory answers with June's title |

## The CSAF document

A CSAF 2.0 document generated for one advisory, from what is already held.
Nothing is sent anywhere.

| Rule | Reason |
|---|---|
| Only for a flaw in what this deployment ships | An issue a scanner reported against a third-party component is refused by name rather than answered with a document that looks the same and means something else |
| The document's identity is the advisory's minted identifier | A document naming an issue's identifier as its own tracking identifier claims to be the authority on that issue, which a coordinator is and this deployment is not |
| One entry per issue, and one branch per product | The tree carries a vendor branch holding one product branch for each product the advisory covers, and every status names releases of the product the issue was covered in |
| The publisher is deployment configuration, not an administrator's setting | It is the identity of the organization running this. Both a name and a namespace are required, because a document naming no publisher is not a CSAF document |
| A document about an undisclosed flaw travels no further, whatever its editorial state | Reaching a disclosure date discloses nothing (REQ-37), so generating a document does not either. The distribution label is what carries this; the tracking status says where the document is in its life |
| Releases are named by stream and variant together | Every release a status refers to is named in the product tree, and the list is ordered here rather than by the engine, so two documents generated from the same facts are the same bytes |
| A release that fixed the flaw is named as fixed rather than omitted | Omission reads identically to a release that never shipped the thing. What fills that list is somebody saying so (REQ-19), because for a recorded flaw no scan will |
| Every date the document states is a date and a time | The standard defines each of them that way, and a validator run with format assertions refuses a bare day — which is a document a customer's tooling drops, the failure that looks like nothing happening. A schema check run without them passes it, so the two disagree about a document nobody would accept |
| The document's version is the last number its own revision history states | Counted separately the two disagree the moment an advisory has been issued once, and a validator compares them. They agree by accident for a document nobody has published, which is where the disagreement hides |
| The publisher's category is one of the six the standard names, refused at startup otherwise | The value reaches the document verbatim, so a typo produces advisories that fail validation wherever anybody takes them — which is the one use a generated advisory has |
| The document declares the profile it satisfies, worked out from what it turned out to carry | Declared unconditionally, a document missing a profile-mandatory element fails that profile's own tests and is dropped by the tooling that reads it |
| The security-advisory profile is the product tree, the vulnerabilities, and notes and a status on each | The standard's own list. Notes and references on the *document* belong to the informational advisory — the profile for a document carrying no vulnerabilities at all — and gating on those declared a base document for every flaw of ours that nobody outside had written up yet, which a customer's tooling filtering for security advisories skips |

### Document contents

Everything below is already held. Nothing is derived, and a field the standard
defines and the record cannot answer is left out — an advisory is read by
somebody deciding whether to act.

| Element | What fills it | |
|---|---|---|
| References | The issue's write-up and everywhere else a report points, each address once | On the document rather than on the vulnerability. The document is about one flaw, so the two lists would hold the same addresses, and the profile requires the document's |
| Scores | The CVSS base vector, scored here | Worked out from the vector rather than read beside it: a stored number and a stored vector that disagree have nothing to say which was meant. A vector this deployment cannot score, or one on a scheme the standard's score object has no field for — version 4, which arrives with the standard's next version — yields nothing rather than a number in the wrong place |
| Acknowledgments | The credit the reporter asked to be named by | The credit alone. Reporting under a name gives it so somebody can reply, not so it can be published, and "anonymous" is a real answer to the question the credit field asks |
| Remediations | Stated for the releases that still carry the flaw, and the details name the releases that do not | That is who a remediation is for: the standard defines the product identifiers as what the item applies to, and a vendor fix as one for the affected product. Pointed at the releases already fixed, the customer who has to act reads an advisory with no remediation for them. "Update to a release in which this flaw is fixed" is that instruction with the answer left out, so the details name them, by the names the product tree gives them and in the order it gives them — not the earliest, which would mean ordering release names, and an ordering that answers confidently for a pair it cannot order is worse than none. Nothing about planned work: a commitment is one build's internal plan, and the same sentence in a published advisory is a promise to a customer about a date |
| Distribution | Whether anything it covers is still held back — RED while anything is, WHITE otherwise | Handing a document about a flaw nobody outside has been told about to somebody who may pass it on is the disclosure the embargo exists to hold, and that is true of a document at any point in its editorial life. The labels are the standard's four, which is why a disclosed document is WHITE rather than the word the protocol renamed it to |

An address a report supplied goes through the rule an address stored beside a
claim goes through, and a custom application scheme is dropped rather than
published. It is leaving the deployment, into tooling that follows it.

The weakness is stated in the catalog's own words. The standard carries a
weakness as the identifier and the name assigned to it, and a consumer's
validator compares the pair — so the name is read from the authority that
assigns it, never from anything held here.

| Rule | Reason |
|---|---|
| The names come from the published catalog, fetched and committed | A thousand names nobody can check by eye is a file that goes wrong quietly: one transcription error is a document refused at a customer, months later, over a weakness nobody was looking at. The same reason the reserved-word list is asked rather than typed |
| Not the names the interface uses | A screen names a weakness in a few words somebody scans — "Buffer overflow" — and the catalog calls that one "Improper Restriction of Operations within the Bounds of a Memory Buffer". Both are right for their reader and only one passes a validator, so they are two lists rather than one used twice |
| One weakness, the one the data calls the root cause | The standard carries one and an issue is commonly classified as several. Taking whichever sorts first is an answer with nothing behind it. A feed says which it calls primary and a person recording a flaw names theirs first, so the answer is carried from where it was stated |
| An identifier the catalog does not assign states nothing | Categories and views carry identifiers of the same shape and are not what a vulnerability is classified as, and a newer catalog assigns numbers an older one predates. The name is the half that cannot be invented |
| The catalog version is recorded and is not gated against what it publishes today | The engines the reserved-word list asks are pinned in CI and this authority is not, so a drift check would fail a build on the day it publishes, for a reason no change here caused |

Each release is named by what its own inventory called it. The product
identification helper carries the package identifier the build declared for the
component the document is about, where it declared one.

| Rule | Reason |
|---|---|
| The identifier the build declared, never one minted here | An identifier only helps if it appears on both sides of the comparison. A reader holding the image has whatever the build wrote into its inventory, which is this exact string if they ingested that document. A plausible identifier nothing outside this deployment has seen is worse than none, because a reader matches on it and misses |
| Read from the scan rather than from the root component | The root is stored by name alone, deliberately: a package identifier carries the version, the root's version moves every build, and the root's identity moving takes every edge hanging off it. What the document declared is a fact about that document, so it is kept beside the serial and what the inventory was made of |
| Absent where the document named no component of its own | The tracked unit stands in for the root there, and what stands in is ours rather than the producer's. A release with a declared root carrying no package identifier is the same answer for the same reason |

## The VEX document

Assembled from approved `not-applicable` and `already-fixed` claims (REQ-39),
and from `wont-fix` claims that say what a holder can do instead, for one
product, stream and variant.

A customer running their own scanner against a shipped image asks "which of these
are you not affected by" more often than they ask for an advisory. Generating it
puts this deployment's dismissals in writing, machine-readable, in front of every
customer — which is the reason the two-person approval on those claims exists.

| Rule | Reason |
|---|---|
| OpenVEX rather than the CSAF profile | It is the format this deployment already reads. One document shape to get right, and one deployment's output can be another's input |
| Approved claims only | A proposal is one person's opinion and this document is the deployment's word to a customer |
| The impact statement carries what stops the flaw, never the reasoning | The reasoning is the argument a triager put to a second person here, addressed to a reader who can see the record it argues against. Published it is this deployment's review of itself, machine-readable, in front of every customer running a scanner. The mitigation is the half somebody holding the build can act on |
| Where no mitigation was named the field is absent | Only one recognized reason asks for a mitigation, so most statements carry none. The justification beside it is what the format asks for, and silence says less wrongly than the wrong text |
| A deferral is absent rather than exported as anything | Publishing it as not-affected would assert we assessed something as harmless when we had only postponed it. Silence already reads as affected in this format |
| A claim that will not be fixed is published as affected, and only where it names what to do instead | It is the truth about such a flaw: it is there and it is staying. Nothing else ever says so — no scan closes a standing property of a shipped feature and no advisory is issued about one — so under silence it reaches a customer never. The format requires an action on an affected statement, so a claim with nothing to offer has nothing to publish, and left out it falls through to the silence that already reads as affected |
| The mitigation goes in a different field depending on the status | On a claim that something does not apply it is why, beside the category a machine reads. On one that will not be fixed it is what to do instead. An affected statement carrying a not-affected justification says both things at once |
| Public findings only | Asking for the undisclosed ones is a preview for somebody who may read them, and refused for anybody who may not |
| The statement is about the build, with the component underneath | A VEX statement is about a thing somebody has, and what they have is the image |
| A component with no package identifier is named by the name the build calls it | Less use to a machine, and better than a silent omission, which in this format reads as "no claim" |
| Every statement carries the other names its issue answers to (REQ-18) | A customer holds identifiers their own scanner produced, matched under the name *its* database uses. The primary is not repeated among the aliases |
| Ordered here rather than by the engine | Two documents generated from the same state are byte-for-byte identical |
| A build with more statements than one document carries is refused, not truncated | There is no second request for the rest, so a document that stopped at a ceiling would say "nothing is claimed about this" by omission about everything past it — to every customer running a scanner, which is the one thing a document of dismissals must never say. The ceiling is well above anything real, and reaching it names the build and the number |

A statement is made only where every open place agrees, and agrees the same
way. The format says "this product, this component, not affected" and has no
finer grain. A component commonly sits at several places, so a dismissal agreed
at one of them is not a claim about the component: published as one it is a
machine-readable "not affected" about something that is affected, sent to every
customer running a scanner against the image.

Places dismissed for different reasons — one not applicable, one already fixed —
produced two contradictory statements and now produce none.

Where several places were decided in separate sittings the document states the
earliest: the claim that has stood longest and the one a reader can check
against the record. Grouping on the words and the moment emitted the same claim
twice.

The earliest decision is picked first, and then read. A minimum per column with
nothing tying the columns to one row composes a statement from two claims: with
"component_not_present" and "inline_mitigations_already_exist / bound to the
management VLAN" both standing at a component, the machine-readable category
comes from one and the impact statement from the other, and the published
statement says the component is not present while describing the network
control that protects it. That is a composite no record ever held, going to
every customer running a scanner. The group answers with the earliest
decision's identifier, and its words are read by that identifier.

### Identity and revisions

| Rule | |
|---|---|
| The identifier names the build and nothing that moves | A reader keeps documents by it and tells a revision of one document from a second document by whether it matches. An identifier carrying the moment made every fetch a document in its own right, and named two documents generated inside one second alike |
| The build is named by the stored names | A name people type is matched without regard to capitals, so one build asked for two ways carries one name |
| The version is one past what has gone out | A document nobody has published is the first revision, and the next one generated after an issuance is the second. It says so before it goes out, because the bytes an operator sends carry the number they will be known by |
| Two generations with nothing published in between are one revision | The document is assembled from what stands now, and a change nobody has published is a revision no reader can hold |
| The moment the document was assembled sits in its own field | The format carries it there, and an identifier is an identity |

## Issuance records

An issuance records when a document went out, by whom, and a digest of what
went out. An advisory's is keyed on the advisory, which is what makes a
revision of a document covering two issues one record rather than two; a VEX
document's is keyed on the build it describes, which is what its identifier
names.
Without it a second document for the same advisory could carry no revision history
and could not increment its version, both of which CSAF validators check.

| Rule | Reason |
|---|---|
| It is a fact about a moment | What was published on a date cannot be worked out again once a release is added, a decision is revised or a fix lands |
| The digest covers what the document says, not the whole document | The current release date, the generator's date, the version and the revision history all move on generation or *because* of issuance, and the tracking status follows the agreement rather than the words. What is hashed is the title, the product tree and the vulnerabilities |
| The digest is taken from the document generated here | A caller-supplied digest is a digest of whatever they say, and both sides of the comparison must come from the same place |
| The version and history are derived from it | The next document is one past what has gone out. The last history entry is the document in hand, which has not gone out and says so |
| A revision is of the advisory, not of a flaw | An advisory covering two flaws that goes out once is one issuance, so the next document's history does not depend on which flaw is asked about |
| Recording that a VEX document went out asks for the triage role on the product | The document is this deployment's word to a customer. The second pair of eyes on each statement it carries was taken when the claim was approved, so no further agreement is asked for |
| The public document is what is recorded, never the preview | The preview carries work nobody has announced, and a record of it going out would say this deployment published that work |

### The two hashes

A published document has two, and they answer different questions.

| Hash | Over | Answers |
|---|---|---|
| The settled digest | What the document says, with the moment it was assembled, the software that assembled it, the version and the revision history left out | Is what is published still what this would generate |
| The delivered checksum | The bytes as published, every volatile field included | Did the file a reader fetched arrive intact |

The settled digest is taken as an issuance is recorded. The delivered checksum
belongs beside a published file and is not built; `Not built` below says what
is missing.

## Publisher identity

One record, not one per format. A VEX document and an advisory both name their
publisher and read it from the same configuration. Each carried its own copy of
the same two fields with a byte-identical method asking whether they were set,
and the handler between them converted one to the other.

The CSAF category rides along and VEX ignores it: a deployment publishing about
its own product is a vendor, which is what the format wants to be told.

## Not built

The CSAF document's VEX profile. The generated document is categorized as a
security advisory rather than as VEX — that profile's point is "not affected,
and here is why", and those justifications are not assembled into it.
The vocabulary is already correct; what is missing is the mapping from a
decision to the releases it covers. This does not concern the OpenVEX document
above, which is built and is a different document for a different reader.

The tracker hand-off (REQ-36). What exists is the link somebody typed, stored
and never fetched; what is missing is opening or updating an item in the system
it points at. The signed outbound request is built and is described in
`DESIGN-notifications.md`.

Every adapter that would send an advisory somewhere, which is the whole of
Publication above. The CSAF document is generated and served; no destination,
no adapter and no route to one exists.

The checksum over the delivered bytes. A CSAF provider directory publishes one
beside every file it serves, and nothing here writes such a directory, so
there are no delivered bytes to take it over. The settled digest above is the
hash that exists and answers a different question.

Prose of the deployment's own in the document beyond its title. An edition
carries the title, and the rest of what a reader acts on is assembled from the
flaws the advisory covers.

## Limits

| | |
|---|---|
| A bump is keyed on where it is going as well as where it comes from | Pending upgrades grouped on the first two fields and took the third from whichever row made the bucket, so two bundles at 5.9.0 and 5.9.2 rendered as one row saying 5.9.0. On a real image forty-two of a hundred and twenty-seven pairs carry more than one target version |
| A fix declared for a product covers its builds without being written per build | A decision's live key names the place and not the build, so a product shipping the same component in two builds produced two identical proposals and the second collided with the unique index, rolling back the whole declaration. The proposals are made distinct before they are written |
| A statement about a group speaks for the group | The outbound format has no place granularity, so a dismissal covering some of a group is not published as covering all of it |
