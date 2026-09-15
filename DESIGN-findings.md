# Findings

What a scan run found, where it sits, and how it is ranked and closed.

Satisfies REQ-08, REQ-11, REQ-13, REQ-14, REQ-15, REQ-17, REQ-18, REQ-19,
REQ-20, REQ-21, REQ-22, REQ-25, REQ-32, REQ-37.

## Contents

- [Fan-out](#fan-out)
- [The row a person reads](#the-row-a-person-reads)
- [Issue identity](#issue-identity)
- [What a report supplies](#what-a-report-supplies)
- [Who supplied a component](#who-supplied-a-component)
- [Merging later reports](#merging-later-reports)
- [Derived addresses](#derived-addresses)
- [What an index says](#what-an-index-says)
- [How a match was made](#how-a-match-was-made)
- [Interning a component](#interning-a-component)
- [Recorded flaws](#recorded-flaws)
- [Reporter details](#reporter-details)
- [Scoring](#scoring)
- [Affected build sets](#affected-build-sets)
- [Closure by a person](#closure-by-a-person)
- [What a scan governs](#what-a-scan-governs)
- [Interval storage](#interval-storage)
- [Closure reasons](#closure-reasons)
- [Build-declared claims](#build-declared-claims)
- [Fan-out cost](#fan-out-cost)
- [Decision state on a row](#decision-state-on-a-row)
- [Urgency](#urgency)
- [Work across builds](#work-across-builds)
- [Incomplete upgrades](#incomplete-upgrades)
- [Scanning as separate work](#scanning-as-separate-work)
- [A year of nightly scans](#a-year-of-nightly-scans)
- [The total above a list](#the-total-above-a-list)
- [The severity ladder](#the-severity-ladder)
- [File organization](#file-organization)
- [Limits](#limits)

## Fan-out

A scanner reports that a package at a version is affected and stops. It never
saw the dependency graph — it was given a list.

Fanning one reported issue out across the places it occupies is this
deployment's work, derived from the edges the inventory described. It is the
step where one line in a report becomes the number of decisions somebody has to
make.

A place is the component and what directly pulled it in. One issue in a shared
library used by two things is two findings, because different consumers use
different parts of what they depend on.

Something reported against a component this deployment does not hold is counted
and reported rather than dropped. It means the two documents describe different
builds.

## The row a person reads

Store expanded, present collapsed. Every place is stored, because the graph has
to stay answerable and the exact record has to name the artifact that shipped.
What a person reads is the fold: one issue at one source package, at the version
it was built at.

| | |
|---|---|
| Rows on the demo, by issue and component | 7,648 |
| Rows by issue and fold | **6,775**, 11.4% fewer |

Concentrated rather than uniform. Most rows are untouched; what collapses is the
work that was already one thing — `util-linux` was fourteen rows of the same
judgment, the same upgrade and the same routing rule.

Every number a person sees is counted in the unit they acted in. A row says how
many packages of the fold sit here and how many things pull them in, because
deciding on the row decides about all of them. The place count is still stored
and still what the bulk cap is measured against and what the disposition
register expands to — it is not a figure a reader is asked to reconcile with the
two above.

## Issue identity

The same vulnerability arrives as a national identifier from one database and an
advisory identifier from another. Which one a report calls primary is a
preference of whichever source the scanner consulted, so **identity spans the
names**: every name resolves to one row, and a decision holds across all of them.

| Rule | Reason |
|---|---|
| The lookup covers every name a report supplies, not the one it led with | One scanner reports the national identifier alone; another reports its own and knows the first as an alias. Matching only the leading name makes those two issues. The test pins that ordering, because the other ordering passes either way |
| An issue is filed under the most widely recognized of its names | What a person sees is the name they will find in an advisory. The rest are kept, and any of them finds the row |
| Identifiers are compared in one case | Every scheme treats them as case-insensitive and reports disagree about which case to write |
| A report that would merge two held issues is refused | That is a merge of findings and decisions already made against both, and reading a scan is the wrong moment to do it quietly |
| **Recording a name by hand asks for triage in every product the issue is open in** | Identity is deployment-wide, so from that moment a scan of any product reporting the name resolves to this issue and inherits its decisions and its approvals. Held at a role on the product in the path alone, somebody who reaches nothing in another product changed what a finding there means. Refused whole rather than partly done, and at the visibility each place carries |

## What a report supplies

Everything a report says about an issue is kept. None of it is recoverable
later, because a report is not kept once read.

Measured on a public switch operating-system image, per scan of 7,917 findings:

| Field | Present in |
|---|---:|
| Known to be exploited | **5** |
| Published likelihood of exploitation | 7,835 |
| Where the issue is written up | 7,917 |
| Description | 7,879 |
| Severity as a number, with the vector it assumed | 6,136 |
| When a fixing version became available | 5,390 |
| References | 11,593, of which **420 are patches** |

The first row is the reason for the rest. Five of nearly eight thousand are being
exploited, and that number turns an impossible queue into an afternoon. It was
being parsed and thrown away.

| Field | Treatment |
|---|---|
| Severity | Stored as a word, which is what ranks and what sets a deadline. A number is taken where the report carries one — the first rating stating both a score and its vector, worst claim winning. The vector travels with the number |
| Fix state | Three situations, not two: no fix available, upstream declined to fix, and a fixed version exists. "Upstream will not fix this" is a permanent condition that changes the outcome somebody should reach, and is invisible if the only record is that a fix is absent |
| Weakness classification | Kept where the data carries it, deduplicated and ordered. It groups findings by the shape of the mistake rather than the package it landed in |

## Who supplied a component

An inventory often says who supplied a component — a distribution, a vendor, a
project — and that is kept, because a bare name is not enough for a dependency of
a dependency somebody has never heard of.

| Rule | Reason |
|---|---|
| From the inventory, never from an index | It is what the producer of this build said, not what a registry says about a package in general. What an index says has its own section below and covers different fields |
| Absent for most of it, and said so rather than filled in | Measured on a switch image: 759 of 6,866 components carry one. A screen states that nobody said rather than showing a blank |
| Two ways of saying it, resolved after the whole description is read | One format states an object and a plainer string beside it, and the object wins where a producer fills in both. Resolved while reading, whichever key the producer happened to write first won — and key order is the producer's choice |
| A party's kind is dropped, its name kept | The other format prefixes it — "Organization: Debian" — and one of the two words is a label rather than a name. The word that format uses for "nobody stated one" is treated as nobody having stated one |
| Never part of identity | Two producers describing one component name its supplier differently or not at all, and an identity that moved with it would take every triage decision attached along with it |
| A later report fills it in where the row has none | The rule the section below states for everything else two reports can disagree about. Written only on the insert instead, a component first seen through a producer that stated none never got one, however many later scans said who it was |

## Merging later reports

Reports disagree and arrive in an order nobody controls. A later one fills in
what an earlier one did not know and **overwrites nothing**, or what is stored
would depend on which scan ran last.

| Field | Rule | Reason |
|---|---|---|
| Known-exploited | Moves forward only | It is a claim about the world rather than a description of an issue: a later report not mentioning it is a gap in that report |
| Score, likelihood | Keeps the worst anybody claimed | A maximum is the only answer that comes out the same whatever the order. A report saying something is worse is news; one saying it is milder is a gap |

A test puts the same two reports through in both orders and asserts they agree.

The maximum is written out rather than using the engines' greatest-of function,
which is not agreed on when one side is absent: two of the four answer "unknown"
where the useful answer is the number that is known.

## Derived addresses

Reading a finding offers addresses worked out from the two identifiers already
held (REQ-18): the issue's own record and the record under each other name it
goes by; where a distribution packages the component, that distribution's
answer; and the package's page in its own ecosystem.

Derived at read time and stored nowhere. An address worked out from two names
cannot go stale while the names are right, and storing it would put a second copy
of the templates somewhere to fall behind the first.

**One table, and the interface reads its answer.** The component screen had a
second table of its own, in a second language, with a different membership —
neither a superset of the other — and different answers for the same
identifier: it sent every Debian-family package to Debian's tracker, so an
Ubuntu package's link landed on a record for different code with a different
version history and a different advisory status, while the same finding's
server-computed link went to Launchpad. A link that lands on a record for the
wrong thing costs more than no link, because it is followed before it is
disbelieved. The package's page travels on the component's own read now, and
the second table is gone.

Kept apart from the references a report carried, because the provenance is a
different claim. On this deployment's own image, the references for a package
matched by identifier were a vendor bulletin, two gists and two mailing-list
attachments; the issue's write-up was another distribution's tracker; and the
record for the identifier on the screen appeared nowhere.

Nothing here fetches any of them. They are addresses handed to a person, so the
restriction on outbound network access is untouched (REQ-69).

References list patches first. Somebody deciding whether to backport rather than
upgrade needs the change itself. What is a patch is guessed from the shape of
the address — a commit, a pull request, a diff — and the guess errs toward
saying less: an unrecognized address is reported as discussion rather than
asserted to be a patch.

Patches are usually on another record. A Debian package matches Debian's record,
which points at Debian's tracker; the commits that carry the fix sit on the
upstream record, which the scanner reports alongside as a related vulnerability.
The parser declared the related records as carrying an identifier and nothing
else, so a kernel CVE whose upstream record lists eight `git.kernel.org` commits
showed one tracker link and no patches. References from every identifier an
issue answers to are kept, deduplicated against the matched record's own.

## What an index says

A bare name is not enough for a dependency of a dependency. Where an ecosystem
publishes an index, what it says about a package is asked for alongside the
newest version — one line saying what the package is, and where it is developed.

| Rule | Reason |
|---|---|
| One line, never the long description | What some indexes call a description is the package's whole README, measured at 2,894 characters for one ordinary package. That is a document; a row of a table wants a label |
| Absent is the ordinary case, not a gap | The module protocol for one ecosystem has no such field anywhere, and no index is asked about a distribution package, so a version with no summary beside it is normal. A screen shows what there is rather than a space where something failed |
| The address the index states beats one worked out from the name | A publisher said where the project lives; a template guessed. Where the index says nothing, the name still yields one, so there is usually an address either way |
| The project's own pages before its repository | Three of the indexes carry both and publishers fill in whichever they bothered with, so they are asked for in the order a reader wants rather than by picking one |
| Bounded and judged before it is stored | Both arrive over the network from a third party and are rendered to staff holding the most access. The summary is cut to a label on a rune boundary, and the address is judged against the two schemes anything else here may link to — at storage as well as at rendering, because a value that should never have been stored is one somebody later reads out by another route (REQ-66 and REQ-69) |
| An unusable half does not cost the rest | A refused address leaves the version and the summary recorded. One field a publisher filled in badly is not a reason to know nothing about the package |

Asking is the same pass that asks for the newest version, so it costs no extra
request: this is reading more of an answer already fetched. It is off unless a
deployment turns it on, like everything else that reaches the network.

**What no index gives is a distribution package's description.** Those live in a
distribution's own package index, which is one file per release rather than one
request per package — a different shape from the per-package asks here, and not
built.

## How a match was made

A scanner reaches a finding one of two ways, and on a distribution's package they
mean very different things (REQ-13).

| Method | Meaning |
|---|---|
| By advisory | The people who package it published one for this package in this ecosystem. It counts the packaging — "fixed in 1.37.0-r15" — so what it says about a fix concerns the version actually installed |
| By identifier | A published identifier compared against an upstream version range. It knows nothing about packaging, and a distribution backports fixes without moving the upstream version, so the match fires whether or not the patch is in. Neither confirmed nor refuted |

That distinction is the first question anybody asks about a distribution's
packages, and the scanner answers it in every result. It was being discarded,
which left a finding nobody had confirmed looking exactly like one the packagers
had.

The range and the source are kept with the finding, because "somebody has to
look" is easier to act on with the thing to look at in hand. Neither is compared
against anything, which would need an ordering per ecosystem.

| Rule | Reason |
|---|---|
| Unrecognized reads as the weaker of the two | A word this does not know is a word whose strength nobody has checked, and reading it as authoritative hides something |
| Unknown is not unconfirmed | Where a scanner said nothing, nothing is claimed. A working list that quietly holds everything nobody classified is one nobody can work down |
| Kept on the finding, not the issue | One issue reached through two ecosystems has two answers and the issue can hold only one. An issue first seen in a Debian image and later matched in an Alpine one showed Debian's tracker against the Alpine package |
| One answer per group | Every place of an issue at a component comes from the same line of a scanner's report |

## Interning a component

A component identified by its content is one row whoever writes it, so two
scans describing the same library at the same version are agreeing rather than
colliding.

| Rule | |
|---|---|
| The lookup is inside the writing transaction | A retry runs against a database that has moved |
| **A row another writer got to first is left alone** | The lookup says nothing about another transaction, against another target, finding the same component absent at the same moment — and a unique violation is not a retryable failure, so the loser did not retry: its whole scan apply failed and the producer was told its upload could not be read, for a component that is now present. Two replicas reading two scans at once is the shipped arrangement |
| The identifiers are read back rather than taken from the rows | A row somebody else wrote carries their identifier, and a row this statement skipped carries none |

## Recorded flaws

A vulnerability in what this deployment ships is usually known here before it is
known anywhere. It is a finding of a different kind (REQ-21), triaged, assigned,
decided, clocked and reported like everything else.

Filed under an identifier this deployment mints (REQ-19): the product's name,
the year, and a number — `SONIC-2026-481907` — which is the shape a vendor
advisory takes. A flaw nobody has published has no CVE, and waiting for one
means the record of what was known starts after the work does. Nothing is
configured for that prefix: the product has a name people type.

The number is drawn rather than counted. Counted from one it is a running total
of what the product has kept quiet: ask for the first, walk upward until the
answers change, and both how many undisclosed flaws exist and when the last was
recorded fall out of the names alone. Six digits, so every identifier reads the
same length. A collision is answered by drawing again inside the same
transaction, which also stops two people recording at the same moment being
handed the same one.

The width is not what makes it safe to probe. That is the routes answering a name
somebody holds and a name nobody holds identically (REQ-43).

| Rule | Reason |
|---|---|
| A CVE assigned later is another name for the same issue (REQ-18) | Identity is the issue rather than what it is called, so nothing moves: not the finding, not the decisions, not the approvals. The issue is then filed under the better-known name and the minted one stays an alias |
| A name another issue already answers to is refused, checked before the write | A constraint violation cannot distinguish "already recorded" from "that would merge two issues" |
| It starts undisclosed, and recording one asks for the private triage right (REQ-37) | Defaulting the other way makes the dangerous mistake the quiet one. Somebody who may argue about known issues in shipped components has not been handed the ones nobody has announced. Already-public is a flag on the request, asking the ordinary right |

One identifier, one finding per build. The same code goes out on several lines
and as several variants at once, so a flaw in it is not a fact about one build.
This is the shape a scanner's findings already have, so it lists, ranks, comes
due, carries decisions, groups across variants and appears in a comparison
exactly as a reported one does.

| Rule | Reason |
|---|---|
| Every build is resolved before anything is written | A component name one build holds and another does not is a question about which builds are affected, so it is refused and names the build rather than recorded against some of them and silently not the rest |
| One product | The identifier is minted per product, so a flaw in two products is two records |
| Every row gets the same embargo, rank and deadline | They are the same flaw. A build added later copies them, or the newest build would get a later deadline for the same flaw |
| What carries it is a component of the build, or the build itself | Naming nothing puts it on the root, which is honest where the flaw is in how the pieces fit together. Naming something the build does not hold is refused |
| A name the build holds more than once is refused with the choices | A name is not unique within a build and not rarely: a real switch image ships three vendored copies of one library, and thirteen names in it are held at one version by two components. The resolution goes through the same lookup every other component reference takes — it did not, and took the first row a name matched |

## Reporter details

The name, how to reach them, when it arrived, when it was acknowledged, and how
they wish to be credited (REQ-19). Without these the coordinated-disclosure
timeline cannot be evidenced, and the advisory's acknowledgments section is
empty, which is the part a researcher reads first.

| Rule | Reason |
|---|---|
| Every field is optional | A flaw found by whoever is typing has no reporter, and a form demanding one asks them to invent an answer. Nothing said reads as "we found it" |
| One row per issue, not per finding | A flaw recorded against four builds is one report from one person, and four copies of their address is four places for it to be wrong |
| **It records the product it was reported against, and that is who may read it** | An issue's identity spans its aliases, so the moment a CVE is recorded the same issue is open in every product a scan reports it in. Keyed on the issue alone, the reporter's name, address and received date were readable by anybody holding triage rights in any of those — and acknowledging from one of them cleared the unanswered condition out of another product's queue. The unanswered list stops fanning one letter out across every product the name reaches |
| Credit preference is kept apart from the name reported under | "Anonymous" is a real answer, and so is a handle that is not the name on the mail |
| The received date is what the embargo runs from (REQ-37) | A report that arrived a fortnight before anybody typed it in no longer puts this clock behind the reporter's. It falls back to when the record was made, and a date nobody can read is treated as one nobody gave |
| The acknowledged date records that somebody answered, rather than answering | What reaches a researcher is a mail from an address somebody already has. Acknowledging twice keeps the first date, and the condition it raises fires at once rather than after a period |

A public intake form is out of scope. This is the inside half.

## Scoring

| Rule | Reason |
|---|---|
| A score is never taken alongside a vector | Two values a caller states separately can disagree, and afterwards nothing says which was meant. The number sorts and the vector is what somebody can argue with |
| Base metrics only | Temporal and environmental scores describe a moment and a deployment, and the deployment reading a finding is not the one it is about |
| **The formula is here and nowhere else** | A screen composing a vector shows what it will score by asking, rather than holding a second copy: two implementations of a score disagree eventually, and what somebody saw while choosing would not be what was stored. That is what the scoring operation is for — it reads nothing, writes nothing and is reachable by any recognized credential, because a vector is not a secret |
| Version 3.0 and 3.1; anything else refused by name | They share a base formula, version 4 does not, and version 2 is a different scheme. A vector scored with the wrong formula produces a number nothing downstream can tell from a real one |
| Rounding is the scheme's own, in integer arithmetic | Floating point gets a different answer for some inputs: a value that should be exactly 8.6 is not representable, and a naive ceiling returns 8.7 |
| An unstated vector is not a score of zero | Zero says "harmless", a judgment nobody made during early triage |
| A severity may be left unstated (REQ-18) | Making somebody choose a word to get the record written is how a guess ends up stored as a judgment. It is not given *no* deadline: the windows answer for a severity they do not recognize |
| A person's severity is checked against the words rather than folded | A report's is folded, because a scanner that rated nothing is silent and silence is not a claim that something is mild. A person typing "urgent" is not silent; they are wrong, and folding would replace their judgment with one nobody made |
| Weaknesses are recorded as given, against no catalog | Trimmed, upper-cased, de-duplicated. A list refusing an identifier it had not heard of would refuse next year's |

## Affected build sets

Stated as a whole and the difference worked out. A set somebody can read back and
check is not the same as a stream of additions and removals.

Widening opens findings. Narrowing closes them as `invalid`, which counts as no
fix — the fix rate would otherwise improve every time somebody corrected a filing
mistake — and appears in no release note.

| Rule | Reason |
|---|---|
| A reason is required whenever a build is taken out, and no second person is | Removing a build with no explanation is the state a history exists to prevent. Requiring review to correct a filing mistake is how wrong records stay in place, and this narrows this deployment's own claim about its own product |
| Only a flaw recorded here | Which builds hold an issue a scanner reported is what the scans found, and setting it by hand would overwrite that |

## Closure by a person

Resolution is computed from scans everywhere else, which removes the gap between
somebody marking work done and the work being done. It needs evidence, and for a
recorded flaw there is none: the one path that closes a finding is a scan
applying what it found, and it passes over anything a person recorded.

So the computation has no input, and what came of that was not "not yet resolved"
but a finding that stayed open forever — a fix that shipped three releases ago
still reading as present, invisibly.

| Rule | Reason |
|---|---|
| A scanner's finding is refused | The evidence exists, and overruling it is what computing resolution was chosen to prevent |
| Closed per build, across every place the issue sits at there | A fix ships in a release |
| It carries who, when and why | A closure with no reason is refused |
| It asks the same right recording it asked, checked against each row | Somebody who may argue about disclosed findings has not been handed the undisclosed ones |
| Nothing reopens one | Undoing a closure needs somewhere to keep the closure that was undone, which is a table rather than a column |

Each refusal is the caller's to fix and says so: a name that reaches nothing, a
name that reaches several, a summary of nothing but whitespace, and a build with
no contents. The third is worth naming — a minimum length passes whitespace, so
it arrives from a request and used to be answered as a server fault.

## What a scan governs

A run is the authority on what it reported. It opens what it found and **closes
everything open that it no longer reports**, which is how a component leaving a
build stops being a finding without anybody saying so.

The sweep is bounded by what a scan can have an opinion about. A finding carries
a kind saying what produced it, and the sweep covers only the kind a scan
produces. Without that bound, a flaw somebody recorded by hand is closed by the
first run after it is written — silently, with a closure reason reading as
though the issue went away, and nothing reporting it.

The kind exists ahead of the second thing to put in it for that reason: a model
assuming every finding came from a scan could not take one that did not without
changing how closure works.

## Interval storage

Findings are open until closed and never deleted. Re-scanning happens nightly
against a vulnerability database that has barely moved, so a run finding the same
things writes nothing.

A finding carries when it opened and when it closed, rather than reaching the
run for a timestamp.

Three passes did the reaching, all as inner joins: the trend, the deadline
rewrite when the policy changes, and the urgency recount when a rating moves. A
finding with no run did not appear in any of them — not wrongly, but **absent**,
which is the worse failure. A number that is wrong invites somebody to check it;
a row that is missing looks like there was nothing to say.

Closure carries one more reason. Spelled as "a run closed this", the column
saying a finding is over could only be filled by something that never looks at it,
so a finding a run will never close could not be closed at all. The row carries
the moment, and what closed it sits beside as provenance: the run, or the person
and their reason. Every index that carried the run to answer "is this open"
carries the moment instead.

The run is still recorded where there is one, and it is what "what did this run
change" is counted by.

| Rule | Reason |
|---|---|
| One writer at a time, per target | Recording what a run found begins by taking the target row. Two runs in flight would both read the same open findings, compute the same difference and write it, leaving two open rows for one finding. An ordinary update is a lock every supported engine honors. The test runs two overlapping applications and was checked by removing the hold, which reproduces the double-open on all three server engines |
| A finding that is already open still moves | A fix appears, upstream declines to fix it, the build answers it. A run compares what it found against what is recorded and updates the parts that can move, stamping when they moved. Only those parts are compared: everything else is what makes it that finding |
| The intervals are the change record | Every node, edge, finding and claim records the run that opened it and the run that closed it, so asking what changed between two points is a query over those. There is no second table duplicating them |

## Closure reasons

| Reason | Meaning |
|---|---|
| Removed | The component is not in the build any more |
| Upgraded | Its upstream version moved — the version a vulnerability is matched against |
| Revised | The shipped version changed while the upstream version did not, which is what a carried patch looks like from outside |
| Superseded | The upstream version moved and the issue came with it: this row closed and the same issue is open against the new version |
| Fixed | Somebody declared a recorded flaw fixed here. The only closure a person writes |
| Unexplained | The component is present and unchanged, and the scanner stopped reporting it |
| Invalid | The record should not have existed: this build never shipped it, the entry named the wrong product, or it duplicates an issue already tracked |

Superseded is told apart from Upgraded because they are opposite answers to "was
this fixed", and conflating them put one issue in a release comparison as both
fixed and newly present.

Invalid is on a different axis. Every other reason answers "why did this stop
being present"; this says it was never present, so it is neither a resolution
nor a disappearance. **It never means the finding exists but does not apply
here** — that is a triage decision of `not-applicable` with the justification
that fits, agreed by a second person and exported as VEX. Letting the closure
absorb that case would route dismissals around approval.

Unexplained is always reported and never suppressed. There is no volume at which
"we cannot account for this" stops mattering. Several in one scan additionally
raise a scan-level warning, which says nothing the individual flags do not —
only that the likely fault is one broken scan rather than a dozen independent
oddities. A count rather than a proportion: on a large image a handful of
genuine disappearances is ordinary and a handful of unexplained ones is not.

The reason is worked out from what the build now contains, compared against what
the finding was about. That comparison reads the departed component from the
component catalog rather than the current build, because the reason it is closing
is usually that it is no longer there.

## Build-declared claims

A build sends what it has already decided does not apply to it. **Those claims
are kept as data when the scan is read**, not left in the document.

A nightly scan's documents are discarded once read, the vulnerability scan runs
after that, and it runs again on a schedule. A claim that lived only in the file
would be gone by the time anything needed it, and every carried patch would come
back as an outstanding vulnerability on the first re-scan.

A statement naming several packages becomes several claims, one per subject.
Claims are held over intervals, so re-sending them writes nothing; withdrawing
one closes it rather than deleting it, because what a release argued is a
question asked years later.

A covered finding is marked, not dropped. This is why claims are applied here
rather than upstream: a finding that never arrived is indistinguishable from a
scanner fault.

| The build says | Effect |
|---|---|
| It carries a fix, or the vulnerability does not apply | The finding is marked with the claim and is not work anybody has to do |
| It is affected, or it has not decided | Nothing is marked. The build is stating that it looked, which is information rather than an answer |

Where two claims cover one finding, the one attached to the component wins over
one that named something to be matched: the first knows exactly what it is about,
while the second may name a whole source tree. Where neither is attached, the
claims are read in a stable order.

## Fan-out cost

Measured on one real switch image, scanned live:

| | |
|---|---:|
| Components scanned | 8,523 |
| Distinct vulnerabilities | 5,652 |
| Components carrying at least one | 437 |
| **Findings** | **335,021** |
| …of which one kernel | **305,487** |

The kernel is 91% of it: 4,849 issues in it, and 62 modules built against it.
Those edges are real and the producer emits them deliberately, so anyone can
reason about kernel-ABI risk — but which module is loaded does not change whether
the kernel has a bug.

The model is not wrong: a finding is a component at a place, and those are the
places. What the number settles is that **grouping cannot be an afterthought in
presentation.** What is read back is one row per issue in a component, carrying
how many places it occupies and how many the build has already argued about. The
same image reads as **7,906 rows rather than 335,021**.

The grouping is done by the database. A page of fifty grouped rows read out of a
third of a million findings is not a page of fifty findings, and counting in the
application would mean reading all of them to show any of them. Only the names
are fetched in a second pass, because aggregating text is spelled differently on
every engine.

## Decision state on a row

Each row carries how far it has been decided, in the same four words the state
filter takes and by the same definition:

| State | Condition |
|---|---|
| Undecided | Nothing stands, waits or has lapsed at any place |
| Waiting | A claim stands proposed and nobody has agreed |
| Agreed | Every place is answered by a standing decision |
| Lapsed | A decision here stopped applying and nothing replaced it |

Some places approved and the rest never decided, with nothing waiting or lapsed,
is none of the four: the row carries no state, and the interface labels it partly
decided.

Undecided is nothing standing, not nothing ever said. Reading it as "no decision
row covers this place" left a withdrawn claim in no state at all — the row it
leaves behind covers the place, deliberately, so that "lapsed" can be said about
a claim holding no key. A finding somebody claimed and took back was neither
undecided nor any of the other three, disappeared from the count above the list
as well as from the list, and was never offered as work again. The product's own
totals counted it the same way and agreed.

The word on the row and the filter's own buckets are one rule, not two spellings
of it. They came apart twice: the filter counted a place as waiting without
asking whether the claim still held its key, while the row required it, so a
claim proposed and withdrawn put its group in the waiting list with a blank
state column; and the row asked "was anything ever said" for undecided where the
filter asked "does anything stand", so the same group was undecided to one and
nothing to the other. Both now ask the filter's question.

A live decision covers a place at the versions it was keyed on and no other.
These counts match a live decision by product, issue, place and both versions,
and match a lapsed or withdrawn one — which holds no key — by place alone.
Matched by place alone, a decision approved against one build's version read as
agreed over the next build shipping another.

A row also states when a live claim at one of its places is with its author, sent
back for more. That is the row a proposer is looking for, and the one the queue
no longer shows.

The page is read in two statements:

1. Group every open finding in the build by issue and component and keep the
   fifty most urgent, reading only the columns a covering index on the finding
   table holds. The total rides on the same statement as a window count over the
   groups, so it is counted through exactly the page's narrowing.
2. Read what the page shows about those fifty groups and no others: likelihood
   and score, the four decision counts, how many ways down there are, the fix.

Every filter narrows both statements through the same clauses, and none needs the
issue or the component joined under the grouping — a rating or a name is asked as
a membership test against the table that holds it. The decision-state filter is
built from the decisions outward, joined to the grouping by the finding's
identifier rather than a lookup per open row.

Measured on the full-size build, 241,479 open rows in 7,329 groups: the page
went from 2.0 s to 0.12 s, and asking for what is undecided from 2.3 s to 0.18
s.

## Urgency

Each finding carries an urgency, worked out when a scan is applied and read back
as written. Computing it while reading would mean joining every signal it is made
of, for every row, on every page of every list.

Ordering by how many places something occupies puts whatever is most widespread
at the top, which on a real image is the kernel.

It is worked out from what is on record about the issue, not from the report
being applied. A report is one source's account of one moment: it may omit that
something is being exploited, or carry a score lower than last week's. What the
issue holds is the worst anybody has claimed, moving only toward worse.

**The fourth signal, the rating, belongs to a product** (REQ-29). Three of the
four are properties of the issue and reach every product holding it; the rating
is the product's own where somebody there has made one and the published word
otherwise, so the same issue can sit at two different places in two products'
lists. A finding opened later reads it at the moment it opens, rather than
carrying a copy something has to remember to refresh.

And it is rewritten wherever the issue is open, not only in the build being
scanned — once per product holding it, each against that product's rating. A
nightly branch scan raising one of the issue's signals left every other build
carrying a number worked out from a world that had moved — a known-exploited issue in a shipped tag below
the triage line, answering no exploited filter, on no exploited clock, at the
bottom of the list, until somebody rescanned that tag, which for a tag is never.

| Rule | |
|---|---|
| The signals that moved are what decides who is re-ranked | The write that raises them reports whether any of them actually rose, so nothing is recomputed for a report that told us nothing new |
| Only learning something is exploited moves a clock | Neither the score nor the likelihood is in the deadline, and a clock reset by a revised number would never arrive |
| The clock runs from when it was learned | Counted from when the finding opened, an issue that became exploited after six months lands three days before it was known — a deadline nobody could have met |
| It is not a cache being refreshed | The stored order describes an issue rather than a moment, so it is rewritten when the signals move. What is stored because it cannot be worked out again is a different thing |

Four signals, in this order:

| Signal | Reason for its position |
|---|---|
| Known to be exploited | The difference between a risk and an incident |
| Reaches customers | A critical in something only the build system runs matters less than a medium in what people install |
| Severity | How bad it would be if it happened |
| Likelihood of exploitation | Which of two equally severe things to look at first |

Severity above likelihood, measured rather than assumed. The original order had
them the other way, and on a real image that put a 2004 negligible with no score
at all above every one of 379 criticals: its likelihood was 0.80 where theirs
topped out at 0.073. Multiplying the two — the published practice where these
scores are well spread — was tried next and reversed on the same image: 95% of
its open issues sit between 0.001 and 0.01 likelihood, so multiplying mostly
amplifies what is inside that spike and mediums jump criticals on noise.

The number is packed rather than weighted: each signal owns a range of digits,
so a signal never trades against a lower one. The reason is explainability — "it
scored 0.4 higher on a weighted sum of four things" is not something anyone
trusts or argues with, and packing gives a rule statable in a sentence.

Explainability is the packing, not a sentence generated beside it. A function
that turned a rank back into a list of reasons existed, exported and called by
nothing but its own test. What makes a position explainable is that the rule is
statable, and the interface says it from the signals a finding already carries.

A signal reported out of range is clamped. A source sending something impossible
would otherwise carry into the band above and rank as though it were being
exploited.

Where a report rates an issue only in words, the word stands in for a number, so
a finding rated in words does not sort below everything rated at all. A group
takes the urgency of the worst place it covers.

What is known changes under a finding that has not:

| Rule | Reason |
|---|---|
| The rank follows the issue | A scan finding the record has moved rewrites the urgency of every open finding of that issue. Held as at opening, the list would order by a number nobody could reconcile with the row beside it. It does not flap nightly, because the stored signals only move toward worse |
| The deadline follows only exploitation | Severity is the flaw, exploitation is a fact about the world, and neither score nor likelihood sets a clock. A clock reset whenever a number was revised would never arrive |
| A recount runs from the scan that learned the fact | An issue that becomes exploited after six months, clocked from the opening, would be given three days that ran out five months ago. This is how the published exploited catalogs work: their due dates run from the date an entry was added |

## Work across builds

A judgment carries no variant: it is keyed on the product, the place and the
upstream versions, so answering it on one build answers it on every build of that
product holding the same code.

Screens asking "what is there to do" show **one item per issue in a component in
a product**, not one per build (REQ-25). Listed per build, importing a second
variant doubles the list while doubling none of the work — which is what happened
the day a second variant was seeded, and the list went from 7,354 items to
14,681 against the same estate.

| Rule | Reason |
|---|---|
| Genuine differences break out by themselves | A component row is one name at one version, shared by every build shipping it, so two variants at the same version group together and two at different versions do not |
| The product stays in the key | A decision is a claim about one product's code, so two products shipping the identical component at the identical version are two judgments |
| An item still names a build | A screen has to link somewhere. It is one of the builds rather than the only one, chosen stably, with the count of builds beside it |
| Acting on it acts on all of it | Assigning covers every build of the product holding the component. Assigning one build would leave the identical work unassigned beside it |
| Counted in pieces of work | Counted in findings, one kernel flaw assigned to one person read as forty-eight held against her on the summary and as the single item it is in her own list. Late is counted the same way: a piece of work is late when any of its places is |

Measured on two variants of one switch image: 7,587 rows on one and 7,610 on the
other, which is 15,197 rows read one build at a time. Across the product it is
7,612 — so 7,585 of those rows were one piece of work seen twice, and **27 were
the genuine differences.**

What it gives up across builds is the way down. A dependency chain belongs to
one build's graph, so the column naming the two ends of the chain is empty
rather than filled from whichever build the row named. That is why the screens
*about* a chain still require a whole build, and why narrowing the list to a
subtree is refused rather than answered with the empty list walking no build
would produce.

A finding reads as one row per place. Two of its rows share a place where an
inventory describes one consumer twice — as a source package and as the
distribution's package: two components, one pair of names, and the key is the
names.

| Folding two rows into one place | |
|---|---|
| The way down is whichever of the two the graph could be walked to | Usually only one of them is reachable from the root |
| It is argued away by the build only where the build argued away both | An argument about one of two components is not an argument about the place |
| A claim standing on either row stands at the place, the lowest identifier first | A decision is keyed on the place and expires on the versions, and the two rows need not hold the same versions — a source package and the distribution's package of one name differ by a packaging revision, so a decision matches one row and not the other |

A row names what pulls it in even where the route up is unknown. Where the walk
up reaches nothing, both ends used to be blank and the row read "nothing records
what pulls this in" — two different statements, and the second was false. The
finding records its consumer whatever the graph managed; what was missing was
the route up, which happens where an inventory describes something under a
component not itself reachable from the root. A row with no walkable chain names
its consumer and leaves the owner empty.

A place names the claim standing on it, not only the decision. At most one live
decision stands per combination of code, so the two reach the same row — but the
claim is what a person acts on, and without it a claim shown there can count its
places and cannot name them.

## Incomplete upgrades

A finding that stays open across a component's upstream version change, where the
shipped version is not the version recorded as fixing the issue, is marked as an
incomplete upgrade. Both inputs are already stored, and the test is inequality.

For a producer that patches and bumps rather than upgrading wholesale, this is
the failure that otherwise goes unnoticed for a whole release cycle. It surfaces
today as a lapsed decision and a finding to judge again, which is aimed at a
triager; the useful reading is aimed at whoever did the bump.

Component identity carries the version, so a bump closes one finding and opens
another rather than updating in place, and both versions are in hand at the
moment of the change. The closed row records `superseded` and the version it
moved to; the new row records the version it arrived from.

The version moved to is written as the scan applies and cannot be derived later,
because the component that carried the issue leaves the inventory when the run
ends. It is recorded only where the version change closed the finding — not for a
removed component, and not for an unexplained closure.

Shown on the finding as the version it arrived from, and in the still-present
column of a release comparison. Not in the review queue, which lists decisions
rather than findings.

## Scanning as separate work

An inventory is read once, when it arrives. It is scanned again and again as the
vulnerability data moves underneath it, so reading an inventory leaves a scan to
be done rather than doing it.

| Rule | Reason |
|---|---|
| The scanner is given what was stored, not the file the build sent | That file is not kept for a moving line, so anything not stored can never be scanned. This is the argument for capturing a component's second identifier scheme at ingest |
| The product itself is left out of what the scanner sees | It is not a package any vulnerability database has heard of, and including it invites a match on a name that happens to collide |
| A run is recorded whether or not it found anything | Which scanner, which version, which vulnerability database, and whether it ran here. A run that failed is recorded as a run that failed, with the reason — a scanner that stopped working is otherwise indistinguishable from a product that stopped having problems |

## A year of nightly scans

The interval storage was shaped so a rebuild changing nothing writes nothing, and
a test asserts that. What nobody had checked was the shape after a year.

The model, stated because every number depends on it: a build of 700 components,
each sitting in 34 containers, so 23,800 places; 260 issues open at the start;
365 nightly rebuilds; 1% of components changing version each night; three new
issues a night matching something already shipped. A real image at about a tenth
of its size, with the shape kept and the constant shrunk.

The table grew 16.8 times over the year, from 8,840 rows to 148,614. The graph
grew alongside: 23,834 edges to 110,466, and 736 nodes to 3,284, because a
component whose version moves opens a new node and 34 new edges while the old
ones stay as closed intervals. Neither is a leak — every row is an interval
somebody can ask a question about — but **a deployment sizing a disk should know
the shape is multiplicative in consumers, not additive in components.**

| | findings list | running out | trend | a night, average | a night, worst |
|---|---:|---:|---:|---:|---:|
| SQLite | 27 ms | 72 ms | 419 ms | 0.31 s | 0.51 s |
| PostgreSQL | 24 ms | 75 ms | 136 ms | 0.67 s | 1.11 s |
| MySQL | 65 ms | 100 ms | 259 ms | 4.82 s | 12.56 s |
| MariaDB | 24 ms | 115 ms | 215 ms | 0.32 s | 0.83 s |

Read the read columns as an order of magnitude, not as a benchmark. Each is one
sample, and the harness takes two seconds apart on identical data: MySQL's trend
was 1.19 s and then 259 ms, MariaDB's findings list 212 ms and then 24 ms. What
the run is for is the *growth*, which is stable across both samples.

| Finding | Detail |
|---|---|
| The reads hold up | The findings list grew between 1.5 and 3.5 times while the table grew 16.8, because it is indexed on the target and whether a finding is closed |
| Trend is the one that grows, about linearly | 18 ms to 394 ms on SQLite, 7 ms to 114 ms on PostgreSQL, 15 ms to 1.19 s on MySQL. It reads every interval overlapping the window rather than a page, and the open set grows as issues accumulate. It is the first query to reshape if a deployment reports a slow front page |
| MySQL writes seven times slower than PostgreSQL and fifteen times slower than MariaDB | A nightly scan taking thirteen seconds is not an operational problem; the same code being fifteen times more expensive on one supported engine than on its own sibling is a fact to have before somebody chooses one |
| The cost is per statement, not per row | A night issues **1,699 statements on every engine**. What differs is what one costs: **203 µs on MariaDB, 404 µs on PostgreSQL, 2,835 µs on MySQL**. The lever for making MySQL faster is issuing fewer statements |

A quiet night issues **more** statements than the first — 1,699 against 1,077 —
because the first night is bulk inserts five hundred at a time and a quiet night
is an update per finding that moved.

The correction to the model says what that cost is made of. An earlier run
applied twice the churn it documented and its figures were withdrawn rather than
halved. Halving the churn halved MariaDB (0.64 s to 0.32 s) and cut PostgreSQL
by a third (1.04 s to 0.67 s) — and moved MySQL by four percent, from 5.01 s to
4.82 s. A cost that barely responds to how many rows changed is paid per
statement, and the error did not scale the four engines alike, which is why the
withdrawal was right.

Two reads grow with the calendar rather than with a build:

| After | receipts, first page | receipts, last page | release counts |
|---|---:|---:|---:|
| night 1 | 0–3 ms | 0–1 ms | 11–17 ms |
| night 365 | 3–4 ms | 2–3 ms | 71–88 ms |

The last page costs what the first does, because the pairing is done over all of
history precisely so it does not depend on which page is read. It grows with the
number of runs and not with the square of it: the uploads and the runs are both
held newest first and walked together once, so the upload a run is attributed to
is looked for from where the run before it stopped rather than from the top of
the list.

The two orderings that walk has to have are worth stating, because neither is
the one the page itself wants. The uploads are ordered by when they arrived
rather than by identifier — two recorded at the same moment take their
identifiers in whichever order they reach the table, and "the newest upload this
run covered" is a question about arrival. The runs are ordered by when they
finished rather than by identifier, which is the order the page reads them in.

What this does not measure: it was read as an administrator, who sees every
product, so the queries ran with no narrowing by product — the cheapest plan
available. One build, not the several a deployment tracks. And it assumes a
churn rate rather than observing one. `make measure` re-runs it, and the
constants at the top of the harness are the model.

## The total above a list

The figure above a list is what somebody quotes, so it counts the population
the list itself pages through.

| Rule | |
|---|---|
| It rides on the page | Counted after the grouping and before the limit, in the statement that groups, so the number and the rows cannot describe different sets |
| The empty page counts the same way | A page past the end, a deep link somebody kept, or the last page has no row to carry it, so a second statement answers — **grouped exactly as the page groups**. Grouped one step finer, two binaries of one source counted as two where the page draws one, and the figure changed depending on which page was being looked at |

## The severity ladder

The severity words were written out ten times under seven names, with three
different memberships. Three copies of an ordering is three chances for a word
added to one to be missing from the others.

| List | Purpose |
|---|---|
| The four rated bands | The order a report reads in |
| `negligible` and `none` | Answers a scanner gives and nobody ranks. They rank below every band, so they survive no floor at all |
| `everything` | Not a severity: the absence of a floor, which is why it sits with the floor rather than the ladder |

## File organization

The reads had grown into one file of two and a half thousand lines. They are
three questions:

1. **What is open here** — the list every screen pages through.
2. **Everything known about one issue at one component** — what somebody looking
   at a single row needs. A different question from the list rather than a longer
   version of it.
3. **What is open, gathered by the thing that would answer it** — by the upstream
   bump that would close it, or by the component it is against.

The split turned up a doc comment describing the component grouping sitting two
hundred lines away, above an unrelated type.

The narrowing, the page and the component view each have their own test file
already, which is what says the seam is real rather than a line count. What is
left beside them is the naming layer they share.

### What stays as it is

Recorded because the conclusion is the deliverable: a review that asks the same
question next year should find the answer rather than the question.

| Left alone | Why |
|---|---|
| `Store.Apply` | Applying a scan is one act with four phases that share too much state to separate without passing a ten-field struct between them. It is also the model the rest of the package is held to: every value the closure uses it fetches inside the closure, the target is locked first, the difference is computed in memory and written as bounded batches |
| `Store.Enter` | Fifty lines of refusals, each with its own reason, and one transaction. Both belong to the act; what it needed was the transaction discipline, which it has |
| `fix.go` | Two responsibilities with a clean read-and-write seam, and one subject — upgrade commitments. Splitting it now would be splitting to hit a number. The cut is there when the write half grows |
| The schema migrations | Each is one list of `CREATE TABLE` statements. The length is the schema, the comment beside each column is what makes it legible, and splitting a table group across two functions would break the ordering the chain exists to check |
| `sortedBy` and `sortedAcross` | Twenty near-identical lines whose tie-breaks genuinely differ. Both already read from the one allowlist, which is the half that matters; a shared function taking the tie-break as an argument saves a line and costs a call site that has to be read to know which list it is |

## Limits

- **Incomplete upgrades are stated as inequality, not ordering.** Nothing here
  can compare 3.0.12 against 3.0.14: there is no version comparison in this
  codebase, the fixed-in field is free text and is sometimes a list, and doing it
  properly means per-ecosystem ordering for Debian epochs, RPM release segments,
  semantic versions, and ecosystems following none of them.
- **The inverse is not detected**, and cannot be: a component at or past the named
  fix while the scanner still reports the issue would mean the scanner and the fix
  data disagree, and deciding that needs the ordering above.
- **A component nothing leads to still has a place — itself.** It ships, and an
  incomplete graph is normal.
- **Severity is stored on the issue, fix state on the finding.** Severity is a
  property of the vulnerability; whether a fix exists is a property of the version
  in front of you.
- **A place under the product records no consumer at all**, rather than recording
  the root and excluding it later. The root's name differs per variant, and a key
  that has to be remembered to ignore is one somebody will forget.
- **A derived address refuses a name that is nothing but dots**, rather than
  escaping it. A name and a version become path segments, and "." and ".." are
  resolved by the browser before the request leaves it. Everything else,
  separators included, is escaped into its segment (REQ-66).
- **An identifier is matched against an anchored scheme before it resolves.** A
  flaw this deployment recorded is filed under a name it minted, and a loose match
  would send somebody to a public page about something else.
- **A package kind nothing here knows produces no link.** A link that lands on the
  wrong thing costs more than no link, because it is followed before it is
  disbelieved.
