# Kinds of finding

A finding has a kind, saying what produced it. Each kind declares what
arrives, what its issue is, how a finding of it is identified and carried
across builds, what its absence means and which visibilities it may hold. Each
consumer of findings names the kinds it includes. Assignment, notes, approval,
the trail, queues and notifications are one implementation over every kind.

Satisfies REQ-14, REQ-17, REQ-18, REQ-19, REQ-21, REQ-25, REQ-43, REQ-50.

Neighboring pieces: what a vulnerability finding is and how a run closes one is
in `DESIGN-findings.md`; who reads each visibility is in `DESIGN-access.md`;
what is particular to analyzer results is in `DESIGN-analysis.md`.

## Contents

- [Kinds](#kinds)
- [Issue kinds](#issue-kinds)
- [Name resolution](#name-resolution)
- [Consumers](#consumers)
- [Inclusion](#inclusion)
- [Runs and series](#runs-and-series)
- [Component from a path](#component-from-a-path)
- [Source locations](#source-locations)
- [Limits](#limits)

## Kinds

| Declaration | Vulnerability | Entered | Analysis |
|---|---|---|---|
| What arrives | An inventory, matched by the scanner | A person | SARIF (`DESIGN-analysis.md`) |
| Issue | A published vulnerability, or a flaw minted here that a CVE was later recorded against | A flaw minted here | The analyzer's rule |
| Occurrence identity | Component and consumer (`DESIGN-data-model.md` § Occurrence identity) | Component and consumer | A code finding identity, minted at the first sighting and carried by matching |
| Carry across builds | Version and chain match (REQ-25) | Stated by a person | Matching (`DESIGN-analysis.md`) |
| Absence | The run closes it, with a reason | Nothing; a person closes it | No longer detected; the finding stays open |
| Visibilities | Public, private | Private, public | Internal, and public once its flaw is disclosed |

The issue kinds are data the code reads: a producer's names resolve among the
ones its kind declares. What absence means is what each kind's own reader
does, and the visibility a finding opens at is set by whatever records it.
Fuzzing is an intended kind and is **not built**; it needs a declaration, a
reader and an evidence view, and nothing in this document changes for it.

## Issue kinds

| Issue kind | Filed under | Its findings |
|---|---|---|
| Vulnerability | A CVE or an advisory database's identifier, with every name a report gives it | Vulnerability |
| Flaw | An identifier this deployment minted (`DESIGN-findings.md` § Recorded flaws) | Entered, and vulnerability where a scan reports a name recorded against it |
| Rule | The analyzer's name and its rule, `clang/core.NullDereference` | Analysis |

| Rule | |
|---|---|
| An issue holding a finding somebody recorded is a flaw | That is what minting one makes, and how an issue recorded before issues carried a kind is read |
| A merge keeps an issue a flaw where either side was one | The recorded findings move to the issue kept |
| The issue lists, the names an issue goes by and the issue statistics read per kind | An analyzer's rule is not a vulnerability, and a count of issues that mixed them would count both |

## Name resolution

A name a scan reports, and a name a person types, is resolved among
vulnerability and flaw issues only. A rule is never reached by one.

| Rule | |
|---|---|
| A producer's names are resolved among the issue kinds its finding kind declares | A rule reached by a CVE's name would merge an analyzer's rule with a vulnerability |
| A rule is filed under the analyzer's name and its rule identifier, joined by a slash | Two analyzers reuse rule names. No published vulnerability identifier holds a slash |
| An issue new to a report is filed as the first issue kind its finding kind declares | A scan introduces a vulnerability; recording a flaw mints one |

## Consumers

A consumer is something that reads findings. Each names the kinds it includes,
and a kind it does not name never reaches it.

| Consumer | Covers | Kinds |
|---|---|---|
| Closure | A run's sweep: what it opens, updates and closes | Vulnerability |
| Version carry | A decision lapsing when a version it was about moved, and a decision carried to a build whose versions match (REQ-25) | Vulnerability, entered |
| Ranking | Urgency and deadlines, and the passes that rewrite them | Vulnerability, entered |
| Triage | The findings lists and their counts, one finding's page, notes on an issue, and disclosure | Vulnerability, entered |
| Assignment | Giving work to a person or a team, handing over everything somebody holds, handing back what a lost role carried, assignment by a team's rules and their preview, and the lists of who holds what: unassigned work, one person's work, a team's queue and the totals per holder (`DESIGN-access.md` § Teams, `DESIGN-analysis.md` § Code finding assignment) | Vulnerability, entered, analysis |
| Decisions | Decisions and their occurrences, the reasoning and its revisions, approvals, comments on a decision, the review queue, every read of one decision, the audit log and its file, and the notices about decisions: waiting, sent back, lapsed and an agreement withdrawn | Vulnerability, entered, analysis |
| Inventory | A build's tree, a component and the occurrences it sits at | Vulnerability, entered |
| Statistics | Trends, comparisons of two builds, coverage, the reports and the home page's figures | Vulnerability, entered |
| Exports | The findings lists written out as files (REQ-50): the list's rows, then the code findings of the same selection as the Code findings consumer reads them | Vulnerability, entered, analysis |
| Register | The disposition register: what was decided at every occurrence of one build, its screen and its file | Vulnerability, entered |
| VEX | The documents stating what affects a build | Vulnerability, entered |
| Advisories | The documents about flaws recorded here | Vulnerability, entered |
| Notifications | What is said to people about findings | Vulnerability, entered |
| Evidence | One code finding's evidence: where it is, the path the analyzer took to it, links into the source, and the source kept beside it (`DESIGN-analysis.md` § Source) | Analysis |
| Code findings | The code finding queue: a product's code findings by where they stand, with how many each list leaves out, the code findings a suppression rule covers, the queue's file, the code findings a findings list's file carries, and the counts of a product's code findings by analyzer series, and the notices about code findings and their series (`DESIGN-analysis.md` § Code finding queue, § Suppression rules; `DESIGN-notifications.md` § Analyzer alerts, § Code finding notices) | Analysis |

Analysis findings are included by Evidence, Code findings, Decisions, Assignment and
Exports alone: a code finding is read through the code finding queue, its evidence and the
decisions about it (`DESIGN-analysis.md` § Code finding triage), held the way a finding
is, and a findings list's file writes out the open code findings of its selection
beside the list's rows. The audit log's file follows Decisions and includes decisions about
code findings, because it writes what the audit log shows, under the same visibility
(REQ-50). `DESIGN-interface.md` § Security testing holds the screens.

| Rule | |
|---|---|
| Exports names the findings lists' files alone, and the disposition register is Register | The register states the decision at every occurrence of a build beside its VEX document, and reads findings rows by the consumer it names. Naming analysis on one consumer covering both would put every code finding into a statement about what a build ships |
| A findings list's file reads its code findings through the Code findings consumer's read, and its other rows through the list's own | A list and its file are one read (`DESIGN-analytics.md` § Exports), and a findings file holds the open code findings under the queue's visibility and in its order |
| The counts by series are part of Code findings, not of Statistics | Statistics feeds the vulnerability figures, and a code finding nobody has judged is not one of them |
| Each is the queue's own read over the queue's own visibility | A figure, the list it opens and the file of that list count one population |
| Assignment is a consumer of its own, not part of Triage | Triage feeds the findings lists and disclosure, and naming analysis there puts a code finding nobody has judged into both. Holding work is one act whatever the work is, so a handover and a lost role move a code finding with everything else |
| The lists of who holds what are Assignment's | Holding work is one act whatever the work is, so a code finding held is listed where held work is. The digest of what somebody holds is Notifications', and names no code finding |
| A code finding is one piece of held work at its occurrence | A vulnerability's piece of work is an issue in a component in a product. A code finding is judged at its occurrence, and its builds may name different versions of its component |

## Inclusion

| Rule | |
|---|---|
| Every statement reading or writing findings names its consumer's kinds | A statement that names none includes every kind there will ever be |
| Kinds are named as an inclusion, never as an exclusion | A list of exclusions is a list somebody forgets to extend |
| A statement reading findings by identifiers a kind-narrowed statement chose names none again | The identifiers already carry the answer |
| The finding indexes a read answers from without the table carry the kind beside the visibility | A covering index without the kind costs a table row per finding read |
| The kind is the first boundary, and the internal visibility the second | A code finding included in its flaw's disclosure is public once its flaw is disclosed, and only its kind keeps it out of the vulnerability documents and figures |

## Runs and series

A series is one analysis a product runs the same way on every build, named by
the producer: `clang-tidy/default`. A run is one arrival of a series' results
against one build. The analysis kind is the one that arrives this way
(`DESIGN-analysis.md`).

| Rule | |
|---|---|
| A series is per product and per kind, and its name is matched without regard to capitals | A name people type |
| A run is ordered by the build time it states, and only one built after the series' last applied run on the build is applied | A run arriving late would mark results absent and the next would reopen them |
| A run repeating one already held, on its documents and stated build time, is answered as that one | A retry after a timeout that had succeeded (REQ-06) |
| A run is comparable where its absences are evidence; one that is not adds and updates findings and marks none absent | `DESIGN-analysis.md` § Run parameters holds the reasons |
| A sighting is what a series knows of one finding: the run that first saw it, the last that did, and the first comparable run that did not | Absence is an interval on the sighting rather than a closure |
| A run's documents are placed at the door and not stored; its placed results are held until it is applied, then let go, and its receipt stays | What a run said is recorded on the findings it saw |

## Component from a path

A finding of a kind whose results carry paths is placed at the component the
build's inventory says was built from the repository holding the path, and at
the build itself where none was. `DESIGN-analysis.md` § Placement holds the
rules.

## Source locations

The path, lines, columns, enclosing function, flow steps and related places
of a finding are stored as the newest run that saw it stated them. Links into
the source are built when the evidence is read, and source text is kept only
under a path the product allows it for (`DESIGN-analysis.md` § Source).

## Limits

| Limit | Detail |
|---|---|
| A rule's identifier could collide with a published name | The name is unique across every issue kind. A scanner reporting a name with a slash identical to an analyzer's rule would be refused where it would be written. No published vulnerability identifier holds a slash |
| The kind is declared in code | A kind is a reader, a matcher and an evidence view as well as a declaration, so a deployment cannot add one by configuration |
