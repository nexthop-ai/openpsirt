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
| Place identity | Component and consumer (`DESIGN-data-model.md` § Place identity) | Component and consumer | A lead identity, minted at the first sighting and carried by matching |
| Carry across builds | Version and chain match (REQ-25) | Stated by a person | Matching (`DESIGN-analysis.md`) |
| Absence | The run closes it, with a reason | Nothing; a person closes it | Not reproduced; the finding stays open |
| Visibilities | Public, private | Private, public | Internal; private once moved into a case |

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
| Triage | The findings lists and their counts, one finding's page, assignment and routing, notes on an issue, and disclosure | Vulnerability, entered |
| Decisions | Claims and their rows, the reasoning and its revisions, approvals, comments on a claim, the review queue, every read of one claim, and the record of judgments and its file | Vulnerability, entered, analysis |
| Inventory | A build's tree, a component and the places it sits at | Vulnerability, entered |
| Statistics | Trends, comparisons of two builds, coverage, the reports and the home page's figures | Vulnerability, entered |
| Exports | The findings lists written out as files (REQ-50) | Vulnerability, entered |
| VEX | The documents stating what affects a build | Vulnerability, entered |
| Advisories | The documents about flaws recorded here | Vulnerability, entered |
| Notifications | What is said to people about findings | Vulnerability, entered |
| Evidence | One lead's evidence: where it is, the path the analyzer took to it, links into the source, and the source kept beside it (`DESIGN-analysis.md` § Source) | Analysis |
| Leads | The lead queue: a product's leads by where they stand, with how many each list leaves out, what pulls one out of the baseline, and the leads a standing rule covers (`DESIGN-analysis.md` § Lead queue, § Dismissal rules) | Analysis |

Analysis findings are included by Evidence, Leads and Decisions alone: a
lead is read through the lead queue, its evidence and the claims about it
(`DESIGN-analysis.md` § Lead triage). The record's file follows Decisions and
includes claims about leads, because it writes what the record shows, under the
same visibility (REQ-50). A file of the lead queue is **not built**;
`DESIGN-interface.md` § Static analysis leads holds the screens.

## Inclusion

| Rule | |
|---|---|
| Every statement reading or writing findings names its consumer's kinds | A statement that names none includes every kind there will ever be |
| Kinds are named as an inclusion, never as an exclusion | A list of exclusions is a list somebody forgets to extend |
| A statement reading findings by identifiers a kind-narrowed statement chose names none again | The identifiers already carry the answer |
| The finding indexes a read answers from without the table carry the kind beside the visibility | A covering index without the kind costs a table row per finding read |
| The kind is the first boundary, and the internal visibility the second | A lead moved into a private case is private, and only its kind keeps it out of the vulnerability documents and figures |

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
