# Kinds of finding

A finding's kind says what produced it. Each kind declares what arrives, its
issue, how a finding is identified and carried across builds, what its absence
means and which visibilities it holds; each consumer of findings names the
kinds it includes. Assignment, notes, approval, the trail, queues and
notifications are one implementation over every kind.

Satisfies REQ-06, REQ-14, REQ-17, REQ-18, REQ-19, REQ-21, REQ-25, REQ-43, REQ-50.

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
| What arrives | An inventory, matched by the scanner | A person (REQ-19) | SARIF (`design-docs/analysis.md`) |
| Issue | A published vulnerability, or a flaw minted here that a CVE was later recorded against | A flaw minted here | The analyzer's rule |
| Occurrence identity | Component and consumer (`design-docs/data-model.md` § Occurrence identity, REQ-17) | Component and consumer | A code finding identity, minted at the first sighting and carried by matching |
| Carry across builds | Version and chain match (REQ-25) | Stated by a person | Matching (`design-docs/analysis-matching.md` § Matching) |
| Absence | The run closes it, with a reason (REQ-21) | Nothing; a person closes it | No longer detected; the finding stays open |
| Visibilities | Public, private | Private, public | Internal, and public once its flaw is disclosed |

| Rule | Reason |
|---|---|
| The issue kinds are data the code reads, and a producer's names resolve among those its kind declares | |
| What absence means is each kind's own reader's, and the visibility a finding opens at is set by whatever records it | |
| Fuzzing is an intended kind and is not built (REQ-14) | It needs a declaration, a reader and an evidence view, and nothing here changes for it |

## Issue kinds

| Issue kind | Filed under | Its findings |
|---|---|---|
| Vulnerability | A CVE or an advisory database's identifier, with every name a report gives it (REQ-18) | Vulnerability |
| Flaw | An identifier this deployment minted (`design-docs/findings-flaws.md` § Recorded flaws) | Entered, and vulnerability where a scan reports a name recorded against it |
| Rule | The analyzer's name and its rule, `clang/core.NullDereference` | Analysis |

| Rule | Reason |
|---|---|
| An issue holding a finding somebody recorded is a flaw | That is what minting one makes, and how an issue recorded before issues carried a kind is read |
| A merge keeps an issue a flaw where either side was one, and the recorded findings move to the issue kept | |
| The issue lists, the names an issue goes by and the issue statistics read per kind | A count mixing rules and vulnerabilities counts both |

## Name resolution

| Rule | Reason |
|---|---|
| A name a scan reports or a person types resolves among vulnerability and flaw issues only, never a rule | |
| A producer's names resolve among the issue kinds its finding kind declares | A rule reached by a CVE's name would merge an analyzer's rule with a vulnerability |
| A rule is filed under the analyzer's name and its rule identifier, joined by a slash | Two analyzers reuse rule names, and no published vulnerability identifier holds a slash |
| An issue new to a report is filed as the first issue kind its finding kind declares | A scan introduces a vulnerability; recording a flaw mints one |

## Consumers

A consumer reads findings and names the kinds it includes; a kind it does not
name never reaches it.

| Consumer | Covers | Kinds |
|---|---|---|
| Closure | A run's sweep: what it opens, updates and closes | Vulnerability |
| Version carry | A decision lapsing when a version it was about moved, and carried to a build whose versions match (REQ-25) | Vulnerability, entered |
| Ranking | Urgency and deadlines, and the passes rewriting them | Vulnerability, entered |
| Triage | The findings lists and their counts, one finding's page, notes on an issue, and disclosure | Vulnerability, entered |
| Assignment | Giving work to a person or team, handing over everything somebody holds, handing back what a lost role carried, a team's assignment rules and their preview, and the lists of who holds what: unassigned work, one person's work, a team's queue and totals per holder (`design-docs/access.md` § Teams, `design-docs/analysis-triage.md` § Code finding assignment) | Vulnerability, entered, analysis |
| Decisions | Decisions and their occurrences, reasoning and revisions, approvals, comments, the review queue, every read of one decision, the audit log and its file, and the notices about decisions: waiting, sent back, lapsed and an agreement withdrawn | Vulnerability, entered, analysis |
| Inventory | A build's tree, a component and the occurrences it sits at | Vulnerability, entered |
| Statistics | Trends, comparisons of two builds, coverage, the reports and the home page's figures | Vulnerability, entered |
| Exports | The findings lists written as files (REQ-50): the list's rows, then the code findings of the same selection as the Code findings consumer reads them | Vulnerability, entered, analysis |
| Register | The disposition register: what was decided at every occurrence of one build, its screen and its file | Vulnerability, entered |
| VEX | The documents stating what affects a build | Vulnerability, entered |
| Advisories | The documents about flaws recorded here | Vulnerability, entered |
| Notifications | What is said to people about findings | Vulnerability, entered |
| Evidence | One code finding's evidence: where it is, the analyzer's path to it, links into the source, and the source kept beside it (`design-docs/analysis-source.md` § Source) | Analysis |
| Code findings | The code finding queue by state, with what each list leaves out, the code findings a suppression rule covers, the queue's file, those a findings list's file carries, the counts by analyzer series, and the notices about code findings and their series (`design-docs/analysis-queue.md` § Code finding queue, `design-docs/analysis-triage.md` § Suppression rules, `design-docs/notifications.md` § Analyzer alerts, § Code finding notices) | Analysis |

Analysis findings reach Evidence, Code findings, Decisions, Assignment and
Exports alone (`design-docs/analysis-triage.md` § Code finding triage). The
audit log's file follows Decisions and includes decisions about code findings,
because it writes what the audit log shows under the same visibility (REQ-50).
`design-docs/interface.md` § Security testing holds the screens.

| Rule | Reason |
|---|---|
| Exports names the findings lists' files alone, and the disposition register is Register | The register states the decision at every occurrence beside the build's VEX document; analysis on a consumer covering both would put every code finding into a statement of what a build ships |
| A findings list's file reads its code findings through the Code findings consumer's read, and its other rows through the list's own | A list and its file are one read (`design-docs/analytics.md` § Exports), holding the open code findings under the queue's visibility and order |
| The counts by series are part of Code findings, never Statistics | Statistics feeds the vulnerability figures, and an unjudged code finding is not one |
| Each is the queue's own read over the queue's own visibility | A figure, the list it opens and that list's file count one population |
| Assignment is a consumer of its own, apart from Triage | Triage feeds the findings lists and disclosure. Holding work is one act whatever the work, so a handover and a lost role move a code finding with everything else |
| The lists of who holds what are Assignment's; the digest of what somebody holds is Notifications', and names no code finding | A held code finding is listed where held work is |
| A code finding is one piece of held work at its occurrence | A vulnerability's piece of work is an issue in a component in a product; a code finding's builds may name different versions of its component |

## Inclusion

| Rule | Reason |
|---|---|
| Every statement reading or writing findings names its consumer's kinds | One naming none includes every kind there will ever be |
| Kinds are named as an inclusion, never an exclusion | A list of exclusions is one somebody forgets to extend |
| A statement reading findings by identifiers a kind-narrowed statement chose names none again | The identifiers carry the answer |
| The finding indexes a read answers from without the table carry the kind beside the visibility | A covering index without it costs a table row per finding |
| The kind is the first boundary, and the internal visibility the second (REQ-43) | A code finding included in its flaw's disclosure is public once the flaw is, and only its kind keeps it out of the vulnerability documents and figures |

## Runs and series

A series is one analysis a product runs the same way on every build, named by
the producer: `clang-tidy/default`. A run is one arrival of a series' results
against one build. The analysis kind arrives this way (`design-docs/analysis.md`).

| Rule | Reason |
|---|---|
| A series is per product and per kind, its name matched without regard to capitals | A name people type |
| A run is ordered by its stated build time, and only one built after the series' last applied run on the build is applied | A late run marks results absent and the next reopens them |
| A run repeating one held, on its documents and stated build time, is answered as that one | A retry after a timeout that had succeeded (REQ-06) |
| A run is comparable where its absences are evidence; one that is not adds and updates findings and marks none absent | `design-docs/analysis.md` § Run parameters holds the reasons |
| A sighting is what a series knows of one finding: the run that first saw it, the last that did, and the first comparable run that did not | Absence is an interval on the sighting, never a closure |
| A run's documents are placed at the door and not stored; its placed results are held until applied, then let go, and its receipt stays | What a run said is recorded on the findings it saw |

## Component from a path

A finding of a kind whose results carry paths is placed at the component the
build's inventory says was built from the repository holding the path, or at the
build itself where none was (`design-docs/analysis-source.md` § Placement).

## Source locations

The path, lines, columns, enclosing function, flow steps and related places of
a finding are stored as the newest run that saw it stated them. Links are built
when the evidence is read, and source text is kept only under a path the product
allows (`design-docs/analysis-source.md` § Source).

## Limits

| Limit | Detail |
|---|---|
| A rule's identifier could collide with a published name | The name is unique across every issue kind, so a scanner reporting a slashed name equal to an analyzer's rule would be refused where written. No published vulnerability identifier holds a slash |
| The kind is declared in code | A kind is a reader, a matcher and an evidence view as well as a declaration, so no deployment adds one by configuration |
