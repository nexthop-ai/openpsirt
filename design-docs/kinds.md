# Kinds of finding

A finding's kind says what produced it. Each kind declares what arrives, its
issue, how a finding is identified and carried, what its absence means and
which visibilities it holds; each consumer names the kinds it includes.
Assignment, notes, approval, the trail, queues and notifications are one
implementation over every kind.

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
| Issue | A published vulnerability, or a flaw minted here later given a CVE | A flaw minted here | The analyzer's rule |
| Occurrence identity | Component and consumer (`design-docs/data-model-graph.md` § Occurrence identity, REQ-17) | Component and consumer | Minted at first sighting, carried by matching |
| Carry across builds | Version and chain match (REQ-25) | Stated by a person | Matching (`design-docs/analysis-matching.md` § Carrying) |
| Absence | The run closes it with a reason (REQ-21) | Nothing; a person closes it | No longer detected; it stays open |
| Visibilities | Public, private | Private, public | Security testing, public once its flaw is disclosed |

| Rule | Reason |
|---|---|
| Issue kinds are data the code reads | |
| Absence is each kind's reader's; the opening visibility is the recorder's | |
| Fuzzing is an intended kind, not built (REQ-14) | It needs a declaration, a reader and an evidence view |

## Issue kinds

| Issue kind | Filed under | Its findings |
|---|---|---|
| Vulnerability | A CVE or advisory identifier, with every name reports give it (REQ-18) | Vulnerability |
| Flaw | An identifier minted here (`design-docs/findings-flaws.md` § Recorded flaws) | Entered, and vulnerability where a scan reports a name recorded against it |
| Rule | Analyzer and rule, `clang/core.NullDereference` | Analysis |

| Rule | Reason |
|---|---|
| An issue holding a recorded finding is a flaw | How pre-kind issues read |
| A merge keeps a flaw a flaw, moving recorded findings to the issue kept | |
| Issue lists, names and statistics are read per kind | Mixed counts count rules as vulnerabilities |

## Name resolution

| Rule | Reason |
|---|---|
| A name a scan reports or a person types resolves among vulnerability and flaw issues, never a rule; a producer's among the kinds its finding kind declares | A CVE name reaching a rule merges the two |
| A rule is filed as analyzer and rule identifier joined by a slash | Analyzers reuse rule names |
| An issue new to a report takes the first issue kind its finding kind declares | A scan introduces a vulnerability; recording mints a flaw |

## Consumers

A consumer reads findings and names its kinds; others never reach it.

| Consumer | Covers | Kinds |
|---|---|---|
| Closure | A run's sweep | Vulnerability |
| Version carry | A decision lapsing on a version move, or carried to matching versions (REQ-25) | Vulnerability, entered |
| Ranking | Urgency, deadlines and their rewrites | Vulnerability, entered |
| Triage | Findings lists and counts, a finding's page, issue notes, disclosure | Vulnerability, entered |
| Assignment | Giving work, handovers, a lost role's hand-back, team assignment rules and preview, and the lists of held work: unassigned, one person's, a team's queue, totals per holder (`design-docs/access-assignment.md` § Teams, `design-docs/analysis-triage.md` § Code finding assignment) | Vulnerability, entered, analysis |
| Decisions | Decisions and occurrences, reasoning and revisions, approvals, comments, the review queue, every read of one decision, the audit log and file, and decision notices: waiting, sent back, lapsed, agreement withdrawn | Vulnerability, entered, analysis |
| Inventory | A build's tree, a component and its occurrences | Vulnerability, entered |
| Statistics | Trends, build comparisons, coverage, reports, the home page's figures | Vulnerability, entered |
| Exports | The findings lists as files (REQ-50): the rows, then the selection's code findings as Code findings reads them | Vulnerability, entered, analysis |
| Register | The disposition register, screen and file | Vulnerability, entered |
| VEX | Documents stating what affects a build | Vulnerability, entered |
| Advisories | Documents about flaws recorded here | Vulnerability, entered |
| Notifications | What people are told about findings | Vulnerability, entered |
| Evidence | One code finding's place, path, links and kept source (`design-docs/analysis-source.md` § Source) | Analysis |
| Code findings | The queue by state with what each list leaves out, rule coverage, the queue file, a findings file's code findings, counts by series, and code finding and series notices (`design-docs/analysis-queue.md` § Code finding queue, `design-docs/analysis-triage.md` § Suppression rules, `design-docs/notifications-alerts.md` § Analyzer alerts, `design-docs/notifications-work.md` § Code finding notices) | Analysis |

The audit log's file follows Decisions and includes code finding decisions under
the log's visibility (REQ-50). `design-docs/interface-security-testing.md` § Security testing
holds the screens.

| Rule | Reason |
|---|---|
| Exports names the findings lists' files alone; the disposition register is Register | Analysis on a shared consumer puts code findings into a statement of what a build ships |
| A findings file reads its code findings through Code findings' read, its other rows through the list's (`design-docs/analytics-exports.md` § Exports) | A list and its file are one read |
| Counts by series belong to Code findings, never Statistics | Statistics feeds vulnerability figures |
| Each is the queue's own read and visibility | Figure, list and file count one population |
| Assignment is its own consumer, apart from Triage | Triage feeds the findings lists and disclosure, and naming analysis there puts a code finding nobody has judged into both. Holding work is one act, so handovers move code findings too |
| The held-work lists are Assignment's; the digest of held work is Notifications' and names no code finding | |
| A code finding is one piece of held work at its occurrence | Its builds may hold different versions of its component |

## Inclusion

| Rule | Reason |
|---|---|
| Every statement reading or writing findings names its consumer's kinds | Naming none includes kinds yet to exist |
| Kinds are named as inclusions, never exclusions | Exclusion lists go unextended |
| A statement reading identifiers a kind-narrowed statement chose names none again | |
| Indexes answering without the table carry the kind beside the visibility | Otherwise a table row per finding |
| The kind is the first boundary, security testing visibility the second (REQ-43) | Only kind keeps a disclosed code finding out of vulnerability documents and figures |

## Runs and series

A series is one analysis a product runs the same way on every build, named by
the producer, `clang-tidy/default`; a run is one arrival of its results against
one build (`design-docs/analysis.md`).

| Rule | Reason |
|---|---|
| A series is per product and kind, its name ignoring capitals | |
| A run is ordered by stated build time, and only one built after the series' last applied run on the build applies (REQ-06) | A late run would mark results absent |
| A run repeating one held, on documents and build time, is answered as that one | A retry after a timeout that succeeded |
| Whether absences are evidence is comparability (`design-docs/analysis.md` § Run parameters) | |
| A sighting is the first run seeing a finding, the last, and the first comparable run not seeing it | Absence is an interval, never a closure |
| Documents are placed at the door, never stored; placed results are held until applied; the receipt stays | |

## Component from a path

A finding whose results carry paths sits at the component built from the
repository holding the path, else at the build
(`design-docs/analysis-source.md` § Placement).

## Source locations

Path, lines, columns, function, flow steps and related places are stored as the
newest run stated them; links are built when read, and source is kept unless
the product turns it off (`design-docs/analysis-source.md` § Source).

## Limits

| Limit | Detail |
|---|---|
| A rule identifier could collide with a published name | Names are unique across kinds, so a scanner reporting a slashed name equal to a rule is refused where written; no published identifier holds a slash |
| Kinds are declared in code | A kind is a reader, matcher and evidence view too |
