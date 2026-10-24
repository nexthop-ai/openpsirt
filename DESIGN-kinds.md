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

The declarations are data the code reads: the issue kinds a producer's names
resolve among, what absence means to a run's sweep, and the visibilities a
finding of the kind may hold. Fuzzing is the next kind intended and is **not
built**; it needs a declaration, a reader and an evidence view, and nothing in
this document changes for it.

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
| Triage | The findings lists and their counts, one finding's page, assignment and routing, decisions and approvals, notes, queues and disclosure | Vulnerability, entered |
| Inventory | A build's tree, a component and the places it sits at | Vulnerability, entered |
| Statistics | Trends, comparisons of two builds, coverage, the reports and the home page's figures | Vulnerability, entered |
| Exports | Every list written out as a file (REQ-50) | Vulnerability, entered |
| VEX | The documents stating what affects a build | Vulnerability, entered |
| Advisories | The documents about flaws recorded here | Vulnerability, entered |
| Notifications | What is said to people about findings | Vulnerability, entered |

Analysis findings are included by no consumer above. The screens, queues,
counts and exports that read them are built for them (`DESIGN-analysis.md`) and
are **not built**; until they are, a lead is recorded and counted on its run's
receipt and read nowhere else.

## Inclusion

| Rule | |
|---|---|
| Every statement reading or writing findings names its consumer's kinds | A statement that names none includes every kind there will ever be |
| Kinds are named as an inclusion, never as an exclusion | A list of exclusions is a list somebody forgets to extend |
| A statement reading findings by identifiers a kind-narrowed statement chose names none again | The identifiers already carry the answer |
| The finding indexes a read answers from without the table carry the kind beside the visibility | A covering index without the kind costs a table row per finding read |
| The internal visibility is a second boundary, not the first | A lead moved into a private case is private, and only its kind keeps it out of the vulnerability documents and figures |

## Runs and series

Runs and series are the arrival of results for a kind whose producer sends
them per series, and are **not built**: the analysis upload is their first
user (`DESIGN-analysis.md`).

## Component from a path

A finding of a kind whose results carry paths is placed at a component derived
from the path when results arrive. It is **not built**.

## Source locations

Locations, source links and snippets belong to any kind with source locations.
They are **not built**.

## Limits

| Limit | Detail |
|---|---|
| A rule's identifier could collide with a published name | The name is unique across every issue kind. A scanner reporting a name with a slash identical to an analyzer's rule would be refused where it would be written. No published vulnerability identifier holds a slash |
| The kind is declared in code | A kind is a reader, a matcher and an evidence view as well as a declaration, so a deployment cannot add one by configuration |
