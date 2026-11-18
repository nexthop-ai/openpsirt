# Corrections by source paths

One correction answering every issue a binary package inherits from a large
source and is not built from: what it names, what it answers, and when.

Satisfies REQ-90.

## Contents

- [The rule](#the-rule)
- [Answered occurrences](#answered-occurrences)
- [Agreement and ending](#agreement-and-ending)
- [Answers on later scans](#answers-on-later-scans)
- [Withdrawn answers](#withdrawn-answers)
- [Readback](#readback)
- [Limits](#limits)

## The rule

A correction by source paths (REQ-90) names a package, the source package it is
matched through, and the paths within that source the package is built from.
It is a correction (`design-docs/triage.md` § Corrections): a wrong match, keyed
without versions, answering at every version. The case is `linux-perf`, built
from `tools/perf`, `tools/lib` and `tools/include` and matched through `linux`
for every issue the kernel collects; of 20,372 CVE records listing files on
2026-11-18, 18,245 are the kernel's.

| Part | Rule |
|---|---|
| Product | One; it answers in that product's builds only |
| Package | Matched by the name the component is identified by, without regard to capitals, held in lower case |
| Source | Matched as the scanner records it, in lower case; differs from the package |
| Paths | One to 64, each at most 1,024 bytes, relative to the source's root; leading and trailing slashes, `.` segments and repeated slashes are removed; the root, a path leaving it and a path holding a control character are refused; held in byte order, one a line |
| Reason | One of the two saying something is not there |
| Reasoning | Required, and holds for every issue it answers |
| Kind | `source`, beside the decision kinds in `design-docs/triage-decisions.md` § Decisions |

Proposing takes the same rights as any decision in the product, and is refused
where it answers nothing open now, naming fewer paths or the names a finding
shows as the remedy.

## Answered occurrences

An occurrence is answered when every condition holds.

| Condition | Reason |
|---|---|
| An open finding of a published issue, at the package, in the product | |
| Matched through the source, as `design-docs/findings-components.md` § Match methods records it | A match on the package's own name or a CPE is a claim about the package itself |
| The issue's CVE record lists files, and none lies under any path | A record listing no files says nothing about where the fault is |
| A path holds a file by whole segments: `drivers/phy` holds `drivers/phy/ti/x.c`, not `drivers/phylib.c` | |
| Public | An undisclosed finding is a person's to answer |
| No incident stands for the issue in the product | An attack through the issue outranks a rule about where its code lives |
| No live decision holds the occurrence, under the key with versions or without | One live decision per key (`design-docs/triage.md` § One live decision per key); a standing won't-fix keyed on versions stays affected |
| No decision set aside or returned from the correction ever held it | Answering it again would bring back, under the old agreement, what the approver excluded |
| No incident withdrew the correction's answer there | Clearing an incident restores nothing (`design-docs/incidents.md` § Decisions against an incident) |

Each answered row records the files the record listed when it was written. The
files are the record's, read from the snapshot each scan reads
(`design-docs/ingest-scanner.md` § Program files).

## Agreement and ending

| Rule | Reason |
|---|---|
| A second person agrees, always, to the rule over whatever it reaches | It hides risk with nothing scheduled to look again |
| Until agreed, every row it writes waits | |
| A row written while an approval of the current reasoning stands is approved with it | The approver agreed to the rule, and the row follows from the rule and the record |
| A row written after the reasoning is revised waits for agreement again | The approval named the earlier words |
| A row written while every waiting row is sent back is sent back with them | |
| Withdrawing is the one way it ends, its withdrawn answers included; none of its rows stays in To reaffirm | |
| A withdrawn correction is not revised | It ends at its withdrawal, and nothing re-checks it afterwards |
| Revising brings back its rows that were not withdrawn, and leaves the withdrawn ones lapsed | A withdrawn answer ended on a fact the new words do not change |
| An incident recorded through an issue withdraws the correction's answers about that issue alone, agreed or waiting | The correction is one argument per issue, and the rest still hold; sending it back whole would reopen every other issue for one attack |
| One whose every row was set aside answers nothing more | A rule set aside row by row has nobody standing behind it |
| Agreed, it is published as not affected with its reason, as any wrong match is, for every issue it answers, later ones included; a waiting row publishes nothing | Each later answer reaches customers with no second look at that issue |
| It is not bounded: no cap on how many occurrences it answers (REQ-27) | The reviewer approves one rule, and the re-check re-examines every answer on every scan; 229,000 occurrences are proposed in 7.3 s on SQLite, 27.7 s on PostgreSQL, 11.8 s on MySQL and 12.0 s on MariaDB, and a steady pass takes 2 to 7 s |
| The review queue shows it as one rule over many issues: its package, paths and source, and how many issues it answers | The approver agrees to the rule, not to one issue |

## Answers on later scans

A scan applying a build's findings then re-examines what every correction
standing in the build's product has answered, and answers by each, so an issue
published after the agreement is answered on the first scan that reports it.

| Rule | Reason |
|---|---|
| Only the scanned build's findings are answered | A product's other builds were answered when they were scanned |
| Every live answer of the correction is re-examined, in any build of the product | A record is one per issue, and the build that next reports it need not be the one answered |
| A failure is logged and leaves the scan applied | The next scan answers what this one did not; a scan's findings are not held back by a correction |
| Two proposals over one occurrence at once leave one; the other's pass fails and is logged | The unique key decides |
| The pass restamps every correction it answers or withdraws by, from the stamp read before it read whether the correction stands (`design-docs/database-transactions.md` § Reads a write depends on) | A withdrawal committing during the pass otherwise leaves an answer standing under a withdrawn correction |

## Withdrawn answers

An answer stands only while what it rests on holds. On each scan's pass, and
when an incident is recorded, an answer is withdrawn for one of three reasons.

| Reason | Withdrawn when |
|---|---|
| Record | The issue's record now lists a file under the paths, or lists no files |
| Match | An open finding of the issue at the occurrence, in any build of the product, is matched on the package's own name, a CPE or another source |
| Incident | An incident is recorded through the issue in the product |

| Rule | Reason |
|---|---|
| A file now listed under the paths withdraws the answer | The record now places the fault in what the package is built from |
| A record now listing no files withdraws the answer | The answer rests on the files; with none listed nothing bears it out, and an issue with no files is never answered in the first place |
| A list read as none, past a bound or leaving the root, withdraws it the same way | It is the same answer as a record listing none (`design-docs/ingest-scanner.md` § Program files) |
| A record whose files changed and all still lie outside leaves the answer | The rule still holds of it |
| A match on the package itself withdraws the answer | The match is then a claim about the package, which the correction does not answer |
| The row lapses: the finding is open for a person, the proposer is told why, and the decision is in their To reaffirm with that reason | Lapsing is how a decision that stopped holding is handed back |
| Re-affirming a withdrawn answer waits for a second person | The agreement was not given over what withdrew it, and the decision re-made is one no pass re-checks |
| The answer keeps the files it was answered on, and records when it was withdrawn, why, and the files the record then listed | Fixed at that moment, since the record can move again |
| The correction keeps standing and answers later issues | One answer withdrawn says nothing about the rest |
| An issue whose record again puts every file outside, or matched through the source alone again, is answered again, as a new row | The rule holds of it again |
| An answer at an occurrence no build holds open any more is not re-examined, and stays as it was | The finding it answered closed with the scan that stopped reporting it; the answer covers nothing until the issue returns, and is re-examined then |

## Readback

| Surface | Carries |
|---|---|
| A finding's evidence | The source it was matched through and the files its record lists |
| The decision | The package, source and paths |
| A decision occurrence | The files it was answered on; where it was withdrawn, why, and the files the record then listed |
| To reaffirm | What withdrew the answer, beside a version move and a worse rating |
| The review queue | The package, paths and source, and the issues it answers |
| The finding screen | The source and files under the match evidence, and the form, filled with the package and source |

## Limits

| Limit | Detail |
|---|---|
| A match through two sources, or through a source and on the package's own name, records no source | The scanner's details disagree, and a correction is a claim about one route |
| A record's files are every entry's, joined | A file any of them names is one the issue may be in; 103 of 20,372 records listing files on 2026-11-18 list different files per entry |
