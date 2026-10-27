# Issues

One issue across every name it goes by, what a report says about it, and how
reports that disagree are merged.

Satisfies REQ-18, REQ-22. Names REQ-82, not built.

## Contents

- [Issue identity](#issue-identity)
- [Merged issues](#merged-issues)
- [Report contents](#report-contents)
- [Report merging](#report-merging)
- [Issue dates](#issue-dates)
- [Limits](#limits)

## Issue identity

The same vulnerability arrives as a national identifier from one database and an
advisory identifier from another, so **identity spans the names**: every name
resolves to one row, and a decision holds across all of them (REQ-18).

| Rule | Reason |
|---|---|
| The lookup covers every name a report supplies | One scanner reports the national identifier alone, another its own with the first as an alias. A test pins the ordering that fails |
| An issue is filed under its most widely recognized name; any other name finds it | It is the name a person finds in an advisory |
| The filed name is chosen from the filed name and the report's names together, the filed name first | Chosen from the report alone, the filed name flips between scans with each producer's names |
| Identifiers compare in one case | Every scheme is case-insensitive and reports disagree on case |
| A name given twice is one name, under a unique index on its normalized form | A report may list its own identifier among its aliases |
| The filed name, folded, is what makes one issue one row | |
| What a finding screen reports (holder, placing rule) is asked of the whole fold: one name for the group, empty where its occurrences disagree | Asked per component, one rule reads as none and as all |
| Recording a name by hand asks for triage in every product the issue is open in, at each occurrence's visibility, refused whole | From then every product's scans resolve the name here and inherit its decisions |
| A report naming two issues held apart merges them (§ Merged issues) | One issue is one issue under every name |

## Merged issues

A report can name two issues held apart: one feed matches the national
identifier on one copy of a library, another feed its own advisory on a second
copy before a national one exists. The merge happens in the transaction that
applies the scan, and is a record of its own (REQ-22).

| Rule | Reason |
|---|---|
| The kept issue is the one filed under the best-known of all the names, otherwise the one recorded first | |
| A merge record names the absorbed issue, the kept issue, the report's names, the run and the moment | The issue page reads where a name came from |
| Every issue states the issue it is read as: itself, or the one it merged into, one step away however many merges led there | Equality on that column is indexed on every engine: counting decisions over 300,000 findings takes 72 ms on PostgreSQL, 0.47 s on MySQL, 2.5 s on MariaDB; through a subquery, over ten minutes; through a null meaning itself, 0.19 s hashing every row |
| Two scans merging overlapping sets take the issues in turn, and go again where one is no longer its own | No issue ends two steps from the one that stands |
| What people recorded stays filed under the absorbed issue and is read as the kept issue: decisions and their occurrences, approvals, revisions, notes, rating claims, incidents, attachments, case grants, advisories, embargo movements, reports | History is append-only. A decision about the absorbed issue suppresses, counts and lists at the kept issue's findings as at its own. The rows below are the whole of what a merge writes to them |
| A case grant under either name reaches every record under either | |
| An advisory covering either name covers the kept issue, once per product, and a search by either name finds it | |
| One report stands for an issue across its names | A second is refused |
| A re-affirmation reads the kept issue's rating in force and accepts a decision filed under the absorbed name at the same occurrence | |
| What a report said moves to the kept issue: names, findings, classification, ratings, references, ranking signals | It is observed state about one issue. The absorbed row keeps its copy |
| A scanned finding open under both names at one occurrence keeps the longer-open row; the other closes `invalid` | One finding held twice. A finding a person entered is never closed this way |
| The surviving finding takes the other's assignment where it has none | |
| Two live decisions at one product and occurrence collide where their versions agree, or where both stand at any version | Those hold one key under one issue (REQ-25) |
| Of two that collide, approved beats proposed, otherwise the newer; the other lapses, naming the merge and its replacement | One live decision per occurrence |
| A live decision under the absorbed issue holds its key under the kept issue | The key is the database's guard of one live decision per occurrence |
| The key is the one column of a standing decision occurrence a merge rewrites | The key is an index, never a field anybody decided. A test pins every other column across a merge |
| Labels move to the kept issue, once per word per component | |
| The rating in force moves unless the kept issue has its own in that product; then the absorbed one's is dropped | |
| A rating claim and an incident hold their key under the kept issue | One standing per issue and product |
| Two rating claims in one product: the one in force beats the waiting one, otherwise the newer | |
| The losing claim is withdrawn, naming no person, with "Superseded when the absorbed issue merged into the kept one"; the rating in force is recomputed, re-ranking and re-clocking the product's findings | |
| Two incidents in one product: the newer stays; the other is cleared, naming no person, with the same reason | |
| Each claim withdrawn and incident cleared this way is an administration trail row with a merge as its actor | `design-docs/access.md` § The administration trail |
| Two answers that disagree are told to everybody who triages the product; two that agree tell nobody | Different outcomes, ratings, or dates of attack. A different date is a different obligation |
| Published advisories and VEX documents are left as issued | |
| A name recorded by hand that another issue holds is still refused | A person asserting identity is not a report |

## Report contents

Everything a report says about an issue is kept, because a report is not kept
once read. On a switch image's 7,917 findings: 5 known exploited, 7,835 with a
likelihood, 7,879 with a description, every one with a write-up, 6,136 with a numeric score, 5,390 with a fix date, and 420 of 11,593
references are patches.

| Field | Treatment |
|---|---|
| Severity | Stored as a word, which ranks and sets a deadline. A number is the first rating stating both score and vector, worst winning; the vector travels with it |
| What counts as a fix | One list, named once. A closure not on it is churn or a correction |
| Fix state | Three: no fix, upstream declined, a fixed version exists. Declined changes the outcome somebody should reach |
| A group whose occurrences disagree on fix state | Says so, read from both ends of the group; the fix version is empty |
| Weakness classification | Deduplicated and ordered, the data's root cause first. A published advisory states one |

## Report merging

Reports disagree and arrive in no controlled order. A later one fills what an
earlier one did not know and **overwrites nothing**. A test applies two reports
in both orders and requires the same result.

| Field | Rule | Reason |
|---|---|---|
| Known-exploited | Moves forward only | Silence in a later report is a gap |
| Day the known-exploited catalog listed it | Earliest stated | Moving it re-clocks exploited findings (`design-docs/remediation.md` § Deadlines) |
| Score | Worst claimed | The one order-independent answer |
| Likelihood | Newest by the day the estimate is about; dated beats undated; two undated are last-seen | It is a daily forecast that legitimately falls |
| Likelihood, where a report carries none | Left alone | Omission is not zero |
| Severity word | Filled where the issue holds none or a scanner's "unknown", by a word the fold recognizes; recomputes every product's order and deadlines | A flaw recorded here has no word until the world publishes one |
| Score provenance | Scheme, publisher and primary or secondary, filled where known, never overwritten | |
| Estimate | Carries its percentile and the day it was computed for | Nobody reads 0.00042 |

The maximum is written out, never the engines' greatest-of function, which two
engines answer as unknown when one side is absent.

A scan's reports are interned together:

| Rule | Reason |
|---|---|
| A report byte-identical to others in the scan is interned as its first and last copy | Every other write fills a gap, moves toward worse or newer, or takes the last value |
| The last copy is skipped where nothing since the first resolved to or merged that issue | |
| What is on record for a run of reports is read together: one statement per kind of record for a few hundred reports | |
| A part of a report is written only where the read says its statement would match a row | A rescan of unchanged data writes nothing |
| A newer estimate is written in a statement per day and batch of issues, each value chosen by identifier inside it, and the batch is written before anything reads the rows again | A feed moves nearly every issue on one day: 46 statements against 7,652 |
| Whether a queued estimate moved is answered from the read where both days are the start of a UTC day; otherwise the issue's own statement runs | |
| A report the read cannot answer for is resolved alone from the database | Names reaching no issue or several, a better-known name than the filed one, non-ASCII names, or an issue an earlier report in the run wrote. Creating, merging and renaming happen there only |
| Comparisons lean toward writing; names compare case-insensitively, never narrower than an engine | A wasted statement costs a round trip; a skipped one loses a write |
| Description and advisory are written only into a gap; spaces alone are a gap | MySQL and MariaDB compare spaces equal to empty |

A test interns random overlapping rounds both ways and requires identical rows,
names, merges and moves. An unchanged rescan of 11,435 reports is 570
statements rewriting no issue row, against 114,339 a report at a time rewriting
all 11,435.

## Issue dates

An issue's published and last-modified dates are read from OSV, asked in the
background, because no scanner report carries either (REQ-82). Not built.

| Rule | Reason |
|---|---|
| The source is OSV | Answers national and advisory identifiers, in batches, without a key |
| Asked in the background | A scan never waits on the network (REQ-12) |
| Only the dates are taken | Severity and fix state stay the scanner's |
| An issue OSV does not know has no date; a figure needing one says unknown | |

## Limits

| Limit | Detail |
|---|---|
| A merge is not undone | Nothing a report says unmerges, and unmerging divides findings and decisions made since |
| An absorbed issue's filed name is not taken by the kept issue | Where the best-known name is the absorbed row's, the kept issue stays filed where it is |
