# Control reports

What an auditor reads: everything known in a build, what stands on one person,
how much a second person did, and the dismissals.

Satisfies REQ-17, REQ-42, REQ-43, REQ-49, REQ-52, REQ-53.

## Contents

- [The disposition register](#the-disposition-register)
- [The exception report](#the-exception-report)
- [Approval quality](#approval-quality)
- [Dismissals and last uploads](#dismissals-and-last-uploads)
- [Limits](#limits)

## The disposition register

The complement of the audit log: the audit log states what was decided, the
register what was known, decided or not. One row per issue and occurrence in a
named build, with its state, outcome, justification, proposer, approvers, the
date of each, its deadline and whether it was met. A page of the catalog's own
(`design-docs/analytics-catalog.md` § Pages of the catalog's own).

| Rule | Reason |
|---|---|
| One row per issue and occurrence, whatever else is true of it | Agreement is read as a scalar: nothing makes an approval unique per decision, and a join multiplies the row and skips one per later page |
| It applies no minimum severity and states none, whatever else is asked | Everything in the build is the basis an auditor relies on; a filter hiding part would make it the findings list at a second address |
| Joined outward from the finding, left | The undecided occurrence is the row it exists for. Closed rows are included, the only ones a met deadline answers |
| A lapsed decision is part of the record; a superseded one is not | Who proposed and approved a lapsed decision is what compliance reads, and the findings list calls it lapsed |
| A row reports one decision: the live one covering the finding's versions, else the latest lapsed one | Decision occurrence rows are never deleted. A live decision covers only its keyed versions, as on the findings list. Where a versioned decision and a correction both cover a finding, the row names what the finding's screen names: the correction in force, else the older |
| The row names what pulls the component in beside the occurrence identity | The identity is sixty-four hex characters and names no location |
| It narrows by closure reason | What CVE records and supplier statements closed are listed apart, which is how a wrong one is found |
| A row closed as unaffected carries the record's lines that closed it, in one cell of a file | The snapshot is replaced by the next |
| A row a supplier's statement answers carries the statement: publisher, product, justification and words, in one cell | On a disclaimed row it closed it; on an open row it answers the routes through the supplier's product |
| It names what it was measured with: the upload, its inventory, the run, the scanner, the vulnerability data and the CVE record snapshot | The audit chain runs artifact, inventory, run, scanner and database, disposition |
| The inventory is a link, never a hash; one let go says so | A tagged release keeps its documents and a branch build does not |
| It narrows by what stands, outcome, component, issue, and one side of the history; the count is of the narrowed list | Otherwise later offsets page a different list |
| An unrecognized state word keeps nothing | A filter that widens reads as complete about rows left out. The route refuses one first |
| Provenance missing never fails the report; provenance unreadable does | No upload means no block, no finished run a block without one; a failed read would read as nothing uploaded |
| Current state, with no `as_of` | Each row carries the timestamps evidencing it, and past deadlines are not recoverable |

Findings and decisions filter on when things happened instead: opened after,
opened before, closed after, proposed after, and an age in days from either side
(open at least, open under). An age and a date on one side keep the tighter.
Closed after is accepted and reaches nothing on the findings lists, which read
open rows, so the filter panel does not offer it; an address carrying it shows
it among the filters in force, removable.

## The exception report

The audit log with its filters set: dismissals no second person has a standing
agreement on (REQ-53). Not-applicable, wrong match, will-not-fix, already-fixed,
a code finding dismissed and a code finding called no security issue all
require approval, so it returns nothing, and a row is a control that failed. The
audit log's empty state is written as that answer.

Filtered only for decisions one person made, the population is large and
legitimate, because an outcome hiding nothing needs no second person and a short
deferral stands alone until the threshold. The screen states which question it
asks. The same question is a condition told to administrators
(`design-docs/notifications-alerts.md` § Reports that must come back empty).

| Rule | Reason |
|---|---|
| It asks for every outcome that hides risk and stores no date, over every kind | Each always needs a second person |
| The outcomes are the ones the server publishes as that class | A list typed in the interface misses one the server adds |
| Asked of the record, never a flag: no standing agreement from anybody but the proposer | A test writes a self-approval straight to the table, because a report trusting the write path reports on itself |
| Four filters: proposer, who has a standing agreement, issue, component | |
| A withdrawn agreement does not match the approver filter | Otherwise the report cannot see a withdrawal |
| Product, outcome and state take several values; a named product the reader may not see refuses the request | Answering about two of three reads as three |
| It says "this should be empty" only where every outcome asked is a dismissal | Mixed with deferrals it holds legitimate rows |
| What was asked is printed with every value | |
| A code finding decision is listed and counted only for a reader of internal material in its product | REQ-42, REQ-43 |
| The audit log narrows to one build through the findings at each occurrence, in the decision's own product | A decision names no build, so it carries across releases; an occurrence carries no product |
| A build is a product, a branch or tag and a variant together, or none | A branch name alone matches another product's |
| The file carries every agreement with its dates, beside who agrees now | What was agreed and then withdrawn is what an audit looks for |

### Standing corrections

The audit log with its other filters set: the wrong matches that apply now.
Every other decision lapses when the code moves and comes back to somebody; a
correction does not, so the set is read only by asking. Applying now differs
from having been approved, which the state filter answers.
`design-docs/triage.md` § Corrections holds what one is.

## Approval quality

The rule cannot be broken: approving refuses the proposer and the revision's
author and is conditional on the revision being current. This reports where the
rule did not apply and where it applied in form only. It counts decisions about
vulnerabilities, flaws and code findings, each where the reader may read it, a
code finding only for a reader of internal material in its product.

| Section | What it says |
|---|---|
| Risk standing on one person | In two halves. A dismissal, of a vulnerability or a code finding, is a control that did not hold. A short deferral, or an upgrade promised inside the existing deadline, is the exception working; the pattern across a program is what nothing else shows |
| Proposer and approver pairs | Every pair with its share of everything agreed. Fifty of fifty-two and fifty of nine hundred differ |
| Agreements given in bulk | One act at the proposer's unit is the control working; a batch of two hundred is still not two |
| Agreed to before, covering more now | Consent recorded at the moment against what the decision reaches today, since matching covers new builds unasked |
| Standing from somebody who could not give it now | Correct behavior, and the first list after a reorganization |

| Rule | Reason |
|---|---|
| Only what stands with nobody agreeing has to be empty | Bulk agreement and an approval from a role since withdrawn are correct |
| A pair raises a condition only past a share among a set number of people who may approve, both settings a product may override | A small team is one pair. `design-docs/notifications-alerts.md` § Concentrated approval pairs (REQ-49) |
| A pair's share is of every decision a standing agreement covers, counted apart from the list | A list cut at its limit does not raise its pairs' shares |
| Dated by proposal | A late approval otherwise moves work out of its period |
| Every section is bounded and says when it reached the bound | |
| Growth is capped after it is found, most grown first | Every standing agreement is examined; capped before, the oldest fill the page |
| Ties break by decision, then approver | A decision with two agreements is two equal rows |
| What a decision covers now is what its live rows reach | A withdrawn or lapsed row covers nothing |
| Coverage is counted for a bounded set of decisions per statement | One per decision is ten thousand round trips |

## Dismissals and last uploads

Dismissals are a dataset of their own (REQ-53). The findings list filters on
outcome and on whether a rating was changed; the audit log lists every decision
with reasoning, approvals, dates and reach. Which reason applied is on the entry.

| Dismissal | What it asserts |
|---|---|
| Not applicable | The vulnerable code is not reachable |
| Wrong match | The scanner matched something not here |
| Will not fix | It is not worth fixing |
| Already fixed here | The packager backported the fix |

Nothing was changed in any of the four, which is why each needs a second person
and why anything counting dismissals asks for all four: a program dismissing
everything as "will not fix" otherwise reads as one that argued nothing away.

| Audit log rule | Reason |
|---|---|
| One entry per decision, ordered by its newest matching occurrence | One argument by one person; the group is derived when read (REQ-17) |
| The total counts decisions | The heading, sheet and pages count one thing |
| A decision is listed where any occurrence matches the filters, period and build included | |
| Every count on an entry is of matching occurrences the reader may read, the total included | A count of undisclosed occurrences is the disclosure (REQ-42, REQ-43) |
| An entry is named from its earliest matching occurrence, beside how many issues, products, component names and occurrences match | Component names count through readable findings |
| An entry's state is one word, or mixed with counts per state | |
| An entry stands where every matching occurrence applies now; else it says how many do | |
| An entry links to its occurrences on the findings list, narrowed to the decision and the asked states, across every release, planned or not | The decision page asks the same |
| The file is one row per occurrence, naming occurrence and decision | An auditor reconciles occurrences |
| The per-occurrence list stays | The reports overview reads the newest dismissals from it, and an issue's document its decision occurrences |

What is scanned, and when each build was last seen, is its own view
(REQ-52; the shape is in `design-docs/ingest.md`). A product silently dropping
out of scanning leaves every figure looking reasonable about a build nobody has
looked at since. Releases past end of life are reported apart and raise no
coverage alert, or the view fills with releases stopped on purpose. Nothing here
emits outward: a VEX document per build and a recorded advisory are documents
somebody asks for.

## Limits

| Limit | Detail |
|---|---|
| An approval is a fact about a moment | Losing a role does not withdraw it; approval quality lists it instead |
