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

What was known in a named build, decided or not; the audit log says what was
decided. One row per issue and occurrence with its state, outcome,
justification, proposer, approvers, the date of each, its deadline and whether
it was met. A page of the catalog's own (`design-docs/analytics-catalog.md`
§ Pages of the catalog's own).

| Rule | Reason |
|---|---|
| One row per issue and occurrence, agreement read as a scalar | Nothing makes an approval unique per decision, and a join multiplies rows and skips one per later page |
| It applies no minimum severity and states none, whatever else is asked | Everything in the build is what an auditor relies on |
| Joined outward from the finding, left; closed rows included | The undecided occurrence is its reason to exist; a met deadline is answerable only once closed |
| A lapsed decision is part of the record; a superseded one is not | |
| A row reports one decision: the live one covering the finding's versions, else the latest lapsed one | Decision occurrence rows are never deleted. A live decision covers only its keyed versions, so a build shipping the occurrence at other versions reads undecided on both surfaces. A versioned decision beside a correction names what the finding's screen names: the correction in force, else the older |
| The row names what pulls the component in beside the occurrence identity | The identity names no location |
| It narrows by closure reason | A wrong CVE record or supplier statement is found this way |
| A row closed as unaffected carries the record's lines that closed it, in one cell of a file | The snapshot is replaced by the next |
| A row a supplier's statement answers carries publisher, product, justification and words, in one cell | On a disclaimed row it closed it; on an open row it answers the routes through the supplier's product |
| It names the upload, its inventory, the run, the scanner, the vulnerability data and the CVE record snapshot | The audit chain runs artifact, inventory, run, scanner and database, disposition |
| The inventory is a link, never a hash; one let go says so | A tagged release keeps its documents and a branch build does not |
| It narrows by what stands, outcome, component, issue, and one side of the history, counting the narrowed list | Otherwise later offsets page another list |
| An unrecognized state word keeps nothing, behind the route's own refusal | |
| Provenance missing never fails the report; provenance unreadable does | No upload means no block, no finished run a block without one |
| Current state, with no `as_of` | Rows carry their timestamps, and past deadlines are not recoverable |

Findings and decisions filter instead on opened after, opened before, closed
after, proposed after, and an age in days from either side; an age and a date on
one side keep the tighter. Closed after reaches nothing on the findings lists,
which read open rows, so the filter panel does not offer it; an address carrying
it shows it among the filters in force, removable.

## The exception report

The audit log filtered to dismissals no second person has a standing agreement
on (REQ-53). Not-applicable, wrong match, will-not-fix, already-fixed, a code
finding dismissed and a code finding called no security issue all need approval,
so a row is a control that failed, and the empty state is written as that
answer. The same question is a condition told to administrators
(`design-docs/notifications-alerts.md` § Reports that must come back empty).
Filtered only for one person's decisions, the population is legitimately large,
and the screen states which question it asks.

| Rule | Reason |
|---|---|
| It asks for every outcome that hides risk and stores no date, over every kind, as the server publishes that class | A list typed in the interface misses one the server adds |
| Asked of the record: no standing agreement from anybody but the proposer | A test writes a self-approval straight to the table |
| Four filters: proposer, who has a standing agreement, issue, component; a withdrawn agreement does not match the approver filter | |
| Product, outcome and state take several values; a named product the reader may not see refuses the request | |
| It says "this should be empty" only where every outcome asked is a dismissal | |
| What was asked is printed with every value | |
| A code finding decision is listed and counted only for a reader of security testing material in its product | REQ-42, REQ-43 |
| The audit log narrows to one build through the findings at each occurrence, in the decision's own product | A decision names no build |
| A build is a product, a branch or tag and a variant together, or none | A branch name alone matches another product's |
| The file carries the whole agreement record beside who agrees now | `design-docs/analytics-exports.md` § File contents |

### Standing corrections

The audit log filtered to the wrong matches that apply now. A correction never
lapses, so only this asks for the set; applying now differs from having been
approved. `design-docs/triage.md` § Corrections.

## Approval quality

Approving refuses the proposer and the revision's author, conditional on the
revision being current, so this reports where the rule did not apply or applied
in form only. It counts decisions about vulnerabilities, flaws and code
findings, each where the reader may read it.

| Section | What it says |
|---|---|
| Risk standing on one person | Two halves: a dismissal is a control that did not hold; a short deferral, or an upgrade promised inside the existing deadline, is the exception working |
| Proposer and approver pairs | Every pair with its share of everything agreed. Fifty of fifty-two and fifty of nine hundred differ |
| Agreements given in bulk | One act at the proposer's unit is the control working; two hundred is still not two |
| Agreed to before, covering more now | Consent at the moment against what the decision reaches today |
| Standing from somebody who could not give it now | Correct behavior, and the first list after a reorganization |

| Rule | Reason |
|---|---|
| Only what stands with nobody agreeing has to be empty | |
| A pair raises a condition only where its share of a product's agreements passes a threshold among at least a set number of people who may approve, both settings a product may override | `design-docs/notifications-alerts.md` § Concentrated approval pairs (REQ-49) |
| A pair's share is of every decision a standing agreement covers, counted apart from the list | A list cut at its limit does not raise its pairs' shares |
| Dated by proposal | |
| Every section is bounded and says when it reached the bound | |
| Growth is capped after it is found, most grown first; ties break by decision, then approver | Capped before, the oldest fill the page |
| What a decision covers now is what its live rows reach | |
| Coverage is counted for a bounded set of decisions per statement | One per decision is ten thousand round trips |

## Dismissals and last uploads

Dismissals are a dataset of their own (REQ-53): the findings list filters on
outcome and on whether a rating changed, and the audit log lists every decision
with reasoning, approvals, dates and reach. Which reason applied is on the
entry, never a filter.

| Dismissal | What it asserts |
|---|---|
| Not applicable | The vulnerable code is not reachable |
| Wrong match | The scanner matched something not here |
| Will not fix | It is not worth fixing |
| Already fixed here | The packager backported the fix |

Nothing changed in any of the four, so each needs a second person, and anything
counting or listing dismissals asks for all four.

| Audit log rule | Reason |
|---|---|
| One entry per decision, ordered by its newest matching occurrence | The group is derived when read (REQ-17) |
| The total counts decisions | |
| A decision is listed where any occurrence matches the filters, period and build included | |
| Every count on an entry is of matching occurrences the reader may read, the total included | REQ-42, REQ-43 |
| An entry is named from its earliest matching occurrence, beside how many issues, products, component names and occurrences match | |
| An entry's state is one word, or mixed with counts per state; it stands where every matching occurrence applies now, else says how many do | |
| An entry links to its occurrences on the findings list, narrowed to the decision and the asked states, across every release, planned or not | |
| The file is one row per occurrence, naming occurrence and decision | |
| The per-occurrence list stays | The reports overview and an issue's document read it |

What is scanned and when each build was last seen is its own view (REQ-52;
`design-docs/ingest.md`), because a product silently dropping out leaves every
figure looking reasonable. Releases past end of life are reported apart and raise
no coverage alert.

## Limits

| Limit | Detail |
|---|---|
| These reports read and emit nothing outward | A VEX document per build and a recorded advisory are documents somebody asks for |
