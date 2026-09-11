# Reporting

The figures this produces and what each is a count of.

Satisfies REQ-25, REQ-33, REQ-35, REQ-50, REQ-51, REQ-52, REQ-53, REQ-54,
REQ-74, and part of REQ-30.

Everything here reads what the findings and decisions already hold. No table in
this document is its own.

## Contents

- [The counting unit](#the-counting-unit)
- [Computed on demand](#computed-on-demand)
- [Trends](#trends)
- [Build comparison](#build-comparison)
- [The release note](#the-release-note)
- [Deadlines](#deadlines)
- [Deadline compliance](#deadline-compliance)
- [Release readiness](#release-readiness)
- [Holder workload](#holder-workload)
- [Inheritance preview](#inheritance-preview)
- [Remediation metrics](#remediation-metrics)
- [Triage latency](#triage-latency)
- [Repeated deferrals](#repeated-deferrals)
- [Subtree trends](#subtree-trends)
- [The disposition register](#the-disposition-register)
- [The exception report](#the-exception-report)
- [Dismissals and scan coverage](#dismissals-and-scan-coverage)
- [The report catalog](#the-report-catalog)
- [Exports](#exports)
- [Settings](#settings)
- [Limits](#limits)

## The counting unit

Every rate and count is **one issue at one component**, never one place. The
deadline is stored per place, but a place is not a piece of work: one flaw in one
library that forty-five packages pull in is one decision. Counted per place it
was forty-five late things beside one late thing on the findings list, both
labeled the same, and on a real kernel the two numbers were about thirty-seven
apart.

Where a report groups places first, it states what a group means rather than
summing:

| A group is | When |
|---|---|
| Closed | No place is still open |
| Met | None of the closed places was late |
| Deferred | *Every* open place is covered by a standing deferral. One covering some of a group leaves the rest running |
| Overdue | Anything open is past its date and uncovered |

**Two closure reasons are not resolutions**, and a velocity figure counting them
measures churn:

| Reason | Why it is not a resolution |
|---|---|
| `superseded` | The component's version moved and the issue came with it. Counting it as resolved draws a line saying work was completed while the same chart's new line rises by exactly as much |
| `unexplained` | The scanner stopped reporting it with the component present and unchanged. A fault to investigate |

The other four — removed, upgraded, revised, and a recorded flaw declared fixed —
are counted.

**Closed exactly at the deadline met it.** Something still open at its deadline
instant is not yet overdue, so something closed at that instant was not late.

## Computed on demand

Every count is worked out when it is asked for. Nothing is precomputed, cached,
or refreshed on a schedule.

The best-known tool in this space stores metric snapshots and runs a refresh job,
for reasons that are its own: a hosted portfolio with far more traffic than a
self-hosted deployment sees. The traffic here is dozens of people in a month.

**A second cost is easy to miss.** Visibility is per subject, so a precomputed
total is a total *for somebody* — either computed per person, which is not a
saving, or computed once and then filtered, which is a second path through the
visibility rules.

**What would change this:** a dashboard measured slow on a real deployment. The
shape is then known and should not be reinvented under pressure — precompute at
the grain access is granted at, one row per product per day, so a portfolio
number stays the sum of what the reader may see.

## Trends

Three series over time — new, resolved and open — with open split by severity.
Separately they are three numbers; together they state whether the team is
keeping pace. An open count that barely moves while its critical share rises is
getting worse, and one line hides that.

| Viewing | Axis | Reason |
|---|---|---|
| A branch | Calendar time | It is scanned nightly and has continuous data |
| Tagged releases | Release over release, oldest first, drawn as bars | Each is one frozen point. Releases months apart make a calendar count read as slow drift rather than the step change it was, and a line between two frozen points draws a path nothing travelled |

| Rule | Reason |
|---|---|
| Answered against today's vulnerability data, not as of the day each was cut | That is what re-scanning a shipped release is for. A chart that froze the answer would hide the advisory published after it shipped |
| Rates stay on calendar | How much appeared and was resolved between two releases is an artifact of how far apart somebody cut them |
| A product must be named, and two releases is the fewest that is a shape | Across products the tags interleave by date and mean nothing side by side; one bar reads as broken rather than as sparse |
| A release with nothing open is still a release | The figures are read from every build that has been *scanned*, with counts attached to that list rather than the list derived from the counts. Driven from findings alone, a clean release had no row, and absent is how this list says "never scanned" |

**The window becomes predicates before the statement runs**: a finding opened
after the last point contributes to nothing, and one closed before the first
contributes to nothing either. Without that the query reads every finding ever
recorded, so the cost of drawing a chart grows with the age of the deployment
rather than with the range asked about.

The step and the number of steps are both bounded, because they arrive as query
parameters: a step of zero would draw one instant twelve times and a step of a
century would draw a range nothing falls in.

## Build comparison

What was fixed, what is newly present, and what is still there, between any two
builds of one product. What a release note has to answer is usually about the
last release a customer actually has, which is rarely the previous one.

| Rule | Reason |
|---|---|
| Both builds are authorized, not one | The first version authorized the later target and applied that answer to the earlier one, so somebody who could reach one product could read findings out of another |
| Public findings only unless asked otherwise | The destination is usually a public document. Where the two builds differ in what the reader may see, the narrower answer governs |
| Ordered worst first and stably | A release note that reorders between reads is one nobody can diff |
| Bounded by the size of a build, not the calendar | Every open entry of both builds, which is what diffing them means. There is no page of a diff |

**Each fixed entry states why.** "Fixed by upgrading to 2.4" and "fixed by a
carried patch" are different sentences, and the closure reason distinguishes
them. `superseded` means the version moved and the issue came with it — before
that reason existed, such a bump put one issue in both the fixed and the
newly-present column of the same document.

**A fixed entry states what it moved to**: "the component was upgraded, 3.7.0 →
3.9.0". That pair is written when the scan closes the finding, because the
component that carried the issue is gone from the inventory by then and anything
asking later holds one version and not two.

**Each still-present entry states whether somebody tried**, carrying the version
its place arrived from where the version moved since. On the still-present column
only: a fixed entry's closure reason already says what happened, and a new one had
nothing to bump.

**Explanations are read once for the whole list**, not once per entry. A
comparison against a release a customer has been on for a year has as many fixed
entries as the note is long. The statement narrows by the issues and the
components separately rather than by the pairs, because no engine here spells a
comparison against a pair of columns the same way, so what comes back is a
superset and the pairing is done on the way out.

## The release note

The same comparison as prose (REQ-51): markdown, served as `text/markdown` rather
than as a string in a JSON field.

Rendered on the server. What an API caller gets and what the screen shows have to
be the same words, and two implementations of how a release note reads is one
that drifts.

**It carries what was fixed and nothing else.** Not what is still present, not
what newly appeared, and not a bump that carried the issue with it.

A disposition belongs in a VEX document, which is machine-readable and is what a
customer's scanner consumes. Carrying the same judgments in prose lets the two
drift, and prose is the copy nobody regenerates. Publishing "we know this
critical is present and we deferred it" is also a disclosure act rather than a
template choice.

The comparison screen keeps all three sets: that is an internal view of two
builds, and this is a document going to a customer.

| Rule | Reason |
|---|---|
| A lead line makes it re-checkable | Which two builds, when the later one was last measured, and the scanner and vulnerability-database versions it was measured with. A vulnerability database ships bad data and is corrected, and "which data said so" is the question a note kept for a year has to answer |
| Dated by the measurement, not the request | That is the moment the answer reflects, and it is the same for everybody. Dated by the request, two people reading the same comparison hold documents that disagree |
| Builds are named the way a customer knows them | From the catalog's display names. A heading reading "main container" puts internals on the first line of somebody else's document |
| An empty section is not written | A heading with nothing under it is a question about whether something is missing |

**What was left out is counted.** A reader cannot otherwise tell a release that
fixed nothing undisclosed from one whose undisclosed fixes were taken off the
page. A number and never the entries, and zero for a reader who could not have
seen them anyway.

**The count is of fixes, by the same rule the listed entries are.** A pair open
in one build and not the next has left the affected list, which is not the same
as having been fixed: an invalid record means the build was never affected, a
superseded row means a bump carried the issue along, and an unexplained closure
says nothing at all. The listed half excluded all three; the counted half was a
plain set difference that never read a closure reason, so the sentence beneath
the note told a customer each of those was a security fix. Both halves go through
one function.

## Deadlines

A finding carries a deadline from how urgent it is: a configured window, counted
from when it was first seen. Being overdue is reported and never acted on
automatically.

| Rule | Reason |
|---|---|
| Known-exploited has its own window, and it is the shortest | Severity is how bad a flaw is; being exploited is a fact about the world. Without a separate window the deadline contradicts the ranking |
| Anything the reports did not rate takes the medium window | Nobody having scored it is not a claim that it is mild, and giving silence the longest window puts the findings least is known about at the back of the queue |
| Days remaining are rounded down rather than truncated toward zero | Truncation reports something twelve hours overdue as having zero days left, which reads as due today |

**Stored at ingest, recomputed when the policy changes** (REQ-33). Computing it
per request costs a pass over every open finding *per urgency band*, because each
band allows a different number of days — measured at about eight seconds over
441,108 findings. Stored, it is an indexed range scan.

Urgency is stored at ingest for the same reason and carries the same staleness,
but nobody edits the ranking and people do edit deadlines.

**The clock runs on what nobody has answered.** A dismissal takes a finding off
it entirely; a deferral replaces the deadline with its own date.

It stops only for a decision that **applies**: approved, or proposed where no
second person is required, at the versions this build ships, and a deferral only
until its date. A proposal still waiting for an approver stops nothing. "Who is
holding what" counts overdue by the same condition, spelled once.

**One range scan ordered on the stored deadline.** It was asked band by band
before that — once per window, each with its own first-sighting cutoff, merged
afterwards — because ordering by a deadline meant date arithmetic, which has no
portable spelling across the four engines.

Before that it took the oldest findings and discarded whatever was not due in a
loop, so an exploited finding first seen yesterday and due tomorrow lost its
place to a low from two years ago that filled the buffer. **A list ordered on a
proxy for the answer is not the list it claims to be.**

A person is named on a row only where every place has the same one. Reporting one
of several would say a finding is being dealt with when most of it is not.

## Deadline compliance

Per severity: closed within the deadline against closed in total, and open past
the deadline against open in total. The inputs are stored, because a closed row
keeps its deadline; only open rows lose one at end-of-life or below the floor.

**Deferred by decision is split from plainly late**, giving three numbers rather
than two. A rate counting an approved deferral as a failure punishes the
deliberate act the deferral mechanism exists to make possible, and within a
quarter people stop deferring and let work run late quietly instead.

**Only a deferral in force counts as one** — agreed, or short enough to stand on
its own. A claim waiting for a second person is neither deferred nor an excuse
for lateness, and treating it as both would let one person take their own late
work off the report. The same test decides what the outcome filter answers for
and when a deferral's end is announced.

**A product is required**, because a place identity carries no product and a
decision correlated without one would reach decisions made in every product.
Every severity band comes back even where empty, because a rate table with rows
missing reads as one that has been narrowed.

**The report says what carries no deadline**, because a rate about dates is
silent about three populations that were never due: below the product's line, in
a tag, and in a release out of support. The last has a report of its own and is
linked from here.

**Only the whole-of-it figure opens a list.** The findings list reads a severity
as that band or worse, so a link from one band's row would open more than the
row counts — and a figure whose list holds something else is the failure a
report is easiest to ship.

## Release readiness

A branch beside the last release cut from it: *8 criticals now, v2.4.1 shipped
with 4*. Both halves come from scans already collected, so this asks nothing new
of a build pipeline.

| Rule | Reason |
|---|---|
| The same variant on both sides | A branch built for one chip beside a release built for another compares two different pieces of software, and the difference reads as a regression |
| The release is the newest one cut from this branch that has been scanned here | A tag is cut at a moment and never moves. One declared and never built has no counts, and answering with zeroes would report a clean release that does not exist, so the comparison is absent and what is missing is stated |
| A tag is not compared against itself | It is one frozen point and was not cut into anything |

Counted as issues at components, at or above the deployment's line, with the line
named beside the number (REQ-30).

## Holder workload

How much work each person has, and how much of it is past its deadline. Read on
the assignments screen, and listed in the report catalog from there.

The figure that matters is not how many findings exist but how many are stuck
behind somebody: an idle account holding nothing is harmless. The overdue count
separates somebody keeping up with a large list from somebody sitting on one.

Counted as pieces of work — an issue in a component in a product — rather than
as the findings they cover, so the figure agrees with the list behind it.

It carries the same narrowing every other query does. **A count is as much a
disclosure as a row.**

It is bounded, worst first, like every other list. It was the one name-yielding
projection with no ceiling at all — no limit parameter, no default, one row per
person holding open work as the deployment grows.

## Inheritance preview

Asked before a line is created, because the answer is what somebody is agreeing
to and a carry that happens silently is one nobody reviews.

| Group | Treatment |
|---|---|
| Reaches the new line by matching | Counted, never offered. A decision is a claim about a combination of code, so these have already happened |
| Held a claim at a version this line does not have | Offered as a *proposal carrying the old reasoning*, never as a decision, because the version moved and the old conclusion is not a conclusion about the new code |
| Deferrals | Offered separately, never carried by default. "Not this sprint" was about that sprint |
| Covers nothing here | Counted and left behind |

| Rule | Reason |
|---|---|
| Which product this is about is read from the build, not from the caller | The first version selected by live key and matching place alone, and a place is a hash of component names carrying no product — so a shared distribution package matched across products, and the reasoning of undisclosed claims came back to anybody who could read one product |
| Both upstream versions are compared, not just the component's | Comparing only one reported a build whose *consumer* had moved as already covered, when the claim does not reach it |
| A deferral states how long it has already run, across every line it has been carried through | Four consecutive carries of "not this release" are a year nobody decided on, and each looks reasonable alone. Withdrawn deferrals are not counted |

## Remediation metrics

Fix velocity, average time to remediate by severity, and aging buckets over a
window. A finding records when it opened and when it closed, so how long
something took is a subtraction rather than a second record somebody maintains.

**The aging buckets are cut two ways.** One number per bucket says a hundred
things are over three months old, and neither whether any of them matters nor
whether anybody has looked. So each bucket carries the same count by severity,
and how many carry no standing judgment.

**Matched on the live key rather than on both versions**, unlike the deadline
list: the aging query does not join the components those versions sit on, and for
a figure about a backlog the question is "has anybody said anything here".

Subtracting two moments has no portable spelling, so this is one of the few
places an engine is asked directly. It is confined to a single expression, and
the answer comes back as a fraction of a day: declaring it a whole number scanned
on none of the four — one refused a float outright and three handed back a
decimal string.

## Triage latency

Two waits, per severity, because a critical waiting a week and a low waiting a
week are not the same fact:

1. From a finding appearing to anybody proposing anything about it.
2. From a proposal to a second person agreeing.

**Three numbers rather than an average**: the middle, what nine in ten came in
under, and the longest. Ten decisions in a day and one in a quarter average to a
fortnight, which describes neither, and it is the quarter somebody is asking
about. The percentile is nearest-rank, because these are waits something actually
had.

| Rule | Reason |
|---|---|
| The arithmetic is in Go rather than SQL | Subtracting two moments is spelled four ways across these engines, and so is a percentile |
| Bounded, and it says so | At most the most recent few thousand claims in the window, with the answer stating how many and whether the ceiling was reached |
| Throughput is per person, counted where the work happened | A claim belongs to the window it was proposed in, and an agreement to the window it was given in |
| Send-backs are counted for the deployment, not per person | The record holds that a claim came back and not who sent it. Attributing it by finding the comment written at that moment would be a guess presented as a figure |

## Repeated deferrals

Places deferred more than once, with how often and for how long in total. The
cumulative threshold refuses a *further* deferral past a point, one item at a
time; what it cannot show is the shape across everything, and one item deferred
three times is a judgment where forty of them is a policy nobody wrote down.

Counted over the judgments rather than the findings they cover. A withdrawn
deferral is not time anything spent put off.

## Subtree trends

The three series are askable about an area, not only a product. A team owns a
kernel or a runtime rather than a whole image.

| Rule | Reason |
|---|---|
| It takes the findings list's own two narrowings | A component at any version, or a component and everything under it. A chart and a list describing a subtree differently is drift worth a shared definition to avoid |
| Across several builds it refuses | A subtree is a walk over one build's edges, so a selection holding two has no single answer, and both ways of producing one are silent: a chart of whichever build sorted first, or an empty one from an identifier left at zero |

**This is where a build beginning to carry patches becomes visible.** A carried
patch that names what it resolves is read at ingest and files a suppression, so
the finding closes where it sits without the package version moving. In a list of
what is open now the row is simply gone; here it is a step down.

## The disposition register

The complement of the audit list. The audit list states what was decided; the
auditor's first question is what was **known**, decided or not.

One row per issue and place in a named build, with its state, outcome,
justification, proposer, approvers, the dates each of those happened, its
deadline, and whether the deadline was met.

| Rule | Reason |
|---|---|
| One row per issue and place, whatever else is true of it | The agreement is read as a scalar rather than joined, because nothing makes an approval unique per decision — a second approver adds a row, and a join multiplied the finding. The page then held fewer rows than its total said, and because paging is by offset every page after that skipped one |
| It states no triage line, because it applies none | Everything in the build is here, decided or not, which is the basis on which an auditor can rely on it. The file said it had been taken above a line and had not |
| Everything is joined outward from the finding and joined left | A place nobody has decided about is the row this exists to show. Closed rows are included, and whether a deadline was met is answerable only for something that closed |
| The row names what pulls the component in, beside the place identity | The identity is derived from content, so it correlates two rows and names no location. A register whose only answer to "where" is sixty-four hex characters is one nobody can read, and where is what an auditor is asking |

**Current state, with no `as_of`.** Reconstructing the view as of a past date was
refused on two grounds. Each row carries the timestamps that evidence the thing
being checked — that a decision predates the ship date. And the reconstruction
would be least trustworthy on the column it would be checked hardest on:
deadlines are recomputed when the policy moves and removed below the floor and
past end-of-life, so a deadline "as of" a date is not recoverable.

Findings and decisions filter on when things happened instead: opened after,
closed after, proposed after. Asking for what closed after a date is the one
filter that changes what the list is *about* rather than narrowing it, and the
caller states so by asking for it.

## The exception report

**Filtered for decisions one person made, it returns a large and entirely
legitimate population**: an outcome that hides nothing needs no second person,
and a short deferral stands on its own until the cumulative time crosses the
threshold. The screen states which of the two questions is being asked.

**What it is for is showing that no dismissal sits in that population.**
Not-applicable, won't-fix and already-fixed all require approval, so that query
should return nothing, and a row in it is a control that failed.

**Asked of the record, never of a flag.** The condition is that no agreement
stands from somebody other than the proposer, which is the same question the
row's own answer is computed from. The test writes a self-approval straight to
the table: the report has to answer correctly about a row the write path should
have prevented, and one that trusted the write path would be reporting on itself.

Four filters: who proposed it, who has a standing agreement on it, which issue,
and which component. An agreement later taken back does not match the approver
filter, because answering otherwise would make a withdrawal invisible to the one
report that exists to find it.

**The product, the outcome and the state each take several answers.** "Dismissed
or deferred" and "waiting or sent back" are the questions somebody reading the
record has, and one value cannot ask either; the parameter repeats and any of
what is named matches. A product named that the reader may not see refuses the
whole request rather than being dropped, because a report answering about two
products when three were asked for reads as covering three.

**The exception report says "this should be empty" only where every outcome
asked for is a dismissal.** Mixed with a deferral the answer holds legitimate
rows, and saying otherwise over them would report a control as failed when it
had not.

**What was asked for is printed with every value.** A sheet headed "dismissed —
not applicable" over rows that also hold deferrals is a sheet nobody can check
against anything.

## Dismissals and scan coverage

Dismissals are a reportable dataset in their own right. Answered two ways: the
findings list filters on outcome and on whether a rating was changed, and the
record screen lists every judgment with its reasoning, its approvals and the
dates. Which of the five reasons applied is on the row rather than a filter,
because it is what an auditor reads on the row they stopped at.

**A dismissal is any of three outcomes**, and anything counting or listing them
asks for all three:

| Outcome | The claim |
|---|---|
| Not applicable | The vulnerable code is not reachable |
| Will not fix | It is not worth fixing |
| Already fixed here | Whoever packages the component backported the fix |

What they have in common is that nothing was changed, which is why they are the
three that need a second person. Asked of one, a program that dismisses
everything as "will not fix" reads as a program that has argued nothing away.

**Where a dismissal is listed, the place is named.** A judgment covering forty
places is forty rows in the record, and rows differing only in something the
screen does not draw read as the same dismissal recorded forty times.

What is being scanned, and when each build was last seen, is its own view. The
shape is in `DESIGN-ingest.md`. A product silently dropping out of scanning is
the failure that quietly makes everything else wrong: every number on every
screen goes on looking reasonable, and each describes a build nobody has looked
at since.

Releases past end-of-life are reported apart from live ones and raise no coverage
alert. Left in, the view that exists to catch the product that dropped out
silently fills with releases that stopped on purpose.

**This is a report an operator uses, not the tool publishing.** Nothing here
emits anything outward. Publication exists — a VEX document per build, an
advisory recorded when it goes out — and those are documents somebody asks for
and takes away.

## The report catalog

A report is a question somebody asks often enough to have a name. The catalog is
the list of those names, each a page of its own; the screen holding the list also
holds the files that are reachable nowhere else.

| Rule | Reason |
|---|---|
| A named report is a page at its own address | Printable, linkable and quotable. A section of a dashboard is none of those, and the screen this replaced was a metrics dashboard and an export panel stapled together under a name promising neither |
| A report about the thing you are standing on stays on that screen and is listed in the catalog; one that spans things lives only in the catalog | Otherwise one screen is rebuilt as a second copy under a reports address, and the two drift |
| Every report states what it was asked of and when it was taken | A figure narrowed to one variant and a figure spanning a program read alike on paper without it |
| A report that is a list exports as CSV and JSON; a report that is figures prints | There is no stream behind an aggregate. Inventing one publishes a file nothing here computed |
| Every figure opens the list it counts, and that list exports | The traceable form of a number, and what somebody asking for "the numbers as a file" actually wants: a row nobody can trace back to a finding is a number in a spreadsheet |
| No PDF is generated | Printing is the browser's, and the stylesheet is the record's. Server-side rendering is deferred |
| The register is a page of the catalog's own | It is about one build, and had no screen — only a file, which an auditor had to download to read. So the catalog owns it rather than a build screen listing it, and it asks for a whole build the way the build-scoped entries do |
| An entry may point at a screen rather than owning a page | Seven do: release readiness, upgrade plan status, carried patches, holder workload, embargo and disclosure, the exception report, and administrative changes. Each is a report about the thing you are standing on, so it stays where it is and the catalog carries it with the scope already applied |
| An entry that points at a build's screen asks for a whole build | Five screens exist for one build and no other. An entry into one on a partial selection would open on a scope that means nothing, so it says which picker to touch instead |
| The question with no name is asked on the findings list, not on a panel of the catalog's own | A panel offering the findings list's filter panel and the findings list's query is that screen at a second address, and the copy is the poorer one: it passed an empty tag list, so it offered fewer filters than the screen it copied. The catalog points at the list instead |
| The catalog offers only the files reachable nowhere else | Two are: what is running out of time, and the VEX document. Every other file is offered on the screen that answers for it and carries that screen's filters, so a second unfiltered link beside it is a worse copy of the same answer |

**The exception report is the record with its filters set** — dismissals no
second person has a standing agreement on. REQ-53 names it as the report that
should come back empty, and the record's own empty state is already written as
that answer rather than as an absence.

**Program overview** is the first of them: what is being fixed against what is
appearing, what is aging and whether anybody has looked at it, how long a claim
waits to be decided and then agreed to, what keeps being put off, and what has
been argued away. Its window is seven, thirty or ninety days, and the printed
header names which.

**Advisories issued** is what has gone out about flaws in our own product over
a period, and what went out twice. Answered per flaw elsewhere, which is the
shape somebody about to publish a revision needs; a period asks something else.
A row carries the digest the document hashed to when it went out, because the
published document belongs to whoever published it and the digest is what makes
comparing the two possible.

**An issuance carries no visibility of its own**, so the row is narrowed by the
flaw it was written about. Reading one as public because it has no visibility
column would announce an undisclosed flaw in the report about announcements, and
the row names the identifier.

**Rubber-stamp** asks how much a second pair of eyes actually did.

**It is not a list of people who broke the rule**, because the rule cannot be
broken: approving refuses the proposer, refuses the author of the revision being
agreed to, and is conditional on that revision still being current. What it
reports is where the rule did not apply and where it applied in form only.

| Section | What it says |
|---|---|
| Risk standing on one person | Split in two, because the halves read oppositely. A dismissal here is a control that did not hold. A short deferral, or an upgrade promised inside the deadline the work already had, is the exception working — deliberate, so that gating every routine act does not put ordinary triage through a queue nobody then reads. One at a time it is triage; the pattern across a program is what nothing else shows |
| Who agrees with whom | Every proposer and approver pair, with the share of everything agreed to that ran between them. The share is the signal rather than the count: fifty of fifty-two and fifty of nine hundred are the same number and not the same situation |
| Agreements given in bulk | An approver works at the unit the proposer acted at, so agreeing to a batch as one act is the control working. A batch of two hundred is still not a batch of two |
| Agreed to before, covering more now | What was consented to, recorded at the moment of consent, against what the same claim reaches today. A claim reaches by matching, so a build appearing later is covered with nobody acting and nobody having agreed to the larger number |
| Standing from somebody who could not give it now | Correct behavior — an approval is a fact about a moment, and losing a role does not un-say what somebody said — and the first list asked for after a reorganization |

Everything is dated by when a claim was **proposed** rather than when it was
agreed to, for the reason the record is: a judgment belongs to when it was
argued, and dating it by its agreement moves it out of that period whenever an
approval comes late.

**Releases out of support** is the third, and the one nothing else counts.
Past end-of-life the deadline is removed from every open finding on a release,
so none of that pile is overdue, none is due soon, and none of it reaches a
figure built on either. That is correct — no work will land there — and it
means asking for it is the only way to see it. The report is the releases whose
date has passed, how long ago that was, and how many issues are still open
against each, ordered by what is open. A date inherited from the product says
so: a release following a date and one that stated the same date are different,
and only the first moves when the product changes its mind.

**Scan coverage** is the second, and the one every other number rests on: the
whole estate longest silent first, with how many builds are being scanned, how
many have gone quiet, and how many were declared and never filed against. A
build out of support is listed, marked, and never counted as quiet — silence
there is expected, and a coverage report filling with those stops catching the
product that dropped out. The front page names the three quietest and the
inventories screen answers for one product; this answers for the estate.

## Exports

Any list that can be read can be exported, as CSV or JSON. Nine lists export:
the findings list, the cross-product findings list, the record of judgments, the
review queue, the by-component view, what is running out of time, scan coverage,
what is out of support, and a comparison of two builds.

**The subject travels through the stream.** An export is the easiest place to
build the list first and narrow it afterwards, so it is the same query with the
same subject, written out as it goes and paged as it streams at the page the
screen reads. No complete list ever exists to be filtered afterwards. A failure
part-way writes a line saying the file is incomplete, because a file that simply
stops is one somebody reads as whole.

| Rule | Reason |
|---|---|
| A file states what it is narrowed or computed by, in a header row | A spreadsheet opened six months later has nothing else to say that everything below medium was never in it (REQ-30), or what threshold a true/false column was measured against. One statement, a label and a value, so the record's file — which has no severity line — states nothing rather than an empty one |
| The cross-product list states no single line | Each product applies its own |
| The findings list offers its file whether or not a product is picked | The two lists are two endpoints and the filters mean the same on both, so offering the control on one and not the other left one narrowing reachable as a file and the other not, for no reason a reader could see. The spanning file drops the filters a single build resolves, the same narrowing the screen's own read applies |
| Each takes the same filters as its screen, from the same struct | Two declared their parameters by hand and drifted: the findings export accepted fourteen of the list's filters and the by-component export ten, so nineteen arrived and were dropped before the handler ran. Nothing rejects an undeclared parameter, so there was no error and no clue |
| Paging is a struct of its own, kept out of the filters | An export answers the whole of a narrowing and pages internally; embedding the filters wholesale would make it offer a page size it does not honor |
| The deadline report needed an offset before it could be a file | What somebody exports a deadline report for is precisely the part they have not read. Paging it also needed the build in the ordering, since an arbitrary order between pages repeats one row and skips another |
| The comparison is one file with a column naming which of the three parts a row belongs to | Three files are three things to keep together by hand. It is read whole rather than paged, because a comparison is a single answer computed from two builds at once |
| The queue's file is what is waiting on you | Your own claims are not in it |
| An agreement taken back is not somebody who agrees | The record's file lists only agreements that still stand, and states separately whether a second person has one |

## Settings

What an administrator changes from inside the application, as opposed to what an
operator sets when deploying it. A configuration file is edited by whoever can
reach the filesystem and restart the process.

| Setting | Controls |
|---|---|
| The five deadline windows | Exploited, critical, high, medium, low |
| The deferral threshold | How long something may be put off before a second person has to agree |
| The session lifetime | Also the window in which somebody who moved out of a team still holds what the team gave them |
| The token ceiling | The longest a personal token may last |
| The limit on one action | How many findings a single judgment may cover |
| The triage floor | The severity below which findings are recorded and counted but kept off the working list. A product may state its own |
| Quiet after | How long a build may go without a scan before it is reported as quiet |
| Scan every | How often everything tracked is scanned again |
| Upstream currency | Whether to ask public package indexes for the newest version. Off unless turned on: the only thing here that reaches the network |
| The two attachment bounds | The largest single file, and the deployment total |
| Absent after | How long somebody may go without signing in before work they hold is raised |
| The three disclosure periods | How long a finding stays undisclosed, how much that date may move in total before a second person agrees, and the lead time before it |
| The four staleness periods | A claim waiting on a second person, one sent back, a deferral ending, and work in a team's queue |

The shipped numbers are a starting point rather than a recommendation. A deadline
nobody agreed to produces an estate that is permanently late.

**A value nothing can read is refused, not stored.** Every reader falls back to
the shipped default where a setting is unset or unparseable, so a stored value
nobody can read is a policy that quietly stopped applying. The value is checked
before it is written, against the kind the name is: a duration for the windows,
threshold and lifetimes; a whole number above zero for the limit on one action; a
severity word for the triage floor; on or off for upstream currency.

| Rule | Reason |
|---|---|
| Zero and negative are refused | Every reader treats them as unset, so storing one produces a setting that looks set and does nothing |
| Only known names may be set | Storing an unknown one creates a setting nothing reads |
| A failure to *read* a setting is not "unset" | Every caller has a default, so a database that could not answer would silently swap the deployment's configuration for the shipped one, including the threshold deciding which deferrals need a second person. That is reported |
| Everything offered is read | The session lifetime was offered here while sign-in took its value from the environment and never looked. The order is the administrator's setting, then what the process was started with, then the built-in default |

## Limits

- **An export answers the question the list beside it answers**, embedding the
  same filters rather than re-declaring them. A filter the list applied and the
  export dropped produced eight rows on screen and seven thousand in the file,
  under the same heading.
- **A cell a spreadsheet reads as a formula is neutralized.** Component names
  arrive in somebody else's inventory, and these files are opened by the people
  holding the most access in the deployment.
- **The disclosure periods were read and wired into behavior with no way to set
  them**, while two other documents described each as a setting.
