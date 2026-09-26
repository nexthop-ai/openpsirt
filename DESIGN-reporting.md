# Reporting

The figures this produces and what each is a count of.

Satisfies REQ-25, REQ-33, REQ-35, REQ-50, REQ-51, REQ-52, REQ-53, REQ-54,
REQ-74, and part of REQ-30.

Everything here reads what the findings and decisions already hold. No table in
this document is its own.

## Contents

- [The counting unit](#the-counting-unit)
- [Computed on demand](#computed-on-demand)
- [The period a report covers](#the-period-a-report-covers)
- [Trends](#trends)
- [Build comparison](#build-comparison)
- [The release note](#the-release-note)
- [Deadlines](#deadlines)
- [Deadline compliance](#deadline-compliance)
- [Release readiness](#release-readiness)
- [Holder workload](#holder-workload)
- [Inheritance preview](#inheritance-preview)
- [Remediation metrics](#remediation-metrics)
- [Effort by subject](#effort-by-subject)
- [Triage latency](#triage-latency)
- [Repeated deferrals](#repeated-deferrals)
- [Subtree trends](#subtree-trends)
- [The disposition register](#the-disposition-register)
- [Known issues at release](#known-issues-at-release)
- [One issue across the estate](#one-issue-across-the-estate)
- [The exception report](#the-exception-report)
- [Dismissals and scan coverage](#dismissals-and-scan-coverage)
- [The report catalog](#the-report-catalog)
- [Fix-bundle page cost](#fix-bundle-page-cost)
- [Exports](#exports)
- [Settings](#settings)
- [Limits](#limits)

## The counting unit

Every rate and count is one issue at one component, never one place. The
deadline is stored per place, but a place is not a piece of work: one flaw in
one library that forty-five packages pull in is one decision. Counted per place
it is forty-five late things beside one late thing on the findings list, both
labeled the same, and on a real kernel the two numbers are about thirty-seven
apart.

Where a report groups places first, it states what a group means rather than
summing:

| A group is | When |
|---|---|
| Closed | No place is still open |
| Met | None of the closed places was late |
| Deferred | *Every* open place is covered by a standing deferral. One covering some of a group leaves the rest running |
| Overdue | Anything open is past its date and uncovered |

Two closure reasons are not resolutions, and a velocity figure counting them
measures churn:

| Reason | Why it is not a resolution |
|---|---|
| `superseded` | The component's version moved and the issue came with it. Counting it as resolved draws a line saying work was completed while the same chart's new line rises by exactly as much |
| `unexplained` | The scanner stopped reporting it with the component present and unchanged. A fault to investigate |

The other five — removed, upgraded, revised, patched, and a recorded flaw
declared fixed — are counted.

Closed exactly at the deadline met it: something still open at its deadline
instant is not yet overdue, so something closed at that instant was not late.

## Computed on demand

Every count is worked out when it is asked for. Nothing is precomputed, cached,
or refreshed on a schedule.

The best-known tool in this space stores metric snapshots and runs a refresh job,
for reasons that are its own: a hosted portfolio with far more traffic than a
self-hosted deployment sees. The traffic here is dozens of people in a month.

A second cost is easy to miss. Visibility is per subject, so a precomputed
total is a total *for somebody* — either computed per person, which is not a
saving, or computed once and then filtered, which is a second path through the
visibility rules.

What would change this is a dashboard measured slow on a real deployment. The
shape is then known and should not be reinvented under pressure — precompute at
the grain access is granted at, one row per product per day, so a portfolio
number stays the sum of what the reader may see.

## The period a report covers

Every report over a stretch of time takes one: deadline compliance,
remediation, triage latency, approval coverage, where the effort went, what
advisories went out, and what has been changed administratively. Two
dates, or a rolling window of days, in one shape so that a screen linking from
one report to another carries the same two parameters.

| Rule | Reason |
|---|---|
| A period is two dates; a rolling window is a number of days | A window ending today cannot say "last financial year", which is the number an auditor asks for, and dates alone make "how are we doing lately" a date somebody has to work out |
| Only one of the two may be sent, and sending both is refused | A caller who sent both meant one of them, and answering about the other is a figure quoted for the wrong period — the failure a period control exists to fix |
| The end is the day it stops, not a day inside it | The same rule the record of judgments already used, so the two cannot come to mean different things |
| A period that ends before it starts is refused, and so is one that holds no days | A report answering zero for either is indistinguishable from a quarter in which nothing happened. Two refusals, because the end is not itself in the period: naming one day twice asks for no days rather than for a day |
| Every report says back the period it covered, with the end resolved | A figure read apart from its window is a number nobody can check, and a start with no end answered with nothing over figures that ran to now. An unstated *start* is the beginning and says so by being absent |
| A default window belongs to the report, and each says which in its own words | They differ — thirty days, ninety, or the whole of it — and one shared parameter cannot carry three answers |
| **What is open is always now** | Deadlines are recomputed as the policy moves and dropped below the line and past end of life, so what stood open on a date gone by is not recoverable — the same reason the register states current state with no `as_of`. A period bounds what closed in it |
| The rate asked for no period is the lifetime figure | It is what that report has always answered, and a default window would quietly change what the number means for everybody reading it |
| The change log takes no default window | A record read with one answers about the last stretch while looking like it answers about everything, which is the reading an audit must not be given |
| **A trend is stepped, so its window is a count of steps rather than a period** | It is the one report whose answer is a series: a step is a week, and what is asked for is how many of them. Two dates cannot say "in steps of a week" and a number of days cannot say where a step ends, so the shape above does not fit and is not pretended to |
| The longest window offered is two years | Measured rather than assumed, because the walk that fills the buckets is per row per step: over 8,407 open findings on two builds, twelve weeks answers in 1.28 s and a hundred and four in 1.40 s — nine per cent for nearly nine times the steps, because the cost is the query rather than the walk. The file over the same window is 1.43 s |

## Trends

Three series over time — new, resolved and open — with open split by severity.
Separately they are three numbers; together they state whether the team is
keeping pace. An open count that barely moves while its critical share rises is
getting worse, and one line hides that.

| Viewing | Axis | Reason |
|---|---|---|
| A branch | Calendar time | It is scanned nightly and has continuous data |
| Tagged releases | Release over release, oldest first, drawn as bars | Each is one frozen point. Releases months apart make a calendar count read as slow drift rather than the step change it was, and a line between two frozen points draws a path nothing traveled |

| Rule | Reason |
|---|---|
| Answered against today's vulnerability data, not as of the day each was cut | That is what re-scanning a shipped release is for. A chart freezing the answer hides the advisory published after it shipped |
| Rates stay on calendar | How much appeared and was resolved between two releases is an artifact of how far apart somebody cut them |
| A product must be named, and two releases is the fewest that is a shape | Across products the tags interleave by date and mean nothing side by side; one bar reads as broken rather than as sparse |
| A release with nothing open is still a release | The figures are read from every build that has been *scanned*, with counts attached to that list rather than the list derived from the counts. Driven from findings alone, a clean release had no row, and absent is how this list says "never scanned" |

The window becomes predicates before the statement runs: a finding opened
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
| What left the affected list is two sets | An upgrade, a carried patch, a patch the build declares, a component no longer shipped and a recorded flaw declared fixed are fixes. A bump that carried the issue with it, a record taken back, and a closure nothing explains are not — the last means the component is unchanged and the scanner stopped reporting it, which is a fault to investigate. One list, and the number a release coordinator quotes includes them |
| The split is made once, where the release note and the remediation rate read it | A screen making the same judgment a second time in a column heading disagrees with it: a column headed "Fixed" then carries unexplained closures, under an explanatory note about the one reason not in it |
| An entry that left says which run stopped reporting it | An unexplained closure is a fault, and the first question about one is which run. Told it is unexplained and given nowhere to look, a reader has the fault and no way to start on it. Absent where a person closed the finding, which is the other way one closes |
| Each fixed entry states why | "Fixed by upgrading to 2.4" and "fixed by a carried patch" are different sentences, and the closure reason distinguishes them. `superseded` means the version moved and the issue came with it — before that reason existed, such a bump put one issue in both the fixed and the newly-present column of the same document |
| A fixed entry states what it moved to | "The component was upgraded, 3.7.0 → 3.9.0". That pair is written when the scan closes the finding, because the component that carried the issue is gone from the inventory by then and anything asking later holds one version and not two |
| Each still-present entry states whether somebody tried | It carries the version its place arrived from where the version moved since. On the still-present column only: a fixed entry's closure reason already says what happened, and a new one had nothing to bump |
| Explanations are read once for the whole list, not once per entry | A comparison against a release a customer has been on for a year has as many fixed entries as the note is long. The statement narrows by the issues and the components separately rather than by the pairs, because no engine here spells a comparison against a pair of columns the same way, so what comes back is a superset and the pairing is done on the way out |
| Each entry is rated as its own product rates it | Read from the published rating alone, the document contradicts the findings list it was written from wherever a product has re-rated an issue — and this is the copy that leaves the building. The two builds can be in two products, so each half of the comparison is rated by its own |

## The release note

The same comparison as prose (REQ-51): markdown, served as `text/markdown` rather
than as a string in a JSON field.

Rendered on the server. What an API caller gets and what the screen shows have to
be the same words, and two implementations of how a release note reads is one
that drifts.

It carries what was fixed and nothing else: not what is still present, not what
newly appeared, and not a bump that carried the issue with it.

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
| Fixes are grouped by what was done, not by the issue | One kernel upgrade closes 917 issues at once, and a bullet per issue states the same version pair 917 times in a document going to a customer — while the part a reader is looking for, which version to move to, is the part that repeats. The move is stated once and the issues it closed are listed under it |
| A group is the component with its closure reason and its version pair | Two upgrades of one component in one comparison are two different answers to "what do I move to", and folding on the component alone states one of them over both |
| A bullet carries the score, whether it is known exploited, and where it is written up | The name and the word do not say whether the upgrade is taken tonight or next month, and all three are already held. The address goes through the rule an address stored beside a claim does, because this document leaves the building and a scheme a reader's machine acts on is not something to hand them |
| The description is not in the bullet | One upgrade closes hundreds of issues and they are listed under it, so a sentence apiece is a document nobody reads to the end. The description is behind the link, which is what the link is for |
| An empty section is not written | A heading with nothing under it is a question about whether something is missing |
| A release that fixed nothing says so, in a sentence | Answering nothing at all is indistinguishable from a truncated response, the wrong pair of builds and a request that went astray. A sentence is not a heading over nothing, so the rule above still holds: what comes back names the two builds and what measured them, and carries no section |
| What was left out is counted | A reader cannot otherwise tell a release that fixed nothing undisclosed from one whose undisclosed fixes were taken off the page. A number and never the entries, and zero for a reader who could not have seen them anyway |
| The count is of fixes, by the same rule the listed entries are | A pair open in one build and not the next has left the affected list, which is not the same as having been fixed: an invalid record means the build was never affected, a superseded row means a bump carried the issue along, and an unexplained closure says nothing at all. The listed half excluded all three; the counted half was a plain set difference that never read a closure reason, so the sentence beneath the note told a customer each of those was a security fix. Both halves go through one function |

## Deadlines

A finding carries a deadline from how urgent it is: a configured window, counted
from when it was first seen. Being overdue is reported and never acted on
automatically.

| Rule | Reason |
|---|---|
| Known-exploited has its own window, and it is the shortest | Severity is how bad a flaw is; being exploited is a fact about the world. Without a separate window the deadline contradicts the ranking |
| Anything the reports did not rate takes the medium window | Nobody having scored it is not a claim that it is mild, and giving silence the longest window puts the findings least is known about at the back of the queue |
| Days remaining are rounded down rather than truncated toward zero | Truncation reports something twelve hours overdue as having zero days left, which reads as due today |
| Stored at ingest, recomputed when the policy changes (REQ-33) | Computing it per request costs a pass over every open finding *per urgency band*, because each band allows a different number of days — measured at about eight seconds over 441,108 findings. Stored, it is an indexed range scan |
| The clock runs on what nobody has answered | A dismissal takes a finding off it entirely; a deferral replaces the deadline with its own date. It stops only for a decision that *applies*: approved, or proposed where no second person is required, at the versions this build ships, and a deferral only until its date. A proposal still waiting for an approver stops nothing, and "who is holding what" counts overdue by the same condition, spelled once |
| One range scan ordered on the stored deadline | Asked band by band instead — once per window, each with its own first-sighting cutoff, merged afterwards — because ordering by a deadline means date arithmetic, which has no portable spelling across the four engines. Taking the oldest findings and discarding whatever is not due loses an exploited finding first seen yesterday and due tomorrow to a low from two years ago that filled the buffer. A list ordered on a proxy for the answer is not the list it claims to be |
| A person is named on a row only where every place has the same one | Reporting one of several would say a finding is being dealt with when most of it is not |

Urgency is stored at ingest for the same reason and carries the same staleness,
but nobody edits the ranking and people do edit deadlines.

## Deadline compliance

Per severity: closed within the deadline against closed in total, and open past
the deadline against open in total. The inputs are stored, because a closed row
keeps its deadline; only open rows lose one at end-of-life or below the floor.

| Rule | Reason |
|---|---|
| Deferred by decision is split from plainly late, giving three numbers rather than two | A rate counting an approved deferral as a failure punishes the deliberate act the deferral mechanism exists to make possible, and within a quarter people stop deferring and let work run late quietly instead |
| Only a deferral in force counts as one — agreed, or short enough to stand on its own | A claim waiting for a second person is neither deferred nor an excuse for lateness, and treating it as both would let one person take their own late work off the report. The same test decides what the outcome filter answers for and when a deferral's end is announced |
| A product is required | A place identity carries no product, and a decision correlated without one would reach decisions made in every product. Every severity band comes back even where empty, because a rate table with rows missing reads as one that has been narrowed |
| The report says what carries no deadline | A rate about dates is silent about the populations that were never due: below the product's line, in a tag, in a release out of support, and with nothing upstream to take. The third has a report of its own and is linked from here |
| Taking a population off the clock moves the rate, and upward | A row needs a deadline to be judged at all, so one losing its deadline leaves the numerator and the denominator together — and the rows leaving are disproportionately the late ones. The figure rises with no work done, which is a correction rather than an improvement, and anybody tracking it is told why. A rate over a period spanning such a change is computed from two rules, because only open rows are re-clocked |
| Only the whole-of-it figure opens a list | The findings list reads a severity as that band or worse, so a link from one band's row would open more than the row counts — and a figure whose list holds something else is the failure a report is easiest to ship |
| What is still open at all is a column, beside deferred and overdue | Those two alone are numerators with no denominator, so "eleven overdue" cannot be read as a share of anything, which is what a rate is |

## Release readiness

A branch beside the last release cut from it: *8 criticals now, v2.4.1 shipped
with 4*. Both halves come from scans already collected, so this asks nothing new
of a build pipeline.

| Rule | Reason |
|---|---|
| The same variant on both sides | A branch built for one chip beside a release built for another compares two different pieces of software, and the difference reads as a regression |
| The release is the newest one cut from this branch that has been scanned here | A tag is cut at a moment and never moves. One declared and never built has no counts, and answering with zeroes would report a clean release that does not exist, so the comparison is absent and what is missing is stated |
| A tag is not compared against itself | It is one frozen point and was not cut into anything |
| The count carries the list it is made of, worst first and bounded | A number read at the moment there is no time to assemble what it is made of is a number nobody can act on, and this is the screen a release conversation happens in |
| The bound is the worst few, not a page | Against a blocker count in the thousands, twenty rows are an arbitrary page of the list rather than what the count is made of — and they made the panel three times the height of everything beside it, on the screen named after the comparison those others draw. The list the panel links to is where the whole of it is worked |
| The component name gives before the panel does | It is the part of a row that varies, and a Debian kernel package is forty-four characters of it — so it shrinks and ends in an ellipsis with the whole of it on the title, rather than running out of a panel sized by the comparison beside it |
| A row carries the version, because the group does | A group is keyed on the issue and the fold, and a fold is the source package at the version it was built at. Named by component alone, one issue at three versions of one component drew as three identical rows differing in a count that is not on the row |
| Anything agreed to is absent from that list | Agreeing is the decision to ship with it, which is the opposite of a blocker. What is left is undecided, waiting on a second person, or standing on a judgment that lapsed |
| It is read through the findings list's own reader, with the same line | So the list it opens is the list it counts |

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

It carries the same narrowing every other query does. A count is as much a
disclosure as a row.

It is bounded, worst first, like every other list. Unbounded it is one row per
person holding open work, growing with the deployment, and it yields names.

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
| Both upstream versions are compared, not just the component's | Comparing only one reports a build whose consumer has moved as already covered, when the claim does not reach it |
| A deferral states how long it has already run, across every line it has been carried through | Four consecutive carries of "not this release" are a year nobody decided on, and each looks reasonable alone. Withdrawn deferrals are not counted |

## Remediation metrics

Fix velocity, average time to remediate by severity, and aging buckets over a
period. A finding records when it opened and when it closed, so how long
something took is a subtraction rather than a second record somebody maintains.

The aging buckets are cut two ways. One number per bucket says a hundred
things are over three months old, and neither whether any of them matters nor
whether anybody has looked. So each bucket carries the same count by severity,
and how many carry no standing judgment.

The aging figures match on the live key rather than on both versions, unlike the deadline
list: the aging query does not join the components those versions sit on, and for
a figure about a backlog the question is "has anybody said anything here".

Subtracting two moments has no portable spelling, so this is one of the few
places an engine is asked directly. It is confined to a single expression, and
the answer comes back as a fraction of a day: declaring it a whole number scanned
on none of the four — one refused a float outright and three handed back a
decimal string.

## Effort by subject

What the judgments in a period were about, most argued first: the component,
the product, how many arguments were made, how far they reached, how many
people made them, and what came out of them.

Every other figure here counts the backlog. None of them answers what a
planning meeting asks — what the quarter actually went into — and it is the one
a manager has to answer without any of the others.

| Rule | Reason |
|---|---|
| Counted in claims, with the places beside them | A claim is one person's act. Counted by its rows, this would measure how far a component fans out through an image, and the component every image vendors would be the answer every quarter. Both, because ten claims over ten places and one claim over a thousand are different afternoons |
| What came out of them is part of the answer | Forty arguments that dismissed forty and forty that promised forty upgrades are different quarters, and a report carrying only the volume says they are the same |
| What a judgment was about is reached through the findings at its place | A decision names a place rather than a component. A judgment about something since removed still names what it was about, which is what a report about where the time went has to keep |
| Dated by when a judgment was proposed | The work happened when it was argued; dating it by its agreement moves it out of the period whenever an approval came late, which is the ordinary case. The same rule the record dates by |
| It takes the same period and the same scope the other reports do | One product or one team, so a manager reads their own quarter rather than the deployment's. The team is picked on the sheet, from the teams that exist |

## Triage latency

Two waits, per severity, because a critical waiting a week and a low waiting a
week are not the same fact:

1. From a finding appearing to anybody proposing anything about it.
2. From a proposal to a second person agreeing.

Three numbers rather than an average: the middle, what nine in ten came in
under, and the longest. Ten decisions in a day and one in a quarter average to a
fortnight, which describes neither, and it is the quarter somebody is asking
about. The percentile is nearest-rank, because these are waits something actually
had.

| Rule | Reason |
|---|---|
| The arithmetic is in Go rather than SQL | Subtracting two moments is spelled four ways across these engines, and so is a percentile |
| Nearest rank is the first observation at or past that position | Three waits of one, two and thirty days have a median of two. Truncating instead of rounding up picks the one below, which for an odd count is not the middle and for a tail figure is not the tail |
| A wait is measured from the finding the claim is about | A place is a pair of names with no product in it, so the same place sits in every product shipping that component. Matching on the place alone took the figure from another product's finding, and from findings the reader may not see |
| Bounded, and it says so | At most the most recent few thousand claims in the window, with the answer stating how many and whether the ceiling was reached |
| Throughput is per person, counted where the work happened | A claim belongs to the window it was proposed in, and an agreement to the window it was given in |
| Send-backs are counted for the deployment, not per person | The record holds that a claim came back and not who sent it. Attributing it by finding the comment written at that moment would be a guess presented as a figure |
| It narrows to one product, or to one team's people | Without a scope there are no per-team figures, so a manager asking how their own people are doing reads the deployment's numbers with their name on them |
| A team narrows the two waits by who **proposed**, and its throughput by who did each piece of work | A claim belongs to whoever argued it, which is the rule the record of judgments dates by — narrowed by the approver, a team's time to agree would be about claims its people agreed to for somebody else. Throughput is a row per person, so it is narrowed by the person the row is about |
| A team with nobody on it measures nothing | A narrowing that silently widens to the deployment is the one mistake a narrowing must not make |

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

A carried patch shows here as a step down in the open count. A patch that names
what it resolves closes the finding as patched on the scan that first carries it
(`DESIGN-findings.md` § Build-declared claims), and a patch that moves the shipped
version closes it as revised. In a list of what is open now the row is simply
gone.

## The disposition register

The complement of the audit list. The audit list states what was decided; the
auditor's first question is what was **known**, decided or not.

One row per issue and place in a named build, with its state, outcome,
justification, proposer, approvers, the dates each of those happened, its
deadline, and whether the deadline was met.

| Rule | Reason |
|---|---|
| One row per issue and place, whatever else is true of it | The agreement is read as a scalar rather than joined, because nothing makes an approval unique per decision — a second approver adds a row, and a join multiplied the finding. The page then held fewer rows than its total said, and because paging is by offset every page after that skipped one |
| It states no triage line, because it applies none | Everything in the build is here, decided or not, which is the basis on which an auditor can rely on it. A file stating it has been taken above a line where it has not is worse than silence |
| Everything is joined outward from the finding and joined left | A place nobody has decided about is the row this exists to show. Closed rows are included, and whether a deadline was met is answerable only for something that closed |
| A judgment that lapsed is part of the record, and a superseded one is not | Asked of the decision's own columns rather than of the join. In the join it hid a lapsed judgment entirely, so the place reported as never decided and the register lost who proposed and who approved it — while the findings list called the same place lapsed |
| The row names what pulls the component in, beside the place identity | The identity is derived from content, so it correlates two rows and names no location. A register whose only answer to "where" is sixty-four hex characters is one nobody can read, and where is what an auditor is asking |
| It names what it was measured with: the upload, the inventory in it, the run, the scanner and the vulnerability data | The chain an auditor follows is shipped artifact, inventory, run, scanner and database, disposition. The register is the last link, and naming none of the first four leaves what it says standing on nothing a reader can check — while all of them are recorded |
| The inventory is a link, not a hash | A hash nobody can fetch the bytes for is a claim rather than evidence. A tagged release keeps its documents and a branch build does not, so an inventory that was let go says so instead of reading as an omission |
| It narrows by what stands, by outcome, by component, by issue, and to one side of the history | An auditor asks "what has nobody decided" and "show me the dismissals", which are ways of reading the same complete answer rather than different questions. The count is of the narrowed list, because counted over the build a narrowed page says how many rows the build holds and every later offset is a page of a different list |
| It still applies no triage line, whatever else is asked of it | That is what it is for, and a filter that could hide part of the build would make it the findings list at a second address |
| A state word it does not recognize keeps nothing | A filter that silently widens is how a register reads as complete about rows it left out. The route's own vocabulary refuses one at the door; this is the guard behind it |
| Provenance never fails the report | A build nothing has finished scanning is the one somebody is most likely asking about, so what cannot be read is absent rather than an error |

Current state, with no `as_of`. Reconstructing the view as of a past date is
refused on two grounds. Each row carries the timestamps that evidence the thing
being checked — that a decision predates the ship date. And the reconstruction
would be least trustworthy on the column it would be checked hardest on:
deadlines are recomputed when the policy moves and removed below the floor and
past end-of-life, so a deadline "as of" a date is not recoverable.

Findings and decisions filter on when things happened instead: opened after,
closed after, proposed after. Asking for what closed after a date is the one
filter that changes what the list is *about* rather than narrowing it, and the
caller states so by asking for it.

## Known issues at release

What a build still carries, with what stands about each. The comparison
already answers it, so this is that screen's third column rather than a page
of its own, and the catalog carries it with the selection made.

| Rule | Reason |
|---|---|
| A still-present row says how far it has been decided, what was decided and when it is due | A list of what is still there with no way to tell an approved not-applicable from something nobody has looked at is not a list anybody can sign. Those are opposite answers to the question a release sign-off asks |
| The outcome is stated only where every standing decision over the row's places reaches the same one | A component argued away at one place and deferred at another is two claims, and stating either over the row would be a claim nobody made. The same rule the VEX document publishes under |
| Agreement is about the outcome, and the reason is stated only where one claim answered the row | Two claims can argue a component away for different recognized reasons and still agree it does not apply; counted as disagreement, the column goes blank on a row every place of which has been argued away. Which of the two reasons it was is what the row cannot say |
| The claims behind a row are told apart by their identifiers, never by their words | A justification is a long-text column on two of the four engines, which compare a bounded prefix for grouping. Told apart by the text, two engines could disagree about whether a row has one answer or two |
| The state is counted the way the findings list counts it | One spelling of each of the four, so a row here and the same row on the list cannot say different things about how far it has been decided |
| The column narrows to what nobody has agreed to | That is the coordinator's blocker list, and it is the one narrowing the sheet is read for |
| It is read for the still-present entries alone | What was fixed needs no justification and what is newly present has not been looked at yet |

## One issue across the estate

A document: the issue, every build of ours that carries it, what was decided
about each and the argument behind it. The form a customer inquiry is answered
from. Assembled out of four screens and a copy-paste instead, the answer is
assembled differently every time.

| Rule | Reason |
|---|---|
| It is internal, and says so on its first line | It carries the reasoning, which is this deployment's own argument rather than its word to a customer. What goes out is the advisory or the VEX document, and both say less on purpose. A document that does not say who it is for is one somebody forwards |
| Markdown, served as markdown | The same reason the release note is: the point of it is that it goes straight into a reply |
| Nothing of yours affected is a document, not a refusal | "Are you affected by this" could be answered yes and never no, and the second is the answer an inquiry is usually asking for |
| An identifier nobody has seen and one that sits only in products you cannot read produce the same document | Told apart, the pair says which issues this deployment holds, one guess at a time |
| Every address in it goes through the rule an address stored beside a claim goes through | It is a document somebody forwards, and a scheme a reader's machine acts on is not something to hand them |
| It is bounded, and says when the list is a page of a longer one | An issue at a widely vendored component carries hundreds of judgments, and what this is for is being read |

## The exception report

Filtered for decisions one person made, it returns a large and entirely
legitimate population: an outcome that hides nothing needs no second person, and
a short deferral stands on its own until the cumulative time crosses the
threshold. The screen states which of the two questions is being asked.

It exists to show that no dismissal sits in that population.
Not-applicable, wrong match, will-not-fix and already-fixed all require
approval, so that query should return nothing, and a row in it is a control
that failed.

That is why nobody has to open it to find out. The same question is asked as
a condition and told to administrators when it stops answering nothing —
because a report that is empty every time is one nobody opens, and it is then
read only after something has already gone wrong. `DESIGN-notifications.md`
§ Reports that must come back empty holds the rest, including why the
condition carries a count and a link and never these rows.

The rubber-stamp report is not the same shape, despite asking the same
question in one of its sections. Only what stands with nobody agreeing has to
be empty. Bulk agreement is the control working at the grain somebody acted at,
and an approval from a role since withdrawn is correct behavior, so neither
raises anything. The same two people agreeing is what a small team looks like,
so the pairs section raises a condition only past two thresholds: a share of a
product's agreements, among at least a set number of people who may approve.
Both are settings a product may override. `DESIGN-notifications.md` § Concentrated
approval pairs holds the rule, and why a pair counted without the
second threshold would be an alert nobody can clear (REQ-49).

Four filters: who proposed it, who has a standing agreement on it, which issue,
and which component. An agreement later taken back does not match the approver
filter, because answering otherwise would make a withdrawal invisible to the one
report that exists to find it.

| Rule | Reason |
|---|---|
| Asked of the record, never of a flag | The condition is that no agreement stands from somebody other than the proposer, which is the same question the row's own answer is computed from. The test writes a self-approval straight to the table: the report has to answer correctly about a row the write path should have prevented, and one that trusted the write path would be reporting on itself |
| The product, the outcome and the state each take several answers | "Dismissed or deferred" and "waiting or sent back" are the questions somebody reading the record has, and one value cannot ask either; the parameter repeats and any of what is named matches. A product named that the reader may not see refuses the whole request rather than being dropped, because a report answering about two products when three were asked for reads as covering three |
| It says "this should be empty" only where every outcome asked for is a dismissal | Mixed with a deferral the answer holds legitimate rows, and saying otherwise over them would report a control as failed when it had not |
| What was asked for is printed with every value | A sheet headed "dismissed — not applicable" over rows that also hold deferrals is a sheet nobody can check against anything |
| The record narrows to one build, reached through the findings at each place | A decision names no build, deliberately — it is keyed on the product, the issue and the place, so that it carries across the releases that share the code. What a release sign-off asks is the other question, and it could not be asked at all. The build's own product has to be the one that made the judgment, because a place identity carries none |
| A build is a product, a stream and a variant together, or none of them | Named alone, a stream would narrow to a stream of some other product that happens to share the name — a report about somebody else's releases under this one's heading |
| The file carries every agreement with its dates, beside who agrees now | What somebody agreed to and then stopped agreeing to is what an audit is looking for, and the file carried neither it nor any date. The two are different questions and a column mixing them is the one answer an auditor must not be given |

## Dismissals and scan coverage

Dismissals are a reportable dataset in their own right. Answered two ways: the
findings list filters on outcome and on whether a rating was changed, and the
record screen lists every judgment with its reasoning, its approvals and the
dates. Which of the five reasons applied is on the row rather than a filter,
because it is what an auditor reads on the row they stopped at.

A dismissal is any of four outcomes, and anything counting or listing them
asks for all four:

| Outcome | The claim |
|---|---|
| Not applicable | The vulnerable code is not reachable |
| Wrong match | The scanner matched something that is not here |
| Will not fix | It is not worth fixing |
| Already fixed here | Whoever packages the component backported the fix |

What they have in common is that nothing was changed, which is why they are the
four that need a second person. Asked of one, a program that dismisses
everything as "will not fix" reads as a program that has argued nothing away.

Where a dismissal is listed, the place is named. A judgment covering forty
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

This is a report an operator uses, not the tool publishing. Nothing here
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
| A sheet that takes a period offers both ways of asking, and naming dates drops the rolling window | The two cannot travel together, so a control that let them would send a request the server refuses. What the sheet covers is written in its header either way, and every link out of it carries the same stretch |
| A report that is a list exports as CSV and JSON; a report that is figures prints | There is no stream behind an aggregate. Inventing one publishes a file nothing here computed |
| Every figure opens the list it counts, and that list exports | The traceable form of a number, and what somebody asking for "the numbers as a file" actually wants: a row nobody can trace back to a finding is a number in a spreadsheet |
| A link out of a report carries the period and the product the figure was computed with | The record reads its narrowing from the address rather than from the picker, so an entry that dropped the selection opened every product the reader can see from a page scoped to one — a different population under the same name, which is worse than no link |
| No PDF is generated | Printing is the browser's, and the stylesheet is the record's. Server-side rendering is deferred |
| What is about to go out of support is asked for, and comes back as its own list | The day a release crosses, the deadline comes off every open finding on it and that work leaves every overdue count at once, with nobody having decided anything. A warning and an exposure are two things: one is a date somebody can still act before. Asked for, because a second population appearing unasked changes what every figure on the report counts |
| The register is a page of the catalog's own | It is about one build, and had no screen — only a file, which an auditor had to download to read. So the catalog owns it rather than a build screen listing it, and it asks for a whole build the way the build-scoped entries do |
| An entry may point at a screen rather than owning a page | Eight do: release readiness, upgrade plan status, carried patches, holder workload, embargo and disclosure, the exception report, release comparison, and administrative changes. Each is a report about the thing you are standing on, so it stays where it is and the catalog carries it with the scope already applied |
| An entry that points at a build's screen asks for a whole build | Five screens exist for one build and no other. An entry into one on a partial selection would open on a scope that means nothing, so it says which picker to touch instead |
| The question with no name is asked on the findings list, not on a panel of the catalog's own | A panel offering the findings list's filter panel and the findings list's query is that screen at a second address, and the copy is the poorer one: it passed an empty tag list, so it offered fewer filters than the screen it copied. The catalog points at the list instead |
| The catalog offers only the files reachable nowhere else | Two are: what is running out of time, and the VEX document. Every other file is offered on the screen that answers for it and carries that screen's filters, so a second unfiltered link beside it is a worse copy of the same answer |

### Pages of the catalog's own

Eight, in the order the catalog lists them. Deadline compliance and the
disposition register have sections above.

| Page | What it answers |
|---|---|
| Program overview | What is being fixed against what is appearing, what is aging and whether anybody has looked at it, how long a claim waits to be decided and then agreed to, what keeps being put off, and what has been argued away. Its window is seven, thirty or ninety days or a period between two dates, and the printed header names which |
| Scan coverage | The whole estate, longest silent first: how many builds are being scanned, how many have gone quiet, and how many were declared and never filed against. Every other number rests on it. A build out of support is listed, marked, and never counted as quiet — silence there is expected, and a coverage report filling with those stops catching the product that dropped out. The front page names the three quietest and the inventories screen answers for one product; this answers for the estate |
| Releases out of support | The releases whose date has passed, and — asked for — the ones about to, how long ago or how long there is left, and how many issues are still open against each, ordered by what is open. Past end-of-life the deadline is removed from every open finding, so none of that pile is overdue, none is due soon, and none of it reaches a figure built on either. That is correct — no work will land there — and it is what makes asking the only way to see it. A date inherited from the product says so: a release following a date and one that stated the same date are different, and only the first moves when the product changes its mind |
| Backlog over time | Whether the backlog is growing, and what kind of thing is making it grow: what arrived, what was answered and what stood open at the end of each step, each split by severity. Only the open count was split, and ten arriving against ten answered is a team keeping pace where both are low and a team losing ground where what arrives is critical and what leaves is not — which a line of totals draws as flat. A resolved issue is counted at the severity it held while it was open, because the step it left in no longer has one |
| Rubber-stamp | How much a second pair of eyes actually did. Its sections are below |
| The destination of the effort | The subjects of the judgments in a period, most argued first, with what came out of them. It has a section of its own above |
| Deadline compliance | Whether work met the dates policy set for it, by severity |
| Disposition register | Every vulnerability known in one build and what became of it |
| Advisories issued | What has gone out about flaws in our own product over a period, and what went out twice. Answered per flaw elsewhere, which is the shape somebody about to publish a revision needs; a period asks something else. A row carries the digest the document hashed to when it went out, which is what makes comparing it against what would be generated now possible |

An issuance carries no visibility of its own, so a row of the last of those is
narrowed by the flaw it was written about. Reading one as public because it has
no visibility column would announce an undisclosed flaw in the report about
announcements, and the row names the identifier.

The exception report is the record with its filters set — dismissals no second
person has a standing agreement on. REQ-53 names it as the report that should
come back empty, and the record's own empty state is already written as that
answer rather than as an absence.

The standing corrections are the record with its other filters set: the wrong
matches that apply now. Every other judgment lapses when the code moves, so
each comes back round to somebody; a correction does not, and the only way to
read the set is to ask for it. `DESIGN-triage.md` § Corrections holds what one
is.

Applying now is not the same question as having been approved. A judgment is
approved and lapses afterwards when the code moves out from under it, so the
state filter answers what was once agreed to.

### Rubber-stamp

It is not a list of people who broke the rule, because the rule cannot be
broken: approving refuses the proposer, refuses the author of the revision being
agreed to, and is conditional on that revision still being current. What it
reports is where the rule did not apply and where it applied in form only.

| Section | What it says |
|---|---|
| Risk standing on one person | Split in two, because the halves read oppositely. A dismissal here is a control that did not hold. A short deferral, or an upgrade promised inside the deadline the work already had, is the exception working — deliberate, so that gating every routine act does not put ordinary triage through a queue nobody then reads. One at a time it is triage; the pattern across a program is what nothing else shows |
| Proposer and approver pairs | Every pair, with the share of everything agreed to that ran between them. The share is the signal rather than the count: fifty of fifty-two and fifty of nine hundred are the same number and not the same situation |
| Agreements given in bulk | An approver works at the unit the proposer acted at, so agreeing to a batch as one act is the control working. A batch of two hundred is still not a batch of two |
| Agreed to before, covering more now | What was consented to, recorded at the moment of consent, against what the same claim reaches today. A claim reaches by matching, so a build appearing later is covered with nobody acting and nobody having agreed to the larger number |
| Standing from somebody who could not give it now | Correct behavior — an approval is a fact about a moment, and losing a role does not un-say what somebody said — and the first list asked for after a reorganization |

Everything is dated by when a claim was proposed rather than when it was agreed
to, for the reason the record is: a judgment belongs to when it was argued, and
dating it by its agreement moves it out of that period whenever an approval
comes late.

Every section is bounded and says when it reached the bound. Unbounded, a
deployment that has been triaging for a while answers one row per approved
claim in force, and the last section asks three more questions about each of
them one at a time — thirty thousand sequential statements in one request on
ten thousand claims, with nothing checking whether the caller is still there.
What each claim covers now is one statement for the page. A capped section
reading as complete misleads the one reader this report is for, so it says it
was capped.

## Fix-bundle page cost

Measured rather than asserted. It runs at 2.2 s on a real deployment, and "the
design says it should be fine" is a sentence with a word doing too much work in
it.

One build, 204,000 open findings, 136,000 of them naming a version that fixes
them, folding to 700 bumps — the same two-thirds-fixable ratio a real switch
image has, at the same order of open rows.

| | Fix bundles | The findings list, over the same rows |
|---|--:|--:|
| SQLite | 1.28 s | 0.19 s |
| PostgreSQL | 1.29 s | 0.43 s |
| MariaDB | 1.49 s | 0.52 s |
| MySQL | 1.56 s | 0.48 s |

The findings list groups those rows into 6,000 groups off an index that covers
everything it reads. The bundle query groups the same rows into 700 and takes
three to eight times as long, because two of the columns it reads are not in
any index it can use: the version that fixes a finding, and the fold key, which
is on the component rather than on the finding.

Nothing is built on that yet. Grouping on the component instead of the fold
saves six percent, so the fold is not where the time goes, and the remaining
candidates are a stored fold key on the finding and an index that covers the
fix version. The first is a derived value stored for speed, which has to be
asked for rather than added while building something else.

The measurement is `make measure`, and it runs on every engine.

## Exports

Any list that can be read can be exported, as CSV or JSON. What exports: the
findings list, the cross-product findings list, the record of judgments, the
review queue, the by-component view, what is running out of time, scan coverage,
what is out of support, a comparison of two builds, the fix bundles, the
upgrades one build is waiting on, what keeps being put off, the backlog over
time, what has been changed administratively, and the disposition register,
which is the one an auditor asks for first.

The subject travels through the stream. An export is the easiest place to
build the list first and narrow it afterwards, so it is the same query with the
same subject, written out as it goes and paged as it streams at the page the
screen reads. No complete list ever exists to be filtered afterwards. A failure
part-way writes a line saying the file is incomplete, because a file that simply
stops is one somebody reads as whole.

| Rule | Reason |
|---|---|
| Every file says what it is and the moment it was taken | Two files in somebody's downloads six months later are two spreadsheets of rows. Written where the file is written rather than asked of each list, because a fact every file must carry is one no file can be written without |
| A file states what narrowed or computed it, one label and value per fact | A spreadsheet opened six months later has nothing else to say that everything below medium was never in it (REQ-30), what threshold a true/false column was measured against, or which two builds a comparison compares. A fact with nothing to say is left out rather than stated empty |
| What narrowed it is the request's own query, not a description of the filter | A description assembled field by field is a list somebody keeps in step with the filters, and the one it misses is the one that makes a file read as complete about rows it left out. What was asked for also reproduces the file |
| The register states no line and says which build it is | It applies no line, and a file claiming to have left things out reads as complete about what remains |
| Every CSV record is the header's width, statements and markers included | CSV has no comment convention: the `#` opening those two is a data character, and a narrow record makes the document one a conformant reader refuses. Every test here had the field-count check turned off, which is the check that would have said so |
| One document uses one key convention | The stated fact's key was written with underscores and every column name kept the spaces it is read with on paper, so the same file named its fields two ways |
| A column of numbers says nothing where there is no number | An unscored finding written as a zero sorted with the genuinely 0.0-rated ones at the bottom of a release meeting's file, and every filter asking for a score below anything took it |
| A refusal is answered before the first byte | A stream's status is gone by the time the store can refuse, so a refusal arriving there could only be said in the file — which said the export stopped early, with a 200 in front of it |
| The cross-product list states no single line | Each product applies its own |
| The findings list offers its file whether or not a product is picked | The two lists are two endpoints and the filters mean the same on both, so offering the control on one and not the other left one narrowing reachable as a file and the other not, for no reason a reader could see. The spanning file drops the filters a single build resolves, the same narrowing the screen's own read applies |
| A list and its file are built from one function, not two | Three exports rendered their rows again beside the handler, which is the same drift a second parameter list is: the screen gains a column and the file quietly does not |
| Each takes the same filters as its screen, from the same struct | A second parameter list drifts from the first, and a filter the file does not declare is refused rather than applied |
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
| The session lifetime | Also the window in which somebody who moved out of a team still holds what the team gave them, through a browser and through a personal token alike |
| The token ceiling | The longest a personal token may last |
| The limit on one action | How many findings a single judgment may cover |
| The triage floor | The severity below which findings are recorded and counted but kept off the working list. A product may state its own |
| Quiet after | How long a build may go without a scan before it is reported as quiet |
| Scan every | How often everything tracked is scanned again |
| Upstream currency | Whether to ask public package indexes for the newest version. Off unless turned on, and what goes out is a component's name. Names this deployment calls its own are held back, and the report of what has no upstream answer says which |
| The two attachment bounds | The largest single file, and the deployment total |
| Absent after | How long somebody may go without signing in before work they hold is raised |
| The three disclosure periods | How long a finding stays undisclosed, how much that date may move in total before a second person agrees, and the lead time before it |
| The four staleness periods | A claim waiting on a second person, one sent back, a deferral ending, and work in a team's queue |

The shipped numbers are a starting point rather than a recommendation. A deadline
nobody agreed to produces an estate that is permanently late.

A value nothing can read is refused, not stored. Every reader falls back to
the shipped default where a setting is unset or unparseable, so a stored value
nobody can read is a policy that quietly stopped applying. The value is checked
before it is written, against the kind the name is: a duration for the windows,
threshold and lifetimes; a whole number above zero for the limit on one action; a
severity word for the triage floor; on or off for upstream currency.

| Rule | Reason |
|---|---|
| Zero and negative are refused | Every reader treats them as unset, so storing one produces a setting that looks set and does nothing |
| Only known names may be set | Storing an unknown one creates a setting nothing reads |
| A triage line that is not one of the severity words reads as no line | The word admits nothing and narrows nothing, so a line outside the vocabulary was displayed everywhere as in force while every query let everything through. A line that cannot be enforced says so |
| A failure to *read* a setting is not "unset" | Every caller has a default, so a database that could not answer would silently swap the deployment's configuration for the shipped one, including the threshold deciding which deferrals need a second person. That is reported |
| Everything offered is read | The session lifetime was offered here while sign-in took its value from the environment and never looked. The order is the administrator's setting, then what the process was started with, then the built-in default |

## Limits

- An export answers the question the list beside it answers, embedding the same
  filters rather than re-declaring them. A filter the list applied and the
  export dropped produced eight rows on screen and seven thousand in the file,
  under the same heading.
- A cell a spreadsheet reads as a formula is neutralized. Component names
  arrive in somebody else's inventory, and these files are opened by the people
  holding the most access in the deployment.
- The disclosure periods were read and wired into behavior with no way to set
  them, while two other documents described each as a setting.
