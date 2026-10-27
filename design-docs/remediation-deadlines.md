# Deadlines

How long a finding has, the moment its clock starts, and the reason one
carries none.

Satisfies REQ-15, REQ-33.

What a deadline feeds, the escalation view, time remaining and the compliance
rate, is in `design-docs/analytics.md`.

## Contents

- [Deadline policy](#deadline-policy)
- [Clock start](#clock-start)
- [Exploitation dates](#exploitation-dates)
- [Findings with no deadline](#findings-with-no-deadline)
- [Exploited refusals](#exploited-refusals)
- [Recounts and rewrites](#recounts-and-rewrites)
- [Recorded flaws](#recorded-flaws)
- [Limits](#limits)

## Deadline policy

| Rule | Reason |
|---|---|
| No per-item due date: a deadline comes from how urgent the finding is (REQ-33) | |
| Moving one is a deferral, which carries a reason and an approval threshold, and the deferral date becomes the effective target | |
| Deferred items are reported apart from plainly overdue ones | |
| A plan names where a fix lands and moves no deadline | Only a deferral moves one |
| The deadline is stored | Deriving it costs a pass over every open finding per urgency band |
| It is rewritten whenever the answer moves, not only when the ranking does | A fix appearing upstream starts a clock that was not running, and a fix withdrawn stops one |
| The reason a finding has none is derived, where the minimum severity is applied | The two cannot disagree |

## Clock start

The clock starts at the latest of three moments, never the earliest and never
now: when the finding was first seen here, when exploitation was learned, and
when the fix became available. All three have passed, so a recount reaches the
same answer every time and a deadline never restarts nightly.

| Case | Counted from | Reason |
|---|---|---|
| The fix existed when the finding opened | The sighting | The ordinary case; the response time is from when it was learned |
| The flaw was seen before upstream released anything | The fix | From the sighting, the deadline runs against a version that did not exist, the common case for an inventory of distribution packages |
| The issue became exploited later | The learning | From the opening, an issue exploited after six months lands three days before anybody knew |

| Rule | Reason |
|---|---|
| A fix dated later than the moment it is weighed at has not arrived | A scan weighs it at the run's start, a rewrite at the edit |
| A recount reasons at the store's clock, one moment per recount | The clock every other write reads, so a fix date weighs the same in a recount and in the scan beside it |
| A finding may be overdue the moment it opens | There is no floor for a slow pipeline |

## Exploitation dates

Exploitation is learned on the day the known-exploited catalog added the issue,
bounded by the moment of the scan, as a fix's date is. The days before a scan
sees a listing are the pipeline's lag and do not extend the window; a finding
opened after the listing counts from its opening, because the latest moment
wins.

| Rule | Reason |
|---|---|
| The listing day is read from the scanner's output: the catalog entries on the matched record and on every related record, the earliest readable day, as midnight UTC | |
| An entry whose day cannot be read still marks the issue exploited, from no day | |
| A scan with no listing day learns exploitation at its own start | It is the moment every issue a database held before the day was read counts from |
| The issue keeps the earliest day any report states, stored on the issue and only moved earlier, by a statement of its own | Two reports stating different days leave the earlier, whichever arrives first |
| A listing day filled or moved earlier re-clocks the issue: every open exploited finding counting from a later moment moves onto the day, in every build, and its deadline is worked out again | Once per issue: after it nothing counts from later |
| A severity word filled in re-clocks the issue in every product holding it: each open finding's deadline is worked out again from when it opened, by the product's rating in force with the new word as its fallback (`design-docs/findings-issues.md` § Report merging) | |

## Findings with no deadline

A finding with no deadline states which reason applies.

| Reason | Reported as | Precedence |
|---|---|---|
| A flaw recorded here that nobody has rated | `not-rated` | The narrowest: about what this finding lacks |
| Below its product's minimum severity | `below-minimum-severity` | The narrowest statement about how it is rated |
| Upstream has released no fix, or declined to on an issue nobody is exploiting | `nothing-to-take` | Above the release, being about this finding. A fix that will never arrive is as absent as one not yet arrived |
| Its release is a tag, so it cannot change | `out-of-support` | Above end-of-life: a supported tag is as unfixable as a retired one |
| Its release is past end-of-life (REQ-15) | `out-of-support` | |

| Rule | Reason |
|---|---|
| Five reasons share four words: a tag reports `out-of-support` | A supported tag has no deadline for a more fundamental reason than a retired one. A word of its own is added when somebody needs to tell them apart |
| There is no other reason | Everything else gets a deadline at ingest, and a blank reads as missing data on the screen for noticing what runs out |
| A deadline nobody can meet is not set | With nothing released there is no version to take, and the only act stopping the clock is recording a decision, the act the deadline asks for. An overdue list of rows no upgrade answers is one people stop reading. On the demo's two SONiC images, seeded 2026-09-23, 95,497 of 335,491 open findings had no fix released (28.5%) and 14,196 more were an upstream refusal (4.2%) |
| A tag carries no deadline | It was built once and is what somebody received, so no work lands in it. Without this rule all 26 open findings on the demo's one tag carried an unmeetable deadline, and tags accumulate where branches do not |
| A scanner that did not answer leaves the fix state unstated, and an unstated fix state stays on the clock | Silence read as "no fix exists" is a claim about the world from a gap in a report, and loses a deadline somebody could have met |
| A finding with no deadline is in no figure built on one: nothing overdue, due soon, or in the compliance rate | Three reasons are seen elsewhere: the line a list states over what it hides, a tag's findings at the release, and what upstream has done as a findings column and filter. Releases out of support are a report of their own (`design-docs/analytics.md`) |

## Exploited refusals

An upstream refusal of an exploited issue keeps its deadline. Exploited is
either signal: the feed's, or a record that this product was attacked.

| Rule | Reason |
|---|---|
| The refusal keeps the clock | It will never be reversed, so what remains is work only this deployment can do, patching, replacing, or recording what stands in the way, and on an issue somebody uses that work has a date |
| A missing fix takes no such exception | One may arrive, and a deadline against it could only be met by waiting |

| Writer | Where the exception is asked |
|---|---|
| A scan opening a finding, or answering one already open | The one deadline rule, with either exploitation signal |
| A scan learning exploitation, for every other build of the issue | Only a missing fix loses the clock just given |
| A scan moving the listing day earlier, for every build of the issue | The one deadline rule, over findings already carrying a deadline |
| A record of this product being attacked, set or cleared | The recount, with either signal |
| An edited window | The sweep removing clocks passes over an exploited refusal; the sweep taking clocks off what is below the minimum severity passes over either signal |

## Recounts and rewrites

One rule governs every writer. A scan counts it per finding; an edited window
rewrites every open deadline as three passes, one per moment, each over the rows
for which that moment is the latest.

| Rule | Reason |
|---|---|
| The rewrite writes a deadline only where one belongs: a release that moves and is in support, a band the minimum severity admits or an issue this product was attacked through, and a fix to take | |
| A rewrite stopped part way, by an error or a shutdown, leaves every row it reached right and every other as it was | |
| The sweeps after it take the clock off what was written before a release went out of support, a minimum severity moved, or upstream answered | |
| A finding with no deadline keeps none when re-clocked | A tag, a release past end-of-life and a missing fix are off the clock whatever the moment. A rating moving, a word filled in, an incident, and an issue becoming exploited each re-clock only what sits on a release that moves and is in support |

## Recorded flaws

A flaw recorded in our own product has windows of its own, and its clock starts
when it is first given a severity (REQ-33).

| Rule | Reason |
|---|---|
| The windows are the product's own: shipped at 7 days exploited, 30 critical, 90 high, 180 medium and 365 low, against 3, 7, 30, 90 and 180 for a scanned finding | The fix has to be written, never taken from upstream. Both sets are settings, and changing either rewrites every open deadline |
| A flaw recorded with a severity starts at the recording; one recorded without carries no deadline until a rating is first put in force for it in that product | |
| The start is stored on the finding | A rating withdrawn and made again moves the window and keeps the start; restarted, a flaw near its date gets a fresh window by re-rating, a deferral nobody agreed to |
| Exploitation learned later and a fix arriving move it as they move a scanned finding | |
| A recorded flaw is recounted row by row, never in bands | Recorded flaws are few, one row per occurrence in each build |

## Limits

| Rule | Reason |
|---|---|
| Counting from the latest moment lowers overdue counts against counting from the first sighting | It is a correction: a two-year-old issue learned today has its response time from today, and that it was not learned sooner is a question about scanning coverage |
| Findings with no deadline are absent from every deadline figure | Each reason is visible elsewhere, as § Findings with no deadline lists |
