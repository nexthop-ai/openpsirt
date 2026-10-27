# Deadlines

How long a finding has, when its clock starts, and the reason one carries none.

Satisfies REQ-15, REQ-33.

The escalation view, time remaining and the compliance rate are in
`design-docs/analytics.md`.

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
| A deadline comes from the finding's urgency, never a per-item due date (REQ-33) | |
| A person moves one only by a deferral, with a reason and an approval threshold; its date becomes the target | |
| Deferred items are reported apart from plainly overdue ones | |
| A plan names where a fix lands and moves no deadline | |
| The deadline is stored, and rewritten whenever the answer moves, not only the ranking | Deriving it costs a pass over every open finding per urgency band. A fix appearing upstream starts a clock; one withdrawn stops it |
| The reason a finding has none is derived where the minimum severity is applied | The two cannot disagree |

## Clock start

The clock starts at the latest of three moments: first seen here, exploitation
learned, and fix available. All three have passed, so a recount reaches the same
answer and a deadline never restarts nightly.

| Case | Counted from | Reason |
|---|---|---|
| The fix existed when the finding opened | The sighting | The ordinary case |
| The flaw was seen before upstream released anything | The fix | From the sighting, the deadline runs against a version that did not exist, common for distribution packages |
| The issue became exploited later | The learning | From the opening, an issue exploited after six months lands three days before anybody knew |

| Rule | Reason |
|---|---|
| A fix dated later than the moment it is weighed at has not arrived; a scan weighs at the run's start, a rewrite at the edit | |
| A recount reads the store's clock, once per recount | A fix date weighs the same in a recount and in the scan beside it |
| A finding may be overdue the moment it opens | There is no floor for a slow pipeline |

## Exploitation dates

Exploitation is learned on the day the known-exploited catalog added the issue,
bounded by the scan's moment as a fix date is. The pipeline's lag before a scan
sees a listing does not extend the window.

| Rule | Reason |
|---|---|
| The listing day is the earliest readable day in the catalog entries on the matched record and every related record, as midnight UTC | |
| An entry with no readable day still marks the issue exploited, from no day | |
| A scan with no listing day learns exploitation at its own start | |
| The issue keeps the earliest day any report states, moved only earlier | Two reports leave the earlier, whichever arrives first |
| A listing day filled or moved earlier moves every open exploited finding counting from later onto the day, in every build, and works its deadline out again | Once per issue |
| A severity word filled in re-clocks the issue in every product holding it, by the product's rating in force with the new word as fallback (`design-docs/findings-issues.md` § Report merging) | |

## Findings with no deadline

| Reason | Reported as | Precedence |
|---|---|---|
| A flaw recorded here that nobody has rated | `not-rated` | Narrowest: what the finding lacks |
| Below its product's minimum severity | `below-minimum-severity` | How the finding is rated |
| Upstream released no fix, or declined to on an issue nobody exploits | `nothing-to-take` | About the finding, above the release |
| Its release is a tag | `out-of-support` | Above end-of-life: a supported tag is as unfixable as a retired one |
| Its release is past end-of-life (REQ-15) | `out-of-support` | |

| Rule | Reason |
|---|---|
| A tag reports `out-of-support`, so five reasons share four words | A word of its own is added when somebody needs them apart |
| There is no other reason | Everything else gets a deadline at ingest |
| A deadline nobody can meet is not set | The only act stopping it is recording a decision, which the deadline asks for. On the demo's two SONiC images, seeded 2026-09-23, 95,497 of 335,491 open findings had no fix released (28.5%) and 14,196 more were an upstream refusal (4.2%) |
| A tag carries no deadline | No work lands in it. All 26 open findings on the demo's one tag carried an unmeetable deadline before this rule, and tags accumulate |
| An unstated fix state stays on the clock | A scanner's silence is not upstream saying no |

## Exploited refusals

An upstream refusal of an exploited issue keeps its deadline. Exploited is
either signal: the feed's, or a record that this product was attacked.

| Rule | Reason |
|---|---|
| The refusal keeps the clock | The remaining work, patching, replacing, or recording what stands in the way, is this deployment's alone and has a date |
| A missing fix takes no exception | One may arrive, so its deadline is met only by waiting |

| Writer | Where the exception is asked |
|---|---|
| A scan opening a finding, or answering one already open | The deadline rule, with either signal |
| A scan learning exploitation, for every other build of the issue | Only a missing fix loses the clock just given |
| A scan moving the listing day earlier, for every build | The deadline rule, over findings already carrying one |
| A record of this product being attacked, set or cleared | The recount, with either signal |
| An edited window | The sweep removing clocks passes over an exploited refusal; the sweep for below the minimum severity passes over either signal |

## Recounts and rewrites

A scan counts the rule per finding; an edited window rewrites every open
deadline in three passes, one per moment, each over the rows where that moment
is latest.

| Rule | Reason |
|---|---|
| A rewrite writes a deadline only for a release that moves and is in support, a band the minimum severity admits or an issue this product was attacked through, and a fix to take | |
| A rewrite stopped part way leaves every row it reached right and the rest as they were | |
| Sweeps after it take the clock off what went out of support, fell below a moved minimum severity, or upstream answered | |
| Re-clocking keeps a finding with no deadline without one; a rating moving, a word filled in, an incident and exploitation each re-clock only releases that move and are in support | |

## Recorded flaws

A flaw recorded in our own product has windows of its own, and its clock starts
when it is first given a severity (REQ-33).

| Rule | Reason |
|---|---|
| Shipped at 7 days exploited, 30 critical, 90 high, 180 medium and 365 low, against 3, 7, 30, 90 and 180 for a scanned finding; both sets are settings, and changing either rewrites every open deadline | The fix has to be written, never taken from upstream |
| Recorded with a severity, the clock starts at recording; without, when a rating is first put in force in that product | |
| The start is stored on the finding | Restarted, re-rating would give a fresh window, a deferral nobody agreed to |
| Exploitation learned later and a fix arriving move it as for a scanned finding | |
| Recounted row by row, never in bands | Recorded flaws are few |

## Limits

| Rule | Reason |
|---|---|
| Counting from the latest moment lowers overdue counts | A two-year-old issue learned today responds from today; learning sooner is scanning coverage |
| A finding with no deadline is in no deadline figure: nothing overdue, due soon or in the compliance rate | Three reasons are seen elsewhere: below the minimum severity in the line a list states over what it hides, a tag's findings at the release, and nothing to take in the findings list's upstream column and filter. End-of-life has a report of its own (`design-docs/analytics-catalog.md`). Not-rated has no view of its own |
