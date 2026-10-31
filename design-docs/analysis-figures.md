# Security testing figures

The figures beside the trend that say how security testing work is going: time
to judge, time to fix, analyzer precision, analysis coverage, and code findings
by release, with who reads them, their files and their pages; and the figures
home reads across products.

Satisfies REQ-17, REQ-42, REQ-43, REQ-50, REQ-52, REQ-54, REQ-74, REQ-87.

## Contents

- [Shared rules](#shared-rules)
- [Time to judge](#time-to-judge)
- [Time to fix](#time-to-fix)
- [Analyzer precision](#analyzer-precision)
- [Analysis coverage](#analysis-coverage)
- [Code findings by release](#code-findings-by-release)
- [Access](#access)
- [Figures across products](#figures-across-products)
- [Figure files](#figure-files)
- [The pages](#the-pages)
- [Limits](#limits)

## Shared rules

Every figure reads the Security testing statistics consumer
(`design-docs/analysis-statistics.md` § The consumer) and takes the trend's
narrowing (`design-docs/analysis-statistics.md` § Narrowing), except where a
figure says otherwise.

| Rule | Reason |
|---|---|
| Counted per testing method, never beside a dependency figure (REQ-87) | A rule at a place and an advisory at a component are different units |
| Counted by occurrence, once however many builds in the scope hold it (REQ-17) | A code finding carried to the next build is one piece of work |
| A wait is a median and a 90th percentile by nearest rank, with the longest and how many it is over, for the whole and per tier | One slow tier hides inside the whole |
| Days are rounded to a tenth | |
| A window is the newest 1 to 104 weeks, thirteen unless named, ending at the coming midnight UTC | The trend's weeks |
| Waits are worked out in the application from stored times | Subtraction of times is spelled four ways across the engines |
| The tier is the rule's as rated now | No rating history is stored |
| No presence spans and no stored figure; each is worked out from opening, closing, decision and run times when asked (REQ-74) | Absence closes nothing, and a stored answer drifts |
| A figure counting no fixed code finding reads the queue's rows of open findings alone, kept by the conditions of its states | A state other than fixed has no closed finding to test for opening anew (`design-docs/analysis-queue.md` § Code finding queue) |
| Nothing names a testing method that is not built | AI review is not supported |

## Time to judge

```
GET /v1/products/{product}/code-finding-time-to-judge?weeks=13
```

How long a new code finding waits for a person.

| Part | Holds |
|---|---|
| Judged | The waits of the code findings first judged in the window: from opening to the first decision proposed at the occurrence, whatever it decided |
| Waiting | The queue now: open code findings with no decision proposed and none waiting for approval, by age (under a week, one to four weeks, one to three months, over three months), each split by tier |
| Oldest | When the oldest waiting code finding opened |
| No longer detected | Today's count of that state, which waits in no queue |

| Rule | Reason |
|---|---|
| The first proposal is the judgment, a dismissal included | Proposing is when a person looked; approval is a second person's step |
| The first proposal is the occurrence's in the product, read once per occurrence and issue | A decision is the occurrence's, so every build holding it reads the same one |
| A wait is from the occurrence's earliest opening in the scope; a proposal before it waited nothing | A decision outlives a closure, so a code finding opened anew may already be judged |
| A code finding withdrawn and decided again is judged once, at the first proposal | |
| Waiting rows are the queue's own, so the age buckets add up to the list they open | |
| Releases past their end of life are left out of waiting | Nobody works them |
| The first proposals are the decisions joined to the findings and grouped, never asked per finding | Asked per finding, PostgreSQL reads every finding of the product first (`design-docs/analysis-measurements.md` § Security testing figures) |

## Time to fix

```
GET /v1/products/{product}/code-finding-time-to-fix?weeks=13
```

How long until a code finding is fixed.

| Part | Holds |
|---|---|
| Fixed | The waits of the code findings fixed in the window: from the earliest opening in the scope to the last closure as fixed, once no build in the scope holds it open |
| Dismissed | How many closed as fixed in the window were answered as noise, and are left out |
| No longer detected | The waits of the code findings in that state now: from opening to the first run that did not see them |

| Rule | Reason |
|---|---|
| A code finding answered as noise, by a standing decision or a covering suppression rule, is left out of fixed | A dismissal is not a fix, and an analyzer change closing it says nothing of the work |
| Fixed is a person's closure; absence closes nothing | 5 of 28 hand-checked absences returned within two builds |
| No longer detected is timed apart, never counted as fixed | Absence is no proof |
| The closings in the window are read from the product's code findings alone | Read across the deployment, PostgreSQL took 5.94 s at 240,957 dependency closings (`design-docs/analysis-measurements.md` § Security testing figures) |

## Analyzer precision

```
GET /v1/products/{product}/code-finding-precision
```

Which analyzers and rules are noise. Each code finding is counted once, by
occurrence, at the first of these that holds:

| Order | Counted as | When |
|---|---|---|
| 1 | Dismissed | The standing decision dismisses it |
| 2 | Not security | The standing decision says it is not a security issue |
| 3 | Confirmed | Any other standing decision, or a flaw record |
| 4 | Fixed | Closed as fixed, with nothing open at it on any build in the scope |
| 5 | By rule | A suppression rule in force covers it |
| 6 | Unjudged | None of these |

| Part | Holds |
|---|---|
| By series | The six counts per series, how many were judged (every count but unjudged), and the noise share: dismissed, not security and by rule, of those judged |
| By rule | The same per analyzer rule and series, for rules with a code finding judged, noisiest first, then the most judged |
| Suppression rules | Every rule of the product with its state, approval and retirement times, the open code findings it names now, and what it covered when approved (`design-docs/analysis-triage.md` § Suppression rules) |

| Rule | Reason |
|---|---|
| A person's decision outranks a rule | It is the answer somebody gave about this code finding |
| A closure as fixed is judged and is no noise | Somebody changed the code |
| A noise share is absent where nothing was judged | Zero of zero reads as a precise analyzer |
| Suppression coverage is worked out from today's paths, and the page says so | No path history is stored |
| The figure takes no window | A rule's precision is everything said about it |

## Analysis coverage

```
GET /v1/products/{product}/analysis-coverage?weeks=13
```

What is analyzed, and what has gone quiet: one row per series and build in use.

| Part | Holds |
|---|---|
| Newest run | When the newest applied run arrived and was applied, why its absences prove nothing where they do not, and the units it said it was meant to analyze and did |
| Newest comparable run | When it arrived |
| Runs in the window | Applied, not comparable among them, and failed |
| Expected interval | The median of the newest ten gaps between applied runs on that build, the silence it allows, and how long the series has been silent |
| Quiet | Whether no comparable run arrived within the silence allowed |

| Rule | Reason |
|---|---|
| Each series is judged on its own build against its own interval, never one deployment-wide window; a quiet series is the stale analysis REQ-52 reports | A quarterly series is not quiet after a week |
| The interval and the silence allowed are the stopped-reporting alert's: three usual gaps, never under a day, once three runs were applied (`design-docs/notifications-alerts.md` § Analyzer alerts) | One rule for the interval, in one place |
| The silence is counted from the newest comparable run; never comparable, from the oldest of the runs read | Runs whose absences prove nothing leave the code as unwatched as runs that stopped |
| A build retired at any level is left out; a release past its end of life is listed, marked, and never quiet | Nobody analyzes a release out of support on purpose |
| A series whose every run failed is listed by its failed runs | A pipeline failing every night is the case to find |
| Quiet first, then the longest since the newest run, then never applied | |
| Narrowed by branch, variant, series and method; no component | A run covers a build, not a component |

## Code findings by release

```
GET /v1/products/{product}/code-findings-by-release?releases=12
```

Whether a release shipped fewer code findings than the one before (REQ-54).

| Part | Holds |
|---|---|
| A point per tag | Its name and when it went out: the released date where one is set, and when it was declared otherwise |
| Not fixed | The code findings on its builds nobody closed as fixed, whatever was decided, split by tier, every tier named |
| States | Open, dismissed (by a decision or a suppression rule), not security, and no longer detected, as the queue states them on its builds |

| Rule | Reason |
|---|---|
| Tags only, oldest first by when they went out, the newest 1 to 50, twelve unless named | Release over release is the axis tags have |
| A tag is a point once a run of a series in the scope was applied to one of its builds; a tag never analyzed is absent, and one analyzed with nothing is a point at zero | An absent point and a zero say different things |
| Counted now, as the queue answers it today | A tag is frozen; its code findings are answered as decisions stand |
| A code finding on two builds of a release in two states counts in both state counts and once in not fixed | The state counts open the queue's lists |
| Each state count opens the queue's list of that state on the tag, open included | The default queue leaves out releases past their end of life and what waits for approval |
| Drawn as bars in release order, never a line | A line between two releases draws a path nothing travelled |
| Narrowed by variant, series, method and component; no branch and no subtree | The release line is the branch axis; a subtree is one build's |

## Access

| Rule | Reason |
|---|---|
| Only `security-testing-read` on the product reads a figure or its file; anybody else reading the product is refused 403, naming no count, series or rule | Every figure is at security testing visibility |
| A product the reader cannot see is 404 | |
| The check runs before any component or series name is resolved, so an unknown one is refused as a known one is (REQ-42); a branch or variant, which every reader of the product sees, resolves first | A refusal differing by name is a directory |
| The check is repeated in the data layer, and every count carries the subject: a code finding counts where its visibility is read or its flaw's reach includes the reader (REQ-43) | A handler missing its check still leaks nothing |
| Series and runs carry the family's visibility alone | A series names no code finding |
| A role, visibility and endpoint matrix holds every figure and its files | |

## Figures across products

Home's Security testing figures with no product picked
(`design-docs/interface-shell.md` § Security testing figures) are one read
each, across products.

```
GET /v1/code-finding-counts
GET /v1/code-finding-trend?weeks=12
GET /v1/code-finding-time-to-judge?weeks=13
GET /v1/analysis-coverage?weeks=13
```

| Figure | Holds |
|---|---|
| Counts | The queue's counts with no rows: its length, each state, waiting for a second person, ruled, past end of life (`design-docs/analysis-queue.md` § Queue across products) |
| Trend | One product's trend, each week's counts summed; a series of one name in two products is one split; each marker names its product (`design-docs/analysis-statistics.md` § Code findings over time) |
| Time to judge | Every product's waits as one population, the queue's ages summed, the oldest of any product's queue |
| Analysis coverage | Every product's rows, each naming its product, in one order |

| Rule | Reason |
|---|---|
| The products are those in use where the reader holds `security-testing-read`: a retired product, a product read at another visibility and a product not seen contribute nothing | They are the products the session lists as read, so the head's count, the tiles and the trend cover one set (REQ-42) |
| A reader of security testing material in no product is answered with nothing counted | An empty set is an answer |
| A pipeline key is refused 403 | It sends scans and reads nothing |
| Each finding counts at its own product's visibilities, bound per product in the data layer, and each figure checks the reader on every product before reading (REQ-43) | A disclosed code finding counts where the reader reads disclosed work beside security testing material, and nowhere else |
| A decision, a suppression rule and an end of life are each worked out in the finding's own product | They belong to one product |
| Each count and list is the sum or merge of each product's own figure, row for row | One population split by product; series identity is a product's, so no occurrence is in two products |
| Counts are the queue's counts with no row built | Counts across two products took 919 ms on PostgreSQL, where one product's queue of one row took 6.95 s (`design-docs/analysis-measurements.md` § Figures across products) |
| A spread across products is worked out over every product's waits together | A median of medians is no median |
| Narrowed by series and method alone | A branch, a variant, a component and a subtree name part of one product |
| Each has a file at `.csv` and `.json`, in the columns of one product's; a coverage row and a marker name the product | REQ-50 |

## Figure files

```
GET /v1/products/{product}/code-finding-time-to-judge.{csv,json}
GET /v1/products/{product}/code-finding-time-to-fix.{csv,json}
GET /v1/products/{product}/code-finding-precision.{csv,json}
GET /v1/products/{product}/analysis-coverage.{csv,json}
GET /v1/products/{product}/code-findings-by-release.{csv,json}
```

| Rule | Reason |
|---|---|
| Each is its page's own read, narrowing and access, as a file (REQ-50) | A figure and its file are one read |
| CSV is long-format, one row per part the page draws, with what the row is in its first columns | A spreadsheet pivots one table |
| JSON is the figure's own answer | |

## The pages

Each figure is a page of the analytics catalog's Security testing group
(`design-docs/analytics-catalog.md` § Catalog groups), drawn as the trend page
is (`design-docs/analysis-statistics.md` § The page).

| Page | Draws | Reached from |
|---|---|---|
| Time to judge | The judged waits by tier, the queue by age and tier with its oldest, and today's no longer detected opening that list | The catalog; the Security testing screen, with its narrowing |
| Time to fix | The fixed waits by tier with the dismissals left out, and the no longer detected waits apart | The catalog |
| Analyzer precision | By series, the noisiest rules, and the suppression rules with what each covers | The catalog; Code findings by analyzer; Suppression rules |
| Analysis coverage | A row per series and build with its standing (quiet, not comparable, arriving, never applied, past end of life), newest run, interval, units, newest comparable run and window counts | The catalog; Code findings by analyzer; Last upload per build |
| Code findings by release | Bars of not fixed per release, and a table per release with its tiers and its state counts opening the queue on that tag | The catalog |

| Rule | Reason |
|---|---|
| Needs a product | A series is one product's |
| A reader not reading security testing material in the product is shown "Nothing to list." and the code family's line, and nothing is asked (`design-docs/interface.md` § Families a reader holds) | A figure of zeros reads as clean code |
| A branch and variant in the address stand over the picker's; beneath with no build picked asks for one | As on the trend page |
| A window, where the figure has one, is picked from 4, 13, 26, 52 or 104 weeks and kept in the address | |
| The Last upload per build link shows only to a reader of security testing material somewhere | Anybody else reaches nothing behind it |

## Limits

| Limit | Detail |
|---|---|
| A tier reads as rated now | A rule rated anew moves every wait it was counted in |
| Suppression coverage uses today's paths | A file moved since a rule's approval counts where it is now |
| The silence before the first comparable run is a lower bound | Only the newest ten applied runs are read |
| A release's not fixed is answered today | It is not what was open when the tag shipped |
