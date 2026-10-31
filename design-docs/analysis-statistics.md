# Security testing statistics

How code findings are counted over time: the Security testing statistics
consumer, the trend of code findings, its markers, the count of code findings
no longer detected, who reads them, the file, and the page drawing them.

Satisfies REQ-17, REQ-42, REQ-43, REQ-50, REQ-54, REQ-74, REQ-87.

## Contents

- [The consumer](#the-consumer)
- [Code findings over time](#code-findings-over-time)
- [Analyzer markers](#analyzer-markers)
- [No longer detected](#no-longer-detected)
- [Narrowing](#narrowing)
- [Access](#access)
- [The trend file](#the-trend-file)
- [The page](#the-page)
- [Limits](#limits)

## The consumer

Security testing statistics is the consumer every security testing figure over
time reads (`design-docs/kinds.md` § Consumers). It names the analysis kind,
and another testing method's kinds join it by inclusion.

| Rule | Reason |
|---|---|
| Security testing results are counted per testing method and never added to dependency vulnerability counts (REQ-87) | A rule at a place and an advisory at a component are different units, and one total would misstate both |
| Statistics names the vulnerability and entered kinds alone | A code finding in the backlog trend reads as a vulnerability |
| No consumer counting figures spans the two families: Statistics names dependency kinds alone, Security testing statistics code kinds alone; a test holds both | A shared consumer is how one total forms |
| Every trend of security testing work is this consumer's, a component's included | One grant reads every chart of the family |
| Current standing (counts by series and state, a component's counts, the tree's) stays Code findings' | Those counts are the queue's length, and the queue is Code findings' read |

## Code findings over time

```
GET /v1/products/{product}/code-finding-trend?weeks=12
```

| Part | Holds |
|---|---|
| A point per week | Its last day; the code findings not fixed at its end; those opened and fixed in the week |
| Not fixed by tier | Memory safety, input, resource, other: the tier of the rule's weaknesses (`design-docs/analysis-queue.md` § Weakness families), every tier named, zero included |
| Not fixed by series | Each series with a code finding counted anywhere in the window, zero in the weeks it has none |
| Not fixed by method | Every testing method, zero included |
| Markers | § Analyzer markers |
| No longer detected | § No longer detected |

| Rule | Reason |
|---|---|
| Not fixed runs from a code finding's opening until a person closes it as fixed | A decision answers a code finding and closes nothing; absence closes nothing |
| Opened and fixed are the difference between one week's set and the one before, so the three numbers agree; the first week has no difference | |
| Counted by occurrence, once however many builds in the scope hold it, and not fixed while any of them holds it unfixed (REQ-17) | A code finding carried to the next build is one piece of work |
| Plotted on when a run was applied, the time a code finding opened, as the dependency trend is | A built-time axis would differ from every other chart |
| Weeks end at midnight UTC, the last at the coming one; a week holds its start and not its end | A marker is dated by its UTC day, so it falls in the week its runs moved the line |
| A code finding open only in releases past their end of life counts, as the backlog trend counts a vulnerability | End of life is a state of today; applied to past weeks it rewrites them |
| On calendar weeks, the axis REQ-54 gives a branch; release over release for tags is Code findings by release (`design-docs/analysis-figures.md` § Code findings by release) | |
| The tier is the rule's as rated now | No rating history is stored, as for the vulnerability trend |
| No table of presence spans; every week is worked out from opening and closing times (REQ-74) | A return after absence is mostly analyzer nondeterminism, and absence closes nothing |
| Each occurrence's weeks are one bit each, read in one statement and counted in the application | A statement per week is a hundred round trips; one statement takes 46 ms on PostgreSQL and 257 ms on MySQL 8.4 for 104 weeks of 4,000 code findings on a 16,000-component build (`design-docs/analysis-measurements.md` § Trend of code findings) |
| The weeks are 1 to 104, twelve unless named | Two years is the backlog's widest window |

## Analyzer markers

A marker says a series' analyzer changed on one day, or a run's absences proved
nothing. A move in the line beside one comes from the analyzer.

| Change | Said where a run, against the run applied before it on its build |
|---|---|
| `tool` | Names another tool; from and to are the two names |
| `tool-version` | Names the same tool at another version; from and to are the two versions |
| `rules` | Has another rule set; from and to are the two rule counts |
| `not-comparable` | Is not comparable for another reason: exit status, incomplete, a failure of its own, no coverage, units short; the reason is named |

| Rule | Reason |
|---|---|
| Read from the runs not comparable, applied in the window | A tool, version or rule change already makes a run not comparable (`design-docs/analysis.md` § Run parameters) |
| The run before is the series' newest applied run on the build built before it | It is the run it was compared with |
| A tool change and a rule change on one run are two markers; a failed run on a new version is two | A run records its first reason alone |
| One marker per day, series, change and the values it names, with how many builds it was made on; a series run twice on one build counts it once | A nightly series over forty builds is one change |
| A first run has no run before it and marks nothing unless it is not comparable for its own reason | |
| A tool, version or rule count a run did not state is left out of the answer, and the page and the file say "not stated" | A blank reads as a value lost |

## No longer detected

Today's count of code findings in the scope a comparable run did not see: the
queue's count of that state, so the figure is the length of the list it opens.

| Rule | Reason |
|---|---|
| Today only, with no weekly line | A return clears an absence, and 5 of 28 hand-checked absences returned within two builds |
| Counted inside not fixed | Absence is no proof of a fix |

## Narrowing

The trend takes the queue's narrowing through the same statement fragment, so
a figure narrowed alike counts the list it opens
(`design-docs/analysis-queue.md` § Code finding queue).

| Narrowing | Detail |
|---|---|
| Branch, variant | Builds of that branch or variant; markers too |
| Series | One series, its name matched ignoring capitals; markers too |
| Method | One testing method; markers too |
| Component, version | Code findings on the source package or binary named |
| Beneath | At or under a component on one build, which takes branch and variant; a replaced component counts at the build's live one of its name, as in the queue; markers narrow to that build by its branch and variant |

## Access

| Rule | Reason |
|---|---|
| Only `security-testing-read` on the product reads the trend or its file; anybody else reading the product is refused 403, naming no count or series | Every figure is at security testing visibility |
| A product the reader cannot see is 404 | |
| The check runs before any name in the scope is resolved, so an unknown component is refused as a known one is | A refusal differing by name is a directory (REQ-42) |
| The check is in the data layer, and the counts carry the subject: a code finding counts where its visibility is read or its flaw's reach includes the reader (REQ-43) | A disclosed code finding counts for a reader of disclosed work beside security testing material, and not for a reader of security testing material alone |
| A role, visibility and endpoint matrix holds the trend and its file | |

## The trend file

```
GET /v1/products/{product}/code-finding-trend.csv
GET /v1/products/{product}/code-finding-trend.json
```

| Rule | Reason |
|---|---|
| The page's own read, narrowing and access, as a file (REQ-50) | A list and its file are one read |
| CSV is long-format: week ending, split, part, not fixed, opened, fixed, and the week's changes in words; a row for the whole, then one per tier, method and series | A spreadsheet pivots one table |
| JSON is the trend's own answer | |

## The page

Code findings over time is a page of the analytics catalog, in its Security
testing group (`design-docs/analytics-catalog.md` § Catalog groups), reached
from the rail, the Security testing screen, a component's trend panel and home's
This week figure (`design-docs/interface-security-testing.md` § Security
testing, `design-docs/interface-component.md` § Security testing on the
component, `design-docs/interface-shell.md` § Security testing figures).

| Part | Holds |
|---|---|
| Controls | The window (4, 13, 26, 52 or 104 weeks, thirteen unless picked) and the split (tier, series, method), both in the address; CSV and JSON with the narrowing on screen |
| Pace chart | Not fixed, new and fixed per week, with a dashed mark at each week holding a marker, said on hover |
| Split chart | Not fixed, stacked by the split picked |
| Today's count | No longer detected, opening the queue in that state with the same narrowing |
| Week by week | Each week's three numbers, its split, and its markers in words |

| Rule | Reason |
|---|---|
| Needs a product | A series is one product's |
| A branch and variant in the address stand over the picker's; one named empty is every one | A link from a queue opens on the builds it lists |
| Beneath with no build picked says it needs one and offers the picker, asking nothing | At or under a component is read on one build |
| A reader not reading security testing material in the product is shown "Nothing to list." and the code family's line, and nothing is asked (`design-docs/interface.md` § Families a reader holds) | A chart of zeros reads as clean code |
| The page states that the tier is as rated now, and that only fixing takes a code finding off the line | |
| Tiers take the severity ladder's tokens; series and methods take the chart tokens in turn | Tiers are a ranking |
| The page names no testing method that is not built | AI review is not supported |

## Limits

| Limit | Detail |
|---|---|
| A tier reads as rated now | A rule rated anew moves every week it counted in |
| A version change is unseen where a tool states no version at both ends | Its runs read as one version |
