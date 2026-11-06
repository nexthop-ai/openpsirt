# Program figures

How a program is doing over time: trends, deadlines and compliance, remediation,
who holds what, where the effort went, and how long triage takes.

Satisfies REQ-33, REQ-35, REQ-53, REQ-54.

## Contents

- [Trends](#trends)
- [Subtree trends](#subtree-trends)
- [Burndown](#burndown)
- [Deadlines](#deadlines)
- [Deadline compliance](#deadline-compliance)
- [Remediation metrics](#remediation-metrics)
- [Holder workload](#holder-workload)
- [Effort by subject](#effort-by-subject)
- [Triage latency](#triage-latency)
- [Repeated deferrals](#repeated-deferrals)
- [Limits](#limits)

Every figure counts in the unit and period `design-docs/analytics.md` defines.

## Trends

Open at the end of each step, and four flows in it, each split by severity: an
open count that barely moves while its critical share rises is getting worse.
The unit is an issue at a component, the unit of `design-docs/analytics.md`
§ The counting unit, as Home's open figure counts: one issue in three packages
is three, each counted once however many products, builds and occurrences hold
it. A component is its name, at any version.

| Viewing | Axis | Reason |
|---|---|---|
| A branch | Calendar time, in daily or weekly steps | Scanned nightly (REQ-54); a team fixing dozens a day sees it by the day |
| Tagged releases | Release over release, oldest first, as bars | Frozen points; a line between them draws a path nothing traveled |

### Counting by identity

Each issue at a component is one identity (REQ-54), derived from content
(REQ-08), so one that leaves the open set and comes back is returned, and a
build's first scan is a baseline rather than new work.

| Series | An issue at a component counted in the step |
|---|---|
| Open | Open at the step's end: some finding of it in the selection opened at or before that moment and had not closed |
| New | Open at the step's end, open at no moment before in the selection, and not brought by a build's first scan |
| Returned | Open at the step's end, not at the end of the step before, and open at some moment before that in the selection, the window's start or earlier included; not returned after a gap |
| Returned after a gap | Returned, its last departure a removal by an upload that moved its build's inventory sharply; drawn as a mark, never a bar |
| Corrected | Open at the end of the step before, not at this one's end, every closure of it in the step a resolution (`design-docs/analytics.md` § The counting unit), and no finding of it opened after this step's end |
| Baseline | Open at the step's end for the first time, brought by a build's first scan; drawn as a mark, never a bar |

| Rule | Reason |
|---|---|
| A component is its name, at any version | A version bump carrying an issue is no flow, and one fixing it is one corrected |
| Present before is asked of the issue at its component | An issue fixed in one package says nothing about another |
| A bounce is one return and no correction | A broken inventory that drops every component for a scan otherwise counts the whole estate resolved and then new |
| A sharp upload is the one the alert about a sharply moved inventory names, with its share and floor as set when the trend is read (`design-docs/notifications-alerts.md` § An inventory that moved sharply), worked out from the inventories stored | One rule for one event; nothing new is stored, so a changed threshold re-reads past marks |
| A removal's upload is the latest to take the component out of the build, arriving at or before the closure | The run that closed the row read that inventory |
| Only a removal is a gap; an upgrade a sharp upload made is a fix, and its return is returned | A component missing is the inventory broken; a version moved is work |
| Returned after a gap is out of the arrivals a reading compares with corrected | The inventory coming back is not work arriving |
| A correction stops counting when its issue returns, at whatever later moment | Corrected means still closed now; past bars move when an issue comes back |
| A build's first scan is its earliest run by start that did not fail | A failed run opened nothing |
| A first scan's issues are baseline, and the step says how many builds were first scanned in it | The inventory arriving is not work arriving; a new branch or variant is its own baseline |
| An issue already open elsewhere in the selection is no flow when another build's first scan finds it | It was already open |
| An issue present before, counted again only through a first scan, is returned | It was in the selection once |
| A finding recorded by hand has no run and is never baseline | |
| The first step's flows are its difference from the window's start | The moment before the first step is in the read |
| A finding the reader cannot read says nothing about whether its issue was present before | Returned against new would disclose it (REQ-43) |

### Steps and windows

| Rule | Reason |
|---|---|
| A step is a day or a week, sent as a count of days (1 to 730) or of weeks (1 to 104); both in one request is refused; neither is twelve weeks | Two years is the widest window (`design-docs/analytics.md` § The period a report covers) |
| Steps end at midnight UTC, the last at the coming one; each point is dated by its last day | A day holds whole days, and a fix at 23:00 lands on its own date |
| A step holds the interval after the previous step's end, up to and including its own end | A moment on a boundary belongs to the step it ends |
| The read covers findings open at the window's start or opened since, through now; whether an issue was present before the window is asked of the findings closed before it, for the issues the window's read did not reach opened at or before the start | Cost follows the window's start, not the deployment's age (REQ-74) |
| A build's first scan is asked only for the runs that opened something in the window | |
| Whether an upload was sharp is worked out only for the uploads deciding a closure a return in the window reverses, each build's in one comparison, from the graph up to the latest such closure | A build that drops packages every night otherwise costs a read per removing upload it ever received; every past closure of a returning component is still read, so such a build costs more as it ages (`design-docs/analytics-measurements.md` § Daily trend) |
| The backlog over time sheet steps daily unless weekly is picked: 14, 30, 90, 365 or 730 days, thirty unless picked, or 4, 13, 26, 52 or 104 weeks, thirteen unless picked, both in the address | |

| Rule | Reason |
|---|---|
| Answered against today's vulnerability data | Re-scanning a release is for the advisory published after it shipped |
| Rates stay on calendar | Between releases they measure how far apart they were cut |
| Release over release names a product and needs two releases | Tags across products interleave; one bar reads as broken |
| A release with nothing open is still a point | Counts attach to the list of every scanned build; absent says never scanned |
| Release over release counts each issue at a component open against the release, a component by its name | The unit of the calendar trend and of Home's open figure beside it |
| A corrected issue counts at the severity it held while open, at the end of the step before | |

## Subtree trends

The same series for an area: a team owns a kernel or a runtime, not an image.

| Rule | Reason |
|---|---|
| It takes the findings list's two narrowings: a component at any version, or a component and everything under it | |
| Under a component, a finding on a version a rescan replaced counts where the build's present version of its name sits, for every series alike (`design-docs/data-model-graph.md` § Path traversal) | A bump closes what it fixed on the version it replaced |
| Whether an issue was present before the window is asked under the same narrowing | An issue that sat elsewhere in the build is new to the area; by a component's name it costs 722 ms on MySQL 8.4 and 471 ms on MariaDB against 45 ms on PostgreSQL, accepted until a deployment shows it as a problem (`design-docs/analytics-measurements.md` § Daily trend) |
| Across several builds it refuses | A subtree is one build's walk |
| A selection naming no product refuses before any build is counted | |
| The component resolves as on the findings list, after the selection is authorized | An unreadable product refuses the same whatever it holds |
| The export resolves the component before the file begins | A later refusal can only cut a file sent as success |

A carried patch shows as a step down: one naming what it resolves closes the
finding as patched on the first scan carrying it, one moving the version closes
it as revised (`design-docs/findings-closure.md` § Build-declared claims).

## Burndown

The backlog of one selection from a day 0, in daily steps, and where the recent
pace takes it. Counted in the trend's unit, an issue at a component, with the
trend's identity rules (§ Counting by identity).

| Term | Meaning |
|---|---|
| **Left** | Open at a moment, with some finding of it in the selection open and not answered by a dismissal in force |
| **Done** | Left the backlog by a fix, a dismissal in force, or a publisher's statement that it is not affected, and not left since through now |
| **Added** | New or returned |

| Series | An issue at a component counted in the day |
|---|---|
| Left | Left at the day's end, split by the severity it held |
| New | Left at the day's end for the first time, open at no moment before in the selection, not brought by a build's first scan |
| Returned | Left at the day's end, not at the end of the day before, and open at some moment before; a dismissal that lapsed or was withdrawn is one |
| Fixed | Left at the end of the day before, closed at this one's end, every closure in the day a resolution or a statement and one a resolution, and done |
| Dismissed | Left at the end of the day before, open at this one's end with every finding answered, or closed in the day by statements alone, and done |
| Returned after a gap | As on the trend; a mark |
| Baseline | As on the trend; a mark |

### Answered by a dismissal

| Rule | Reason |
|---|---|
| The dismissals are not applicable, wrong match, will not fix and already fixed (`design-docs/analytics-controls.md` § Dismissals and last uploads) | A dismissal is part of the work |
| A dismissal answers a finding where the deadline's test matches it: the product, the issue under any name it merged into, the occurrence, and the versions the finding holds, a wrong match at any version | One test for what a decision answers |
| One needing a second person is in force from each agreement to its withdrawal; one needing nobody from its proposal; either until the decision stopped applying | The deadline stops for a decision in force and for nothing else |
| A waiting proposal, a deferral, a planned upgrade and a promised patch answer nothing | A promise is not the fix |
| An issue at a component is answered only where every finding of it open at the moment is | Answered at one occurrence and open at another is not done (REQ-17) |
| A dismissal that lapses or is withdrawn puts the issue back, counted as returned, and its dismissed day stops counting | Done means still done now |
| A disclaimed closure counts as dismissed; a superseded or unexplained one is no departure that counts | `design-docs/analytics.md` § The counting unit |

### Day 0 and steps

| Rule | Reason |
|---|---|
| Day 0 is a picked day, or the day the earliest finding in the selection opened | The first scan that found anything there |
| Steps are days ending at midnight UTC, from day 0's start through the coming midnight | The trend's steps |
| A day 0 more than 730 days back is moved to 730 days back, and the answer names the day it used | Two years is the widest window (`design-docs/analytics.md` § The period a report covers) |
| What was left at day 0's start is stated beside the first day | The line starts from it |

### The projection

The pace of the latest 14 days, a fixed span, and the day the line reaches zero
at it.

| Rule | Reason |
|---|---|
| The rate is done less added over the latest 14 days, or every day where fewer are drawn, a day | Two weeks: a quiet weekend does not swing it, and a change of pace shows within a sprint |
| Where the rate is above zero, the zero date is today plus left over the rate; past ten years no date is given | A date nobody plans by is noise |
| Where the rate is zero or below, there is no zero date; the screen says it is not converging and how many a day the backlog grows by | A line drawn to a date that never comes reads as a plan |
| Marks are out of the rate | A first scan or a restored inventory is not work |

### Narrowing

| Rule | Reason |
|---|---|
| It takes the subtree trend's two narrowings, with the same refusals (§ Subtree trends) | One meaning of a subtree |
| A component is chosen by name, or by a package identifier prefix (`design-docs/data-model-components.md` § Package identifier prefixes) | A repository is named by its identifier, never by the name its producer gave it |
| The answer names the packages a name or a prefix chose, with each one's ecosystem, at most 20 | A name two ecosystems share reads as one otherwise |
| A severity names the least severe band kept; an unrated issue reads as medium | As every band filter reads it |
| Visibility applies to every read, the dismissals included, and the export reads through the same method (REQ-43, REQ-50) | |

### Added and done

Two running totals from day 0, on one axis: added, and done. The gap between
them is the net move. Each day's done is split into fixed and dismissed, so the
mix stays visible.

| Rule | Reason |
|---|---|
| Totals start at zero on day 0; the baseline and restored marks are out of both | The inventory arriving is not work arriving |
| The totals need not sum to the line's move | A superseded or unexplained closure lowers the line and neither total, and an issue done and back is counted once, as returned |

### Burndown sheet

The catalog's findings burndown page draws both panels for the scope picked.

| Rule | Reason |
|---|---|
| The left panel is the line from day 0's start, the day's added above a zero rule and its fixed and dismissed below, in two colors, and the marks as dashed rules | The trend's chart shape, with done split |
| A dotted line runs from today's count toward zero at the rate; the chart widens by as much again as is drawn at most, and past that the line ends at the edge at the count it would reach there | Two years of history and a ten-year date on one axis flatten the history |
| One sentence above the chart names the zero date, more than ten years, or that it is not converging and about how many a day the backlog grows | |
| Day 0 is a date field, empty for the first scan | |
| A severity switch keeps a band and worse | |
| One field takes a name or a purl prefix: text starting `pkg:` is a prefix, anything else a name | Nobody types a prefix not starting with its scheme |
| The packages a choice matched are listed beneath the controls, each with its ecosystem where two share a name | |
| At or under a component arrives in a link from the dependency tree, a repository row or the component screen, and needs one build; without one the sheet asks for a build and reads nothing | The walk is one build's |
| The export links carry the same query | |

## Deadlines

A configured window from the finding's urgency, counted from first sighting
(REQ-33). Overdue is reported, never acted on.

| Rule | Reason |
|---|---|
| Known-exploited has its own window, the shortest | Otherwise the deadline contradicts the ranking |
| Anything unrated takes the medium window | Silence is no claim of mildness |
| Days remaining round down | Truncated, twelve hours overdue reads as due today |
| Stored at ingest, recomputed when the policy changes | Computed per request it is about eight seconds over 441,108 findings; stored, an indexed range scan |
| The clock stops only for a decision that applies: approved or needing nobody, at the versions this build ships. A dismissal takes the finding off; a deferral replaces the deadline with its date. A waiting proposal stops nothing, and "who is holding what" counts overdue by the same condition | |
| The overdue list is one range scan ordered on the stored deadline | Ordering by a computed deadline needs date arithmetic, which has no portable spelling, so it would be asked band by band; oldest-first and filtered loses an exploited finding due tomorrow behind old lows |
| A person is named on a row only where every occurrence has the same one | |
| Urgency is stored at ingest the same way | |

## Deadline compliance

Per severity: closed within the deadline against closed in total, and open past
it against open in total. A closed row keeps its deadline; only open rows lose
one, at end of life or below the minimum severity.

| Rule | Reason |
|---|---|
| Deferred by decision is split from plainly late: three numbers | Counted as failure, deferring stops and work runs late quietly |
| Only a deferral in force counts, until its date and at the versions it was made at | A waiting one would let a person take their own late work off. The outcome filter and the deferral-ending notice use the same test |
| A product is required, and every band returns, even empty | An occurrence carries no product |
| It says what carries no deadline: below the product's line, in a tag, out of support, and nothing upstream to take, the last linked to its own report | |
| Taking a population off the clock moves the rate upward, and the reader is told; a period spanning such a change is computed from two rules | The rows leaving are mostly late |
| Only the whole figure opens a list | The findings list reads a severity as that band or worse |
| Open in total is a column beside deferred and overdue | They are numerators |

## Remediation metrics

Fix velocity, time to remediate by severity, and aging buckets over a period.
Resolution is computed from scans (REQ-35), and a duration is a subtraction.

| Rule | Reason |
|---|---|
| A fix is counted in issues, fixed in the period its last occurrence the reader may see, in any product, closed by a fix | Fixed at one occurrence and open at another is not gone |
| An issue with any occurrence open is fixed in no period; an occurrence closed for a reason that is no fix is left out | |
| A fix is timed from the earliest occurrence opening to the last closing | |
| An occurrence one run recorded already closed is neither opened nor fixed | It was never open |
| A replaced inventory's check match on an issue with a known publication date is opened and fixed, timed from its opening to the replacement (`design-docs/findings-closure.md` § Replaced inventories) | It was open over that stretch |
| A check match marked publication date unknown is in no remediation figure | Its opening is the widest stretch it could have, so its duration is a guess |
| A check match withdrawn as never exposed is in no remediation figure, as in no run's opened count | It was never present |
| The check matches are one set each row is looked up in, never a condition asked of each row | Asked of each row, PostgreSQL compiles every figure: 1,685 ms against 170 ms at 103,095 findings (`design-docs/findings-measurements.md` § Remediation beside a check) |

Each aging bucket carries its count by severity and how many hold no standing
decision.

| Rule | Reason |
|---|---|
| A bucket names its start and end in days; the last has no end | |
| A bucket's link asks for open at least its start and under its end, and lifts the list's defaults | It counts tags, end-of-life releases, planned work and below the line |
| Matched on the live key, never on both versions | The query joins no components; the question is whether anybody has said anything |
| An issue in two buckets counts in both, undecided in one only where an occurrence there is unanswered | |
| A rating naming no band ranks below every band | |
| The time difference is one engine-specific expression returning a fraction of a day | No portable spelling; a whole number scanned on none of the four |

The buckets are one pass over what is open:

1. Each occurrence is matched once against the decision occurrences in force, built from the decision side and joined on the finding.
2. Each issue gets, per bucket, a flag for an occurrence there, a flag for an unanswered one, and the strictest rating among them.
3. Issues are counted by flags and ratings, a handful of rows.

## Holder workload

Work each person holds and how much is overdue, on the assignments screen.

| Rule | Reason |
|---|---|
| Counted in pieces of work: an issue in a component in a product | It agrees with the list behind it |
| Narrowed as every query is | A count discloses as a row does |
| Bounded, worst first | Unbounded, it grows and yields names |

## Effort by subject

What a period's decisions were about, most argued first: component, product,
arguments, reach, people, and outcomes.

| Rule | Reason |
|---|---|
| Counted in decisions, with occurrences beside them | Rows measure fan-out |
| Outcomes are part of the answer | Forty dismissals and forty promised upgrades differ |
| The subject is reached through findings at the decision's occurrences, in its own product, readable by the reader | A decision about something removed still names it; an unreadable finding's name is the disclosure |
| Dated by proposal | The audit log's rule |
| It takes the common period, and one product or one team picked from the teams that exist | |
| It pages, its total counting every row before the limit | |

## Triage latency

Two waits per severity, each the median, the ninetieth percentile and the
longest:

1. From a finding appearing to anybody proposing anything.
2. From a proposal to a second person agreeing.

| Rule | Reason |
|---|---|
| Percentiles are nearest-rank, the first observation at or past the position | Waits of one, two and thirty days have a median of two |
| The arithmetic runs in the application | Subtraction and percentiles are spelled four ways |
| A wait is measured from the finding the decision is about | An occurrence sits in every product |
| Bounded to the most recent few thousand decisions, saying how many and whether the ceiling was reached | |
| Throughput is per person: a decision in the window it was proposed, an agreement in the window it was given | |
| Throughput, waits and send-backs count decisions, made, agreed and withdrawn alike; a wait runs from a decision's earliest finding to its first proposal | |
| Send-backs are counted for the deployment | The record holds no sender |
| It narrows to one product or one team's people | |
| A team narrows waits by proposer and throughput by who did each piece | |
| A team with nobody on it measures nothing | A narrowing never widens |
| Only an administrator gets a team's per-person rows; anybody else its totals | `design-docs/access-assignment.md` § Teams |

## Repeated deferrals

Occurrences deferred more than once: how often, counted in decisions, and for
how long, counted as the deferral threshold counts
(`design-docs/triage-approval.md` § The deferral threshold). A withdrawn or lapsed
deferral counts for the part that ran, and overlapping stretches count once.

## Limits

| Limit | Detail |
|---|---|
| An issue rated differently in two products counts once, in the strictest band | Trends, aging buckets and fixes agree on one screen |
| A component a rescan removed, with no component of its name left in the build, sits beneath nothing | Its closures leave the trend of the component it sat beneath; there is no present version to count them at, as for code findings |
| A finding two dismissals answer at once counts twice toward its moment on the burndown | The moment's answered findings are summed over dismissals; one live decision per key keeps it rare |
| A dismissal needing nobody that was sent back is read as never in force, and one sent back after an agreement keeps the agreement's span | The record keeps whether it is sent back, not when |
| A build's own suppression or a statement applied to an open finding is no answer on the burndown | Neither records when it took effect |
