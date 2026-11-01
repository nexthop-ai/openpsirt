# Program figures

How a program is doing over time: trends, deadlines and compliance, remediation,
who holds what, where the effort went, and how long triage takes.

Satisfies REQ-33, REQ-35, REQ-53, REQ-54.

## Contents

- [Trends](#trends)
- [Subtree trends](#subtree-trends)
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

New, resolved and open, each split by severity: an open count that barely moves
while its critical share rises is getting worse.

| Viewing | Axis | Reason |
|---|---|---|
| A branch | Calendar time | Scanned nightly (REQ-54) |
| Tagged releases | Release over release, oldest first, as bars | Frozen points; a line between them draws a path nothing traveled |

| Rule | Reason |
|---|---|
| Answered against today's vulnerability data | Re-scanning a release is for the advisory published after it shipped |
| Rates stay on calendar | Between releases they measure how far apart they were cut |
| Release over release names a product and needs two releases | Tags across products interleave; one bar reads as broken |
| A release with nothing open is still a point | Counts attach to the list of every scanned build; absent says never scanned |
| A resolved issue counts at the severity it held while open | |
| The window becomes predicates before the statement runs | Cost follows the range asked, not the deployment's age |
| The step and the number of steps are bounded | They arrive as parameters |

## Subtree trends

The three series for an area: a team owns a kernel or a runtime, not an image.

| Rule | Reason |
|---|---|
| It takes the findings list's two narrowings: a component at any version, or a component and everything under it | |
| Under a component, a finding on a version a rescan replaced counts where the build's present version of its name sits, for opened, resolved and open alike (`design-docs/data-model-graph.md` § Path traversal) | A bump closes what it fixed on the version it replaced |
| Across several builds it refuses | A subtree is one build's walk |
| A selection naming no product refuses before any build is counted | |
| The component resolves as on the findings list, after the selection is authorized | An unreadable product refuses the same whatever it holds |
| The export resolves the component before the file begins | A later refusal can only cut a file sent as success |

A carried patch shows as a step down: one naming what it resolves closes the
finding as patched on the first scan carrying it, one moving the version closes
it as revised (`design-docs/findings-closure.md` § Build-declared claims).

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
