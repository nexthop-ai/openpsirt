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

Three series, new, resolved and open, each split by severity. Together they say
whether the team keeps pace: an open count that barely moves while its critical
share rises is getting worse.

| Viewing | Axis | Reason |
|---|---|---|
| A branch | Calendar time | Scanned nightly, continuous (REQ-54) |
| Tagged releases | Release over release, oldest first, as bars | Each is a frozen point. On a calendar, releases months apart read as drift, and a line between them draws a path nothing traveled |

| Rule | Reason |
|---|---|
| Answered against today's vulnerability data, never as of each cut | Re-scanning a shipped release is for the advisory published after it shipped |
| Rates stay on calendar | Between two releases they measure how far apart they were cut |
| Release over release names a product and needs two releases | Tags across products interleave meaninglessly; one bar reads as broken |
| An issue open in two products counts once, in the stricter band | The aging figures do the same, so the two charts agree |
| A release with nothing open is still a point | Counts attach to the list of every scanned build; absent says never scanned |
| A resolved issue counts at the severity it held while open | The step it left in has none |
| The window becomes predicates before the statement runs | A finding opened after the last point or closed before the first contributes nothing, so cost follows the range asked, not the deployment's age |
| The step and the number of steps are bounded | They arrive as parameters; a zero step draws one instant twelve times |

## Subtree trends

The three series for an area: a team owns a kernel or a runtime, not an image.

| Rule | Reason |
|---|---|
| It takes the findings list's two narrowings: a component at any version, or a component and everything under it | A chart and a list describing a subtree differently drift |
| Across several builds it refuses | A subtree is one build's walk; both silent alternatives, the first build sorted or an empty chart, are wrong |
| A selection naming no product refuses before any build is counted | Across products it counts builds the caller may not read |
| The component resolves as on the findings list, after the selection is authorized | Not found where the build does not hold it, the choices where it holds several. An unreadable product refuses the same whatever it holds |
| The export resolves the component before the file begins | A refusal after the first row can only cut a file sent as success |

A carried patch shows as a step down in the open count: a patch naming what it
resolves closes the finding as patched on the first scan carrying it, and one
moving the shipped version closes it as revised (`design-docs/findings-closure.md`
§ Build-declared claims).

## Deadlines

A finding carries a deadline from its urgency: a configured window counted from
when it was first seen (REQ-33). Being overdue is reported and never acted on.

| Rule | Reason |
|---|---|
| Known-exploited has its own window, the shortest | Exploitation is a fact about the world; without it the deadline contradicts the ranking |
| Anything unrated takes the medium window | Silence is not a claim of mildness |
| Days remaining round down | Truncation shows twelve hours overdue as zero days left, which reads as due today |
| Stored at ingest, recomputed when the policy changes | Computed per request it is a pass over every open finding per urgency band, about eight seconds over 441,108 findings; stored, an indexed range scan |
| The clock runs on what nobody has answered | A dismissal takes a finding off; a deferral replaces the deadline with its date. Only a decision that applies stops it: approved or needing nobody, at the versions this build ships, a deferral until its date. A waiting proposal stops nothing, and "who is holding what" counts overdue by the same condition |
| The overdue list is one range scan ordered on the stored deadline | Band by band needs date arithmetic with no portable spelling; oldest-first and filtered loses an exploited finding due tomorrow behind lows from two years ago |
| A person is named on a row only where every occurrence has the same one | One of several says the finding is handled when most is not |
| Urgency is stored at ingest the same way | Nobody edits the ranking; people edit deadlines |

## Deadline compliance

Per severity: closed within the deadline against closed in total, and open past
it against open in total. The inputs are stored, since a closed row keeps its
deadline and only open rows lose one at end of life or below the minimum
severity.

| Rule | Reason |
|---|---|
| Deferred by decision is split from plainly late: three numbers | Counting an approved deferral as failure teaches people to stop deferring and run late quietly |
| Only a deferral in force counts: agreed, or short enough to stand alone | A waiting decision would let one person take their own late work off the report. The same test answers the outcome filter and when a deferral's end is announced |
| A deferral counts until its date, at the versions it was made at | Past its date or at other versions it is overdue, as the running-out list and each person's overdue count say |
| A product is required | An occurrence carries no product. Every band comes back, even empty |
| It says what carries no deadline: below the product's line, in a tag, out of support, and nothing upstream to take | The third has its own report, linked |
| Taking a population off the clock moves the rate upward, and the reader is told | The rows leaving are disproportionately late. A period spanning such a change is computed from two rules |
| Only the whole figure opens a list | The findings list reads a severity as that band or worse |
| Open in total is a column beside deferred and overdue | They are numerators without it |

## Remediation metrics

Fix velocity, time to remediate by severity, and aging buckets over a period. A
finding records when it opened and closed, so a duration is a subtraction.
Resolution is computed from scans (REQ-35).

| Rule | Reason |
|---|---|
| A fix is counted in issues | The unit opened work is counted in |
| An issue is fixed in the period its last occurrence closed by a fix, across every occurrence the reader may see in every product | Fixed at one occurrence and open at another is not gone |
| An issue with any occurrence open is fixed in no period | |
| An occurrence closed for a reason that is no fix is left out | Churn carried it to an open occurrence; a record taken back never was one |
| A fix is timed from the earliest occurrence opening to the last closing | How long the issue was there |
| Rated in the strictest band any of its products gives it | So an issue rated two ways is one fix |

The aging buckets carry, beside their count, the count by severity and how many
hold no standing decision, which say whether anything over three months matters
and whether anybody has looked.

| Rule | Reason |
|---|---|
| Each bucket names its start and end in days; the last has no end | |
| A bucket's link asks the findings list for open at least its start and under its end, and lifts the list's defaults | A start alone asks for every older bucket. The bucket counts tags, releases past end of life, planned work and below the line |
| Matched on the live key, never on both versions | The query joins no components, and the backlog question is whether anybody has said anything |
| An issue in two buckets counts in both, undecided in one only where an occurrence there is unanswered | |
| A rating naming no band ranks below every band | |
| The time difference is one engine-specific expression returning a fraction of a day | Subtracting moments has no portable spelling; a whole number scanned on none of the four |

The buckets are one pass over what is open:

1. Each occurrence is matched once against the decision occurrences in force, built from the decision side and joined on the finding.
2. Each issue gets, per bucket, a flag for an occurrence there, a flag for an unanswered occurrence there, and the strictest rating among those occurrences.
3. Issues are counted by flags and ratings: a handful of rows however many issues.

## Holder workload

How much work each person holds and how much is past its deadline, on the
assignments screen. The overdue count separates somebody keeping up with a
large list from somebody sitting on one; an idle account holding nothing is
harmless.

| Rule | Reason |
|---|---|
| Counted in pieces of work: an issue in a component in a product | It agrees with the list behind it |
| Narrowed as every query is | A count discloses as a row does |
| Bounded, worst first | Unbounded it grows with the deployment and yields names |

## Effort by subject

What a period's decisions were about, most argued first: component, product,
how many arguments, how far they reached, how many people, and what came out.
It answers what a quarter went into, which no backlog figure does.

| Rule | Reason |
|---|---|
| Counted in decisions, with occurrences beside them | Counted by rows it measures fan-out; ten decisions over ten occurrences and one over a thousand are different afternoons |
| Outcomes are part of the answer | Forty dismissals and forty promised upgrades are different quarters |
| The subject is reached through the findings at the decision's occurrences | A decision's rows name occurrences. A decision about something removed still names it |
| Those findings are the decision's own product's, and readable by the reader | An occurrence matches the same pair in every product, and an unreadable finding's component name is the disclosure |
| Dated by proposal | Dated by agreement, late approvals move work out of its period. The audit log's rule |
| It takes the common period, and one product or one team, picked from the teams that exist | A manager reads their own quarter |
| It pages, and its total counts every row before the limit | A total off the page reads a cut list as complete |

## Triage latency

Two waits per severity, because a critical waiting a week is not a low waiting a
week:

1. From a finding appearing to anybody proposing anything.
2. From a proposal to a second person agreeing.

Each is three numbers: the median, the ninetieth percentile and the longest. Ten
decisions in a day and one in a quarter average to a fortnight, describing
neither.

| Rule | Reason |
|---|---|
| Percentiles are nearest-rank, the first observation at or past the position | They are waits something had. Waits of one, two and thirty days have a median of two |
| The arithmetic runs in the application | Subtracting moments and taking percentiles are spelled four ways |
| A wait is measured from the finding the decision is about | An occurrence sits in every product; matched alone, it reads another product's finding |
| Bounded to the most recent few thousand decisions in the window, stating how many and whether the ceiling was reached | |
| Throughput is per person, a decision in the window it was proposed in, an agreement in the window it was given | |
| Throughput, waits and send-backs count decisions, made, agreed and withdrawn alike | A decision is one piece of work however many rows; each wait is one per decision and band, from its earliest finding to its first proposal |
| Send-backs are counted for the deployment, not per person | The record holds that a decision came back, not who sent it |
| It narrows to one product or one team's people | |
| A team narrows the waits by who proposed, throughput by who did each piece | A decision belongs to whoever argued it |
| A team with nobody on it measures nothing | A narrowing must never silently widen |
| Only an administrator is given a team's per-person rows; anybody else its totals | Membership is an administrator's to know (`design-docs/access.md` § Teams) |

## Repeated deferrals

Occurrences deferred more than once, how often and for how long in total. The
cumulative threshold refuses one further deferral at a time; this shows the
shape, where forty items deferred three times is a policy nobody wrote.

| Rule | Reason |
|---|---|
| Counted over decisions: how often is how many decisions put it off | |
| How long is counted as the deferral threshold counts it (`design-docs/triage.md` § The deferral threshold) | |
| A withdrawn or lapsed deferral counts for the part that ran, and overlapping stretches count once | |

## Limits

| Limit | Detail |
|---|---|
| A rate about dates says nothing of what was never due | Below the line, tags, out of support and nothing upstream are reported apart |
