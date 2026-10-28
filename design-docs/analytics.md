# Analytics

The unit every figure counts, how a figure is computed, the period a report
covers, and the settings an administrator changes in the application.

Satisfies REQ-30, REQ-33, REQ-74.

## Contents

- [The counting unit](#the-counting-unit)
- [Computed on demand](#computed-on-demand)
- [The period a report covers](#the-period-a-report-covers)
- [Settings](#settings)
- [Limits](#limits)

| Document | Holds |
|---|---|
| `design-docs/analytics-catalog.md` | The catalog of named reports, its pages, unmatched components |
| `design-docs/analytics-program.md` | Trends, deadlines, compliance, remediation, workload, effort, latency |
| `design-docs/analytics-releases.md` | Build comparison, the release note, readiness, inheritance, one issue across the estate |
| `design-docs/analytics-controls.md` | The disposition register, the exception report, approval quality, dismissals, last uploads |
| `design-docs/analytics-exports.md` | Files |
| `design-docs/analytics-measurements.md` | Benchmark runs |

## The counting unit

Every rate and count is one issue at one component, never one occurrence: one
flaw in a library forty-five packages pull in is one decision, and on a real
kernel the two counts are about thirty-seven apart. The deadline is stored per
occurrence all the same.

| A group is | When |
|---|---|
| Closed | No occurrence is still open |
| Met | No closed occurrence was late |
| Deferred | Every open occurrence is covered by a standing deferral |
| Overdue | Anything open is past its date and uncovered |

Five closure reasons are not resolutions, since a velocity counting them
measures churn:

| Reason | Why it is not a resolution |
|---|---|
| `superseded` | The version moved and the issue came with it |
| `unexplained` | The scanner stopped reporting it with the component unchanged: a fault |
| `invalid` | A record taken back was never present. Left out of every open set |
| `unaffected` | The CVE record states the release was never affected. Left out of every open set |
| `disclaimed` | A supplier states the product the occurrence sits in is not affected, or an upstream states the component is not affected or fixed at the version shipped. Nothing changed, so the occurrence is in the open sets up to its closure and in the releases an issue was in (`design-docs/findings-closure.md` § Closure reasons) |

| Rule | Reason |
|---|---|
| Removed, upgraded, revised, patched, and a recorded flaw declared fixed are resolutions | |
| An occurrence closed `invalid`, `unaffected` or `disclaimed` is judged against no deadline, in the compliance rate or the register's met column | It was never work |
| Closed exactly at the deadline met it | Open at that instant is not yet overdue |

## Computed on demand

Every count is worked out when asked (REQ-74). Nothing is precomputed, cached or
refreshed: traffic is dozens of people a month, and visibility is per subject,
so a precomputed total is computed per person or filtered through a second path.
What would change this is a dashboard measured slow on a real deployment, and
then the grain is one row per product per day, the grain access is granted at.

| Rule | Reason |
|---|---|
| A count over findings groups the occurrences on their own columns first, then joins the issue, its rating and the catalog's names | One issue sits at many occurrences: the backlog trend answers in 0.25 s against 1.58 s (`design-docs/analytics-measurements.md` § Grouping before the join) |
| Every narrowing applies before the grouping | Visibility, the selection and the minimum severity are conditions on an occurrence |
| A DISTINCT over joined rows is not the reduction | The join still runs per occurrence, slower on PostgreSQL |

## The period a report covers

Deadline compliance, remediation, triage latency, approval coverage, effort,
advisories issued and administrative changes each take one period, in one
shape, so a link between reports carries the same two parameters.

| Rule | Reason |
|---|---|
| A period is two dates; a rolling window is a number of days; sending both is refused | A window cannot say "last financial year"; answering one of two quotes the wrong period |
| The end is the day it stops, as in the audit log | |
| A screen's "To" is the last day in the period, sent to the server as the day after, translated once where the screen reads its address | Picking March 31 means March 31 is in it. Files, sections and headings follow |
| A day not on the calendar is refused as an end | A parser rolls February 30 into March |
| A period ending before it starts is refused, and so is one holding no days, such as one day named twice | Either answers like a quiet quarter |
| Every report says back its period with the end resolved; an unstated start is the beginning, shown as absent | |
| A default window belongs to the report, stated in its own words | Thirty days, ninety, or the whole |
| What is open is always now; a period bounds what closed in it | Deadlines move with policy, the minimum severity and end of life, so past open sets are not recoverable |
| The rate asked for no period is the lifetime figure | |
| The change log takes no default window | It must not look like it answers about everything |
| A trend's window is a count of week steps | It is a series |
| The longest window offered is two years | Over 8,407 open findings on two builds, twelve weeks take 1.28 s and a hundred and four 1.40 s, the file 1.43 s |

## Settings

What an administrator changes inside the application; a configuration file is
the operator's.

| Setting | Controls |
|---|---|
| The five deadline windows | Exploited, critical, high, medium, low |
| The deferral threshold | How long something may be put off before a second person agrees |
| The session lifetime | Also how long somebody who left a team keeps what it gave them, by browser and personal token alike |
| The token ceiling | The longest a personal token may last |
| The bulk action limit | Reports one ruling may cover, occurrences one answer about one issue may cover, and rows a screen acts on in one request |
| The reviewed issue limit | Issues one answer about many issues may cover where a second person agrees |
| The re-confirmation issue limit | Issues one re-confirmation may cover where nobody agrees again |
| The write ceiling | Findings one answer about many issues, or one flaw recorded here, may write |
| The minimum severity | Below it findings are recorded and counted but kept off the working list (REQ-30). A product may state its own |
| Quiet after | How long a build may go unscanned before it is quiet |
| Scan every | How often everything tracked is scanned again |
| Upstream currency | Whether public package indexes are asked for the newest version. Off by default; a component's name goes out, names this deployment calls its own are held back, and the no-upstream report says which |
| The two attachment bounds | The largest file, and the deployment total |
| Absent after | How long somebody may go unsigned-in before work they hold is raised |
| The three disclosure periods | How long a finding stays undisclosed, how far that date may move in total before a second person agrees, and the lead time before it |
| The four staleness periods | A decision waiting on a second person, one sent back, a deferral ending, and work in a team's queue |

The shipped numbers are a starting point: a deadline nobody agreed to makes an
estate permanently late.

| Rule | Reason |
|---|---|
| A value is checked against its kind before it is written: a duration, a whole number above zero for the limits, a severity word, on or off | Readers fall back to the default on an unreadable value, a policy quietly stopped |
| Zero and negative are refused | Readers treat them as unset |
| Only known names may be set | |
| A stored minimum severity outside the severity words reads as none, and says it cannot be enforced | |
| A failure to read a setting is reported, never read as unset | Defaults would change which deferrals need a second person |
| Every setting offered is read: the administrator's value, then the process's startup value, then the built-in default | |

## Limits

| Limit | Detail |
|---|---|
| Analytics owns no table | Every figure reads what the findings and decisions already hold |
