# Operational alerts

Alerts about the deployment and its data: new criticals in a release, sharp
inventory moves, analyzer series, the reports that must come back empty, and
absent holders.

Satisfies REQ-42, REQ-43, REQ-45, REQ-49, REQ-53.

## Contents

- [New criticals in a shipped release](#new-criticals-in-a-shipped-release)
- [An inventory that moved sharply](#an-inventory-that-moved-sharply)
- [Analyzer alerts](#analyzer-alerts)
- [Reports that must come back empty](#reports-that-must-come-back-empty)
- [Absent holders](#absent-holders)
- [Limits](#limits)

## New criticals in a shipped release

Outside the opt-in digest, which is silent on the deployment needing it most.

| Rule | Reason |
|---|---|
| A condition, cleared when the finding closes or somebody answers it | |
| Tags only | A critical on a branch is work in progress |
| To whoever may read and may triage it, never administrators as such | It names an issue, component and build; administering reads no product (REQ-42) |

## An inventory that moved sharply

An upload that changed much of what a build is made of: a base image changed, a
lockfile regenerated, a transitive tree arrived.

| Rule | Reason |
|---|---|
| An event | It is true of one upload, so nothing clears |
| The fact and a link, never the names | The list is a screen under the reading rule |
| One upload is one thing to carry outside | The sentence is the same for every reader; the application area shows each their own line |
| To whoever may read the product | An administrator with no product role administers the catalog |
| Never for a build's first upload | Every name is new |

### The two thresholds

An upload passes both, each set by the deployment.

| Threshold | What it stops | Shipped |
|---|---|---|
| A share of what the build held | A count alone is noise on large builds or silence on one that replaced everything | A quarter |
| The fewest names that count | A share alone fires on an inventory of ten moving three names | Ten |

| Rule | Reason |
|---|---|
| A share above the whole and a count at or below zero are refused | Nothing reaches them, while the screen reports them as applying |
| The shipped numbers are a starting point | Nightly movement depends on what a build is built from |
| An empty inventory's share stops nothing; the floor still applies | |

## Analyzer alerts

To everybody who reads the product's security testing findings. Each names a series and
a build and nothing found, and is withheld as security testing work
(`design-docs/notifications.md` § The notification list).

| Alert | Kind | Says | Clears |
|---|---|---|---|
| Many findings no longer detected (`security-testing-dropped`) | event | A comparable run marked more open code findings no longer detected than expected of one run, with both counts. Once, after the run commits, linked to those code findings | Acknowledged |
| Latest run can't be compared (`security-testing-not-comparable`) | condition | The newest applied run could not be compared, and why. Nothing it stops reporting is marked no longer detected | The next comparable run |
| Security testing stopped reporting (`security-testing-stopped`) | condition | No run applied for three usual gaps, never under a day. Names the last upload turned away since, with what its sender was told | The next applied run |

| Rule | Reason |
|---|---|
| A sharp drop is applied, never held | A held run leaves every later run superseded behind it, and a fix sweep looks like a partial run |
| Its thresholds are the analyzer drop share and floor, both passed | `design-docs/analysis.md` § Run application |
| The usual gap is the median of the newest ten | A long weekend or rerun burst does not move it; Analysis coverage reads the same interval (`design-docs/analysis-figures.md` § Analysis coverage) |
| Fewer than three applied runs on a build is never quiet | Two runs are one gap |
| Builds retired at any level, and releases past end of life, are left out | |

## Reports that must come back empty

The register filtered for one person's decisions returns nothing, the
vulnerability data keeps moving, and a configured supplier keeps answering. None
is a report or a scheduled mail:

| Shape | Why it fails |
|---|---|
| A report to go and read | Always empty, it is stopped, then read after something went wrong |
| Mailed only when non-empty | Silence means the control held or the job did not run |
| Mailed always | Fifty-one empty messages teach a filter for the fifty-second |

Each is a condition, sent only when the control fails, to administrators.

| Condition | What is wrong |
|---|---|
| The vulnerability data has stopped moving | Every scan answers confidently against old data |
| Something is hidden with nobody's agreement | The write path was got around |
| An upstream cannot be read | Raised once the last read of a trusted upstream failed and nothing was read for two read intervals; names the product, address, last error and last read. Cleared by a read, which tells its holders once, or by the upstream no longer being trusted (`design-docs/upstream.md` § Failure notices) |
| A supplier has stopped answering | Unread past a setting, a week by default, never under two scan intervals, from the last good read or from configuration; it looks like a supplier publishing nothing. Cleared by a read, withdrawal, or its product retiring |
| One pair agrees to most of a product's work | Thresholds apply, below which one pair is a small team |

| Rule | Reason |
|---|---|
| The fact and a link, never the rows; the question underneath returns counts | Otherwise a list of failed controls goes wherever the channel goes |
| Asked as the deployment, never as a person | Administering grants no reading |

### Hidden with nobody agreeing

| Rule | Reason |
|---|---|
| Does not apply, will not be fixed and already fixed are counted whatever else is recorded | Each closes the question and needs a second person, so a write path clearing its own flag is still caught |
| A code finding dismissed or called no security issue is counted the same way | The count spans products, so no security testing work reaches the administrator |
| A deferral or promise counts where the gate asked for a second person | Both are approved conditionally, on the date against the deadline |
| The gate's verdict is read, re-worked against the policy in force when the write landed, never a caller's | |
| Agreement is asked of the record: an approval from anybody but the proposer, not taken back | A flag is the row's own account of itself |
| A decision still waiting is not counted | It hides nothing while somebody looks |
| Counted across every product and the whole record; the linked report narrows to its reader and asks for everything | An administrator holding no product reads the count and an empty page |

### Concentrated approval pairs

| Rule | Reason |
|---|---|
| Raised where one pair's share of a product's agreements reaches a threshold, among at least a set number of people who may approve | A share alone is permanently true in a team of two, an alert nobody can clear (REQ-49). A share of a hundred is raised |
| Only over at least ten agreed decisions in the period | Below it, aging out flips the condition back and forth |
| Each threshold is a deployment setting a product may override; cleared, the product follows the deployment | The minimum severity's shape |
| A pair is two people whichever proposed | Counted by direction, it reads as two halves under the threshold |
| Counted in decisions, over the last ninety days of proposals, older agreements left out of the whole too | Approval quality's period, so the linked report holds what raised it |
| People who may approve are counted, not people who did; a triager and an approver each may where they read | |
| Keyed on the product and the two people | A pair staying dominant stays one condition |
| Names the two people and the share, never the counts | Volume follows visibility (REQ-42, REQ-43) |

### Data that stopped moving

| Rule | Reason |
|---|---|
| The scanner's data version is checked for inequality, never order | It is opaque |
| Only a finished run stating a version counts | A deployment that never finished a scan is the quiet-build condition's |
| Measured from the latest time any version was first seen | A returning version is no change; otherwise an air-gapped re-import reads seven months stale and two replicas flap (REQ-49) |
| Stopped after a setting, shipping at a week | |
| One key however the data moves, its sentence naming the data in force | A key carrying the version reopens while nothing changed |
| The version in force and when it last moved are read apart, and the linked screen shows both | One statement answering both gets the age wrong |
| The CVE record snapshot a run read is asked the same, in the same condition, saying which stopped | A deployment never reading a snapshot narrows nothing |

## Absent holders

An administrator is told when somebody has not signed in for a configured
period and still holds assigned work (REQ-45).

| Rule | Reason |
|---|---|
| Both halves are required | An unused account holding nothing is harmless |
| It asks, never acts | Leave and departure look identical |
| Never signed in counts as absent, from when they were added | Otherwise adding and assigning alerts at once |
| Counted in pieces of work; an open report held is one, a judged one none | "6 items" meaning 288 findings reads as catastrophe |

## Limits

| Limit | Detail |
|---|---|
| A deployment alert carries counts and a link | What it is about is read on a screen under the reader's own visibility |
