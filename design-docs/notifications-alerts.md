# Operational alerts

Alerts about the deployment and its data rather than about one person's work:
new criticals in a release, sharp inventory moves, analyzer series, the reports
that must come back empty, and absent holders.

Satisfies REQ-42, REQ-43, REQ-45, REQ-49, REQ-53.

## Contents

- [New criticals in a shipped release](#new-criticals-in-a-shipped-release)
- [An inventory that moved sharply](#an-inventory-that-moved-sharply)
- [Analyzer alerts](#analyzer-alerts)
- [Reports that must come back empty](#reports-that-must-come-back-empty)
- [Absent holders](#absent-holders)
- [Limits](#limits)

## New criticals in a shipped release

An operational alert outside the opt-in digest, since an opt-in category is
silent on the deployment that most needs it.

| Rule | Reason |
|---|---|
| A condition | It clears when the finding closes or somebody answers it |
| Tags only | A critical on a branch is ordinary work in progress |
| To whoever may read and may triage it, never to administrators as such | It names an issue, a component and a build. Administering reads no product (REQ-42), and a reader who cannot act is interrupted for nothing |

## An inventory that moved sharply

An upload that changed much of what a build is made of: a base image changed, a
lockfile regenerated, a transitive tree arrived. Nothing else tells somebody not
watching.

| Rule | Reason |
|---|---|
| An event | It is true of one upload; the next is a different upload, so nothing clears |
| The fact and a link, never the names | What moved is a screen that applies the reading rule; a message travels outside |
| One upload is one thing to carry outside | The sentence is the same for every reader, so a channel is told once; the application area shows each reader their own line |
| To whoever may read the product | It links to the inventory. An administrator holding no product role administers the catalog, and granting themselves one is recorded |
| Never for the first upload read for a build | Every name is new |

### The two thresholds

Both set by the deployment, and an upload passes both.

| Threshold | What it stops | Shipped |
|---|---|---|
| A share of what the build held | A count alone is noise on large builds or silence on a build that replaced everything | A quarter |
| The fewest names that count | A share alone fires on an inventory of ten every time three names move | Ten |

| Rule | Reason |
|---|---|
| A share above the whole and a count at or below zero are refused | Nothing reaches them, so the alert never fires while the screen reports the setting as applying |
| The shipped numbers are a starting point | How much a build moves nightly depends on what it is built from |
| An empty inventory's share stops nothing; the floor still applies | Three names given back to an emptied build are three names |

## Analyzer alerts

What an analyzer series does on a build, told to everybody who reads the
product's internal findings. Each names a series and a build and nothing found,
and is withheld as internal (`design-docs/notifications.md` § The notification
list).

| Alert | Kind | Says | Clears |
|---|---|---|---|
| Many findings no longer detected (`security-testing-dropped`) | event | A comparable run marked more open code findings no longer detected than the deployment expects of one run, with both counts. Told once after the run commits, linked to the series' code findings no longer detected | Acknowledged |
| Latest run can't be compared (`security-testing-not-comparable`) | condition | The newest applied run could not be compared, and why. Nothing it stops reporting is marked no longer detected | The next comparable run |
| Security testing stopped reporting (`security-testing-stopped`) | condition | No run applied for three usual gaps, never under a day. Names the last upload turned away since, with what its sender was told | The next applied run |

| Rule | Reason |
|---|---|
| A sharp drop is applied, never held | A held run leaves every later run superseded behind it, and a fix sweep looks like a partial run |
| The thresholds are the analyzer drop share and floor, both passed | `design-docs/analysis.md` § Run application |
| The usual gap is the median of the newest ten | A long weekend or burst of reruns does not move it; a pipeline gone nightly is judged by what it does now |
| A series with fewer than three applied runs on a build is never quiet | Two runs are one gap |
| Builds retired at any level, and releases past end of life, are left out | |

## Reports that must come back empty

Empty is what these are for: the register filtered for one person's decisions
returns nothing because every outcome hiding risk needs a second person, the
vulnerability data never stops moving, and a configured supplier never stops
answering. None is a report to open or a scheduled mail:

| Shape | Why it fails |
|---|---|
| A report to go and read | Empty every time, it is stopped, then read only after something went wrong |
| Mailed only when non-empty | Silence means the control held or the job did not run |
| Mailed always | Fifty-one empty messages teach a filter for the fifty-second |

So each is a condition, sent only when the control fails, to administrators.

| Condition | What is wrong |
|---|---|
| The vulnerability data has stopped moving | Nothing failed; every scan answers confidently against month-old data |
| Something is hidden with nobody's agreement | The write path was got around |
| An upstream cannot be read | Raised once the last read of a trusted upstream failed and nothing has been read for two read intervals, so one failure the next read answers raises nothing. Names the product, address, last error and last read. Cleared by a successful read, which tells its holders once, or by the upstream no longer being trusted (`design-docs/upstream.md` § Failure notices) |
| A supplier has stopped answering | Unread past a setting, a week by default, never under two scan intervals, measured from the last good read or from configuration. One stopped and one silent look alike everywhere but its panel. Cleared by a read, withdrawal, or its product retiring |
| One pair agrees to most of a product's work | The second person is there in form only. It carries thresholds, below which one pair is a small team |

| Rule | Reason |
|---|---|
| The fact and a link, never the rows | Otherwise a list of failed controls goes wherever the channel goes |
| The question underneath returns counts | The rule holds by construction |
| Asked as the deployment, never as a person | Administering grants no reading |

### Hidden with nobody agreeing

| Rule | Reason |
|---|---|
| Does not apply, will not be fixed and already fixed are counted whatever else is recorded | Each closes the question and needs a second person; counted unconditionally, a write path clearing its own flag is still caught |
| A code finding dismissed or called no security issue is counted the same way | The count spans every product, so nothing internal reaches an administrator who reads none |
| A deferral or promise counts where the gate asked for a second person | Both are approved conditionally, on the date against the deadline |
| The gate's verdict is read, never a caller's | A proposal is re-worked against the policy in force when the write lands |
| Agreement is asked of the record: an approval from anybody but the proposer, not taken back | A flag is the row's own account of itself |
| A decision still waiting is not counted | It hides nothing while somebody looks at it |
| Counted across every product and the whole record | The report behind the link narrows to its reader, so an administrator holding no product reads the count and an empty page, and the link asks for everything rather than the sheet's default quarter |

### Concentrated approval pairs

| Rule | Reason |
|---|---|
| Raised where one pair's share of a product's agreements reaches a threshold, among at least a set number of people who may approve | A share alone is permanently true in a team of two, an alert nobody can clear (REQ-49). A share of a hundred is raised |
| Only over at least ten agreed decisions in the period | Below it one decision is a hundred percent, and aging out flips the condition back and forth |
| Each threshold is a deployment setting a product may override; cleared, the product follows the deployment | Team sizes differ. The minimum severity's shape |
| A pair is two people whichever proposed | Counted by direction, the pattern reads as two halves under the threshold |
| Counted in decisions | |
| Over the last ninety days of proposals, older agreements left out of the whole as well | Approval quality's period, so the linked report holds what raised it; a spread-out past does not hide a concentrated present |
| People who may approve are counted, not people who did | One pair doing everything beside idle approvers is the case. A triager and an approver may each approve where they read |
| Keyed on the product and the two people | A pair staying dominant stays one condition |
| It names the two people and the share, never the counts | Volume follows visibility (REQ-42, REQ-43); the decisions are on the linked report |

### Data that stopped moving

| Rule | Reason |
|---|---|
| The check is inequality of the scanner's data version, never ordering | The version is opaque |
| Only a finished run stating a version counts | A failed run says nothing; a deployment never finishing a scan is the quiet-build condition's |
| Measured from the most recent time any version was first seen | A returning version is no change; measured otherwise, an air-gapped re-import reads seven months stale, and two replicas on different versions flap (REQ-49) |
| Stopped after a setting, shipping at a week | A slow publisher is no alert; a feed nobody fetches is noticed within its week |
| One key however the data moves, its sentence rewritten to name the data in force | A key carrying the version clears and reopens while nothing changed |
| The version in force and when it last moved are read apart | One statement answering both gets the age wrong |
| The linked screen shows both | Otherwise it lands on the job queue |
| The CVE record snapshot a run read is asked the same, in the same condition, saying which stopped | Same kind of data. A deployment never reading a snapshot narrows nothing, which its screen says |

## Absent holders

An administrator is told when somebody has not signed in for a configured
period and still holds assigned work (REQ-45).

| Rule | Reason |
|---|---|
| Both halves are required | An unused account holding nothing is harmless |
| It asks rather than acts | Leave and departure look identical, and nothing detects departure |
| Never signed in counts as absent, from when they were added | Otherwise adding and assigning a colleague alerts at once |
| Counted in pieces of work | "6 items" meaning 288 findings looks like catastrophe |
| An open report held is one piece; a judged one none | A report is often told to its holder alone |

## Limits

| Limit | Detail |
|---|---|
| An alert carries a fact and a link, never the rows behind it | What it is about is read on a screen, under the reader's own visibility |
