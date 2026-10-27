# Promised work

Decisions that promise work by a date: an upgrade of a component and a patch for
one issue, how one act answers a whole bump, when a promise needs a second
person, and what it covers.

Satisfies REQ-27, REQ-35.

## Contents

- [Planned upgrades](#planned-upgrades)
- [Promised work](#promised-work)
- [Approval gate](#approval-gate)
- [Covered work](#covered-work)
- [Limits](#limits)

## Planned upgrades

One row per bump with what it would close, and one act answering the whole of
it. A planned upgrade is keyed on the upstream name, the version in hand and the
version that fixes it (REQ-35), falling back to the component name where no
upstream is recorded; the version in hand is the upstream version where one is
recorded. The key is presentation, like every grouping here.

On a real image 5,047 fixable rows are 271 distinct bumps, and one kernel bump
closes 917. Keyed on the upstream name, curl, `libcurl4t64` and `libcurl3t64`
are one source package bumping once, which also answers the same issue at
sibling packages: 2,831 of 7,612 rows on that image.

| Rule | Reason |
|---|---|
| No build appears in the key, and the upgrade proposes once per key | A component at one version in two builds is one thing to decide and two findings. Proposed per row, the second write collides with the one-live-decision index, and every product with two builds refuses every upgrade naming a decision it has just written |
| Where an occurrence is undisclosed in one build and public in another, the one row there carries the stricter | |
| Everything it decides from is read inside the transaction: the builds named, which are past end-of-life, and the occurrences the bump reaches | A retry re-runs against a database that has moved |
| One request, one transaction, one decision, written with the fix targets | Half written declares a bump for a release it is not declared for |
| A release past end-of-life named in the request refuses the whole as 422, "release X is retired" | The caller may triage there; naming the release says which to drop |

It is safe at that size because a fix target is intent the next scan answers,
so an upgrade that never lands is reported. § Approval gate says when it needs
a second person.

## Promised work

| Outcome | About |
|---|---|
| `upgrade-needed` | A component. Carries the version it moves to and the date, and is written in bulk for everything open on the component in the declared builds |
| `patch-needed` | One issue, the version unmoved. The build's next inventory declares the patch and what it resolves, so the finding goes while the version stays, which no version comparison finds |

Without them the most common answer to a fixable finding, an upgrade, goes in as
`affected` with the plan in a separate record, and the decision and what a
release waits on come to disagree.

| Rule | Reason |
|---|---|
| Neither is recordable at the other's grain: an upgrade from a single finding is refused with the sentence saying where to record it, and a backport naming a version is refused | Moving no version is the whole difference |
| Both need the date | Otherwise nothing gates and nothing lapses |
| Both may stand at once, and the issue-grain decision wins where they disagree | An upgrade may not fix every issue on its component |
| Coverage follows the source package: naming any binary or the source reaches all of them in the releases ticked, at whatever version each ships, and covers everything open on them | Deciding that 3.5.2 covers what 3.5.0 fixed needs an ordering per ecosystem. A person claims the move answers what is open, and the scan says which was true |
| One source version per promise; one naming none where a release ships two is refused with the versions offered | Two versions are two pieces of code |
| A blank name reaches nothing | An empty source name is what every component naming no source holds |
| The same resolution decides how far a handover discloses: every visibility among what the promise covers is read across the same source packages | An embargoed finding on a sibling binary makes handing over the named one the disclosure |
| The source packages a name reaches are read first, and the findings against them as a list of values; the promise, the disclosure check and the component's screen all read this way | Statistics lag the table after a large scan until the server's refresh reaches it, and as a subquery PostgreSQL then runs it once per finding: 22 s against 1.9 s (`design-docs/triage-measurements.md` § Kernel upgrade promise) |
| Recorded on the component's screen: the releases ticked, the version, the date and why; releases needing different versions are two promises | |
| Who carries it, a person or a team, is set in the same transaction | A promise nobody carries and a holder with no promise are both impossible. The handover is product-wide, and the holder is asked about every level in the set |
| The upgrade is reachable as a decision | Its reasoning, approval and conversation live there |
| No bound on how much one promise covers; every other bulk check applies: who may decide, what each proposal carries, whom it is recorded as made by | One kernel bump on a real image is 4,485 findings across 44,016 occurrences, and a cumulative bundle 243,945; capped, a bump answers part of what it answers |
| One transaction, never chunked and never a job | The cap's other job was transaction size, measured on the act: 243,950 occurrences take 7.5 s on SQLite, 5.5 s on MariaDB, 6.3 s on MySQL and 11.9 s on PostgreSQL, from 44,030 at 1.0 s, 0.9 s, 1.8 s and 2.1 s. A deliberate one-off act at the largest size the data asks needs no chunk or queue |

## Approval gate

Both outcomes hide risk, so work with a plan and a date does not come round again
the next morning. The gate is placed by the date.

| Where the date falls | Effect |
|---|---|
| At or before the earliest deadline among what the act covers | No approval: nothing is hidden longer than policy already allowed, and the most routine act stays out of the queue |
| Past it | A second person agrees: the promise defers the worst thing it covers |
| Nothing covered has a deadline | A second person agrees: there is no date to be past. A product below its minimum severity is the ordinary case |
| No date at all | Not a commitment, and refused |

| Rule | Reason |
|---|---|
| Measured over the whole set, never per finding | One act covering a critical and a medium is gated by the critical |
| The deadline is resolved with the occurrences, never supplied | A caller stating it chooses whether their own promise needs a second person, as with the visibility and the versions |
| One computation, the one the gate uses | Two spellings of a separation-of-duties threshold disagree, and one goes unexecuted |
| The response says whether it is waiting | |

| Act | Deadline read |
|---|---|
| A decision on one finding | The earliest among the findings at that occurrence |
| A decision across builds | The earliest across every occurrence reached, in every build named |
| An upgrade on a component | The earliest among the occurrences the bump reaches |

## Covered work

What a promise covers is derived, never marked: a covered finding is one a
standing promise reaches, which the decision already records, so the mark is a
join.

| Rule | Reason |
|---|---|
| Derived per build | A label is per product and cannot say "planned on master, not on the 2.4 branch", the case the per-build target exists for |
| Withdrawing a promise puts what it covered back | No second record to keep in step |
| Offered as a filter and its negation | What is not covered is the working list once planned work is out of view |
| The by-issue list asks for uncovered work unless told otherwise; the by-component view is untouched | Deciding covered work again a finding at a time is what the promise replaced, and the component view is where the upgrade is managed |
| The default is written into the address, as a removable chip traveling with a link, and the parameter has a word for either | |
| Only the decision that currently stands counts | A withdrawn promise is not one |

## Limits

| Limit | Detail |
|---|---|
| A promise is checked by the next scan, never by a version ordering | Whether a bump answers a finding is the scan's to say; nothing here orders versions per ecosystem |
