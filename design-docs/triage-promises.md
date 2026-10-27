# Promised work

Decisions promising work by a date: an upgrade of a component and a patch for
one issue, when a promise needs a second person, and what it covers.

Satisfies REQ-27, REQ-35.

## Contents

- [Planned upgrades](#planned-upgrades)
- [Promised work](#promised-work)
- [Approval gate](#approval-gate)
- [Covered work](#covered-work)

## Planned upgrades

One row per bump with what it would close, and one act answering it. A planned
upgrade is keyed on the upstream name, the version in hand and the fixing
version (REQ-35), the component name where no upstream is recorded. The key is
presentation. On a real image 5,047 fixable rows are 271 bumps, one kernel bump
closing 917; keyed on the upstream name, curl, `libcurl4t64` and `libcurl3t64`
bump once, which answers 2,831 of 7,612 rows at sibling packages.

| Rule | Reason |
|---|---|
| No build is in the key, and it proposes once per key | Per row, the second write collides with the one-live-decision index in every product with two builds |
| An occurrence undisclosed in one build and public in another carries the stricter | |
| The builds named, which are past end-of-life, and the occurrences reached are read inside the transaction | A retry re-runs against a moved database |
| One request, one transaction, one decision, written with the fix targets | |
| A named release past end-of-life refuses the whole as 422, "release X is retired" | |

A fix target is intent the next scan answers, so an upgrade that never lands is
reported.

## Promised work

| Outcome | About |
|---|---|
| `upgrade-needed` | A component: the version it moves to and the date, written in bulk for everything open on it in the declared builds |
| `patch-needed` | One issue, the version unmoved: the next inventory declares the patch and what it resolves |

| Rule | Reason |
|---|---|
| Neither is recordable at the other's grain: an upgrade from one finding is refused saying where to record it, and a backport naming a version is refused | |
| Both need the date | Nothing to gate or lapse otherwise |
| Both may stand, and the issue-grain decision wins where they disagree | |
| Coverage follows the source package: any binary or the source reaches all of them in the releases ticked, at each release's version, covering everything open on them | Whether 3.5.2 covers what 3.5.0 fixed needs an ordering; the scan says what the move answered |
| One source version per promise; naming none where a release ships two is refused, offering the versions | |
| A blank name reaches nothing | Every component naming no source holds it |
| A handover discloses by the same resolution, every visibility read across the source packages | An embargoed sibling binary makes the handover a disclosure |
| Source packages are read first, findings then read as a list of values, by the promise, the disclosure check and the component screen | After a large scan PostgreSQL misestimates a subquery and runs it per finding: 22 s against 1.9 s (`design-docs/triage-measurements.md` § Kernel upgrade promise) |
| Recorded on the component's screen: releases, version, date and why; releases needing different versions are two promises | |
| The carrier, a person or a team, is set in the same transaction, product-wide, and asked about every level in the set | Neither a promise nobody carries nor a holder with none can exist |
| The upgrade is reachable as a decision | |
| No bound on how much one promise covers; every other bulk check applies | One kernel bump is 4,485 findings across 44,016 occurrences, a cumulative bundle 243,945; capped, it records part of a bump |
| One transaction, never chunked nor a job | 243,950 occurrences take 7.5 s on SQLite, 5.5 s on MariaDB, 6.3 s on MySQL and 11.9 s on PostgreSQL; 44,030 take 1.0, 0.9, 1.8 and 2.1 s |

## Approval gate

Both outcomes hide risk; the date places the gate.

| Where the date falls | Effect |
|---|---|
| At or before the earliest deadline among what the act covers | No approval: nothing hides past what policy allowed |
| Past it | A second person agrees |
| Nothing covered has a deadline | A second person agrees; a product below its minimum severity is the ordinary case |
| No date | Not a commitment, and refused |

| Rule | Reason |
|---|---|
| Measured over the whole set | A critical in the act gates its mediums |
| The deadline is resolved with the occurrences, never supplied | A caller would choose whether they need a second person |
| One computation, the gate's | |
| The response says whether it waits | |

| Act | Deadline read |
|---|---|
| A decision on one finding | The earliest at that occurrence |
| A decision across builds | The earliest over every occurrence reached in every build named |
| An upgrade on a component | The earliest over the occurrences the bump reaches |

## Covered work

A covered finding is one a standing promise reaches, derived per build by a
join, never a stored mark.

| Rule | Reason |
|---|---|
| Derived per build | "Planned on master, not on the 2.4 branch" is the case |
| Withdrawing a promise uncovers what it covered | |
| Offered as a filter and its negation | |
| The by-issue list shows uncovered work by default; the by-component view is untouched | The component view is where an upgrade is managed |
| The default is in the address, a removable chip, and the parameter has a word for either | |
| Only the standing decision counts | |
