# Code finding matching

How a run's results pair with the code findings a series holds, carry across
builds, and survive a fingerprint change.

Satisfies REQ-08, REQ-25.

## Contents

- [Matching](#matching)
- [Keys](#keys)
- [Layers](#layers)
- [Carrying](#carrying)
- [Fingerprint change](#fingerprint-change)
- [Limits](#limits)

## Matching

Identity is computed here (REQ-08); a document's fingerprint is one key input,
never a key. A run pairs one to one with the code findings its series holds
open on the build; an unpaired result is carried from elsewhere or opens at a
new occurrence.

## Keys

| Key | Digest of | Strength |
|---|---|---|
| Whole | Rule, path, fingerprint else line, message without digits, function, call chain | Strong |
| Unprinted | The whole key without fingerprint or line, on a fingerprint change alone, where one result and one code finding hold it | Strong |
| Function | Rule, path, message without digits, function; absent with no function | Probable |
| Line | Rule, path, message without digits, nearest line | Probable |

| Part | Taken as |
|---|---|
| Rule | `<tool>/<rule>` as filed |
| Path | Relative to the checkout |
| Fingerprint | The first of `openpsirt/context/v1`, `clang/issueHash/v1`, `hash/v1`, `primaryLocationLineHash`, then any other by name |
| Message without digits | Quoted line numbers and counts move |
| Call chain | The flow's functions, consecutive repeats once |

## Layers

Whole key, the unprinted key on a fingerprint change, function, then nearest
line, each on what the last left.

| Rule | Reason |
|---|---|
| A code finding the last comparable run missed is a candidate in every layer; one it saw comes first on a tie | Of 28 absences hand-checked, 5 returned within two builds |
| The line layer offers the eight nearest code findings sharing the line key | A generated file holds thousands under one key |
| Each sighting records its pairing layer | A dismissal carries on strong and lapses on probable (`design-docs/analysis-triage.md` § Code finding triage) |

## Carrying

An unpaired result is the same as a series code finding elsewhere where one of
these finds it, and opens at that occurrence, so its decision reaches it
(REQ-25).

| Order | Where | How |
|---|---|---|
| 1 | Open on the same variant in the parent branch, on the series' first run on the build | Every layer, and the unprinted key on a fingerprint change against it |
| 2 | Closed on this build | Whole key; a new code finding at the closed occurrence |
| 3 | The series on another build, open or closed | Whole key, oldest first; a probable guess is not taken |

A result found nowhere opens at an occurrence derived from series and whole
key, so first seen on two builds at once it is one occurrence.

## Fingerprint change

A run records its fingerprint schemes and the client's salt mark. Differing
from the newest applied run on the build that reported anything is a
**fingerprint change**; a series' first run on a branch compares with the
parent build's.

| Rule | Reason |
|---|---|
| A run reporting nothing records nothing | It would make the next run a change |
| `none` is recorded only where no result had a fingerprint | |
| The salt is recorded as the client's short digest mark | A rotation changes no scheme name |
| The receipt says so | Whole keys no longer meet |
| A result and a code finding alone holding an unprinted key pair strongly | A rotation changes only fingerprints, so dismissals carry |
| Shared unprinted keys fall to the probable layers | Their dismissals lapse |
| The unprinted key is compared on a fingerprint change alone | Otherwise a changed fingerprint means a changed result |
| Carrying from closed code findings or other builds stays on the whole key | |
| Carrying from the parent build pairs on the unprinted key | A branch cut after rotation inherits its line's decisions |

## Limits

| Limit | Detail |
|---|---|
| A moved result with no fingerprint and no function matches on its line alone | clang-tidy, and clang before 22. It pairs probably with the nearest same rule and message, and two passing each other can swap |
| A new variant inherits on the whole key alone | Every layer carries only from the parent branch; a variant's first run takes a sibling's occurrences on equal whole keys |
| A result equal to a moved code finding's first whole key opens at its occurrence | Occurrences mint from the first key; it is one flaw reported twice |
| Two identical results in one build share an occurrence | |
| A renamed file's results open as new | The path is in every key, so decisions do not follow |
| Coverity is matched as plain SARIF | Its `mergeKey` is lost outside its JSON |
