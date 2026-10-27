# Code finding matching

How a run's results are paired with the code findings a series already holds,
carried across builds, and kept through a change of fingerprint.

Satisfies REQ-08, REQ-25.

## Contents

- [Matching](#matching)
- [Keys](#keys)
- [Layers](#layers)
- [Carrying](#carrying)
- [Fingerprint change](#fingerprint-change)
- [Limits](#limits)

## Matching

Identity is computed here (REQ-08). A fingerprint a document carries is one
input to a key, never a key by itself. A run is paired with the code findings
its series holds open on the build, one to one; a result nothing on the build
takes is carried from elsewhere (§ Carrying) or opens at a new occurrence.

## Keys

| Key | Digest of | Strength |
|---|---|---|
| Whole | The rule, the path, the fingerprint or else the line, the message without digits, the enclosing function and the call chain | Strong |
| Unprinted | The whole key without fingerprint or line. Compared on a fingerprint change alone, where one result and one code finding hold it | Strong |
| Function | The rule, the path, the message without digits, and the enclosing function. Absent where the output names no function | Probable |
| Line | The rule, the path and the message without digits, compared with the nearest line | Probable |

| Part | Taken as |
|---|---|
| The rule | As filed, `<tool>/<rule>` |
| The path | Relative to the checkout |
| The fingerprint | The first of `openpsirt/context/v1`, `clang/issueHash/v1`, `hash/v1`, `primaryLocationLineHash`, then any other in name order |
| The message without digits | A message quoting a line number or count changes when lines move |
| The call chain | The functions the result's flow passes through, each once where consecutive steps share it |

## Layers

Pairing runs a layer at a time, each on what the layers before left: the whole
key, the unprinted key on a fingerprint change, the function, then the nearest
line.

| Rule | Reason |
|---|---|
| A code finding the last comparable run did not see is a candidate in every layer | Of 28 absences hand-checked, 5 came back a build or two later. One it saw comes first where a layer cannot tell two apart |
| The line layer offers a result the eight code findings sharing its line key nearest its line | A generated file repeating one message holds thousands of results under one key, and offering each all of them is quadratic |
| Each code finding records how its newest sighting was paired: whole key, unprinted key, function or line | A dismissal carries on a strong pairing and lapses on a probable one (`design-docs/analysis-triage.md` § Code finding triage) |

## Carrying

A result no open code finding on the build took is the same result as a code
finding the series holds elsewhere where one of these finds it, and opens at
that code finding's occurrence, so a decision keyed on the occurrence reaches
it (REQ-25).

| Order | Where | How |
|---|---|---|
| 1 | Code findings open on the same variant's build in the branch this one was cut from, on the series' first run on the build | Every layer, and the unprinted key where the run is a fingerprint change against that build. A new branch inherits what its line decided |
| 2 | A closed code finding on this build | The whole key; the same flaw found again opens a new code finding at the closed one's occurrence |
| 3 | Any code finding of the series on another build, open or closed | The whole key, oldest first. A probable pairing with a code finding this build never saw is a guess |

A result found nowhere opens at an occurrence derived from the series and its
whole key, so one result first seen on two builds at once is one occurrence.

## Fingerprint change

A run records the fingerprint schemes its keys were built from, and the mark of
the salt the client used. A run whose record differs from the newest run applied
to the build that reported anything is a **fingerprint change**. The series'
first run on a build cut from another branch is compared with the newest such
run on the parent build.

| Rule | Reason |
|---|---|
| A run reporting nothing records nothing | It says nothing about fingerprinting, and would make the next run a change |
| `none` is recorded only where no result carried a fingerprint | One unhashable result coming or going says nothing about the run |
| The salt is recorded as the client states its mark, a short digest | A rotated salt changes every fingerprint and no scheme name |
| A fingerprint change says so on its receipt | Its whole keys no longer meet the code findings' |
| A fingerprint change pairs a result and a code finding on the unprinted key where they alone hold it, strongly | A rotation changes every fingerprint and nothing else, so the dismissal carries |
| A result or code finding sharing its unprinted key with another falls to the probable layers | The fingerprint told them apart, so their dismissals lapse |
| The unprinted key is compared on a fingerprint change alone | On any other run a changed fingerprint is the analyzer saying the result changed |
| Carrying from a closed code finding or another build stays on the whole key on a fingerprint change | A result carried across a rotation opens there as a new code finding |
| Carrying from the parent build on a fingerprint change pairs on the unprinted key, as the build's own are paired | A branch cut after a rotation inherits its line's decisions |

## Limits

| Limit | Detail |
|---|---|
| A moved result with no fingerprint and no function is matched on its line alone | clang-tidy, and clang before 22, give rule, path, line and message. A line moved above such a result pairs it probably with the nearest code finding of the same rule and message, and two moving past each other can swap |
| A new variant inherits on the whole key alone | Carrying by every layer is from the branch a tag was cut from; a variant's first run takes a sibling variant's occurrences where whole keys are equal |
| A result whose whole key equals a moved code finding's first key opens at its occurrence | Occurrences are minted from the first key a series saw; equal rule, path, fingerprint and message is one flaw reported twice |
| Two identical results in one build share an occurrence | A decision on one reaches the other; they are one flaw reported twice |
| A renamed file's results open as new code findings | Every key holds the path, so the old ones go no longer detected and nothing carries their decisions |
| Coverity's native JSON is not read, so its SARIF is matched as plain SARIF | Its `mergeKey` is in the JSON and lost in the SARIF |
