# Version ordering

Which of two versions of one package is further along, per ecosystem, and the
counts a list of candidate upgrades shows.

Satisfies REQ-35.

## Contents

- [Candidate counts](#candidate-counts)
- [Ordered ecosystems](#ordered-ecosystems)
- [Published suites](#published-suites)
- [Version refusals](#version-refusals)
- [Limits](#limits)

## Candidate counts

The candidates for a component are the versions its open findings name as
their fix.

| Count | Meaning |
|---|---|
| What that release fixed | Open findings naming that exact version; needs no comparison |
| What reaching it closes | That, plus everything fixed at or before it; needs an ordering |

| Rule | Reason |
|---|---|
| A list is not ranked on what each release fixed | The version worth taking sinks: on the demo's kernel 158 of 168 open had a fix across 13 releases; 6.12.100-1 fixed 49, and the newest, 6.12.107-1, fixed 2 while carrying every earlier fix |
| Unranked, the two counts are equal | One version is never inferred to reach another |
| An ordering ranks candidates and never decides which findings apply or what a commitment covers | The scanner already matched the findings |

## Ordered ecosystems

Debian, RPM, Alpine, PEP 440, Maven, NuGet and dotted numeric releases are
ordered; everything else is left unordered.

| Rule | Reason |
|---|---|
| An ordering exists only where its algorithm is written down, never approximated | A guessed ordering is the confident wrong answer |
| An algorithm is transcribed from the project defining it | The tilde and caret rules, numeric runs outranking alphabetic ones, a leading zero turning a part into text are decisions, not deductions |
| A scheme is added by its own algorithm, never mapped onto one held; language ecosystems genuinely sharing one share it | Schemes differ in details that show only on untried pairs |
| The spelling decides, read from the package identifier, never the string's shape | A runtime on a language index may name itself after its own toolchain; two ecosystems spell some versions alike and order them differently |
| NuGet is not Semantic Versioning | A fourth number is compared, a missing one is zero, labels compare caselessly, and a label is a number only within a 32-bit integer, so a longer digit run is a word above every number. Whitespace is allowed around a number, never inside |
| Ordered ecosystems and indexed ones are separate lists | A distribution has an ordering and no index; an ecosystem may have an index and no ordering |

## Published suites

| Rule | Reason |
|---|---|
| A published suite is taken whole where its license permits: PEP 440's, Maven's and NuGet's | Somebody else chose the cases; three of Maven's tables are a bug report each |
| A taken case asserting nothing is left out, and says so | One NuGet "not equal" table compares strings, not versions, and one of its pairs is one version under NuGet's rule. Its strict-parser and formatting cases have no counterpart |
| Debian's, RPM's and Alpine's suites are GPL-licensed, so cases are written here instead: one per rule, each naming it, the ones reversing the obvious answer marked | This tree is Apache-2.0. A pair nobody here thought of is not covered |
| Every scheme has cases for what a security feed writes where a version belongs, and for the set one unreadable version leaves unranked | No reference implementation does |

## Version refusals

A wrong order is worse than none: somebody schedules a release around it, and
the scan catching it runs after the release.

| Rule | Reason |
|---|---|
| Every scheme can refuse, even those whose comparison answers for any two strings | Debian's, RPM's and Maven's walk any string, so "unfixed" outranked every release, a letter sorting above a digit |
| One refused version leaves the whole set unranked | |
| Where an ecosystem states what a version is, that is the rule | PEP 440 is a grammar |
| A Debian upstream version may hold a hyphen where a revision follows and a colon where an epoch precedes; the revision is cut at the last hyphen | Debian policy |
| A dotted numeric pre-release is non-empty identifiers of letters, digits and the hyphen; a Go pseudo-version passes | Semantic Versioning's rule |
| An empty dotted part, epoch or label is refused, except in Maven | Maven reads a separator with nothing before it as zero, and that is transcribed |
| Where an ecosystem states no rule, a version starts with a digit and holds only version characters | Debian states it and RPM follows. Maven states nothing, and its `RELEASE` and `LATEST` are not versions |
| Where a scheme's own tool falls back, this refuses, and a published suite's "invalid" list says which versions those are | Alpine sorts the unreadable as text and RPM orders any two strings, which suits resolving a dependency and not a recommendation |

## Limits

| Rule | Reason |
|---|---|
| Coverage of ecosystems is never complete | A product's deployers' ecosystems are unknowable, so the long tail stays unranked |
