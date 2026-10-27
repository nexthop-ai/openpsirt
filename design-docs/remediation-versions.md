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

Where a component could go is every version the findings open against it name
as their fix. Each candidate answers two counts.

| Count | Meaning |
|---|---|
| What that release fixed | How many open findings name that exact version: the release's own security content, with no comparison |
| What reaching it closes | That, plus everything fixed at or before it: the question somebody choosing between two versions asks, and the one needing an ordering |

| Rule | Reason |
|---|---|
| A list is not ranked on what each release fixed | The version worth taking sinks. On the demo's kernel, 158 of 168 open findings had a fix across 13 releases; 6.12.100-1 fixed 49, and the newest, 6.12.107-1, fixed 2 while carrying every fix before it |
| Unranked, the two counts are equal and say so | An exact match still counts. One version is never inferred to reach another, so nothing overstates what an upgrade closes |
| An ordering ranks candidates and never decides which findings apply or what a commitment covers | The scanner already compared versions to match the finding; what is added is which answer is furthest along |

## Ordered ecosystems

Debian's, RPM's, Alpine's, PEP 440's, Maven's, NuGet's and dotted numeric
releases are ordered. Everything else is left unordered.

| Rule | Reason |
|---|---|
| An ordering exists only where its algorithm is written down, and is never approximated | An ordering claimed before its algorithm exists is the confident wrong answer. Coverage cannot be complete for unknowable ecosystems, so an unranked list is the answer for the long tail |
| An algorithm is transcribed from the project defining it | The tilde and caret rules, a numeric run outranking an alphabetic one, a leading zero turning a part into text: each is somebody's decision, not something to reason out from a description |
| A scheme is added by adding its algorithm, never by mapping it onto one held | Every scheme differs in a detail that shows only on a pair nobody tried. The language ecosystems genuinely sharing a scheme share it |
| The spelling decides, not the ecosystem | A runtime published through a language index and naming itself after its own toolchain has that scheme and not the spelling |
| The scheme is read from the package identifier | Two ecosystems spell some versions identically and order them differently, so reading the string's shape orders a package by whichever scheme it resembles |
| NuGet is not Semantic Versioning | A fourth number is compared, a missing number is zero, labels compare without regard to case, and a label is a number only where it fits a 32-bit integer, so a longer digit run is a word sorting above every number. Whitespace around a number is allowed, inside one it is not |
| Ordered ecosystems and ecosystems with an index are separate lists | An index answers the newest version upstream, an ordering which of two is further along. A distribution has an ordering and no index; an ecosystem may have an index and no ordering until its algorithm is written down |

## Published suites

| Rule | Reason |
|---|---|
| A published suite is taken whole where its license permits: PEP 440's, Maven's and NuGet's | Somebody else chose the cases; three of Maven's tables are a bug report each, which nobody reading the format's description arrives at |
| A taken case asserting nothing is left out, and says so | One of NuGet's "not equal" tables compares the two strings, not two versions, so it passes any comparer, and one of its pairs is one version under NuGet's own rule. What the suite asks of its strict parser and formatting has no counterpart here and is left out too |
| A suite whose license forbids it is replaced by cases written here: a case per rule, the ones reversing the obvious answer marked | Debian's, RPM's and Alpine's are GPL-licensed and this tree is Apache-2.0, as the SBOM fixtures already answer. A pair nobody here thought of is not covered, so each case names the rule it pins |
| Every scheme is given cases for what a security feed writes where a version belongs, and for the candidate set one unreadable version leaves unranked | A reference implementation raises on anything but a version, so no taken suite has them |

## Version refusals

A wrong order is worse than none: it arrives as a recommendation somebody
schedules a release around, and the scan catching it runs after the release.

| Rule | Reason |
|---|---|
| Every scheme can refuse, including those whose comparison answers for any two strings | Debian's, RPM's and Maven's walk any string, so "unfixed" or a sentence outranked every release, a letter sorting above a digit, and was offered as the upgrade closing the most. Each scheme decides what its version looks like before comparing |
| One version a comparison refuses leaves the whole set unranked | A list ordered except for the entry nobody could place is not ordered |
| Where an ecosystem states what a version is, that is the rule | PEP 440 is a grammar, and a string it does not match is not a version |
| A Debian upstream version may hold a hyphen where a revision follows, and a colon where an epoch precedes | Debian policy's own rule. The revision is cut at the last hyphen and holds neither |
| A dotted numeric pre-release is identifiers, none empty, of letters, digits and the hyphen | Semantic Versioning's rule; an empty pre-release, empty identifier or space is text after a hyphen. A Go pseudo-version passes |
| An empty part is not a zero, in any scheme but Maven's | An empty dotted part, epoch or label is refused. Maven's own comparison reads a separator with nothing before it as a zero, and that is transcribed |
| Where an ecosystem states no rule, a version starts with a digit and holds only the characters a version may | Debian's policy states it and RPM follows the shape. Maven states nothing, and its stand-ins `RELEASE` and `LATEST` are not versions |
| Where a scheme's own tool falls back, this refuses | Alpine sorts what it cannot read as text and RPM orders any two strings; both suit a package manager that must resolve, and neither a recommendation. A published suite's own "invalid" list says which versions those are |

## Limits

| Rule | Reason |
|---|---|
| An ecosystem with no written ordering stays unranked | Its candidates show both counts equal |
