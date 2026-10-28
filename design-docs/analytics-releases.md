# Release figures

What changed between two builds, the release note made of it, whether a branch
is ready to release, what a new line inherits, and one issue across every build.

Satisfies REQ-25, REQ-30, REQ-51.

## Contents

- [Build comparison](#build-comparison)
- [The release note](#the-release-note)
- [Release readiness](#release-readiness)
- [Known issues at release](#known-issues-at-release)
- [Inheritance preview](#inheritance-preview)
- [One issue across the estate](#one-issue-across-the-estate)
- [Limits](#limits)

## Build comparison

Fixed, newly present and still present between any two builds of one product
(REQ-51), since a customer is rarely on the previous release.

| Rule | Reason |
|---|---|
| Both builds are authorized | |
| Public findings only unless asked; where the builds differ in what the reader may see, the narrower governs | It usually feeds a public document |
| Ordered worst first, stably; never paged | |
| What left the affected list is two sets. Fixes: an upgrade, a carried patch, a declared patch, a component no longer shipped, a recorded flaw declared fixed. Not fixes: `superseded`, a record taken back, a closure nothing explains | |
| An entry that left names the run that stopped reporting it, unless a person closed it | |
| A fixed entry states why, and what it moved to: "upgraded, 3.7.0 → 3.9.0" | The pair is written at closure, before the old component leaves the inventory |
| A still-present entry carries the version its occurrence arrived from where it moved, on the still-present column only | It says whether somebody tried |
| Explanations are read once for the list, narrowed by issues and components separately and paired on the way out | No engine here spells a column-pair comparison alike |
| Each half is rated as its own product rates it | |

## The release note

The comparison as markdown, served as `text/markdown` and rendered on the server
(REQ-51). It carries only what was fixed. Dispositions belong in the VEX
document; the comparison screen keeps all three sets.

| Rule | Reason |
|---|---|
| The line under the heading makes it re-checkable: the two builds, the day the later was last measured, and the scanner and vulnerability-database versions | Databases ship bad data and are corrected |
| Dated by the measurement, never the request | |
| Builds are named by the catalog's display names | |
| Fixes are grouped by component, closure reason and version pair, the issues closed listed under it | One kernel upgrade closes 917 issues |
| A bullet carries the score, whether known exploited, and an address written in angle brackets that names `http`, `https` or `mailto` by the rule for an address beside a decision, or is left out | |
| Every name, version, identifier, severity word, build name and scanner and database version is escaped where written, only where a character opens syntax there | `design-docs/text.md` § Rendered and escaped text |
| No description in the bullet; no empty section | |
| A release that fixed nothing says so in a sentence, naming the builds and what measured them | |
| What was left out is counted, a number and never entries, zero for a reader who could not have seen it, by the listed entries' rule through one function | |

## Release readiness

A branch beside the last release cut from it: *8 criticals now, v2.4.1 shipped
with 4*, from scans already collected, as issues at components at or above the
minimum severity, named beside the number (REQ-30).

| Rule | Reason |
|---|---|
| The same variant on both sides | |
| The release is the newest scanned tag cut from this branch; with none, the comparison is absent and says what is missing | Zeroes report a clean release that does not exist |
| A tag is not compared against itself | |
| A build nothing has scanned, or whose every upload was refused, says nothing is scanned there yet | |
| The count carries its list, worst first, bounded to the worst few; the linked list is where it is worked | |
| The component name shrinks with an ellipsis, whole on the title | |
| A row carries the version | A group is keyed on the fold |
| Anything agreed to is absent from the list | Agreeing is deciding to ship with it |
| Read through the findings list's reader at the same line, and linked without the list's defaults | The list it opens is the list it counts |

## Known issues at release

The comparison's third column, reached from the release comparison entry: what
a build still carries and what stands about each.

| Rule | Reason |
|---|---|
| A still-present row says how far it is decided, what was decided and when it is due | |
| A standing decision is one in force: agreed, or needing nobody | |
| The outcome is stated only where every standing decision over the row reaches the same one | The VEX document's rule |
| The reason is stated only where one decision answered the row | Two reasons can agree on an outcome |
| Decisions are told apart by identifier, never by their words | Two engines compare a prefix of long text |
| The state is counted as the findings list counts it | |
| It narrows to what nobody has agreed to | The coordinator's blocker list |

## Inheritance preview

Asked before a line is created, because a silent carry is one nobody reviews
(REQ-25).

| Group | Treatment |
|---|---|
| Reaches the new line by matching | Counted, never offered; a correction counts at any version |
| Held a decision at a version this line does not have | Offered as a proposal carrying the old reasoning |
| Deferrals | Offered separately, never carried by default |
| Past its date at an occurrence the line holds | Counted apart; a carried decision keeps its date, so it cannot carry |
| Covers nothing here | Counted and left behind |

| Rule | Reason |
|---|---|
| The product is read from the build, never the caller | An occurrence carries no product |
| Both upstream versions are compared | |
| A deferral states how long it has run across every line carried through, withdrawn ones excluded | Four carries of "not this release" are a year |

## One issue across the estate

A markdown document answering a customer inquiry: the issue, every build
carrying it, what was decided about each and the argument.

| Rule | Reason |
|---|---|
| It is internal, and says so on its first line | It carries reasoning |
| Nothing affected is a document, not a refusal | |
| An unknown identifier and one only in unreadable products produce the same document | |
| The description, other names and addresses are left out where a recorded flaw about the issue sits where the reader may not read | `design-docs/findings-flaws.md` § Recorded words on a shared issue |
| Every address names `http`, `https` or `mailto` by the rule for an address beside a decision; one carrying a space, control character or bracket is left out | |
| Everything not checked at submission is escaped; a reasoning is written as typed | |
| Bounded, saying when it is a page and, over a page, how many decision occurrences stand and how many are recorded | |
| The issue screen's product count is taken before the limit, over what the reader may see | |

## Limits

| Limit | Detail |
|---|---|
| One split of fixes from non-fixes | The comparison, the release note and the remediation rate read it, so no column heading judges a second time |
