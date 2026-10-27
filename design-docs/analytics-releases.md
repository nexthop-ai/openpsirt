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
(REQ-51). A release note is usually about the last release a customer has, which
is rarely the previous one.

| Rule | Reason |
|---|---|
| Both builds are authorized | Authorizing one leaks findings out of another product |
| Public findings only unless asked; where the builds differ in what the reader may see, the narrower governs | The destination is usually a public document |
| Ordered worst first, stably | A note that reorders cannot be diffed |
| Bounded by the size of a build, never paged | Diffing means every open entry of both |
| What left the affected list is two sets. Fixes: an upgrade, a carried patch, a patch the build declares, a component no longer shipped, a recorded flaw declared fixed. Not fixes: a bump carrying the issue (`superseded`), a record taken back, a closure nothing explains | The last is a fault to investigate |
| The split is made once, where the release note and the remediation rate read it | A second judgment in a column heading puts unexplained closures under "Fixed" |
| An entry that left names the run that stopped reporting it, unless a person closed it | The first question about an unexplained closure is which run |
| Each fixed entry states why, from its closure reason, and what it moved to: "upgraded, 3.7.0 → 3.9.0" | The pair is written when the scan closes the finding, since the old component then leaves the inventory |
| A still-present entry carries the version its occurrence arrived from where the version moved since | It says whether somebody tried |
| Explanations are read once for the list, narrowed by issues and components separately and paired on the way out | A year-old baseline has as many fixed entries as the note is long; no engine here spells a comparison against a column pair alike |
| Each entry is rated as its own product rates it, each half by its own | This is the copy that leaves the building, and must agree with the findings list |

## The release note

The comparison as prose (REQ-51): markdown served as `text/markdown`, rendered on
the server, so an API caller and the screen read the same words. It carries what
was fixed and nothing else: not what is still present, not what newly appeared,
not a bump carrying the issue. A disposition belongs in the VEX document, which
a customer's scanner consumes; prose copies drift, and publishing "we deferred
this critical" is a disclosure act. The comparison screen, internal, keeps all
three sets.

| Rule | Reason |
|---|---|
| A line makes it re-checkable: the two builds, when the later was last measured, and the scanner and vulnerability-database versions | Databases ship bad data and are corrected |
| Dated by the measurement, not the request | Two readers then hold the same document |
| Builds are named by the catalog's display names | |
| Fixes are grouped by what was done: component, closure reason and version pair, with the issues closed listed under it | One kernel upgrade closes 917 issues; two upgrades of one component are two answers to "what do I move to" |
| A bullet carries the score, whether known exploited, and where it is written up | Whether to upgrade tonight. The address passes the rule for an address stored beside a decision and is written in angle brackets, so it names `http`, `https` or `mailto` or is left out |
| Every name, version, identifier, severity word, build name and scanner and database version is escaped where written, and only characters that open syntax there | Each was chosen upstream or by an uploader. `6.12.41-1` reads as written. `design-docs/text.md` § Rendered and escaped text |
| No description in the bullet | It is behind the link |
| An empty section is not written | |
| A release that fixed nothing says so in a sentence, naming the builds and what measured them | Nothing at all reads as a truncated or misdirected response |
| What was left out is counted: a number, never entries, and zero for a reader who could not have seen it | Otherwise no fixes and hidden fixes read alike |
| The count is of fixes by the listed entries' rule, through one function | A plain set difference calls an invalid, superseded or unexplained closure a security fix |

## Release readiness

A branch beside the last release cut from it: *8 criticals now, v2.4.1 shipped
with 4*. Both halves come from scans already collected. Counted as issues at
components, at or above the minimum severity, named beside the number (REQ-30).

| Rule | Reason |
|---|---|
| The same variant on both sides | Two chips differ and read as a regression |
| The release is the newest scanned tag cut from this branch; with none, the comparison is absent and says what is missing | A declared, unbuilt tag answering zero reports a clean release that does not exist |
| A tag is not compared against itself | |
| A build nothing has scanned answers that nothing is scanned there yet, including one whose every upload was refused | A refused upload names its build first; zeroes read as clean |
| The count carries its list, worst first, bounded to the worst few | Twenty rows of thousands is an arbitrary page; the linked list is where it is worked |
| The component name shrinks with an ellipsis, whole on the title | A Debian kernel package is forty-four characters |
| A row carries the version | A group is keyed on the fold, so one issue at three versions is three rows |
| Anything agreed to is absent from the list | Agreeing is deciding to ship with it. What remains is undecided, waiting or lapsed |
| Read through the findings list's own reader, at the same line | The list it opens is the list it counts |
| The link opens the list without its defaults | The count includes planned work, tags and end-of-life releases |

## Known issues at release

What a build still carries and what stands about each: the comparison's third
column, reached from the release comparison entry.

| Rule | Reason |
|---|---|
| A still-present row says how far it is decided, what was decided and when it is due | Approved not-applicable and never looked at are opposite answers to a sign-off |
| A standing decision is one in force: agreed, or needing nobody | The agreed count's test |
| The outcome is stated only where every standing decision over the row reaches the same one | Otherwise it states a decision nobody made. The VEX document's rule |
| The reason is stated only where one decision answered the row; agreement is about the outcome | Two recognized reasons still agree it does not apply |
| Decisions are told apart by identifier, never by their words | Two engines compare a bounded prefix of long text |
| The state is counted as the findings list counts it | |
| It narrows to what nobody has agreed to | The coordinator's blocker list |
| Read for still-present entries alone | Fixed needs no justification; new has not been looked at |

## Inheritance preview

Asked before a line is created, because a silent carry is one nobody reviews
(REQ-25).

| Group | Treatment |
|---|---|
| Reaches the new line by matching | Counted, never offered: these have happened. A correction stands at any version, so it counts whatever version the line holds |
| Held a decision at a version this line does not have | Offered as a proposal carrying the old reasoning, never as a standing decision |
| Deferrals | Offered separately, never carried by default |
| Past its date at an occurrence the line holds | Counted apart, since the finding is left with no answer. A carried decision keeps its date, so it cannot be carried |
| Covers nothing here | Counted and left behind |

| Rule | Reason |
|---|---|
| The product is read from the build, never from the caller | An occurrence carries no product, so matching alone returns undisclosed reasoning from another product |
| Both upstream versions are compared | Comparing one reports a build whose consumer moved as covered |
| A deferral states how long it has run across every line carried through, withdrawn ones excluded | Four carries of "not this release" are a year nobody decided |

## One issue across the estate

A document: the issue, every build carrying it, what was decided about each and
the argument behind it. A customer inquiry is answered from it.

| Rule | Reason |
|---|---|
| It is internal, and says so on its first line | It carries reasoning. The advisory or VEX document is what goes out |
| Markdown, served as markdown | It goes straight into a reply |
| Nothing affected is a document, not a refusal | "No" is the answer an inquiry usually wants |
| An unknown identifier and one only in unreadable products produce the same document | Otherwise it lists the issues held, one guess at a time |
| The description, other names and addresses are left out where a recorded flaw about the issue sits where the reader may not read | `design-docs/findings-flaws.md` § Recorded words on a shared issue |
| Every address passes the rule for an address stored beside a decision and names `http`, `https` or `mailto`; one carrying a space, control character or bracket is left out | In angle brackets anything else opens markup |
| Everything not checked at submission is escaped: identifier, description, severity, aliases, component, versions, product and person names | A reasoning passed the policy when typed and is written as it was |
| Bounded, saying when it is a page; over a page, how many decision occurrences stand and how many are recorded | A vendored component carries hundreds |
| The issue screen's product count is taken with its total before the limit, over what the reader may see | |

## Limits

| Limit | Detail |
|---|---|
| The release note carries no disposition | Dispositions are published in the VEX document alone |
