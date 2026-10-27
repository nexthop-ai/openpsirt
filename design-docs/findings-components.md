# Components

What is kept about a component beyond its identity: who supplied it, its
license, how a scanner matched it, its declared scope, and the addresses a
reader is offered.

Satisfies REQ-08, REQ-13.

## Contents

- [Component interning](#component-interning)
- [Component suppliers](#component-suppliers)
- [Component licenses](#component-licenses)
- [Match methods](#match-methods)
- [Declared dependency scope](#declared-dependency-scope)
- [Derived addresses](#derived-addresses)
- [Index responses](#index-responses)
- [Limits](#limits)

## Component interning

A component identified by its content (REQ-08) is one row whoever writes it.

| Rule | Reason |
|---|---|
| The lookup is inside the writing transaction | A retry runs against a moved database |
| A row another writer got to first is left alone | A unique violation is not retryable, and two replicas applying two scans at once is the shipped arrangement |
| Identifiers are read back, never taken from the written rows | A skipped row carries none |

## Component suppliers

| Rule | Reason |
|---|---|
| From the inventory, never an index | It is what this build's producer said |
| Absent for most components, and said so | 759 of 6,866 on a switch image carry one |
| Two spellings in one format are resolved after the whole description is read; the object beats the plain string | Key order is the producer's choice |
| A party's kind prefix is dropped ("Organization: Debian"); the format's word for nobody is nobody | |
| Never part of identity | Producers name suppliers differently, and identity moving with it takes every decision along |
| A later report fills it where the row has none | `design-docs/findings-issues.md` § Report merging |

## Component licenses

Kept beside the supplier and shown on the component's page; 4,483 of 6,866
components on a switch image declare one. Asking a build which licenses it
ships is not built.

| Rule | Reason |
|---|---|
| As the producer wrote it: an SPDX expression or the producer's own name, untranslated | A translation is a license judgment nobody here made |
| Declared first, concluded where nothing is declared | A real producer declares NOASSERTION for most language packages and concludes from source |
| NOASSERTION and NONE are nothing stated | |
| Several licenses on one component are one conjunction: joined with AND, repeats dropped, producer's order; a compound entry is parenthesized; a name with spaces is one license | |
| An identifier beats a name beside it | Another tool can match it |
| A license element is resolved after the whole document is read | One format points at license elements in no fixed order, possibly at the license list's own address without describing it |
| Never part of identity; a later report fills a gap | As for suppliers |
| Bounded to 4,096 characters, cut on a character; the supplier likewise (REQ-69) | One component can list licenses to the document's size |
| Absent where nothing is stated, and a screen says so | A component scanned before the column existed carries none until a scan of a build shipping it |

## Match methods

A scanner reaches a finding two ways, which mean different things on a
distribution's package. The method is kept on the finding (REQ-13).

| Method | Meaning |
|---|---|
| By advisory | The packagers published one for this package in this ecosystem, counting their packaging, so its fix concerns the installed version |
| By identifier | An identifier against an upstream range. A backported fix leaves the upstream version unchanged, so it is neither confirmed nor refuted |

| Rule | Reason |
|---|---|
| The range and source are kept with the finding, compared against nothing | Comparing needs an ordering per ecosystem. The CVE record is read instead: `design-docs/findings-closure.md` § CVE record ranges |
| An unrecognized method reads as by identifier | An unchecked word must not read as authoritative |
| Unknown is not unconfirmed | Where a scanner said nothing, nothing is claimed |
| Kept on the finding, never the issue | One issue reached through two ecosystems has two answers |
| One answer per group | Every occurrence of an issue at a component comes from one report line |

## Declared dependency scope

A producer's stated scope is stored on the graph edge in the producer's own
word. Recorded, and read by nothing that decides anything.

| Where it is stated | Words |
|---|---|
| A CycloneDX component | `required`, `optional`, `excluded`, carried to the edges arriving at it |
| An SPDX 3 relationship | `build`, `design`, `development`, `other`, `runtime`; `hasOptionalDependency` with no scope is `optional` |
| An SPDX 2 relationship type | `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF` as `build`, `development`, `runtime`, `optional` |

| Rule | Reason |
|---|---|
| **Nothing acts on it**: no rank input, no prefilled outcome, no default narrowing, nothing hidden | `build` does not mean "does not ship": a compiled language links build-phase dependencies into the binary. Deciding is a person's |
| Recording is not inferring | It is a fact about the document received |
| The producer's own word, never folded onto one vocabulary | Folding is a reading |
| A word neither format defines is not recorded | Nobody can interpret or filter on it |
| The scope is part of the edge's identity | A changed scope closes the old edge and opens a new one |
| A pair declared twice takes the stated scope; two different scopes keep the first | |
| A test dependency places nothing and carries no word | Both readers drop that edge. The component is still held and scanned |

| Surface | What it does |
|---|---|
| A filter on the findings list | Asked of the component's incoming edges in the build, so a component under two scopes answers to both |
| An evidence line on the finding's dependency path | Beside its occurrence, next to the build's own VEX. Of two words, the earliest scan's, then the first in byte order |

## Derived addresses

Reading a finding offers addresses worked out from the identifiers held
(REQ-18): the issue's record under each of its names, the packaging
distribution's tracker, and the package's page in its ecosystem.

| Rule | Reason |
|---|---|
| Derived at read time, stored nowhere | A second copy of the templates falls behind |
| One table, on the server; the interface reads its answer, including the package's page on the component read | A second table sent Ubuntu packages to Debian's tracker |
| Kept apart from a report's references | Provenance is a different claim |
| Nothing is fetched | They are addresses handed to a person (REQ-69) |
| A name that is only dots is refused; everything else is escaped into its path segment (REQ-66) | The browser resolves `.` and `..` before sending |
| An identifier matches an anchored scheme before it resolves | A minted identifier must not reach a public page about something else |
| A package kind nothing here knows gets no link | A wrong link is followed before it is disbelieved |

| References rule | Reason |
|---|---|
| Patches first; a patch is guessed from the address shape (commit, pull request, diff), erring toward discussion | A backporter needs the change |
| References from every identifier the issue answers to are kept, deduplicated | A distribution's record points at its tracker; the fixing commits sit on the upstream record the scanner reports alongside |
| Two references are one where their addresses match apart from surrounding space; keyed by a digest | Addresses are case-sensitive past the host and longer than an index key |

## Index responses

Where an ecosystem has an index, the newest-version ask also reads one line
saying what the package is and where it is developed.

| Rule | Reason |
|---|---|
| One line, never the long description | Some indexes' description is the whole README: 2,894 characters for one ordinary package |
| The first paragraph of a markup description, on one line | Maven and nuget.org put a paragraph there |
| Absent is ordinary | One ecosystem's protocol has no such field, and distribution packages are not asked |
| The index's stated address beats one derived from the name | |
| Project pages before the repository; the first that may be stored wins | A home page of "UNKNOWN" falls through |
| Bounded and judged before storage: the summary cut on a rune; the address absolute, `http` or `https`, and held to the typed-link rules (REQ-66, REQ-69) | Third-party text rendered to the staff with most access |
| A refused half keeps the rest | |
| Maven Central costs a second request (the project document, which also gives the date); off unless turned on | |

A distribution package's description is not built: it lives in a per-release
index file, a different shape from per-package asks.

## Limits

| Limit | Detail |
|---|---|
| Scope is shown and never acted on | The largest deferral class a vendor has stays a person's decision |
