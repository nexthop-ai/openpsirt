# Code finding queue

How a product's code findings are listed, ordered, counted and written out,
the weakness families the order rests on, and code findings two analyzers
report as one flaw.

Satisfies REQ-17, REQ-30, REQ-42, REQ-43, REQ-50, REQ-56, REQ-64.

## Contents

- [Code finding queue](#code-finding-queue)
- [Queue across products](#queue-across-products)
- [Queue file](#queue-file)
- [Code findings by series](#code-findings-by-series)
- [Code findings of a component](#code-findings-of-a-component)
- [Weakness families](#weakness-families)
- [Grouped code findings](#grouped-code-findings)
- [Limits](#limits)

## Code finding queue

One row per code finding however many builds hold it, showing the newest
finding: rule, path, line, function, message, build and state
(`design-docs/analysis-triage.md` § Code finding states).

| Order | Reason |
|---|---|
| The tier of the rule's weaknesses, highest first | Memory safety above style |
| Whether another analyzer reports the same flaw on the build | Two tools agreeing is the strongest sign |
| The tool's security severity for the rule, 0 to 10, highest first, none last | CodeQL and semgrep rate rules |
| The tool's precision: `very-high`, `high`, `medium`, `low`, none | |
| Newest first | |

Whether a path ships orders nothing; a suppression rule naming the path takes
its code findings out.

| List | Holds |
|---|---|
| No state named | The queue: open code findings with no decision waiting for a second person |
| A state named | That state; fixed is those closed on a build and not reopened there |

| Rule | Reason |
|---|---|
| Every list counts its scope by state, the open ones a waiting decision leaves out, and the dismissed ones a rule covers | A list leaving things out says how many (REQ-30) |
| One open on two builds in two states counts in both | |
| Only what the subject may read is listed or counted (REQ-42, REQ-43) | |
| A branch or tag and a variant narrow independently | |
| A series narrows by name, ignoring capitals; an unknown name lists nothing | |
| A testing method narrows to its kind; the filter offers every method known, and an unrecorded one is refused by name | SAST, the analysis kind, is the one recorded |
| Narrowed to unheld work, it keeps code findings with no holder on each row's build, under the findings list's parameter, and every count follows | The findings list holds no code finding |
| A component narrows to the code findings placed on a source package, by a binary's name or the source's, ignoring capitals; a version narrows to the source version it was built at, and every count follows | The component screen names a source package (`design-docs/interface-component.md` § The component screen) |
| A name reaches the folds of the live components of the name, or built from a source of the name, in the builds in scope, read once and bound as values | A name only another product ships is no source package here; as a subquery, MySQL probed the fold index once per code finding: 342 ms against 56 ms bound as values for one name at 16,000 components a build |
| A name also reaches the folds of every component of the name, or built from a source of the name, holding a finding in the builds in scope, whatever version a rescan has since replaced | A code finding keeps the component it opened on (`design-docs/analysis-source.md` § Placement); the finding's component index answers which hold one, and the node history has no index by component |
| A name naming a build's root reaches every component that was ever that build's root | A code finding keeps the component it opened on, and a root a rescan replaced is still the build (`design-docs/analysis-source.md` § Placement) |
| Beneath a component narrows to one build and the code findings placed at the component or anywhere under it, by the tree's walk, and every count follows (REQ-56) | A tree count opens the list it counts |
| Beneath the build's root is every code finding of the build | The root adopts what hangs from nothing, which no edge from it reaches, and a former root is no node the walk reaches; walking 16,000 children of the root took 2.48 s on PostgreSQL, against 143 ms reading the build |
| Beneath is refused without one build; a name the build does not hold answers not found, after the reader is authorized (REQ-42) | An empty list is a clean subtree, and a refusal after resolving a name is a directory |
| A rule's rating is the newest naming run's, held until rated again | |
| A rule's tier is the highest of every weakness recorded for it, re-ranked each run naming it | |
| A severity outside 0 to 10 or not a number, and an unknown precision, are none | |

## Queue across products

`GET /v1/code-findings` lists the code findings of every product the reader
reads security testing material in (REQ-43), as one queue: the same rows,
order, states, filters and counts as a product's queue, each row naming its
product.

| Rule | Reason |
|---|---|
| The products are those the reader holds `security-testing-read` in; a product read no other way contributes nothing, and a reader holding it nowhere is answered an empty queue | A flaw's reader reads one code finding, never a product's queue |
| Every state and count is the sum of each product's own, row for row | One population, split by product |
| Each product's state is worked out against that product: the rules that cover it, the outcome standing for it and its flaw records are its own | A rule or a decision belongs to one product |
| The component and version filters, the method, the series, the state and unheld work narrow as they do in one product | |
| Beneath is refused, since it names one build | The list across products refuses it the same way (`design-docs/api-lists.md` § Issue-keyed and cross-product reads) |
| A pipeline key is refused | It sends scans and reads nothing |
| `GET /v1/code-findings.{format}` writes it, under the rules of the queue file | |

## Queue file

`GET /v1/products/{product}/code-findings.{format}` writes the list as CSV or
JSON (`design-docs/analytics-exports.md` § Exports).

| Rule | Reason |
|---|---|
| The file is the list, every row, same filters and order, same visibility (REQ-42, REQ-43) | One read |
| A row names the holder (who, display name, whether a team's queue) and whether third-party, from the newest run seeing it | A team and a person may share a name |
| A row names the component it is placed on, its version while the build still ships it and whether it is the build itself, on the row's build (`design-docs/analysis-source.md` § Placement) | |
| A row names its product, in the last column of the CSV | The queue across products writes the same file |
| No row carries source text | |
| With no state named, the file says it lists the queue; narrowed to unheld work, it says so | An empty query reads as everything |
| A refusal is answered before the first byte | |
| A findings list's file writes the open code findings of its selection below its findings, through this read, keeping those a decision waits on | The finding exports include them (REQ-50) |

## Code findings by series

`GET /v1/products/{product}/code-finding-series` counts code findings per
analyzer series by state, drawn as Code findings by analyzer
(`design-docs/analytics-catalog.md` § Pages of the catalog's own).

| Rule | Reason |
|---|---|
| Every state counts, zero included, beside those a waiting decision leaves out and those a rule covers | |
| Each count is the list's total for that series and state | One population |
| Counted over every build | Narrowed, a series never run there shows zeros like a clean one |
| A series with no code finding is listed with zeros | |
| Only `security-testing-read` on the product reads it; anybody else is refused naming no count or series | Counts are at security testing visibility; a flaw's reader reads one code finding, not the figures |
| Ordered by series name | |

## Code findings of a component

Every count that opens a list is the queue's own read for the same reader,
narrowed by component, so it is the length of the list it opens. Code
findings are counted by occurrence, once however many builds hold one
(REQ-17). Only `security-testing-read` on the product reads any of them,
through one check every read shares; anybody else is refused naming no count,
before any component name is resolved (REQ-42, REQ-43).

| Read | Counts |
|---|---|
| `GET /v1/products/{product}/components/{component}/code-finding-counts` | Every series of the product by state, zero included, over every build; the open ones placed on a build's own root, as unplaced; and the open ones per build and source version |
| The tree's components and one step around a component, with `code_findings` | Open code findings on each row's component and at it or under it, one build |
| `GET .../components/{component}/code-finding-trend` | Per week on one build: the code findings at the component or under it not fixed at its end, and those opened and fixed in it |
| `GET /v1/components?q=` | Open code findings on each source package a term matches, beside its open issues, in every product the reader reads where none is picked (REQ-64; `design-docs/interface-shell.md` § The search box) |

The trend reads the findings themselves, never the queue's state, because its
line keeps what a decision answered. The chooser's issue count is the
findings lists' read of open issues.

| Rule | Reason |
|---|---|
| Open is the queue's open state, a decision waiting included | The list a count opens holds them |
| Unplaced is the code findings on every component that was ever the root of a build whose root the name names: what no repository the build is built from holds (`design-docs/analysis-source.md` § Placement); zero for any other name | The root is a component, so the tree counts them on its root row |
| Unplaced is counted over the roots named as values | Asked of every code finding on the component, whether it was ever a root took 339 ms on MySQL 8.4 for the root's card at 16,000 components a build, against 23 ms as values |
| Under a tree row is the union of the occurrences on everything the walk reaches from it, each once | A code finding placed on a library pulled in twice is one |
| On the tree's root row are the code findings on every root the build has had, and under it every code finding of the build | The list the badge opens is the whole build |
| A code finding on a component the build no longer holds counts at the build's live components of the same name: on them, beneath every row that reaches them, in the list beneath them and in their trend. A replaced root is left to the root, which counts every root the build has had | A code finding keeps the component it opened on, so a rescan at a new version replaces the component and not the finding (`design-docs/analysis-source.md` § Placement); at 4,000 components a build, the tree's first screen took 251 ms against 268 ms on MySQL 8.4 and 627 ms against 630 ms on PostgreSQL |
| A tree read reaching no component reads no code finding | The read takes no components as the whole build |
| A chooser match counts what its name reaches in the match's builds, each code finding or issue once per name however many folds and binaries hold it | Joined once per binary, a kernel of ten binaries sorted ten rows for each it counted: 718 ms on PostgreSQL and 913 ms on MySQL 8.4 at 16,000 components a build, against 228 ms and 225 ms once per name |
| A tree count is asked for only with `code_findings`; asked by a reader not reading security testing material, the read is refused | A count not drawn is not asked for |
| The trend's line is not fixed: from opening until a person closes it as fixed; a decision answers a code finding and closes nothing, and absence closes nothing | Ruling a code finding not a problem keeps its record; the line counts what remains in the code |
| Opened and fixed are the difference between one week's set and the last, so the three numbers agree | |
| Plotted on when a run was applied, as the dependency trend is | |
| The weeks are 1 to 104, twelve unless named | |
| A chooser match in a product where the reader does not read security testing material carries no code finding count; one where they read no dependency finding carries no issue count | Absent is never zero (`design-docs/interface.md` § Families a reader holds) |

## Weakness families

A rule names the weaknesses its tags name, as `external/cwe/cwe-N` or semgrep's
`CWE-N: name`, else those a table here names. Tools disagree on numbers (one
overflow was CWE-788, 119 and 121) and agree on families.

| Tool | Weaknesses from |
|---|---|
| CodeQL, semgrep | Rule tags |
| cppcheck XML | Tags the upload client writes from each error |
| cppcheck SARIF | Rule tags, except releases 2.16 to 2.18, which tag `security` only; a table from `cppcheck --errorlist` by `make cppcheck-weaknesses` covers 302 checks of 2.22.0 |
| clang, and clang checkers clang-tidy runs | A table here over the 47 checkers clang 18 runs on C, none where no weakness fits with confidence; `make clang-checkers` names new ones |

| Rule | Reason |
|---|---|
| A family is the nearest class up the primary parents in the research view, or the weakness itself if a class or pillar | CWE-121, 122, 126, 787, 788, use after free and double free are all CWE-119 |
| A pillar is nobody's family; below a pillar with no class, the weakness just under it is | CWE-710 directly holds a null dereference, an always-true condition and an obsolete function, which 26 rules shared; cppcheck's CWE-467 and clang's CWE-131 meet at the base under CWE-682 |
| An unplaced weakness is its own family | A newer catalog numbers more |
| `make weakness-names` reads the hierarchy from the published catalog and commits it (`design-docs/build.md` § Make targets) | |
| A clang checker reporting several kinds names each | unix.Malloc is in the resource and bounds families |
| Tags, where present, classify alone | |

A weakness's tier is the nearest named one of itself and its ancestors; a
weakness named here outranks its class. The table is a judgment no decision
records, for C and C++.

| Tier | Names |
|---|---|
| Memory safety | CWE-119, a bound overrun, with use after free and double free; CWE-476, a null pointer, filed under coding standards; CWE-824, CWE-908 and CWE-457, read before written; CWE-190, a wrapping integer; CWE-134, a caller's format string |
| Input reaching where it should not | CWE-74, CWE-77, CWE-943, injection; CWE-20, unvalidated input; CWE-706, a name resolved wrongly; CWE-362, a race |
| A resource or error unhandled | CWE-404, unreleased; CWE-754, unchecked condition; CWE-665, bad initialization; CWE-834, unbounded iteration; CWE-682, bad calculation |
| Everything else | Style, dead code, an unnamed weakness, none |

## Grouped code findings

Each analyzer's result stays its own code finding. Two are the same flaw where
all hold:

| Condition | Reason |
|---|---|
| Open on one build | |
| Different analyzers: the rule name before the first `/`, any case, a clang-tidy clang checker counted as clang | clang-tidy runs clang's analyzer |
| Weaknesses sharing a family | |
| Last places in one file within two lines | cppcheck marks the start, others where it bites: first places differed in 8 of 41 same-flaw pairs, last in 2 |

Two lines grouped every same-flaw pair of clang, cppcheck, CodeQL and semgrep
over libyaml, jq, Lua, giflib and seeded files, and none of five pairs of flaws
a line or two apart; wider, or by first place, at least one merged falsely.

| Rule | Reason |
|---|---|
| A last place is the path's last step, the last related place in its own file, or its own place | cppcheck lists later places as related |
| Within ten lines and otherwise alike is Possibly also found by, never grouped | A false merge hides a real flaw |
| The evidence lists both, where the reader may read them (REQ-42) | |
| A group is a code finding and those within two lines of it, per code finding | Two at four lines apart sharing a third are two groups |
| Whether another analyzer agrees is worked out over the whole build | Order does not depend on the reader |
| Nearby code findings are found through an index on a digest of the last path, and the last line | No MySQL index takes a path whole. 16,000 code findings: 0.6 s on PostgreSQL 16 and 1.2 s on MySQL 8.4, against 90 s and 37 minutes without |
| A rule with no weakness groups with nothing | |
| A decision covers its code finding and every unanswered one of its group, agreed once | |
| Excluded from that: answered, waiting, under a rule, fixed, recorded as a flaw, past end of life, unreadable to the judge, or only possibly the same | A decision reaches nothing its author cannot read (REQ-42) |

## Limits

| Limit | Detail |
|---|---|
| Every code finding of a series' first run is in the queue | As with a scanner's first scan, nothing is a baseline; the order and suppression rules thin it |
