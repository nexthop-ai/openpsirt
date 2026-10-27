# Analyzer findings

A static analyzer's run over a build arrives as SARIF. Each result is placed in
the checkout, matched to what the same analysis reported before, and recorded
as a finding of the analysis kind, a **code finding**, internal until a person
judges it.

Satisfies REQ-06, REQ-08, REQ-13, REQ-14, REQ-21, REQ-42, REQ-66, REQ-69.

## Contents

- [Scope](#scope)
- [The upload](#the-upload)
- [Bounds](#bounds)
- [Run contents](#run-contents)
- [Run parameters](#run-parameters)
- [Run application](#run-application)
- [Receipts](#receipts)
- [Not built](#not-built)
- [Limits](#limits)

## Scope

What a kind declares, and runs and series as any kind uses them, are
`design-docs/kinds.md`.

| Decision | Reason |
|---|---|
| A run is scoped to a product, a release and a variant | A finding that cannot name its build cannot be compared release to release |
| SARIF is the interchange read, and a tool's native format is read by the upload client (`design-docs/analysis-client.md` § Upload client) | Analyzers already emit it; native output means one reader per tool |
| Identity is computed here, never taken from the producer (REQ-08) | An analyzer's result identifier moves when the tool is upgraded or the file reformatted, and a moved identity reopens as new |
| The bounded JSON reading an inventory uses is shared with the SARIF reader | One implementation of size, depth and token limits for every document read (`design-docs/ingest-parsing.md`) |

## The upload

One request carries one run of one analysis against one build:

```
POST /v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/analyses
  sarif=@…        one or more SARIF 2.1.0 documents, gzip accepted
  series, commit, built, tool-version, rules, units-expected, units-analyzed,
  exit-status, source-root, third-party
```

| Rule | Reason |
|---|---|
| Its own operation beside the scan upload | Analysis runs on its own schedule, often in another job |
| A pipeline key covering the build sends it, or a person holding `internal-triage` on the product | Every result opens internal |
| The documents are read and results placed at the door; the placed results are stored until the run ends, the documents never; a queued job applies the run | An unreadable document is refused in words the sender reads. No file contents, fix or scanner run is written, a snippet only where the product keeps source under its path (`design-docs/analysis-source.md` § Snippets), and applying waits for the build's inventory |
| A retired product, release or variant takes no run, and a queue past its backlog answers 503 | As the scan upload |
| The fields fill what the documents leave unstated, and the documents win where both state a value | The upload client writes them into the SARIF; a plain producer passes them beside it |
| The series is required, from the field or each run's `automationDetails.id`, written `<series>/<built>` | The next run is compared against it |
| A run is identified by its documents' digests and its stated build time (REQ-06) | The same bytes from two nightly builds are two runs; the same documents again for one build answer 200 with the run they repeat |
| A run stating no build time is dated on arrival | Analyzers write no timestamp |
| A build time more than five minutes ahead of this deployment's clock is refused | Runs are ordered by it, and one dated ahead supersedes every later run |

| Status | Meaning |
|---|---|
| 202 `queued` | Stored and waiting to be applied |
| 200 `already_held` | The same documents for the same series, build and build time, answered as the run they repeat |
| 422 | A document or field could not be read, the upload holds no analyzer run that ran, its placed results pass the byte bound, or the series name is longer than a name may be; the detail names which |
| 409 | The product, release or variant is retired |
| 503 | The queue is past its backlog |

## Bounds

A SARIF document is hostile input (REQ-66, REQ-69). Each bound is
configuration (`docs/configuration.md` § Analyzer result limits), and an upload
past one is refused naming it.

An upload's documents are read whole and their results placed before any is
stored, so the bytes and entries are bounded across the upload as memory
figures. Placed results take about 1.25 times their encoded size: 150,000
results with 600,000 flow steps read as 145 MB, and placing them added 103 MB,
an encoding of 98 MB.

| Bound | On |
|---|---|
| Bytes as sent | The request, and each document, as sent, compressed where compressed. The request past its bound is refused before it is read |
| Bytes decompressed | Each document decompressed; the upload's documents together decompressed, counting the text each result takes from its rule's message strings; and the placed results encoded, before any is stored. A compressed document decompresses against what is left of the lesser of the two |
| Entries held | The upload's documents together: runs, results, rules, locations, kept flow steps, invocations, and the members of every list and map, each costing memory however few bytes it took |
| Documents | Per upload. clang writes one per translation unit, so a tool's per-unit documents are merged before sending |
| Runs | Per document |
| Results, rules, repositories, named starting points | Per run |
| Locations and related locations, flow steps | Per result |
| Starting-point chains | Named starting points one path passes through. A chain that loops refuses the document |
| Property members | Per property bag, every bag read or walked past, nested bags included |
| Text | Per message or description; a longer one is cut, and filling a message string's placeholders stops at it |
| Snippet | Per place; a longer one is cut |
| Depth | Nesting of the JSON |

| Rule | Reason |
|---|---|
| The bytes as sent default to the bytes decompressed | An uncompressed document is bounded the same either way, and one document may take the whole upload's bounds, as merged per-unit documents do |
| The defaults are many times what real producers reach: nesting 64 against 14, a property bag 256 against 9, 1,000 places against 4, 10,000 flow steps against 12 | A producer writing richer output is not refused for it (`design-docs/analysis-measurements.md` § Producer output) |
| The snippet default is 4 KiB | What the upload client sends at most; no measured output carries one |

## Run contents

| Rule | Reason |
|---|---|
| A run from a dependency or secret scanner is left out whole and named on the receipt | This upload takes static analysis; an inventory goes to the scan upload |
| An upload whose every run is a scanner's is refused, naming the scanners | Nothing in it is analysis |
| An upload with a run whose `results` is absent or null is refused | Absent is a tool that did not start, `[]` one that found nothing |
| A result's rule is found by its identifier, whole and then by its leading `/`-separated components, within the tool component the result names; a rule-list position is read only where the result states no identifier, within the component it names, the driver where it names none | Each extension numbers its rules from zero, and `CA5350/md5` is reported under `CA5350` |
| A result whose rule is an advisory's identifier is dropped and counted | A scanner's finding would be filed as a rule |
| A result that is the tool's own failure is dropped, counted, and makes the run not comparable, wherever it is and whether or not it names a file | `clang-diagnostic-error`, `syntaxError`, `internalAstError`, `cppcheckError` and `preprocessorErrorDirective` say a unit was not analyzed; a generated header outside the checkout fails a unit too |
| A result of kind `pass`, `notApplicable` or `informational` is dropped and counted as `not-a-problem` | It reports no problem. No kind is a `fail`, and `review` and `open` ask a person |
| A result covered by a suppression in force, one stating no status or `accepted`, is dropped and counted as `suppressed-by-the-tool` | The tool honoring a person's decision in the source; `underReview` and `rejected` are not in force |
| A result whose `baselineState` is `absent` is dropped and counted as `absent` | The tool says it is gone, and opened it could never be found again |
| A path is resolved through its named starting points and placed against the source root | Paths arrive absolute, as `file://` addresses, relative to the working directory, and under an undefined starting point |
| A path naming no starting point is relative to the working directory the run's first invocation states where that is in the checkout, and to the top otherwise; a path under the source root's own name left undefined is relative to the top | cppcheck run from a subdirectory writes paths relative to it |
| A path outside the checkout is dropped with its result, and counted | A build host's home directory never lands |
| A result repeating another of the upload on rule, path, line, column and message is dropped and counted | clang repeats a header's result per translation unit including it |
| Whole-file contents, fixes and markdown messages are left out of everything recorded, and counted on the receipt | A message is its text |
| A message holding only markdown is reduced to the words it shows: no emphasis, heading, list or quote marker, a link and an image as their words, escapes and character references resolved in one pass as a renderer does (`\&lt;` is `&lt;`), code as written, and no raw HTML | The text is shown encoded, never rendered, and is part of what matches a code finding |
| A snippet is kept only where the product keeps source under its path, and counted as discarded otherwise | A misconfigured pipeline puts no source into the deployment, and the upload is still accepted |
| The source root is used at the door and not stored | It is a path on somebody's build host |

## Run parameters

| Parameter | Source |
|---|---|
| Tool name and version | The first analyzer run in the documents; the field where they state no version (REQ-13) |
| Client version | `openpsirt/client` in the run's properties |
| Units expected and analyzed | `openpsirt/unitsExpected` and `openpsirt/unitsAnalyzed`, summed across runs, or the two fields, sent together or not at all |
| Exit status and completion | `invocations[].exitCode` and `executionSuccessful`; the first non-zero and the first failure win |
| Rule set | A digest of the enabled rule identifiers, and their count, from the `rules` field, or from the rule list where it lists a rule that never fired. A list of only fired rules is no rule set: clang and cppcheck list what fired |
| Commit, series, build time | `openpsirt/commit`, `openpsirt/series`, `openpsirt/built`, or `automationDetails.id` |
| Third-party paths | The `third-party` field, recorded on the run (`design-docs/analysis-source.md` § Third-party code) |

A run is **comparable** where its absences are evidence. The first reason that
holds is recorded:

| Reason | A run that |
|---|---|
| `exit-status` | Exited with a status other than zero |
| `incomplete` | Said it did not finish |
| `failure-signal` | Reported a failure of its own run |
| `no-coverage` | States neither its units nor its rule set |
| `units-short` | Analyzed fewer units than it was meant to |
| `tool-changed` | Ran another tool or version than the series' last applied run on the build |
| `rules-changed` | Ran another rule set than that run |

| Failure signal | Example |
|---|---|
| A notification about its run at error level | CodeQL's `cpp/diagnostics/failed-extractor-invocations` |
| A result that is the tool's own failure | § Run contents |
| Coverage notifications naming files expected and none extracted | CodeQL states success with every compilation failed. It names each expected file as `<language>/baseline/expected-extracted-files` and each extracted one as `<language>/diagnostics/successfully-extracted-files` |

| Rule | Reason |
|---|---|
| A comparable run marks a code finding no longer detected only where it is also comparable to the run that last saw it, by tool, version and rule set; otherwise the code finding stays open and is counted as uncompared | A code finding last seen before an upgrade says nothing by its absence afterwards |
| Coverage notifications are a signal, never units | CodeQL's baseline is every file of the language in the tree, compiled or not |

## Run application

A worker claims the queued job and applies the run in one transaction, reading
the placed results before it.

| State | When |
|---|---|
| `waiting` | The build has no inventory read. The job is handed back and asked again a minute later, for a day from arrival, without reading the placed results |
| `superseded` | The series applied a run to this build built at or after this one. Nothing changes |
| `failed` | The placed results are in a shape this release does not read, or no inventory was read within a day |
| `applied` | Results matched, opened and recorded |

An applied run, in order:

1. Matches each result to a code finding the series holds open on the build (`design-docs/analysis-matching.md` § Matching).
2. Files each rule as an issue of the rule kind, `<tool>/<rule>` with the tool name in lower case, recording the weaknesses its `external/cwe/cwe-N` tags name (`design-docs/kinds.md` § Name resolution).
3. Opens a code finding, internal, for each result nothing matched, at the occurrence matching gives it and the component placement gives it (`design-docs/analysis-source.md` § Placement).
4. Replaces what the last run said about each code finding seen again: path, lines, columns, enclosing function, call chain, message, fingerprint, flow steps and related places.
5. Records each code finding as seen. A comparable run records each open one it did not see as no longer detected, where comparable to the run that last saw it; one seen again is counted as returned.
6. Records the repositories the run says its checkout held.
7. Lets the placed results go, and writes the receipt.

| Rule | Reason |
|---|---|
| Two runs of one series apply one after the other, each first writing to the series' row a value no run wrote before | Each reads what the series last saw, so two at once open one result twice. A cluster certifies only rows written (`design-docs/database.md` § Retryable transactions) |
| No longer detected is absence, recorded with the run that did not see it, and the code finding stays open (REQ-21, `design-docs/kinds.md` § Kinds) | Absence from one run is weak evidence of a fix |
| A run that is not comparable opens and updates code findings and marks none | |
| A code finding is open and in the queue from the run opening it, a series' first run in the product included | |
| A comparable run marking more open code findings no longer detected than the analyzer drop share and floor both allow is a sharp drop: applied, said on its receipt, and told once to the product's internal readers after commit (`design-docs/notifications.md` § Analyzer alerts) | A run that analyzed part of the tree silently reads like a fix sweep; set aside, it would leave every later run superseded |
| The share is of the code findings the last comparable run saw, and the floor is a count | The floor keeps a small series from alerting each time two are fixed |

## Receipts

`GET …/analyses` lists a build's runs newest first.

| Field | |
|---|---|
| Status, failure | § Run application |
| Comparable, and the reason where not | § Run parameters |
| Tool and version | As recorded |
| Counts | Opened, seen again, returned, no longer detected, left open as uncompared, paired probably, carried from the branch a build was cut from, reopened at a closed code finding's occurrence, and what was dropped, left out and discarded, each by reason |
| Fingerprint change | `design-docs/analysis-matching.md` § Fingerprint change |
| Sharp drop | § Run application |

| Rule | Reason |
|---|---|
| The list carries each series' last upload to the build turned away after its sender was admitted: the series as named, when, and the words the sender was told; one per series and build, replaced | |
| An upload refused before its sender was admitted to the build is recorded nowhere | Recording it tells the build's readers somebody without access tried |
| A receipt counts code findings and never names one | |
| A pipeline key reads the receipts of a build it may send to, and a person where they read internal findings in the product | The counts are of internal findings. A key's other reads are unchanged (`design-docs/access.md` § Subject kinds) |
| Anybody else is answered as for a build nothing was sent to, before the build's runs are looked up (REQ-42) | The answer is the same whether or not the build holds any |

## Not built

| Part | State |
|---|---|
| Code findings over time | Not built. Statistics include no code finding (`design-docs/kinds.md` § Consumers), so no report says how long one took to be judged or fixed, or how a series' counts moved. Current standing is counted by series (`design-docs/analysis-queue.md` § Code findings by series). Approval quality and the exception report read code finding decisions: a dismissal standing on one person is a control that did not hold (`design-docs/analytics.md` § Approval quality) |
| A repository an SPDX inventory states | Not read. A package's download location is read by nothing, so an SPDX component is built from a repository only where its identifier names one |
| Pulling from a hosted analyzer | Not built. A hosted analyzer has its own store and no reason to call this deployment |
| Fuzzing findings | Intended scope, not built (REQ-14) |

## Limits

| Limit | Detail |
|---|---|
| A run that ends unread counts nothing on its receipt | A run is read only once its build has an inventory, so one superseded or failed while waiting, or held in a shape this release does not read, names no drop and no discard |
| A run waits a day for its build's inventory, then fails | Until then each run holds a job counted against the backlog, and its placed results |
| A rule set read from a rule list flips where every listed rule fires | A run where all of them fire states no rule set, and is compared as a rule set change |
| The counts per run are measured against small trees | The largest real output measured is CodeQL's 226,586 bytes. The results per run and the two memory figures rest on the 150,000-result measurement of reading cost; a deployment analyzing a large tree raises them, and the memory limit with them |
| A tool is told apart by the name its output gives it | Two configurations of one tool in one invocation are one series; a pipeline running a tool twice runs the client twice |
| An upload refused before it names its series is recorded against no series | The build's receipts list it, and no series gone quiet names it |
