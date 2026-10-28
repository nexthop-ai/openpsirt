# Analyzer findings

A static analyzer's run over a build arrives as SARIF. Each result is placed in
the checkout, matched to what the same analysis reported before, and recorded
as a finding of the analysis kind, a **code finding**, internal until a person
judges it (`design-docs/access.md` § Internal visibility).

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

Kinds, runs and series in general are `design-docs/kinds.md`.

| Decision | Reason |
|---|---|
| A run is scoped to a product, release and variant | A finding must name its build to compare releases |
| SARIF is read; a tool's native format is read by the upload client (`design-docs/analysis-client.md`) | Analyzers emit it; native output is one reader per tool |
| Identity is computed here (REQ-08) | An analyzer's identifier moves with a tool upgrade or a reformat |
| The SARIF reader shares the inventory's bounded JSON reading (`design-docs/ingest-parsing.md`) | One implementation of size, depth and token limits |

## The upload

```
POST /v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/analyses
  sarif=@…        one or more SARIF 2.1.0 documents, gzip accepted
  series, commit, built, tool-version, rules, units-expected, units-analyzed,
  exit-status, source-root, third-party
```

| Rule | Reason |
|---|---|
| Its own operation, one run of one analysis against one build | Analysis runs on its own schedule |
| Sent by a pipeline key covering the build, or a person holding `internal-triage` on the product | Every result opens internal |
| The documents are read and results placed at the door, and answered 202; the placed results are stored until the run ends, the documents never; a queued job applies the run (REQ-06) | An unreadable document is refused in the sender's words, and applying waits for the inventory |
| No file contents, fix or scanner run is written, and a snippet only per `design-docs/analysis-source.md` § Snippets | |
| A retired product, release or variant takes no run; a queue past its backlog answers 503 | As the scan upload |
| Fields fill what documents leave unstated; documents win where both state one | The client writes them into the SARIF |
| The series is required, from the field or each run's `automationDetails.id`, written `<series>/<built>` | |
| A run is identified by its documents' digests and stated build time | The same bytes from two nightly builds are two runs |
| A run stating no build time is dated on arrival | Analyzers write none |
| A build time over five minutes ahead of this clock is refused | It would supersede every later run |

| Status | Meaning |
|---|---|
| 202 `queued` | Stored and waiting |
| 200 `already_held` | The same documents for the same series, build and build time, answered as the run repeated |
| 422 | A document or field unreadable, no analyzer run that ran, placed results past the byte bound, or a series name too long; the detail names which |
| 409 | Product, release or variant retired |
| 503 | Queue past its backlog |

## Bounds

A SARIF document is hostile input (REQ-66, REQ-69). Each bound is configuration
(`docs/configuration.md` § Analyzer result limits), and a refusal names it.
Documents are read whole and results placed before anything is stored, so bytes
and entries are bounded across the upload as memory: placed results take about
1.25 times their encoding, and 150,000 results with 600,000 flow steps read as
145 MB plus 103 MB placed, an encoding of 98 MB.

| Bound | On |
|---|---|
| Bytes as sent | The request and each document, compressed where compressed; the request is refused unread past it |
| Bytes decompressed | Each document; the upload's documents together, counting text taken from rule message strings; the placed results encoded. A compressed document decompresses against what is left of the lesser |
| Entries held | Across the upload: runs, results, rules, locations, kept flow steps, invocations, and every list and map member |
| Documents | Per upload; a tool's per-unit documents are merged first |
| Runs | Per document |
| Results, rules, repositories, named starting points | Per run |
| Locations, related locations, flow steps | Per result |
| Starting-point chains | Per path; a loop refuses the document |
| Property members | Per bag, every bag read or walked past, nested included |
| Text | Per message or description, cut past it, placeholders included |
| Snippet | Per place, cut past it |
| Depth | JSON nesting |

| Rule | Reason |
|---|---|
| Bytes as sent default to bytes decompressed, and one document may take the whole upload's bounds | Merged per-unit documents do |
| Defaults far exceed real producers: nesting 64 against 14, a bag 256 against 9, 1,000 places against 4, 10,000 flow steps against 12 (`design-docs/analysis-measurements.md` § Producer output) | Richer output is not refused |

## Run contents

| Rule | Reason |
|---|---|
| A dependency or secret scanner's run is left out and named on the receipt; an upload of only those is refused, naming them | Inventories go to the scan upload |
| A run whose `results` is absent or null refuses the upload | Absent is a tool that did not start |
| A result's rule is found by identifier, whole then by leading `/` components, within the tool component it names; a rule index only where no identifier is stated, within its component or the driver | Extensions number rules from zero; `CA5350/md5` is `CA5350` |
| A rule that is an advisory's identifier drops the result, counted | |
| A result that is the tool's own failure is dropped, counted, and makes the run not comparable, wherever it is | `clang-diagnostic-error`, `syntaxError`, `internalAstError`, `cppcheckError`, `preprocessorErrorDirective` |
| Kind `pass`, `notApplicable` or `informational` drops the result as `not-a-problem`; no kind is `fail`; `review` and `open` stay | |
| A suppression with no status or `accepted` drops the result as `suppressed-by-the-tool`; `underReview` and `rejected` do not | |
| `baselineState` `absent` drops the result as `absent` | It could never be found again |
| Paths resolve through named starting points and place against the source root | Paths arrive absolute, as `file://`, relative, or under undefined starting points |
| A path with no starting point is relative to the first invocation's working directory where that is in the checkout, else the top; one under the source root's own undefined name is relative to the top | cppcheck run from a subdirectory |
| A path outside the checkout drops its result, counted | |
| A result repeating another on rule, path, line, column and message is dropped, counted | clang repeats a header per unit |
| Whole-file contents, fixes and markdown messages are left out of every record, counted | |
| A markdown-only message is reduced to the words it shows: no markers, links and images as their words, escapes and references resolved in one pass (`\&lt;` is `&lt;`), code as written, no raw HTML | It is shown encoded and is part of matching |
| The source root is used at the door, never stored | It is a build-host path |

## Run parameters

| Parameter | Source |
|---|---|
| Tool name and version | The first analyzer run; the field where none is stated (REQ-13) |
| Client version | `openpsirt/client` |
| Units expected and analyzed | `openpsirt/unitsExpected`, `openpsirt/unitsAnalyzed` summed, or the two fields together |
| Exit status, completion | `invocations[].exitCode`, `executionSuccessful`; the first non-zero and first failure win |
| Rule set | Digest and count of enabled rules, from `rules` or a rule list naming a rule that never fired; a list of fired rules is none |
| Commit, series, build time | `openpsirt/commit`, `openpsirt/series`, `openpsirt/built`, or `automationDetails.id` |
| Third-party paths | `third-party` (`design-docs/analysis-source.md` § Third-party code) |

A run is **comparable** where its absences are evidence. The first reason that
holds is recorded:

| Reason | A run that |
|---|---|
| `exit-status` | Exited non-zero |
| `incomplete` | Said it did not finish |
| `failure-signal` | Reported a failure of its own run |
| `no-coverage` | States neither units nor rule set |
| `units-short` | Analyzed fewer units than meant |
| `tool-changed` | Ran another tool or version than the series' last applied run on the build |
| `rules-changed` | Ran another rule set than that run |

| Failure signal | Example |
|---|---|
| An error-level notification about its run | `cpp/diagnostics/failed-extractor-invocations` |
| A result that is the tool's failure | § Run contents |
| Coverage notifications naming expected files and none extracted | CodeQL succeeds with every compilation failed: `<language>/baseline/expected-extracted-files` against `<language>/diagnostics/successfully-extracted-files` |

| Rule | Reason |
|---|---|
| A run that is not comparable adds and updates code findings and marks none absent | |
| A code finding is marked no longer detected only by a run comparable to the run that last saw it too: same tool, version and rule set; otherwise it is counted uncompared | An absence across an upgrade says nothing |
| Coverage notifications are a signal, never units | CodeQL's baseline counts uncompiled files |

## Run application

A worker applies the run in one transaction (REQ-06), reading the placed results
first.

| State | When |
|---|---|
| `waiting` | No inventory read yet; asked again each minute for a day, holding a backlog job and its placed results meanwhile |
| `superseded` | The series applied a run built at or after this one to the build; only a newer run applies (REQ-06) |
| `failed` | Placed results in a shape this release does not read, or no inventory within a day |
| `applied` | Matched, opened and recorded |

An applied run, in order:

1. Matches each result to a code finding open in the series on the build (`design-docs/analysis-matching.md` § Matching).
2. Files each rule as an issue of the rule kind, `<tool>/<rule>` in lower-case tool name, with the weaknesses its `external/cwe/cwe-N` tags name (`design-docs/kinds.md` § Name resolution).
3. Opens an internal code finding for each unmatched result, at the occurrence matching gives and the component placement gives (`design-docs/analysis-source.md` § Placement).
4. Replaces each seen code finding's path, lines, columns, function, call chain, message, fingerprint, flow steps and related places.
5. Records each as seen; marks each open one unseen as no longer detected, per § Run parameters; counts one seen again as returned.
6. Records the checkout's repositories.
7. Lets the placed results go, and writes the receipt.

| Rule | Reason |
|---|---|
| Two runs of one series apply in turn, each first writing a new value to the series' row | Both would open one result twice; a cluster certifies only written rows (`design-docs/database-transactions.md` § Retryable transactions) |
| No longer detected is absence, and the code finding stays open (`design-docs/kinds.md` § Kinds) | |
| A code finding is in the queue from the run opening it, a first run included | |
| A comparable run marking more no longer detected than the analyzer drop share and floor both allow is a sharp drop: applied, said on its receipt, and told once to internal readers after commit (REQ-21, `design-docs/notifications-alerts.md` § Analyzer alerts) | Partial analysis reads as a fix sweep; set aside, it would supersede every later run |
| The share is of what the last comparable run saw; the floor is a count | A small series does not alert on two fixes |

## Receipts

`GET …/analyses` lists a build's runs newest first.

| Field | |
|---|---|
| Status, failure | § Run application |
| Comparable, with the reason | § Run parameters |
| Tool and version | |
| Counts | Opened, seen again, returned, no longer detected, uncompared, paired probably, carried from the parent branch, reopened at a closed occurrence, and each drop, omission and discard by reason |
| Fingerprint change | `design-docs/analysis-matching.md` § Fingerprint change |
| Sharp drop | § Run application |

| Rule | Reason |
|---|---|
| Each series' last upload turned away after admission is listed: series, time, the sender's words; one per series and build | |
| One refused before admission is recorded nowhere | It would tell readers somebody without access tried |
| A receipt counts code findings and names none | |
| A pipeline key reads its build's receipts; a person reads them where they read internal findings; anybody else is answered as for a build sent nothing, before runs are looked up (REQ-42, `design-docs/access.md` § Subject kinds) | |

## Not built

| Part | State |
|---|---|
| Code findings over time | Not built: Statistics include none (`design-docs/kinds.md` § Consumers), so nothing reports time to judge or fix or a series' trend. Current standing is by series (`design-docs/analysis-queue.md` § Code findings by series); approval quality and the exception report read code finding decisions (`design-docs/analytics-controls.md` § Approval quality) |
| A repository an SPDX inventory states | Not read; a download location places nothing |
| Pulling from a hosted analyzer | Not built |
| Fuzzing findings | Intended scope, not built (REQ-14) |

## Limits

| Limit | Detail |
|---|---|
| A run ending unread counts nothing on its receipt | Superseded, failed, or unreadable while waiting, it names no drop or discard |
| A rule set read from a rule list flips where every listed rule fires | Then no rule set is stated, compared as a change |
| Per-run counts are measured on small trees | The largest real output is CodeQL's 226,586 bytes; results per run and the memory figures rest on the 150,000-result reading measurement, raised with the memory limit for a large tree |
| A tool is told apart by its output's name | Two configurations in one invocation are one series |
| An upload refused before naming its series is recorded against none | The build's receipts list it |
