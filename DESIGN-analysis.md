# Analyzer findings

A static analyzer's run over a build arrives as SARIF. Each result it reports
is placed in the checkout, matched to what the same analysis reported on that
build before, and recorded as a finding of the analysis kind, called a lead.
A lead is internal until a person judges it.

Satisfies REQ-14, REQ-06, REQ-08, REQ-13, REQ-17, REQ-21, REQ-25, REQ-69.

Neighboring pieces: what a kind declares, and runs and series as any kind
uses them, are in `DESIGN-kinds.md`; who reads the internal visibility is in
`DESIGN-access.md` § Internal visibility; the bounded reading every document
shares is in `DESIGN-ingest.md`.

## Contents

- [The upload](#the-upload)
- [Bounds](#bounds)
- [Run contents](#run-contents)
- [Run parameters](#run-parameters)
- [Run application](#run-application)
- [Matching](#matching)
- [Placement](#placement)
- [Receipts](#receipts)
- [Not built](#not-built)
- [Limits](#limits)

## The upload

One request carries one run of one analysis against one build:

```
POST /v1/products/{product}/streams/{stream}/variants/{variant}/analyses
  sarif=@…        one or more SARIF 2.1.0 documents, gzip accepted
  series, commit, built, tool-version, rules, units-expected, units-analyzed,
  exit-status, source-root, third-party
```

| Rule | |
|---|---|
| Its own operation beside the scan upload | Analysis runs on its own schedule, often in another job from the inventory |
| A pipeline key covering the build sends it; a person sends where they hold `internal-triage` on the product | Every result opens internal |
| The documents are read and their results placed at the door; the placed results are stored until the run ends, and the documents are not stored; the run is applied by a queued job | A document that cannot be read is refused in words the sender reads, no snippet, file contents, fix or scanner run is ever written, and applying waits for the build's inventory |
| A retired product, release or variant takes no run, and a queue past its backlog answers 503 | The scan upload's rules, for the same reasons |
| The fields fill what the documents leave unstated, and the documents win where both state a value | The upload client writes them into the SARIF; a plain producer passes them beside it |
| The series is required, from the field or from each run's `automationDetails.id`, written `<series>/<built>` | It is what the next run is compared against |
| A run is identified by its documents' digests and the build time it states | The same bytes from two nightly builds are two runs; the same documents sent again for one build answer 200 with the run they repeat (REQ-06) |
| A run stating no build time is dated on arrival | Analyzers write no timestamp |
| A build time more than five minutes ahead of this deployment's clock is refused | Runs are ordered by it, so one dated ahead leaves every later run superseded |

Answers:

| Status | Meaning |
|---|---|
| 202 `queued` | Stored and waiting to be applied |
| 200 `already_held` | The same documents for the same series, build and build time, answered as the run they repeat |
| 422 | A document or a field could not be read, the upload holds no analyzer run that ran, its placed results are past the byte bound, or the series name is longer than a name may be; the detail names which |
| 409 | The product, release or variant is retired |
| 503 | The queue is past its backlog |

## Bounds

A SARIF document is hostile input (REQ-69). Each bound is configuration,
`docs/configuration.md` § Analyzer result limits lists them with their
defaults, and an upload past one is refused with the bound named.

An upload's documents are read whole and their results placed before any of
it is stored, so what they hold and the placed results are in memory at once.
The bytes and the entries held are bounded across the upload for that reason,
and are memory figures. Placed results take about 1.25 times their encoded
size in memory: 150,000 results with 600,000 flow steps read as 145 MB, and
placing them added 103 MB beside that, an encoding of 98 MB.

| Bound | On |
|---|---|
| Bytes | The request, compressed; the upload's documents together once decompressed, counting the text each result is worded with from its rule's message strings; and the placed results once encoded, before any of them is stored |
| Entries held | The upload's documents together: runs, results, rules, locations, kept flow steps, invocations, and the members of every list and map they carry. Each costs memory however few bytes of the document it took |
| Documents | Per upload. clang writes one per translation unit, so a tool's per-unit documents are merged into one before they are sent |
| Runs | Per document |
| Results, rules, repositories, named starting points | Per run |
| Locations and related locations, flow steps | Per result |
| Starting-point chains | How many named starting points one path passes through. A chain that loops refuses the document |
| Property members | Per property bag |
| Text | Per message or description; a longer one is cut. Filling a message string's placeholders stops at this length |
| Depth | Nesting of the JSON |

## Run contents

| Rule | |
|---|---|
| A run from a dependency or secret scanner is left out whole and named on the receipt | This upload takes static analysis alone; an inventory goes to the scan upload |
| An upload whose every run is a scanner's is refused, naming the scanners | Nothing in it is analysis |
| An upload with a run whose `results` is absent or null is refused | SARIF's own distinction: absent is a tool that did not start, `[]` is one that ran and found nothing |
| A result's rule is found by its identifier, whole and then by its leading `/`-separated components, within the tool component the result names where it names one; a position in a rule list is read only where the result states no identifier, and only within the component it names, the driver where it names none | Each extension numbers its own rules from zero, and a hierarchical identifier such as `CA5350/md5` is reported under the rule `CA5350` |
| A result whose rule is an advisory's identifier is dropped and counted | A scanner's finding wearing an analyzer's clothes would be filed as a rule |
| A result that is the tool's own failure is dropped, counted, and makes the run not comparable, wherever it is and whether or not it names a file | `clang-diagnostic-error`, `syntaxError`, `internalAstError`, `cppcheckError` and `preprocessorErrorDirective` say a unit was not analyzed; a generated header outside the checkout fails a unit as surely as a file in it |
| A result whose kind is `pass`, `notApplicable` or `informational` is dropped and counted as `not-a-problem` | It reports no problem. A result stating no kind is a `fail`, and `review` and `open` ask a person to settle it |
| A result covered by a suppression in force is dropped and counted as `suppressed` | A suppression stating no status, or `accepted`, is the tool honoring a person's decision in the source; one `underReview` or `rejected` is not in force |
| A result whose `baselineState` is `absent` is dropped and counted as `absent` | The tool says it is no longer found, and opening it would leave a lead no later run could find again |
| A path is resolved through its named starting points and placed against the source root | Paths arrive absolute, as `file://` addresses, relative to the working directory, and under a starting point left undefined |
| A path outside the checkout is dropped with its result, and counted | A build host's home directory never lands |
| A result repeating another of the same upload on rule, path, line, column and message is dropped and counted | clang repeats a header's result once per translation unit that includes it |
| Snippets, whole-file contents, fixes and markdown messages are left out of everything a run records, and counted on the receipt | Source enters no finding, no lead's description, no receipt and nothing stored |
| The source root is used at the door and not stored | It is a path on somebody's build host |

## Run parameters

What a run says about itself, from its documents or from the fields:

| Parameter | Source |
|---|---|
| Tool name and version | The first analyzer run in the documents; the field where the documents state no version (REQ-13) |
| Client version | `openpsirt/client` in the run's properties |
| Units expected and analyzed | `openpsirt/unitsExpected` and `openpsirt/unitsAnalyzed`, summed across runs, or the two fields, which are sent together or not at all |
| Exit status and completion | `invocations[].exitCode` and `executionSuccessful`; the first non-zero and the first failure win |
| Rule set | A digest of the rule identifiers enabled, and their count. From the `rules` field, or from the documents' rule list where it lists a rule that never fired |
| Commit, series, build time | `openpsirt/commit`, `openpsirt/series`, `openpsirt/built`, or `automationDetails.id` |
| Third-party paths | The `third-party` field, recorded on the run |

A rule list naming only rules that fired is not a rule set: clang and cppcheck
list what fired, and a run of them that found nothing lists nothing.

A run is comparable where its absences are evidence. The first reason that
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

## Run application

A worker claims the queued job and applies the run in one transaction. The
placed results are read before it, since they do not change once stored.

| State | When |
|---|---|
| `waiting` | The build has no inventory that has been read. The job is handed back and asked again a minute later, for a day from the run's arrival. The placed results are not read while a run waits |
| `superseded` | The series has applied a run to this build built at or after this one. Nothing changes |
| `held` | A comparable run would mark more of the build's open leads not reproduced than the deployment allows at once. Nothing changes |
| `failed` | The placed results are held in a shape the release applying them does not read, or the build had no inventory read within a day of the run arriving |
| `applied` | Results matched, opened and recorded |

Two runs of one series are applied one after the other. Each reads what the
series last saw and writes what it sees, so two at once would open one result
twice or record two baselines. Each takes the series' row first, by writing a value to it that
no run wrote before, because a cluster certifies only rows that were written
(`DESIGN-database.md` § Retryable transactions).

The hold is two settings, the analyzer drop share and floor, and both have to
be passed. The share is of the leads the last comparable run saw; the floor
keeps a small series from being held each time two leads are fixed.

An applied run, in order:

1. Matches each result to a lead the series holds open on the build (§ Matching).
2. Files each rule as an issue of the rule kind, named `<tool>/<rule>` in lower-case tool name, and records the weaknesses its `external/cwe/cwe-N` tags name (`DESIGN-kinds.md` § Name resolution).
3. Opens a lead for each result nothing matched, internal, at the place § Matching gives it and the component § Placement gives it.
4. Replaces what the last run said about each lead it saw again: path, lines, columns, enclosing function, call chain, message, fingerprint, and the flow steps and related places.
5. Records each lead as seen by this run. A comparable run records each open lead it did not see as not reproduced by it, and a lead not reproduced that is seen again is counted as returned.
6. Records the repositories the run says its checkout held.
7. Lets the placed results go, and writes the receipt.

Not reproduced is absence, and a lead stays open (`DESIGN-kinds.md` § Kinds).
A not-comparable run opens and updates leads and marks none.

A run is the baseline where it is the series' first comparable run on any
build of the product. A lead opened for a result the baseline already holds on
another build is in the baseline too.

## Matching

Identity is computed here (REQ-08). A fingerprint a document carries is one
input to the key and never the key by itself.

The match key is a digest of:

| Part | |
|---|---|
| The rule | As filed, `<tool>/<rule>` |
| The path | Relative to the checkout |
| The fingerprint, or the line where there is none | The first of `openpsirt/context/v1`, `clang/issueHash/v1`, `hash/v1`, `primaryLocationLineHash`, then any other in name order |
| The message with its digits taken out | A message quoting a line number or a count changes when lines move |
| The enclosing function | Where the output names it |
| The call chain | The functions the result's flow passes through, each once where consecutive steps share it |

| Rule | |
|---|---|
| Results pair with open leads one to one on an equal key | Two results with one key are two leads |
| A result nothing on the build matched opens a lead at a place derived from the series and the key | One result is one place on every build of the series, so a decision keyed on it reaches each (REQ-25) |

## Placement

A lead is one component at one place (REQ-17).

| Rule | |
|---|---|
| A result in a repository the run names is placed on the build's component built from that repository | The innermost repository holding its path |
| A component is built from a repository where its package identifier names it: the `github`, `gitlab` and `bitbucket` types by namespace and name, and any type by a `vcs_url` qualifier | The inventory is the only statement of which component a directory became |
| Repository addresses compare as host, owner and name, in lower case, without scheme, credentials, port, revision or `.git` | A remote written for SSH and an identifier written for HTTPS name one repository |
| A result in no repository the inventory names is placed on the build itself | Every build has a root |
| The inventory placed against is the build's newest that has been read | A run arriving before its inventory waits for it |

## Receipts

`GET …/analyses` lists a build's runs newest first.

| Field | |
|---|---|
| Status, failure | § Run application |
| Comparable, and the reason where not | § Run parameters |
| Baseline | The series' first comparable run |
| Tool and version | As recorded |
| Counts | Opened, seen again, returned, not reproduced, what a held run would have marked, and what was dropped, left out and discarded, each by reason |

A receipt counts leads and never names one. A pipeline key reads the receipts
of a build it may send to; a person reads them where they read internal
findings in the product, since the counts are of internal findings. A
pipeline key's other reads are unchanged (`DESIGN-access.md` § Subject kinds).

## Not built

| Part | State |
|---|---|
| The screens, queues, counts and exports that read leads | No consumer includes the analysis kind (`DESIGN-kinds.md` § Consumers), so a lead is recorded and counted on its run's receipt and read nowhere else |
| Triage of a lead: dismissal with a second person's approval, standing rules, escalation from the baseline | Not built |
| Moving a lead into a private case | Not built |
| Matching a moved result: a line shifted with no fingerprint, a renamed file | Not built. Such a result opens as a new lead, and the old one is not reproduced |
| A stream's first run matched against the stream it was cut from | Not built |
| Source links into the repositories a run names, and stored snippets | Not built. The repositories are recorded; snippets are discarded |
| Third-party paths | Recorded on the run and read by nothing |
| Conditions for a not-comparable run, a held run, and a series gone quiet | Not built. A held run says so on its receipt alone |
| Releasing a held run | Not built. A held run changes nothing and keeps nothing; the next run is compared against the last applied one |
| The upload client, `openpsirt-analysis` | Not built. Each pipeline writes the run parameters itself |
| Fuzzing findings | Intended scope, not built (REQ-14) |

## Limits

| Limit | Detail |
|---|---|
| Exact matching churns where an analyzer writes no fingerprint | clang-tidy, and clang before 22, give rule, path, line and message alone; every line moved above a result reopens it as a new lead |
| A run that ends unread counts nothing on its receipt | A run is read only once its build has an inventory, so one superseded or failed while it waits, or held in a shape the release applying it does not read, ends with a receipt naming no drop and no discard |
| Two identical results in one build share a place | Their key is the same, so a decision on one reaches the other. They are one flaw reported twice |
| A rule set read from a rule list flips where every listed rule fires | A tool listing its whole rule set lists rules that never fired, and a run where all of them fire states no rule set; that run is compared as a rule set change |
| A run waits a day for its build's inventory, and then fails | A pipeline that sends analysis for a build it never inventories has each run fail after a day. Until then each run holds a job counted against the backlog, and its placed results |
| The bounds' defaults are a judgment | They are several times the fixtures here and are not measured against the largest real producer. A deployment analyzing a large tree raises them, and the memory limit with the two that are memory figures |
| The upload records no refusal for the coverage report | A refused analyzer upload is answered to the sender and logged by nobody; a series gone quiet is not built |
