# Analyzer findings

A static analyzer's run over a build arrives as SARIF. Each result it reports
is placed in the checkout, matched to what the same analysis reported on that
build before, and recorded as a finding of the analysis kind, called a code finding.
A code finding is internal until a person judges it.

Satisfies REQ-14, REQ-06, REQ-08, REQ-13, REQ-17, REQ-21, REQ-24, REQ-25,
REQ-19, REQ-27, REQ-28, REQ-30, REQ-40, REQ-42, REQ-43, REQ-66, REQ-69.

Neighboring pieces: what a kind declares, and runs and series as any kind
uses them, are in `design-docs/kinds.md`; who reads the internal visibility is in
`design-docs/access.md` § Internal visibility; the bounded reading every document
shares is in `design-docs/ingest.md`.

## Contents

- [The upload](#the-upload)
- [Bounds](#bounds)
- [Run contents](#run-contents)
- [Run parameters](#run-parameters)
- [Run application](#run-application)
- [Matching](#matching)
- [Placement](#placement)
- [Source](#source)
- [Code finding triage](#code-finding-triage)
- [Code finding queue](#code-finding-queue)
- [Code finding assignment](#code-finding-assignment)
- [Weakness families](#weakness-families)
- [Grouped code findings](#grouped-code-findings)
- [Flaw records](#flaw-records)
- [Third-party code](#third-party-code)
- [End of life](#end-of-life)
- [Receipts](#receipts)
- [Upload client](#upload-client)
- [Not built](#not-built)
- [Limits](#limits)

## The upload

One request carries one run of one analysis against one build:

```
POST /v1/products/{product}/branches-and-tags/{branch_or_tag}/variants/{variant}/analyses
  sarif=@…        one or more SARIF 2.1.0 documents, gzip accepted
  series, commit, built, tool-version, rules, units-expected, units-analyzed,
  exit-status, source-root, third-party
```

| Rule | |
|---|---|
| Its own operation beside the scan upload | Analysis runs on its own schedule, often in another job from the inventory |
| A pipeline key covering the build sends it; a person sends where they hold `internal-triage` on the product | Every result opens internal |
| The documents are read and their results placed at the door; the placed results are stored until the run ends, and the documents are not stored; the run is applied by a queued job | A document that cannot be read is refused in words the sender reads, no file contents, fix or scanner run is ever written, a snippet is written only where the product keeps source under its path (§ Source), and applying waits for the build's inventory |
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
| Bytes as sent | The request, and each document, as sent: compressed where it was compressed. The request past its bound is refused before it is read |
| Bytes decompressed | Each document once decompressed; the upload's documents together once decompressed, counting the text each result is worded with from its rule's message strings; and the placed results once encoded, before any of them is stored. A compressed document is decompressed against what is left of the lesser of the two |
| Entries held | The upload's documents together: runs, results, rules, locations, kept flow steps, invocations, and the members of every list and map they carry. Each costs memory however few bytes of the document it took |
| Documents | Per upload. clang writes one per translation unit, so a tool's per-unit documents are merged into one before they are sent |
| Runs | Per document |
| Results, rules, repositories, named starting points | Per run |
| Locations and related locations, flow steps | Per result |
| Starting-point chains | How many named starting points one path passes through. A chain that loops refuses the document |
| Property members | Per property bag, every bag the document holds, read or walked past, a bag within a bag included |
| Text | Per message or description; a longer one is cut. Filling a message string's placeholders stops at this length |
| Snippet | Per place; a longer one is cut (§ Snippets) |
| Depth | Nesting of the JSON |

The bytes as sent default to the bytes decompressed, so a document sent
without compression is bounded the same either way, and one document may take
the whole upload's bounds, which is what a tool's per-unit documents merged
into one take.

Measured on real producers' output:

| Output | Bytes | Gzipped | Results | Rules | Most places per result | Most flow steps per result | Largest property bag | Deepest nesting |
|---|---|---|---|---|---|---|---|---|
| CodeQL 2.15.0, C++ queries over a small interpreter | 226,586 | 22,398 | 22 | 165 | 2 | 0 | 9 | 11 |
| CodeQL 2.2.5, Java queries | 111,783 | 6,439 | 15 | 25 | 4 | 12 | 7 | 14 |
| clang 18.1.3 static analyzer, one unit | 12,899 | 1,284 | 3 | 2 | 1 | 5 | none | 14 |
| cppcheck 2.22.0, two units | 6,182 | 853 | 4 | 3 | 2 | 0 | 4 | 9 |
| clang-tidy through `clang-tidy-sarif` | 751 | 328 | 1 | 0 | 1 | 0 | none | 9 |

The Java output is `samples/sarif/java/detailed/java.sarif` in
github.com/peter-murray/github-security-report-action at commit `84b2945`; the
others are the reader's fixtures, whose origins are recorded beside them.

Every output of 5 KB or more compressed 7 to 17 times over, so a gzipped
upload meets the decompressed bound well before the bound as sent. The largest
was CodeQL's, about 10 KB a result, most of it the description of every query
it ran. The defaults are many times what any of them reached: nesting 64
against 14, a property bag 256 against 9, 1,000 places against 4 and 10,000
flow steps against 12, so a producer writing richer output than these is not
refused for it. None of them carries a snippet; the snippet default is the
4 KiB the upload client sends at most.

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
| A result covered by a suppression in force is dropped and counted as `suppressed-by-the-tool` | A suppression stating no status, or `accepted`, is the tool honoring a person's decision in the source; one `underReview` or `rejected` is not in force |
| A result whose `baselineState` is `absent` is dropped and counted as `absent` | The tool says it is no longer found, and opening it would leave a code finding no later run could find again |
| A path is resolved through its named starting points and placed against the source root | Paths arrive absolute, as `file://` addresses, relative to the working directory, and under a starting point left undefined |
| A path naming no starting point is relative to the working directory the run's first invocation states where that is in the checkout, and to the top of the checkout otherwise; a path under the source root's own name left undefined is relative to the top | cppcheck run from a subdirectory writes its paths relative to that directory |
| A path outside the checkout is dropped with its result, and counted | A build host's home directory never lands |
| A result repeating another of the same upload on rule, path, line, column and message is dropped and counted | clang repeats a header's result once per translation unit that includes it |
| Whole-file contents, fixes and markdown messages are left out of everything a run records, and counted on the receipt | No whole file or replacement text is stored, and a message is its text |
| A message holding only markdown is reduced to the words it shows: no emphasis, heading, list or quote marker, a link and an image as their words, escapes and character references resolved in one pass as a renderer resolves them, so `\&lt;` is `&lt;`, code as written, and no raw HTML | The text is what the analyzer said, shown encoded and never rendered, and a message is part of what matches a code finding |
| A snippet is kept only where the product keeps source under its path, and counted on the receipt as discarded otherwise (§ Source) | A misconfigured pipeline does not put source into the deployment, and the upload is still accepted |
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
| Third-party paths | The `third-party` field, recorded on the run and read at flaw record and in the evidence (§ Third-party code) |

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

| Rule | |
|---|---|
| A comparable run marks a code finding no longer detected only where it is also comparable to the run that last saw the code finding: the same tool, version and rule set | A code finding last seen before an upgrade says nothing by its absence from a run of the new version. It stays open, and the receipt counts it as uncompared |

A tool reports a failure of its own run in three ways, and each one counts:

| Signal | |
|---|---|
| A notification about its run at error level | CodeQL names a compilation it could not extract this way, as `cpp/diagnostics/failed-extractor-invocations` |
| A result that is the tool's own failure | § Run contents |
| Coverage notifications naming files it expected and none it extracted | CodeQL states its run successful with every compilation failed. It names each file its baseline expects as `<language>/baseline/expected-extracted-files` and each file it extracted as `<language>/diagnostics/successfully-extracted-files` |

The coverage notifications are read as a signal and never as units. CodeQL's
baseline is every file of the language in the tree, compiled or not, so a
count of them against the files extracted would leave every run of a tree
holding a file the build never compiles short of units.

## Run application

A worker claims the queued job and applies the run in one transaction. The
placed results are read before it, since they do not change once stored.

| State | When |
|---|---|
| `waiting` | The build has no inventory that has been read. The job is handed back and asked again a minute later, for a day from the run's arrival. The placed results are not read while a run waits |
| `superseded` | The series has applied a run to this build built at or after this one. Nothing changes |
| `failed` | The placed results are held in a shape the release applying them does not read, or the build had no inventory read within a day of the run arriving |
| `applied` | Results matched, opened and recorded |

Two runs of one series are applied one after the other. Each reads what the
series last saw and writes what it sees, so two at once would open one result
twice. Each takes the series' row first, by writing a value to it that
no run wrote before, because a cluster certifies only rows that were written
(`design-docs/database.md` § Retryable transactions).

A comparable run marking more of the build's open code findings no longer detected than
the deployment expects of one run is a sharp drop. It is applied, its receipt
says so, and the product's internal readers are told once, after the run
commits (`design-docs/notifications.md` § Analyzer alerts). A run that analyzed
part of the tree without saying so reads like a fix sweep, so a person is
asked to look; setting the run aside would leave every later run superseded
behind it.

A sharp drop is two settings, the analyzer drop share and floor, and both
have to be passed. The share is of the code findings the last comparable run saw; the
floor keeps a small series from raising one each time two code findings are fixed.

An applied run, in order:

1. Matches each result to a code finding the series holds open on the build (§ Matching).
2. Files each rule as an issue of the rule kind, named `<tool>/<rule>` in lower-case tool name, and records the weaknesses its `external/cwe/cwe-N` tags name (`design-docs/kinds.md` § Name resolution).
3. Opens a code finding for each result nothing matched, internal, at the occurrence § Matching gives it and the component § Placement gives it.
4. Replaces what the last run said about each code finding it saw again: path, lines, columns, enclosing function, call chain, message, fingerprint, and the flow steps and related places.
5. Records each code finding as seen by this run. A comparable run records each open code finding it did not see as no longer detected by it, where it is comparable to the run that last saw the code finding, and a code finding no longer detected that is seen again is counted as returned.
6. Records the repositories the run says its checkout held.
7. Lets the placed results go, and writes the receipt.

No longer detected is absence, and a code finding stays open (`design-docs/kinds.md` § Kinds).
A not-comparable run opens and updates code findings and marks none.

A code finding is open and in the queue from the run that opens it, the series' first
run in the product included.

## Matching

Identity is computed here (REQ-08). A fingerprint a document carries is one
input to a key and never a key by itself.

### Keys

| Key | Digest of | Strength |
|---|---|---|
| Whole | The rule, the path, the fingerprint or the line where there is none, the message with its digits taken out, the enclosing function and the call chain | Strong |
| Unprinted | The whole key without the fingerprint or the line. Compared by a fingerprint change alone, and only where one result and one code finding hold it (§ Fingerprint change) | Strong |
| Function | The rule, the path, the message with its digits taken out, and the enclosing function. Absent where the output names no function | Probable |
| Line | The rule, the path and the message with its digits taken out, compared with the nearest line | Probable |

| Part | |
|---|---|
| The rule | As filed, `<tool>/<rule>` |
| The path | Relative to the checkout |
| The fingerprint | The first of `openpsirt/context/v1`, `clang/issueHash/v1`, `hash/v1`, `primaryLocationLineHash`, then any other in name order |
| The message with its digits taken out | A message quoting a line number or a count changes when lines move |
| The call chain | The functions the result's flow passes through, each once where consecutive steps share it |

### Layers

A run is paired with the code findings its series holds open on the build, one to
one, a layer at a time, each layer on what the layers before it left: the
whole key, then the function, then the nearest line. A fingerprint change
compares the unprinted key after the whole key and before the function.

| Rule | |
|---|---|
| A code finding the last comparable run did not see is a candidate in every layer | Of 28 absences hand-checked, 5 came back one or two builds later. A code finding it saw comes first where a layer cannot tell two apart |
| The line layer offers a result the eight code findings sharing its line key nearest its line | A generated file repeating one message holds thousands of results under one key, and offering each all of them is quadratic |
| Each code finding records how its newest sighting was paired: on the whole key, the unprinted key, the function or the line | A dismissal carries on a strong pairing and lapses on a probable one (§ Code finding triage) |

### Carrying

A result no open code finding on the build took is the same result as a code finding the
series holds elsewhere where one of these finds it. It opens at that code finding's
occurrence, so a decision keyed on the occurrence reaches it (REQ-25).

| Order | Where | How |
|---|---|---|
| 1 | The code findings open on the build of the same variant in the branch this one was cut from, on the series' first run on the build | Every layer, and the unprinted key where the run is a fingerprint change against that build. A new branch inherits what the line it was cut from has decided |
| 2 | A closed code finding on this build | The whole key. The result is the same flaw found again, and opens a new code finding at the closed one's occurrence |
| 3 | Any code finding of the series on another build, open or closed | The whole key, the oldest code finding first. A probable pairing with a code finding this build never saw is a guess |

A result found nowhere opens at an occurrence derived from the series and its whole key, so
the same result first seen on two builds at once is one occurrence.

### Fingerprint change

A run records the fingerprint schemes its results' keys were built from, and
the mark of the salt the client took its own with. A run whose record differs
from the newest one applied to the build that reported anything is a
fingerprint change. The series' first run on a build cut from another branch
is compared with the newest such run on the parent build, whose code findings it
inherits.

| Rule | |
|---|---|
| A run reporting nothing records nothing | It says nothing about how results are fingerprinted, and reading it as a change would make the next run a fingerprint change |
| `none` is recorded only where no result carried a fingerprint | One unhashable result appearing or going away beside others says nothing about how the run fingerprints |
| The salt is recorded as the client states its mark, a short digest | A rotated salt changes every fingerprint and no scheme name |
| A fingerprint change says so on its receipt | Its whole keys no longer meet the code findings' |
| A fingerprint change pairs a result and a code finding on the unprinted key where they are the only result and the only code finding holding it, and the pairing is strong | A rotated salt or a new scheme changes every fingerprint and nothing else, so a key nothing else holds is the same result, and its dismissal carries |
| A result or a code finding sharing its unprinted key with another falls to the probable layers | The fingerprint was what told them apart, and pairing them by line is a guess, so their dismissals lapse |
| The unprinted key is compared for a fingerprint change alone | On any other run a fingerprint that changed is the analyzer saying the result changed |
| Carrying from a closed code finding or another build is on the whole key, on a fingerprint change too | A result carried across a rotation opens as a new code finding there |
| Carrying from the parent build on a fingerprint change pairs on the unprinted key as the build's own code findings are paired | A branch cut after a salt rotation inherits its line's decisions rather than re-asking them |

## Placement

A code finding is one component at one occurrence (REQ-17).

| Rule | |
|---|---|
| A result in a repository the run names is placed on the build's component built from that repository | The innermost repository holding its path |
| A component is built from a repository where its package identifier names it: the `github`, `gitlab` and `bitbucket` types by namespace and name, and any type by a `vcs_url` qualifier | The inventory is the only statement of which component a directory became |
| A component whose identifier names no repository is built from the one its inventory states in a CycloneDX external reference of type `vcs`, the first where it states several | A distribution package's identifier names no repository. sonic-buildimage states one this way on packages whose identifier is `pkg:deb` |
| A repository no identifier or reference names is built into the first component whose platform enumeration names its owner as the vendor and its name as the product, compared in lower case with a hyphen and an underscore alike | `cpe:2.3:a:frrouting:frr` is `github.com/FRRouting/frr`. The enumeration is a weaker statement than an identifier naming the repository, so it is read only where nothing else names one |
| Repository addresses compare as host, owner and name, in lower case, without scheme, credentials, port, revision or `.git` | A remote written for SSH and an identifier written for HTTPS name one repository |
| A result in no repository the inventory names is placed on the build itself | Every build has a root |
| The inventory placed against is the build's newest that has been read | A run arriving before its inventory waits for it |

## Source

Every place a code finding names links into the repository's web view at the analyzed
commit, and carries the source kept beside it where the product keeps source
under its path. The deployment builds an address and never requests it; the
reader's browser does, and signs in where the repository is private.

### Repository settings

An administrator states them per product, through the API or the product's
Repositories screen (`design-docs/interface.md` § The repositories screen), and the
change is in the administrative trail.

| Setting | |
|---|---|
| Hosts | Each a remote prefix, a web address, and a style: `github`, `gitlab`, `gitea` (Forgejo writes Gitea's), or `custom` with a file template and an optional comparison template |
| Paths | Each a prefix of the checkout, with a repository and branch for links where an upload names none, whether source under it is kept, whether kept source is disclosed with a flaw, or any of them |

| Rule | |
|---|---|
| A web address is `https`, with no credential, query or fragment | A scheme is something a browser acts on |
| A custom template begins with `{repo}/` and names only `{commit}`, `{path}`, `{start}` and `{end}`, or `{from}` and `{to}` for a comparison | A template beginning anywhere else could open on another host |
| A remote prefix may hold a path, which is how a mirror is named: the host covering a remote is the one with the longest prefix, and the rest of the remote is the repository under its web address | `git.example.com/mirror/github/FRRouting/frr` opens at `https://github.com/FRRouting/frr` |
| A path's repository and branch are named together or not at all | One is no link |
| A path that names no repository and says nothing of source is refused | It says nothing |
| A product states at most 100 hosts and 2,000 paths | sonic-buildimage pins dozens of submodules |
| Remotes and prefixes are compared normalized: a host in lower case, a path with no leading or trailing slash | One repository written two ways is one entry |

### Source links

| Rule | |
|---|---|
| A path is in the run's repository with the longest prefix holding it, and the rest of the path is within that repository | `src/sonic-sairedis/SAI/inc/saiport.h` is `inc/saiport.h` in SAI, at SAI's commit |
| A relative remote resolves against the remote of the repository holding it, itself resolved the same way; an SSH remote is read as the host and path it names, written with a user or without one | `.gitmodules` uses both |
| A remote is recorded and shown with any credential and query taken out | It comes from the upload, and a token in it would reach every reader of the code finding |
| A remote on no host the product names is shown as text, unlinked | The remote comes from the upload, so without the list its host is the uploader's choice |
| A revision an upload states opens a link only where it is a commit: 7 to 64 hexadecimal digits, and is shown unlinked otherwise | A branch an upload names moves, and `?` or `#` in it would steer the link |
| Each path segment is percent-encoded, and a segment that is empty, `.` or `..` leaves the place unlinked | `?`, `#` and traversal in a path would otherwise steer the link |
| A finished address must open over `https` on the host the web address names, or the place is unlinked | The last check, after every template and substitution |
| A repository whose working tree differed from its commit when it was analyzed is marked patched | The link shows the source before the patch |
| A path no run repository holds links to the branch a product names for its longest prefix, marked approximate | The commit is unknown |
| A place with no line opens the file; an end before the start is the start | |
| A code finding the build no longer holds open carries a comparison of its repository between the build of the newest run that saw it and the build of the first that did not, or says the two name the same commit and neither was patched | A disappearance where the code did not change is not a fix in that code, and a patch applied at build time is a change the commit does not show |

Each unlinked place says why: no repository is known, the repository is on no
named host, the revision is not a commit, or the path leaves the repository.

### Snippets

| Rule | |
|---|---|
| Source is kept under a path where the longest prefix stating it says so, and nowhere where no prefix states it | Off by default: a private product may not allow its source in another system, and may carry public upstreams it does |
| The upload's own statement of which paths are public decides nothing | A misconfigured pipeline could label a private path public |
| Source is decided as an upload arrives, for the result and for every step and related place, and a place outside the checkout keeps none | A change to the setting reaches the uploads after it |
| A context region's source is preferred to its region's, with the line it starts at | It is the wider of the two |
| At most `analysis.max_snippet` bytes of source are kept per place, 4 KiB where nobody has said | A client sends a few lines either side |
| A snippet is answered as text, and shown as text | It is uploaded data (REQ-66) |
| Source is disclosed with a flaw under a path where the longest prefix stating it says so, and stripped everywhere else | Off by default: a private product's source is not published because one flaw in it was (§ Flaw records) |

### Rule documentation

A rule's documentation address is recorded as a `documentation` reference on
its issue where it is `https`, on the default port, with no credential, on a
host analyzers document rules on: the LLVM, Cppcheck, CodeQL, GitHub
documentation, SonarSource, Semgrep, PMD, SpotBugs, Find Security Bugs,
Bandit, Pylint, Ruff, ESLint, Staticcheck, golangci-lint, Clippy, Microsoft
Learn and PVS-Studio hosts. Any other address is dropped. It comes from the
upload, so a host outside the list is the uploader's choice of where a reader
is sent.

### Evidence

`GET …/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}` answers one code finding's
evidence on one build: its rule, where it is, the path the analyzer took to
it, the related places, each with its link and source, when it was last seen,
and, for a code finding no longer open, when it was first not seen, by which run, with
the comparison above, and the run a person named as the build that fixed it.
Beside each of the two builds it names the commit the code finding's own repository was
at: the run's repository holding the code finding's path, or the top of the checkout
where none does, and nothing where that is not a commit. It names the live decision at the code finding, agreed to or waiting, where the
reader may read one. The occurrence identity addresses a code finding because a rule's name holds a
slash.

| Rule | |
|---|---|
| The code finding is read through the Evidence consumer, which includes the analysis kind alone (`design-docs/kinds.md` § Consumers) | Nothing of a code finding reaches a vulnerability consumer |
| It is read in the data layer at the visibilities the subject reads in the product, and a code finding nobody may read there answers as an occurrence holding nothing (REQ-42, REQ-43) | A different answer would say a code finding is there |
| The open code finding is answered, or the newest where none is open | A reappearance opens a new finding at the same occurrence |
| Every link is built when the evidence is read, from the newest run's repositories and the product's settings | A change to the hosts reaches every place at once |

## Code finding triage

A decision about a code finding is a decision as `design-docs/triage.md` describes one: one
argument, its rows, its reasoning and every revision of it, and a second
person's approval of one revision (REQ-24, REQ-28). It is keyed on the
product, the rule the code finding is filed under, and the code finding's occurrence, with no
versions, so one decision covers the code finding on every branch or tag and variant it is
seen on (REQ-25).

`POST …/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/decision` records one.

| Outcome | Means | Second person |
|---|---|---|
| `dismissed` | Not a flaw to act on, for the reason stated | Yes |
| `not-security` | Real and harmless: a crash on a path no input reaches, a leak in a tool that exits | Yes |
| `confirmed` | A real flaw | No |

| Reason a code finding is dismissed | Means |
|---|---|
| `false_positive` | The analyzer is wrong: the flaw is not there |
| `wont_fix` | The flaw is there and will not be fixed |
| `used_in_tests` | The code is only used in tests and does not ship |
| `mitigated` | Something already in place stops it, which the reasoning names |

| Rule | |
|---|---|
| A code finding takes the code finding outcomes alone, and a vulnerability takes none of them | A code finding is asked whether it is real; a vulnerability, how a known issue applies |
| A dismissal states one of the four reasons | A dismissal nobody can review is one a second person cannot agree to |
| A decision about a code finding covers its occurrence at any version | The occurrence is the code finding, carried by matching rather than by versions |
| A decision about a code finding is approved by somebody holding `approver` and `internal-read` on the product, and never by its author | The approval every decision has, at the visibility a code finding has |
| A fixed code finding takes no decision | It opens again where it is seen again |
| A code finding paired only probably, on its function or its nearest line, lapses the decision dismissing it or calling it no security issue | The decision was about the result as it was keyed. A weaker pairing guesses it is the same result, so its author re-affirms it, one decision or many, as a lapsed decision is re-affirmed (`design-docs/triage.md` § Re-affirmation) |
| A decision confirming a code finding stands through a probable pairing | It says the flaw is real, and a weaker pairing does not make it less so |
| The lapse is written in the transaction that records the pairing | A pairing is never recorded with the decision on it left standing |

### Fixed code findings

`POST …/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/fixed` closes a code finding
on one build, with what fixed it and the build that fixed it.

| Rule | |
|---|---|
| Only a code finding the newest comparable run did not see is closed as fixed | That absence is the evidence the statement is made with; a run still reporting the result is the authority on what it found |
| It closes the code finding on the build named and nowhere else | Each build holding it is a statement of its own |
| It names the run whose build fixed it: one of the code finding's series on that build, applied and comparable, built at or after the first run that did not see the code finding, and any other run is refused | A statement of a fix names the build it shipped in. The code finding's evidence names the first run that did not see it, and once it is fixed, the run named |
| It is closed by somebody holding `internal-triage` on the product, who says what fixed it | The closure a person writes, with who, when and why on the record (`design-docs/findings-flaws.md` § Recorded flaws) |
| A code finding seen again opens anew at the same occurrence | The matching that finds a closed code finding carries the result to its occurrence (§ Carrying) |
| A decision about a code finding is read through the Decisions consumer (`design-docs/kinds.md` § Consumers) | The review queue, approval and one decision's reads include it; the findings lists do not |

### Suppression rules

A suppression rule dismisses every code finding of a product it names, with one reason
and one reasoning: `tests/`, vendored code, a checker noisy on this codebase.
`…/products/{product}/suppression-rules` lists, proposes, approves and retires them.

| A rule names | Covers |
|---|---|
| An analyzer rule | Every code finding filed under it, compared as the rule's issue is, without regard to capitals |
| A path | Every code finding at or under it |
| Both | Every code finding of the rule at or under the path |

| State | When | Dismisses |
|---|---|---|
| `proposed` | Nobody has approved it | Nothing |
| `in-force` | Approved, and covering no more than the code findings its approver was shown times the growth factor | What it names |
| `outgrown` | Approved, naming an analyzer rule, and covering more than that | What it names, and asks to be approved again |
| `needs-path` | Naming an analyzer rule and no path, where a run has since found the rule to find memory safety or injection | Nothing, until it is retired and proposed again with a path |
| `retired` | Taken out of use | Nothing |

| Rule | |
|---|---|
| A rule is proposed by somebody holding `internal-triage` on the product, and approved by somebody else holding `approver` and `internal-read` there | The second person a dismissal has (REQ-24) |
| A rule names an analyzer rule, a path, or both, and states one of the four reasons and its reasoning | A rule naming neither would dismiss every code finding the product has |
| A rule naming an analyzer rule and no path is refused, at proposal and at approval, where the rule finds memory safety or injection (§ Weakness families), or where no run has recorded the rule, and one approved before a run found that stops dismissing at once | A flaw of those kinds is judged one code finding at a time. A whole checker is dismissed where it fights a convention, measures style, or cannot model the code; a leak checker is dismissed under the pool allocator it cannot see |
| A path is a prefix from the top of the checkout, with no leading or trailing slash | `src` holds `src/a.c` and `src`, and not `src2/a.c` |
| A path is compared exactly, character by character | Paths are case-sensitive, and SQLite's LIKE ignores the case of ASCII letters |
| A path climbing out of the checkout or holding an empty segment is refused | It names nothing a run reports |
| Its words never change | An approval is of what was read (REQ-28). A rule worded differently is retired and proposed again |
| Approval records the open code findings the rule covers as its approved size | What the approver was shown |
| The growth factor is `triage.suppression-rule-growth`, two where nobody has said | A rule covering ten code findings when approved and a thousand later is not what the approver read (REQ-27) |
| A rule naming a path alone is never outgrown | Code under a dismissed path grows as a matter of course, and what the approver agreed to is the path |
| An approval shown no code finding is measured as though shown one | A rule approved before its analyzer rule reports anything is not outgrown by its first code finding |
| An outgrown rule is approved again at its new size, and a rule in force is refused | Approving again is how the approver reads what it now covers |
| An outgrown rule keeps dismissing what it names | Withdrawn, every code finding it covers would reach the queue at once, which is the noise the rule exists to hold |
| A rule's coverage counts open code findings by occurrence, approved or not, where the reader may read them | A proposal shows its approver what it would dismiss (REQ-42) |
| Coverage is worked out when it is read | A new code finding under a rule in force never reaches the queue |
| Proposal, approval and retirement are recorded in the administrative trail | As assignment rules are |

### Code finding states

A code finding's state is worked out when it is read, from its finding, its sighting
and the decision standing at its occurrence. The evidence of a code finding carries it.

| State | When |
|---|---|
| Fixed | The finding is closed |
| Recorded as a flaw | It was recorded as a flaw (§ Flaw records) |
| Dismissed, Not a security issue, Confirmed | A decision with that outcome stands at the occurrence: approved, or waiting on nobody and not sent back |
| Dismissed | No decision stands, and a suppression rule in force or outgrown covers it (§ Suppression rules) |
| No longer detected | A comparable run did not see it |
| Open | None of the above |

| Rule | |
|---|---|
| A standing decision comes before a suppression rule | A decision about one code finding is more specific than one about many |
| A standing decision or rule comes before absence | A dismissed code finding a run does not see stays dismissed and records the absence |
| A decision waiting for a second person leaves the code finding where it was | It answers nothing until somebody agrees |
| A code finding recorded as a flaw leaves the queue and takes no decision | Its flaw is what is judged |

## Code finding queue

A product's code findings are listed one row per code finding, however many of the product's
builds it is open on. A row shows the newest of those findings: its rule, its
path, line, function and message, the build it is on, and its state there.

| Order | |
|---|---|
| The tier of the weaknesses the rule names, highest first (§ Weakness families) | Memory safety above style |
| Whether another analyzer reports the same flaw on the build (§ Grouped code findings) | Two tools agreeing is the strongest sign a result is real |
| The tool's own security severity for the rule, highest first, and a rule with none after every rule with one | CodeQL and semgrep rate a rule's results from 0 to 10 |
| The tool's own precision for the rule: `very-high`, `high`, `medium`, `low`, then none | How often the rule is right, as its tool measures it |
| Newest first | The work that arrived last is the work nobody has looked at |

Whether a path ships orders nothing. Code that does not ship — tests, tools,
examples — is set aside by a suppression rule naming its path (§ Suppression
rules), which takes its code findings out of the queue rather than lower in it, and
one way to say a path does not matter is kept rather than two.

| List | Holds |
|---|---|
| The queue, with no state named | Open code findings with no decision waiting for a second person |
| A state named | The code findings in that state. Fixed is the code findings closed on a build and not opened anew there |

| Rule | |
|---|---|
| Every list counts the code findings in the scope by state, the open code findings a waiting decision leaves out of the queue, and the dismissed code findings a suppression rule covers | A list that leaves code findings out says how many it left (REQ-30) |
| A code finding closed as fixed is listed and counted as fixed on its build until it opens anew there | A code finding seen again opens at the same occurrence (§ Fixed code findings), and then it is what the newer finding says |
| A code finding open on two builds in two states counts in both | The count is of code findings in a state, and a code finding no longer detected on one build is open on another |
| Only what the subject may read is listed or counted | Visibility is enforced where the code findings are read (REQ-42, REQ-43) |
| A branch or tag and a variant narrow the list independently | One build, one line, or the whole product |
| A series narrows the list by its name, matched without regard to capitals | A name no series of the product holds lists nothing, the same answer as a series holding no code finding |
| A testing method narrows the list to the kind of finding the method records, and the filter offers every method the queue knows | SAST is static analysis, the analysis kind, and the one method recorded. A method nothing records is refused by name |
| Narrowed to work nobody holds, the list keeps the code findings with no holder on the build each row names, under the parameter and value the findings list uses | The findings list holds no code finding, so this is where unheld code findings are found (§ Code finding assignment) |
| Narrowed to work nobody holds, every count is of the code findings the narrowing keeps | A count beside a narrowed list describes what that list leaves out |
| A rule's rating is the one the newest run naming it gave, held until a run rates it again | A run of the tool that omits the properties says nothing about the rule |
| A rule's tier is the highest of every weakness recorded for it, ranked again each time a run names the rule | A rule's weaknesses accumulate as its tags do, and a tier table changed by an upgrade reaches a rule at its next run |
| A severity outside 0 to 10, or one that is not a number, and a precision outside the four words, are read as none | The order is the tool's, and a value it does not define orders nothing |

### Queue file

`GET /v1/products/{product}/code-findings.{format}` writes the list out as CSV or
JSON, as `design-docs/analytics.md` § Exports writes every file.

| Rule | |
|---|---|
| The file is the list: the same filters, the same order, every row rather than one page | A list and its file are one read, so a filter the screen applies is never missing from the file |
| It is read under the list's visibility | A reader is written the code findings the list shows them, and nothing else (REQ-42, REQ-43) |
| A row names who holds the code finding as the list does: who, their display name, and whether it is a team's queue | A team and a person may share a name, and every signal the list carries is a column (`design-docs/analytics.md` § Exports) |
| A row says whether the code finding is in third-party code, as the list does | Read from the newest run that saw the code finding, as its evidence is (§ Third-party code) |
| No row carries source text | The queue holds none. A snippet is evidence, kept under the path's setting (§ Snippets) |
| With no state named the file says it lists the queue | An empty query reads as everything, and the queue leaves out code findings a waiting decision holds and code findings past their end of life |
| Narrowed to work nobody holds, the file says so beside what it lists | A file read later carries the narrowing it was written under |
| A refusal is answered before the first byte | A refusal written into the file would follow a 200 |
| A findings list's file writes every open code finding of its selection below its findings, through this read with the code findings a decision waits on kept in (`design-docs/analytics.md` § Exports) | The finding exports include the code findings the reader reads (REQ-50) |

### Code findings by series

`GET /v1/products/{product}/code-finding-series` counts a product's code findings per analyzer
series, by state. The analytics catalog draws it as Code findings by analyzer
(`design-docs/analytics.md` § Pages of the catalog's own).

| Rule | |
|---|---|
| Every state is counted, zero included, beside how many open code findings a waiting decision leaves out of the queue and how many dismissed code findings a suppression rule covers | The states are worked out for the queue already, so each costs nothing more |
| Each count is the total the list answers for that series and state | A figure and the list it opens count one population, under the same visibility |
| Counted over every build of the product | A series is the product's. A branch or tag or a variant would list a series that never ran there with every count zero, which reads as an analyzer that found nothing |
| A series holding no code finding is listed with every count zero | An analyzer that runs and finds nothing is a fact about the product |
| Read only by somebody holding `internal-read` on the product, and refused to anybody else with no count and no series named | A count of code findings is internal however it is narrowed. A reader of an included code finding through its flaw reads the code finding and not the product's figures |
| Ordered by the series' name | The series are few, and a reader looks one up by its name |

## Code finding assignment

`PUT …/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/assignment` gives a
code finding to a person or a team, or hands it back to nobody, as a finding is
assigned (`design-docs/access.md` § Assignment, § Teams; REQ-34).

| Rule | |
|---|---|
| It covers the code finding on every build of the product it is open on | A code finding is one occurrence across the product's builds, as a decision about it is |
| The assigner triages the code finding at every visibility it is open at | Internal, where a code finding not recorded as a flaw is. Somebody who does not is answered as though the code finding were not there |
| Giving it to somebody else, or taking it from them, needs `assigner` as well | The assigner right a finding's assignment asks for |
| A person is given it only where they read it at every visibility it is open at, and a team only where one member reads all of them | Holding a code finding is not a way to read one. A code finding collaborator reads the code finding through their grant and is not given it |
| Asked inside the transaction that writes | As every assignment asks it |
| A code finding past its end of life is refused with 409 | § End of life |
| A code finding recorded as a flaw, included in disclosure or not, is refused with 409, and its page offers no holder | It is closed work for its holder, and its flaw is assigned instead |
| A code finding seen on a build where it was not open when it was assigned starts unassigned there | As a finding arriving under an assigned component does |
| Losing the reading a code finding needs, deactivation and a handover move code findings with everything else, but for the code finding recorded as a flaw below | One act whatever the work is (`design-docs/kinds.md` § Consumers) |
| A team's assignment rules place code findings nobody holds, and no code finding recorded as a flaw | `design-docs/access.md` § Assignment rules. Whoever triages internal work in the product reads and previews them |
| The lists of held work list a code finding, one row per code finding, to whoever reads it | Unassigned work, one person's work, a team's queue and the totals per holder (`design-docs/kinds.md` § Consumers). A code finding is listed to readers of internal work in the product. A row names the analyzer's rule and opens the code finding's page |
| The unassigned list leaves out a code finding's sightings in releases past their end of life | Nobody may take a code finding seen only there, and the code finding queue narrowed to work nobody holds leaves it out the same way (§ End of life) |
| A code finding recorded as a flaw leaves the lists of held work, included in disclosure or not | Its flaw is what is judged, fixed and disclosed, and the flaw is held and listed as itself. The code finding recorded as a flaw is closed work for its holder |
| Handing somebody's work to another person leaves a code finding recorded as a flaw with them, and asks nothing about it. Releasing their work releases it | It is listed to nobody, so moving it hands over nothing, and a recipient who may not read it is not refused for it |
| The code finding's page and every row of the queue and its file name who holds it | The page names the holder on its build while it is open there; a row names the holder of the finding it shows |
| The person given it is told "a code finding assigned", at internal visibility | `design-docs/notifications.md` § Code finding notices |

## Weakness families

A rule names the weaknesses its tags name, as `external/cwe/cwe-N`, or as
`CWE-N: name`, which semgrep writes. A rule
whose tags name none takes the weaknesses a table held here names for it.
Tools disagree about the number for one flaw: one overflow was CWE-788, 119
and 121 from three tools. They agree about its family.

| Tool | Source of its weaknesses |
|---|---|
| CodeQL | Its rule tags |
| semgrep | Its rule tags |
| cppcheck XML | The tags the upload client writes from each error's weakness |
| cppcheck SARIF | Its rule tags from the release that writes them. Releases 2.16 to 2.18 tag a rule `security` and name no weakness, so a table generated from `cppcheck --errorlist` by `make cppcheck-weaknesses` names one, for 302 checks of cppcheck 2.22.0 |
| clang, and the clang checkers clang-tidy runs | A table held here, by checker, over the 47 checkers clang 18 runs on C. clang tags nothing and publishes no table. A checker no weakness fits with confidence is held as naming none, and `make clang-checkers` names a checker a new release adds |

| Rule | |
|---|---|
| A weakness's family is the nearest class up its primary parents in the catalog's research view, or itself where it is a class or a pillar | CWE-121, 122, 126, 787 and 788 are all CWE-119, and so are use after free and double free |
| A pillar is the family of no weakness under it. A weakness reaching a pillar with no class between takes the weakness just under the pillar | The catalog files a null dereference, a condition always true and an obsolete function directly under CWE-710, and 26 cppcheck and clang rules shared that family. cppcheck names a `sizeof` on a pointer CWE-467 and clang names the same `malloc` CWE-131, the base above it under CWE-682 |
| A weakness the catalog does not place is its own family | A newer catalog than the one committed assigns numbers this one does not know |
| The hierarchy is read from the published catalog by `make weakness-names` and committed with the names | `design-docs/build.md` § Make targets. Nobody types a thousand parents |
| A clang checker reporting several kinds of flaw names each | unix.Malloc reports leaks, double frees and uses after free under one name, so it is a memory-safety rule and groups in the resource family and the bounds family both |
| A rule whose tags name a weakness is classified by its tags alone | The tool's own word about its rule outranks a table about it |

A weakness's tier says how likely it is to be a flaw worth fixing first. It is
the tier of the nearest of itself and its ancestors the table names, so naming
a class names everything under it, and a weakness named here outranks its own
class.

| Tier | Names |
|---|---|
| Memory safety | CWE-119, a bound overrun, and use after free and double free under it; CWE-476, a null pointer, which the catalog files under coding standards; CWE-824 and CWE-908, a pointer or value read before it is written, and CWE-457; CWE-190, an integer that wraps; CWE-134, a format string the caller controls |
| Input reaching where it should not | CWE-74, CWE-77 and CWE-943, injection; CWE-20, input not validated; CWE-706, a name resolved wrongly; CWE-362, a race |
| A resource or an error left unhandled | CWE-404, a resource not released; CWE-754, a condition not checked; CWE-665, initialization done wrongly; CWE-834, iteration with no bound; CWE-682, a calculation done wrongly |
| Everything else | Style, dead code, a weakness no tier names, and no weakness at all |

The table is a judgment no decision records: memory safety above style, for
the C and C++ these analyzers read.

## Grouped code findings

Two analyzers on one build report some flaws twice. Each tool's result stays
its own code finding, with its own history. Two code findings are the same flaw where every
one of these holds:

| Condition | |
|---|---|
| Both are open on one build | A flaw is in the code one build was made from |
| Their analyzers differ | One analyzer reporting two results on adjacent lines has already told them apart. An analyzer is the part of a rule's name before the first `/`, in any case, and a clang checker clang-tidy runs is clang's: clang-tidy runs clang's own static analyzer, so the two agreeing is one analyzer agreeing with itself |
| Their rules' weaknesses share a family (§ Weakness families) | One overflow was CWE-788, 119 and 121 from three tools |
| Their last places are in one file, within two lines | cppcheck names where a problem starts and the others where it bites: first places differed in 8 of 41 same-flaw pairs, last places in 2 |

Within two lines grouped every same-flaw pair of clang, cppcheck, CodeQL and
semgrep over libyaml, jq, Lua, giflib and seeded files, and none of five pairs
of flaws a line or two apart. A wider window or a first place falsely merged
at least one.

| Rule | |
|---|---|
| A result's last place is the last step of its path, the last related place in its own file, or its own place | cppcheck lists the places after the first as related, in order |
| Code findings within ten lines and otherwise alike are listed under Possibly also found by, and never grouped | A false merge hides a second real flaw behind one decision |
| A code finding's evidence lists, under Also found by and Possibly also found by, the code findings that are the same flaw and those that possibly are, where the reader may read them | Visibility is enforced where the code findings are read (REQ-42) |
| A group is a code finding and the code findings within two lines of it, worked out for each code finding | Two code findings each the same flaw as a third and four lines apart are two groups |
| Whether another analyzer reports a code finding is worked out over every code finding on the build, whoever reads it | Where a code finding sorts does not depend on who is looking |
| The code findings near a code finding are found through an index on a digest of the last path, and the last line | A path is text no MySQL index takes whole. For 16,000 code findings of two analyzers' first runs on one build, the queue answered in 0.6 s on PostgreSQL 16 and 1.2 s on MySQL 8.4, and in 90 s and 37 minutes without the index |
| A rule with no weakness groups with nothing | clang tags none, so a clang code finding groups only once its weaknesses are known |
| A decision about a code finding covers it and every code finding of its group that nothing answers yet, agreed to once | The same flaw takes the same answer whichever tool reported it |
| A code finding of the group already answered, waiting on a decision, under a suppression rule, fixed, recorded as a flaw, past its end of life (§ End of life), or unreadable by the person judging is left out | A code finding already answered keeps its own answer, and a decision reaches no code finding its author cannot read (REQ-42) |
| A code finding possibly the same flaw is left out | It is judged on its own |

## Flaw records

A confirmed code finding is recorded as a flaw found here (REQ-19), through the path
every recorded flaw takes (`design-docs/findings-flaws.md` § Recorded flaws), and linked
to it. The code finding is then recorded as a flaw: its flaw is what is judged, fixed and
disclosed.

`GET …/branches-and-tags/{branch_or_tag}/variants/{variant}/code-findings/{occurrence}/flaw` is what a
flaw record is offered, and `POST` on the same address records it.

| Rule | |
|---|---|
| Only a confirmed code finding is recorded as a flaw, and only once | Confirmation is the decision that it is a flaw; a second flaw for one code finding is one flaw recorded twice |
| A flaw record links the code finding and every code finding its confirming decision covers that nobody recorded as a flaw to the one flaw | One decision confirmed them as one flaw (§ Grouped code findings). A code finding of the group left behind holds a decision nothing may change, and no flaw |
| A flaw record is made by somebody holding `internal-triage` and `private-triage` on the product | It reads the internal code finding and writes the private flaw |
| The flaw is undisclosed, found here, and recorded at no version | A flaw in our own code is the disclosure process's case. A code finding is carried by its occurrence rather than by versions |
| The flaw and the link are written in one transaction, which reads again that the code finding is confirmed and not recorded as a flaw | A retry is asked the question again (REQ-71) |
| A flaw record changes the stamp of the decision standing at the code finding, matched on the stamp it read, as every write to a decision does (`design-docs/database.md` § Reads a write depends on) | A withdrawal of the confirmation committing beside the flaw record would otherwise leave a flaw nobody confirmed. The one that matches nothing is taken again, and finds the other |
| A code finding recorded as a flaw takes no decision, and no decision about it is revised, withdrawn, split, approved or sent back; each is refused with 409. An undone batch of approvals leaves such a decision out | The flaw's decisions replace the code finding's, and a confirmation withdrawn under a code finding recorded as a flaw leaves a flaw nobody confirmed |
| Recording as a flaw, an inclusion in disclosure, a removal from it and a withdrawn flaw record are refused to anybody without both triage roles before any build the request names is resolved | A refusal that differed for a build that exists and one that does not would list a product's builds (REQ-42) |

| The flaw records the code finding it was recorded from, the component the offer ranked first, and the builds it proposed: every build the code finding was seen in, and the builds holding the chosen component that the series never analyzed | `design-docs/findings-flaws.md` § Recorded flaws. The record outlasts the link, so a flaw whose flaw record was undone still says where it came from |
| The flaw's page names its code finding to a reader who reads the flaw there and the code finding in full, and to nobody else | An internal-only code finding is internal, and a reader of the private flaw has not been given it (REQ-42) |

### Flaw record offer

| Part | |
|---|---|
| Builds | Every build holding the code finding, open or closed, which the flaw is proposed against. The person chooses which it is recorded against |
| Components | Ranked: the one the code finding's prefix was confirmed as before, the one the code finding was placed on as it arrived, up to five whose names resemble the prefix's last segment, then the build itself |
| Lacking | For each component, the builds the code finding was seen in that hold no such component. Recording the flaw against them is refused |
| Unanalyzed | For each component, the builds in use that hold it and that the code finding's series never analyzed. A variant nobody analyzes ships the same code |
| Prefix | The innermost repository the run names or third-party path it declared holding the file, or else the file's directory |
| Third-party | Whether the file is under a path the run declared third-party, so the flaw is reported to the upstream (§ Third-party code) |
| Together | How many other code findings the flaw record links to the flaw with this one, which are included in disclosure or taken out with it |
| Disclosure | What including the code finding and the code findings linked with it in disclosure discloses with the flaw: every note on a decision about them, by author, the paths and messages the analyzer wrote, and whether snippets are published (§ Disclosure inclusion) |

| Rule | |
|---|---|
| The component chosen is recorded for the prefix, replacing what it was confirmed as before, and the build itself leaves the prefix confirmed as nothing | The next code finding under the prefix is offered it first. A component a person turned down is not offered first again |
| The longest recorded prefix holding a code finding's path is the one offered | A repository nested in another names its own component |
| A resembling component is offered and never chosen for the person | A name contained in a directory's name is a guess |

### Disclosure inclusion

A code finding recorded as a flaw is internal only, or included in its flaw's
disclosure. Include in disclosure is one choice, off by default, made when the
flaw is recorded and changed while it is undisclosed: it decides only what is
published at disclosure. `PUT …/code-findings/{occurrence}/flaw/disclosure`
includes an internal-only code finding, and `DELETE` on the same address takes an
included one out.

| | Internal only | Included in disclosure |
|---|---|---|
| Visibility of the code finding and the decisions at its occurrence | Internal | Internal |
| An internal reader reads | The whole code finding and its decisions, and nothing of the case | The whole code finding and its decisions, and nothing of the case |
| Somebody granted the code finding reads | The whole code finding without its decisions, and its flaw | The whole code finding without its decisions, and its flaw |
| A reader of undisclosed work reads | Nothing | The whole code finding and its decisions, and its flaw |
| A reader on the flaw's case reads | Nothing, unless they were granted the code finding | The whole code finding and its decisions, and its flaw |
| When the flaw is disclosed | The code finding stays internal | The code finding and its decisions go public with the flaw (REQ-40) |
| A later sighting opens | Internal | Internal, read by both audiences |

| Rule | |
|---|---|
| An inclusion adds the flaw's readers to the code finding's readers and takes nobody away | Somebody who read the code finding once keeps reading it |
| Taking a code finding out of disclosure takes back only the readers the inclusion added, from the code finding and from the decisions at its occurrence | The code finding's internal readers and its grants are as they were |
| The flaw's readers read an included code finding wherever its internal readers do: its evidence, the queue and the counts beside it, its file and the findings file, the coverage of a suppression rule, and its kin | One rule in the data layer, so no list answers differently from the page (REQ-42, REQ-43) |
| Reading undisclosed work reads no internal code finding the flaw does not hold | The addition is the included code findings of an undisclosed flaw, and nothing else of the product's internal work |
| The flaw's readers read the decisions at an included code finding's occurrence while the flaw is undisclosed: the reasoning and its revisions, the approvals, the comments, one decision's page, and every list, count and export holding them | The audience that reads the code finding's evidence reads the decisions about it, and those go public with the code finding at disclosure |
| The decisions stay internal, and the addition is the internal decisions at an included code finding's occurrence and nothing else | A decision is filed under the analyzer's rule, and the flaw's readers read no other internal decision in the product |
| Reading a decision at an included code finding is not arguing it | A comment and an approval each keep the decision's internal triage role, and a decision about a code finding recorded as a flaw is neither revised nor withdrawn |

| Rule | |
|---|---|
| An inclusion discloses, with the flaw, every revision of reasoning and every comment on a decision about the code finding or the code findings linked with it, every path they name and every message the analyzer wrote there | People writing in the record have to know that from the first word (REQ-40) |
| The offer shows that writing before the inclusion, grouped by author, with the paths and messages, and says whether snippets are published and how many are stripped | The person including it reads what goes public |
| The writing in the offer is read at the visibilities the caller reads in the product | A flaw record takes both triage roles, and the read is narrowed in the data layer all the same (REQ-42) |
| Disclosed means readable in the portal by everybody signed in with public access to the product | A code finding is never in a published VEX or CSAF document, and the anonymous subject reads no code finding |
| At disclosure an included code finding's kept source is stripped, except under a path whose setting discloses it (§ Snippets), and a later run describing the disclosed code finding again is stripped the same way | A product's source is not published because one flaw in it was, and a run writes what the analyzer sent |
| Disclosure records the time on the flaw record of every code finding recorded as the flaw, included in disclosure or not | An internal-only code finding stays internal, so its visibility does not say its flaw is public |
| An inclusion or its removal is refused with 409 once the flaw is disclosed | Disclosure is one way |
| The notice of an inclusion goes to the audience it went to before the readers changed | An inclusion tells the flaw's people the code finding is part of the case |
| An inclusion and its removal take every code finding recorded as the flaw | The code findings of one flaw are one case |
| A run writes itself onto the flaw record of every code finding it describes or opens at, before it reads a flaw record or writes a code finding's source | A disclosure or an inclusion of one of those code findings then waits for the run, or finds the flaw record changed |
| An inclusion, its removal and a disclosure each change the flaw record only as it was read in their transaction: its visibility, its flaw undisclosed, and the last run to describe it | One that lost a race to another, or to a run, is asked again. A disclosure that read the flaw record before a run cannot see the source the run wrote, and an inclusion cannot see the sighting it opened |
| An inclusion and its removal are recorded in the administrative trail, as the change of access they are | An inclusion changes who reads the code finding |
| An inclusion and its removal are made by somebody holding `internal-triage` and `private-triage` | The flaw record's own rule |

### Withdrawn flaw record

`POST …/code-findings/{occurrence}/flaw/withdrawal` undoes a flaw record, with why.

| Rule | |
|---|---|
| It takes every code finding recorded as the flaw | The code findings of one flaw are one case, as an inclusion takes them |
| It is refused with 409 once the flaw is disclosed, and asks for a reason | Disclosure is one way. Undoing takes the flaw out of every build, which a person explains |
| Each code finding is confirmed again: the link goes, the decision confirming it stands, and it returns to the queue's lists of held work with whoever held it | Undoing takes back the recording and leaves the decision that it is real |
| An included code finding is read by its internal readers alone again | A code finding with no case to be in is the internal material it always was |
| Every grant of the code findings ends, each recorded in the administrative trail as a withdrawal | A grant brings somebody into a case, and there is none |
| The flaw's open findings close as `invalid`, with the reason, on every build | A flaw recorded from a flaw record somebody undid should not have been recorded, and a flaw record made again records a flaw of its own. Invalid counts as no fix and names no release fixed (`design-docs/findings-closure.md` § Affected build sets) |
| The flaw keeps the record of its code finding, marked undone with who, when and why | What was recorded and taken back stays on the record |
| It is written in one transaction that reads each flaw record again and deletes it only as read | An inclusion, a disclosure or a run describing the code finding since is a lost race, asked again (REQ-71) |
| It is recorded in the administrative trail once per code finding, each under that code finding's own name, as each grant it ends is | It changes who reads the code findings and what the flaw is |

### Fixed in

A flaw recorded from a code finding is offered as fixed on each build it is open on
where its code finding is no longer detected, with the first run there that did not see
it and, where a person closed the code finding as fixed, the run they named. A person
closes the flaw there (`design-docs/findings-closure.md` § Closure by a person), and the
advisory names the build fixed from that closure (`design-docs/remediation.md`
§ The advisory).

| Rule | |
|---|---|
| The code finding read is the one the flaw record was made at, its newest finding on each build | A code finding seen again after a fixed closure opens anew, and the new finding speaks |
| Nothing closes the flaw but a person | Absence is weak evidence: of 28 comparable absences hand-checked, 10 were fixes |
| The offer is read where the flaw's code finding is, under the reader's visibility | It is part of the code finding |

### Code finding collaborators

`…/code-findings/{occurrence}/collaborators` lists, adds and removes people brought into
one code finding recorded as a flaw, as case collaborators are brought into one flaw
(REQ-43, `design-docs/access.md` § Case collaborators).

| Rule | |
|---|---|
| A grant reaches the code finding's evidence while its flaw is undisclosed, and nothing else | It is one code finding, never a list. Disclosure ends it, whether or not the code finding is included in disclosure |
| A grant does not reach the build's inventory or tree, or the code finding's kin | It is a grant of one code finding, not of the build it is on or the code findings beside it |
| Collaborators are managed by somebody who reads the product's internal work, whether or not the code finding is included in disclosure | The code finding is internal until its flaw is disclosed. A grant of the code finding, and a reading through the flaw, are not readings of internal work |
| A grant or a withdrawal is refused with 409 once the flaw is disclosed, and is made in one transaction with the read of the flaw record it depends on | The grants have ended |
| A grant and its withdrawal are recorded in the administrative trail, and the person is told they were brought in, in a line their grant reaches | As a case collaborator is |
| A reader on the flaw's case reads an included code finding in full | The code finding is part of the case |

## Third-party code

A run declares the paths holding code the product did not write (§ Run
parameters). A code finding under one is a code finding like any other, triaged and confirmed
as any other is.

| Rule | |
|---|---|
| A declared path is a prefix in its own right, as a repository is | Vendored code copied into the tree has no repository of its own. Every file under the path, at any depth, shares one prefix and one confirmed component (§ Flaw record offer) |
| The innermost of the run's repositories and declared paths holding a file is its prefix | A repository nested in vendored code names its own component, as a repository nested in another does |
| A declared path is recorded as a path from the top of the checkout | `./src/vendor`, `src//vendor/` and `/src/vendor` are `src/vendor`, and `..` climbs no higher than the top. A code finding's path is compared in that form |
| A declared path holds itself and every path under it, compared exactly | `src/vendor/zlib` holds `src/vendor/zlib/inflate.c` and not `src/vendor/zlibx/a.c`; paths are case-sensitive |
| The declaration read is the newest run's to see the code finding | The run's description of the checkout is the one the code finding's path was read against, as its repositories are |
| A run's list that does not read as a list of paths declares nothing | The upload writes a list of paths from the top of the checkout, and nothing else is a declaration |
| The code finding's evidence, its flaw record offer, its row in the queue and the queue's file say it is third-party | A person recording as a flaw the flaw reports it to the upstream it came from. Its advisory or VEX then reaches the product's builds through the supplier and upstream paths (`design-docs/ingest.md` § Supplier advisories) |
| A third-party code finding is still recorded as a flaw here | The flaw ships in the product's builds until the upstream's fix arrives, and recording it is what tracks that |

## End of life

A code finding seen only in releases past their end of life is kept as it stands, and
nothing about it is deleted (REQ-15). When a release reaches its end of life
is in `design-docs/data-model.md` § End of support.

| Rule | |
|---|---|
| A code finding is past its end of life when every release of the product holding a finding of it is | A code finding also seen in a supported release is work there |
| The queue leaves out every sighting in a release past its end of life, and counts the open code findings it leaves out | A list that leaves code findings out says how many (REQ-30). The lists by state still hold them |
| A code finding open only in releases past their end of life leaves the queue, and is past its end of life only where its other sightings are too | A code finding closed or no longer detected on a supported release is still that release's to decide, and the queue holds open work |
| A decision, a fixed closure, an assignment and a flaw record are refused with 409 | Nobody fixes a release nobody supports |
| A re-affirmation of a lapsed decision leaves such a code finding out, re-makes the rest, and is refused with 409 where none is left | A re-affirmation writes the decision at each occurrence again. The list of what is yours to re-affirm counts the same occurrences and leaves off a decision with none |
| A decision about a code finding still in support reaches none of its kin past their end of life | The kin is refused a decision of its own |
| A decision already standing at it is still agreed to or withdrawn | The decision is one somebody made, and an approval is of what was read (REQ-28) |
| A code finding already recorded as a flaw is still included in or taken out of its flaw's disclosure | The inclusion is about the flaw, which is judged on its own builds |
| Its evidence says it is past its end of life | The page offers none of the refused controls |
| A retired branch, tag or variant takes no run (§ The upload), so it stops producing sightings, and its code findings stay listed with the product | `design-docs/data-model.md` § Catalog retirement. Retiring closes off what arrives, and keeps what was found |

## Receipts

`GET …/analyses` lists a build's runs newest first.

| Field | |
|---|---|
| Status, failure | § Run application |
| Comparable, and the reason where not | § Run parameters |
| Tool and version | As recorded |
| Counts | Opened, seen again, returned, no longer detected, left open as uncompared, paired probably, carried from the branch a build was cut from, reopened at a closed code finding's occurrence, and what was dropped, left out and discarded, each by reason |
| Fingerprint change | Whether the run's fingerprints changed from the build's last (§ Fingerprint change) |
| Sharp drop | Whether the run marked more no longer detected than the deployment expects of one run (§ Run application) |

Beside the runs, the list carries the last upload of each series to the
build that was turned away after its sender was admitted: the series as the
upload named it, when, and the words the sender was told. One is kept per
series and build, replaced by the next. An upload refused before its sender
was admitted to the build is recorded nowhere, because recording it would
tell whoever reads the build that somebody without access tried.

A receipt counts code findings and never names one. A pipeline key reads the receipts
of a build it may send to; a person reads them where they read internal
findings in the product, since the counts are of internal findings. A
pipeline key's other reads are unchanged (`design-docs/access.md` § Subject kinds).
Anybody else is answered as for a build nothing was sent to, before the
build's runs are looked up, so the answer is the same whether or not the build
holds any (REQ-42).

## Upload client

`openpsirt-upload` runs in a pipeline beside the analyzer. It reads the
analyzer's output and the checkout, writes one SARIF run per analyzer holding
what the deployment cannot learn from the output alone, and sends each as
§ The upload describes.

```
openpsirt-upload upload --product P --branch-or-tag B --variant V --series [TOOL=]NAME... \
  [--commit SHA] [--built TIME] [--snippets] [--salt-file FILE] \
  [--third-party PATH]... OUTPUT...
openpsirt-upload write --series [TOOL=]NAME... --output FILE OUTPUT...
```

`write` builds the same document and stores it rather than sending it, so a
pipeline can see exactly what would leave.

### Formats read

| Format | Read as |
|---|---|
| clang `plist-multi-file` | One result per diagnostic. Its issue hash as `clang/issueHash/v1`, its enclosing function as a logical location, its path as a code flow with each step's function, and each checker's documentation address. One document is one translation unit analyzed |
| cppcheck XML version 2 | One result per error. `error` and `warning` keep their level, `style`, `performance` and `portability` are notes, and `information` and `debug` are left out: they describe cppcheck's own run. Its CWE as the tag `external/cwe/cwe-<n>`, its hash as `hash/v1`, the first location as the result's and the others as related locations with their text |
| SARIF 2.1.0, from any tool | Forwarded. Artifact and rule references resolved to paths and identifiers, so nothing points into a list the client removes |
| Any of the three, gzipped | Decompressed first |

| Rule | |
|---|---|
| A native format is read where the tool has one | clang's plist carries the issue hash, the call path and the enclosing function; clang's SARIF carries none of them |
| clang's plain `plist` is not what to send | It drops a diagnostic whose path crosses files. `plist-multi-file` keeps it |
| An HTML report and a directory of output are refused | Both carry source |
| The outputs of one tool merge into one run | Rules merge by identifier, results and invocations are concatenated, and per-unit counts add |
| The outputs of several tools are one upload per tool | A series is one tool. `write` stores each in a file of its own, the tool's name before the extension. One refused does not keep the others from being sent |
| Output of several tools names each one's series, as `--series TOOL=NAME` | A series named once for all of them changes name whenever a tool is added or dropped. A bare `--series NAME` serves output of one tool |
| `--rule`, `--rules-file`, `--tool-version`, `--exit-status` and `--units-analyzed` are refused for output of several tools | Each describes one tool, and one value stamped on every tool's run would be wrong for all but one |
| `--series TOOL=NAME` naming one tool twice is refused | Neither name can be chosen without guessing |
| An output that is none of the formats is refused | It is named, with the formats read |

### Paths

Every path is written relative to the checkout, with `/`, under the starting
point `SRCROOT`, which the document leaves undefined, so the deployment places
it against the source root it is given (§ Placement).

| Rule | |
|---|---|
| A path arrives absolute, as a `file://` address, relative to the working directory, or under a starting point the output defines | Each is resolved before it is placed. A chain of starting points is followed to sixteen steps |
| A path naming no starting point is relative to the directory the client runs in | The working directory the output states is not read here, so the client is run from where the analyzer ran |
| A drive letter and a path on a drive compare without regard to case | Windows compares them that way |
| A path's case is taken from the checkout's index | A tool on a case-insensitive system writes the case it was asked for. Where two indexed paths differ only by case, the path is left as the tool wrote it |
| A path is inside the checkout where it is as written, or once the links along it and along the checkout's own path are followed | git names the checkout with its links followed, and a tool run from a directory reached through a link writes its paths through the link |
| A path outside the checkout is written as the `file://` address it is | The deployment drops it with its result and counts it; nothing about it is placed |
| A path under a starting point the output never defines is left as written | Guessing its root would place it somewhere it is not |
| A region whose end is before its start loses its end | It states a line and no span |

### Repositories

| Rule | |
|---|---|
| Every repository the checkout holds is listed, submodules at every depth | A result is placed on the component built from the innermost repository holding it (§ Placement) |
| Each is written as a `versionControlProvenance` entry with its commit and the directory it is checked out at, as a `mappedTo` under `SRCROOT` | A directory written under another starting point chained to `SRCROOT` is not placed by the deployment |
| The top repository's commit is `--commit`, or the commit checked out | The submodules' are the commits checked out |
| A remote is written as a web address: `https`, no credentials, port or `.git`, an SSH or scp-style address turned into the host and path it names | A remote written for SSH and an identifier written for HTTPS name one repository. A submodule's relative address is resolved against its parent's remote |
| A repository whose remote is a local path is left out of the list | It names no repository anybody else can reach |
| A submodule's path and name are read whole, spaces included | `.gitmodules` and `git submodule status` both allow them |
| A repository with tracked changes is named in `openpsirt/changed` | Its results describe code no commit holds |

### Fingerprints

Each result carries `openpsirt/context/v1`, a content fingerprint of the line
it is about.

| Rule | |
|---|---|
| It is a SHA-256 of the line and one line either side, each with its surrounding white space removed and every run of white space inside it written as one space, joined by line feeds | A reindented or moved block keeps it, and the same text gives the same fingerprint whatever line endings a checkout on any system gives it. A line before the first or after the last is empty |
| A carriage return ending a line is removed before anything else | A Windows checkout's line endings are the checkout's, not the code's |
| With `--salt-file`, it is an HMAC-SHA256 keyed on the file's contents, its surrounding white space trimmed | A short line cannot be recovered by hashing guesses |
| A salted run names its salt as `openpsirt/salt`: the first eight bytes of the salt's SHA-256, in lower-case hexadecimal | A changed salt changes every fingerprint, and the name is what says so |
| A salted run carries no fingerprint the tool wrote | A tool's own fingerprint cannot be salted, and a short line is recovered from it by guessing |
| A file is read only inside the checkout, every link along its path followed, and only up to 16 MiB | A fingerprint or a snippet reads nothing off the build host beside the code |

### Contents sent

| Rule | |
|---|---|
| No source text leaves unless `--snippets` is given | A run carries paths, lines and fingerprints |
| With `--snippets`, each location carries its lines, and a context region two lines either side, each bounded at 4,096 bytes | A carriage return is removed from each line |
| Whole-file contents, fixes, attachments, snippets and markdown messages in forwarded SARIF are removed, and counted in what the client prints | A markdown message with no text takes the words its markdown shows as its text, reduced as the deployment reduces one |
| A snippet is removed from every location forwarded SARIF names: a result's own, its related places, its flow steps and stack frames, the flow steps a run lists once, and the places a notification names | Each is a region of source text |
| A forwarded run's artifact list and starting points are removed | Every path is resolved before it is written, so nothing reads them |
| The run parameters are written as § Run parameters reads them: `openpsirt/client`, `openpsirt/commit`, `openpsirt/series` or `automationDetails.id` where `--built` is given, the unit counts together or not at all, and an invocation from `--exit-status` | `--compile-commands` gives the units expected as its entry count; for clang, the units analyzed are the documents read. Units expected for a tool that counts none analyzed are not sent, and the client says so |
| The rule set and the third-party paths are sent as the upload's fields | The deployment reads them from the fields alone |

### Sending

| Rule | |
|---|---|
| The document is gzipped and sent as the one `sarif` part of the upload, with the key as a bearer token | An analyzer's output compresses several times over, and the request's bound is on its compressed size |
| The address is `--url` or `OPENPSIRT_URL`; the key is `OPENPSIRT_KEY` and nothing else | A key on a command line is in every process listing on the build host |
| A 503 is sent again after its `Retry-After`, and a request that reached nothing after a pause doubling each time, five attempts in all, no pause over two minutes | A matrix of builds finishing together each gets its turn |
| A redirect is not followed, and fails the step naming where it points | The key is a bearer token, and a redirect would carry it wherever the answer points, over plain HTTP included |
| The receipt is printed as the deployment returned it; a refusal fails the step with its words | A 202 says the run is queued, and the counts are read from the run's receipt afterwards |

### Distribution

| Rule | |
|---|---|
| One binary, pure Go with cgo off, for Linux, macOS and Windows on amd64 and arm64 | It runs where the analyzer runs. `design-docs/packaging.md` § Release assets names the archives |
| The archives are covered by the release's checksum file and its signature | The same verification as every other asset |
| No Authenticode signature and no notarization | A pipeline fetches the binary by a command, which neither check stops. One downloaded through a browser on macOS or Windows is held by the system until a person allows it |
| CI runs the client's tests on macOS and Windows when one of its sources moved | `design-docs/build.md` § CI jobs. The fingerprints of one function written with each line ending are pinned to hashes worked out by hand, so a system computing them differently fails there |

## Not built

| Part | State |
|---|---|
| Code findings over time | Not built. Statistics include no code finding (`design-docs/kinds.md` § Consumers), so no report says how long a code finding took to be judged or fixed, or how a series' counts moved. What a product's code findings stand at now is counted by series (§ Code findings by series). Approval quality and the exception report read code finding decisions: a code finding's dismissal standing on one person is a control that did not hold (`design-docs/analytics.md` § Approval quality) |
| A repository an SPDX inventory states | Not read. A package's download location is read by nothing, so a component of an SPDX inventory is built from a repository only where its identifier names one |
| Fuzzing findings | Intended scope, not built (REQ-14) |

## Limits

| Limit | Detail |
|---|---|
| A moved result with no fingerprint and no function is matched on its line alone | clang-tidy, and clang before 22, give rule, path, line and message. A line moved above such a result pairs it with the nearest code finding of the same rule and message in the file, which is probable, and two such results moving past each other can swap |
| A new variant inherits on the whole key alone | Carrying by every layer is from the branch a tag was cut from. A variant's first run of a series takes a sibling variant's occurrences where the whole keys are equal |
| A result whose whole key equals the one a moved code finding was first seen with opens at that code finding's occurrence | Occurrences are minted from the first key a series saw. Both are the same rule, path, fingerprint and message, which is one flaw reported twice |
| A run that ends unread counts nothing on its receipt | A run is read only once its build has an inventory, so one superseded or failed while it waits, or held in a shape the release applying it does not read, ends with a receipt naming no drop and no discard |
| Coverity's native JSON is not read, so its SARIF is matched as plain SARIF | Coverity's `mergeKey` is in its JSON and is lost in its SARIF. A Coverity code finding is matched on the key its SARIF states, as any plain SARIF is (§ Keys) |
| Two identical results in one build share an occurrence | Their key is the same, so a decision on one reaches the other. They are one flaw reported twice |
| A rule set read from a rule list flips where every listed rule fires | A tool listing its whole rule set lists rules that never fired, and a run where all of them fire states no rule set; that run is compared as a rule set change |
| A run waits a day for its build's inventory, and then fails | A pipeline that sends analysis for a build it never inventories has each run fail after a day. Until then each run holds a job counted against the backlog, and its placed results |
| The counts per run are measured against small trees | The largest real output measured is CodeQL's 226,586 bytes over a small C++ tree (§ Bounds). No producer's output for a tree the size of a product's own build was measured, so the results per run and the two memory figures rest on the 150,000-result measurement of what reading costs rather than on a producer. A deployment analyzing a large tree raises them, and the memory limit with the two that are memory figures |
| A link reaches only the repositories a product names a host for | A product of many hosts names each. A repository on none is shown as its remote, which is text |
| A snippet records what the upload sent | Nothing compares it with the repository, so a patched repository's snippet is the patched source and its link is the source before the patch |
| A link in a code finding with no repository a run names is to a branch | It is marked approximate, and the branch has moved since the build whenever anybody pushed to it |
| The documentation hosts are a list in the code | An analyzer documenting rules elsewhere has its documentation dropped until the list names it |
| A tool is told apart by the name its output gives it | Two configurations of one tool in one invocation are one series. A pipeline running a tool twice runs the client twice |
| The client's macOS and Windows behavior is tested and not used | No pipeline here runs on either system |
| The client places a path naming no starting point against the directory it runs in, and the deployment against the working directory the output states | One output sent both ways is placed differently when the analyzer ran outside the directory the client runs in |
| An internal reader reads an included code finding whole, and is not told its flaw | The flaw is undisclosed work. The code finding's state reads recorded as a flaw for both |
| A grant of an included code finding reaches its evidence and not the decisions at its occurrence | The decisions are widened for the flaw's two audiences, and a code finding grant is a third reach of one occurrence's findings |
| A notice or a mention about a decision at an included code finding reaches its internal readers alone | A mention resolves names against the people who read the decision's visibility in its product, and that stays internal until disclosure. A reader of the flaw reads the decision and is not told of a note on it |
| A renamed file's results open as new code findings | Every key holds the path, so the code findings under the old name go no longer detected and nothing carries their decisions to the new name |
| Every code finding of a series' first run is in the queue | A vulnerability scanner's first scan has no baseline either, and starting to analyze a codebase leaves what it already holds to be triaged and fixed. A codebase analyzed for the first time puts every result in front of a triager at once, and the order and the suppression rules are what thin it |
| An upload refused before it names its series is recorded against no series | The build's receipts list it, and no series gone quiet names it. One refused before its sender is admitted is recorded nowhere (§ Receipts) |
| A code finding sorts after every finding in the lists of held work | They are ordered by urgency, and a code finding carries none. The rail's Unassigned entry opens the findings list, which holds no code finding (`design-docs/kinds.md` § Consumers): an unassigned code finding is listed by the unassigned list's read, and named unheld in the code finding queue |
