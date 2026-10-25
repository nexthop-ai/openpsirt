# Analyzer findings

A static analyzer's run over a build arrives as SARIF. Each result it reports
is placed in the checkout, matched to what the same analysis reported on that
build before, and recorded as a finding of the analysis kind, called a lead.
A lead is internal until a person judges it.

Satisfies REQ-14, REQ-06, REQ-08, REQ-13, REQ-17, REQ-21, REQ-24, REQ-25,
REQ-27, REQ-28, REQ-30, REQ-42, REQ-43, REQ-66, REQ-69.

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
- [Source](#source)
- [Lead triage](#lead-triage)
- [Lead queue](#lead-queue)
- [Weakness families](#weakness-families)
- [Grouped leads](#grouped-leads)
- [Receipts](#receipts)
- [Upload client](#upload-client)
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
| Whole-file contents, fixes and markdown messages are left out of everything a run records, and counted on the receipt | No whole file or replacement text is stored, and a message is its text |
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
input to a key and never a key by itself.

### Keys

| Key | Digest of | Strength |
|---|---|---|
| Whole | The rule, the path, the fingerprint or the line where there is none, the message with its digits taken out, the enclosing function and the call chain | Strong |
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

A run is paired with the leads its series holds open on the build, one to
one, a layer at a time, each layer on what the layers before it left: the
whole key, then the function, then the nearest line.

| Rule | |
|---|---|
| A lead the last comparable run did not see is a candidate in every layer | Of 28 absences hand-checked, 5 came back one or two builds later. A lead it saw comes first where a layer cannot tell two apart |
| The line layer offers a result the eight leads sharing its line key nearest its line | A generated file repeating one message holds thousands of results under one key, and offering each all of them is quadratic |
| Each lead records how its newest sighting was paired: on the whole key, the function or the line | A dismissal carries on a strong pairing and lapses on a probable one (§ Lead triage) |

### Carrying

A result no open lead on the build took is the same result as a lead the
series holds elsewhere where one of these finds it. It opens at that lead's
place, so a decision keyed on the place reaches it (REQ-25).

| Order | Where | How |
|---|---|---|
| 1 | The leads open on the build of the same variant in the stream this one was cut from, on the series' first run on the build | Every layer. A new branch inherits what the line it was cut from has decided |
| 2 | A closed lead on this build | The whole key. The result is the same flaw found again, and opens a new lead at the closed one's place |
| 3 | Any lead of the series on another build, open or closed | The whole key, the oldest lead first. A probable pairing with a lead this build never saw is a guess |

A result carried from a lead in the baseline is in the baseline too. A result
found nowhere opens at a place derived from the series and its whole key, so
the same result first seen on two builds at once is one place.

### Re-baseline

A run records the fingerprint schemes its results' keys were built from, and
the mark of the salt the client took its own with. A run whose record differs
from the newest one applied to the build that reported anything is a
re-baseline.

| Rule | |
|---|---|
| A run reporting nothing records nothing | It says nothing about how results are fingerprinted, and reading it as a change would make the next run a re-baseline |
| `none` is recorded only where no result carried a fingerprint | One unhashable result appearing or going away beside others says nothing about how the run fingerprints |
| The salt is recorded as the client states its mark, a short digest | A rotated salt changes every fingerprint and no scheme name |
| A re-baseline is matched like any other run, and says so on its receipt | Its whole keys no longer meet the leads', so its pairings are the probable layers' |

## Placement

A lead is one component at one place (REQ-17).

| Rule | |
|---|---|
| A result in a repository the run names is placed on the build's component built from that repository | The innermost repository holding its path |
| A component is built from a repository where its package identifier names it: the `github`, `gitlab` and `bitbucket` types by namespace and name, and any type by a `vcs_url` qualifier | The inventory is the only statement of which component a directory became |
| A component whose identifier names no repository is built from the one its inventory states in a CycloneDX external reference of type `vcs`, the first where it states several | A distribution package's identifier names no repository. sonic-buildimage states one this way on packages whose identifier is `pkg:deb` |
| Repository addresses compare as host, owner and name, in lower case, without scheme, credentials, port, revision or `.git` | A remote written for SSH and an identifier written for HTTPS name one repository |
| A result in no repository the inventory names is placed on the build itself | Every build has a root |
| The inventory placed against is the build's newest that has been read | A run arriving before its inventory waits for it |

## Source

Every place a lead names links into the repository's web view at the analyzed
commit, and carries the source kept beside it where the product keeps source
under its path. The deployment builds an address and never requests it; the
reader's browser does, and signs in where the repository is private.

### Repository settings

An administrator states them per product, and the change is in the
administrative trail.

| Setting | |
|---|---|
| Hosts | Each a remote prefix, a web address, and a style: `github`, `gitlab`, `gitea` (Forgejo writes Gitea's), or `custom` with a file template and an optional comparison template |
| Paths | Each a prefix of the checkout, with a repository and branch for links where an upload names none, whether source under it is kept, or both |

| Rule | |
|---|---|
| A web address is `https`, with no credential, query or fragment | A scheme is something a browser acts on |
| A custom template begins with `{repo}/` and names only `{commit}`, `{path}`, `{start}` and `{end}`, or `{from}` and `{to}` for a comparison | A template beginning anywhere else could open on another host |
| A remote prefix may hold a path, which is how a mirror is named: the host covering a remote is the one with the longest prefix, and the rest of the remote is the repository under its web address | `git.example.com/mirror/github/FRRouting/frr` opens at `https://github.com/FRRouting/frr` |
| A path's repository and branch are named together or not at all | One is no link |
| A path that names neither a repository nor whether source is kept is refused | It says nothing |
| A product states at most 100 hosts and 2,000 paths | sonic-buildimage pins dozens of submodules |
| Remotes and prefixes are compared normalized: a host in lower case, a path with no leading or trailing slash | One repository written two ways is one entry |

### Source links

| Rule | |
|---|---|
| A path is in the run's repository with the longest prefix holding it, and the rest of the path is within that repository | `src/sonic-sairedis/SAI/inc/saiport.h` is `inc/saiport.h` in SAI, at SAI's commit |
| A relative remote resolves against the remote of the repository holding it, itself resolved the same way; an SSH remote is read as the host and path it names, written with a user or without one | `.gitmodules` uses both |
| A remote is recorded and shown with any credential and query taken out | It comes from the upload, and a token in it would reach every reader of the lead |
| A remote on no host the product names is shown as text, unlinked | The remote comes from the upload, so without the list its host is the uploader's choice |
| A revision an upload states opens a link only where it is a commit: 7 to 64 hexadecimal digits, and is shown unlinked otherwise | A branch an upload names moves, and `?` or `#` in it would steer the link |
| Each path segment is percent-encoded, and a segment that is empty, `.` or `..` leaves the place unlinked | `?`, `#` and traversal in a path would otherwise steer the link |
| A finished address must open over `https` on the host the web address names, or the place is unlinked | The last check, after every template and substitution |
| A repository whose working tree differed from its commit when it was analyzed is marked patched | The link shows the source before the patch |
| A path no run repository holds links to the branch a product names for its longest prefix, marked approximate | The commit is unknown |
| A place with no line opens the file; an end before the start is the start | |
| A lead the build no longer holds open carries a comparison of its repository between the build of the newest run that saw it and the build of the first that did not, or says the two name the same commit and neither was patched | A disappearance where the code did not change is not a fix in that code, and a patch applied at build time is a change the commit does not show |

Each unlinked place says why: no repository is known, the repository is on no
named host, the revision is not a commit, or the path leaves the repository.

### Snippets

| Rule | |
|---|---|
| Source is kept under a path where the longest prefix stating it says so, and nowhere where no prefix states it | Off by default: a private product may not allow its source in another system, and may carry public upstreams it does |
| The upload's own statement of which paths are public decides nothing | A misconfigured pipeline could label a private path public |
| Source is decided as an upload arrives, for the result and for every step and related place, and a place outside the checkout keeps none | A change to the setting reaches the uploads after it |
| A context region's source is preferred to its region's, with the line it starts at | It is the wider of the two |
| At most 4 KiB of source is kept per place | A client sends a few lines either side |
| A snippet is answered as text, and shown as text | It is uploaded data (REQ-66) |

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

`GET …/streams/{stream}/variants/{variant}/leads/{place}` answers one lead's
evidence on one build: its rule, where it is, the path the analyzer took to
it, the related places, each with its link and source, when it was last seen,
and, for a lead no longer open, when it was first not seen with the comparison
above. It names the live claim at the lead, agreed to or waiting, where the
reader may read one. The place identity addresses a lead because a rule's name holds a
slash.

| Rule | |
|---|---|
| The lead is read through the Evidence consumer, which includes the analysis kind alone (`DESIGN-kinds.md` § Consumers) | Nothing of a lead reaches a vulnerability consumer |
| It is read in the data layer at the visibilities the subject reads in the product, and a lead nobody may read there answers as a place holding nothing (REQ-42, REQ-43) | A different answer would say a lead is there |
| The open lead is answered, or the newest where none is open | A reappearance opens a new finding at the same place |
| Every link is built when the evidence is read, from the newest run's repositories and the product's settings | A change to the hosts reaches every place at once |

## Lead triage

A claim about a lead is a claim as `DESIGN-triage.md` describes one: one
argument, its rows, its reasoning and every revision of it, and a second
person's approval of one revision (REQ-24, REQ-28). It is keyed on the
product, the rule the lead is filed under, and the lead's place, with no
versions, so one judgment covers the lead on every stream and variant it is
seen on (REQ-25).

`POST …/streams/{stream}/variants/{variant}/leads/{place}/decision` records one.

| Outcome | Means | Second person |
|---|---|---|
| `dismissed` | Not a flaw to act on, for the reason stated | Yes |
| `not-security` | Real and harmless: a crash on a path no input reaches, a leak in a tool that exits | Yes |
| `confirmed` | A real flaw | No |

| Reason a lead is dismissed | Means |
|---|---|
| `false_positive` | The analyzer is wrong: the flaw is not there |
| `wont_fix` | The flaw is there and will not be fixed |
| `used_in_tests` | The code is only used in tests and does not ship |
| `mitigated` | Something already in place stops it, which the reasoning names |

| Rule | |
|---|---|
| A lead takes the lead outcomes alone, and a vulnerability takes none of them | A lead is asked whether it is real; a vulnerability, how a known issue applies |
| A dismissal states one of the four reasons | A dismissal nobody can review is one a second person cannot agree to |
| A claim about a lead covers its place at any version | The place is the lead, carried by matching rather than by versions |
| A claim about a lead is approved by somebody holding `approver` and `internal-read` on the product, and never by its author | The approval every claim has, at the visibility a lead has |
| A fixed lead takes no claim | It opens again where it is seen again |
| A lead paired only probably, on its function or its nearest line, lapses the claim dismissing it or calling it no security issue | The judgment was about the result as it was keyed. A weaker pairing guesses it is the same result, so its author re-affirms it, one claim or many, as a lapsed claim is re-affirmed (`DESIGN-triage.md` § Re-affirmation) |
| A claim confirming a lead stands through a probable pairing | It says the flaw is real, and a weaker pairing does not make it less so |
| The lapse is written in the transaction that records the pairing | A pairing is never recorded with the claim on it left standing |

### Fixed leads

`POST …/streams/{stream}/variants/{variant}/leads/{place}/fixed` closes a lead
on one build, with what fixed it.

| Rule | |
|---|---|
| Only a lead the newest comparable run did not see is closed as fixed | That absence is the evidence the statement is made with; a run still reporting the result is the authority on what it found |
| It closes the lead on the build named and nowhere else | Each build holding it is a statement of its own |
| It is closed by somebody holding `internal-triage` on the product, who says what fixed it | The closure a person writes, with who, when and why on the record (`DESIGN-findings.md` § Recorded flaws) |
| A lead seen again opens anew at the same place | The matching that finds a closed lead carries the result to its place (§ Carrying) |
| A claim about a lead is read through the Decisions consumer (`DESIGN-kinds.md` § Consumers) | The review queue, approval and one claim's reads include it; the findings lists do not |

### Dismissal rules

A standing rule dismisses every lead of a product it names, with one reason
and one reasoning: `tests/`, vendored code, a checker noisy on this codebase.
`…/products/{product}/lead-rules` lists, proposes, approves and retires them.

| A rule names | Covers |
|---|---|
| An analyzer rule | Every lead filed under it, compared as the rule's issue is, without regard to capitals |
| A path | Every lead at or under it, compared as an important path is (§ Escalation) |
| Both | Every lead of the rule at or under the path |

| State | When | Dismisses |
|---|---|---|
| `proposed` | Nobody has approved it | Nothing |
| `in-force` | Approved, and covering no more than the leads its approver was shown times the growth factor | What it names |
| `outgrown` | Approved, naming an analyzer rule, and covering more than that | What it names, and asks to be approved again |
| `needs-path` | Naming an analyzer rule and no path, where a run has since found the rule to find memory safety or injection | Nothing, until it is retired and proposed again with a path |
| `retired` | Taken out of use | Nothing |

| Rule | |
|---|---|
| A rule is proposed by somebody holding `internal-triage` on the product, and approved by somebody else holding `approver` and `internal-read` there | The second person a dismissal has (REQ-24) |
| A rule names an analyzer rule, a path, or both, and states one of the four reasons and its reasoning | A rule naming neither would dismiss every lead the product has |
| A rule naming an analyzer rule and no path is refused, at proposal and at approval, where the rule finds memory safety or injection (§ Weakness families), or where no run has recorded the rule, and one approved before a run found that stops dismissing at once | A flaw of those kinds is judged one lead at a time. A whole checker is dismissed where it fights a convention, measures style, or cannot model the code; a leak checker is dismissed under the pool allocator it cannot see |
| Its words never change | An approval is of what was read (REQ-28). A rule worded differently is retired and proposed again |
| Approval records the open leads the rule covers as its approved size | What the approver was shown |
| The growth factor is `triage.lead-rule-growth`, two where nobody has said | A rule covering ten leads when approved and a thousand later is not what the approver read (REQ-27) |
| A rule naming a path alone is never outgrown | Code under a dismissed path grows as a matter of course, and what the approver agreed to is the path |
| An approval shown no lead is measured as though shown one | A rule approved before its analyzer rule reports anything is not outgrown by its first lead |
| An outgrown rule is approved again at its new size, and a rule in force is refused | Approving again is how the approver reads what it now covers |
| An outgrown rule keeps dismissing what it names | Withdrawn, every lead it covers would reach the queue at once, which is the noise the rule exists to hold |
| A rule's coverage counts open leads by place, approved or not, where the reader may read them | A proposal shows its approver what it would dismiss (REQ-42) |
| Coverage is worked out when it is read | A new lead under a rule in force never reaches the queue |
| Proposal, approval and retirement are recorded in the administrative trail | As routing rules are |

### Lead states

A lead's state is worked out when it is read, from its finding, its sighting
and the claim standing at its place. The evidence of a lead carries it.

| State | When |
|---|---|
| Fixed | The finding is closed |
| Dismissed, Not a security issue, Confirmed | A claim with that outcome stands at the place: approved, or waiting on nobody and not sent back |
| Dismissed | No claim stands, and a standing rule in force or outgrown covers it (§ Dismissal rules) |
| Not reproduced | A comparable run did not see it |
| Baseline | It arrived in its series' first comparable run in the product, or was carried from a lead that did, and nothing has escalated it (§ Escalation) |
| Open | None of the above |

| Rule | |
|---|---|
| A standing claim comes before a standing rule | A judgment about one lead is more specific than one about many |
| A standing claim or rule comes before absence | A dismissed lead a run does not see stays dismissed and records the absence |
| Absence comes before the baseline | A baseline lead nobody sees is no longer anything to work |
| A claim waiting for a second person leaves the lead where it was | It answers nothing until somebody agrees |

## Lead queue

A product's leads are listed one row per lead, however many of the product's
builds it is open on. A row shows the newest of those findings: its rule, its
path, line, function and message, the build it is on, and its state there.

| Order | |
|---|---|
| The tier of the weaknesses the rule names, highest first (§ Weakness families) | Memory safety above style |
| Whether another analyzer reports the same flaw on the build (§ Grouped leads) | Two tools agreeing is the strongest sign a result is real |
| The tool's own security severity for the rule, highest first, and a rule with none after every rule with one | CodeQL and semgrep rate a rule's results from 0 to 10 |
| The tool's own precision for the rule: `very-high`, `high`, `medium`, `low`, then none | How often the rule is right, as its tool measures it |
| Newest first | The work that arrived last is the work nobody has looked at |

Whether a path ships orders nothing. Code that does not ship — tests, tools,
examples — is set aside by a standing rule naming its path (§ Dismissal
rules), which takes its leads out of the queue rather than lower in it, and
one way to say a path does not matter is kept rather than two.

| List | Holds |
|---|---|
| The queue, with no state named | Open leads with no claim waiting for a second person |
| A state named | The open leads in that state. Naming the baseline is how it is searched |

| Rule | |
|---|---|
| Every list counts the leads in the scope by state, the open leads a waiting claim leaves out of the queue, and the dismissed leads a standing rule covers | A list that leaves the baseline out says how many it left (REQ-30) |
| A lead open on two builds in two states counts in both | The count is of leads in a state, and a lead not reproduced on one build is open on another |
| Only what the subject may read is listed or counted | Visibility is enforced where the leads are read (REQ-42, REQ-43) |
| A branch or tag and a variant narrow the list independently | One build, one line, or the whole product |
| A rule's rating is the one the newest run naming it gave, held until a run rates it again | A run of the tool that omits the properties says nothing about the rule |
| A rule's tier is the highest of every weakness recorded for it, ranked again each time a run names the rule | A rule's weaknesses accumulate as its tags do, and a tier table changed by an upgrade reaches a rule at its next run |
| A severity outside 0 to 10, or one that is not a number, and a precision outside the four words, are read as none | The order is the tool's, and a value it does not define orders nothing |

### Escalation

A baseline lead enters the queue when it is escalated.

| Escalated by | |
|---|---|
| Somebody holding `internal-triage` pulling it in | On every build of the product the lead is on. Recorded with who pulled it in and when, and pulled in again it keeps the first |
| Its path being at or under an important path | A product setting under `internal-triage`, recorded in the administrative trail. Taking a path off returns its leads to the baseline |
| Another analyzer's lead on its build being the same flaw (§ Grouped leads) | Two tools agreeing is the strongest sign a result is real. The other lead closing returns it to the baseline |

| Rule | |
|---|---|
| An important path is a prefix from the top of the checkout, with no leading or trailing slash | `src` holds `src/a.c` and `src`, and not `src2/a.c` |
| A path is compared exactly, character by character | Paths are case-sensitive, and SQLite's LIKE ignores the case of ASCII letters |
| An empty path, a path climbing out of the checkout, and a path named twice are refused | The empty path would put the whole baseline in the queue |
| A product marks at most 500 important paths | Each is asked of every baseline lead a list reads |
| Somebody who reads a lead and does not triage it is answered as though it were not there | As closing a lead as fixed answers them |
| Escalation is worked out when a lead is read | Marking or unmarking a path moves every lead under it at once |

## Weakness families

A rule names the weaknesses its tags name, as `external/cwe/cwe-N`. A rule
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
| A pillar is the family of no weakness under it, and a weakness reaching a pillar with no class between is its own family | The catalog files a null dereference, a condition always true and an obsolete function directly under CWE-710, and 26 cppcheck and clang rules shared that family |
| A weakness the catalog does not place is its own family | A newer catalog than the one committed assigns numbers this one does not know |
| The hierarchy is read from the published catalog by `make weakness-names` and committed with the names | `DESIGN-build.md` § Make targets. Nobody types a thousand parents |
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

## Grouped leads

Two analyzers on one build report some flaws twice. Each tool's result stays
its own lead, with its own history. Two leads are the same flaw where every
one of these holds:

| Condition | |
|---|---|
| Both are open on one build | A flaw is in the code one build was made from |
| Their rules differ | Two flaws of one class on adjacent lines are told apart only by the tool reporting them as two |
| Their rules' weaknesses share a family (§ Weakness families) | One overflow was CWE-788, 119 and 121 from three tools |
| Their last places are in one file, within two lines | cppcheck names where a problem starts and the others where it bites: first places differed in 8 of 41 same-flaw pairs, last places in 2 |

Within two lines grouped every same-flaw pair of clang, cppcheck, CodeQL and
semgrep over libyaml, jq, Lua, giflib and seeded files, and none of five pairs
of flaws a line or two apart. A wider window or a first place falsely merged
at least one.

| Rule | |
|---|---|
| A result's last place is the last step of its path, the last related place in its own file, or its own place | cppcheck lists the places after the first as related, in order |
| Leads within ten lines and otherwise alike are listed as possibly the same flaw, and never grouped | A false merge hides a second real flaw behind one decision |
| A lead's evidence lists the leads it is the same flaw with and those it possibly is, where the reader may read them | Visibility is enforced where the leads are read (REQ-42) |
| A group is a lead and the leads within two lines of it, worked out for each lead | Two leads each the same flaw as a third and four lines apart are two groups |
| Whether another analyzer reports a lead is worked out over every lead on the build, whoever reads it | Where a lead stands does not depend on who is looking |
| A rule with no weakness groups with nothing | clang tags none, so a clang lead groups only once its weaknesses are known |
| A judgment about a lead is one claim over it and every lead of its group that nothing answers yet, agreed to once | The same flaw takes the same answer whichever tool reported it |
| A lead of the group already answered, waiting on a claim, under a standing rule, fixed, or unreadable by the person judging is left out | A lead already answered keeps its own answer, and a judgment reaches no lead its author cannot read (REQ-42) |
| A lead possibly the same flaw is left out | It is judged on its own |

## Receipts

`GET …/analyses` lists a build's runs newest first.

| Field | |
|---|---|
| Status, failure | § Run application |
| Comparable, and the reason where not | § Run parameters |
| Baseline | The series' first comparable run |
| Tool and version | As recorded |
| Counts | Opened, seen again, returned, not reproduced, paired probably, carried from the branch a build was cut from, reopened at a closed lead's place, what a held run would have marked, and what was dropped, left out and discarded, each by reason |
| Re-baseline | Whether the run's fingerprints changed from the build's last (§ Matching) |

A receipt counts leads and never names one. A pipeline key reads the receipts
of a build it may send to; a person reads them where they read internal
findings in the product, since the counts are of internal findings. A
pipeline key's other reads are unchanged (`DESIGN-access.md` § Subject kinds).

## Upload client

`openpsirt-analysis` runs in a pipeline beside the analyzer. It reads the
analyzer's output and the checkout, writes one SARIF run per analyzer holding
what the deployment cannot learn from the output alone, and sends each as
§ The upload describes.

```
openpsirt-analysis upload --product P --stream S --variant V --series [TOOL=]NAME... \
  [--commit SHA] [--built TIME] [--snippets] [--salt-file FILE] \
  [--third-party PATH]... OUTPUT...
openpsirt-analysis write --series [TOOL=]NAME... --output FILE OUTPUT...
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
| Whole-file contents, fixes, attachments, snippets and markdown messages in forwarded SARIF are removed, and counted in what the client prints | A markdown message with no text keeps its markdown as its text |
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
| One binary, pure Go with cgo off, for Linux, macOS and Windows on amd64 and arm64 | It runs where the analyzer runs. `DESIGN-packaging.md` § Release assets names the archives |
| The archives are covered by the release's checksum file and its signature | The same verification as every other asset |
| No Authenticode signature and no notarization | A pipeline fetches the binary by a command, which neither check stops. One downloaded through a browser on macOS or Windows is held by the system until a person allows it |
| CI runs the client's tests on macOS and Windows when one of its sources moved | `DESIGN-build.md` § CI jobs. The fingerprints of one function written with each line ending are pinned to hashes worked out by hand, so a system computing them differently fails there |

## Not built

| Part | State |
|---|---|
| The exports that read leads | The Evidence, Leads and Decisions consumers alone include the analysis kind (`DESIGN-kinds.md` § Consumers), so a lead is read through the lead queue, its evidence and the claims about it, and nowhere else. `DESIGN-interface.md` § Static analysis leads holds the screens |
| A screen for a product's repository settings | Not built. They are read and written through the API |
| Telling anybody a standing rule outgrew its approval | Not built. The rule's state says so where its rules are listed |
| Telling anybody a lead was escalated | Not built |
| Telling the author of a claim on a lead that it lapsed | Not built. The claim lapses and waits to be re-affirmed; nobody is told |
| Moving a lead into a private case | Not built |
| Matching a renamed file | Not built. Every key holds the path, so a renamed file's results open as new leads, and the old ones are not reproduced |
| A re-baseline's probable pairings listed together | Not built. Each lapses its claims, and a person re-affirms them through the list of what lapsed |
| Third-party paths | Recorded on the run and read by nothing |
| A repository an SPDX inventory states | Not read. A package's download location is read by nothing, so a component of an SPDX inventory is built from a repository only where its identifier names one |
| Conditions for a not-comparable run, a held run, and a series gone quiet | Not built. A held run says so on its receipt alone |
| Releasing a held run | Not built. A held run changes nothing and keeps nothing; the next run is compared against the last applied one |
| Fuzzing findings | Intended scope, not built (REQ-14) |

## Limits

| Limit | Detail |
|---|---|
| A moved result with no fingerprint and no function is matched on its line alone | clang-tidy, and clang before 22, give rule, path, line and message. A line moved above such a result pairs it with the nearest lead of the same rule and message in the file, which is probable, and two such results moving past each other can swap |
| A new variant inherits on the whole key alone | Carrying by every layer is from the stream a branch was cut from. A variant's first run of a series takes a sibling variant's places where the whole keys are equal |
| A result whose whole key equals the one a moved lead was first seen with opens at that lead's place | Places are minted from the first key a series saw. Both are the same rule, path, fingerprint and message, which is one flaw reported twice |
| A run that ends unread counts nothing on its receipt | A run is read only once its build has an inventory, so one superseded or failed while it waits, or held in a shape the release applying it does not read, ends with a receipt naming no drop and no discard |
| Two identical results in one build share a place | Their key is the same, so a decision on one reaches the other. They are one flaw reported twice |
| A rule set read from a rule list flips where every listed rule fires | A tool listing its whole rule set lists rules that never fired, and a run where all of them fire states no rule set; that run is compared as a rule set change |
| A run waits a day for its build's inventory, and then fails | A pipeline that sends analysis for a build it never inventories has each run fail after a day. Until then each run holds a job counted against the backlog, and its placed results |
| The bounds' defaults are a judgment | They are several times the fixtures here and are not measured against the largest real producer. A deployment analyzing a large tree raises them, and the memory limit with the two that are memory figures |
| A link reaches only the repositories a product names a host for | A product of many hosts names each. A repository on none is shown as its remote, which is text |
| A snippet records what the upload sent | Nothing compares it with the repository, so a patched repository's snippet is the patched source and its link is the source before the patch |
| A link in a lead with no repository a run names is to a branch | It is marked approximate, and the branch has moved since the build whenever anybody pushed to it |
| The documentation hosts are a list in the code | An analyzer documenting rules elsewhere has its documentation dropped until the list names it |
| A tool is told apart by the name its output gives it | Two configurations of one tool in one invocation are one series. A pipeline running a tool twice runs the client twice |
| The client's macOS and Windows behavior is tested and not used | No pipeline here runs on either system |
| The upload records no refusal for the coverage report | A refused analyzer upload is answered to the sender and logged by nobody; a series gone quiet is not built |
