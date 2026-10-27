# Code finding queue

How a product's code findings are listed, ordered, counted and written out,
the weakness families the order rests on, and code findings two analyzers
report as one flaw.

Satisfies REQ-30, REQ-42, REQ-43, REQ-50.

## Contents

- [Code finding queue](#code-finding-queue)
- [Queue file](#queue-file)
- [Code findings by series](#code-findings-by-series)
- [Weakness families](#weakness-families)
- [Grouped code findings](#grouped-code-findings)
- [Limits](#limits)

## Code finding queue

One row per code finding, however many builds it is open on, showing the newest
of those findings: rule, path, line, function, message, build, and its state
there (`design-docs/analysis-triage.md` § Code finding states).

| Order | Reason |
|---|---|
| The tier of the weaknesses the rule names, highest first (§ Weakness families) | Memory safety above style |
| Whether another analyzer reports the same flaw on the build (§ Grouped code findings) | Two tools agreeing is the strongest sign a result is real |
| The tool's security severity for the rule, highest first, a rule with none after every rule with one | CodeQL and semgrep rate a rule's results from 0 to 10 |
| The tool's precision for the rule: `very-high`, `high`, `medium`, `low`, then none | How often the rule is right, by its tool |
| Newest first | The last work to arrive is what nobody has looked at |

Whether a path ships orders nothing: code that does not ship is set aside by a
suppression rule naming its path, which takes it out of the queue, and one way
to say a path does not matter is kept.

| List | Holds |
|---|---|
| The queue, with no state named | Open code findings with no decision waiting for a second person |
| A state named | The code findings in that state. Fixed is those closed on a build and not opened anew there |

| Rule | Reason |
|---|---|
| Every list counts the code findings in scope by state, the open ones a waiting decision leaves out, and the dismissed ones a suppression rule covers | A list leaving things out says how many (REQ-30) |
| One closed as fixed is listed and counted as fixed on its build until it opens anew there | Then it is what the newer finding says |
| One open on two builds in two states counts in both | The count is of code findings in a state |
| Only what the subject may read is listed or counted (REQ-42, REQ-43) | Visibility is enforced where code findings are read |
| A branch or tag and a variant narrow the list independently | One build, one line, or the whole product |
| A series narrows by name, matched without regard to capitals | A name no series holds lists nothing, as a series with no code finding does |
| A testing method narrows to the kind of finding it records, and the filter offers every method the queue knows; one nothing records is refused by name | SAST is static analysis, the analysis kind, the one method recorded |
| Narrowed to work nobody holds, the list keeps the code findings with no holder on each row's build, under the findings list's parameter and value, and every count is of what the narrowing keeps | The findings list holds no code finding, so unheld code findings are found here |
| A rule's rating is the one the newest run naming it gave, held until a run rates it again | A run omitting the properties says nothing about the rule |
| A rule's tier is the highest of every weakness recorded for it, ranked again each time a run names the rule | Weaknesses accumulate as tags do, and a changed tier table reaches a rule at its next run |
| A severity outside 0 to 10 or not a number, and a precision outside the four words, are read as none | A value the tool does not define orders nothing |

## Queue file

`GET /v1/products/{product}/code-findings.{format}` writes the list as CSV or
JSON, as `design-docs/analytics.md` § Exports writes every file.

| Rule | Reason |
|---|---|
| The file is the list: same filters, same order, every row | A list and its file are one read |
| It is read under the list's visibility (REQ-42, REQ-43) | A reader is written what the list shows them |
| A row names the holder as the list does: who, display name, and whether a team's queue | A team and a person may share a name, and every signal the list carries is a column |
| A row says whether the code finding is third-party, read from the newest run that saw it | As its evidence does (`design-docs/analysis-source.md` § Third-party code) |
| No row carries source text | A snippet is evidence, kept under the path's setting |
| With no state named, the file says it lists the queue | An empty query reads as everything, and the queue leaves out what a waiting decision holds and what is past its end of life |
| Narrowed to work nobody holds, the file says so | A file read later carries its narrowing |
| A refusal is answered before the first byte | Written into the file it would follow a 200 |
| A findings list's file writes every open code finding of its selection below its findings, through this read, keeping those a decision waits on (`design-docs/analytics.md` § Exports) | The finding exports include the code findings the reader reads (REQ-50) |

## Code findings by series

`GET /v1/products/{product}/code-finding-series` counts a product's code
findings per analyzer series, by state, drawn as Code findings by analyzer
(`design-docs/analytics.md` § Pages of the catalog's own).

| Rule | Reason |
|---|---|
| Every state is counted, zero included, beside the open code findings a waiting decision leaves out and the dismissed ones a suppression rule covers | The queue works the states out already |
| Each count is the total the list answers for that series and state | A figure and the list it opens count one population under one visibility |
| Counted over every build of the product | A series is the product's; narrowed, a series that never ran there would list every count zero, reading as an analyzer that found nothing |
| A series holding no code finding is listed with every count zero | An analyzer that runs and finds nothing is a fact |
| Read only by somebody holding `internal-read` on the product, and refused to anybody else naming no count and no series | A count of code findings is internal however narrowed, and a reader through a flaw reads the code finding, not the product's figures |
| Ordered by series name | The series are few and looked up by name |

## Weakness families

A rule names the weaknesses its tags name, as `external/cwe/cwe-N` or as
semgrep's `CWE-N: name`; a rule whose tags name none takes those a table held
here names for it. Tools disagree on the number for one flaw (one overflow was
CWE-788, 119 and 121 from three tools) and agree on its family.

| Tool | Source of its weaknesses |
|---|---|
| CodeQL | Its rule tags |
| semgrep | Its rule tags |
| cppcheck XML | The tags the upload client writes from each error's weakness |
| cppcheck SARIF | Its rule tags from the release that writes them. Releases 2.16 to 2.18 tag a rule `security` and name no weakness, so a table generated from `cppcheck --errorlist` by `make cppcheck-weaknesses` names one, for 302 checks of cppcheck 2.22.0 |
| clang, and the clang checkers clang-tidy runs | A table held here, over the 47 checkers clang 18 runs on C; clang tags nothing and publishes no table. A checker no weakness fits with confidence names none, and `make clang-checkers` names a checker a new release adds |

| Rule | Reason |
|---|---|
| A weakness's family is the nearest class up its primary parents in the catalog's research view, or itself where it is a class or pillar | CWE-121, 122, 126, 787 and 788 are all CWE-119, as are use after free and double free |
| A pillar is the family of no weakness under it; a weakness reaching a pillar with no class between takes the weakness just under the pillar | The catalog files a null dereference, an always-true condition and an obsolete function directly under CWE-710, which 26 cppcheck and clang rules shared. cppcheck names a `sizeof` on a pointer CWE-467 and clang the same `malloc` CWE-131, the base above it under CWE-682 |
| A weakness the catalog does not place is its own family | A newer catalog assigns numbers this one does not know |
| The hierarchy is read from the published catalog by `make weakness-names` and committed with the names (`design-docs/build.md` § Make targets) | Nobody types a thousand parents |
| A clang checker reporting several kinds of flaw names each | unix.Malloc reports leaks, double frees and uses after free, so it is a memory-safety rule in both the resource and bounds families |
| A rule whose tags name a weakness is classified by its tags alone | The tool's word outranks a table about it |

A weakness's tier is that of the nearest of itself and its ancestors the table
names, so naming a class names everything under it, and a weakness named here
outranks its class. The table is a judgment no decision records, made for the
C and C++ these analyzers read.

| Tier | Names |
|---|---|
| Memory safety | CWE-119, a bound overrun, with use after free and double free under it; CWE-476, a null pointer, which the catalog files under coding standards; CWE-824 and CWE-908, a pointer or value read before written, and CWE-457; CWE-190, an integer that wraps; CWE-134, a format string the caller controls |
| Input reaching where it should not | CWE-74, CWE-77 and CWE-943, injection; CWE-20, input not validated; CWE-706, a name resolved wrongly; CWE-362, a race |
| A resource or an error left unhandled | CWE-404, a resource not released; CWE-754, a condition not checked; CWE-665, initialization done wrongly; CWE-834, iteration with no bound; CWE-682, a calculation done wrongly |
| Everything else | Style, dead code, a weakness no tier names, and none at all |

## Grouped code findings

Two analyzers on one build report some flaws twice. Each result stays its own
code finding with its own history. Two are the same flaw where all of these
hold:

| Condition | Reason |
|---|---|
| Both are open on one build | A flaw is in the code one build was made from |
| Their analyzers differ: the part of a rule's name before the first `/`, in any case, with a clang checker clang-tidy runs counted as clang's | One analyzer already told adjacent results apart, and clang-tidy runs clang's own static analyzer |
| Their rules' weaknesses share a family | One overflow was CWE-788, 119 and 121 from three tools |
| Their last places are in one file, within two lines | cppcheck names where a problem starts and the others where it bites: first places differed in 8 of 41 same-flaw pairs, last places in 2 |

Within two lines grouped every same-flaw pair of clang, cppcheck, CodeQL and
semgrep over libyaml, jq, Lua, giflib and seeded files, and none of five pairs
of flaws a line or two apart; a wider window or the first place merged at least
one falsely.

| Rule | Reason |
|---|---|
| A result's last place is its path's last step, its last related place in its own file, or its own place | cppcheck lists the places after the first as related, in order |
| Code findings within ten lines and otherwise alike are listed under Possibly also found by, never grouped | A false merge hides a second real flaw behind one decision |
| The evidence lists, under Also found by and Possibly also found by, those the reader may read (REQ-42) | |
| A group is a code finding and those within two lines of it, worked out for each | Two each the same flaw as a third and four lines apart are two groups |
| Whether another analyzer reports a code finding is worked out over every code finding on the build, whoever reads | Where it sorts does not depend on who looks |
| Nearby code findings are found through an index on a digest of the last path, and the last line | No MySQL index takes a path whole. For 16,000 code findings of two analyzers' first runs, the queue answered in 0.6 s on PostgreSQL 16 and 1.2 s on MySQL 8.4, against 90 s and 37 minutes without |
| A rule with no weakness groups with nothing | clang tags none, so its code findings group once their weaknesses are known |
| A decision covers its code finding and every code finding of the group nothing answers yet, agreed once | The same flaw takes the same answer whichever tool reported it |
| Left out of that reach: one already answered, waiting on a decision, under a suppression rule, fixed, recorded as a flaw, past its end of life, or unreadable by the person judging | One answered keeps its answer, and a decision reaches nothing its author cannot read (REQ-42) |
| One possibly the same flaw is left out | It is judged alone |

## Limits

| Limit | Detail |
|---|---|
| Every code finding of a series' first run is in the queue | Starting to analyze a codebase leaves what it already holds to triage, as a vulnerability scanner's first scan does. The order and the suppression rules are what thin it |
