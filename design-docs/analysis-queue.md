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
| A rule's rating is the newest naming run's, held until rated again | |
| A rule's tier is the highest of every weakness recorded for it, re-ranked each run naming it | |
| A severity outside 0 to 10 or not a number, and an unknown precision, are none | |

## Queue file

`GET /v1/products/{product}/code-findings.{format}` writes the list as CSV or
JSON (`design-docs/analytics.md` § Exports).

| Rule | Reason |
|---|---|
| The file is the list, every row, same filters and order, same visibility (REQ-42, REQ-43) | One read |
| A row names the holder (who, display name, whether a team's queue) and whether third-party, from the newest run seeing it | A team and a person may share a name |
| No row carries source text | |
| With no state named, the file says it lists the queue; narrowed to unheld work, it says so | An empty query reads as everything |
| A refusal is answered before the first byte | |
| A findings list's file writes the open code findings of its selection below its findings, through this read, keeping those a decision waits on | The finding exports include them (REQ-50) |

## Code findings by series

`GET /v1/products/{product}/code-finding-series` counts code findings per
analyzer series by state, drawn as Code findings by analyzer
(`design-docs/analytics.md` § Pages of the catalog's own).

| Rule | Reason |
|---|---|
| Every state counts, zero included, beside those a waiting decision leaves out and those a rule covers | |
| Each count is the list's total for that series and state | One population |
| Counted over every build | Narrowed, a series never run there shows zeros like a clean one |
| A series with no code finding is listed with zeros | |
| Only `internal-read` on the product reads it; anybody else is refused naming no count or series | Counts are internal; a flaw's reader reads one code finding, not the figures |
| Ordered by series name | |

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
