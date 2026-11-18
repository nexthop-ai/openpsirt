# Corrections by source paths

One correction answering every issue a binary package inherits from a large
source and is not built from: what it names, what it answers, and when.

Satisfies REQ-90.

## Contents

- [The rule](#the-rule)
- [Answered occurrences](#answered-occurrences)
- [Agreement and ending](#agreement-and-ending)
- [Answers on later scans](#answers-on-later-scans)
- [Readback](#readback)
- [Limits](#limits)

## The rule

A correction by source paths (REQ-90) names a package, the source package it is
matched through, and the paths within that source the package is built from.
It is a correction (`design-docs/triage.md` § Corrections): a wrong match, keyed
without versions, answering at every version. The case is `linux-perf`, built
from `tools/perf`, `tools/lib` and `tools/include` and matched through `linux`
for every issue the kernel collects; of 20,372 CVE records listing files on
2026-11-18, 18,245 are the kernel's.

| Part | Rule |
|---|---|
| Product | One; it answers in that product's builds only |
| Package | Matched by the name the component is identified by, without regard to capitals, held in lower case |
| Source | Matched as the scanner records it, in lower case; differs from the package |
| Paths | One to 64, each at most 1,024 bytes, relative to the source's root; leading and trailing slashes, `.` segments and repeated slashes are removed; the root and a path leaving it are refused; held in byte order |
| Reason | One of the two saying something is not there |
| Reasoning | Required, and holds for every issue it answers |
| Kind | `source`, beside the decision kinds in `design-docs/triage-decisions.md` § Decisions |

Proposing takes the same rights as any decision in the product, and is refused
where it answers nothing open now, naming fewer paths or the names a finding
shows as the remedy.

## Answered occurrences

An occurrence is answered when every condition holds.

| Condition | Reason |
|---|---|
| An open finding of a published issue, at the package, in the product | |
| Matched through the source, as `design-docs/findings-components.md` § Match methods records it | A match on the package's own name or a CPE is a claim about the package itself |
| The issue's CVE record lists files, and none lies under any path | A record listing no files says nothing about where the fault is |
| A path holds a file by whole segments: `drivers/phy` holds `drivers/phy/ti/x.c`, not `drivers/phylib.c` | |
| Public | An undisclosed finding is a person's to answer |
| No incident stands for the issue in the product | An attack through the issue outranks a rule about where its code lives |
| No correction already answers the occurrence | One live decision per key (`design-docs/triage.md` § One live decision per key) |

Each answered row records the files the record listed when it was written. The
files are the record's, read from the snapshot each scan reads
(`design-docs/ingest-scanner.md` § Program files).

## Agreement and ending

| Rule | Reason |
|---|---|
| A second person agrees, always, to the rule over whatever it reaches | It hides risk with nothing scheduled to look again |
| Until agreed, every row it writes waits | |
| A row written while an approval of the current reasoning stands is approved with it | The approver agreed to the rule, and the row follows from the rule and the record |
| A row written after the reasoning is revised waits for agreement again | The approval named the earlier words |
| A row written while every waiting row is sent back is sent back with them | |
| Withdrawing is the one way it ends; one with no live row answers nothing more | A rule set aside row by row has nobody standing behind it |
| Published as not affected with its reason | |
| No bulk cap applies | REQ-90 answers every issue matched that way |

## Answers on later scans

A scan applying a build's findings then answers by every correction standing in
the build's product, so an issue published after the agreement is answered on
the first scan that reports it.

| Rule | Reason |
|---|---|
| Only the scanned build's findings are read | A product's other builds were answered when they were scanned |
| A failure is logged and leaves the scan applied | The next scan answers what this one did not; a scan's findings are not held back by a correction |
| Two proposals over one occurrence at once leave one; the other's pass fails and is logged | The unique key decides |

## Readback

| Surface | Carries |
|---|---|
| A finding's evidence | The source it was matched through and the files its record lists |
| The decision | The package, source and paths |
| A decision occurrence | The files it was answered on |
| The finding screen | The source and files under the match evidence, and the form, filled with the package and source |

## Limits

| Limit | Detail |
|---|---|
| A row is answered on the files its record listed then | A record later naming a file under the paths does not withdraw the row; the files kept on it show what it rested on |
| A match through two sources, or through a source and on the package's own name, records no source | The scanner's details disagree, and a correction is a claim about one route |
| A record's files are every entry's, joined | A file any of them names is one the issue may be in; 103 of 20,372 records listing files on 2026-11-18 list different files per entry |
| No bulk cap | REQ-27 caps a bulk dismissal by what a reviewer reads; REQ-90 has the reviewer read one rule, and the rule answers every issue it covers |
