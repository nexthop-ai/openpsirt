# Code finding flaws

A confirmed code finding recorded as a flaw: the record and its offer,
inclusion in the flaw's disclosure, withdrawal, the fix, and collaborators.

Satisfies REQ-19, REQ-40, REQ-42, REQ-43, REQ-71.

## Contents

- [Flaw records](#flaw-records)
- [Flaw record offer](#flaw-record-offer)
- [Disclosure inclusion](#disclosure-inclusion)
- [Withdrawn flaw record](#withdrawn-flaw-record)
- [Fixed in](#fixed-in)
- [Code finding collaborators](#code-finding-collaborators)
- [Limits](#limits)

## Flaw records

A confirmed code finding is recorded as a flaw found here (REQ-19), through the
path every recorded flaw takes (`design-docs/findings-flaws.md` § Recorded
flaws). `GET …/code-findings/{occurrence}/flaw` is the offer; `POST` records it.

| Rule | Reason |
|---|---|
| Only a confirmed code finding, once | |
| It links every code finding the confirming decision covers and nobody recorded (`design-docs/analysis-queue.md` § Grouped code findings) | One decision, one flaw |
| It needs `security-testing-triage` and `private-triage` | It reads security testing work and writes private |
| The flaw is undisclosed, found here, at no version | |
| Flaw and link are written in one transaction re-reading that the code finding is confirmed and unrecorded (REQ-71) | |
| It changes the standing decision's stamp, matched on the stamp read (`design-docs/database-transactions.md` § Reads a write depends on) | A concurrent withdrawn confirmation would leave a flaw nobody confirmed |
| A recorded code finding takes no decision, and its decisions are neither revised, withdrawn, split, approved nor sent back (409); an undone batch of approvals skips them | The flaw's decisions replace them |
| Recording, inclusion, removal and withdrawal are refused without both triage roles before any build named is resolved | A differing refusal lists builds (REQ-42) |
| The flaw records its code finding, the offer's first component, and the builds proposed: every build seen in, plus those holding the component never analyzed | The record outlasts the link |
| The flaw's page names its code finding only to a reader of both | (REQ-42) |

## Flaw record offer

| Part | Holds |
|---|---|
| Builds | Every build holding the code finding; the person chooses |
| Components | Ranked: the prefix's earlier confirmed component, the one placed on arrival, up to five resembling the prefix's last segment, then the build |
| Lacking | Per component, builds seen in without it; recording there is refused |
| Unanalyzed | Per component, builds in use holding it that the series never analyzed |
| Prefix | The innermost run repository or declared third-party path holding the file, else its directory |
| Third-party | Whether to report upstream (`design-docs/analysis-source.md` § Third-party code) |
| Together | How many others the record links |
| Disclosure | What inclusion publishes: every decision note by author, the analyzer's paths and messages, and whether snippets are published |

| Rule | Reason |
|---|---|
| The chosen component is recorded for the prefix; choosing the build leaves it confirmed as nothing | The next is offered it first |
| The longest recorded prefix is offered | |
| A resembling component is offered, never chosen | |

## Disclosure inclusion

A recorded code finding is security testing only, or included in its flaw's disclosure:
off by default, chosen at recording and changeable while undisclosed.
`PUT …/code-findings/{occurrence}/flaw/disclosure` includes; `DELETE` removes.

| | Security testing only | Included |
|---|---|---|
| Visibility of it and its decisions | Security testing | Security testing |
| A security testing reader | All of it and its decisions, nothing of the case, and is not told its flaw | The same |
| Somebody granted it | It without its decisions, and its flaw | The same |
| A reader of undisclosed work | Nothing | It, its decisions, its flaw |
| A reader on the flaw's case | Nothing unless granted | It, its decisions, its flaw |
| At disclosure | Stays at security testing visibility | Public with its decisions (REQ-40) |
| A later sighting | Security testing | Security testing, read by both audiences |

| Rule | Reason |
|---|---|
| Inclusion adds the flaw's readers and removes nobody; removal takes back only those, from it and its decisions | |
| The flaw's readers read it wherever security testing readers do: evidence, queue, counts, files, rule coverage, kin | One data-layer rule (REQ-42, REQ-43) |
| Reading undisclosed work adds included code findings of undisclosed flaws, nothing else | |
| They read its decisions while undisclosed: reasoning, revisions, approvals, comments, pages, lists, counts, exports; nothing else at security testing visibility | The decisions go public with it |
| Commenting and approving keep the security testing triage role | |
| Inclusion publishes every revision, comment, path and analyzer message on the linked code findings | Writers must know from the first word (REQ-40) |
| The offer shows that writing first, by author, with snippet publication and stripped count, read at the caller's visibilities (REQ-42) | |
| Disclosed is readable in the portal by everybody signed in with public access; never in VEX or CSAF; never anonymous | |
| At disclosure kept source is stripped except where its path discloses it, and later runs strip alike (`design-docs/analysis-source.md` § Snippets) | |
| Disclosure stamps the flaw record of every code finding of the flaw | Security-testing-only visibility does not show it |
| Inclusion and removal are refused with 409 once disclosed, take every code finding of the flaw, and need both triage roles | |
| An inclusion's notice goes to the audience before the change | |
| A run writes itself onto each flaw record it touches before reading one or writing source | Disclosure then waits or sees the change |
| Inclusion, removal and disclosure change the flaw record only as read in their transaction: visibility, undisclosed, last describing run; a lost race is asked again | |
| Inclusion and removal are in the administrative trail | They change access |

## Withdrawn flaw record

`POST …/code-findings/{occurrence}/flaw/withdrawal` undoes a record, with why.

| Rule | Reason |
|---|---|
| It takes every code finding of the flaw, is refused with 409 once disclosed, and requires a reason | |
| Each is confirmed again: link gone, decision kept, back in held work with its holder | |
| An included one returns to its security testing readers | |
| Every grant ends, each a withdrawal in the trail | No case remains |
| The flaw's open findings close `invalid` on every build (`design-docs/findings-closure.md` § Affected build sets) | No fix, no fixed release |
| The flaw keeps the record of its code finding, marked undone with who, when, why | |
| One transaction re-reads each record and deletes it only as read (REQ-71) | |
| The trail records it once per code finding | |

## Fixed in

The flaw is offered as fixed on each build where its code finding is no longer
detected, with the first run not seeing it and any run a person named. A person
closes it (`design-docs/findings-closure.md` § Closure by a person), and the
advisory names the fixed build from that (`design-docs/remediation-advisories.md` § The
advisory).

| Rule | Reason |
|---|---|
| The code finding read is the recorded one's newest finding per build | |
| Only a person closes the flaw | Of 28 comparable absences hand-checked, 10 were fixes |
| The offer is read under the reader's visibility | |

## Code finding collaborators

`…/code-findings/{occurrence}/collaborators` brings people into one recorded
code finding, as case collaborators into a flaw (REQ-43,
`design-docs/access-disclosure.md` § Case collaborators).

| Rule | Reason |
|---|---|
| A grant reaches the evidence while the flaw is undisclosed, never its decisions, the build's tree or its kin; disclosure ends it | One code finding |
| Managed by readers of the product's security testing work | |
| Refused with 409 once disclosed; granted in one transaction with the flaw record read | |
| In the trail, and the person told in a line their grant reaches | |
| A case reader reads an included one in full | |

## Limits

| Limit | Detail |
|---|---|
| A notice or mention on a decision at an included code finding reaches security testing readers alone | Mentions resolve against the decision's security testing visibility until disclosure |
