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
flaws), and linked to it; the flaw is then what is judged, fixed and disclosed.
`GET …/code-findings/{occurrence}/flaw` is the offer, and `POST` there records
it.

| Rule | Reason |
|---|---|
| Only a confirmed code finding is recorded, and only once | Confirmation is the decision it is a flaw |
| A flaw record links the code finding and every code finding its confirming decision covers that nobody recorded to the one flaw | One decision confirmed them as one flaw (`design-docs/analysis-queue.md` § Grouped code findings). One left behind holds a decision nothing may change, and no flaw |
| Made by somebody holding `internal-triage` and `private-triage` on the product | It reads the internal code finding and writes the private flaw |
| The flaw is undisclosed, found here, and recorded at no version | A flaw in our own code is the disclosure process's case, carried by occurrence |
| The flaw and the link are written in one transaction, which reads again that the code finding is confirmed and unrecorded | A retry is asked again (REQ-71) |
| A flaw record changes the stamp of the decision standing at the code finding, matched on the stamp it read (`design-docs/database.md` § Reads a write depends on) | A withdrawn confirmation committing beside it would leave a flaw nobody confirmed. The one matching nothing is taken again and finds the other |
| A code finding recorded as a flaw takes no decision, and no decision about it is revised, withdrawn, split, approved or sent back, each refused with 409; an undone batch of approvals leaves such a decision out | The flaw's decisions replace the code finding's |
| Recording, inclusion, removal from disclosure and withdrawal are refused to anybody without both triage roles before any build the request names is resolved | A refusal differing for a real and an absent build lists a product's builds (REQ-42) |
| The flaw records the code finding it came from, the component the offer ranked first, and the builds it proposed: every build the code finding was seen in, and those holding the chosen component the series never analyzed | The record outlasts the link, so a flaw whose record was undone still says where it came from |
| The flaw's page names its code finding only to a reader of the flaw there who reads the code finding in full | An internal-only code finding is internal, and a reader of the private flaw was not given it (REQ-42) |

## Flaw record offer

| Part | Holds |
|---|---|
| Builds | Every build holding the code finding, open or closed; the person chooses which the flaw is recorded against |
| Components | Ranked: the one the code finding's prefix was confirmed as before, the one it was placed on as it arrived, up to five whose names resemble the prefix's last segment, then the build itself |
| Lacking | Per component, the builds the code finding was seen in that hold no such component; recording against them is refused |
| Unanalyzed | Per component, the builds in use holding it that the series never analyzed; a variant nobody analyzes ships the same code |
| Prefix | The innermost repository the run names or third-party path it declared holding the file, or else its directory |
| Third-party | Whether the file is under a declared third-party path, so the flaw is reported upstream (`design-docs/analysis-source.md` § Third-party code) |
| Together | How many other code findings the record links with this one, included in disclosure or taken out with it |
| Disclosure | What including them discloses with the flaw: every note on a decision about them, by author, the analyzer's paths and messages, and whether snippets are published (§ Disclosure inclusion) |

| Rule | Reason |
|---|---|
| The component chosen is recorded for the prefix, replacing the earlier one, and choosing the build itself leaves the prefix confirmed as nothing | The next code finding under it is offered it first, and one turned down is not first again |
| The longest recorded prefix holding the path is offered | A repository nested in another names its own component |
| A resembling component is offered, never chosen | A name inside a directory's name is a guess |

## Disclosure inclusion

A code finding recorded as a flaw is internal only, or included in its flaw's
disclosure: one choice, off by default, made when the flaw is recorded and
changed while it is undisclosed, deciding only what is published.
`PUT …/code-findings/{occurrence}/flaw/disclosure` includes one, and `DELETE`
there takes it out.

| | Internal only | Included in disclosure |
|---|---|---|
| Visibility of the code finding and the decisions at its occurrence | Internal | Internal |
| An internal reader reads | The whole code finding and its decisions, nothing of the case | The same |
| Somebody granted the code finding reads | The whole code finding without its decisions, and its flaw | The same |
| A reader of undisclosed work reads | Nothing | The whole code finding and its decisions, and its flaw |
| A reader on the flaw's case reads | Nothing, unless granted the code finding | The whole code finding and its decisions, and its flaw |
| When the flaw is disclosed | The code finding stays internal | It and its decisions go public with the flaw (REQ-40) |
| A later sighting opens | Internal | Internal, read by both audiences |

| Rule | Reason |
|---|---|
| An inclusion adds the flaw's readers to the code finding's and takes nobody away | Somebody who read it keeps reading it |
| Taking it out takes back only the readers the inclusion added, from it and the decisions at its occurrence | Its internal readers and grants are as they were |
| The flaw's readers read an included code finding wherever its internal readers do: evidence, queue and counts, its file and the findings file, a suppression rule's coverage, its kin | One rule in the data layer, so no list differs from the page (REQ-42, REQ-43) |
| Reading undisclosed work reads no internal code finding the flaw does not hold | The addition is the included code findings of an undisclosed flaw alone |
| The flaw's readers read the decisions at an included code finding's occurrence while it is undisclosed: reasoning and revisions, approvals, comments, one decision's page, and every list, count and export holding them | The audience reading the evidence reads the decisions, which go public with it |
| The decisions stay internal, and the addition is those decisions alone | A decision is filed under the analyzer's rule, and the flaw's readers read no other internal decision |
| Reading a decision there is not arguing it | A comment and an approval keep the internal triage role, and such a decision is neither revised nor withdrawn |
| An inclusion discloses, with the flaw, every revision of reasoning and comment on a decision about the code findings linked, every path they name and every analyzer message there | People writing in the record must know that from the first word (REQ-40) |
| The offer shows that writing before the inclusion, by author, with paths and messages, whether snippets are published and how many are stripped | The person including it reads what goes public |
| The writing in the offer is read at the caller's visibilities in the product, narrowed in the data layer (REQ-42) | Though a flaw record takes both triage roles |
| Disclosed means readable in the portal by everybody signed in with public access to the product | A code finding is never in a published VEX or CSAF document, and the anonymous subject reads none |
| At disclosure an included code finding's kept source is stripped, except under a path whose setting discloses it, and a later run describing it is stripped the same way (`design-docs/analysis-source.md` § Snippets) | A run writes what the analyzer sent |
| Disclosure records its time on the flaw record of every code finding recorded as the flaw | An internal-only one stays internal, so its visibility does not say its flaw is public |
| An inclusion or removal is refused with 409 once the flaw is disclosed | Disclosure is one way |
| The notice of an inclusion goes to the audience before the readers changed | It tells the flaw's people the code finding is part of the case |
| An inclusion and its removal take every code finding recorded as the flaw | One flaw's code findings are one case |
| A run writes itself onto the flaw record of every code finding it describes or opens at, before it reads a flaw record or writes source | A disclosure or inclusion then waits for the run, or finds the record changed |
| An inclusion, a removal and a disclosure each change the flaw record only as read in their transaction: its visibility, its flaw undisclosed, and the last run to describe it | One losing a race is asked again; a disclosure reading before a run cannot see the source it wrote, nor an inclusion the sighting it opened |
| An inclusion and its removal are in the administrative trail, made by somebody holding `internal-triage` and `private-triage` | It changes who reads the code finding |

## Withdrawn flaw record

`POST …/code-findings/{occurrence}/flaw/withdrawal` undoes a flaw record, with
why.

| Rule | Reason |
|---|---|
| It takes every code finding recorded as the flaw | One flaw's code findings are one case |
| It is refused with 409 once the flaw is disclosed, and asks for a reason | Disclosure is one way, and undoing takes the flaw out of every build |
| Each code finding is confirmed again: the link goes, the confirming decision stands, and it returns to the queue's lists of held work with its holder | The recording is undone and the judgment kept |
| An included code finding is read by its internal readers alone again | With no case it is internal material |
| Every grant of the code findings ends, each in the administrative trail as a withdrawal | A grant brings somebody into a case, and there is none |
| The flaw's open findings close as `invalid`, with the reason, on every build | A flaw from an undone record should not have been recorded, and a new record makes its own flaw. Invalid counts as no fix and names no release fixed (`design-docs/findings-closure.md` § Affected build sets) |
| The flaw keeps the record of its code finding, marked undone with who, when and why | What was recorded and taken back stays on the record |
| Written in one transaction that reads each flaw record again and deletes it only as read | An inclusion, disclosure or run since is a lost race, asked again (REQ-71) |
| In the administrative trail once per code finding, under its own name, as each grant ended is | It changes who reads them and what the flaw is |

## Fixed in

A flaw recorded from a code finding is offered as fixed on each build it is
open on where its code finding is no longer detected, with the first run there
not seeing it and, where a person closed the code finding as fixed, the run
named. A person closes the flaw there (`design-docs/findings-closure.md`
§ Closure by a person), and the advisory names the build fixed from that
closure (`design-docs/remediation.md` § The advisory).

| Rule | Reason |
|---|---|
| The code finding read is the one the record was made at, its newest finding on each build | One seen again after a fixed closure opens anew, and the new finding speaks |
| Nothing closes the flaw but a person | Of 28 comparable absences hand-checked, 10 were fixes |
| The offer is read where the code finding is, under the reader's visibility | It is part of the code finding |

## Code finding collaborators

`…/code-findings/{occurrence}/collaborators` lists, adds and removes people
brought into one code finding recorded as a flaw, as case collaborators are
brought into one flaw (REQ-43, `design-docs/access.md` § Case collaborators).

| Rule | Reason |
|---|---|
| A grant reaches the code finding's evidence while its flaw is undisclosed, and nothing else; disclosure ends it, included or not | It is one code finding, never a list |
| A grant reaches neither the build's inventory or tree nor the code finding's kin | It is not a grant of the build or of what sits beside it |
| Collaborators are managed by somebody reading the product's internal work, included or not | A grant, and a reading through the flaw, are not readings of internal work |
| A grant or withdrawal is refused with 409 once the flaw is disclosed, and made in one transaction with the read of the flaw record it depends on | The grants have ended |
| A grant and its withdrawal are in the administrative trail, and the person is told they were brought in, in a line their grant reaches | As a case collaborator |
| A reader on the flaw's case reads an included code finding in full | It is part of the case |

## Limits

| Limit | Detail |
|---|---|
| An internal reader reads an included code finding whole and is not told its flaw | The flaw is undisclosed work. The state reads recorded as a flaw for both |
| A grant of an included code finding reaches its evidence and not the decisions at its occurrence | The decisions are widened for the flaw's two audiences, and a grant is a third reach of one occurrence's findings |
| A notice or mention about a decision at an included code finding reaches its internal readers alone | A mention resolves against the people reading the decision's visibility, internal until disclosure. A reader of the flaw reads the decision and is not told of a note on it |
