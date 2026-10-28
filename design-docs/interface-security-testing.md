# Security testing screens

The Security testing screen, a code finding's page, decisions on code findings,
recording a flaw from one, and the suppression rules screen.
`design-docs/analysis.md` holds what a code finding is, where it stands and
what a suppression rule covers.

Satisfies REQ-19, REQ-40.

## Contents

- [Security testing](#security-testing)
- [A code finding](#a-code-finding)
- [Flaw records from code findings](#flaw-records-from-code-findings)
- [Suppression rules](#suppression-rules)
- [Limits](#limits)

## Security testing

The Security testing screen lists a product's code findings, reached from the
product page.

| Rule | Reason |
|---|---|
| The link appears only for a reader of internal material in the product | A code finding is internal |
| The rail carries it under the scope beside Dependency findings and Vulnerability reports, for a reader of internal material anywhere, declining where no product is picked or the reader may not read internal material there. It opens on the picked branch and variant where both are, else every build | |
| It opens on the queue, with one tab per state: the queue is open code findings with nothing waiting; each state's tab carries its count, the queue's none | |
| Above the queue: how many wait for approval, how many a suppression rule dismisses (opening the dismissed tab), how many are past end of life | |
| A row opens the code finding on its build, naming that build and how many others hold it in the listed state; build and opening date do not wrap | Evidence is per build |
| Rows name the holder, a team marked team | |
| Rows name the component the code finding is placed on, with its version, opening the component on the row's build; one on the build itself reads Whole build, why on hover | |
| The branch and variant are in the address, so a build's link narrows it; a product picked in the scope bar keeps the screen and drops them | A branch is one product's |
| A series in the address narrows it and is named in the heading; each figure of Code findings by analyzer opens its series and state | |
| Unassigned only narrows to code findings nobody holds, in the address and heading, across tabs, counts and the file (`design-docs/analysis-queue.md` § Code finding queue) | The findings list holds no code finding |
| The list is offered as CSV and JSON with the narrowing on screen, every row (`design-docs/analysis-queue.md` § Queue file) | |
| Code findings by analyzer asks no count from a non-reader of internal material, and says code findings are internal | A table of zeros reads as an analyzer finding nothing |

## A code finding

| Rule | Reason |
|---|---|
| The page holds, in order: the result, the path, the related places, Also found by, the decision | |
| The heading names the component it is placed on, opening the component on its build, or the whole build, why on hover | |
| Each place is file and line, linked to the repository where the address passes the link check, with the analyzer's message there and the captured code | |
| Also found by (the same flaw) and Possibly also found by (maybe) are two lists; one decision covers the first, said on hover | |
| The result card names the holder and offers the finding's holder picker to a triager, searching readers of internal work, not past end of life; choosing applies to every build it is open on | It is held as internal until its flaw is disclosed |
| The decision card names the standing decision, opening the decision page, or offers the form | A code finding under a decision takes no second |
| The form offers the three code finding outcomes as cards, a reason for a dismissal, and reasoning; "Propose" where somebody else agrees, "Submit" for a confirmation, effective at once | |
| The decision page offers Agree on a code finding's decision to a holder of `approver` and `internal-read`, never its proposer | The screen asks the reader's reach as the server does |
| On a decision about internal material the decision page offers the comment box to whoever triages or approves internal work, and the work link, Revise reasoning and Withdraw to whoever triages it | A flaw's readers read included decisions and take no part |
| A code finding no longer detected offers closing it as fixed to a triager of internal material: what fixed it, naming the build of the first run not seeing it; a fixed one names that build | |
| A non-triager of internal material sees no writing control | |
| Past end of life it says so beside its state and offers no decision, Record as a flaw or fixed control (`design-docs/analysis-triage.md` § End of life); Include in disclosure on an already-recorded one stays | The server refuses each |
| In code its run declared third-party it reads Third-party beside its state, on its page and row; Record as a flaw stays, saying to report upstream, what declared it on hover (`design-docs/analysis-source.md` § Third-party code) | The flaw is the upstream's |

## Flaw records from code findings

| Rule | Reason |
|---|---|
| A confirmed code finding offers Record as a flaw to a triager of internal material and undisclosed work | |
| The offered components are cards, most likely first, each saying where it came from; a build not holding the picked one is unticked and cannot be ticked | |
| The first component is picked unless it only resembles the code finding's directory (`design-docs/analysis-flaws.md` § Flaw record offer) | A resemblance is a guess |
| A build holding the picked component that nothing analyzes is listed unticked beside the builds seen, and may be ticked (REQ-19) | It ships the code, unread by the analyzer |
| Include in disclosure is one toggle, off; on, it lists what goes public before sending. Its hover: "Publishes the path, the analyzer's messages, and the decisions and comments on this finding with the flaw; until then, people on the flaw's case can read it." Under Disclosed with the flaw: each author's notes in full, messages and paths, whether snippets publish (REQ-40) | |
| The preview and hover say who public is: "Once the flaw is disclosed, readable by everyone signed in with public access to this product. Not included in published VEX or CSAF." | |
| Once recorded it reads Recorded as a flaw and shows the flaw, linked, in place of the decision; it reads Internal only or Included in disclosure, the second with "Included in its flaw's disclosure" on hover | |
| Include and Take out of disclosure are one button while the flaw is undisclosed, its collaborators listed beside; an internal-only one lists what including discloses above it | |
| Withdraw flaw sits beside it while undisclosed, asks why, and says on hover it closes the flaw on every build | |
| A recorded flaw's page shows its code finding to a reader of it: rule and place linked, state, suggested component, proposed builds, whether the record was withdrawn. Where the code finding is no longer detected on a build, Fixed here starts from the build that did not see it and a person closes it | |

## Suppression rules

| Rule | Reason |
|---|---|
| The screen lists every rule with what it names, what it covers beside the coverage at approval, and its state, explained on hover where needed | An outgrown rule shows why |
| Approve is offered on a waiting or outgrown rule to a holder of `approver` and `internal-read`, never on their own; the rule names its proposer | The server refuses the proposer |
| A new rule names an analyzer rule, a path, or both; one for a memory or injection rule needs a path | The server refuses otherwise |

## Limits

| Limit | Detail |
|---|---|
| A decision never covers Possibly also found by | Those may be other flaws |
