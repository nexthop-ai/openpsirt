# Remediation

Declared fix intent, the commitments it writes, and how scans answer them.

Satisfies REQ-19, REQ-28, REQ-34, REQ-35, REQ-36.

Deadlines, upstream currency, version ordering, advisories, the CSAF document,
the VEX document and the provider directory have documents of their own
(`DESIGN.md`). The escalation view, time remaining and the compliance rate are
in `design-docs/analytics.md`; the party work is assigned to, in
`design-docs/access.md`.

## Contents

- [Declaration, not completion](#declaration-not-completion)
- [The unit](#the-unit)
- [Promise states](#promise-states)
- [Planned upgrades of a build](#planned-upgrades-of-a-build)
- [Build-declared suppressions](#build-declared-suppressions)
- [External links](#external-links)
- [Not built](#not-built)
- [Limits](#limits)

## Declaration, not completion

A fix is declared and never completed (REQ-35). A decision promising work names
the releases it is for, and the next scan of each answers whether it arrived.

| Rule | Reason |
|---|---|
| The stored row is the declaration alone: build, fold, who and when. No state, no completed-at | A scan already says whether the issue is there; a second record of it drifts into a fix shipped in nobody's release |
| A declaration arrives only with the decision arguing for it: a bump, against the component, or a backport, against the issue | Bare intent carries no version, date or reasoning, so nothing lapses and nobody agrees to it |
| A flaw recorded by hand is closed by a person, with who, when and why (REQ-19; `design-docs/findings-closure.md` § Closure by a person) | No scan reports one, so the finding would stay open forever |

## The unit

A commitment is one build moving one fold, a source package at the version it
was built at, to another version: one row.

| Rule | Reason |
|---|---|
| A release is named by branch or tag and variant together | One branch built two ways is two builds |
| Acting on a plan acts on the product, never on the build in the route's path | The route names a finding so a screen can link to it |
| One commitment per build per fold, enforced by the database | A release moves a package to one version |
| A fix declared for a product covers its builds without being written per build, and its proposals are made distinct before they are written | A decision's live key names the occurrence, not the build, so one component in two builds yields identical proposals that collide on the unique index and roll back the declaration |

### Coverage by matching

A finding is covered when its component folds to the commitment's key in the
commitment's build. Nothing is written onto findings.

| Consequence | Detail |
|---|---|
| Changing a target version is one row | |
| An issue published tonight is covered by this morning's commitment | Keyed per issue, it is not covered until somebody declares it too |
| A sibling package moves with its source | curl, libcurl4t64 and libcurl3t64 are one bump, so a commitment recorded against one covers all of them |
| No version comparison decides coverage | An upgrade covers everything open on the fold |

### Commitment changes

| Source | Change |
|---|---|
| A decision somebody agreed to | Through the act revising it, with a reason; it withdraws every agreement and returns the rows to the queue, and the revisions keep what was promised before |
| Intent nobody argued for | The row is edited |

A promise needs a second person when its date falls after the earliest
deadline among what the decision covers. A promise with no date, or over
nothing that carries a deadline, always needs one.

| Rule | Reason |
|---|---|
| Changing the version or the date under a standing agreement is refused, naming the decision to revise | The agreement would stand over a promise nobody read (REQ-28) |
| A revised promise is gated again | A later date can pass the earliest deadline; left ungated, it is in force, suppressing what it covers, and in no queue |
| The gate reads what the decision covers now, inside the writing transaction: builds from its commitments, occurrences from its own rows | Deadlines move with the policy and the rating |
| A promised patch moves by its date alone, its builds those holding an open finding it covers | It has no version and writes no commitments |
| A date already past is refused | |
| The reasoning passes the text policy (`design-docs/text.md`) | |

## Promise states

A commitment is answered by the scans of its build, never by somebody marking
it done (REQ-35). Its state is worked out on every read and stored nowhere.

| State | Condition |
|---|---|
| Landed | Nothing left open under it in that build |
| Lapsed | The date past, with work outstanding |
| Planned | Anything else |

| Rule | Reason |
|---|---|
| The date is on the commitment; the decision is a citation | One fact, changed through the decision |
| Only the decision that made a commitment withdraws it; a promise narrowed to fewer builds keeps those another decision made | That decision's occurrences stand on them |
| A second decision promising a build already committed is refused, naming the standing one, even with the same version and date | Its occurrences would rest on a date only the first moves |
| No "replanned" state | Re-promising writes a new date |
| Several promises over one component in one build report one whole: a version before none, then the latest date, then the later decision | The latest date beside the lowest version pairs two promises nobody made |
| A lapsed promise returns the upgrade as one item, never its findings | The bulk promise replaced answering them one at a time |
| A lapsed upgrade names a party only where one holds all of what is open under it, by identity or team name with the display name beside (`design-docs/api.md` § Addresses and labels) | |
| A finding returns on its own only when the package moved and it did not close | A decision is keyed on the upstream version it was made against |

## Planned upgrades of a build

The product's planned upgrades inverted (REQ-35): a triager reads an upgrade
and what it closes in the findings list's by-upgrade view, a coordinator a build
and the upgrades it waits on, here. One query, keyed on the fold at both ends.

| Rule | Reason |
|---|---|
| The version in hand and the target are stored with the commitment | Read off the open findings, they go blank as the upgrade lands |
| Each row counts what is still open under it: distinct issues and their occurrences | A build is clear when it stops holding them |
| A bump is keyed on its target as well as its source | Grouped on source alone, upgrades to 5.9.0 and 5.9.2 read as one row; on a real image 42 of 127 pairs carry more than one target |
| The last tie breaks on the fold | Rows keep one order across pages |
| One source at two versions in one build lists the earlier first, by the ecosystem's ordering (`design-docs/remediation-versions.md`), else by text | |

## Build-declared suppressions

A carried patch is the only evidence of a backport: the version has not moved
and no comparison finds one. What a build says it handles itself reads as a
history over its scans.

| Rule | Reason |
|---|---|
| The stretch of scans makes it a history | The interesting row is the claim that stopped, whose finding is back |
| Narrowed on what a claim is about, never on a package the build still carries | A claim naming something gone is what somebody asking why a patch stopped working wants |
| The row distinguishes a patch on a component declaring what it fixes from a claim in a document of its own naming something to match; a claim suppressing nothing says so | |
| A claim names the product it places its subject inside | "zlib inside curl" and "zlib inside openssl" are two claims |
| A claim from a document uploaded on its own is not listed | It spans none of the build's scans; the finding shows it |

## External links

A decision carries one link to work elsewhere, stored and read by people;
nothing is sent to it (REQ-36). The signed outbound request (REQ-46) is
`design-docs/notifications.md`'s, with its egress controls and the one place a
private address is permitted.

| Rule | Reason |
|---|---|
| One link per decision, never per release | The conversation about a promise is one |
| Nothing fetches what a link points at; it is stored as text and encoded on output | A fetched typed address is a request-forgery primitive |
| Sent empty, it is cleared | |
| Anybody who may argue about a decision may set it | A link is a note, not a decision |
| Assigning notifies; planning does not (REQ-34) | Planning is done to the work |

## Not built

| Not built | What exists |
|---|---|
| The tracker hand-off (REQ-36): opening or updating an item where a link points | The link, stored and never fetched |
| A roll-up of one promise across its builds: "landed in two of three, planned in the third" | Per-build state, and the findings list, a row per build |

## Limits

| Rule | Reason |
|---|---|
| A commitment is as current as the findings open under it, read at what the reader may see | Landed means nothing open remains, whatever closed it |
