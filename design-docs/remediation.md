# Remediation

Declared fix intent, the commitments it writes, and how the next scan of each
build answers them.

Satisfies REQ-19, REQ-28, REQ-34, REQ-35, REQ-36.

Deadlines, upstream currency, version ordering, advisories, the CSAF document,
the VEX document and the provider directory each have a document of their own
(`DESIGN.md`). The escalation view, time remaining and the compliance rate are
in `design-docs/analytics.md`; the party work is assigned to is in
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

A fix is declared and never completed (REQ-35). A decision promising work
names the releases it is for, and the next scan of each answers whether the fix
arrived.

| Rule | Reason |
|---|---|
| The stored row is the declaration alone: build, fold, who and when. No state, no completed-at, nothing to move along | A scan already finds the issue or does not. A second record of that fact is one somebody keeps true, and it fails by reporting a fix that shipped in nobody's release |
| A declaration arrives only with the decision that argued for it: a bump, recorded against the component, or a backport, recorded against the issue | Bare intent carries no version, date or reasoning, so nothing lapses and nobody agrees to it |
| A flaw recorded by hand is closed by a person, with who, when and why on the record (REQ-19) | No scan reports one, so a declaration has nothing to be checked against and the finding stays open forever (`design-docs/findings-closure.md` § Closure by a person) |

## The unit

A commitment is one build moving one fold, a source package at the version it
was built at, to another version. It is one row.

| Rule | Reason |
|---|---|
| A release is named by its branch or tag and its variant together | One branch built two ways is two builds, and naming the branch alone claims a fix for hardware nobody built for |
| Acting on a plan acts on the product, never on the build in the route's path | A route names a finding so a screen has somewhere to link; the plan belongs to the work |
| One commitment per build per fold, enforced by the database | A release moves a package to one version, and two rows is a plan a coordinator cannot read |
| The proposals a declaration makes are made distinct before they are written | A decision's live key at an occurrence names the occurrence and not the build, so the same component in two builds yields identical proposals that collide on the unique index and roll back the declaration |

### Coverage by matching

A finding is covered when its component folds to the commitment's key in the
commitment's build. Nothing is written onto findings.

| Consequence | Detail |
|---|---|
| Changing a target version is one row | Keyed per issue, component and target version, it would rewrite every row |
| An issue published tonight is covered by this morning's commitment, with nobody acting | |
| A sibling package moves with its source | curl, libcurl4t64 and libcurl3t64 are one bump |
| No version comparison decides coverage | An upgrade covers everything open on the fold, not only what names this version as its fix. An ordering reads candidates, never what a commitment reaches |

### Commitment changes

| Source | Change |
|---|---|
| A decision somebody agreed to | Through the act that revises it, which withdraws every agreement on it and returns its rows to the queue. A reason is required, and the revisions keep what was promised before |
| Intent nobody argued for | The row is edited |

| Rule | Reason |
|---|---|
| Changing the version or the date under a standing agreement is refused, naming the decision to revise | Rewriting either half leaves the agreement over a promise nobody read (REQ-28) |
| A revised promise's need for a second person is worked out again | Moving the date moves what the approval threshold is about. Left as needing nobody, a promise first made inside the deadline returns in force at any later date, suppressing what it covers and in no queue |
| That need is measured over what the decision covers now: its builds from the commitments it wrote, its occurrences from its own rows, read inside the writing transaction | A deadline moves when the policy or the rating moves |
| A promised patch moves by its date alone, and its builds are those holding an open finding the decision covers now | It has no version and writes no commitments |
| A date already past is refused | It says the work happened before now |
| The reasoning passes the text policy (`design-docs/text.md`) | Every path storing typed text runs it |

## Promise states

A commitment is answered by the next scan of its build, never by anybody
marking it done (REQ-35). Its state is worked out on every read; nothing
stores, refreshes or invalidates it.

| State | Condition |
|---|---|
| Landed | Nothing left open under it in that build, as the scans say |
| Lapsed | The date past, with work outstanding |
| Planned | Anything else |

| Rule | Reason |
|---|---|
| States are derived, never stored | Stored, they are a third opinion able to disagree with the scans and the calendar |
| The date is on the commitment, and the decision that argued for it is a citation | They are one fact, and changing it goes through the decision |
| Only the decision that made a commitment withdraws it. A promise naming fewer builds withdraws its own commitments on the rest and keeps those another decision made | That decision's occurrences still stand on them |
| A second decision promising a build already committed is refused, naming the standing decision, even with the same version and date | Its occurrences would rest on a date only the first decision moves |
| No "replanned" state | Re-promising writes a new date, and a state indistinguishable from another is a word |
| Where several promises stand over one component in one build, one is reported whole: one naming a version before one naming none, then the latest date, then the later decision | Its date and version are read together; the latest date beside the lowest version pairs two promises nobody made |
| A lapsed promise returns the upgrade as one item, never its findings | Answering the findings one at a time is what the bulk promise replaced |
| A lapsed upgrade is reported as a party's only where one party holds all of what is still open under it, addressed by identity or team name with the display name beside it (`design-docs/api.md` § Addresses and labels) | |
| A finding returns on its own only when the package moved and it did not close | A decision at an occurrence is keyed on the upstream version it was made against, which tells "the plan was wrong about specifics" from "the plan did not happen" |

## Planned upgrades of a build

The product's planned upgrades inverted (REQ-35). A triager reads an upgrade
and the issues it closes in the findings list's by-upgrade view; a coordinator
reads a build and the upgrades it waits on, here. One query, both ends drawn,
both keyed on the fold.

| Rule | Reason |
|---|---|
| The version in hand and the target are stored with the commitment | Read off the open findings, they go blank as the upgrade lands and closes them |
| Each row reports what is still open under it, counted from the findings: the distinct issues it closes here and the occurrences they sit at | Nothing is declared done; a build is clear when it stops holding them |
| A bump is keyed on its target as well as its source | Grouped on the first two alone, upgrades to 5.9.0 and 5.9.2 read as one row saying 5.9.0. On a real image 42 of 127 pairs carry more than one target |
| The list breaks its last tie on the fold | The last grouped column, so two rows equal on every other key keep one order across pages |
| One source at two versions in one build lists the earlier first | By the ecosystem's ordering where the fold has one (`design-docs/remediation-versions.md`), by text where it has none |

## Build-declared suppressions

A carried patch is the only way a backport is visible here: the version has not
moved and no comparison finds one, so the build declaring it is the sole
evidence. What a build says it handles itself reads as a history over its
scans.

| Rule | Reason |
|---|---|
| The stretch of scans is what makes it a history | The interesting row is the claim that stopped: a dropped patch and the finding it answered back. A list of what stands would not hold it |
| Narrowed on what a claim says it is about, never on a package the build still carries | A claim naming something gone is what somebody asking why a patch stopped working wants |
| The two kinds are distinguished on the row | A claim on a component is a patch declaring what it fixes; a claim in a document of its own names something to match. A claim suppressing nothing says so |
| A claim names the product it places its subject inside, where it names one | "zlib inside curl" and "zlib inside openssl" are two claims |
| A claim from a document uploaded on its own is not listed | It spans no stretch of the build's own scans; the finding it covers shows it |

## External links

A decision carries one link to work happening elsewhere, stored and read by
people; nothing is sent to it (REQ-36). The signed outbound request (REQ-46) is
built, and `design-docs/notifications.md` owns it, including its egress
controls and the one place a private address is permitted.

| Rule | Reason |
|---|---|
| One link per decision, never per release | The conversation about a promise is one conversation |
| Nothing fetches what a link points at | Fetching a typed address is a request-forgery primitive. It is stored as text, shown as a link, and encoded on output |
| Sent empty, it is cleared | A stale link sends somebody to a ticket closed for a different reason |
| Anybody who may argue about a decision may set it | A link is a note about where the conversation is, never a decision |
| Assigning notifies; planning does not (REQ-34) | Somebody is told when work is put on them; naming the releases it reaches is done to the work |

## Not built

| Not built | What exists |
|---|---|
| The tracker hand-off (REQ-36): opening or updating an item in the system a link points at | The link somebody typed, stored and never fetched |
| A roll-up of one promise across its builds: "landed in two of three releases, planned in the third, due on the first" | Its source is the promise: the releases it names, the version and the date, each resolved by that release's next scan. What is built answers per build, and where an issue stands across builds is read from the findings list, a row per build |

## Limits

| Rule | Reason |
|---|---|
| A commitment is as current as its build's last scan | Landed is what the last scan holds; a build not scanned again stays planned, or lapses at its date |
