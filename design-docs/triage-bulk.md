# Decisions over many

How far one decision reaches across occurrences and builds, bulk decisions over
many issues, decisions a saved filter prepares, and decisions carried to a new
line.

Satisfies REQ-17, REQ-25, REQ-26, REQ-27, REQ-30.

## Contents

- [Reach across builds](#reach-across-builds)
- [Bulk decisions](#bulk-decisions)
- [Rule-prepared decisions](#rule-prepared-decisions)
- [Decisions on a new branch](#decisions-on-a-new-branch)
- [Limits](#limits)

## Reach across builds

How far a decision reaches is three parts.

| Part | What it is | What the person does |
|---|---|---|
| Occurrences in this build | The same component under several consumers: the same code and versions | Nothing. One decision covers all of them |
| Other builds already matching | Variants and branches whose upstream versions and chains are identical | Nothing. The decision reaches them by matching |
| Builds where the code differs | The same issue at the same occurrence, at another version | Chooses, one build at a time, each unticked: a component may be used in a later release and not an earlier one |

Covering by default suits identical code, where answering sixty-two times
guarantees nobody reads; a tick per build suits differing code, where a tick is a
decision about a version nobody looked at.

| Rule | Reason |
|---|---|
| One decision covers every occurrence it sits at by default (REQ-26); the occurrences are listed and ticked, and unticking one leaves it open with nothing asked about it | Silence about an occurrence is not a decision about it |
| The answer to making a decision says how many findings it covers and how many distinct versions sit there | A kernel issue reaches dozens of modules, and somebody otherwise learns afterwards they answered for sixty-two things. More than one version means the build ships the package twice under one consumer, which one decision cannot honestly cover |
| Covering many occurrences does not by itself require a second person | Otherwise people make narrow decisions, more records saying less |
| One action writes a separate record per build, each keyed to its own versions | A dismissal carried onto an older branch lapses by itself the moment that branch moves |
| A differing build is judged by the expression the decision is keyed on, and named with the version it ships, one entry per version | |
| Builds already covered are counted and never offered | A tick beside them asks for agreement to what has already happened |
| Only occurrences nothing already stands at are written; a build wholly reached by lookup records nothing, and that is no error | |
| One request, one transaction, one decision | A failure part way leaves an act nobody performed |
| Bounded on the occurrences it resolves to, never the builds named (REQ-27) | One name expands into every occurrence the issue has there |
| Nothing is withheld for sitting past the named fix | That needs an ordering per ecosystem, which exists for some and not the rest. The case needing no ordering is recorded instead: a version moved and the issue came with it |
| An approval names the reach as well as the words: the three parts are shown before the approver acts, and how much was covered is counted then and kept as one number | The number moves on its own, as a branch cut next month at the same versions is covered with nobody acting. What a decision covers now and what somebody consented to are different questions |
| Grouping is presentation (REQ-17): one grouped action writes a record per occurrence, and the group is derived when read | A stored group describes a build that is gone within a scan or two |
| A list hiding something says so, with the count (REQ-30) | |
| Exceptions are grouped by their layer: a suppression a build supplied, a decision made here, and a finding below the minimum severity (REQ-25) | Three kinds of "not shown"; one flat list reads a build's claim as this deployment's decision. Every kind of variant follows the same model |

## Bulk decisions

One action records one decision against a set of issues at one component: one
outcome, one justification, one reasoning, one approval, and a row per issue,
each keyed and expiring on its own. Grouping otherwise runs one issue across many
occurrences; the transpose is the case that breaks a queue, a kernel carrying
thousands of issues in drivers a given image never builds.

| Rule | Reason |
|---|---|
| A separate row per issue and per occurrence | Built from one occurrence of an issue, a decision silences one consumer and reports covering the rest |
| The component names a fold, never a binary package | The list folds the source package, so one vim row is four packages at sixty-one occurrences. Keyed on one binary, the decision covers a quarter of what the person meant |
| The fold is read as a short list of identifiers, never through a join | These queries read their page off the finding table's covering index; a third join under the aggregate costs 0.35 s against 0.04 s on the kernel, 222,435 of 272,539 open rows |
| The occurrences are resolved from the findings inside the writing transaction | A caller naming one chooses which decisions apply where, and an occurrence read before the write describes a database that has moved |
| How large the decision is, is said before it is submitted (REQ-27) | |
| A decision may span more than one page of candidates; selecting everything the narrowing matches fetches the rest | Assembled a page at a time, it is eighteen decisions where the person meant one |
| Every outcome a single decision offers is offered, deferred and already fixed included | Those are the bulk cases: a bump scheduled for the next release, and a distribution's backport |
| What is exploited or critical can be excluded before deciding | Take the bulk, and hand-triage the handful |
| A candidate row says what a single finding's row says: what the issue says about itself, whether anybody is known to exploit it, the published estimate, the fixing version, and the earliest deadline among its occurrences | The narrowing matches the report's text, and deciding many on less evidence than deciding one is backwards |
| It always needs a second person, whatever the outcome | One person answering hundreds in one act is the case a second pair of eyes exists for |
| The limit counts issues, 200 by default, with a ceiling on occurrences, 50,000 by default (REQ-27); both are counted over what the names resolve to | A reviewer reads issues; the ceiling guards the write |
| The limit follows what a reviewer reads: a new answer goes to a second person and takes the reviewer's limit; re-affirming answers takes 2,000 issues by default only where nothing in the act goes back to an approver; answers carried onto another line always go back | |
| The bound is reversibility: a promise to upgrade has none (`design-docs/triage-promises.md` § Promised work) | Nothing re-checks a decision, so one sentence over a thousand findings must stay a size a reviewer can follow. The next scan re-checks every row a promise names, and narrowing one makes the record false |
| Other acts keep a limit in rows, 2,000 by default: how many reports one ruling covers, how many occurrences one answer about one issue covers, and how many rows a screen acts on one request at a time | They bound a reading or a loop rather than a review |

The candidate list carries both numbers and both limits: how many issues the
narrowing holds, how many findings they sit at, how many issues one answer may
cover, and how many findings it may write. The findings are counted over the
whole narrowed set. A kernel issue sits at about 45 occurrences, so 2,000
occurrences is 44 issues; the 805 kernel candidates on a real image are five
answers at 200 issues.

### The narrowing record

Whatever narrows the set, such as a weakness class or a subsystem named in
advisory text, is a starting point for a person, never a selection the tool
asserts is right. No SBOM says whether a driver was compiled in, so the kernel
configuration or whatever supports it goes into the reasoning.

How the set was narrowed is recorded apart from the reasoning, twice: in the
proposer's words, and as something an approver can re-run. Narrowing is how a
candidate was found, and the reasoning is why the decision is true.

| Rule | Reason |
|---|---|
| The narrowing is re-run where the decision is written, and what it reached is stored beside how many were named | A decision reading "drivers this image does not build" over a set chosen by ticking everything otherwise looks honest. Equal counts say the decision is exactly the narrowing; far apart, the sentence does not describe the set |
| Re-run, never sent | A count sent with the request is the proposer's word twice |
| Read with the candidate list's visibility rule | The two counts must be of one population |
| It is evidence, and refuses nothing | Deciding about part of what a narrowing returns is legitimate; the approver sees that it happened |
| The proposer's own sentence is kept | It says what they meant |

### Decided occurrences

A selection covering an occurrence a live decision already covers is refused
whole by default, naming that decision (`design-docs/triage.md` § One live
decision per key). The proposer may ask for those occurrences to be left out.

| Rule | Reason |
|---|---|
| Skipping is asked for | Silent skipping covers less than was selected; refusing says which decision to read |
| What was skipped is returned: each occurrence, by the issue's name, with the decision standing there and how far it has got | A decision smaller than its selection is visible to its maker |
| An occurrence counts as decided under either key: a live decision at the versions, or a correction at any version | The unique index's question; an occurrence skipping keeps is one the index accepts |
| The bounds count what is written | A selection within them once skipped occurrences are left out is not refused |
| Every occurrence decided refuses the request, recording nothing | A decision with no rows is nothing to agree to |
| The approver sees the rows written; what was skipped is not recorded on the decision | The narrowing's two counts still compare the issues named with those the narrowing reaches |

## Rule-prepared decisions

A rule produces a saved filter and a prefilled outcome, justification and
reasoning. A named person submits it as their decision, and a second person
approves it (REQ-27).

| Rule | Reason |
|---|---|
| It is the saved filter, never a second object | A table of its own makes "the filter" and "the rule" two things pointing at each other |
| The reasoning is required where an outcome is | An empty prefill is a button proposing a dismissal that says nothing |
| Saving over a name takes the old prefill with it | The act decides what the name means now |
| It proposes nothing by itself, and the screen says so | Picking the filter fills the form; submitting is a person's act, and the record carries their name |
| A deferral is prepared as a length, never a date: required for a deferral, refused otherwise | No length fills a form that cannot be submitted, and a length on another outcome is read by nothing. `design-docs/interface.md` says how the length becomes a date |
| What a filter prepares passes the decision submission gate, called rather than restated: a recognized outcome, a reason exactly where the outcome takes one, and the markdown policy on the reasoning | A prefill the store refuses fails when somebody presses the button rather than when it was saved |
| A prefill cannot state that mitigations already exist | That reason asks what stops it in words, which a filter does not carry |
| How many filters one person keeps is capped by `saved.max-per-person`, which also bounds the list | Many acts of one row fill a table as one act of many does, and the panel reads every row on every open |
| A rule applies in every product | A filter is per person. A person still submits, a decision hiding risk still waits, and the form names the filter that prepared it |

A rule proposing a pending decision of its own leaves the approver as the only
judge and puts a configuration file where a name belongs in the record, which
matters on the day a dismissal proves wrong and somebody asks who made it.

## Decisions on a new branch

What a new line would inherit is shown before anything happens, and what moved
is chosen rather than taken (REQ-25).

| Group | Treatment |
|---|---|
| Already applies | Nothing to agree to |
| Covers nothing here | Nothing to apply to |
| Moved | A question |
| Postponed | A question carrying its own history |
| Run out at an occurrence the new line holds | Counted apart, never carried; the finding there is unanswered |
| A promised upgrade whose version moved | Counted apart, never carried; planned again from its component |

Reasoning travels and conclusions do not: everything carried arrives as a
decision waiting for a second person, because the version moved, and starting
from a blank page teaches people to stop writing reasoning.

| Rule | Reason |
|---|---|
| Only what was offered may be carried; naming a decision the preview classed as already applying or covering nothing is refused | A caller with the wrong set hears so |
| The occurrence is read from the new line, never copied from the old decision | The versions are the key and the thing that moved |
| Both versions come from one finding: where the new line holds two open findings at the occurrence, the first in the order both sort as text, in the preview and the act | A pair drawn half from each is a key no finding holds |
| A dated decision carries its date unchanged; the total a deferral has run for is shown beside it | Moving a date forward makes the decision for the person, and a promise without its date is refused on every path |
| A decision whose date has gone by is not offered | Carried, it is finished the moment it lands |
| A promised upgrade is not carried | Carried onto one occurrence it writes neither the components covered nor what each release waits on; planned from the component, naming the new line, it writes both |
| What is carried is checked as anything written: the occurrence records whether the new line is a tag, and who may write is asked at the new line's visibility | A dated decision carried onto a release built once is refused as when proposed there |
| An occurrence the carrier may not argue about on the new line is neither offered nor counted | Its visibility there may be stricter, and a count of such occurrences says what the new line holds |
| Bounded, and written in one transaction | Half landing is a line nobody can tell from one chosen that way |

## Limits

| Limit | Detail |
|---|---|
| A bulk act is bounded by what it writes, never by what was asked | One named issue expands into many occurrences (REQ-27) |
