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

| Part | What it is | What the person does |
|---|---|---|
| Occurrences in this build | One component under several consumers, the same code | Nothing; one decision covers them |
| Other builds already matching | Variants and branches with identical versions and chains | Nothing; matched by lookup |
| Builds where the code differs | The same issue and occurrence at another version | Ticks each build, unticked by default: a component may be used in a later release and not an earlier one |

| Rule | Reason |
|---|---|
| One decision covers every occurrence by default (REQ-26); unticking one leaves it open, and nothing is asked about it | Silence about an occurrence is not a decision |
| The answer says how many findings it covers and how many distinct versions; more than one is a package shipped twice under one consumer | Otherwise somebody learns later they answered for sixty-two |
| Covering many occurrences alone needs no second person | Otherwise people make narrow decisions saying less |
| One action writes a record per build, keyed to its own versions | A dismissal carried onto an older branch lapses when that branch moves |
| A differing build is judged by the key's expression, one entry per version it ships | |
| Builds already covered are counted, never offered | |
| Only occurrences nothing stands at are written; a build wholly reached by lookup records nothing, without error | |
| One request, one transaction, one decision | |
| Bounded on the occurrences resolved, never the builds named (REQ-27) | |
| An approval names the reach: the three parts are shown first, and what was covered is counted then and kept as one number | Coverage moves on its own, and consent is a different question |
| Grouping is presentation (REQ-17): a grouped action writes a record per occurrence | A stored group describes a build gone in a scan or two |
| A list hiding something says so, with the count (REQ-30) | |
| Hidden findings are grouped by layer: a build's suppression, a decision here, below the minimum severity (REQ-25); every kind of variant follows one model | One flat list reads a build's claim as our decision |

## Bulk decisions

One action records one decision, with one outcome, justification, reasoning and
approval, against a set of issues at one component, as a row per issue and per
occurrence, each expiring on its own. The case is a kernel carrying thousands of
issues in drivers a given image never builds.

| Rule | Reason |
|---|---|
| A row per issue and per occurrence | One occurrence would silence one consumer and report covering all |
| The component names a fold, never a binary package | One vim row is four packages at sixty-one occurrences |
| The fold is read as a short identifier list, never a join | The page reads off the covering index; a third join costs 0.35 s against 0.04 s on the kernel, 222,435 of 272,539 open rows |
| Occurrences are resolved from the findings inside the writing transaction | |
| Its size is said before it is submitted (REQ-27) | |
| It may span pages; selecting all the narrowing matches fetches the rest | |
| Every single-decision outcome is offered, deferred and already fixed included | They are the bulk cases: a scheduled bump and a backport |
| Exploited or critical issues can be excluded first | |
| A candidate shows what a finding row shows: the issue's own text, exploitation, the published estimate, the fixing version, the earliest deadline | The narrowing matches report text |
| It always needs a second person | |
| Limited to 200 issues by default, with a ceiling of 50,000 occurrences, both counted over what names resolve to (REQ-27) | A reviewer reads issues; the ceiling guards the write |
| Re-affirming answers takes 2,000 issues by default only where nothing in the act goes back to an approver; new answers and answers carried to another line take the reviewer's limit | The limit follows what a reviewer reads |
| A promise to upgrade has no limit (`design-docs/triage-promises.md` § Promised work) | The next scan re-checks it, and a capped promise records a false bump |
| Other acts take 2,000 rows by default: reports one ruling covers, occurrences one answer about one issue covers, rows a screen acts on one request at a time | They bound a loop, not a review |

The candidate list carries the issues and findings the narrowing holds and both
limits, findings counted over the whole set. A kernel issue sits at about 45
occurrences, so 2,000 occurrences is 44 issues; 805 kernel candidates on a real
image are five answers at 200 issues.

### The narrowing record

A narrowing, such as a weakness class or a subsystem in advisory text, is a
starting point a person signs for; the kernel configuration or other support
goes in the reasoning. It is recorded apart from the reasoning, in the
proposer's words and as something an approver can re-run.

| Rule | Reason |
|---|---|
| Re-run where the decision is written, storing what it reached beside how many were named | Far-apart counts show the sentence does not describe the set |
| Re-run, never sent | A sent count is the proposer's word twice |
| Read with the candidate list's visibility rule | Both counts must be of one population |
| It refuses nothing | Deciding part of a narrowing is legitimate |
| The proposer's sentence is kept | |

### Decided occurrences

A selection reaching an occurrence a live decision covers is refused whole,
naming that decision (`design-docs/triage.md` § One live decision per key),
unless the proposer asks to skip them.

| Rule | Reason |
|---|---|
| Skipping is asked for | Silent skipping covers less than selected |
| Each skipped occurrence is returned, by issue name, with the decision standing there and its state | |
| Decided means either key: a live decision at the versions, or a correction at any | The unique index's question |
| The bounds count what is written | |
| Every occurrence decided refuses the request, recording nothing | |
| The approver sees the rows written; skips are not recorded on the decision | The narrowing counts still compare issues named and reached |

## Rule-prepared decisions

A rule is a saved filter with a prefilled outcome, justification and reasoning.
A named person submits it as their decision, and a second person approves it
(REQ-27).

| Rule | Reason |
|---|---|
| It is the saved filter, not a second object | |
| The reasoning is required where an outcome is | An empty prefill proposes a dismissal saying nothing |
| Saving over a name takes the old prefill with it | |
| It proposes nothing itself, and the screen says so; the record carries the submitter's name and the form names the filter | |
| A deferral is prepared as a length, required for a deferral and refused otherwise (`design-docs/interface-filters.md` § Saved filters turns it into a date) | |
| A prefill passes the decision submission gate, called rather than restated: a recognized outcome, a reason exactly where one is taken, the markdown policy | A refusal lands at saving, not at submitting |
| A prefill cannot state that mitigations already exist | That reason needs words a filter does not carry |
| `saved.max-per-person` caps one person's filters and bounds the list | The panel reads every row on every open |
| A rule applies in every product | A filter is per person |

A rule proposing a decision of its own would leave the approver the only judge
and record a configuration file where a name belongs.

## Decisions on a new branch

What a new line would inherit is shown first, and what moved is chosen (REQ-25).

| Group | Treatment |
|---|---|
| Already applies | Nothing to agree to |
| Covers nothing here | Nothing to apply to |
| Moved | A question |
| Postponed | A question with its history |
| Run out at an occurrence the line holds | Counted, never carried |
| A promised upgrade whose version moved | Counted, never carried; planned again from its component |

Everything carried arrives as a decision waiting for a second person, because
the version moved; the reasoning travels so nobody starts from a blank page.

| Rule | Reason |
|---|---|
| Only what was offered may be carried; naming another is refused | |
| The occurrence is read from the new line | The versions moved |
| Both versions come from one finding: of two open at the occurrence, the first as both sort as text, in preview and act | A half-and-half pair is a key no finding holds |
| A dated decision keeps its date, and a deferral shows the total it has run | Moving a date forward decides for the person |
| A decision past its date is not offered | It would finish on landing |
| A promised upgrade is not carried | Carried onto one occurrence it records neither its components nor what releases wait on |
| What is carried is checked as anything written, at the new line's visibility, a tag refusing dates | |
| An occurrence the carrier may not argue about on the new line is neither offered nor counted | The count would disclose |
| Bounded, and one transaction | |

## Limits

| Limit | Detail |
|---|---|
| Nothing carried across builds is withheld for sitting past the named fix | That needs a version ordering per ecosystem, which exists only for some; what is recorded instead is a version that moved with the issue still open |
