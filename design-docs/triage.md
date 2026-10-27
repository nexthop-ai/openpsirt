# Triage

What a decision about a finding is keyed on, the outcomes it takes, and when it
stops applying. The text rules are in `design-docs/text.md`; the reports these
decisions feed are in `design-docs/analytics.md`.

Satisfies REQ-18, REQ-23, REQ-25.

## Contents

- [Decision identity](#decision-identity)
- [Expiry](#expiry)
- [Outcomes](#outcomes)
- [Corrections](#corrections)
- [One live decision per key](#one-live-decision-per-key)
- [Statement scope](#statement-scope)
- [Not built](#not-built)
- [Limits](#limits)

## Decision identity

A decision at an occurrence is keyed on the product, the issue, the occurrence,
and the upstream versions of the component and of what pulls it in. The release
it was made in is outside the key.

| Rule | Reason |
|---|---|
| A later release inherits by lookup, never by copy | Nothing to synchronize, so nothing drifts |
| A variant inherits exactly where its code matches | A variant whose chain differs computes a different key |
| The builds a decision was made on are recorded beside it, outside the key: the build on screen when it was proposed, and every build chosen beside it on the reach sheet | A build reached by lookup is never recorded, because telling it apart from the builds it was made on is what the record is for. An advisory flags a release of a variant its covering decision was not made on, and whoever prepares one marks it affected where the code differs (`design-docs/remediation.md` § The CSAF document) |
| The two version columns are bounded, in characters as the columns hold them | The match is an index lookup on every screen asking whether anything stands here. The reference producer's real output: 6,845 components, the longest version 49 characters |
| A version that does not fit is refused, never shortened | Shortened, the decision is keyed on something the finding does not hold |
| A version nobody stated and an empty version differ; two absences match each other and nothing else | Equal, a decision about a component with no known version would stand over one whose version is blank |

`design-docs/triage-decisions.md` § The decision and its rows says which builds
each act records.

## Expiry

A decision is stored under the versions it was made about, and an occurrence
asks under the versions it has now. When the code moves the two stop matching.
Nothing sweeps and nothing runs on a timer.

Identity is structural and expiry is version-based, and neither reaches into the
other: overlapped, a bump at the top of a build invalidates a decision about a
leaf.

| Rule | Reason |
|---|---|
| Only the upstream version counts: `10.5.4` to `10.6` lapses a decision, a packaging revision does not | A shipped package is rebuilt constantly, and a rebuild is not somebody's reasoning becoming wrong |
| A version change mid-chain has no rule of its own | It changes the direct consumer of something, which lapses that decision, or it does not |
| A rebuilt container image lapses nothing beneath it; a package inside one that moves lapses its own decision | An image is identified by its name and stores no version (`design-docs/data-model.md` § Container images) |
| A carried patch lapses nothing | A producer fixing by patching moves no version this can see, so under heavy patching a decision may never be re-examined automatically |
| A decision's age travels with it everywhere it appears | The compensating control for the line above: an eight-year-old decision looks like one |
| A deferral runs out on a date, never on a version, and its finding returns to the queue marked deferred | A bump does not change a decision about priority, and a calendar does not change one about applicability |
| A wrong match runs out on neither | It is a decision about identity (§ Corrections) |
| A decision a severity bears on also lapses when its issue is rated worse (REQ-25) | Nothing matched changes, so it is swept for: `design-docs/triage-lapse.md` § Lapse marking |
| A lapsed decision is found by the structural half of its key alone | Its reasoning is offered back to whoever decides again |

## Outcomes

The outcomes about a vulnerability. A code finding takes its own
(`design-docs/analysis.md` § Code finding triage).

| Outcome | Means |
|---|---|
| Affected | It applies, and goes to remediation |
| Not applicable | It does not affect this product here |
| Wrong match | The scanner matched this against something that is not here |
| Deferred | It affects us, and is not worked on until a date |
| Will not fix | It affects us, and will not be addressed |
| Already fixed | The version shipping here carries the fix, and nothing here can see that it does |
| Upgrade needed | A component is being upgraded, by a date |
| Patch needed | One issue is being backported, by a date |

| Rule | Reason |
|---|---|
| Deferred is an outcome of its own | With only "affects us" and "does not", "yes, but not now" is recorded as one of the two, and no report tells them apart |
| A deferral is never published as not-affected; where it publishes, it is affected. The VEX document takes none, so it is absent there, and silence in that format reads as affected (`design-docs/remediation.md` § The VEX document) | Deferring is internal scheduling. Published as not-affected it claims an assessment nobody made |
| Not applicable and a wrong match require a reason | Each of those decisions is which recognized reason applies |
| The reason vocabulary is the exchange format's | A private one needs a mapping nobody maintains, and loses meaning at every step |

### Already fixed

For a distribution's package (REQ-23). A backported patch moves no upstream
version, so a scanner comparing an identifier against an upstream range fires on
a fixed package and an unfixed one alike.

| Rule | Reason |
|---|---|
| It requires the package version the fix arrived in, as a deferral requires a date | Alone among the outcomes it asserts a fact, and an outcome hiding risk on a fact is the one most worth care |
| The version is never compared with what ships | That needs an ordering per ecosystem |
| It expires on the upstream version, never the packaging revision | A later revision of the same upstream version still carries the patch |
| Published, it is fixed | |
| It is apart from not applicable | The code is present and was affected, and an audit of "the vulnerable code is absent" would find it there. The exchange format keeps the two apart the same way |
| Computed resolution does not stand in for it | Closure follows what a scan reports, and the scan reports it at every later revision |
| It is the word a build's suppressions already use on the way in, `fixed` | It fills the case where nobody upstream can make the claim |

### Mitigations

Two outcomes carry a mitigation, and no other may: a decision about priority
does not say something is handled.

| Outcome | Mitigation |
|---|---|
| Not applicable, because inline mitigations already exist (`inline_mitigations_already_exist`) | Required: what actually stops it, such as the rule, the setting, or the service that is not exposed. The mitigation is the decision |
| Will not fix | Optional. A standing property of a shipped feature, such as a protocol that cannot change without breaking compatibility, often has a real answer and often has none, and a false one is worse than none |

| Rule | Reason |
|---|---|
| A mitigation dismissal is about configuration, which nothing here watches, so removing the mitigation expires nothing | Every other not-applicable reason is about code, and code is what lapses a decision. Naming the control makes the decision checkable, and it is the justification an auditor asks about first |
| A will-not-fix is published only where it fills the mitigation | Nothing closes such a flaw: no scan, because the code does not move, and no advisory, because it is no event. The published status says the flaw stays, and the mitigation field is what makes that worth publishing |

### Outcomes on a tag

A tag never moves. An outcome may state a fact about it and may not carry a
date.

| Allowed | Refused |
|---|---|
| Affected, not applicable, wrong match, will not fix, already fixed | Deferred, upgrade needed, patch needed |

| Rule | Reason |
|---|---|
| The check asks whether the outcome stores a date | The refused three are exactly those that do. A deferral's date is a review date rather than a commitment, and is as meaningless on a release that will not move |
| Whether an occurrence sits on a tag is read from the finding, as its visibility is | What may be said about an occurrence is a fact about it. Every route deciding at an occurrence, re-affirmation included, builds it from the finding in one spelling, so the refusal holds on each |

### Dates still to come

A deferral's date and a promise's date are refused at or before the moment the
decision is made.

| Without the refusal | Effect |
|---|---|
| A deferral until a date gone | Takes the occurrence's live key so nobody else decides there, suppresses nothing, and arrives in the queue already run out |
| Promised work due on a date gone | The gate asks whether the date is past the deadline the work already has, which a past date never is, so the promise stands on one signature and hides the finding for good |

| Rule | Reason |
|---|---|
| The refusal names the date as the UTC day it falls on, whatever offset the request wrote and whatever zone the server's clock is in | It is the day the interface shows for that moment (`design-docs/interface.md`) |
| Checked where every write path inherits it | Acts building a decision outside the ordinary entry point otherwise write decisions nothing checked |

## Corrections

A correction says the scanner matched this against something it is not. Its
outcome is wrong match (REQ-23), the one decision about identity rather than
risk (REQ-25). The case is a distribution-heavy inventory, where a package name
matching a database's naming for an unrelated project recurs at every point
release.

| Rule | Reason |
|---|---|
| No version expires it: it is keyed on the product, the issue and the occurrence without the versions, and the lapse sweep passes over it | A bump does not make a wrong match right |
| A second person agrees, always | It hides risk with nothing scheduled to look again. The control attaches to the effect: a component that never appears again, with nothing saying it was suppressed |
| Its reason is one of the two saying something is not there: what the inventory named is not in what ships, or what ships is not the code the issue is about | The other three describe how the code is reached or what stops it, which a bump changes; carried past every bump, each would be a decision about risk nothing re-examines |
| It stands beside whatever was decided at the occurrence, and is the answer to the finding | A decision about risk at an occurrence the match does not describe is about something that is not there |
| Withdrawing is the one way it ends | So the set in force has to be readable (§ The standing set) |
| Published, it is not-affected, with the reason it states | Both reasons are the exchange format's own |
| Curated correction data published elsewhere is not read | Where such a file comes from, what regenerates it, and under what terms are unanswered |

### The standing set

Corrections in force are read from the audit log, filtered by the outcome and by
what applies now. `design-docs/analytics.md` holds the audit log and the one other
question asked of it this way.

What applies now differs from what was approved: an approved decision lapses
when the code moves, so a list of approved decisions is a list of what was once
agreed.

## One live decision per key

Proposing where a decision stands is answered with revising it; a second beside
it is refused.

| Rule | Reason |
|---|---|
| Only a live decision holds the key: a withdrawn or lapsed one releases the occurrence the moment it stops applying | Otherwise one lapse walls an occurrence off for good |
| The key is the combination with the versions | A decision about one version and one about the next are two decisions, and both stand |
| Enforced by the database: the key is held while a decision is live and set to null after, under a unique index | Null values do not collide in a unique index on any of the four engines. A read-then-write check is the shape two simultaneous proposals both walk through, and a test drives that case |
| A rating of an issue holds the same: keyed on the issue, held from the moment it is proposed, released when it is withdrawn | Six proposals at once leave one standing; with the constraint removed, all six land. A merge of two issues each holding one in a product withdraws the one with less standing, naming the merge rather than a person (`design-docs/findings-issues.md` § Merged issues) |
| The key names the issue a decision is read as | A decision under an issue merged into another holds its key under the other, and a new decision is filed under the issue that stands. `design-docs/findings-issues.md` § Merged issues says how a merge settles the keys |
| Revising keeps the old words readable, takes back the approval given for them, returns the decision to the queue, and records who wrote the new version | Two people disagreeing produce one legible argument. Two decisions would stand unmarked as contradictory: agreed-beats-waiting then newest-wins picks one, and approving both leaves one governing silently |

## Statement scope

Whom a statement published from a decision holds for: anybody shipping the
component at that version, or this product's own build.
`design-docs/publishing.md` holds what it decides in a published document and
what the reason decides where a decision states none.

| Rule | Reason |
|---|---|
| A stated property of the decision, beside its outcome and reason | It is published in the deployment's name, so it is part of what the second person agrees to |
| Stated when a decision is proposed, or not at all; empty is the ordinary case, and the reason decides | Changing it is proposing again, as changing the reason is |
| Refused on a deferral | A deferral says nothing about the component a reader could take |
| Carried with the argument: a re-affirmation, a decision carried to another line, and the rows an approver sets aside keep it; an extension keeps its source's | |
| Not offered on a bulk answer | One sentence answering many issues states the reason, and the reason decides |
| Read back as stated and as it holds | A decision answers with the scope it states, and whom its statement holds for either way |

## Not built

| Item | Detail |
|---|---|
| Narrowing a decision over many occurrences to a chosen set | An interface question. The count exists, which makes the choice informed when it arrives |
| A refusal of a deferral for being long | Absent by design: the cumulative threshold is the whole refusal (`design-docs/triage-approval.md` § The deferral threshold). The pattern is reported at `/v1/deferrals/repeated`, because one item deferred three times is a decision and forty are a policy nobody wrote |

## Limits

| Limit | Detail |
|---|---|
| The names in a request are resolved against what was scanned, never taken as given | A caller naming an occurrence freely would choose which decisions apply where; the versions a decision is keyed on come from the rows for the same reason |
| An issue is named by any identifier it is known under (REQ-18) | A national identifier from an advisory and a database's own identifier from a report ask about one thing |
