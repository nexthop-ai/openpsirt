# Triage

What a decision about a finding is keyed on, the outcomes it takes, and when it
stops applying. Text rules are in `design-docs/text.md`; the reports these
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
it was made in is outside the key, so a later release inherits by lookup and a
variant inherits exactly where its chain matches.

| Rule | Reason |
|---|---|
| The builds a decision was made on are recorded beside it, outside the key: the build on screen, and every build chosen on the reach sheet. A build reached by lookup is never recorded | An advisory flags a release of a variant its covering decision was not made on, for whoever prepares it to mark affected where the code differs (`design-docs/remediation.md` § The CSAF document) |
| The two version columns are bounded in characters, and a version that does not fit is refused, never shortened | The match is an index lookup on every screen. The reference producer's longest version is 49 characters over 6,845 components |
| A version nobody stated and an empty version differ; two absences match each other only | |

`design-docs/triage-decisions.md` § The decision and its rows says which builds
each act records.

## Expiry

A decision is stored under the versions it was made about, and an occurrence
asks under the versions it has now; when the code moves they stop matching.
Nothing sweeps and nothing runs on a timer. Identity is structural and expiry
version-based, and neither reaches into the other, or a bump at the top of a
build invalidates a decision about a leaf.

| Rule | Reason |
|---|---|
| Only the upstream version counts: `10.5.4` to `10.6` lapses a decision, a packaging revision does not | A rebuild is not reasoning becoming wrong |
| A version change mid-chain has no rule of its own | It moves the direct consumer of something, lapsing that decision, or it does not |
| A rebuilt container image lapses nothing beneath it; a package inside it that moves lapses its own decision | An image stores no version (`design-docs/data-model.md` § Container images) |
| A carried patch lapses nothing, so under heavy patching a decision may never be re-examined | A patch moves no version this can see |
| A decision's age travels with it everywhere it appears | The compensating control for the line above |
| A deferral runs out on a date, never a version, and its finding returns marked deferred | A bump does not change priority, nor a calendar applicability |
| A wrong match runs out on neither (§ Corrections) | |
| A decision a severity bears on also lapses when its issue is rated worse (REQ-25), by a sweep (`design-docs/triage-lapse.md` § Lapse marking) | Nothing matched changes |
| A lapsed decision is found by the structural half of its key | Its reasoning is offered to whoever decides again |

## Outcomes

The outcomes about a vulnerability; a code finding takes its own
(`design-docs/analysis.md` § Code finding triage).

| Outcome | Means |
|---|---|
| Affected | It applies, and goes to remediation |
| Not applicable | It does not affect this product here |
| Wrong match | The scanner matched something that is not here |
| Deferred | It affects us, and is not worked on until a date |
| Will not fix | It affects us, and will not be addressed |
| Already fixed | The version here carries the fix, which nothing here can see |
| Upgrade needed | A component is being upgraded, by a date |
| Patch needed | One issue is being backported, by a date |

| Rule | Reason |
|---|---|
| Deferred is an outcome of its own | Otherwise "yes, but not now" is recorded as one of the others |
| A deferral is never published as not-affected; where it publishes, it is affected. The VEX document takes none, and silence there reads as affected (`design-docs/remediation.md` § The VEX document) | Deferring is internal scheduling, not an assessment |
| Not applicable and a wrong match require a reason, from the exchange format's vocabulary | The reason is the decision; a private vocabulary needs a mapping nobody maintains |

### Already fixed

For a distribution's package (REQ-23), whose backported patch moves no upstream
version, so a scanner fires on it fixed or not. Computed resolution cannot stand
in, because the scan reports it at every revision.

| Rule | Reason |
|---|---|
| It requires the package version the fix arrived in | It asserts a fact that hides risk |
| The version is never compared with what ships | That needs an ordering per ecosystem |
| It expires on the upstream version, never the packaging revision | A later revision still carries the patch |
| Published, it is fixed | |
| It is apart from not applicable, as the exchange format keeps them | The code is present and was affected |
| It is the word a build's suppressions use on the way in, `fixed` | |

### Mitigations

Two outcomes carry a mitigation, and no other may.

| Outcome | Mitigation |
|---|---|
| Not applicable because inline mitigations already exist (`inline_mitigations_already_exist`) | Required: what stops it, such as the rule, the setting, or the service not exposed |
| Will not fix | Optional. A standing property such as a protocol fixed for compatibility often has an answer and often none |

| Rule | Reason |
|---|---|
| Removing a mitigation expires nothing | It is configuration, which moves no version and which nothing here watches; named, the control is checkable |
| A will-not-fix is published only where it fills the mitigation | No scan or advisory ever closes such a flaw, and the mitigation is what makes the published status worth reading |

### Outcomes on a tag

A tag never moves, so an outcome on it may not carry a date.

| Allowed | Refused |
|---|---|
| Affected, not applicable, wrong match, will not fix, already fixed | Deferred, upgrade needed, patch needed |

| Rule | Reason |
|---|---|
| The check asks whether the outcome stores a date | A deferral's review date is as meaningless on a tag as a promise's |
| Whether an occurrence sits on a tag is read from the finding, as its visibility is, on every route that decides, re-affirmation included | |

### Dates still to come

A deferral's date and a promise's date are refused at or before the moment the
decision is made.

| Without the refusal | Effect |
|---|---|
| A deferral until a date gone | Holds the occurrence's live key, suppresses nothing, and arrives in the queue already run out |
| A promise due on a date gone | A past date is never past the deadline, so the promise skips the gate and hides the finding on one signature |

| Rule | Reason |
|---|---|
| The refusal names the UTC day the date falls on, whatever offset the request wrote and whatever zone the server is in | It is the day the interface shows (`design-docs/interface.md`) |
| Checked where every write path inherits it | Acts outside the ordinary entry point also write decisions |

## Corrections

A correction is a wrong match (REQ-23): the one decision about identity rather
than risk (REQ-25). The case is a distribution package matching a database's
naming for an unrelated project at every point release.

| Rule | Reason |
|---|---|
| No version expires it: keyed on product, issue and occurrence without versions, and passed over by the lapse sweep | A bump does not make a wrong match right |
| A second person agrees, always | It hides risk with nothing scheduled to look again |
| Its reason is one of the two saying something is not there: what the inventory named is not in what ships, or what ships is not the code the issue is about | The other three describe reachability or controls, which a bump changes |
| It stands beside whatever was decided at the occurrence, and answers the finding | A decision about risk at an occurrence the match does not describe is about nothing |
| Withdrawing is the one way it ends | |
| Published, it is not-affected with its reason | |
| Curated correction data published elsewhere is not read | Its origin, regeneration and terms are unanswered |

### The standing set

Corrections in force are read from the audit log, filtered by the outcome and by
what applies now (`design-docs/analytics.md`). What applies now differs from
what was approved, since an approved decision lapses when the code moves.

## One live decision per key

Proposing where a live decision stands is refused; the answer is revising it.

| Rule | Reason |
|---|---|
| Only a live decision holds the key: a withdrawn or lapsed one releases it at once | Otherwise one lapse walls an occurrence off |
| The key includes the versions, so decisions about two versions both stand | |
| Enforced by a unique index, the key set to null once a decision is not live | Nulls do not collide on any of the four engines; a read-then-write check lets two simultaneous proposals through, and a test drives that case |
| A rating of an issue holds the same, keyed on the issue from proposal to withdrawal | Six proposals at once leave one; without the constraint all six land |
| The key names the issue a decision is read as; a merge settles the keys and withdraws the rating with less standing, naming the merge (`design-docs/findings-issues.md` § Merged issues) | |
| Revising keeps the old words readable, takes back their approval, returns the decision to the queue, and records the new author | Two decisions would be contradictory and unmarked, one silently governing |

## Statement scope

Whom a statement published from a decision holds for: anybody shipping the
component at that version, or this product's own build.
`design-docs/publishing.md` holds what it decides.

| Rule | Reason |
|---|---|
| A property of the decision, agreed by the second person | It is published in the deployment's name |
| Stated when proposed or not at all; empty is ordinary, and the reason decides. Changing it is proposing again | |
| Refused on a deferral, and not offered on a bulk answer | |
| Kept by a re-affirmation, a carried decision and set-aside rows; an extension keeps its source's | |
| Read back as stated and as it holds | |

## Not built

| Item | Detail |
|---|---|
| Narrowing a decision over many occurrences to a chosen set | An interface question; the count already exists |
| A refusal of a long deferral | Absent by design: the cumulative threshold is the refusal (`design-docs/triage-approval.md` § The deferral threshold), and `/v1/deferrals/repeated` reports the pattern |

## Limits

| Limit | Detail |
|---|---|
| Every name in a request is resolved against what was scanned, never taken as given | A caller naming an occurrence would choose which decisions apply; the keyed versions come from the rows |
| An issue is named by any identifier it is known under (REQ-18) | |
