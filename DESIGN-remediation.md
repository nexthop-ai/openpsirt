# Remediation

Declared fix intent, how the tool determines whether it arrived, and the
documents generated from what was decided.

Satisfies REQ-15, REQ-19, REQ-33, REQ-34, REQ-35, REQ-36, REQ-39.

Neighboring pieces: the escalation view, per-item time remaining and the SLA
compliance rate are in `DESIGN-reporting.md`; the assignment model is in
`DESIGN-access.md`, which defines the party a thing is assigned to.

## Contents

- [Declaration, not completion](#declaration-not-completion)
- [The unit](#the-unit)
- [Resolution](#resolution)
- [Deadlines](#deadlines)
- [Pending upgrades](#pending-upgrades)
- [Promise states](#promise-states)
- [Build-declared suppressions](#build-declared-suppressions)
- [External links](#external-links)
- [Publication](#publication)
- [The CSAF document](#the-csaf-document)
- [The VEX document](#the-vex-document)
- [Issuance records](#issuance-records)
- [Publisher identity](#publisher-identity)
- [Not built](#not-built)
- [Limits](#limits)

## Declaration, not completion

A fix is declared and never completed. A judgment promising work states which
releases it is for; whether the fix arrived is answered by the next scan of each
of those releases (REQ-35).

The stored row is the declaration and nothing else: which build, which fold, who
said so, and when. There is no state column, no completed-at, and nothing to
move along.

**A declaration arrives with the judgment that argued for it**, from the two
outcomes that promise work — a bump, recorded against the component, and a
backport, recorded against the issue. There is no way to record where a fix will
land without saying what was decided: bare intent carried no version, no date
and no reasoning, so nothing could lapse and nobody was asked to agree to it,
which made it a promise in the shape of a record and not in its effect.

The alternative — planned, in progress, done, moved by a person — is how every
tracker works, and is wrong here because independent evidence already exists. A
scan of the release either finds the issue or does not. A second record of the
same fact is one somebody has to keep true, and the way that fails is the tool
reporting a fix that shipped in nobody's release.

A flaw recorded by hand is the exception (REQ-19). No scan reports one, so there
is no second opinion to check a declaration against, and refusing the
declaration leaves the finding open forever. That class is closed by a person,
with who, when and why on the record. `DESIGN-findings.md` carries the shape.

## The unit

A commitment is one build moving one fold: a source package, at the version it
was built at, going to another version. That is the piece of work somebody
actually does, and it is one row.

A release is named by its stream and its variant together, never by one of them:
the same branch built two ways is two builds, and a plan naming only the branch
would claim a fix for hardware nobody built for.

Acting on the plan acts on the product, not on the build in the path. A route
names a finding so a screen has somewhere to link to; what is planned belongs to
the work that finding is part of.

### Coverage by matching

A finding is covered when its component folds to the commitment's key in the
commitment's build. **Nothing is written onto findings.**

| Consequence | |
|---|---|
| Changing the version a release is moving to is one row | It was keyed per issue *and* per component *and* per target version, so a change meant rewriting every row of it |
| An issue published tonight is covered by this morning's commitment | With nobody acting. Under the old key it was not covered until somebody declared it too |
| A sibling package moves with its source | curl, libcurl4t64 and libcurl3t64 are one bump, so a commitment recorded against one covers all of them |
| No version comparison is involved | An upgrade covers everything open on the fold rather than only what records this version as its fix. Deciding otherwise needs a per-ecosystem ordering nothing here has (REQ-21) |

A build has one commitment per fold, enforced by the database rather than by a
check somebody remembers. A release moves a package to one version; two rows
saying otherwise is a plan a coordinator cannot read.

### Moving a commitment

| Where it came from | How it changes |
|---|---|
| A judgment somebody agreed to | Through the act that revises the claim, which withdraws every agreement on it and returns its rows to the queue. A reason is required, and the revisions are where what was promised in October survives being changed in November |
| Intent nobody argued for | The row is edited |

Changing the version or the date under a standing agreement is refused, naming
the claim to revise. An approver agreed to a version by a date; rewriting either
half quietly would leave the agreement standing over a promise nobody read,
which is the failure REQ-28 exists to prevent.

| Rule | |
|---|---|
| **The gate is worked out again** | Moving the date moves the thing the gate is about. Withdrawing the agreements and leaving the rows recorded as needing nobody put a promise first made inside the deadline back in force at any later date somebody chose — in force, suppressing what it covered, and listed in no queue |
| It is measured over what the claim covers now | The builds come from the commitments the claim wrote and the places from its own rows, read inside the transaction that writes. A deadline moves when the policy or the rating moves, so the one it was made against is not the one it is judged by |
| A date already past is refused | It says the work will have happened before now |
| The reasoning goes through the text policy | Every path that stores typed text runs it before storing, and this one reached the write through an inner act that did not |

## Resolution

An issue is resolved when every build somebody chose is clear. Progress is
readable at any point: two of three clear, one outstanding (REQ-35).

Worked out from the same list every time it is asked for. Nothing stores it,
nothing refreshes it, and nothing has to be invalidated when a scan closes a
finding.

## Deadlines

There are no per-item due dates. A deadline comes from how urgent the finding is
(REQ-33). Moving one is a deferral, which carries a reason and an approval
threshold, and the deferral date becomes the effective target. Deferred items are
reported apart from plainly overdue ones. **A plan says where, not when.**

A finding with no deadline states which of exactly three reasons applies:

| Reason | Precedence |
|---|---|
| Below the line its product triages at | The narrowest statement about this finding, so it is the one stated |
| **Its release is a tag, so it cannot change** | Above end-of-life, being the more fundamental statement: a supported tag is as unfixable as a retired one |
| Its release is past end-of-life (REQ-15) | |

There is no fourth reason, because a deadline is worked out at ingest for
everything else. Left blank, the column reads as missing data on the one screen
whose purpose is noticing what is running out.

What has no deadline is absent from every figure built on one, which is the
point and also the gap: nothing overdue, nothing due soon, and nothing in the
compliance rate. Two of the three reasons already have somewhere to be seen —
the line is stated wherever a list hides something, and a tag's findings are
read at the release. The third does not, so releases out of support are a report
of their own; `DESIGN-reporting.md` holds it.

A tag was built once and is what somebody received. No work will land in it
whatever a date says, so a deadline on one was unmeetable the moment it was
written. Measured on the demo before this rule: all 26 open findings on its one
tag carried a deadline, every one of them unmeetable by construction. Real
deployments accumulate tags while branches do not, so that side grows — and it
inflates every overdue count, the compliance rate among them.

The reason is derived rather than stored, and derived where the triage line is
applied, so the two cannot disagree.

## Pending upgrades

The fix-bundle query inverted (REQ-35). A triager reads a bump and the issues it
closes, in the findings list's by-bump view; a coordinator reads a build and the
bumps it is waiting on, here. One query read from either end, and both ends are
drawn.

Both ends key their rows on the fold, so a bump reads the same from either
direction.

The version in hand and the version being moved to are both stored with the
commitment. They are read off the findings that are still open, and landing the
bump closes them — so a plan deriving them went blank on a bump exactly as the
bump succeeded.

What each row reports is what is still open under it, counted from the findings
rather than from anything written down: the distinct issues the bump would close
here, and how many places those sit at. Nothing is declared done by hand — a
build is clear when it stops holding them.

## Promise states

Three states, derived on every read and set by nobody.

| State | Condition |
|---|---|
| Landed | Nothing left open under it here, which the scans say |
| Lapsed | The date past with work outstanding |
| Planned | Everything else |

| Rule | Reason |
|---|---|
| The date is on the commitment, and the claim that argued for it is a citation | What somebody decided and what a release is waiting on are one fact. Changing it goes through the claim, so the two cannot come to disagree |
| There is no "replanned" | Re-promising writes a new date and the standing promise is the one read. A state nothing can distinguish from another is a word rather than a fact |
| A lapsed promise returns the upgrade, not its findings | One item, to whoever is carrying it — reported as a party only where one party holds all of what is still open under it. Answering the findings again one at a time is what the bulk promise was made instead of |
| A finding returns on its own only when the package moved and it did not close | A decision is keyed on the upstream version it was made against, so the existing key distinguishes "the plan was wrong about specifics" from "the plan did not happen" |

Stored rather than derived, these would be a third opinion capable of being wrong
about both the scans and the calendar.

## Build-declared suppressions

What a build says it deals with itself is readable as a history rather than a
list of what is true tonight. A carried patch is the only way a backport is
visible here — the fix is in the package, the version has not moved, and no
comparison of versions finds one — so the build declaring it is the sole
evidence.

| Rule | Reason |
|---|---|
| The stretch of scans is what makes it a history | The interesting row is the claim that *stopped*: somebody dropped a patch and the finding it answered is back. A list of what stands would not contain that row |
| Narrowed on what the claim says it is about, not on a package the build still carries | A claim naming something that has gone is what somebody asking why a patch stopped working wants |
| The two kinds are distinguished on the row | A claim attached to a component is a patch declaring what it fixes; a claim in a document of its own names something to be matched. A claim that suppresses nothing says so |

## External links

A claim carries a link to work happening elsewhere, and **nothing is sent to
it** (REQ-36): the link is stored and read by people. One link per claim rather
than one per release, because the conversation about a promise is one
conversation. What is not built is the tracker hand-off — opening or updating an
item in whatever system that link points at.

The signed outbound request (REQ-46) is a different thing and it is built;
`DESIGN-notifications.md` owns it, including the egress controls and the one
place a private address is deliberately permitted. Recorded here as unbuilt, it
read as there being no egress path at all, so the most review-worthy egress in
the deployment sat behind a document saying it did not exist.

| Rule | Reason |
|---|---|
| Nothing fetches what a link points at | A tool that fetched an address a person typed is a request-forgery primitive. Stored as text, shown as a link, encoded on the way out |
| Sent empty, it is cleared | A stale link sends somebody to a ticket that closed for a different reason |
| Anybody who may argue about a claim may point it somewhere | A link is a note about where the conversation is rather than a judgment |

Assigning notifies; planning does not (REQ-34). Somebody is told when work is put
on them. Saying which releases the work is meant to reach is done to the work.

## Publication

Publication covers a vulnerability in this deployment's own product. A known CVE
in a shipped third-party component is dependency hygiene a consumer reads out of
the inventory.

| Rule | Reason |
|---|---|
| A pluggable output with several adapters, not one integration | Publishing routes differ completely by product: an open-source project uses its forge's advisory system, an appliance vendor publishes on its own site. One integration would be one of those wearing the name of the general case |
| The triage record is ours; the published advisory is the platform's | Neither is a copy of the other and neither syncs |
| CSAF is the adapter that matters for commercial products | Nearly free from what is already held, because VEX is a CSAF profile and the dismissal vocabulary was aligned to it from the start |
| A forge's advisory system is one adapter | Draft privately, request an identifier, publish, and use its temporary private fork for fix work under embargo. Applies to nothing hosted elsewhere |
| Publishing aggregates | One advisory covers a product and a version range, not a path. A reader is asking "am I affected", and the answer is a version |
| Optional and configured per deployment | Nobody should need an account anywhere to use this |

## The CSAF document

A CSAF 2.0 document generated for one issue in one product, from what is already
held. Nothing is sent anywhere.

| Rule | Reason |
|---|---|
| Only for a flaw in what this deployment ships | An issue a scanner reported against a third-party component is refused by name rather than answered with a document that looks the same and means something else |
| The publisher is deployment configuration, not an administrator's setting | It is the identity of the organization running this. Both a name and a namespace are required, because a document naming no publisher is not a CSAF document |
| A document about an undisclosed flaw is a draft, and says so | Reaching a disclosure date discloses nothing (REQ-37), so generating a document does not either |
| Releases are named by stream and variant together | Every release a status refers to is named in the product tree, and the list is ordered here rather than by the engine, so two documents generated from the same facts are the same bytes |
| A release that fixed the flaw is named as fixed rather than omitted | Omission reads identically to a release that never shipped the thing. What fills that list is somebody saying so (REQ-19), because for a recorded flaw no scan will |

## The VEX document

Assembled from approved `not-applicable` and `already-fixed` claims (REQ-39), for
one product, stream and variant.

A customer running their own scanner against a shipped image asks "which of these
are you not affected by" more often than they ask for an advisory. Generating it
puts this deployment's dismissals in writing, machine-readable, in front of every
customer — which is the reason the two-person approval on those claims exists.

| Rule | Reason |
|---|---|
| OpenVEX rather than the CSAF profile | It is the format this deployment already reads. One document shape to get right, and one deployment's output can be another's input |
| Approved claims only | A proposal is one person's opinion and this document is the deployment's word to a customer |
| A deferral is absent rather than exported as anything | Publishing it as not-affected would assert we assessed something as harmless when we had only postponed it. Silence already reads as affected in this format |
| Public findings only | Asking for the undisclosed ones is a preview for somebody who may read them, and refused for anybody who may not |
| The statement is about the build, with the component underneath | A VEX statement is about a thing somebody has, and what they have is the image |
| A component with no package identifier is named by the name the build calls it | Less use to a machine, and better than a silent omission, which in this format reads as "no claim" |
| Every statement carries the other names its issue answers to (REQ-18) | A customer holds identifiers their own scanner produced, matched under the name *its* database uses. The primary is not repeated among the aliases |
| Ordered here rather than by the engine | Two documents generated from the same state are byte-for-byte identical |

A statement is made only where every open place agrees, and agrees the same way.
The format says "this product, this component, not affected" and has no finer
grain. A component commonly sits at several places, so a dismissal agreed at one
of them is not a claim about the component. Published as one it was a
machine-readable "not affected" about something that is affected, sent to every
customer running a scanner against the image.

Places dismissed for different reasons — one not applicable, one already fixed —
produced two contradictory statements and now produce none.

Where several places were decided in separate sittings the document states the
**earliest**: the claim that has stood longest and the one a reader can check
against the record. Grouping on the words and the moment emitted the same claim
twice.

## Issuance records

An advisory records when it went out, by whom, and a digest of what went out.
Without it a second advisory for the same flaw could carry no revision history
and could not increment its version, both of which CSAF validators check.

| Rule | Reason |
|---|---|
| It is a fact about a moment | What was published on a date cannot be worked out again once a release is added, a decision is revised or a fix lands |
| The digest covers what the document says, not the whole document | The current release date, the generator's date, the version and the revision history all move on generation or *because* of issuance. What is hashed is the title, the notes, the product tree and the vulnerability |
| The digest is taken from the document generated here | A caller-supplied digest is a digest of whatever they say, and both sides of the comparison must come from the same place |
| The version and history are derived from it | The next document is one past what has gone out. The last history entry is the document in hand, which has not gone out and says so |

## Publisher identity

One record, not one per format. A VEX document and an advisory both name their
publisher and read it from the same configuration. Each carried its own copy of
the same two fields with a byte-identical method asking whether they were set,
and the handler between them converted one to the other.

The CSAF category rides along and VEX ignores it: a deployment publishing about
its own product is a vendor, which is what the format wants to be told.

## Not built

The CSAF document's VEX profile. The generated document is categorized as a
security advisory rather than as VEX, because that profile's point is "not
affected, and here is why" and those justifications are not assembled into it.
The vocabulary is already correct; what is missing is the mapping from a
decision to the releases it covers. This does not concern the OpenVEX document
above, which is built and is a different document for a different reader.

The tracker hand-off (REQ-36). What exists is the link somebody typed, stored
and never fetched; what is missing is opening or updating an item in the system
it points at. The signed outbound request is built and is described in
`DESIGN-notifications.md`.

## Limits

- **A bump is keyed on where it is going as well as where it comes from.**
  Pending upgrades grouped on the first two fields and took the third from
  whichever row made the bucket, so two bundles at 5.9.0 and 5.9.2 rendered as one
  row saying 5.9.0. On a real image forty-two of a hundred and twenty-seven pairs
  carry more than one target version.
- **A fix declared for a product covers its builds without being written per
  build.** A decision's live key names the place and not the build, so a product
  shipping the same component in two builds produced two identical proposals and
  the second collided with the unique index, rolling back the whole declaration.
  The proposals are made distinct before they are written.
- **A statement about a group speaks for the group.** The outbound format has no
  place granularity, so a dismissal covering some of a group is not published as
  covering all of it.
