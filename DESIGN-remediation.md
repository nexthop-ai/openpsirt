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
- [Asking upstream what is current](#asking-upstream-what-is-current)
- [Ordering the versions a scanner named](#ordering-the-versions-a-scanner-named)
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
| No version comparison decides coverage | An upgrade covers everything open on the fold rather than only what records this version as its fix. What an ordering is used for is reading a set of candidates, never deciding what a commitment reaches |

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

A commitment is answered by the next scan of the build it was made for, never by
anybody marking it done (REQ-35). Each stands at landed, lapsed or planned, and
those three are worked out on every read — nothing stores them, nothing refreshes
them, and nothing has to be invalidated when a scan closes a finding.

**A roll-up across the builds one issue was promised in is not built.** There was
one, reading "two of three chosen releases are clear", and it was the only reader
of a screen that offered a set of builds to tick with no version, no date and no
reasoning attached; both went together. What remains answers per build, which is
the grain a commitment is made at. Where an issue stands across several is read
from the findings list, which has a row per build.

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

The fix-bundle query inverted (REQ-35). A triager reads an upgrade and the
issues it closes, in the findings list's by-upgrade view; a coordinator reads a
build and the upgrades it is waiting on, here. One query read from either end,
and both ends are drawn.

Both ends key their rows on the fold, so an upgrade reads the same from either
direction.

The version in hand and the version being moved to are both stored with the
commitment. They are read off the findings that are still open, and landing the
upgrade closes them — so a plan deriving them went blank on an upgrade exactly
as the upgrade succeeded.

What each row reports is what is still open under it, counted from the findings
rather than from anything written down: the distinct issues the upgrade would
close here, and how many places those sit at. Nothing is declared done by hand — a
build is clear when it stops holding them.

## Asking upstream what is current

What the public index for an ecosystem says the newest version is, for the
components this deployment builds rather than the ones a distribution
maintains. Off unless an administrator turns it on: it is the one thing here
that reaches the network.

| Rule | Reason |
|---|---|
| One replica asks, settled by a lease | These are free services somebody else runs, and the politeness the pass is built around — two hundred at a time, a quarter of a second apart — is a rate per deployment rather than per replica |
| The lease is taken again as the pass runs | Sized from the interval between cycles it was a guess at how long a pass takes, and the arithmetic beside it said so: two hundred requests with a timeout each is far past several intervals. A slow index handed the pass to a second replica mid-flight and both asked |
| A pass that has lost the lease stops | Two replicas asking is what the lease exists to prevent, and it is at somebody else's expense |
| The candidates are the ecosystems there is an index for | Maintained as the complement of one of them, every other unaskable ecosystem passed the filter, reached the asker, found none and was recorded empty — spending one of the pass's slots. An image with ten thousand distribution packages spent fifty passes writing nothing |
| A distribution package is not asked about | The distribution is the maintainer, and the date it released says nothing about the age of the software inside |

What comes back is classified, because the classes want opposite treatment.

| Answer | Recorded | Reason |
|---|---|---|
| A version | Yes | The thing being asked for |
| The index has never heard of it | Asked, with no version | A private module and a vendored fork both look like this, and neither is a fault. Recorded so the question is not asked again tomorrow |
| A refusal the index will repeat | Asked, with no version | A package withdrawn, a region blocked, a name that cannot be turned into a request, a document nothing can read. An answer we will never get is still an answer about this component |
| A bad day — too many requests, or the index itself unwell | Nothing | The one class worth coming back to: it stays due and the next pass asks again |

**Everything that is not a bad day is recorded.** Read as one, a refusal the
index repeats every time left the component unrecorded — and the window takes
the never-asked first, so it held the head of every pass afterwards for ever,
with the components behind it never reached.

A previous answer is never overwritten by an empty one. An index returns
not-found for a renamed package and for some transient conditions, and letting
one of those destroy a version already in hand would sit on the hole for a
month.

## Ordering the versions a scanner named

Where a component could go is every version the findings open against it name as
their fix. Two counts are answered for each, because they are two questions.

| Count | |
|---|---|
| What that release fixed | How many of what is open name that exact version. This is the release's own security content, and it is what the scanner said without any comparison |
| What reaching it closes | That, plus everything fixed at or before it. This is the question somebody choosing between two versions asks, and it is the one that needs an ordering |

Sorted on the first, the version worth taking sinks. Measured on the demo's
kernel: of 168 open, 158 have a fix across 13 named releases, the 6.12.100-1
release fixed 49, and the newest named, 6.12.107-1, fixed 2 while carrying every
fix before it. A list ranked on what each release fixed puts the version that
closes everything near the bottom.

| Rule | Reason |
|---|---|
| An ordering is per ecosystem, and only where its algorithm is written down | A distribution's version comparison and dotted numeric releases are written here. Everything else is left unordered rather than approximated, because an ordering claimed before its algorithm exists is the confident wrong answer |
| The spelling decides, not the ecosystem | A runtime published through a language index and naming itself after its own toolchain has the scheme and not the spelling. One version a comparison refuses leaves the whole set unranked: a list ordered except for the entry nobody could place is not ordered |
| Every scheme can refuse, including the one whose comparison answers for any two strings | The distribution comparison walks alternating runs of digits and non-digits and always produces an ordering, so it read as a scheme that never fails. What an advisory wrote where a version belongs — "unfixed", a sentence — then outranked every real release, because a letter sorts above a digit, and was presented as the upgrade closing the most. Each scheme decides what a version of it looks like before comparing: the distribution's rule is its own, that an upstream version begins with a digit |
| Unranked means the two counts are equal and say so | An exact match still counts. What is never done is inferring that one version reaches another, so nothing overstates what an upgrade would close |
| Which scheme applies is read from the package identifier | Two ecosystems spell some versions identically and order them differently, so reading the shape of the string would order a package by whichever scheme its version happened to resemble |
| The scanner already compared versions to match the finding | So refusing to compare does not make the tool comparison-free — it leaves it unable to rank what it has already been told. What is new here is saying which of the answers is furthest along, not deciding which findings apply |

**A wrong order is worse than none**, which is why the refusal is part of the
mechanism rather than a gap in it: the answer arrives as a recommendation
somebody schedules a release around, and the scan that would catch it runs after
the release.

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

**Not built, apart from the document.** A CSAF document is generated and
reachable at the advisory routes; nothing sends it anywhere. The rules below are
what publication would be, kept here because the document they are about exists
and the shape it would be published in is what makes its content right.

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
| The document's version is the last number its own revision history states | Counted separately the two disagreed the moment an advisory had been issued once, and a validator compares them. The two agreed by accident only for a document nobody had published, which is why it went unseen |
| The publisher's category is one of the six the standard names, refused at startup otherwise | The value reaches the document verbatim, so a typo produces advisories that fail validation wherever anybody takes them — which is the one use a generated advisory has |
| The document declares the profile it satisfies, worked out from what it turned out to carry | Declared unconditionally, a document missing a profile-mandatory element fails that profile's own tests and is dropped by the tooling that reads it |
| The security-advisory profile is the product tree, the vulnerabilities, and notes and a status on each | The standard's own list. Notes and references on the *document* belong to the informational advisory — the profile for a document carrying no vulnerabilities at all — and gating on those declared a base document for every flaw of ours that nobody outside had written up yet, which a customer's tooling filtering for security advisories skips |

### What the document carries

Everything below is already held. Nothing is derived, and a field the standard
defines and the record cannot answer is left out — an advisory is read by
somebody deciding whether to act.

| Element | What fills it | |
|---|---|---|
| References | The issue's write-up and everywhere else a report points, each address once | On the document rather than on the vulnerability. The document is about one flaw, so the two lists would hold the same addresses, and the profile requires the document's |
| Scores | The CVSS base vector, scored here | Worked out from the vector rather than read beside it: a stored number and a stored vector that disagree have nothing to say which was meant. A vector under a scheme this deployment does not score yields nothing rather than a number under the wrong formula |
| Acknowledgments | The credit the reporter asked to be named by | The credit alone. Reporting under a name gave it so somebody could reply, not so it could be published, and "anonymous" is a real answer to the question the credit field asks |
| Remediations | Stated for the releases that still carry the flaw, and the details name the releases that do not | That is who a remediation is for: the standard defines the product identifiers as what the item applies to, and a vendor fix as one for the affected product. Pointed at the releases already fixed, the customer who has to act reads an advisory with no remediation for them. "Update to a release in which this flaw is fixed" is that instruction with the answer left out, so the details name them, by the names the product tree gives them and in the order it gives them — not the earliest, which would mean ordering release names, and an ordering that answers confidently for a pair it cannot order is worse than none. Nothing about planned work: a commitment is one build's internal plan, and the same sentence in a published advisory is a promise to a customer about a date |
| Distribution | The same fact the tracking status reads — a draft is RED, a disclosed document is WHITE | Handing a draft to somebody who may pass it on is the disclosure the embargo exists to hold. The labels are the standard's four, which is why a final document is WHITE rather than the word the protocol renamed it to |

An address a report supplied goes through the rule an address stored beside a
claim goes through, and a custom application scheme is dropped rather than
published. It is leaving the deployment, into tooling that follows it.

**Two fields the standard defines are not carried.** The weakness
classification needs the name that goes with the identifier, and what is held
is the identifier alone — a name invented to fill the field is the one thing a
validator checks it against. The product identification helper names a package,
and this tree names releases rather than components, which is what an advisory
aggregates to.

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
| The impact statement carries what stops the flaw, never the reasoning | The reasoning is the argument a triager put to a second person here, addressed to a reader who can see the record it argues against. Published it is this deployment's review of itself, machine-readable, in front of every customer running a scanner. The mitigation is the half somebody holding the build can act on |
| Where no mitigation was named the field is absent | Only one recognized reason asks for a mitigation, so most statements carry none. The justification beside it is what the format asks for, and silence says less wrongly than the wrong text |
| A deferral is absent rather than exported as anything | Publishing it as not-affected would assert we assessed something as harmless when we had only postponed it. Silence already reads as affected in this format |
| Public findings only | Asking for the undisclosed ones is a preview for somebody who may read them, and refused for anybody who may not |
| The statement is about the build, with the component underneath | A VEX statement is about a thing somebody has, and what they have is the image |
| A component with no package identifier is named by the name the build calls it | Less use to a machine, and better than a silent omission, which in this format reads as "no claim" |
| Every statement carries the other names its issue answers to (REQ-18) | A customer holds identifiers their own scanner produced, matched under the name *its* database uses. The primary is not repeated among the aliases |
| Ordered here rather than by the engine | Two documents generated from the same state are byte-for-byte identical |
| A build with more statements than one document carries is refused, not truncated | There is no second request for the rest, so a document that stopped at a ceiling would say "nothing is claimed about this" by omission about everything past it — to every customer running a scanner, which is the one thing a document of dismissals must never say. The ceiling is well above anything real, and reaching it names the build and the number |

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

**The earliest decision is picked first, and then read.** Each column had its own
minimum over the group, and nothing tied them to one row: with two claims
standing at a component — "component_not_present" and
"inline_mitigations_already_exist / bound to the management VLAN" — the
machine-readable category came from one and the impact statement from the other,
and the published statement said the component was not present while describing
the network control that protects it. That is a composite no record ever held,
going to every customer running a scanner. The group answers with the earliest
decision's identifier and its words are read by that identifier.

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
security advisory rather than as VEX — that profile's point is "not affected,
and here is why", and those justifications are not assembled into it.
The vocabulary is already correct; what is missing is the mapping from a
decision to the releases it covers. This does not concern the OpenVEX document
above, which is built and is a different document for a different reader.

The tracker hand-off (REQ-36). What exists is the link somebody typed, stored
and never fetched; what is missing is opening or updating an item in the system
it points at. The signed outbound request is built and is described in
`DESIGN-notifications.md`.

Every adapter that would send an advisory somewhere, which is the whole of
Publication above. The CSAF document is generated and served; no destination,
no adapter and no route to one exists.

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
