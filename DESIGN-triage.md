# Triage

What people decide about findings, and when a decision stops applying.

Satisfies REQ-17, REQ-18, REQ-23, REQ-24, REQ-25, REQ-26, REQ-27, REQ-28,
REQ-29, REQ-30, REQ-31, REQ-32, REQ-33, REQ-35, REQ-40, REQ-43, REQ-53,
REQ-57, REQ-65, REQ-66.

The text rules are in `DESIGN-text.md`; the reports these numbers feed are in
`DESIGN-reporting.md`.

## Contents

- [Decision identity](#decision-identity)
- [Expiry](#expiry)
- [Outcomes](#outcomes)
- [Approval](#approval)
- [Rights](#rights)
- [Readback](#readback)
- [Reading a claim whole](#reading-a-claim-whole)
- [Claims](#claims)
- [Approving a claim](#approving-a-claim)
- [Setting rows aside](#setting-rows-aside)
- [Holding part of a claim back](#holding-part-of-a-claim-back)
- [Extensions](#extensions)
- [Decision lists on a finding](#decision-lists-on-a-finding)
- [The review queue](#the-review-queue)
- [Sending a claim back](#sending-a-claim-back)
- [The deferral threshold](#the-deferral-threshold)
- [One live claim per key](#one-live-claim-per-key)
- [The triage line](#the-triage-line)
- [Issue assessments](#issue-assessments)
- [Coverage count](#coverage-count)
- [Reach across builds](#reach-across-builds)
- [Applying to other builds](#applying-to-other-builds)
- [Bulk claims](#bulk-claims)
- [Fix bundles](#fix-bundles)
- [Promised work](#promised-work)
- [Deadlines](#deadlines)
- [Lapse marking](#lapse-marking)
- [Re-affirmation](#re-affirmation)
- [Comments and reasoning](#comments-and-reasoning)
- [VEX statements as evidence](#vex-statements-as-evidence)
- [Dates still to come](#dates-still-to-come)
- [Mitigation-based dismissals](#mitigation-based-dismissals)
- [Outcomes on a tag](#outcomes-on-a-tag)
- [Tags](#tags)
- [Rule-prepared claims](#rule-prepared-claims)
- [Carrying onto a new line](#carrying-onto-a-new-line)
- [Not built](#not-built)
- [Limits](#limits)

## Decision identity

A decision is keyed on the product, the issue, the place, and the upstream
versions of the component and of the thing that pulls it in. The release it was
made in is not part of the key.

| Consequence | |
|---|---|
| A later release inherits by lookup, not by copy | Nothing to synchronize, so nothing drifts |
| A variant inherits exactly when its code matches | A variant whose chain differs computes a different key and fails to match. No extra test |

The match is an index lookup on every screen that asks whether anything stands
here, so the two version columns are bounded where the component columns they
copy are not. **A version that will not fit is refused, not shortened**;
shortening would key the decision on something the finding does not hold.

Measured before settling the bound: the reference producer's real output is
6,845 components, longest version 49 characters, none over the limit.

## Expiry

A decision is stored under the versions it was a claim about. A place asks under
the versions it has now. When the code moves the two stop matching. Nothing
sweeps and nothing runs on a timer.

| Rule | |
|---|---|
| Only the upstream version counts | `10.5.4` to `10.6` lapses a decision; a packaging revision does not. A shipped package is rebuilt constantly, and a rebuild is not somebody's reasoning becoming wrong |
| A version change mid-chain needs no rule of its own | It either changes the direct consumer of something, which lapses that decision, or it does not |
| A carried patch does not lapse a decision | A producer that fixes by patching moves no version this can see. For one that patches heavily, a decision may never be automatically re-examined however much the code moves |
| A decision's age travels with it everywhere it appears | The compensating control for the line above. An eight-year-old judgment should look like one |
| A deferral runs out on a date, not on a version | A bump does not change a judgment about priority, and a calendar does not change one about applicability. The finding returns to the queue marked as deferred rather than as new |

Identity is structural and expiry is version-based, and neither reaches into the
other. Overlapping them is how a bump at the top of a build invalidates a
judgment made about a leaf.

## Outcomes

| Outcome | Means |
|---|---|
| **Affected** | It applies, and goes to remediation |
| **Not applicable** | It does not affect this product here |
| **Deferred** | It affects us, and is not being worked on until a date |
| **Won't fix** | It affects us, and will not be addressed |
| **Already fixed** | The version shipping here carries the fix, and nothing here can see that it does |
| **Upgrade needed** | A component is being upgraded, by a date |
| **Patch needed** | One issue is being backported, by a date |

| Rule | |
|---|---|
| A deferral publishes as affected, never as not-affected | Deferring is an internal scheduling judgment. Published as not-affected it would tell the world we assessed something as harmless when we had only put it off |
| Only not-applicable carries a reason, and it is required there | The claim that something does not affect us *is* which recognized reason applies |
| The reason vocabulary is the exchange format's | A private one needs a mapping nobody maintains and loses meaning at every step |

Two outcomes would not be enough: with only "affects us" and "does not" there is
nowhere to put *yes, but not now*, and people record it as one of the other two,
after which no report can tell the difference.

### Already fixed

For a distribution's package (REQ-23). A backported patch does not move the
upstream version, so a scanner comparing a published identifier against an
upstream range fires either way: a package that has been fixed looks exactly like
one that has not.

| Rule | |
|---|---|
| It requires the package version the fix arrived in | The way a deferral requires a date. Alone among the outcomes this one asserts a fact rather than a judgment, and an outcome that hides risk on a matter of fact is the one most worth being careful of |
| The version is never compared against what ships | Deciding whether one version is at or past another needs an ordering per ecosystem |
| It expires on the upstream version, not the packaging revision | A later revision of the same upstream version still carries the patch |
| Where it is published, it publishes as fixed | |

No other outcome says this. It is not not-applicable: the code is present and it
*was* affected, and somebody auditing a claim that the vulnerable code is absent
would find it sitting there. The exchange format keeps the two apart the same
way. Nor can it be left to computed resolution: closure is derived from what a
scan reports, and this scan keeps reporting it at every later revision.

The word already existed on the way in and only on the way in — a build's
suppressions may say `fixed` — so this fills the gap where nobody upstream can
make the claim, using the same word.

## Approval

**The proposer and the approver are always different people, with no override.**
A deployment with one person cannot approve anything.

| Rule | |
|---|---|
| An approval names one revision of the reasoning, not the decision | A second pair of eyes read particular words. An approval floating free of them would still stand after somebody rewrote them, and nothing would report it |
| **The row count is the control, so an engine that cannot report it refuses** | The rows move only while the approved revision is still what the claim rests on, and that condition is checked by counting what moved. Read as optional, the check was skipped on any driver that does not answer — after the approval row was already written |
| The reasoning is revised, never overwritten; every revision is readable | |
| Editing the reasoning takes back the approval | The item returns to the queue marked as previously approved rather than as a fresh proposal |
| Withdrawing, revising and sending back need no approval | Hiding risk needs a second person; putting it back on the table does not |
| Undoing works at the size it was done | A bulk approval records what it covered; undoing takes the whole batch back to *proposed*. The claims still stand — it is the agreement that was taken back |
| A withdrawn approval stays on the record | It says a second person did once agree, and to which words |
| **A carried agreement says it was carried** | A re-affirmation stands on the agreement its predecessor had and states its own reasoning, so the approver named read the earlier words. Written as an ordinary approval it said they had agreed, today, to text they have never seen — and the register, the audit list and the claim's own approvals all reported it that way |

## Rights

Arguing, agreeing and reading are separate questions.

| Act | Needs |
|---|---|
| Propose, revise, withdraw | Triage on the product, at the finding's visibility |
| Approve, undo an approval | The approver capability **or** triage, plus being able to read the finding |
| Comment, or edit your own comment | Either of the above |
| Read what was decided | Being able to read the finding |

| Rule | |
|---|---|
| A triager may approve somebody else's claim | Two triagers agreeing to each other's work is the ordinary shape of a small team, and the control that matters is that the two are different people. Asking for the triage role alone made the approver capability decorative |
| Reading is the finding's own visibility and nothing else (REQ-43) | Asking whether the reader could decide or approve was narrower: a reader saw "deferred" with no way to see why, and on a real deployment somebody holding private reading opened a finding and was told none of its 91 decisions existed |
| Writing is named apart from reading in the code | They are separate rules. Adding a comment had leaned on the reading rule, so widening one would let a reader comment on a decision they may not argue about |
| Every check reads the product and visibility from the row | Never from what a caller stated |
| A place stating no visibility is undisclosed, normalized before the check | Doing it only before the write let a place stating nothing pass the check for disclosed findings and then be stored as undisclosed |
| Unreachable and non-existent give the same answer | Guessing identifiers says nothing |

## Readback

Each way of adding to a decision has a matching way of reading the result: the
decision with the reasoning it currently rests on, the earlier justifications,
who agreed to which of them, and the discussion. Decisions list across products
and filter by outcome, by state, and by whether a deferral's date has passed.

Without these the only list of decisions is the review queue, which by definition
holds the ones nobody has agreed to yet.

| Rule | |
|---|---|
| Each list carries the reasoning and the names with the row | A list where seeing why means opening every entry is a list nobody reads before acting. A row saying product 4, issue 91 is two more requests to understand, fifty times a page |
| Undoing a bulk approval narrows to what the person undoing may reach | A batch is one reviewer's afternoon and may span products |
| Who may read it is the finding's own visibility | The decision, its revisions, the approvals, who acted, and the comments — comments in rather than carved out, because disclosure makes the record mean all three together |

## Reading a claim whole

One read answers everything about one claim: what it says, where a
representative row sits and what that row is about, the reasoning as it stands,
what became of it, what it wrote, and what it covers now.

| Part | |
|---|---|
| **What it says** | The outcome, the reason, the mitigation, the dates, the version an upgrade moves to, and the justification as it stands — the claim's, however many rows it wrote. It names no decision and carries no row state |
| **What became of it** | One word over every row, the same word the proposer's own list reads, with when it became that and who did it. A claim whose rows did not all end the same way is said to be mixed rather than reported as whichever came first. A claim marked as having come back is one with an approval on record that is not standing on one — asked of a claim that is currently approved, "was this ever approved" answers about the agreement being read |
| **What it wrote** | Rows, distinct issues, distinct places. The place count is what the bulk cap is measured against |
| **What it covers now** | Folds, packages, consumers and findings, matched the way a finding asks whether a decision applies to it, and every build it reaches |

| Rule | |
|---|---|
| The state on it is the claim's, never a representative row's | A row's state standing in for the claim's is how one row approved beside forty-three sent back read as approved |
| What it covers is worked out when it is asked for | A claim reaches by matching, so a build appearing afterwards is covered with nobody acting. What somebody consented to covering is stored with their approval, and is the different question |
| Refused whole or answered whole | Shown half, a reader would be told about words whose other half is about a finding they may not see |
| A case grant reaches it | Somebody brought into one issue is offered its decisions by every list they can reach, and a claim offered and then refused reads as a fault rather than as a rule |
| The counts are narrowed to findings the reader may see | A claim somebody may read can match findings they may not, and a count is the leak even where no row is shown |

## Claims

A judgment about a finding writes one decision per place; a judgment about many
issues writes one per issue and per place. Rows stay that fine because each is
keyed and lapses on its own. The thing a second person reads and agrees to is the
**claim** — one argument with its reach. The review queue, approval, sending back
and undoing all work on claims.

| Kind | What it is |
|---|---|
| **finding** | One judgment about one issue in one component, covering the places it sits at. A re-affirmation is one too |
| **together** | One judgment about many issues at one component |
| **extension** | An approved claim carried to a new issue at the same component under the same consumer, with the same justification |
| **returned** | The rows an approver set aside from a claim they agreed the rest of |

A claim records what sort of action it was, who took it and when, how a bulk set
was narrowed, and — for two kinds — which claim it came from.

### The claim and its rows

**One act is one argument.** The claim carries what the judgment says; the rows
underneath carry where it lands and when it stops applying.

| On the claim | On each row |
|---|---|
| The outcome | The place, and the two upstream versions it was made against |
| The justification, and the mitigation that goes with one of them | Its state, and when it ended |
| The date a deferral looks again on | Whether that row needs a second person — a short deferral does not, and the threshold is measured per place |
| The date a promise acts by, and the version an upgrade moves to | The finding's visibility, which takes the stricter of two where a place is private |
| The version an already-fixed claim names | How bad it was judged to be, which is read from the place |
| The reasoning, every revision of it, and which revision stands | The VEX statement the argument was started from, where one was |
| The approvals given for it, and the comments about it | |

**This was on the row.** A judgment reaching forty-four places was forty-four
copies of one sentence, each revisable on its own — so revising one returned that
row to the queue and left the other forty-three saying the old thing under a
claim that read as agreed. Measured on the demo before the move: 11 claims, 155
decisions, 155 revisions, and **five distinct pieces of reasoning**; one claim
carried forty-four identical copies of its own words. Every payload field was
constant across every row of every claim.

**An action recording two things is refused.** A proposal per place permitted a
per-place outcome and version, and nothing has ever produced one. Refused rather
than quietly taking the first, because a set that disagrees is two claims
somebody meant to record as one, and taking the first loses whichever half was
not first.

### Where each act lands

| Act | On |
|---|---|
| Approve, send back, set rows aside, point elsewhere | The claim |
| Hold part of it back | The claim, by its author. The rows named become a claim of their own |
| Revise the reasoning | The claim. One text, one history, one set of approvals to withdraw |
| Withdraw | The claim. Taking back part of an argument is setting rows aside, which is a different act with a different record |
| Comment | The claim. A note on one place of forty-four is one nobody else reading the claim would see |
| Re-affirm | One place. A version moved under one row and not the others, so what is being re-made is that row's judgment |

**Recording in bulk and changing your mind one row at a time was the split, and
it was the wrong middle.** Approval was already claim-scoped while revising,
withdrawing and commenting were not, so somebody could record five hundred rows
in one act, have them agreed to in one act, and then only unpick them five
hundred times.

**One approval row, not one per place.** An approver reads the words once and
agrees to them once. Per row, a claim over a kernel wrote two thousand copies of
one agreement, each able to go on standing after the words changed.

The queue lists one entry per claim, newest first, with a representative row, its
place and reasoning, how many rows, issues and places it covers, and every build
it currently reaches by matching. The count beside the queue counts claims.

**An entry says what it is about** (REQ-28): the build to open, the issue and
what the report says of it, the component and version, how bad and whether it is
being exploited, what upstream has done, the two ends of the way down, how many
places the issue sits at, and how many of those the claim covers. All read from
the open finding the row matches — by place and versions while live, by place
alone once lapsed — in a handful of statements for a page. An entry carried only
an identifier before.

| Rule | |
|---|---|
| The builds named are the ones the reader may see | A claim somebody may read matches findings they may not, so the builds, the fix versions behind the outliers and the counts on a card are all narrowed per product |
| A claim is shown only to somebody who may act on every row of it | Acting on a claim is acting on the argument, which does not come in halves. Shown half, a reader would agree to words whose other half waits on somebody else, and the size beside the card would be wrong |

## Approving a claim

Approving a claim approves every waiting row in it, in one transaction, under the
rules each row is approved under: by somebody other than whoever wrote the words,
against the revision that stands now, with what it covered counted and kept. A
row already approved, withdrawn or lapsed is left alone. **A row already sent
back is not approved with the rest** — it is with the author.

It is a set operation, not a loop. A claim over a kernel is two thousand rows;
one row at a time, **1,760 rows took 15.6 s on the demo, and 500 rows were 2,500
statements**.

As a set it is a bounded number of statements whatever the size:

1. The author of the claim's current reasoning, read once.
2. One approval row, naming the revision it was given for and carrying what it
   covered, counted in one statement over every row and narrowed to what the
   approver may read.
3. The rows moved to approved in one update, conditioned on the claim still
   resting on that revision.
4. The matched count checked against what was meant, refusing the whole claim
   where it falls short, so a revision landing in between leaves nothing half
   agreed to.

Measured on SQLite: 500 rows with two set aside in 15 statements. A test pins the
statement count rather than the time, because the count is what a per-row loop
cannot satisfy.

**Recording is set-based for the same reason.** One judgment covers every place
it sits at, and on shared code that is many — 507 for the worst case on the demo,
which one row at a time is 1.4 s on MySQL. The rows are written in batches, the
shape the scan apply already uses; measured on SQLite, 500 places in 6
statements, pinned by a test the same way.

## Setting rows aside

The queue entry carries its **outliers** — the rows that do not look like the
rest. An approver may set some aside: the rest is approved as one claim, and the
rows set aside move into a claim of their own, derived from the original,
belonging to the original proposer, marked sent back, with the reason recorded on
each as a comment.

| Rule | |
|---|---|
| A reason is required | |
| Setting aside a row outside the claim is refused, not ignored | A stray identifier is more likely a mistake than a wish |
| The proposer may not set rows of their own claim aside | Setting aside is an approver's act: the rest of the claim is approved in the same action |

The outliers are four signals, all already stored, counted over the distinct
issues in the claim: known to be exploited; rated critical or high, by our
assessment where one stands; a fix available, read from the open findings the
claim's rows match and only those the reader may see; and, where the record of
how the set was narrowed names a term, a description that does not carry it.
Exploited first, then the worst rated, then by name, capped at twenty, with
counts saying how many are behind the cap.

Without this an approver of a bulk claim chooses between refusing everything and
agreeing to everything.

## Holding part of a claim back

The proposer's side of the same act, and the same mechanism: the rows named move
into a claim of their own, derived from the original, carrying the argument they
were made under, with the reason recorded as a comment and the rows sitting with
their author until the argument for them is stated again. Revising is what gives
them one of their own.

**The outliers are shown to the author too.** Whoever wrote a bulk claim faces
the choice an approver faces — hold part of it back, or argue all of it as
one — and the signals that help an approver choose a subset were shown only to
the approver.

| Rule | |
|---|---|
| A reason is required | The same rule setting rows aside holds, for the same reason |
| Naming a row outside the claim is refused, not ignored | A stray identifier is more likely a mistake than a wish |
| Naming all of what is still being argued is refused | That is a revision or a withdrawal; two claims saying the same thing is not what anybody meant |
| A row already agreed, withdrawn or lapsed cannot be held back | It is not part of what is still being argued |
| **Splitting is the author's act and setting rows aside is the approver's**, each refused to the other | An approver holding rows back is agreeing to the rest in the same action, so an author doing that would be approving their own claim |

Until this the author could only withdraw the whole thing and start again, so
"this holds for most of them but not those four" was unavailable to the person
best placed to say it.

**Narrowing within a fold is a different thing and is not offered.** One
judgment covers the whole fold, with no escape hatch. A claim still spans
several folds — a judgment about many issues at one component, or one carried
across builds — which is what makes splitting a real need that folding does not
remove.

## Extensions

An extension records an existing judgment against a new issue at the same places,
as a claim of its own. Every nightly scan adds issues to components that already
carry agreed claims, and each arrives as a blank decision.

Three things hold, read inside the transaction that writes:

1. **The source is approved** — every row of it, none withdrawn or lapsed.
2. **The new rows sit at places the source sits at, in the same product.** A
   place is the component and its consumer, and "the same argument" is about the
   same code.
3. **The outcome and justification are the source's.** A different conclusion is
   a different claim.

It needs a second person like any other dismissal. The queue marks it as an
extension and names its source, so the approver knows the argument was read once
already rather than that it was agreed to twice.

*Whether rejecting a source should reach its extensions is not decided.*

## Decision lists on a finding

The finding carries three lists, each narrowed to what the reader may see.

| List | Holds |
|---|---|
| **Standing** | Live claims covering any of its places, newest first, with how many places each covers, every build it reaches that the reader may see, and who agreed to it and when |
| **Previous** | Decisions at its places that lapsed or were withdrawn, newest first, with when they ended and the reasoning as it last stood |
| **Similar** | Approved not-applicable claims about *other* issues at the same places, at most five, each with its reasoning and how many issues it covers. These are what an extension can carry |

| Rule | |
|---|---|
| Standing is matched by key, not by place alone | The same pair of names sits in every build of the product at whatever version each ships, so matched by place a claim keyed at one build's version stood on a build shipping another. The screen asks with the build's own places and versions, read by the finding store rather than taken from the request |
| Each entry carries how its rows here stand and the claim's state as a whole | Approved only where every live row is. A representative row's state stood in for the claim's, and one row approved beside forty-three sent back read as approved |
| Rows sent back carry when, and the reason the approver gave | |
| A decision records when it stopped applying | Nothing else did: an approval's withdrawal date exists only where somebody had agreed |

## The review queue

Each entry carries the reasoning as it currently stands, whether this was agreed
to before, and how long the finding has already been put off. A list where
judging each row means opening it is a list that gets approved without being
read.

It shows only work the reader can do, narrowed in the query. A work list holding
work somebody cannot do teaches them to skip rows.

**It carries what would make an approver disagree** (REQ-28) — two counts and no
argument: what has already been *agreed* about the same issue at other places, by
outcome; and how much else at the same place nobody has answered. Neither says
the claim is wrong. They say what a careful reader would go and look up, so that
not looking is a choice rather than an omission.

| Rule | |
|---|---|
| Approved claims only, on the first count | Counting proposals would let two people in a queue be counted at each other as evidence |
| The claim's own place is not excluded from that count | A place identity is a pair of names with no product in it, so excluding by place alone would drop a decision in *another* product shipping the same pair — exactly the counter-evidence worth having. Nothing of the claim's own can be counted anyway, because it is proposed |
| A run is the second signal | A claim in a run of forty is usually right, and a run is also how forty get waved through |
| Both are read for the whole page in two statements | Fifty cards read a row at a time is a hundred round trips before the queue draws |

### What waits in the queue

| | |
|---|---|
| A claim awaiting agreement | The obvious one |
| **A rating of an issue** somebody proposed | It had nowhere to be agreed to at all — the route existed and no screen reached it |
| **A deferral that has run out** | The finding is back. Left out, it resurfaces as new with what somebody wrote last time attached to nothing anyone is looking at |
| **A decision the code moved out from under** | The person who made the judgment is the person to tell, which is the entire reason a lapse is marked rather than the decision deleted |
| **A promise whose date has gone by** | The work was to be done by then and the finding is still open, so the promise did not hold. A commitment has no expiry of its own — it goes on suppressing the finding, and the deadline the finding had passes behind it in silence |

A claim that needed nobody — a deferral under the threshold — is not here at all,
by the same rule that keeps unreachable work out.

## Sending a claim back

Sending a claim back takes it out of the approval queue and returns it when the
author revises. A reason is required and travels as a comment.

| Rule | |
|---|---|
| Not a state of its own | The claim is still proposed and what changed is whose turn it is. A fifth state would have to be reasoned about everywhere the other four are, for a distinction about attention rather than about standing |
| **It suppresses nothing while it is back** | A gated claim already suppressed nothing, so this is about the one that needed nobody: a short deferral went on hiding the finding after an approver returned it, while the notice to its author said in those words that it applied to nothing until it was revised. Revising puts it back, which is what returning it asked for |
| It needs no approval | Same reason revising and withdrawing do not |
| Nobody sends back a claim whose current words are their own | That is theirs to revise |
| Everybody whose words went back is told | A claim revised row by row can rest on several people's words. The notice sends them to the finding — the build, the issue and the component, at the version — because that is where the words are revised. Where no open finding the sender may read still describes the claim, it sends them to the decision itself |

Approve and withdraw were the only two, and withdrawing throws away somebody's
work over a missing sentence. What actually happened was a comment, and the claim
sat in the queue looking untouched.

## The deferral threshold

A deferral shorter than a configured threshold stands on its own. A quick "not
this sprint" is ordinary triage, and putting every routine act through a queue is
how a queue stops being read.

**Short is measured against everything the finding has already been put off
for**, not against the deferral being asked for. Otherwise four twenty-nine-day
deferrals are a year nobody approved. **The time counted is what each deferral
asked for**, not what it has spent.

Every deferral counts for as long as it actually held: from when it was asked
for to the date it returns on, cut short where it was taken back before that
date.

| Rule | |
|---|---|
| A deferral that was **taken back** counts for the part that ran | A withdrawal shortens the time a finding spent hidden and does not erase it. Erased, the threshold was defeated by withdrawing and deferring again — each span under the line, the running total back to zero every time, and a place hidden indefinitely with nobody ever agreeing to it. Withdrawing needs nobody, so the whole loop is one person's |
| One taken back **before it held** counts for nothing | Correcting a mistake is not avoiding the work, and counting it would make the two read alike |
| A deferral asking for a date **already past** counts for nothing | It asks for nothing, and it is refused at submission besides. Counting it as a negative would let a back-dated request subtract from what a finding has already been put off for |

The report that shows the pattern counts them the same way, and groups on the
product and the issue rather than on the words they are displayed under. Only
the product's own name is unique and it is not the one anybody reads, so two
products a catalog displays alike merged into one row: an ordinary judgment in
each read as a repeated-deferral pattern with a total summed across both, and a
genuine pattern was reported against whichever name the group collapsed onto.

## One live claim per key

Propose where one already stands and the answer is to revise that claim, not to
record a second beside it.

| Rule | |
|---|---|
| **Live, not ever** | A withdrawn or lapsed decision covers nothing and stops holding the place the moment it stops applying. Otherwise one lapse walls a place off permanently |
| **Per combination, not per place** | The versions are part of what a decision is about, so a claim about one version and a claim about the next are different claims and both stand |
| Enforced by the database, not by a check | The key is held while a decision is live and set to null once it is not, under a unique index. Null values do not collide in a unique index on any of the four engines, which is what makes a rule applying to only some rows portable. A read-then-write check is exactly the shape two simultaneous proposals both walk through, and the test drives that case |
| The same holds for a rating of an issue | Keyed on the issue, held from the moment a claim is proposed, released when it is withdrawn. Six proposals at once leave one claim standing; removing the constraint lets all six through |

Revising keeps the old words readable, takes back the approval given for them,
returns the claim to the queue and records who wrote the new version. Two people
disagreeing then produces one legible argument rather than two rows neither can
see at once. Before this, nothing prevented two contradictory claims and nothing
marked them as contradictory: what applies is chosen by agreed-beats-waiting and
then newest-wins, so approving both left one silently governing while the other
stayed on the record as agreed.

## The triage line

A deployment says what it considers worth triaging. **Below that line a finding
is still recorded, still counted and still reportable** — out of the working
list, not out of the system. Five thousand findings is a list nobody reads, and
the ones that drown it are the ones nobody was ever going to act on.

| Rule | |
|---|---|
| Nothing is hidden until somebody decides to hide it | A tool that kept findings out of the list on the day it was installed would be deciding something nobody asked it to |
| The line is compared against our rating where one stands | Being able to say a published rating is wrong is pointless if everything that ranks and filters then ignores us |
| An unrated issue is judged as a medium | The same folding the deadline uses, spelled once. Briefly two rules read one fact and disagreed: on a real image 91,040 findings rated "unknown" dropped out of the working list *and* off any clock |
| Being known to be exploited is never below the line | A line is a claim about how bad something has to be before it is worth an afternoon; being exploited is a fact about the world |
| Below the line nothing is on a clock | A line says "this is not work" and a deadline says "this is work, and it is late". Within a year the overdue figure would be thousands of things nobody intended to look at |
| Nothing on a release out of support is on a clock either (REQ-15) | Applied separately rather than folded in: it reaches further, because a line never sets aside something known to be exploited while end-of-life says nothing here will be fixed at all |

A product may state its own line. Products differ in what they can afford to
ignore, and a single number for an estate is either too strict somewhere or too
loose somewhere else.

| | |
|---|---|
| A product with no opinion **inherits rather than copies** | A product that stated the deployment's current line would stop following the next time the deployment changed its mind, and nobody would see that happen. Clearing a product's line is its own act |
| Stating one is administration | The same authority that sets the deployment's. It hides findings, which is the act every other part of this gates |
| Moving either line rewrites what is stored | Away from the request and one replica at a time — see `DESIGN-queue.md` |

## Issue assessments

A published rating can be wrong for us: the score assumes a configuration we do
not ship, or the world has not rated it and it is being treated as a medium by
default.

**The claim is about the issue, not about a place.** A rating being wrong is one
statement about the vulnerability: true wherever it appears, true in products it
has not reached yet, and it does not stop being true because somebody rebuilt.
Keyed to a place it would be repeated at each one and would lapse on a version
change that had nothing to do with it.

| Rule | |
|---|---|
| Making one asks for triage anywhere (REQ-29) | There is no product to hold a role on |
| Every act on a claim asks whether the person may read a finding of this issue, in any product, at its visibility (REQ-43) | The claim carries the severity recorded against the issue and the argument somebody wrote about it, so a row about an embargoed flaw is that flaw's disclosure. A refusal answers exactly as a name nobody has ever used, and a claim that fails it is absent from the list rather than refused |
| An issue that sits at no build here is exempt | It is nobody's secret, and refusing it would take away the half of REQ-29 that reaches products an issue has not met yet |
| The counts beside a waiting claim stop at the products the reader holds | Narrowing on visibility alone admits every disclosed finding in the deployment, so an approver holding one product was told how many findings the issue has elsewhere — a count of what somebody else ships |
| Rating something worse takes effect at once | Nobody needs protecting from being told something is worse than the world says |
| Rating it milder waits for a second person | Severity sets the deadline, and where a product has said what is worth triaging, a downgrade below that line takes the finding off the working list and off any clock |
| The published rating is never overwritten | A rating of ours shown where the world's goes reads as the world's. Both are on screen; ours is what ranks, what the triage line compares and what sets the deadline |
| A claim in force is written onto the issue as the rating in force | Everything that ranks, filters or clocks reads that one value with the published rating as its fallback, rather than each reader joining the claim and folding it its own way. Findings already open are reordered and re-clocked when it lands |

### What agreeing removes

Agreeing to "look at this in ninety days instead of seven" and agreeing to
"nobody will look at this" are not the same act. Which one it is depends on where
the rating lands, so the claim carries how many open findings the rating would
take off a working list, and in how many products.

| | |
|---|---|
| Counted per product | A line lives on a product and an assessment is about an issue. One issue can be above the line in one product and below it in another, so the honest form is a count rather than a yes |
| What is already below the line is not counted | Agreeing takes it off nothing |
| Narrowed to what the reader may see | That understates the effect for them, which is the right way for it to be wrong: the alternative discloses a count of undisclosed work |
| Worked out only for the claims that are waiting | Answering it for every historical claim would cost a query each to say nothing |

## Coverage count

The answer to making a decision says **how many findings it covers**, and **how
many distinct versions sit there**. A kernel issue reaches dozens of modules and
the answer is almost always the same for all of them, so without the count
somebody discovers afterwards that they answered for sixty-two things.

One version is the ordinary answer. More than one means the build ships the same
package twice at different versions under the same consumer, and a single
decision cannot honestly cover both.

## Reach across builds

How far a decision reaches is not one number.

| | What it is | What the person does |
|---|---|---|
| **Places in this build** | The same component under several consumers — the same code, the same versions | Nothing. One judgment covers all of them |
| **Other builds already matching** | Variants and branches whose upstream versions and chains are identical | Nothing. The decision reaches them by matching, not by copying |
| **Builds where the code differs** | The same issue at the same place, at another version | Chooses, one row at a time, each unchecked |

All-places-by-default and one-unchecked-box-per-match cover different axes: the
first is places running identical code, where making somebody answer sixty-two
times guarantees they stop reading; the second is builds running *different*
code, where a tick is a claim about a version nobody has looked at.

| Rule | |
|---|---|
| One action writes a separate record per target, each keyed to its own versions | What makes carrying acceptable at all. A dismissal carried onto an older branch lapses by itself the moment that branch moves |
| Nothing is withheld for sitting past the named fix | It would be the right rule and is not enforced: deciding whether one version sits past another needs per-ecosystem ordering that does not exist here. What is recorded instead is the case that needs no ordering — a version moved and the issue came with it |
| An approval names the reach, not only the words | The three parts are shown to the approver before they act, and how much the claim covered is counted at that moment and kept, because the number moves on its own: a branch cut next month shipping the same versions is covered too, with nobody having acted. Asking afterwards what a claim covers is a *different* question from what somebody consented to. One number is kept, not three — the split is presentation |
| One judgment covers every place it sits at by default (REQ-26) | The places are listed and ticked; unticking one leaves that place open, and nothing is asked about the places left out. Silence about a place is not a claim about it |
| Covering many places does not by itself require a second person | The alternative teaches people to make narrow judgments, which produces more records saying less |
| Grouping is presentation only (REQ-17) | One grouped action writes an individual record per place, and the group is derived when it is read. A stored group would describe a build that no longer exists within a scan or two |
| A list that is hiding something says so, with the count (REQ-30) | |
| Exceptions are grouped by the layer they come from (REQ-25) | A suppression a build supplied, a decision made here, and a finding below the line are three kinds of "not shown", and one flat list invites reading a build's own claim as a judgment this deployment made. Every kind of variant follows the same model — the machinery does not learn what kind of thing a variant is |

## Applying to other builds

A build running the same versions picks a decision up by lookup. What remains is
the builds where the versions differ, and somebody has to say whether the same
reasoning holds there. Differing is judged by the same expression the decision is
keyed on, and each such build is named with the version it ships, one entry per
version.

| Rule | |
|---|---|
| Offered one at a time rather than as one answer | A component may be used in a later release and not an earlier one. All-or-nothing would be a single click making a claim about builds nobody looked at |
| Builds already covered are counted and never offered | A judgment reaching eleven other builds is worth knowing; a tick box beside them asks somebody to agree to something that has already happened |
| Only the places nothing already stands at are written | A build wholly reached by lookup records nothing, and that is not an error |
| One request, one transaction, one claim | A failure part-way used to leave it recorded against some builds and not others — an act nobody performed |
| Bounded on the places it resolves to, not the builds named (REQ-27) | One name expands into as many places as the issue sits at there |

## Bulk claims

One action records the same judgment against a set of issues at one component —
one outcome, one justification, one reasoning, one approval — writing a separate
decision per issue, each keyed and expiring independently.

Grouping otherwise runs one way, one issue across many places. The transpose is
the case that breaks a queue: a kernel carries thousands of issues, most of them
in drivers a given image never builds.

| Rule | |
|---|---|
| A separate decision per issue **and** per place | A claim built from one place of an issue would silence one consumer and leave the rest open while reporting it had covered them |
| The places are resolved from the findings inside the writing transaction | A caller free to name a place would be choosing which decisions apply where, and a place read before the write is a fact about a database that has since moved |
| How large the claim is, is said before it is submitted (REQ-27) | |
| The claim may span more than one page of candidates | Selecting everything the narrowing matches fetches the rest rather than stopping at the page. A claim assembled a page at a time is eighteen claims where the person meant one |
| Every outcome a single claim offers is offered here | Deferred and already-fixed were missing and are exactly the bulk cases: a bump scheduled for the next release, and a distribution's backport |
| What is exploited or critical can be excluded before claiming | Take the bulk, hand-triage the handful the judgment should not cover |
| It always needs a second person, whatever the outcome | The short-deferral exception is about one finding somebody is putting off for a fortnight; one person answering hundreds in a single action is the case a second pair of eyes exists for |
| Two limits: how many issues a request may name, and how many findings it may write | Each name may sit at many places, so a limit checked against the names would let a request naming two thousand issues write sixty thousand rows |

The candidate list carries both numbers and the limit: how many issues the
narrowing holds, how many findings those sit at, and how many one action may
write. The second is counted over the whole narrowed set rather than summed from
a page. The screen counted in issues while the cap counted in findings, so a
kernel issue sitting at 45 places made a cap of two thousand mean about
forty-four issues, discovered after typing the reasoning. **Measured on a real
image, 805 candidates narrowed by hand became eighteen separate claims**, each
with its own outlier table.

**Whatever is offered to narrow the set — a weakness class, a subsystem named in
advisory text — is a starting point for a person, never a selection the tool
asserts is right.** No SBOM says whether a driver was compiled in, so this is a
claim somebody makes and signs for, with the kernel config or whatever else
supports it written into the reasoning.

**How the set was narrowed is recorded with every claim in it**, separately from
the reasoning. Narrowing is how a candidate was found; the reasoning is why the
claim is true. "These matched a word" is not a defense anybody would accept.

## Fix bundles

One row per bump with what it would close, and one act that answers the whole of
it.

A fix bundle is keyed on the upstream name, the version in hand, and the version
that fixes it (REQ-35), falling back to the component name where no upstream is
recorded. The version in hand is the upstream version where one is recorded. It
is presentation, like every other grouping here.

Measured on a real image: 5,047 fixable rows are 271 distinct bumps, and a single
kernel bump closes 917 of them. Keying on the upstream name collapses them
further — curl, `libcurl4t64` and `libcurl3t64` are one source package bumping
once — and that also answers the same issue at sibling packages, which is 2,831
of 7,612 rows on that image. It falls out of the key rather than being a second
feature.

| Rule | |
|---|---|
| No build appears in the key | A component shipped at the same version by two builds is one thing to decide about and two findings. The bundle proposes once per key rather than once per row it closes |
| Where the same place is undisclosed in one build and public in another, the single decision carries the stricter | |
| Everything it decides from is read inside the transaction | The builds the request names, which are past end-of-life, and the places the bump reaches are all reads, and a retry re-runs the closure against a database that has moved |
| One request, one transaction, one claim | Half of it written would be a pending upgrade that says a bump is declared for a release it is not, so the judgments and the fix targets are written together |

Proposing per row instead wrote the same key twice, and the second collided with
the index that keeps one claim standing per place, taking the whole transaction
with it: **every product with more than one build refused every bundle it was
ever asked to declare**, with a message naming a decision it had just written
itself.

It is safe at that size because of what it carries. The outcome hides nothing and
needs no second person, and a fix target is intent the next scan answers, so a
bundle that never lands is reported rather than quietly wrong.

## Promised work

| | |
|---|---|
| **`upgrade-needed` is about a component** | Carries the version it moves to and the date the work will be done, and is written in bulk for everything open on that component in the declared builds |
| **`patch-needed` is about one issue**, and the version does not move | The build's next inventory declares the patch it carries and says what that patch resolves, so the finding goes while the version stays. No version comparison could have found that |

Before these, the most common answer to a fixable finding — the package is being
upgraded — went in as `affected` with the plan in a separate record, so what
somebody decided and what a release was waiting on could come to disagree.

| Rule | |
|---|---|
| Neither is recordable at the other's grain | Naming an upgrade from a single finding is refused with the sentence saying where to record it instead. A backport naming a version is refused, because moving no version is the whole difference between the two |
| Both need the date | Otherwise there is nothing to gate against and nothing to lapse |
| Both can stand at once | A component under an upgrade can carry an issue the upgrade will not fix, and the issue-grain claim wins where they disagree |
| Coverage follows the source package | Naming any binary reaches all of them, and covers everything open on them, not only what records this version as its fix. Deciding that 3.5.2 also covers something fixed in 3.5.0 would need an ordering per ecosystem. A person claims the move answers what is open, and the scan says which of that was true |
| Recorded on the component's own screen | Ticking the releases the promise is for, naming the version and the date, and saying why. Ticking releases that need different versions is **two promises** |
| Saying who carries it is part of the act | A person or a team, in the same transaction, so a promise nobody carries and a holder with no promise are both impossible. The handover is product-wide, and the level that matters is the strictest in the set — one embargoed finding among fifty makes the handover a disclosure |
| The upgrade is reachable as a claim | Where its reasoning, its approval and the conversation about it already live |

**What it covers is derived, never marked.** A covered finding is one a standing
promise reaches, which the decision already records, so the mark is a join rather
than a tag across every row.

| | |
|---|---|
| The argument is grain, not cost | A tag here is per product, and could not say "planned on master, not on the 2.4 branch", which is the case the per-build target exists for. Derived, the answer is per build |
| Withdrawing a promise puts what it covered back | Nothing to clean up: there was never a second record to keep in step |
| It is offered as a filter and its negation | Asking for what is *not* covered is the working list once planned work is out of view, and a flag could not ask it |
| It is what the by-issue list asks unless told otherwise | Deciding covered work again one finding at a time is what the promise was made instead of. The by-component view is untouched, because that is where the upgrade is managed |
| The default is written into the address | A chip above the list like every other filter, removable by clicking, travelling with a link somebody sends. That is why the parameter has a word for "either" |
| Only the claim that currently stands counts | A promise that was withdrawn is not one |

### Approval gate

Both outcomes hide risk, which is the point: work with a plan and a date on it
should not come round again the next morning. What keeps them from being ungated
deferrals is **where the gate sits**.

| Where the date falls | |
|---|---|
| **At or before the earliest deadline among what the act covers** | No approval. Nothing is hidden for longer than the policy already allowed, and gating every planned upgrade would put the most routine act of all through the review queue |
| **Past it** | A second person agrees. The promise now defers the worst thing the act covers |
| **Measured over the whole set, not per finding** | One act covering a critical and a medium is gated by the critical. Gating each decision separately would let the same act stand for the mediums and wait for the critical |
| **Nothing the act covers has a deadline** | There is no date to be past, so the exemption has nothing to measure against and a second person agrees. A product below its own triage line is the ordinary case, and it was the one place a promise could hide a finding for years on one signature |
| **A commitment with no date at all** | Not a commitment |

**The deadline is resolved with the places, never supplied.** It is a fact about
what the act covers rather than something whoever is promising may state, and a
caller free to state it would be choosing whether their own promise needed a
second person. The same rule the visibility and the versions follow.

| Where it is read | |
|---|---|
| Recording a judgment on one finding | The earliest deadline among the findings at that place |
| Recording one across builds | The earliest across every place the act reaches, in every build named |
| Declaring an upgrade on a component | The earliest among the places the bump reaches |

There is one computation of it and it is the one the gate uses. A second
spelling, reachable only from its own tests, sat beside it and disagreed about
how the set was narrowed — two implementations of a separation-of-duties
threshold, one of which nobody executed.

The response says whether it is waiting, rather than leaving somebody to discover
it from the queue.

## Deadlines

A finding gets a deadline from how urgent it is, counted from when it was first
seen. **Being known-exploited has its own, and it is the shortest**, whatever the
severity says.

The clock runs on what nobody has answered. A dismissal takes a finding off it; a
deferral replaces the deadline with its own date.

Being late is reported and never acted on. The windows are settings, and the
shipped numbers are a starting point rather than a recommendation: a deadline
nobody agreed to, applied to everything, leaves the whole estate permanently
overdue and the signal ignored inside a month.

**Changing a window rewrites what is stored.** A deadline is written onto the
finding when it is first seen, so editing the policy is the one event that makes
every stored one wrong. The rewrite happens away from the request.

| Rule | |
|---|---|
| One replica rewrites at a time | Otherwise two replicas each rewrite the same rows from whatever each read when it started, and whichever finishes last wins |
| It reads the policy after its turn comes, not before | |
| A replica that loses the race waits rather than skipping | A policy somebody just changed has to be applied |

The other event that makes a stored deadline wrong is the issue becoming known to
be exploited, which is in `DESIGN-findings.md`.

## Lapse marking

A decision stops applying the moment its versions move, because what applies is
matched on them. What needs a mechanism is somebody finding out: without it the
finding reappears as though nobody had ever looked at it, and the reasoning sits
on a row nothing points at.

A scan, having just recorded the versions that moved, marks the judgments they
moved out from under, and those land in the review queue as work.

| Rule | |
|---|---|
| One statement, not one per place | A real image holds tens of thousands of places, and a sweep costing a write per place is a sweep somebody turns off, after which nothing lapses and the whole mechanism is decorative |
| A rebuild that moved nothing marks nothing | Rebuilds are nightly, so a sweep marking too much would unpick judgments nobody had revisited, every night |
| A decision covering nothing in the product is not marked | A component that is gone closed its findings. A component still present at a different version is exactly the question somebody has to answer again |
| Covering is asked of the product, not of the build that was scanned | One release stream moving while another still ships the version decided about leaves the decision covering the other. So a sweep marks only when this build holds the place at other versions **and** no open finding anywhere in the product still matches the decision's versions |
| Only the scanned build's product is swept | A place is a pair of names, the same pair sits in other products, and their decisions are theirs |
| The comparison uses the same expression that wrote the version | Shared rather than spelled twice. Two spellings is how a decision starts lapsing on one path and standing on the other |
| Failing to mark is reported and not fatal | What the scan found is recorded and correct; the marking is a prompt, and losing a scan over a prompt is the wrong trade |
| A decision lapses when *either* version moves | Marked once the last build in the product holding its versions has moved, not when the first does |

## Re-affirmation

Two people already agreed to the claim. A version bump is a prompt to re-check
rather than a new claim, so the person who made it may re-make it with a fresh
reason and no second approver. Requiring full approval on every bump produces
rubber-stamping, which costs the control its meaning everywhere.

Two things send it back for full approval:

| | |
|---|---|
| **Nobody agreed to the previous claim** | There is nothing to carry. Asked of the *agreements on the row* and never of its state: a claim lapses from proposed as well as from approved, so reading "lapsed" as evidence of agreement let one person propose a dismissal, wait for a version bump, re-affirm it, and have it stand needing nobody and appearing in no queue |
| **A severity that has risen since** | What was agreed was that this did not matter much; that is not an agreement about what it has become |

The reasoning is the re-affirmer's own and nobody else has read it, so the
agreement carried onto the new claim names the agreement it came from. What is
true is that somebody agreed to the earlier words on the earlier day, and that
is what the record now says — everywhere an approver's name appears against a
re-affirmed claim, it appears marked as carried.

The same question is asked twice — once to decide whether a second person is
needed, once to write the carried agreement — through one function, because two
spellings would eventually disagree and the disagreement is exactly the state
above.

| Rule | |
|---|---|
| A changed justification is not a trigger, because it cannot happen | A re-affirmation copies the justification off the claim it re-makes. Changing the reason is proposing a new claim |
| How bad it was judged to be is kept with the decision | An issue's severity is rewritten in place as reports revise it, so reading it now would compare a number against itself |
| A count of re-affirmations deliberately does not trigger it | That would fire on nothing having changed |
| What may be carried is read from the row, not from what a caller supplied | A caller holding a stale copy would carry an agreement since withdrawn; a caller inventing one would carry an agreement that never existed. A withdrawn decision keeps its approval rows, so without this a version bump would undo a withdrawal |
| All of it is one transaction | Written as three steps, a process stopping in the middle left a claim standing that nobody had agreed to and that no review queue would show |
| The carried agreement is guarded on the revision | An agreement is an agreement to particular words |

## Comments and reasoning

| | Revising the reasoning | Adding a comment |
|---|---|---|
| The approval standing on it | Withdrawn | Untouched |
| What it said before | Kept and readable | Kept and readable behind an "edited" mark |

| Rule | |
|---|---|
| What is kept is the text it stopped saying | Written at the moment it is replaced. The comment row holds what it says now; the history holds what was being lost |
| Both writes go together | An edit that succeeded beside a history write that did not would leave a record saying a comment was changed and nothing saying from what — worse than the state it replaces, because it looks like a history and is not |
| The history is read only when somebody asks | The current text is what a reader is reading |
| Who may read it is asked of the claim, not of the comment | Asking twice is one question with two answers waiting to disagree |
| Nobody else may edit somebody's words | An edit anybody could make is a forgery with a timestamp |
| Being allowed near the claim is settled before anything about the comment is said back (REQ-42) | The row has to be read first, because the claim it hangs off cannot be known otherwise, but no answer turns on what was in it until the asker has been let in. Refusing on authorship first made "that is not your comment" and "there is no such comment" two different answers, so anybody holding triage anywhere could walk the identifiers |
| Every field somebody types into runs through the same policy before storage | The reasoning, a revision of it, and a comment. `DESIGN-text.md` says what that policy is |

## VEX statements as evidence

**It is called VEX rather than "supplier"** (REQ-31), everywhere: the publisher,
the status, the import, the filters. The old word described who tends to publish
rather than what the thing is, so an empty panel read as "nobody has an opinion
about this" when it meant no document had been uploaded. The emptiness is stated:
the panel says there is nothing and says why.

It is a third layer, beside the claims a build supplies with its inventory and
the decisions made here. The screen says what the build claims, what the
distribution says, and what we decided — three statements, not one collapsed
answer. Applying a VEX statement by itself would put a third party's claim into a
number somebody here quotes.

**What the document adds is the reasoning.** The status is already in the fix
state the scanner reports; the reasoning is what a triager otherwise types from
memory and an approver has no way to check.

Filterable by what a statement said and by which publisher said it. 1,113 of
1,125 no-fix findings on a real image are distribution packages, and a
distribution publishes machine-readable judgments about exactly those. Found,
they are an afternoon; unfound, they are retyped one claim at a time.

| Rule | |
|---|---|
| A distribution declining to fix is not a distribution saying it is not affected | Debian's `no-dsa`, Ubuntu's `ignored` and Red Hat's will-not-fix all mean *affected, and judged minor*, so they prefill a won't-fix and never `not-applicable`. A publisher saying they have not decided offers nothing at all |
| The statements are resolved once, never asked per row | There are far fewer statements than findings, so the cheap direction is to work out which pairs the statements name, once, and join the list to that. Distinct on the pair, by `UNION` rather than `UNION ALL`, so joining cannot multiply a finding by the number of statements about it |
| The issue's identifier is folded on write, like every other typed name | A published identifier arrives in whatever case its reporter chose and a statement arrives folded, so without a folded column the two could only be compared through a function — and a function on the indexed side is an index nobody can use |
| Only what stands narrows | A statement set aside by a later document from the same publisher stops answering the filter, while the superseded row stays readable: an approval granted on the strength of it has to remain explicable |

As a correlated `EXISTS` over three subqueries evaluated per candidate finding,
the filter **did not return inside five minutes on a demo image of 281,884
findings and 1,854 statements**, and held a core for minutes after the request
was abandoned.

*This does not contradict rejecting abandonment as a triage signal.* That
rejected the **absence** of a fix, which describes nearly the whole population.
This is the **presence** of a published judgment, made by a security team, about
that issue in that package.

## Dates still to come

A deferral returns on a date, and promised work lands on one. Both are refused
at or before the moment the claim is being made.

| | |
|---|---|
| A deferral until a date already gone | Takes the place's live key so nobody else may decide there, suppresses nothing, and arrives in the review queue already run out — a work item the tool made for itself |
| Promised work due on a date already gone | Worse, because the gate asks whether the date is past the deadline the work already has and a date in the past never is. The promise stands on one signature and hides the finding for good |

Checked where every write path inherits it rather than at each of them, which
is how the two acts that build a claim without going through the ordinary
entry point came to write claims nothing had looked at.

## Mitigation-based dismissals

Choosing `inline_mitigations_already_exist` requires saying what actually stops
it — the rule, the setting, the service that is not exposed.

Every other recognized reason for something not applying is a claim about code,
and code is what makes a decision lapse. This one is a claim about
**configuration**, which can be removed with no version moving at all. **Nothing
here watches configuration, and nothing expires this claim.**

Naming the control does not close that gap. It is the difference between a claim
somebody can go and check and one nobody can, and it is the justification an
auditor asks about first, because the protection lives outside this software
entirely.

## Outcomes on a tag

A tag never moves. **An outcome may state a fact about it; it may not carry a
date.**

| Allowed | Refused |
|---|---|
| affected, not applicable, will not fix, already fixed here | deferred, upgrade needed, patch needed |

The three refused are exactly the three that store a date, so the check asks
whether the outcome carries one rather than keeping a list beside the list of
outcomes. It is not the same question as whether an outcome commits to work: a
deferral's date is a review date rather than a commitment, and it is as
meaningless against a release that will not move as the other two.

What is left is the whole point of triaging a tag — saying what is true of what
somebody received.

Whether a place sits on a tag is read from the finding, like its visibility,
rather than supplied by whoever is deciding: what may be said about a place is a
fact about the place.

## Tags

**A finding takes free-text tags** (REQ-57), filterable, with no fixed
vocabulary. At a dozen products and thousands of findings people mark work
regardless — customer-escalated, release-blocker, waiting on a vendor — and with
nowhere to put it they put it in the reasoning, where nothing can filter on it
and where an approver reads it as part of the argument for the claim.

No vocabulary is fixed, because none has been earned. A tag that becomes
universal is a signal rather than a success: "waiting on vendor" has a subject,
an expected reply and a staleness of its own, and leaving it as a string is how
it stays unreasonable-about forever. What is in use in a product is offered back,
most-used first, which is both what a filter suggests and the evidence for
promoting one.

| Rule | |
|---|---|
| What is in use is narrowed to findings the asker may read | A mark carries no visibility of its own, and free text typed while triaging an embargo says what the embargo is about: "waiting on the reporter" beside an undisclosed issue is the disclosure |
| At the grain somebody looks at | One issue, in one component, in one product. Not per place — a kernel flaw at sixty places is one thing somebody is marking — and not per build, because a tag is about the work rather than a release |
| Matched without regard to capitals and shown as it was typed | Showing the folded form back would read as the tool having rewritten what somebody wrote. Marking what is already marked succeeds and keeps the first spelling |
| Marking is triage | A tag changes what a filtered list answers. Somebody who may only read sees the marks and is not offered the control, because a control offered and then refused teaches people to distrust the ones that work |
| On the row, not only on the finding | The marks come back with each group, read for the whole page in one statement, and each is itself a filter |

## Rule-prepared claims

**A rule produces a saved filter and a prefilled outcome, justification and
reasoning. A named person submits it as their own claim, and a second person
approves it** (REQ-27).

| Rule | |
|---|---|
| It is the saved filter, not a second object | A rule here is a narrowing plus what to say about what it catches. A table of its own would make "the filter" and "the rule" two things to keep pointing at each other |
| The reasoning is required where an outcome is | A prefill with an empty argument is a button that proposes a dismissal saying nothing. Nothing prepared is nothing carried |
| Saving over a name takes the old prefill with it | The act is deciding what that name means now, and one that survived would fire on a filter somebody had made ordinary |
| It proposes nothing by itself, and the screen says so | Picking the filter fills the decision form; submitting it is a person's act, and the record carries their name |

The wider form — a rule proposing a pending claim of its own, marked as proposed
by that rule — leaves the approver as the only human judgment on the claim, and
puts a configuration file where a name belongs in the record. The difference
shows up on the day a dismissal turns out to have been wrong and somebody asks
who made it.

## Carrying onto a new line

What a new line would inherit is shown before anything happens, and what moved is
chosen rather than taken (REQ-25). Four groups, because they need four different
things: what already applies has nothing to agree to, what covers nothing here
has nothing to apply to, what moved is a question, and what was postponed is a
question that carries its own history.

**Reasoning travels and conclusions do not.** Everything carried arrives as a
claim waiting for a second person, however confident whoever carried it was: the
version moved, which is what made the old judgment stop applying. Making somebody
start from a blank page is how a tool teaches people to stop writing reasoning at
all.

| Rule | |
|---|---|
| Only what was offered may be carried | Naming a judgment the preview classified as already applying, or as covering nothing here, is refused rather than skipped: a caller that got the set wrong should hear so |
| The place is read from the new line, never copied from the old claim | The versions are what a decision is keyed on and they are the thing that moved |
| A deferral carries the date it had | Quietly moving it forward would be the tool making the judgment it is asking for. The total it has already run for is shown beside it, because that is what agreeing to it again agrees to |
| **A judgment whose date has gone by is not offered** | It carries its date rather than having it moved forward, so carrying one that has run out writes a claim finished the moment it lands. Offering it is offering something the act behind the button turns down |
| **What is carried is checked like anything else written** | It built a claim and went straight to the writer, so nothing asked whether what it carried could be said at all — and the place it built never read whether the new line was a tag, which is the one rule this act can break that no other can |
| Bounded, and written in one transaction | Carrying six judgments is one act, and half of it landing is a line nobody can tell from one somebody chose that way |

## Not built

| | |
|---|---|
| Choosing a narrower set than "all of them" when a judgment covers many places | An interface question. What exists is the count, which is what makes the choice an informed one when it arrives |
| Nothing refuses a deferral for being long | The cumulative threshold is the whole of the refusal. The pattern is reported instead, at `/v1/deferrals/repeated`: one item deferred three times is a judgment, and forty of them is a policy nobody wrote down. A deliberate absence of a rule rather than a gap |

**A deferred item is never published as not-affected**, and the rule is built
where the outbound documents are: the VEX generator takes only approved
`not-applicable` and `already-fixed` claims, so a deferral is absent rather than
published as anything, and silence in that format already reads as affected.

## Limits

| | |
|---|---|
| A version nobody stated and a version that is empty are different | Both occur, and comparing them as equal would let a decision made about a component with no known version stand over one whose version is merely blank. Two absences match each other and nothing else |
| The claim and its first reasoning are written together, in one transaction | A claim with no reasoning is not something a second person can agree to, and leaving the reasoning to a later write is how an item reaches the queue with nothing in it to review |
| A decision that has lapsed is found by the structural half of its key alone | That is what lets the reasoning behind it be offered back to whoever has to make the judgment again |
| The names in a request are resolved against what was scanned, never taken as given | A caller who could name a place freely would be choosing which decisions apply where, and the versions a decision is keyed on come from the rows for the same reason |
| An issue is named by any identifier it is known under | Somebody who read a national identifier in an advisory and somebody looking at a report that used a database's own identifier are asking about the same thing |
| Whether a claim is waiting for a second person is answered when it is made | A short deferral takes effect at once, and somebody who has just written one should be told rather than left watching a queue |
