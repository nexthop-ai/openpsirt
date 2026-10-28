# Finding screen

The finding screen, the decision form on it, the reach sheet a decision passes
through on submit, and where every act confirms its answer.

Satisfies REQ-13, REQ-18, REQ-25, REQ-26, REQ-28, REQ-29, REQ-57, REQ-59, REQ-60, REQ-69.

## Contents

- [The finding screen](#the-finding-screen)
- [The decision form](#the-decision-form)
- [The reach sheet](#the-reach-sheet)
- [Answer placement](#answer-placement)
- [Limits](#limits)

## The finding screen

The finding is the working screen before a decision and after it.

| State | Carries |
|---|---|
| Before a decision | What the issue is, how bad, what upstream has done, where it sits, the evidence, the assessment, the decision form |
| After | The standing decision in its state, with outcome, justification, scope and who agreed to which revision, the acts that fit the state, and its comments at the foot of its card |
| Under both | The dependency path in its own pane below triage; the notes on this issue in this product; one activity timeline of proposal, revisions, approvals and comments; the revision history marking which revision each approval named; earlier decisions here, offered back as "reuse this reasoning" |

### Layout

| Rule | Reason |
|---|---|
| Evidence full width, then the action full width beneath it, both above the fold | The narrow column of a side-by-side layout reads the evidence at 380 pixels beside an empty text area |
| The description is full width (REQ-60, as amended) | In a narrow column it runs four words a line |
| The rating sits in the severity block, under the words it disagrees with | It is changed where it is read |
| The references sit above the received VEX, at the head of what is read to decide | A write-up is read first, and a third party's claim against it |
| What the build says is a card above the received VEX, shown whatever is decided | A mark the build put on an occurrence stays |
| What is neither evidence nor action (the timeline, revisions, comments, holder, assessment) stays below | |
| Triage is one pane: who is dealing with it and what was decided. With nothing left to decide the form is not drawn and the assignee stands alone | Reassigning a decided finding is ordinary |
| The identifier in the heading opens the issue screen | Everywhere this issue sits |

### Screen parts

| Rule | Reason |
|---|---|
| It says when it runs out and who holds it | |
| It says how many of its occurrences are decided (REQ-57); the count the build argued away in its own VEX does not stand in | That reasoning is not ours |
| It states how the match was made and where it came from (REQ-13), and nothing where the scanner said nothing | Unknown is not unconfirmed |
| Where to read about it is derived from the identifiers on the server at read time (REQ-18): the issue's record, each alias's, the packaging distribution's answer, the package's page; apart from the scanner's links, empty where a name resolves to no known scheme, fetched from nowhere | A machine client gets the same list |
| Where it sits shows the chain | One parent is reached by several routes |
| Where upstream currency is on (REQ-69), it says what upstream released and when; where an issue was named a full year after the last release and is unfixed, that is why there is no fix, never a claim the project is abandoned. Off, the panel is absent | Two year-numbers make five weeks look like five years |
| The references are cut at twelve, patches first, then advisories and reports; the rest are a control away, with how many | |
| A shortened description is cut at a whole character with a mark after it | |
| A patch link carries the branches its commit is on once its repository was asked: three by name in version order, the rest counted, all on hover; a commit the repository lacks says so; not yet asked carries nothing (`design-docs/findings-patch-branches.md` § Display) | "Not yet" is no fact about the patch |
| A publisher's claim carries the version it was made about, is shown at every version, and offers to fill the form only at that version | An advisory names the fixed version, not the shipped one |
| An upstream's statement says what it is here (applying by itself, offered for review, or declined), links the upstream's document where the address may be sent to a reader, and offers a triager decline or take back (`design-docs/upstream.md` § Declined statements) | |
| An occurrence a supplier's statement answers on some routes says so at the end of its way down, naming the supplier's product, the supplier on hover | Open and not work; the routes outside are what is left to judge |
| The rating form offers the four bands; a published "negligible" or "none" opens it on medium | Nothing it offers is milder than either |
| A recorded flaw is closed from its own finding screen, the only kind offered the control; the panel says nothing else closes it and nothing reopens it | A scanner's finding is resolved by scans |
| Starting an advisory mints one name, kept once it exists, and names the flaw once; a failed later step retries from where it stopped | A retry spends no second number |
| What belongs to one finding is reset on walking to the next: the confirmation, the decision being extended, the rating form, the incident forms | The screen is not remounted on an address change |

### What the build says

One entry per claim the build still makes covering an occurrence shown: whose it
is (the build, or the publisher whose document named the build as its product),
the status, the component and version it names, the product it names the
component as shipped inside, the justification, and the build's words. Where it
says the flaw applies, the words are labeled the workaround. The words are a
third party's: shown, never rendered. The list's "Build says" filter asks for
these, and its "affected" gathers the workarounds.

### The dependency path

| Rule | Reason |
|---|---|
| The first six ways down are shown; the rest unfold from a secondary button naming what it adds, "Show 24 more", then "Show fewer" | Somebody deciding whether to click wants how many they have not seen |
| The link into the tree sits apart at the row's far end; the row wraps at a phone's width | Two inline controls read as one run of text |
| One row per occurrence (`design-docs/findings.md` § Work across builds) | |

| Situation | Drawn as |
|---|---|
| A named consumer, walkable to the build | The whole chain, build first, component last |
| The build contains it directly | A chain of two: the build, the component |
| A named consumer nothing places | The consumer, then the component under it, "nothing recorded what pulls this in" on the consumer |
| The inventory placed it nowhere | The component, with "nothing recorded what pulls this in" |

### Notes and comments

The notes and the decision's comments are two threads (REQ-29) in two cards, drawn
by one thread component with each caller's own words; two editors in one card
read as one form.

| Thread | Shown | Says |
|---|---|---|
| Notes | Always, in a card of their own | It is about this issue in this product, every build of it, no other product, and not this component alone. Writing one changes no rank, deadline or triage, said beside the button |
| Comments | Where a decision exists, on each decision's card | About the argument at this occurrence |

The issue screen carries the notes a product at a time, a product picked where
the issue sits in several, because a note belongs to one product.

| Rule | Reason |
|---|---|
| A comment is rewritten in place by its author alone, the box opening on the stored text | A copy would return as an unsent draft |
| A link naming a component ambiguously offers the choices, each with ecosystem and namespace: the components this issue is open at, or every component of that name, each list saying which | A name and version are not unique |
| The refusal offering the choices is not asked again | A retry cannot change the build |
| A decision's scope names up to three locations, then how many more | A kernel sits at sixty |
| An approved decision at the same component and consumer is offered to a new issue (REQ-28) with "apply decision #N", recorded as an extension, still needing a second person | |

## The decision form

Nothing is chosen for the person (REQ-59 and REQ-60). The outcome and the
justification open unselected, and submit is refused until each question asked
has an answer: a justification is a claim about our build, and "affected" is a
claim too.

| Rule | Reason |
|---|---|
| The deferral threshold is a number on the form | Its side decides whether a second person agrees |
| A deferral is forecast against what its occurrences were put off for already: the finding carries each occurrence's total, the form adds the largest it covers, both measured to the moment in days and parts of a day; reaching the threshold exactly waits | The server compares durations, so thirty days picked after midnight is short |
| A promise to act by a date is forecast against the earliest deadline it covers: by it, it stands alone; later, it waits. It is not called a dismissal | |
| It names the next missing answer beside the button; one rule decides that sentence and the refusal | A disabled button never says what |
| Ctrl+Enter submits from inside the form only, says so, and asks what the button asks; nothing is sent while a submission is in flight or the review sheet is open | A comment box on the screen keeps its keys; no double post |
| The last outcome and justification are offered as a button saying what it fills, per session, never applied | A prefilled decision can say what nobody meant |
| A justification is shown with a label and one-line meaning (REQ-60), its token on the title | The token ships to customers as our claim; an approver checks it |
| One vocabulary carries the labels; both choosing forms read it and every display goes through one renderer; a test asserts every allowed value is listed with a label that is not its token | |
| Whom the statement holds for is offered unchosen: the reason decides, or anyone shipping this version, or this build only; the select's title says which reasons decide which. Not offered on a deferral. Kept with the draft | |
| The form is rebuilt when what it decides changes, a scope change included | Otherwise it offers one build's answers against another |
| The second-person hint reads the outcome's published class (`design-docs/interface-look.md` § Interface-wide rules): an outcome hiding no risk needs nobody, and one hiding risk with no date always waits for a second person. Of the dated ones it tells a deferral from a promise by name | Their dates are measured against different things |

Which locations a decision covers is a summary with an exception (REQ-26): "all
62 locations"; "exclude locations" opens the list grouped by consumer, the axis
of applicability, with a group checkbox reading mixed when partly out and a
filter box past a dozen. It reads back "59 of 62, three left open under X".

| Rule | Reason |
|---|---|
| The filter narrows what the group checkbox acts on | It decides what a decision covers |
| The count beside the name is read off the same rows, and a consumer matching nothing is not drawn | The number says what the click does |

## The reach sheet

A guided review on submit (REQ-25), never a list of checkboxes. It opens on a summary: this build, builds
covered automatically, builds at other versions, any not offered. Builds at
other versions are one list, unticked to start and ticked where the reasoning
holds there, because a tick is the decision. Two steps (where it applies, then
confirm), Enter to advance, Escape to leave, arrows to move; the last step lists
what will be written, and only then is anything sent.

| Rule | Reason |
|---|---|
| A build is one entry, however many occurrences reach it; a build at another version is one entry per version | Each version is a separate decision |
| The decision here is recorded first, then each build applied in turn, narrowed where occurrences were excluded; a refusal on one does not decide the rest | |
| The reach is answered whole, never sampled | What is offered is what is written |
| The review step is skipped where no build holds this issue at another version; builds already matching are named in the confirmation | At about 150 decisions a day, some 300 keystrokes confirm nothing |
| This build is counted in consumers, the scope control's unit; what is written in occurrences. A build at another version is counted in occurrences | Its consumers are not read |
| An unread reach is not an empty one: the sheet is skipped only when every read succeeded | |
| Every build at another version is offered | The reach read does not order versions |

## Answer placement

Each act confirms where it happened and offers its next act as a link. The
confirmation is never a toast, and nothing navigates away.

| Act | Confirmed | Offers |
|---|---|---|
| Deciding on the finding screen | Directly above the card it produced, brought into view once drawn | The next finding, and the decision's page where it waits |
| Deciding from a row's preview | Under the row while listed, in its place once a re-read drops it, at the page's end or over the empty list where neither it nor the next row is listed; the cursor moves to the following row | The decision's page where it waits |
| A bulk decision | Above the submit button | The decision's page |
| Promising an upgrade on the component screen | In place of the form | The decision's page where it waits; each build's planned upgrades for three or fewer, else the release they share, or the product's releases where they span several |
| Moving a disclosure date or disclosing | On the row or notice acted from, above the list where the row left it | The queue's disclosure dates where it waits |
| Rating an issue | On the rating line the form opened from | The queue's ratings where it waits |
| Reaffirming | On the card or tab acted from | The re-made decision's page where it waits; from the tab, each waiting page for three or fewer, else Mine, recent |
| Changing a missed promise | On its queue card | The decision's page |

| Rule | Reason |
|---|---|
| Waiting for a second person is said only where one is needed | |
| A decision in force at once offers nothing past the next finding | |
| The finding screen's confirmation follows the card | Submitting hides the form and the received VEX, about 900 pixels |

## Limits

| Limit | Detail |
|---|---|
| Where a fix will land is not on this screen | The promising decision names its releases; the release and the build's waiting list say what became of it |
