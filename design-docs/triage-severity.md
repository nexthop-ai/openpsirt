# Minimum severity and ratings

What a deployment and a product consider worth triaging, a product's own rating
of an issue, and the deadline windows. Each rewrites what is stored when it
moves.

Satisfies REQ-15, REQ-29, REQ-30, REQ-33, REQ-42, REQ-43.

## Contents

- [Minimum severity](#minimum-severity)
- [Issue assessments](#issue-assessments)
- [Deadline windows](#deadline-windows)
- [Limits](#limits)

## Minimum severity

A deployment states its **minimum severity**, the least severity it considers
worth triaging (REQ-30). Below it a finding is still recorded, counted and
reportable, and is out of the working list: five thousand findings is a list
nobody reads, drowned by what nobody was going to act on.

| Rule | Reason |
|---|---|
| Nothing is hidden until somebody sets one | A tool hiding findings on the day it is installed decides what nobody asked it to |
| It is compared against our rating where one stands | Saying a published rating is wrong is pointless if ranking and filtering ignore us |
| An unrated issue is judged as a medium, the folding the deadline uses, spelled once | Two rules reading one fact disagree: on a real image 91,040 findings rated "unknown" dropped out of the working list and off any clock |
| Exploitation is never below the minimum severity, from either signal: a feed's word about the world, and this product's own incident | A minimum severity is how bad something must be to be worth an afternoon, and exploitation is a fact |
| Below the minimum severity nothing is on a clock | A minimum severity says "this is not work" and a deadline "this is work, and late"; within a year the overdue figure is thousands nobody meant to look at |
| Nothing on a release out of support is on a clock either (REQ-15), applied separately | It reaches further: a minimum severity never sets aside something exploited, while end-of-life says nothing here will be fixed |

A product may state its own: products differ in what they can afford to ignore,
and one number for an estate is too strict somewhere or too loose elsewhere.

| Rule | Reason |
|---|---|
| A product with no opinion inherits rather than copies, and clearing a product's minimum severity is its own act | A product storing the deployment's current value stops following it, and nobody sees |
| Stating one is administration, the authority that sets the deployment's | It hides findings, the act everything else here gates |
| Moving either rewrites what is stored, away from the request and one replica at a time | `design-docs/queue.md` |

## Issue assessments

A published rating can be wrong for a product: the score assumes a
configuration it does not ship, or the world has not rated it and it is read as
a medium. An **assessment** is about the issue and belongs to one product
(REQ-29). Keyed to an occurrence it repeats at each and lapses on unrelated
version changes; keyed to nothing it is one statement for the deployment.

| Rule | Reason |
|---|---|
| A rating belongs to one product and reaches every build of it (REQ-29) | A rating assesses how a component is used, and one product may ship the vulnerable configuration while another does not |
| Two products may hold different live ratings of one issue, and neither reaches the other | |
| Nothing inherits: a product nobody rated the issue in reads the published rating | A rating arriving from a product a team cannot see is what this shape removes |
| Making, agreeing to and taking back one ask for the role on that product (REQ-29, REQ-42) | A rating sets the deadline and can push a finding below the minimum severity; asked anywhere, somebody holding one product moves both in a product they cannot see |
| Every act on an assessment asks whether the person may read a finding of this issue in that product, at its visibility (REQ-43); a refusal answers as a name nobody has used, and a failing assessment is absent from the list | The assessment carries the recorded severity and an argument, so a row about an embargoed flaw is its disclosure |
| An issue the product carries no finding of is refused as a name nobody has used | It is not the product's to rate, and the route does not reveal which issues a product ships |
| The list asks it from the issue's own row: the findings are reached through the issue the assessment is filed under and those held under the issue it is read as | Asked from the product's findings, each assessment reads them all: 5.4 s against under 5 ms for 306 assessments on PostgreSQL |
| The counts beside a waiting assessment stop at what the reader may see, inside the rating's product | Narrowed on visibility alone, an approver of one product is told how many findings the issue has in what somebody else ships |
| Rating something worse takes effect at once | Nobody needs protecting from being told something is worse |
| Rating it milder waits for a second person, on that product | Severity sets the deadline, and a downgrade below the minimum severity takes the finding off the working list and any clock |
| Milder is judged against the published rating | What needs a second person is hiding something the world called bad; judged against the product's current rating, the next step down goes unwatched |
| The published rating is never overwritten; both are shown, and the product's ranks, meets its minimum severity and sets its deadline | Ours shown in the world's place reads as the world's |
| An assessment in force is written as the rating in force for that product, read with the published rating as fallback; the product's open findings are reordered and re-clocked when it lands, and no other product's are | Every reader joining and folding the assessment its own way disagrees |
| A finding opened later picks the product's rating up, read by the applying path for the build's product as it opens findings | A copy on each finding carries it only where something remembered |

### The cost of a per-product rating

| Cost | Detail |
|---|---|
| No rating reaches a product the issue has not met | An issue arriving somewhere new arrives unrated; rating ahead of an issue was given up with the deployment-wide rating |
| No one place says a published score is simply wrong | A score assuming the wrong configuration is wrong the same way in three products, and three teams say so, so the products that differ can differ |

### Effects of agreement

Agreeing to "look in ninety days instead of seven" and to "nobody will look"
differ by where the rating lands, so a waiting assessment carries how many open
findings it would take off a working list.

| Rule | Reason |
|---|---|
| Counted in the rating's own product | That is all it reaches |
| What is already below the minimum severity is not counted | Agreeing takes it off nothing |
| Narrowed to what the reader may see | It understates for them, the right way to be wrong: the alternative discloses a count of undisclosed work |
| Worked out only for waiting assessments | |
| Worked out for a page at once: the ratings, which issues the reader may be told of, each product's minimum severity, then one grouped read of the findings; each rating still counts its own issue in its own product | A rating at a time, a page of fifty is 263 statements and 0.32 s, 20 ms of it the database |

## Deadline windows

A finding's deadline comes from its urgency, counted from when it was first seen
(REQ-33). Being known exploited has its own window, the shortest, whatever the
severity says. `design-docs/remediation.md` § Deadlines holds when the clock
starts and which findings carry none.

| Rule | Reason |
|---|---|
| The clock runs on what nobody has answered: a dismissal takes a finding off it, and a deferral replaces the deadline with its own date | |
| Being late is reported and never acted on | |
| The windows are settings, and the shipped numbers are a starting point | A deadline nobody agreed to, applied to everything, leaves an estate permanently overdue and the signal ignored within a month |
| Changing a window rewrites the stored deadlines, away from the request | A deadline is written when a finding is first seen, so editing the policy makes every stored one wrong |
| One replica rewrites at a time, and reads the policy after its turn comes | Two replicas each rewrite from what they read, and the last to finish wins |
| A replica losing the race waits rather than skipping | A policy somebody just changed has to be applied |

The issue becoming known exploited also makes a stored deadline wrong
(`design-docs/findings-severity.md` § Urgency).

## Limits

| Limit | Detail |
|---|---|
| A product's rating, minimum severity and deadlines are stored, so each move is a rewrite | Every reader reads one stored value; the price is a rewrite away from the request whenever a policy or rating moves |
