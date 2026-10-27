# Minimum severity and ratings

What a deployment and a product consider worth triaging, a product's own rating
of an issue, and the deadline windows. Each rewrites what is stored when it
moves.

Satisfies REQ-15, REQ-29, REQ-30, REQ-33, REQ-42, REQ-43.

## Contents

- [Minimum severity](#minimum-severity)
- [Issue assessments](#issue-assessments)
- [Deadline windows](#deadline-windows)

## Minimum severity

A deployment states its **minimum severity**, the least severity worth triaging
(REQ-30). Below it a finding is recorded, counted and reportable, and out of the
working list.

| Rule | Reason |
|---|---|
| Nothing is hidden until somebody sets one | |
| It compares against our rating where one stands | |
| An unrated issue is a medium, the folding the deadline uses | On a real image, two foldings left 91,040 "unknown" findings off the list and off any clock |
| Exploitation is never below it, from a feed or from this product's incident | Exploitation is a fact, not a severity |
| Below it nothing is on a clock | Otherwise the overdue figure fills with what nobody meant to look at |
| Nothing on a release out of support is on a clock (REQ-15), applied separately | It reaches exploited findings too |
| A product may state its own, and one stating none inherits rather than copies; clearing it is its own act | A copy stops following the deployment unseen |
| Stating one is administration, the authority setting the deployment's | It hides findings |
| Moving either rewrites what is stored, away from the request, one replica at a time (`design-docs/queue.md`) | |

## Issue assessments

A published rating can be wrong for a product: its score assumes a
configuration not shipped, or nobody rated it. An **assessment** is about the
issue and belongs to one product (REQ-29).

| Rule | Reason |
|---|---|
| It reaches every build of its product and no other product; two products may hold different live ratings | One may ship the vulnerable configuration and another not |
| Nothing inherits: an unrated product reads the published rating | |
| Making, agreeing to and taking back one ask for the role on that product (REQ-29, REQ-42) | A rating moves the deadline and the minimum severity cut |
| Every act asks whether the person may read a finding of the issue in that product, at its visibility (REQ-43); a refusal answers as an unknown name, and a failing assessment is absent from the list | It carries an argument about a possibly embargoed flaw |
| An issue the product carries no finding of is refused as an unknown name | The route must not reveal what a product ships |
| The list reaches findings from the issue's row, through the issue filed under and the issue read as | From the product's findings: 5.4 s against under 5 ms for 306 assessments on PostgreSQL |
| Counts beside a waiting assessment stop at what the reader may see in its product | |
| Rating worse takes effect at once; rating milder waits for a second person on that product | A downgrade can drop findings below the minimum severity |
| Milder is judged against the published rating | Against the current one, the next step down goes unwatched |
| The published rating is never overwritten; both show, and the product's ranks, meets its minimum severity and sets its deadline | |
| An assessment in force is written as the product's rating in force, the published rating its fallback, and the product's open findings are reordered and re-clocked when it lands | One stored value every reader reads |
| A finding opened later takes the product's rating as it opens | |

### The cost of a per-product rating

| Cost | Detail |
|---|---|
| An issue arriving in a product arrives unrated there | No rating reaches a product before the issue does |
| A published score wrong everywhere is corrected per product | Three teams say it three times |

### Effects of agreement

A waiting assessment carries how many open findings agreeing would take off a
working list.

| Rule | Reason |
|---|---|
| Counted in the rating's product, excluding what is already below the minimum severity | |
| Narrowed to what the reader may see | Understating beats disclosing a count |
| Worked out only for waiting assessments, for a page at once: one grouped read after the ratings, readable issues and minimum severities | A rating at a time, fifty take 263 statements and 0.32 s |

## Deadline windows

A finding's deadline comes from its urgency (REQ-33), on windows that are
settings; `design-docs/remediation.md` § Deadlines holds when the clock starts
and which findings carry none. Being known exploited has the shortest window,
whatever the severity.

| Rule | Reason |
|---|---|
| A dismissal takes a finding off the clock; a deferral replaces the deadline with its date | |
| Lateness is reported, never acted on | |
| The shipped windows are a starting point | A deadline nobody agreed to leaves an estate overdue and ignored |
| Changing a window rewrites stored deadlines, away from the request | Deadlines are written when a finding is first seen |
| One replica rewrites at a time, reading the policy once its turn comes; a replica losing the race waits | Two would each write what they read |

Becoming known exploited also re-clocks an issue
(`design-docs/findings-severity.md` § Urgency).
