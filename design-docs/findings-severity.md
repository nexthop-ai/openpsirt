# Severity and urgency

How a score is computed, how severities compare, which rating is in force for a
product, and how findings are ordered.

Satisfies REQ-29, REQ-32, REQ-33.

## Contents

- [Scoring](#scoring)
- [Weaknesses](#weaknesses)
- [One ladder for every scheme](#one-ladder-for-every-scheme)
- [The severity ladder](#the-severity-ladder)
- [The rating in force](#the-rating-in-force)
- [Urgency](#urgency)
- [Limits](#limits)

## Scoring

| Rule | Reason |
|---|---|
| A score is never taken alongside a vector | Two values stated separately can disagree. The number sorts; the vector is what somebody argues with |
| Base metrics only | Temporal and environmental scores describe somebody else's deployment |
| The formula lives on the server; a screen asks the scoring operation | Two implementations disagree eventually. The operation reads and writes nothing and takes any recognized credential |
| Versions 3.0, 3.1 and 4.0; anything else refused by name | Version 2 is a different scheme |
| Version 3 rounds up to a tenth in integer arithmetic; version 4 rounds to the nearest tenth | Floating point turns 8.6 into 8.7 |
| An unstated vector is no score, never zero | Zero says harmless |
| A severity may be left unstated (REQ-18) | A forced choice stores a guess. A flaw recorded here then carries no deadline and says `not-rated` (REQ-33) |
| A person's severity is checked against the words; a report's is folded | A scanner's silence is not a claim; a person typing "urgent" is wrong |
| The scheme travels with the score | From the vector on a flaw assessed here, from the report otherwise |
| The number shown is the newest generation's rating, whole, with the others named beside it | A list and the finding screen agree. `design-docs/ingest-scanner.md` holds which rating in a generation is kept |

### Version 4 classes

A version 4 base score is a lookup: a vector's equivalence class score, less
its distance from the class's worst member, taken per class, scaled by the drop
to the class below, and averaged over classes with something below.

| Rule | Reason |
|---|---|
| Only the classes a base vector consults are carried | Sixty of the published 270. A transcribed number nothing runs is one nobody finds wrong |
| Exploitation contributes no distance | It is unstated on every base vector. It counts toward the mean and adds nothing |
| No impact anywhere scores zero before the tables | The lowest class is worth more than zero |
| Distance is measured from the first worst vector a class lists | |

## Weaknesses

| Rule | Reason |
|---|---|
| Recorded as given against no catalog: trimmed, upper-cased, deduplicated | A list refusing unknown identifiers refuses next year's. A published document looks names up then, and leaves out one no catalog assigns |
| The root cause is carried, never picked | The feeds say which is primary and a person names theirs first. `CWE-20` is the lower number and `CWE-119` the earlier string |
| A person states at most sixteen, each `CWE-` and a number | Refused before writing; the column is a name's width on three engines |
| Every response a screen draws a weakness from carries its catalog name and, for common ones, a short name | Both lists live on the server. A published document states the catalog name alone |
| A lookup takes identifiers, answered in the order asked, one neither list holds answered with no names; a number prefix, the exact match first; or words, each held by the two names together, case-insensitive. Nothing typed answers the common ones | It reads no finding |
| Most common first | The four commonest in a kernel image (memory leak, race, improper locking, double free), then the 2024 CWE Top 25 in order, then the rest by number |

## One ladder for every scheme

The five severity words cover the same five ranges in version 3 and version 4,
which is what makes a list holding both orderable.

| Rule | Reason |
|---|---|
| Scores under different schemes compare as bands, never numbers | 7.5 under each is two different judgments, both high |
| A score is shown with its scheme | |
| Both scorers stand indefinitely | A distribution base carries issues rated under whichever scheme was current at publication |

## The severity ladder

The severity words are one list in one place.

| List | Purpose |
|---|---|
| The four rated bands | The order a report reads in |
| `negligible` and `none` | Scanner answers no band holds; folded to low |
| `everything` | The absence of a minimum severity, kept with the minimum severity |

| Fold | Rule |
|---|---|
| One table of words to bands | Critical and high stay; `low`, `negligible`, `none` are low; `medium` and every other word, the empty one included, are medium. Unrated is unknown, never harmless |
| SQL is generated from the table | The banding expression is built from it, and a test runs it on every engine for every recordable word, the empty word, `unknown` and a padded capitalized word. A query's `ELSE` is its caller's |
| Server readers read through it | The band a finding is drawn and clocked in, the deadline window, the score standing in for a word. An unrecognized word scores nothing |
| A score's band is the scorer's | A stored score turned back into a word uses the scorer's thresholds |
| The interface reads the same ladder | The floors, the recordable words, the gate refusing a second copy, and the trend chart's fold |

## The rating in force

A finding's severity is this product's word where it has stated one, and the
published word otherwise (REQ-29).

| Rule | Reason |
|---|---|
| A query presenting a severity joins the rating | The expression reads a joined column, so a query without the join fails to compile on every engine rather than answering for the wrong product |
| It names the product it asks about | Bound where the scope names one, from the row's branch or tag across products, from the decision on a decision row: three named spellings, because a placeholder cannot bind a column |
| A flaw recorded here is rated by its recording product, and that rating is that product's rating in force; a rating claim there replaces it, and withdrawing the claim returns to it | Held per product, never on the shared issue row, which would tell readers of every product how bad an undisclosed flaw is |
| The recording product's lists, documents and exports carry the score it recorded; the issue page and evidence carry it where every record of the issue is in reach | |
| Sorting by score reads the issue's own, so a recorded flaw with no published score sorts with the unscored | |
| A query reading the published word aliases it `published` | Those queries ask whether a rating is milder than the world's; aliased `severity` they read as the rating in force |

## Urgency

Each finding stores an urgency, written when a scan applies and when a signal
moves (REQ-32). Computing it on read joins every signal for every row of every
list.

| Signal, highest first | Reason for its position |
|---|---|
| An incident in this product through it | A person here saying this product was attacked. `design-docs/incidents.md` |
| Known exploited in the world | The difference between a risk and an incident |
| Reaches customers | A medium people install beats a critical only the build system runs |
| Severity, as a band | How bad it would be. § One ladder for every scheme |
| Likelihood of exploitation | Which of two equal severities first |

| Rule | Reason |
|---|---|
| Severity ranks above likelihood | Measured: the other order put a 2004 negligible above 379 criticals; multiplying them let mediums jump criticals on noise inside a 0.001–0.01 spike |
| Packed, never weighted: each signal owns a range of digits | A rule statable in a sentence. The interface explains a position from the signals the finding carries |
| The two exploitation signals are one band each, and a column says which holds | The minimum severity asks "is some exploitation on this" from the index alone; reports name which |
| Both columns sit in the covering index beside the urgency | |
| A signal out of range is clamped | It would carry into the band above |
| A word with no number stands in for one | A finding rated in words does not sort below everything |
| Computed from what the issue holds, never from the report being applied | The issue holds the worst claims and the newest likelihood |
| The rating and the incident are the product's; the rest reach every product | One issue sits in different places in two products' lists |
| A finding opened later reads both as it opens | |
| Rewritten wherever the issue is open, once per product against its rating | Otherwise a known-exploited issue in a shipped tag sits below the minimum severity until the tag is rescanned, which is never |
| Only signals that rose decide who is re-ranked | |
| Only learning of exploitation in the world moves a clock | Score and likelihood never set a clock; a clock reset by every revision never arrives |
| The clock runs from when exploitation was learned, kept on the row | Counted from opening, an issue exploited after six months is due five months ago. The published catalogs date from when an entry was added |
| The scanned build's own scanner findings are left out of the rewrite | The scan has just ranked them in the same transaction. Hand-recorded findings there are rewritten, and an earlier listing day still re-clocks them |
| One statement per product and batch of issues; the issues, products and ratings are each read once for all | 16 statements against 1,955 the day a feed moved every likelihood, over 324,508 findings and another build's 43,220 |
| The rank follows the issue; the stored signals move only toward worse | It does not flap nightly |
| An incident moves no deadline | It admits the finding to the minimum severity whatever its rating (and clearing it may drop it again), and puts an upstream refusal back on the clock (`design-docs/remediation-deadlines.md`). `design-docs/incidents.md` § Response windows holds the other clock |

## Limits

| Limit | Detail |
|---|---|
| Urgency describes an issue, never a moment | Stored so a list sorts without joining every signal per row, and rewritten when a signal moves |
