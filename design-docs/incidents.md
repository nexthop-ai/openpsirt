# Incidents

A regulator's questions after an incident, the half of them this answers, and
what a standing incident does to decisions.

Satisfies REQ-32 and REQ-77.

## Contents

- [Recorded, never computed](#recorded-never-computed)
- [Three conflated facts](#three-conflated-facts)
- [Stored facts](#stored-facts)
- [Decisions against an incident](#decisions-against-an-incident)
- [Order](#order)
- [Response windows](#response-windows)
- [Notices outside](#notices-outside)
- [Fix releases](#fix-releases)
- [The shelf](#the-shelf)
- [Limits](#limits)

## Recorded, never computed

| Ours | Theirs |
|---|---|
| The moment something became known here | Whether an obligation applies |
| What was known at that moment | When it falls due |
| Who was told, and when | Whether it was met |

| Rule | Reason |
|---|---|
| No interpretation is encoded, and no screen states a verdict or default window | Deployments read their own counsel, and an encoded reading is wrong for most when a rule is amended |
| A deployment under no duty holds a record it does not use | |
| A regulation is named nowhere in the code, configuration or screens | Named, the record looks like an answer to it |

## Three conflated facts

| Fact | What it is | Where it comes from |
|---|---|---|
| A vulnerability is exploited somewhere in the world | A property of the issue | A feed, through the scanner |
| A vulnerability applies to our product | A triage outcome | A person, through a decision |
| Our product is being exploited through it | An **incident** | A customer, a researcher, an investigation; no feed |

| Rule | Reason |
|---|---|
| Only the third is a reportable event, and nothing computes it | |
| A feed's flag is evidence an issue deserves attention | It says nothing about this product |
| The first and third are kept apart in name and meaning | Both are "exploited", and reading the first as the third is the failure this area prevents |
| On screen the third is the filled badge "Incident", the first the outline "Known exploited" (`design-docs/interface.md` § The ordering signals) | The rarer, attested fact is louder |
| Each is a column on a finding (`design-docs/findings-severity.md` § Urgency) | |

## Stored facts

Facts about moments, stored because the moment is gone when anybody asks.

| Fact | Detail |
|---|---|
| This product was exploited through an issue | Person-recorded, append-only, on a finding of any kind; an inherited flaw needs no flaw of our own |
| An attack through no published issue | A flaw found here at the build's root, one occurrence across variants (`design-docs/findings-flaws.md` § Recorded flaws), with the record against it |
| The moment it became known | Stated, never the clock's: people learn before reaching a screen |
| The grounds | What is asserted and how it is known, the whole of what a later reader has |
| Somebody outside was told | § Notices outside |
| The releases carrying the fix | § Fix releases |
| Clearing | A withdrawal recording who and why. A report merging two issues each holding a standing record in the product clears the older, naming the merge and no person (`design-docs/findings-issues.md` § Merged issues) |

| Rule | Reason |
|---|---|
| A record is against an issue and one product | An attack is about the product, and an occurrence key would lapse at a rebuild |
| One standing record per issue and product, held by the database; clearing releases the key and the cleared record stays readable | It may happen again |
| Read at its finding for one issue in one product, one authorization question; the shelf asks it per record | |
| Recording and clearing ask for triage on the product and land in the administrative trail | The record governs what triage may say, as a setting does |
| Append-only, and clearing is deliberate and named | Nothing can verify an incident |

## Decisions against an incident

A decision gives way to a fact, never the reverse.

| Rule | Reason |
|---|---|
| A decision that the issue does not apply is refused while an incident stands | The two contradict |
| A bulk act setting the issue aside or putting it off is refused: not applicable, wrong match, deferral, will not fix, already fixed | A standing incident is a deadline somebody answers to |
| A bulk act saying it applies, or promising work, is allowed | Neither sets anything aside |
| Rows set aside from a bulk act still count as one, traced to its origin | |
| An approver may set the attacked issue aside and agree to the rest; the refusal is asked of rows being agreed | |
| A record arriving over such a decision is kept, and returns the decision to the queue without its agreement; its author is told | A fact cannot be refused, a decision can |
| The count of rows returned covers what the recorder may read; every contradicted agreement is taken back | |
| Agreeing to such a decision is refused | Approval writes no decision row the write path checks |
| Refused where a decision is written, so a finding decision, bulk act, re-affirmation, extension and carried decision all meet it | |
| At one finding, only a decision that the issue does not apply is refused | Identity, deferrals and promises are not contradicted by an attack |
| Clearing the record restores nothing | |
| No act over many issues reaches a standing record, and clearing is one record at a time | |
| The bulk candidate list marks an attacked issue | A selection reaching one is refused whole |
| A record's findings never fall below a minimum severity (`design-docs/findings-severity.md` § Urgency) | |

## Order

A record puts this product's open findings of the issue above anything a feed
says (REQ-32), in that product only. `design-docs/findings-severity.md` § Urgency
holds the packing and the effect on minimum severity and deadline.

## Response windows

A **response window** is a period a deployment says it answers within, counted
from when an attack became known, from the first notice naming another window,
or from the release of the fix.

### Window declaration

| Rule | Reason |
|---|---|
| A deployment declares its own, once for the deployment, and none ships | A shipped window is an interpretation |
| Declaring, changing and retiring is an administrator's act, in the administrative trail | |
| A name and whole hours from one hour to a year; zero refused | Windows in force start at a day |
| An optional warning: whole hours before the end, at least one, fewer than the length | |
| Limited to named products, or every product where none is named | Products under an obligation sit beside ones under none |
| An undeclared product, a blank name included, refuses the whole window, naming it | |
| A change restates the whole window | |
| Names are unique among windows in force, regardless of capitals | |
| Retired, never deleted; retiring releases the name | Notices keep naming it |
| A window another counts from is neither retired nor narrowed past it, refused naming the one to change first | |
| Its products are named only to readers who may know they exist; a window limited to unknown products is left out | Anybody signed in reads the list |

### Window clock

| Rule | Reason |
|---|---|
| The clock runs from the record's moment, the first notice on the incident naming the counted window, or the release of the fix, and nothing else | It is not the remediation deadline |
| A window counts from one moment | |
| The earliest notice by the moment given counts, whenever recorded; one given too early still holds the start | Notices are append-only |
| It counts only from a window in force applying to every product it does | Otherwise it may never start |
| Not from itself, nor through a loop back to it | |
| The release of the fix is the earliest stated release date of a named tag, at the start of that UTC day (`design-docs/data-model.md` § Release dates); a tag's declaration date never stands in | |
| The release date is read when asked | |
| A release date to come shows when the window starts, and nothing is near, passed or raised before | |
| A window waiting on a notice, or on a fix with no dated named tag, has no start or end | |
| An end is worked out when asked, and the shelf stores no end or state | Changing a window moves every incident's end |
| The remediation computation is not reused (`design-docs/remediation.md` § Deadlines) | It stops where nothing upstream closes the finding, where our own flaws sit |
| A window applies to products, never one incident; one judged not to apply goes on raising its condition until a notice, a clearing or retirement | Applicability to an incident is not judged here |

## Notices outside

> became aware 14:00 Tuesday, told ENISA 09:00 Wednesday

| Stored | Detail |
|---|---|
| Which record | A cleared record and its successor are two incidents |
| Who was told | A name up to two hundred characters |
| When | Supplied, never the clock's |
| What | Required, through the typed-field policy |
| The window it answers | Where named; nothing judges whether it was met |
| The recipient's reference | Up to a name's width |
| The places named | Free text in order, matched against no list |
| What it said about malice | Suspected, not malicious, or unknown, where stated |
| Who recorded it, and when | On the notice, not in the administrative trail |

| Rule | Reason |
|---|---|
| Append-only; an error is answered by a correction beside it | What was said is not unsaid |
| A stage is the window a notice answers | |
| A place repeated in any capitals is kept once, as first typed; a blank place refuses the notice | |
| At most two hundred and fifty places, each up to a name's width | |
| Asked of triage on the record's product | |
| Refused before the attack became known, and in the future | |
| Allowed on a cleared record | |
| Naming a retired window, or one limited to other products, is refused, the latter as undeclared | |
| A window is named to a reader only where they may read it | |
| Shown at the finding and on the shelf | |

## Fix releases

The tags of the record's product named as carrying the fix, with who named and
who withdrew each, and when.

| Rule | Reason |
|---|---|
| A tag of the record's product, never a branch, not retired; a tag not yet scanned is expected | A fix ships in a frozen point |
| One naming per record and tag at a time, by a unique key a withdrawal releases | |
| Withdrawn, never edited or deleted, with no reason asked | |
| Asked of triage on the product, and written to the administrative trail | It sets when a window counts from |
| Only on a standing record | |
| Read only by whoever may be told of the attack | |
| Each tag shows whether its latest scans hold the issue open, once scanned: open is a readable finding of the issue open in a build of the tag; scanned is a scanner's findings applied to one, or a finding open in one | |
| Scans move no clock and state no verdict; nothing decides a fix is available | Scanners miss backports and mismatch versions |
| Shown at the finding and on the shelf, where tags are named and withdrawn | |

## The shelf

Every standing record, earliest known first, with every window in force over
its product as it runs for that incident, and every notice. Its own screen,
never a filter of the overdue list.

| Rule | Reason |
|---|---|
| A separate surface from missed remediation deadlines | An incident has a counterparty, and must not be row 4,782 |
| Named Incidents, its windows headed response windows, never deadlines | |
| A record is kept from the shelf as from its finding, one form, Record an incident; the shelf asks product and issue, offers products the reader triages, and suggests that product's issues, including those only in a tag, past end of support or below the triage line | |
| An empty shelf names the act that fills it | |
| Each record is narrowed by the one-issue, one-product question, nothing counted before | |
| A product in the address narrows to its records, saying so with the way back | |
| The narrowing keeps each record whole and the Response windows card whole | A window may count from another's notice |
| Unpaged | |
| A window shows its start, end, warning, whether passed, and whether a notice names it, never whether an obligation applies | |
| A waiting window says which notice or fix starts it, or when | An empty cell reads as uncounted |
| Each incident lists its fix tags with their release dates and latest scans | |
| A cleared record leaves the shelf, readable at its finding | |
| Hygiene deadlines stay soft | |

Each window raises a condition from its start until a notice names it, a second
at its warning, and a third past its end, each stating the time, what it counts
from, and that no notice is recorded (`design-docs/notifications.md` § Response
window notices).

## Limits

| Limit | Detail |
|---|---|
| Nothing here is a compliance feature | Two deployments with identical records can owe entirely different things, decided outside this software |
