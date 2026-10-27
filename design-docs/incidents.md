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
| No interpretation is encoded | Organizations in different places under different rules each read their own counsel. An interpretation here is one every deployment inherits and none chose, wrong for most the day a rule is amended |
| The facts are the same everywhere | Which is why they are the half this holds |
| No screen states a verdict: none says an obligation applies or reports one met, and no default encodes a jurisdiction's window | |
| A deployment under no duty sees a record it does not use | The record costs nothing to hold and answers nothing on its own |
| A regulation is named nowhere in the code, the configuration or the screens | Naming one makes the record look like an answer to it. The reasoning that a rule prompted this work belongs in a commit message |

## Three conflated facts

| Fact | What it is | Where it comes from |
|---|---|---|
| A vulnerability is exploited somewhere in the world | A property of the issue | A feed, through the scanner |
| A vulnerability applies to our product | A triage outcome | A person, through a decision |
| Our product is being exploited through it | An **incident** | A customer, a researcher, an investigation. No feed reports this |

| Rule | Reason |
|---|---|
| Only the third is a reportable event | It is also the one nothing computes |
| A feed's exploitation flag is evidence an issue deserves attention | It says nothing about whether this product was the thing exploited |
| The first and third are kept apart in name as well as meaning | Both are called exploited, both press for action, and one arrives automatically. Reading the first as the third is the failure this area prevents |
| On screen the third is the filled badge, "Incident", and the first the outline, "Known exploited" | The rarer, attested fact is the louder. `design-docs/interface.md` § The ordering signals holds the rest |
| Each is a column of its own on a finding | `design-docs/findings-severity.md` § Urgency has why the stored order cannot tell them apart |

## Stored facts

Facts about moments, stored because the moment is gone by the time anybody asks.

| Fact | Detail |
|---|---|
| That this product was exploited through an issue, here | Person-recorded, append-only, on any finding regardless of kind. An inherited flaw used against our product needs no flaw of our own |
| An attack through no issue anybody has published | Recorded as a flaw found here, carried by the build itself, with the record against that flaw. A compromised build or update channel is the case: the flaw sits at the build's root, one occurrence across every variant (`design-docs/findings-flaws.md` § Recorded flaws), so the record needs no kind of its own |
| The moment it became known | What a window counts from, directly or through later notices. Stated, never taken from the clock, because somebody learns of an attack before reaching a screen |
| The grounds | What is asserted and how it is known. Nothing re-checks the record, so this is all a later reader has |
| That somebody outside was told | Who, when, and about what, shaped as the record of an advisory going out (§ Notices outside) |
| The releases that carry the fix | Person-stated tags of the product, added as each is cut and withdrawn where named in error (§ Fix releases) |
| Clearing an incident | An explicit withdrawal, recorded with who cleared it and why. A report merging two issues each holding a standing record in the product also clears one: the newer stands, and the other is cleared with the merge as its reason and no person named (`design-docs/findings-issues.md` § Merged issues) |

| Rule | Reason |
|---|---|
| A record is against an issue and one product, as an assessment is | The attack is a fact about the product rather than a dependency path, and keyed to an occurrence it would lapse at the next rebuild |
| One record stands per issue and product, held by the database; a cleared record stays readable, and clearing releases the key | What happened once may happen again |
| A record is read at its finding for one issue in one product; the shelf asks the same question of each record in turn (§ The shelf) | Whether somebody may be told of that pair is one question with one answer |
| Recording and clearing ask for triage on that product, and land in the administrative trail | The record decides what the triage record may say, as a setting, a grant or an alias does |
| Append-only, and clearing is a deliberate act with a name | An incident is somebody's statement and nothing can verify it |

## Decisions against an incident

A decision gives way to a fact, never the reverse: a person who watched this
product be attacked does not give way to a decision that it was never affected.

| Rule | Reason |
|---|---|
| A decision that the issue does not apply is refused while an incident stands | The two say opposite things about one product |
| A bulk act that sets the issue aside or puts it off is refused while an incident stands: not applicable, wrong match, deferral, will not fix, already fixed | A standing incident is a deadline somebody may answer to, and one sentence over a selection is no way off anybody's list |
| A bulk act saying the issues apply, or promising work, is not refused | Neither sets anything aside, and the next scan checks every row a promise names |
| Rows set aside from a bulk act are still a bulk act, followed back to where it began | Otherwise the rule ends one step from where it started |
| An approver may set the attacked issue aside and agree to the rest; the refusal is asked of the rows being agreed | One attacked issue does not make hundreds unanswerable, and what is set aside meets the rule with its author |
| A record arriving over either kind of decision is kept and returns the decision to the queue, losing its agreement; its author is told | A fact cannot be refused and a decision can. The decision stands for somebody to answer again |
| The count of rows returned is of the rows the recorder may read | Every agreement the record contradicts is taken back whatever its visibility, and a count of the rest discloses undisclosed work |
| Agreeing to either kind is refused too | Approving writes no decision row, so meets nothing the write path checks, and a decision proposed before the record and agreed after is what hides the finding |
| Refused where a decision is written: a decision at a finding, a bulk act, a re-affirmation, an extension and a decision carried across builds all pass through it | Paths nobody checked are the ways round a rule checked at entry points |
| At the finding, only the decision that the issue does not apply is refused | A wrong match is about identity, and promising or putting off work is not contradicted by an attack. Made one finding at a time, each is a decision about that finding |
| Clearing the record puts nothing back | Whether the decision was right is for whoever answers the finding |
| No act over many issues reaches a standing record: no bulk dismissal or deferral, no bulk clearing | A record is cleared one at a time, with a reason and a name |
| The list a bulk decision is picked from marks an attacked issue | A selection reaching one is refused whole, so the list says which before anything is sent |
| A record's findings never vanish under a minimum severity | The record puts them in a band above everything a feed says, and the minimum severity admits either exploitation signal (`design-docs/findings-severity.md` § Urgency) |

## Order

A record puts this product's open findings of the issue above everything a feed
can say about it (REQ-32). `design-docs/findings-severity.md` § Urgency holds the
packing, the other four signals, and what the record does to the minimum severity
and the deadline.

| Rule | Reason |
|---|---|
| One product | Another product's findings of the issue keep the order their own signals give them |

## Response windows

A **response window** is a period a deployment says it answers within, counted
from one of three moments: when an attack became known, the first notice naming
another window, or the release of the fix.

### Window declaration

| Rule | Reason |
|---|---|
| A deployment declares its own, and none ships | A shipped window is an interpretation |
| Declaring, changing and retiring one is an administrator's act, in the administrative trail | A window decides what every standing attack is watched against |
| Declared once for the deployment | What a deployment answers to is a fact about its organization |
| A name and a length in whole hours, from one hour to a year; zero is refused | The shortest windows in force anywhere are a day, too coarse to count one in |
| A warning, where it names one: whole hours before the end, at least one and fewer than the window runs | Windows of a day and a fortnight want different warnings. One at or before the start says nothing the start's condition did not |
| Limited to named products, or every product where it names none | One deployment can ship a product under an obligation beside one under none |
| A product nobody declared refuses the whole window, naming it; a blank name is one nobody declared | Silently applying to fewer products is quiet about the one meant; dropped, a list of blanks declares a window over every product |
| A change restates the whole window: name, length, warning, products and what it counts from, so any left off is removed | |
| Names are unique among windows in force, regardless of capitals | A notice names the window it answers |
| Retired, never deleted; retiring releases the name | A notice keeps naming the window it answered |
| A window another counts from is neither retired nor narrowed past it; refused naming the window to change first | The other would wait on a notice nobody can record |
| Its products are named only to whoever may know they exist, and a window limited to products the reader may not know is left out of what they read | The list of windows is readable by anybody signed in, and a product list states what an organization ships |

### Window clock

| Rule | Reason |
|---|---|
| The clock runs from the moment the record says the attack became known, from the first notice on the incident naming the window it counts from, or from the release of the fix, and from no other event | It is not the remediation deadline nor derived from it. A later stage of a report counts from an earlier notice |
| A window counts from one moment; one counting from a notice and the fix at once is refused | |
| The earliest such notice by the moment it was given counts, whenever recorded | A notice recorded later naming an earlier moment moves the start back; one naming a later moment moves nothing. A notice given a moment too early is answered beside it and still holds the start |
| It counts only from a window in force applying to every product it does | A notice names a window only on a product the window applies to, so a product outside it would hold a window that never starts; a reader who may read the one may read the other |
| Not from itself, nor from a window counting back to it | A loop of windows never starts |
| The release of the fix is the earliest release date stated for a tag the record names, at the start of that day in UTC (`design-docs/data-model.md` § Release dates) | A release date is a calendar day |
| The day a tag was declared does not stand in for its release date | A tag is declared so scans can be filed against it, usually before the release |
| The release date is read when asked | Correcting a date, naming a tag or withdrawing one moves the start of every window counting from the fix |
| A release date still to come is a start not arrived: the window shows when it starts, and nothing is near, passed or raised before | |
| A window waiting on a notice, or on a fix with no named tag carrying a stated date, has no start and no end | Nothing is counting, so nothing is near, passed or raised |
| An end is worked out when asked, from the window as it stands, and nothing is stored | Changing a window's length moves every incident's end, which is what changing it means, and nothing records the end before |
| The remediation computation is not reused | That deadline stops where nothing upstream would close the finding, which is exactly where a flaw of our own falls. `design-docs/remediation.md` § Deadlines |
| A window applies to products, never to one incident; one judged not to apply to an incident on a product it covers goes on raising its condition until a notice names it, the record is cleared, or the window is retired | Whether a window applies to an incident is a judgment this does not hold. The condition says only the time, what the window counts from, and that nothing is recorded |

## Notices outside

A record that somebody outside was told about an attack.

> became aware 14:00 Tuesday, told ENISA 09:00 Wednesday

| Stored | Detail |
|---|---|
| Which record it is about | A cleared record and the one after it are two incidents, so a notice belongs to one of them |
| Who was told | A regulator, a customer, a response team; a name up to two hundred characters |
| When they were told | Supplied, never taken from the clock |
| What they were told | Required, and held to the policy every typed field goes through |
| The window it answers | Where the recorder names one. Their statement; nothing here judges whether a notice met a window |
| The recipient's reference | Where given, a case or submission number, up to a name's width |
| The places it named | Free text, in the order given; nothing matches them against a list |
| What it said about malice | Suspected, not malicious, or unknown, where it said anything. Unknown is a statement, which silence is not |
| Who recorded it, and when | On the notice, so it is no row in the administrative trail |

| Rule | Reason |
|---|---|
| Append-only, with no edit and no withdrawal; a notice in error is answered by a correction beside it | What was said to a regulator is not unsaid by editing a row |
| A stage is the window a notice answers | A deployment names its windows for the stages it reports in |
| A place named twice, in any capitals, is kept once as first typed; a blank place refuses the notice | A blank is a slip, and the rest of the list may be wrong with it |
| At most two hundred and fifty places, each up to a name's width | Every country with room to spare, and a bound on one request |
| Asked of triage on the record's product | Recording a notice is part of answering the attack |
| Refused before the attack became known, and in the future | One of two moments is wrong, and the record is the one already kept |
| Allowed on a cleared record | A notice given before the clearing still happened |
| A retired window cannot be named by a new notice | |
| A window limited to other products is refused as a window nobody declared | It is not one this record answers, and its name is not the caller's to learn |
| A notice names its window only to a reader who may read the window; one limited since to products the reader may not know is shown as no window | Its current name is a statement about those products |
| Shown at the finding beside the record, and on the shelf | The record's history reads in one place wherever somebody arrives from |

## Fix releases

The tags of the record's product a person names as carrying the fix.

| Stored | Detail |
|---|---|
| Which record it is about | A fix belongs to the incident, as a notice does |
| Which tag | One of the record's product. A tag declared before any scan of it is the expected case |
| Who named it, and when | On the naming, and a row in the administrative trail |
| Who withdrew it, and when | Where named in error; the naming stays readable |

| Rule | Reason |
|---|---|
| A tag, never a branch | A fix ships in one frozen point |
| Not a retired tag, and not another product's | |
| Named once at a time per record, by a unique key over the record and the tag while the naming stands; withdrawing releases it | |
| Withdrawn, never edited or deleted, with no reason asked | A withdrawal corrects a slip, and the trail names who made it |
| Asked of triage on the record's product, and written to the administrative trail | Naming a fix decides when a window counts from |
| Only on a standing record | A cleared record reads as it stood when cleared |
| Read only by whoever may be told of the attack | The narrowing a notice has |
| Each named tag shows whether its latest scans still hold the issue open, once a build of it has been scanned. Open is a finding of the issue open in a build of the tag, among those the reader may see; scanned is a scanner's findings applied to a build of the tag, or a finding open in one | A fact for a reader to weigh |
| What the scans show moves no clock and states no verdict; a tag named as carrying the fix with the issue open is shown as both | A scanner misses a backported fix and matches versions it should not. Nothing decides a fix is available |
| Shown at the finding beside the record, and on the shelf, where they are named and withdrawn | |

## The shelf

Every standing record, earliest known first, with every window in force applying
to its product as it runs for that incident, and every notice given. Its own
screen, never a filter over the overdue list nor reached by one.

| Rule | Reason |
|---|---|
| A missed remediation deadline has no counterparty and one of these does, so they are different surfaces | The failure designed against is an incident rendering as row 4,782 among four thousand hygiene findings |
| Named Incidents on screen | The words of the record, the finding's mark and the act that keeps one read as one thing, apart from a feed's flag |
| Its windows are headed response windows, never deadlines | A deadline elsewhere is the remediation deadline |
| A record is kept from the shelf as from its finding: one act, request and form, Record an incident in both. The shelf asks for the product and the issue, offers only products the reader triages, and suggests that product's issues as typed, including one only in a tag, a release past end of support, or below the triage line | |
| An empty shelf names the act that fills it | Somebody arriving during an incident is pointed at the control |
| Each record is narrowed by the question authorizing one issue in one product, and nothing is counted before the narrowing | No total tells somebody shown fewer how many exist |
| A product in the address narrows the shelf to its records, saying so with the way back | A figure counted over one product opens what it counted, over what the reader was already shown |
| The narrowing takes each record whole, with its windows, notices and fix releases, and leaves the Response windows card whole | A window belongs to the deployment, and one can count from another's notice whatever products each applies to |
| Unpaged | A deployment where the set is long has a problem paging does not help |
| A window shows when it started, when it ends, whether its warning has come, whether its end has passed, and whether a notice names it | Times and parties; no row says an obligation applies or was met |
| A window waiting on a notice says which window's notice starts it; one waiting on the fix says so, or when it starts where the release date is to come | An empty cell reads as a window nobody counts |
| Each incident lists its fix tags, with each one's stated release date and what its latest scans hold (§ Fix releases) | |
| A cleared record leaves the shelf, readable at its finding with who cleared it and why | |
| Hygiene deadlines stay soft | Correct as they are, stated so nobody hardens the wrong half |

Each window raises a condition from its start until a notice names it, a second
once its warning has come where it names one, and a third once its end has
passed. Each says the time, what the window counts from, and that no notice is
recorded. `design-docs/notifications.md` § Response window notices holds who
hears and when each clears.

## Limits

| Limit | Detail |
|---|---|
| Nothing here is a compliance feature | Two deployments with identical records can owe entirely different things, and the difference lives outside this software |
| An incident is verified by nothing | It is somebody's statement, which is why it is append-only and clearing names who did it |
| The release of the fix is a person's statement: a tag named on the record and a release date somebody stated | Nothing decides that a fix is available, and the scans of a named tag do not either |
| The shelf stores no end and no state | A window changed after an incident moves that incident's end, and nothing records the end before |
