# Obligations

A regulator's questions after an incident, and the half of them this answers.

Satisfies REQ-32 and REQ-77.

## Contents

- [Recorded, never computed](#recorded-never-computed)
- [Three conflated facts](#three-conflated-facts)
- [Stored facts](#stored-facts)
- [The record and the triage record](#the-record-and-the-triage-record)
- [Order](#order)
- [Windows](#windows)
- [Notices outside](#notices-outside)
- [Fix releases](#fix-releases)
- [The shelf](#the-shelf)
- [Bulk acts](#bulk-acts)
- [Limits](#limits)

## Recorded, never computed

| Ours | Theirs |
|---|---|
| The moment something became known here | Whether an obligation applies |
| What was known at that moment | When it falls due |
| Who was told, and when | Whether it was met |

| Rule | Reason |
|---|---|
| No interpretation is encoded | This is a general product installed by organizations in different places under different rules, each reading its own counsel. An interpretation here is one every deployment inherits and none chose, and it is wrong for most of them the day a rule is amended |
| The facts are the same everywhere | Which is why they are the half this holds |
| No screen states a verdict | None says an obligation applies, none reports one met, and no default encodes a jurisdiction's window |
| A deployment under no duty sees a record it does not use | The record costs nothing to hold and answers nothing on its own |

## Three conflated facts

| | What it is | Where it comes from |
|---|---|---|
| A vulnerability is exploited somewhere in the world | A property of the **issue** | A feed, through the scanner |
| A vulnerability applies to our product | A **triage outcome** | A person, through a claim |
| Our product is being exploited through it | An **incident** | A customer, a researcher, an investigation. No feed reports this |

| Rule | Reason |
|---|---|
| Only the third is a reportable event | It is also the one nothing computes |
| A feed's exploitation flag is evidence that an issue deserves attention | It is a statement about the world, and says nothing about whether this deployment's product was the thing exploited |
| The first and the third are kept apart in name as well as in meaning | Both are called exploited, both press for action, and one of them arrives automatically. Reading the first as the third is the failure this area exists to prevent |
| On screen the third is the filled badge, "Exploited here", and the first the outline, "Known exploited" | The rarer, attested fact is the louder one. `DESIGN-interface.md` § The ordering signals holds the rest |
| Each is a column of its own on a finding | `DESIGN-findings.md` § Urgency has why the stored order cannot tell them apart |

## Stored facts

Facts about moments. The moment each describes is gone by the time anybody
asks, which is why they are stored rather than worked out again.

| | |
|---|---|
| That this product was exploited through an issue, here | Person-recorded, append-only, on any finding regardless of kind. An inherited flaw used against our product is the case, and it needs no flaw of our own |
| An attack through no issue anybody has published | Recorded as a flaw found here, carried by the build itself, and the record kept against that flaw. A compromised build or update channel is the case: the flaw sits at the build's root, one place across every variant (`DESIGN-findings.md` § Recorded flaws), so the record needs no kind of its own |
| The moment it became known | What a window counts from, directly or through the notices given after it. Stated rather than taken from the clock, because somebody learns of an attack before they reach a screen |
| The grounds | What is being asserted and how it is known. Nothing re-checks the record, so this is the whole of what a later reader has |
| That somebody outside was told | Who, when, and about what. The same shape as the record of an advisory going out. § Notices outside |
| The releases that carry the fix | Person-stated, each a tag of the product, added as each is cut and withdrawn where named in error. § Fix releases |
| Clearing the exploitation record | An explicit human withdrawal, recorded with who cleared it and why. The one other clearing is a report merging two issues that each held a standing record in the product: the newer stands, and the other is cleared with the merge as its reason and no person named. `DESIGN-findings.md` § Merged issues holds the rule |

The record is against an issue and one product, the shape an assessment has. A
place would be wrong twice over: the attack is a fact about the product rather
than about a dependency path, and keyed to a place it would lapse the next time
somebody rebuilt.

One record stands per issue and product, held by the database rather than by a
check. A cleared record stays readable beside it, and clearing releases the key
so the next one may be kept: what happened once may happen again.

A record is read at its finding for one issue in one product, where whether
somebody may be told of that pair is one question with one answer. The shelf
reads them across the deployment and asks the same question of each record in
turn, so nothing is counted before the narrowing: § The shelf.

Recording one and clearing one both ask for triage on that product, and both
land in the administrative trail. That is the layer the record belongs to — it
decides what the triage record may say, which is what a setting, a grant or an
alias does and not what a judgment about a finding does.

## The record and the triage record

A judgment gives way to a fact, and never the other way round. A person who
watched this product be attacked is not the one to give way to a claim that it
was never affected.

`DESIGN-triage.md` § Claims against a recorded attack holds the rules that
asymmetry produces.

## Order

A record puts this product's open findings of the issue above everything a feed
can say about it (REQ-32). `DESIGN-findings.md` § Urgency holds the packing,
the other four signals, and what the record does to the triage line and the
deadline.

| Rule | Reason |
|---|---|
| One product | The record belongs to one, so another product's findings of the same issue keep the order their own signals give them |

## Windows

A window is a period a deployment says it answers within, counted from one of
three moments: when an attack became known, the first notice naming another
window, or the release of the fix.

| Rule | Reason |
|---|---|
| A deployment declares its own, and none ships | A shipped window is an interpretation, which is the one thing this area refuses to encode |
| Declaring, changing and retiring one is an administrator's act, in the administrative trail | A window decides what every standing attack is watched against, which is the layer a setting sits in |
| A name and a length in whole hours, from one hour to a year | The shortest windows in force anywhere are a day, and a day is too coarse to count one in. Zero reads as unset everywhere, so it is refused rather than stored |
| A warning, where the window names one: whole hours before the end, at least one and fewer than the window runs | A day's window and a fortnight's want warnings of different sizes, so each says its own. A warning at or before the window opens says nothing the condition raised when the window starts has not |
| Limited to named products, or every product where it names none | Which window applies where is the administrator's statement. One deployment can ship a product under an obligation beside one that is under none, and a window over both raises alerts for the product it never applied to |
| A product nobody declared refuses the whole window, naming it | A window silently applying to fewer products than were named is quiet about the one that was meant. A blank name is one nobody declared; dropped, a list of blanks declares a window over every product |
| A change restates the whole window | Name, length, warning, products and what it counts from are all replaced, so any of them left off is removed |
| Names are unique among the windows in force, without regard to capitals | A notice names the window it answers, and two in force under one name make that ambiguous |
| Retired rather than deleted | A notice keeps naming the window it answered. Retiring releases the name, so it may be declared again |
| An end is worked out when asked, from the window as it stands | Changing a window's length moves every incident's end with it, which is what changing it means |
| The clock runs from the moment the record says the attack became known, from the first notice on the incident naming the window it counts from, or from the release of the fix | It is not the remediation deadline and is not derived from it. A later stage of a report counts from an earlier notice, and both moments are already recorded |
| A window counts from one moment | One counting from a notice and from the fix at once is refused |
| The release of the fix is the earliest release date stated for a tag the record names, at the start of that day in UTC | A release date is a calendar day. `DESIGN-data-model.md` § Release dates holds what one is |
| The day a tag was declared does not stand in for its release date | A tag is declared so scans can be filed against it, usually before the release. Its declaration says nothing about when the fix went out |
| A window counting from the fix with no named tag carrying a stated date has no start and no end | The handling a window waiting on a notice has, for the same reason |
| A release date still to come is a start that has not arrived | The window shows when it starts, and nothing is near, passed or raised before then |
| The release date is read when asked | Correcting a tag's date, naming a tag or withdrawing one moves the start of every window counting from the fix |
| The earliest such notice by the moment it was given, whenever it was recorded | The start is when somebody was first told. A notice recorded later naming an earlier moment moves the start back; one naming a later moment moves nothing. Notices are append-only, so a notice given a moment too early is answered beside it and still holds the start |
| A window waiting on a notice, or on the release of the fix, has no start and no end | Nothing is counting, so nothing is near, passed or raised |
| It counts only from a window in force that applies to every product it does | A notice names a window only on a product the window applies to, so a product outside it would hold a window that never starts. A reader who may read the one may read the other |
| Not from itself, and not from a window counting back to it | A loop of windows each waiting on another's notice never starts |
| A window another counts from is neither retired nor narrowed past it | Either would leave the other waiting on a notice nobody can record. Refused, naming the window to change first |
| The remediation computation is not reused | That deadline stops where nothing upstream would close the finding, which is exactly the population a flaw of our own falls into, so reuse leaves the obligation with no clock at all. `DESIGN-remediation.md` § Deadlines has why that rule is right where it is |
| Declared once for the deployment | What a deployment answers to is a fact about the organization running it. Declared per product, one rule would be restated for every product it covers |
| Its products are named only to whoever may know they exist | The list of windows is readable by anybody signed in, and the list of products is itself a statement about what an organization ships. A window limited to products the reader may not know exist is left out of what they read |

## Notices outside

A record that somebody outside was told about an attack.

> became aware 14:00 Tuesday, told ENISA 09:00 Wednesday

| Stored | |
|---|---|
| Which record it is about | A cleared record and the one recorded after it are two incidents, so a notice belongs to one of them rather than to the issue |
| Who was told | A regulator, a customer, a response team. A name, up to two hundred characters |
| When they were told | Supplied rather than taken from the clock, for the reason the moment an attack became known is |
| What they were told | Required, and held to the policy every typed field goes through |
| The window it answers | Where whoever recorded it names one. Their statement; nothing here judges whether a notice met a window |
| The recipient's reference | Where they gave one: a case or submission number. Up to a name's width |
| The places it named | Free text, in the order given. Which places a deployment names is its own business, and nothing matches them against a list |
| What it said about malice | Suspected, not malicious, or unknown, where it said anything. Unknown is a statement of its own, which silence is not |
| Who recorded it, and when | Written on the notice, so it is not also a row in the administrative trail |

| Rule | Reason |
|---|---|
| Append-only, with no edit and no withdrawal | What was said to a regulator is not unsaid by editing a row. A notice recorded in error is answered by recording the correction beside it |
| A stage is the window a notice answers | A deployment names its windows for the stages it reports in. A second list of stages would name the same thing twice |
| A place named twice, in any capitals, is kept once, as first typed. A blank place is refused | A blank is a slip in what was typed, and the rest of the list may be wrong with it |
| At most two hundred and fifty places, each up to a name's width | Every country in the world with room to spare, and a bound on what one request writes |
| Asked of triage on the record's product | Recording a notice is part of answering the attack, which is what recording it asks |
| Refused before the attack became known, and in the future | One of two moments is wrong, and the record is the one already kept |
| Allowed on a cleared record | A notice given before the clearing still happened |
| A retired window cannot be named by a new notice | A window nobody counts any more is not one a new notice answers |
| A window limited to other products cannot be named by a notice | It is not one this record answers, and its name is not the caller's to learn. Refused as a window nobody declared |
| A notice names its window only to a reader who may read the window | Read as the list of windows is. A window limited since to products the reader may not know exist is shown as no window, because its current name is a statement about those products |
| Shown at the finding beside the record, and on the shelf | The record's history is read in one place wherever somebody arrives from |

## Fix releases

The tags of the record's product that a person names as carrying the fix.

| Stored | |
|---|---|
| Which record it is about | A fix belongs to the incident, as a notice does |
| Which tag | One of the record's product. A tag declared before any scan of it is the expected case: naming the release a fix will ship in |
| Who named it, and when | Written on the naming, and also a row in the administrative trail |
| Who withdrew it, and when | Where it was named in error. The naming stays readable |

| Rule | Reason |
|---|---|
| A tag, never a branch | A branch moves. A fix ships in one frozen point |
| Not a retired tag, and not another product's | A retired tag is out of use, and the record is about one product |
| Named once at a time per record, held by the database | A unique key over the record and the tag while the naming stands. Withdrawing releases it, so the tag may be named again |
| Withdrawn rather than edited or deleted | A tag named in error must be correctable, and what was said stays readable with who took it back, the convention clearing a record follows. No reason is asked: a withdrawal corrects a slip in what was typed, and the trail names who made it |
| Asked of triage on the record's product, and written to the administrative trail | Naming a fix decides when a window counts from, which is the layer the record itself sits in |
| Only on a standing record | A cleared record is read as it stood when it was cleared |
| Read only by whoever may be told of the attack | The same narrowing a notice has |
| Each named tag shows whether its latest scans still hold the issue open, once a build of it has been scanned | A fact for a reader to weigh. Open is a finding of the issue open in a build of the tag, among the findings the reader may see. Scanned is a scanner's findings applied to a build of the tag, or a finding open in one |
| What the scans show never moves a clock and states no verdict | A scanner misses a backported fix and matches a version it should not. A tag named as carrying the fix with the issue still open in it is shown as both, and nothing is concluded |
| Shown at the finding beside the record, and on the shelf | Named and withdrawn on the shelf, where notices are recorded |

## The shelf

Every standing record, earliest known first, with every window in force that
applies to its product as it runs for that incident, and every notice given. Its own screen rather than a
filter over the overdue list, and never reached by one.

| Rule | Reason |
|---|---|
| A missed remediation deadline has no counterparty and one of these does | So they are different surfaces. The failure to design against is an obligation rendering as row 4,782 among four thousand unpenalized hygiene findings |
| Named Exploited here on screen | The words of the record, the finding's mark and the act that keeps one, so the three read as one thing and apart from a feed's exploitation flag |
| Its windows are headed response windows, never deadlines | A deadline on any other screen is the remediation deadline, which a window is not and is not derived from |
| A record is kept from the shelf as well as from its finding | One act, one request and one form, named Record exploited here in both places. The shelf asks for the product and the issue as well, offers only the products the reader triages, and suggests the issues that product carries as one is typed, including one only in a tag, in a release past its end of support or below the triage line |
| An empty shelf names the act that fills it | Somebody arriving here during an incident is pointed at the control rather than left at an empty list |
| Each record is narrowed by the question that authorizes one issue in one product | The same question the record's own finding asks. Nothing is counted before the narrowing, so no total says how many records exist to somebody shown fewer |
| A product named in the address narrows the shelf to that product's records, and the screen says so with the way back to every product | A figure counted over one product opens what it counted. The narrowing is over what the reader was already shown, so it reveals nothing |
| The narrowing takes each record whole, with its windows, notices and fix releases, and leaves the Response windows card whole | A response window belongs to the deployment, and one window can count from another's notice whatever products each applies to |
| Unpaged | The set is what this deployment's products have been attacked through and nobody has cleared. A deployment where that is long has a problem no paging would help with |
| A window shows when it started, when it ends, whether its warning has come, whether that end has passed, and whether a notice names it | Times and parties. No row says an obligation applies or was met |
| A window waiting on a notice says which window's notice starts it, and one waiting on the fix says so, or when it starts where the release date is still to come | It has no end to show, and an empty cell reads as a window nobody counts |
| Each incident lists the tags named as carrying the fix | With each one's stated release date and what its latest scans hold. § Fix releases |
| A cleared record leaves the shelf | It stays readable at its finding, with who cleared it and why |
| Hygiene deadlines stay soft | Correct as it is, and stated here so nobody hardens the wrong half |

Each window raises a condition from the moment it starts until a notice names
it, a second once its warning has come where it names one, and a third once its
end has passed. Each says the time, what the window counts from, and that no
notice is recorded. `DESIGN-notifications.md` § Obligation notices holds who
hears and when each clears.

## Bulk acts

No act over many issues reaches a standing record. `DESIGN-triage.md` § Claims
against a recorded attack holds the rules.

| | |
|---|---|
| No bulk dismissal and no bulk deferral | `DESIGN-triage.md` § Claims against a recorded attack |
| No vanishing under a triage floor | The record puts its findings in a band above everything a feed can say, and the line admits either exploitation signal. `DESIGN-findings.md` § Urgency |
| No bulk clearing | A record is cleared one at a time, with a reason and a name |
| The list a bulk judgment is picked from marks an attacked issue | A selection reaching one is refused whole, so the list says which issue that is before anything is sent |

## Limits

Nothing here is a compliance feature and none of it should be sold as one. The
record is a record. Two deployments with identical records can owe entirely
different things, and the difference lives outside this software.

The exploited-here record cannot be verified by anything. It is somebody's
statement that an incident happened, which is what makes it append-only and
what makes clearing it a deliberate act with a name attached. Nothing re-checks
it, because nothing could.

A regulation is named nowhere in the code, the configuration or the screens.
Naming one makes the record look like an answer to that regulation, which is
the claim this area refuses to make. The reasoning that a particular rule
prompted this work belongs in a commit message and in this paragraph, and
nowhere a deployment reads it as advice.

A window applies to products, never to one incident, and whether it applies to
a particular incident is a judgment this software does not hold. A window
judged not to apply to one incident on a product it covers goes on raising its
condition until a notice names it, the record is cleared or the window is
retired. The condition says only what is true: the
time, what the window counts from, and that nothing is recorded.

A window counts from the moment the attack became known, from a notice, or from
the release of the fix, and from no other event. The release of the fix is a
person's statement: a tag named on the record and a release date somebody
stated for it. Nothing here decides that a fix is available, and the scans of a
named tag do not decide it either. An incident not tied to a published issue,
such as a compromised build or update channel, is recorded against a flaw found
here, carried by the build itself (§ Stored facts).

The shelf stores no end and no state. Every end is worked out from the record's
moment and the window as it stands when somebody asks, so a window changed
after an incident moves that incident's end too, and nothing records what the
end was before.
