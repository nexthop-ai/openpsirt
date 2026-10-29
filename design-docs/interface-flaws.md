# Flaw, report and disclosure screens

Recording a flaw, the vulnerability reports screens, disclosure deadlines and the
standing notice, advisories and published VEX, and the Incidents screen.

Satisfies REQ-19, REQ-28, REQ-33, REQ-37, REQ-38, REQ-40, REQ-66.

## Contents

- [Flaw entry](#flaw-entry)
- [Vulnerability reports](#vulnerability-reports)
- [Disclosure and advisories](#disclosure-and-advisories)
- [The Incidents screen](#the-incidents-screen)
- [Limits](#limits)

## Flaw entry

One screen for every flaw reported in what we ship, sent from outside or found
here (REQ-19). It is reached from the rail as "Record a flaw", from a product's
vulnerability reports with the product picked, and from a report being
recorded. Not from the findings list: what is recorded is what the list lacks.

| Rule | Reason |
|---|---|
| Where it came from is asked, with no default (REQ-37): found here asks for the finder and credit; sent in asks for the reporter, how to reach them, the credit, and the day it arrived | It decides the disclosure date and whether an answer is owed |
| A link naming the source opens the form with it answered and changeable; Disclosure deadlines' "Record a reported flaw" is the one | Following it is choosing |
| Filing and recording are one choice. Filed, it waits in Vulnerability reports; recorded, it asks for builds, component and severity, and its report is written in the same act. Somebody who may not work reports is offered recording alone | Filing is working reports |
| Opened from a report, it records that report, reading the source from it, and recording accepts it | |
| A recorded flaw opens on its issue page, with every build it landed in and the advisory panel; a filed report on its own page | |
| The control appears only for somebody who may record: undisclosed needs private triage, already public the ordinary right; holding only the ordinary right offers the second, the first saying why not | |
| It is undisclosed unless somebody says otherwise, as two stated options | The dangerous mistake is not the quiet one |
| The disclosure date an outside undisclosed report gets is stated as this deployment's embargo, the `disclosure.after` length `session/me` publishes; before that answer arrives, the option names no length | |
| The severity has no default and may stay unset; an unrated flaw has no deadline until rated (REQ-33), and the hint says so | |
| Builds are sets of lines and variants ticked under one product, prefilled from the scope without constraint, the count of builds stated | One flaw is one issue in every build shipping the code |
| The component is searched against what the build holds; a name held at two versions is asked | A typed name the server refuses |
| The score is composed as a vector in words and computed on the server, settling the severity | One formula |
| The scheme is picked and the metrics follow: version 4 asks eleven, version 3 eight, the two they share in different words; switching keeps shared answers | |
| A new assessment is composed under 3.1; choosing version 4 says it publishes no score | A published advisory has no field for a version 4 score |
| A score shows its scheme: beside the number where it leads, on the number where the band leads | The schemes are not comparable |
| Weaknesses are suggested from the server's search over both name lists, by number or by words, most common first, and checked for shape only: CWE- and a number, at most sixteen; a bare number reads as that CWE | A picker refusing unknown identifiers refuses next year's |
| Names typed for a recorded flaw are on its reporter card, each removable; a scan-reported name is not. Removing the filed name moves the screen to the name it is refiled under | A removed name stops later scans landing on the flaw |
| Proving files are attached on the same screen, stored against the report when filed and the issue when recorded; a file that fails is named and does not undo the record | The words are the finding |
| Recorded here is a findings list filter, linked from this screen with the release line off | "Is this already filed" asks what exists |

The description is our own markdown, through the editor and the submission
policy. What a scan file said stays escaped and unrendered (REQ-66). A VEX
publisher's words are shown the same way: a third party's text reaching the
people with most access, which rendered would lay out headings, tables, bold
assertions, outbound link text and this deployment's own attachments beside
their argument.

## Vulnerability reports

One product's reports, reached from the product page and from the two notices
naming a report. `design-docs/findings-reports.md` § Reports holds what a report
is and § Dispositions what a ruling does.

| Rule | Reason |
|---|---|
| The link appears only for a reader of undisclosed work in the product, and the product page's link says how many rulings wait | |
| The rail carries it under the scope for a reader of reports anywhere, declining where no product is picked or the reader may not read reports there | |
| A reader who does not work reports sees no writing control (recording, editing, recording a message, writing a note, assigning, accepting, attaching, proposing, withdrawing); notes and correspondence are drawn without a composer. Approve is offered where the capability answer's ruling field says so | |
| A problem somebody sent is called a vulnerability report wherever a person reads it | Analytics' named reports sit on the rail |
| The reported problem, a message and a ruling's reason offer no mentions | Nothing reads a mention there |
| A note offers mentions of readers of undisclosed work in the product; a name reaching nobody says so without why | |
| Two tabs: the reports, and rulings waiting for approval, the second's count on it | The waiting notice points there |
| A status is one word, a waiting ruling in it: "Rejected, waiting" | |
| Only an open report can be selected | The server refuses the rest |
| The selection and the one-report form are one form | The second person approves the selection as one act (REQ-28) |
| A selection past the bulk action limit holds the button back and says why | |
| The button is "Propose" where somebody else must agree, "Submit" where not, counting reports where more than one | |
| A duplicate asks for the issue and says a closed one is rejected instead | |
| A duplicate starting a disclosure date says "This starts a disclosure date of *date* on *flaw*.", adding "once somebody else agrees" past the threshold; asked of the server once typing pauses; nothing is shown where none would start, which is also what an issue not found reads as | |
| Approve is not offered to the ruling's proposer, whom the server tells apart, saying so on the ruling. Withdrawing, offered to whoever works reports, reads Withdraw to the proposer, Send back to others while waiting, Undo once in force | One act, three moments |
| A report's page holds, in order: the reported problem, the holder, correspondence, notes, files, the judgment, history; the heading the reference and title | |
| While unanswered, the judgment offers recording as a new flaw first, as a button, then accepting as a scanned issue, then a ruling; afterwards it shows the judgment | A real report is usually a new flaw |
| A report found here reads "found here" in From, is never shown unanswered, and has no correspondence card | |
| The reported problem card offers Edit while open, saying the earlier version is kept; never once judged or under a waiting ruling | |
| An edited problem shows the original beneath it with who replaced it and when; the versions between behind a toggle naming how many | |
| The holder card is the finding's holder picker, asked for readers of undisclosed work, offered to whoever works reports while open; a team queue says so; once judged it names the last holder | |
| Correspondence says "Not answered." with the line that the first sent message is the acknowledgement, then "Acknowledged" with its day and recorder; each message reads Sent or Received with its day and logger | |
| Recording a message takes direction, day (today where empty) and text, with files attached into it held on the report, and says it sends nothing | |
| History lists every act oldest first, one line each with moment and actor; a rule's placement says so | |
| Rows carry the title beside the reference and the holder, a team marked team | |
| The list's new-report control opens flaw entry with the product picked | One form for every report |
| Files attached on the page, or into a message, note or problem, are held on the report at once and listed together | |
| An issue's reporter card carries its report's correspondence and notes and links the report, under the report rule; writing is offered to whoever works reports | |
| Duplicates are listed on the issue, in the reporter card for a flaw recorded here, in their own card on a scanned issue, under the report rule | Absent, never empty, for a non-reader |

## Disclosure and advisories

| Rule | Reason |
|---|---|
| A finding says whether it is disclosed, wherever shown (REQ-40) | A private reader must know what not to repeat |
| A group is undisclosed when any occurrence is, and its date is the earliest, both read as aggregates by count | A maximum of the visibility word answers "public" for a mixed group |
| The standing notice sits above everything on the finding page (REQ-40), naming where disclosure happens: a ticket, a commit message, a chat; the row's chip is secondary | |
| A screen lists what is approaching disclosure (REQ-38): soonest first, past due at the top, a date moved from it; a product the reader may not read undisclosed work in contributes nothing, not even a count (`design-docs/access-disclosure.md`) | The list is a disclosure |
| A row is one issue in one product: Where names the product, components and every build in scope carrying it, the variant once where shared; Occurrences totals across those builds; the issue links its page. The row, its form and an act's answer are keyed on product and issue | The unit an embargo moves in |
| The screen answers for the scope picked, sent with the request and named in the subtitle, or every product | |
| It offers "Record a reported flaw" to whoever may record undisclosed in the scope's product, or any where none is picked, never labeled as starting a disclosure | An outside report starts a date; Disclose makes an issue public |
| The empty screen says a flaw gets a date when sent in from outside or when an outside report is ruled its duplicate | |
| A reader of no undisclosed work at the scope picked is shown "Nothing to list." and "You don't read undisclosed findings in sonic." (or "in any product."), and the list is not asked | An empty list of embargoes reads as nothing due |
| Disclosing is offered in the notice and on this screen to whoever triages undisclosed work there; it says it cannot be undone, then whether it took effect or waits | |
| The act is chosen before the date, the reason labeled for it | Extending and bringing forward are different events |
| The window opens on this deployment's embargo length; the server answers over it where none is named, and the picker's first option says so | A thirty-day window under a ninety-day policy reads "nothing is coming" |
| The screen says a date arriving publishes nothing and waits for somebody, and what moving the date will do | |
| Agreeing to a movement sits on the review queue (`design-docs/interface-review.md` § The review queue) | Both kinds of second-person turn in one place |
| A notice arrives at a lead time somebody sets (REQ-38), in the application | A movement nobody can agree to in time is approved in name only |

### The advisory

Published advisories lists every advisory this deployment minted, and each has
its own screen. `design-docs/remediation-advisories.md` § The advisory holds what an advisory
is and `design-docs/remediation-advisories.md` § Editions and agreement who may agree.

| Rule | Reason |
|---|---|
| No filters, selection or bulk acts; the review step is a person reading text | Single or low double digits a year, each the company speaking |
| Panels are compose, review, approve, publish, in that order | The order acts happen |
| What is left before it can go out is said once at the top: naming no flaw first, then nobody agreeing | An advisory covering nothing generates no document |
| A control is disabled only on a fact the server answered: taking back an agreement and recording an issuance where nobody agrees. Agreeing is offered to whoever reaches the screen | Who may agree depends on who wrote the standing edition, which the screen is not told |
| Who agrees is named, with when | |
| Whether it changed since it went out is said above what went out, compared on the settled digest: an alert where changed, a line where not, absent where the server has no answer | |
| A control's refusal is the server's sentence: agreeing as its starter, naming a scanned flaw | |
| Starting one asks a product and a flaw, mints the name and names the flaw. A name minted before a refused naming is kept for the next attempt, across closing the card and switching product on a flaw's panel | A mistyped identifier spends no number |
| One flaw picker serves starting and adding: every flaw recorded in the product, open or fixed (marked), less those named; typing is allowed; a failed read says so and leaves the typing | An empty picker reads "none" |
| The picker says when it holds less than is there, at the endpoint's maximum | |
| Retitling and taking a flaw off are on the compose panel, each saying it takes back every agreement (`design-docs/remediation-advisories.md` § Editions and agreement) | They open an edition |
| Each release is listed under compose with its stated status, the decision and reason it stands under, and that decision's builds or "not recorded". A release of a variant none of those builds is reads "Another variant"; another branch or tag of the same variant says nothing | It reached by matching in another configuration |
| A release a decision moves off affected can be marked affected and a mark cleared, the cost on hover, offered only where decisions move it | Either opens an edition |
| A release whose status moved since agreement reads "Changed since approval"; the agreement stands | The moving decision had its own second person |
| The document is asked only where a flaw is named | |
| It is shown as text, never rendered (REQ-66) | It is what a customer's tooling receives |
| What went out is readable without generating anything | |
| Recording that it went out is its own act | What was published cannot be worked out later, and a second document must be a revision |
| Statuses use the standard's names, draft, final and interim, with meaning on hover | Interim is reached by a withdrawn agreement with nothing changed |

#### Published VEX

One build's published VEX has its own screen, reached from the release's customer
documents. `design-docs/remediation-vex.md` § The VEX document holds what it says
and `design-docs/remediation-advisories.md` § Issuance records what recording keeps.

| Rule | Reason |
|---|---|
| What went out is listed with who published it; each revision downloads | The kept bytes are what a customer holds |
| Recording offers the document it recorded | It carries its recorded version |
| The control is offered to whoever reaches the screen, the server refusing without a triage role | |
| Whether it changed is said by the advisory's component | |
| Two tabs, ours first, the shown one in the address; listing and recording follow the tab | |
| The head says a customer loads it with the build's SBOM in one upload, either kind (`docs/vendor-release.md`) | |

#### The panel on a flaw

Start an advisory, name this flaw in this product on it, read what it generates,
open it.

| Rule | Reason |
|---|---|
| Open on a flaw recorded here, folded on anything else | Naming refuses another's component |
| What already covers the flaw is listed first, each a link with whether it is agreed and gone out | |
| Naming a flaw in somebody else's component shows the refusal naming the issue | |
| The panel hands over once there is a draft, with no agreeing or issuance control | Its user just started it and may not agree |

## The Incidents screen

One card per standing incident; `design-docs/incidents.md` holds the parts.

| Rule | Reason |
|---|---|
| The shelf and its count are dependency findings, drawn under `design-docs/interface.md` § Families a reader holds at the product the address names, or across products: a reader not reading them there sees "Nothing to list." and the line, and the shelf is not asked; the response windows stay | "No incidents are recorded." reads as no attack |
| A window's row shows its end, or "Not started" and what it waits on: a named window, or the release date of a named fix release, or when that date comes | |
| The response window form's Counted from offers three starts in one control: when it became known, the fix's release, the first notice for each other window in force | A window counts from one moment |
| Fix releases are listed under the windows with release date ("no release date" starts nothing) and latest scans: "not scanned", "open in its latest scans", "not found in its latest scans"; no word says fixed | |
| A fix release is named by typing a tag, offered from the product's tags in use, declared-before-scanned included; the server refuses a branch or retired tag in its own sentence | |
| Withdraw sits beside each named tag; a withdrawn one stays listed, struck through, with who withdrew it | |
| A notice's places are one per line; only a trailing empty line is dropped, a blank between is sent and refused | A place's name may hold a comma |
| A notice is offered for the windows that apply to the incident's product | |
| Each card's notice form has its own fields | Several may be open |
| The finding shows the incident's named tags with neither form | |

## Limits

| Limit | Detail |
|---|---|
| Correspondence is recorded, never sent | The reporter is written to outside the deployment |
